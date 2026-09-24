//! Root key generation lifecycle.
//!
//! A grant names a root generation, but until this module existed nothing
//! recorded which generations a tenant had, or which one was in force. A grant
//! could therefore name a generation that was never created, and a device that
//! collected several grants had no way to tell which key to actually use.
//!
//! Scope is the bootstrap path from plan 5.6: a tenant creates its first
//! generation in PREPARING, the first device files a self-grant, and the
//! generation becomes ACTIVE once that device confirms it can unwrap what it
//! filed. Rotation and recovery bundles are specified in the plan but are not
//! implemented here.
//!
//! Note on `v2_tenants.active_root_generation`: the frozen schema already
//! carries that column, and it stays the number a tenant advertises. This table
//! records the *lifecycle* the column cannot express — that a generation is
//! being prepared, which root key it commits to, and whether anyone has proven
//! they can open it. Activation writes both, so the two never disagree.

use crate::error::AppError;
use sqlx::{Row, SqlitePool};

/// The states a generation may occupy, mirroring the schema CHECK.
pub const STATE_PREPARING: &str = "PREPARING";
pub const STATE_ACTIVE: &str = "ACTIVE";
pub const STATE_RETIRED: &str = "RETIRED";

/// A generation as stored.
pub struct Generation {
    pub generation: u64,
    pub root_key_id: [u8; 32],
    pub state: String,
    /// Kept because the row carries it and callers reporting generation status
    /// need it; not read by the server's own logic.
    #[allow(dead_code)]
    pub created_at: String,
    pub activated_at: Option<String>,
}

/// Begin the tenant's first root key generation, in PREPARING.
///
/// The generation number is the one the tenant already advertises in
/// `v2_tenants.active_root_generation`, so a bootstrapped tenant does not end
/// up with a lifecycle row numbered differently from the column every other
/// query reads.
///
/// Only the first generation is creatable here: a later one is a rotation,
/// which must carry the previous generation forward and is out of scope.
/// Refusing a second creation matters because it would propose a different root
/// key for a tenant that may already have devices holding the first one.
pub async fn begin_first_generation(
    db: &SqlitePool,
    tenant_id: &[u8; 16],
    root_key_id: &[u8; 32],
    now: &str,
) -> Result<u64, AppError> {
    let existing: i64 =
        sqlx::query_scalar("SELECT count(*) FROM v2_root_key_generations WHERE tenant_id = ?1")
            .bind(tenant_id.as_slice())
            .fetch_one(db)
            .await?;

    if existing > 0 {
        return Err(AppError::Conflict(
            "tenant already has a root key generation".into(),
        ));
    }

    let generation: i64 =
        sqlx::query_scalar("SELECT active_root_generation FROM v2_tenants WHERE id = ?1")
            .bind(tenant_id.as_slice())
            .fetch_optional(db)
            .await?
            .ok_or_else(|| AppError::BadRequest("tenant does not exist".into()))?;

    sqlx::query(
        "INSERT INTO v2_root_key_generations \
         (tenant_id, generation, root_key_id, state, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )
    .bind(tenant_id.as_slice())
    .bind(generation)
    .bind(root_key_id.as_slice())
    .bind(STATE_PREPARING)
    .bind(now)
    .execute(db)
    .await?;

    Ok(generation as u64)
}

/// Look up one generation.
pub async fn get_generation(
    db: &SqlitePool,
    tenant_id: &[u8; 16],
    generation: u64,
) -> Result<Option<Generation>, AppError> {
    let row = sqlx::query(
        "SELECT generation, root_key_id, state, created_at, activated_at \
         FROM v2_root_key_generations WHERE tenant_id = ?1 AND generation = ?2",
    )
    .bind(tenant_id.as_slice())
    .bind(generation as i64)
    .fetch_optional(db)
    .await?;

    let Some(row) = row else { return Ok(None) };
    let key: Vec<u8> = row.try_get("root_key_id")?;
    let root_key_id: [u8; 32] = key
        .try_into()
        .map_err(|_| AppError::Internal("stored root_key_id is not 32 bytes".into()))?;

    Ok(Some(Generation {
        generation: row.try_get::<i64, _>("generation")? as u64,
        root_key_id,
        state: row.try_get("state")?,
        created_at: row.try_get("created_at")?,
        activated_at: row.try_get("activated_at")?,
    }))
}

/// The tenant's ACTIVE generation, if it has one.
///
/// A device asks this to learn which generation to seal under. Before any
/// generation is activated the answer is None, which is what stops a sync from
/// silently falling back to an older key path.
pub async fn active_generation(
    db: &SqlitePool,
    tenant_id: &[u8; 16],
) -> Result<Option<Generation>, AppError> {
    let row = sqlx::query(
        "SELECT generation, root_key_id, state, created_at, activated_at \
         FROM v2_root_key_generations WHERE tenant_id = ?1 AND state = ?2",
    )
    .bind(tenant_id.as_slice())
    .bind(STATE_ACTIVE)
    .fetch_optional(db)
    .await?;

    let Some(row) = row else { return Ok(None) };
    let key: Vec<u8> = row.try_get("root_key_id")?;
    let root_key_id: [u8; 32] = key
        .try_into()
        .map_err(|_| AppError::Internal("stored root_key_id is not 32 bytes".into()))?;

    Ok(Some(Generation {
        generation: row.try_get::<i64, _>("generation")? as u64,
        root_key_id,
        state: row.try_get("state")?,
        created_at: row.try_get("created_at")?,
        activated_at: row.try_get("activated_at")?,
    }))
}

/// Whether this tenant already has a FirstRootSelfGrant on file.
pub async fn has_self_grant(db: &SqlitePool, tenant_id: &[u8; 16]) -> Result<bool, AppError> {
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM v2_tenant_root_key_grants \
         WHERE tenant_id = ?1 AND grant_variant = 'FirstRootSelfGrant'",
    )
    .bind(tenant_id.as_slice())
    .fetch_one(db)
    .await?;
    Ok(n > 0)
}

/// Check that a grant may be filed against the generation it names.
///
/// This is the constraint that gives `FirstRootSelfGrant` its meaning. Two
/// rules, both of which have to hold:
///
///   - the generation must exist, and its root key must be the one the grant
///     claims to wrap. Without this a grant could name generation 0 while
///     wrapping an entirely different key, and a device collecting it would
///     decrypt snapshots with a key nobody else has.
///
///   - a self-grant is only valid while the generation is PREPARING and no
///     self-grant exists yet. It is the act that bootstraps custody, so it
///     cannot be used to append a second root holder later; that is what a
///     custodian-issued grant is for.
pub async fn check_grant_against_generation(
    db: &SqlitePool,
    tenant_id: &[u8; 16],
    grant_variant: &str,
    root_generation: u64,
    root_key_id: &[u8; 32],
) -> Result<(), AppError> {
    let Some(generation) = get_generation(db, tenant_id, root_generation).await? else {
        return Err(AppError::BadRequest(format!(
            "root generation {root_generation} does not exist for this tenant"
        )));
    };

    if &generation.root_key_id != root_key_id {
        return Err(AppError::BadRequest(
            "grant root_key_id does not match the generation's root key".into(),
        ));
    }

    if generation.state == STATE_RETIRED {
        return Err(AppError::Conflict(
            "root generation is retired and cannot receive new grants".into(),
        ));
    }

    if grant_variant == "FirstRootSelfGrant" {
        if generation.state != STATE_PREPARING {
            return Err(AppError::Conflict(
                "a first self-grant is only valid while the generation is preparing".into(),
            ));
        }
        if has_self_grant(db, tenant_id).await? {
            return Err(AppError::Conflict(
                "tenant already has a first root self-grant".into(),
            ));
        }
    } else if generation.state == STATE_PREPARING {
        // A custodian grant hands the key to an additional device, which
        // presupposes the key is already established. Allowing it during
        // PREPARING would let a tenant skip the bootstrap confirmation and
        // activate custody nobody has proven they can open.
        return Err(AppError::Conflict(
            "generation is still preparing; file the first self-grant first".into(),
        ));
    }

    Ok(())
}

/// Activate a PREPARING generation.
///
/// Activation is separate from filing the self-grant on purpose. Filing proves
/// the grant was *written*; it does not prove the holder can *open* it. A
/// tenant that activated on filing could lock itself out permanently by
/// sealing to a key it had already lost. The caller performs the unwrap and
/// only then activates.
pub async fn activate_generation(
    db: &SqlitePool,
    tenant_id: &[u8; 16],
    generation: u64,
    now: &str,
) -> Result<(), AppError> {
    let Some(existing) = get_generation(db, tenant_id, generation).await? else {
        return Err(AppError::BadRequest(
            "root generation does not exist for this tenant".into(),
        ));
    };

    if existing.state == STATE_ACTIVE {
        // Activation is idempotent: a retried confirmation should not fail.
        return Ok(());
    }

    if existing.state != STATE_PREPARING {
        return Err(AppError::Conflict(
            "only a preparing generation can be activated".into(),
        ));
    }

    // Activation without a filed self-grant would produce an active generation
    // that no device can open.
    if !has_self_grant(db, tenant_id).await? {
        return Err(AppError::Conflict(
            "cannot activate a generation with no root key grant on file".into(),
        ));
    }

    // Both writes happen in one transaction so the lifecycle row and the column
    // the rest of the server reads can never disagree about which generation is
    // in force.
    let mut tx = db.begin().await?;

    let result = sqlx::query(
        "UPDATE v2_root_key_generations SET state = ?1, activated_at = ?2 \
         WHERE tenant_id = ?3 AND generation = ?4 AND state = ?5",
    )
    .bind(STATE_ACTIVE)
    .bind(now)
    .bind(tenant_id.as_slice())
    .bind(generation as i64)
    .bind(STATE_PREPARING)
    .execute(&mut *tx)
    .await?;

    // The partial unique index permits one ACTIVE generation per tenant. A zero
    // row count here means the state changed under us, not that the caller sent
    // something invalid.
    if result.rows_affected() == 0 {
        return Err(AppError::Conflict(
            "generation state changed during activation".into(),
        ));
    }

    sqlx::query("UPDATE v2_tenants SET active_root_generation = ?1 WHERE id = ?2")
        .bind(generation as i64)
        .bind(tenant_id.as_slice())
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    Ok(())
}
