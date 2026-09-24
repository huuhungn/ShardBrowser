//! Fleet key (FKEK) generation lifecycle.
//!
//! Mirrors the root generation lifecycle in `generations.rs`, but for the key
//! profile snapshots are actually encrypted under. The two are deliberately
//! separate: the root key authorises custody and rotates rarely, while a fleet
//! key wraps working data and may need to rotate whenever fleet membership
//! changes. Deriving one from the other would fuse those lifetimes.
//!
//! Scope is the same bootstrap shape as the root path: a fleet creates its
//! first generation in PREPARING, the custodian device files a self-grant, and
//! the generation becomes ACTIVE only once that device has proven it can
//! unwrap what it filed. Rotation and revocation are specified in the plan but
//! are not implemented here.

use crate::error::AppError;
use sqlx::{Row, SqlitePool};

/// The states a fleet generation may occupy, mirroring the schema CHECK.
pub const STATE_PREPARING: &str = "PREPARING";
pub const STATE_ACTIVE: &str = "ACTIVE";
pub const STATE_RETIRED: &str = "RETIRED";

/// The grant variants, mirroring the schema CHECK.
pub const VARIANT_FIRST_SELF: &str = "FirstFleetSelfGrant";
pub const VARIANT_DEVICE_HPKE: &str = "DeviceHpkeGrant";

/// A fleet key generation as stored.
pub struct FleetGeneration {
    pub generation: u64,
    pub fkek_key_id: [u8; 32],
    pub state: String,
    #[allow(dead_code)]
    pub created_at: String,
    pub activated_at: Option<String>,
}

/// Read one generation.
pub async fn get_generation(
    db: &SqlitePool,
    tenant_id: &[u8; 16],
    fleet_id: &[u8; 16],
    generation: u64,
) -> Result<Option<FleetGeneration>, AppError> {
    let row = sqlx::query(
        "SELECT generation, fkek_key_id, state, created_at, activated_at \
         FROM v2_fleet_key_generations \
         WHERE tenant_id = ?1 AND fleet_id = ?2 AND generation = ?3",
    )
    .bind(tenant_id.as_slice())
    .bind(fleet_id.as_slice())
    .bind(generation as i64)
    .fetch_optional(db)
    .await?;

    let Some(row) = row else { return Ok(None) };
    let key: Vec<u8> = row.try_get("fkek_key_id")?;
    let fkek_key_id: [u8; 32] = key
        .try_into()
        .map_err(|_| AppError::Internal("stored fkek_key_id is not 32 bytes".into()))?;

    Ok(Some(FleetGeneration {
        generation: row.try_get::<i64, _>("generation")? as u64,
        fkek_key_id,
        state: row.try_get("state")?,
        created_at: row.try_get("created_at")?,
        activated_at: row.try_get("activated_at")?,
    }))
}

/// The fleet's ACTIVE generation, if it has one.
///
/// A device asks this to learn which key to encrypt under. Before activation
/// the answer is None, which is what stops a sync from silently falling back
/// to a weaker key path.
pub async fn active_generation(
    db: &SqlitePool,
    tenant_id: &[u8; 16],
    fleet_id: &[u8; 16],
) -> Result<Option<FleetGeneration>, AppError> {
    let row = sqlx::query(
        "SELECT generation, fkek_key_id, state, created_at, activated_at \
         FROM v2_fleet_key_generations \
         WHERE tenant_id = ?1 AND fleet_id = ?2 AND state = ?3",
    )
    .bind(tenant_id.as_slice())
    .bind(fleet_id.as_slice())
    .bind(STATE_ACTIVE)
    .fetch_optional(db)
    .await?;

    let Some(row) = row else { return Ok(None) };
    let key: Vec<u8> = row.try_get("fkek_key_id")?;
    let fkek_key_id: [u8; 32] = key
        .try_into()
        .map_err(|_| AppError::Internal("stored fkek_key_id is not 32 bytes".into()))?;

    Ok(Some(FleetGeneration {
        generation: row.try_get::<i64, _>("generation")? as u64,
        fkek_key_id,
        state: row.try_get("state")?,
        created_at: row.try_get("created_at")?,
        activated_at: row.try_get("activated_at")?,
    }))
}

/// Begin a fleet's first key generation, in PREPARING.
///
/// Refuses if the fleet already has a generation. Two concurrent bootstraps
/// would otherwise each seal a different key and one would silently win,
/// leaving snapshots encrypted under a key no surviving grant covers.
pub async fn begin_first_generation(
    db: &SqlitePool,
    tenant_id: &[u8; 16],
    fleet_id: &[u8; 16],
    fkek_key_id: &[u8; 32],
    now: &str,
) -> Result<u64, AppError> {
    let fleet_exists =
        sqlx::query("SELECT 1 FROM v2_fleets WHERE tenant_id = ?1 AND id = ?2 LIMIT 1")
            .bind(tenant_id.as_slice())
            .bind(fleet_id.as_slice())
            .fetch_optional(db)
            .await?
            .is_some();
    if !fleet_exists {
        return Err(AppError::BadRequest(
            "fleet does not exist in this tenant".into(),
        ));
    }

    // A fleet key must be anchored to the root generation that authorises
    // custody. Without an active root, no custodian could be verified, so the
    // fleet key would rest on nothing.
    let root_generation: Option<i64> =
        sqlx::query_scalar("SELECT active_root_generation FROM v2_tenants WHERE id = ?1")
            .bind(tenant_id.as_slice())
            .fetch_optional(db)
            .await?
            .flatten();
    let Some(root_generation) = root_generation else {
        return Err(AppError::Conflict(
            "tenant has no active root generation; activate one before creating a fleet key".into(),
        ));
    };

    let existing: Option<i64> = sqlx::query_scalar(
        "SELECT generation FROM v2_fleet_key_generations \
         WHERE tenant_id = ?1 AND fleet_id = ?2 ORDER BY generation DESC LIMIT 1",
    )
    .bind(tenant_id.as_slice())
    .bind(fleet_id.as_slice())
    .fetch_optional(db)
    .await?;

    if let Some(g) = existing {
        return Err(AppError::Conflict(format!(
            "fleet already has key generation {g}"
        )));
    }

    sqlx::query(
        "INSERT INTO v2_fleet_key_generations \
         (tenant_id, fleet_id, generation, fkek_key_id, root_generation, state, created_at) \
         VALUES (?1, ?2, 1, ?3, ?4, ?5, ?6)",
    )
    .bind(tenant_id.as_slice())
    .bind(fleet_id.as_slice())
    .bind(fkek_key_id.as_slice())
    .bind(root_generation)
    .bind(STATE_PREPARING)
    .bind(now)
    .execute(db)
    .await?;

    Ok(1)
}

/// Whether this fleet generation already has its first self-grant.
pub async fn has_self_grant(
    db: &SqlitePool,
    tenant_id: &[u8; 16],
    fleet_id: &[u8; 16],
    generation: u64,
) -> Result<bool, AppError> {
    let row = sqlx::query(
        "SELECT 1 FROM v2_fleet_key_grants \
         WHERE tenant_id = ?1 AND fleet_id = ?2 AND fleet_generation = ?3 \
           AND grant_variant = ?4 LIMIT 1",
    )
    .bind(tenant_id.as_slice())
    .bind(fleet_id.as_slice())
    .bind(generation as i64)
    .bind(VARIANT_FIRST_SELF)
    .fetch_optional(db)
    .await?;
    Ok(row.is_some())
}

/// Check a grant against its generation before it is stored.
///
/// Enforces that the generation exists, that the grant commits to the key that
/// generation was created for, that the first grant is a self-grant, and that
/// custodian grants only follow one.
pub async fn check_grant_against_generation(
    db: &SqlitePool,
    tenant_id: &[u8; 16],
    fleet_id: &[u8; 16],
    generation: u64,
    fkek_key_id: &[u8; 32],
    grant_variant: &str,
) -> Result<(), AppError> {
    let Some(gen) = get_generation(db, tenant_id, fleet_id, generation).await? else {
        return Err(AppError::Conflict(
            "fleet key generation does not exist for this fleet".into(),
        ));
    };

    // A grant naming the right generation but the wrong key would store
    // custody of a key this generation never committed to.
    if &gen.fkek_key_id != fkek_key_id {
        return Err(AppError::Conflict(
            "grant commits to a different fleet key than the generation".into(),
        ));
    }

    if gen.state == STATE_RETIRED {
        return Err(AppError::Conflict(
            "fleet key generation is retired and cannot receive new grants".into(),
        ));
    }

    if grant_variant == VARIANT_FIRST_SELF {
        if gen.state != STATE_PREPARING {
            return Err(AppError::Conflict(
                "a first self-grant is only valid while the generation is preparing".into(),
            ));
        }
        if has_self_grant(db, tenant_id, fleet_id, generation).await? {
            return Err(AppError::Conflict(
                "fleet generation already has a first self-grant".into(),
            ));
        }
    } else if gen.state == STATE_PREPARING {
        // A custodian grant hands the key to another device, which presupposes
        // the key is established. Allowing it during PREPARING would let a
        // fleet skip the bootstrap confirmation.
        return Err(AppError::Conflict(
            "fleet generation is still preparing; file the first self-grant first".into(),
        ));
    }

    Ok(())
}

/// Activate a PREPARING fleet generation.
///
/// Separate from filing the self-grant for the same reason as the root path:
/// filing proves the grant was written, not that anyone can open it. The
/// caller performs the unwrap and only then activates, so a fleet cannot lock
/// itself out by sealing to a key it has already lost.
pub async fn activate_generation(
    db: &SqlitePool,
    tenant_id: &[u8; 16],
    fleet_id: &[u8; 16],
    generation: u64,
    now: &str,
) -> Result<(), AppError> {
    let Some(existing) = get_generation(db, tenant_id, fleet_id, generation).await? else {
        return Err(AppError::Conflict(
            "fleet key generation does not exist for this fleet".into(),
        ));
    };

    // Activation is idempotent: a client that retries after a dropped response
    // must not be told it lost a race it actually won.
    if existing.state == STATE_ACTIVE {
        return Ok(());
    }

    if existing.state == STATE_RETIRED {
        return Err(AppError::Conflict(
            "a retired fleet key generation cannot be activated".into(),
        ));
    }

    if !has_self_grant(db, tenant_id, fleet_id, generation).await? {
        return Err(AppError::Conflict(
            "cannot activate a fleet key generation with no first self-grant".into(),
        ));
    }

    sqlx::query(
        "UPDATE v2_fleet_key_generations SET state = ?1, activated_at = ?2 \
         WHERE tenant_id = ?3 AND fleet_id = ?4 AND generation = ?5",
    )
    .bind(STATE_ACTIVE)
    .bind(now)
    .bind(tenant_id.as_slice())
    .bind(fleet_id.as_slice())
    .bind(generation as i64)
    .execute(db)
    .await?;

    Ok(())
}
