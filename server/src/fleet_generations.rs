//! Fleet key (FKEK) generation lifecycle.
//!
//! Mirrors the root generation lifecycle in `generations.rs`, but for the key
//! profile snapshots are actually encrypted under. The two are deliberately
//! separate: the root key authorises custody and rotates rarely, while a fleet
//! key wraps working data and may need to rotate whenever fleet membership
//! changes. Deriving one from the other would fuse those lifetimes.
//!
//! Generations are created, activated and retired only by the ADR 0002 D-9
//! lifecycle in `routes/v2_fleet.rs`; this module reads the active one.
//!
//! Rows and lookups are keyed by `server_instance_id + tenant_id` like the
//! root generations they rest on.

use crate::error::AppError;
use sqlx::{Row, SqlitePool};

/// The ACTIVE state, mirroring the schema CHECK.
pub const STATE_ACTIVE: &str = "ACTIVE";

/// A fleet key generation as stored.
pub struct FleetGeneration {
    pub generation: u64,
    pub fkek_key_id: [u8; 32],
    pub state: String,
    #[allow(dead_code)]
    pub created_at: String,
    pub activated_at: Option<String>,
}

/// The fleet's ACTIVE generation, if it has one.
///
/// A device asks this to learn which key to encrypt under. Before activation
/// the answer is None, which is what stops a sync from silently falling back
/// to a weaker key path.
pub async fn active_generation(
    db: &SqlitePool,
    instance: &[u8; 16],
    tenant_id: &[u8; 16],
    fleet_id: &[u8; 16],
) -> Result<Option<FleetGeneration>, AppError> {
    let row = sqlx::query(
        "SELECT generation, fkek_key_id, state, created_at, activated_at \
         FROM v2_fleet_key_generations \
         WHERE server_instance_id = ?4 AND tenant_id = ?1 AND fleet_id = ?2 AND state = ?3",
    )
    .bind(tenant_id.as_slice())
    .bind(fleet_id.as_slice())
    .bind(STATE_ACTIVE)
    .bind(instance.as_slice())
    .fetch_optional(db)
    .await?;

    let Some(row) = row else { return Ok(None) };
    let key: Vec<u8> = row.try_get("fkek_key_id")?;
    let fkek_key_id: [u8; 32] = key
        .try_into()
        .map_err(|_| AppError::Internal("stored fkek_key_id is not 32 bytes".into()))?;

    Ok(Some(FleetGeneration {
        generation: crate::util::stored_uint(row.try_get("generation")?)?,
        fkek_key_id,
        state: row.try_get("state")?,
        created_at: row.try_get("created_at")?,
        activated_at: row.try_get("activated_at")?,
    }))
}
