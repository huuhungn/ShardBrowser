//! Root key generation reads.
//!
//! Generations are created by the S6 bootstrap (`routes::v2_root`) and, later,
//! by rotation; activation follows readback and acknowledgement (plan 5.6.4).
//! What remains here is the read side: which generation is ACTIVE.
//!
//! Every row and lookup is keyed by `server_instance_id + tenant_id` (plan
//! 7.2/7.4): callers pass the instance the startup check verified.

use crate::error::AppError;
use sqlx::{Row, SqlitePool};

/// The one state a sync may use (schema CHECK: PREPARING, ACTIVE, RETIRED).
pub const STATE_ACTIVE: &str = "ACTIVE";

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

/// The tenant's ACTIVE generation, if it has one.
///
/// A device asks this to learn which generation to seal under. Before any
/// generation is activated the answer is None, which is what stops a sync from
/// silently falling back to an older key path.
pub async fn active_generation(
    db: &SqlitePool,
    instance: &[u8; 16],
    tenant_id: &[u8; 16],
) -> Result<Option<Generation>, AppError> {
    let row = sqlx::query(
        "SELECT generation, root_key_id, state, created_at, activated_at \
         FROM v2_root_key_generations \
         WHERE server_instance_id = ?3 AND tenant_id = ?1 AND state = ?2",
    )
    .bind(tenant_id.as_slice())
    .bind(STATE_ACTIVE)
    .bind(instance.as_slice())
    .fetch_optional(db)
    .await?;

    let Some(row) = row else { return Ok(None) };
    let key: Vec<u8> = row.try_get("root_key_id")?;
    let root_key_id: [u8; 32] = key
        .try_into()
        .map_err(|_| AppError::Internal("stored root_key_id is not 32 bytes".into()))?;

    Ok(Some(Generation {
        generation: crate::util::stored_uint(row.try_get("generation")?)?,
        root_key_id,
        state: row.try_get("state")?,
        created_at: row.try_get("created_at")?,
        activated_at: row.try_get("activated_at")?,
    }))
}
