//! Quarantine of stored grants whose rows disagree with their signed
//! containers (plan 5.6.1, 5.6.4).
//!
//! A request that finds such a row is refused with `AUTH_CLAIM_COLUMN_MISMATCH`
//! and its transaction rolls back, so the refusal carries a [`Mark`] that the
//! router records in a transaction of its own. The startup integrity pass
//! records the rows it finds the same way. A quarantined grant is refused for
//! good, even if its row is later put back.

use sqlx::{SqliteConnection, SqlitePool};

use crate::util;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    RootGrant,
    CapabilityGrant,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Self::RootGrant => "root_grant",
            Self::CapabilityGrant => "capability_grant",
        }
    }
}

/// The grant a refusal quarantines, by its row key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mark {
    pub kind: Kind,
    pub server_instance_id: [u8; 16],
    pub tenant_id: [u8; 16],
    pub replay_id: [u8; 16],
}

/// Records `mark`; `true` if the grant was not quarantined before.
pub async fn record(pool: &SqlitePool, mark: &Mark) -> sqlx::Result<bool> {
    let done = sqlx::query(
        "INSERT INTO v2_grant_quarantine
             (kind, server_instance_id, tenant_id, replay_id, reason, created_at)
         SELECT ?1, ?2, ?3, ?4, 'container_mismatch', ?5
          WHERE NOT EXISTS (SELECT 1 FROM v2_grant_quarantine
                             WHERE kind = ?1 AND server_instance_id = ?2
                               AND tenant_id = ?3 AND replay_id = ?4)",
    )
    .bind(mark.kind.as_str())
    .bind(mark.server_instance_id.as_slice())
    .bind(mark.tenant_id.as_slice())
    .bind(mark.replay_id.as_slice())
    .bind(util::now_rfc3339())
    .execute(pool)
    .await?;
    let new = done.rows_affected() == 1;
    if new {
        tracing::warn!(
            kind = mark.kind.as_str(),
            "quarantined a stored grant that does not match its signed container"
        );
    }
    Ok(new)
}

/// Whether `mark`'s grant is quarantined.
pub async fn holds(conn: &mut SqliteConnection, mark: &Mark) -> sqlx::Result<bool> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM v2_grant_quarantine
                         WHERE kind = ? AND server_instance_id = ? AND tenant_id = ?
                           AND replay_id = ?)",
    )
    .bind(mark.kind.as_str())
    .bind(mark.server_instance_id.as_slice())
    .bind(mark.tenant_id.as_slice())
    .bind(mark.replay_id.as_slice())
    .fetch_one(conn)
    .await
}
