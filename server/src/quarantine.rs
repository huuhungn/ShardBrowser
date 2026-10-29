//! Quarantine of stored grants whose rows disagree with their signed
//! containers (plan 5.6.1, 5.6.4).
//!
//! A request that finds such a row is refused with `AUTH_CLAIM_COLUMN_MISMATCH`
//! and its transaction rolls back, so the refusal carries a [`Mark`] that the
//! router records in a transaction of its own. The startup integrity pass
//! records the rows it finds the same way. A quarantined grant is refused for
//! good, even if its row is later put back.

use sha2::{Digest, Sha256};
use sqlx::{SqliteConnection, SqlitePool};

use crate::util;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    RootGrant,
    CapabilityGrant,
    FleetDeviceHpke,
    FleetRecovery,
    FleetRotation,
    DeviceApproval,
    DeviceRevocation,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Self::RootGrant => "root_grant",
            Self::CapabilityGrant => "capability_grant",
            Self::FleetDeviceHpke => "fleet_device_hpke_grant",
            Self::FleetRecovery => "fleet_recovery_grant",
            Self::FleetRotation => "fleet_rotation_grant",
            Self::DeviceApproval => "device_approval",
            Self::DeviceRevocation => "device_revocation",
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

/// Records `mark`; `true` if the grant was not quarantined before. A device
/// revocation's mark also records the SHA-256 of the container bytes its row
/// holds now (none if the row is gone), so that only that container can be
/// served again.
pub async fn record(pool: &SqlitePool, mark: &Mark) -> sqlx::Result<bool> {
    let container_sha256 = if mark.kind == Kind::DeviceRevocation {
        sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT exact_signed_container_bytes FROM v2_device_revocations
              WHERE server_instance_id = ? AND tenant_id = ? AND replay_id = ?",
        )
        .bind(mark.server_instance_id.as_slice())
        .bind(mark.tenant_id.as_slice())
        .bind(mark.replay_id.as_slice())
        .fetch_optional(pool)
        .await?
        .map(|bytes| Sha256::digest(bytes).to_vec())
    } else {
        None
    };
    let done = sqlx::query(
        "INSERT INTO v2_grant_quarantine
             (kind, server_instance_id, tenant_id, replay_id, reason, created_at,
              container_sha256)
         SELECT ?1, ?2, ?3, ?4, 'container_mismatch', ?5, ?6
          WHERE NOT EXISTS (SELECT 1 FROM v2_grant_quarantine
                             WHERE kind = ?1 AND server_instance_id = ?2
                               AND tenant_id = ?3 AND replay_id = ?4)",
    )
    .bind(mark.kind.as_str())
    .bind(mark.server_instance_id.as_slice())
    .bind(mark.tenant_id.as_slice())
    .bind(mark.replay_id.as_slice())
    .bind(util::now_rfc3339())
    .bind(container_sha256)
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

/// The container hash recorded with `mark`'s quarantine: `None` if it is not
/// quarantined, `Some(None)` if no hash was recorded.
pub async fn recorded_container_sha256(
    conn: &mut SqliteConnection,
    mark: &Mark,
) -> sqlx::Result<Option<Option<Vec<u8>>>> {
    sqlx::query_scalar(
        "SELECT container_sha256 FROM v2_grant_quarantine
          WHERE kind = ? AND server_instance_id = ? AND tenant_id = ? AND replay_id = ?",
    )
    .bind(mark.kind.as_str())
    .bind(mark.server_instance_id.as_slice())
    .bind(mark.tenant_id.as_slice())
    .bind(mark.replay_id.as_slice())
    .fetch_optional(conn)
    .await
}
