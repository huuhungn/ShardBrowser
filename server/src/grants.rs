//! Root key grant reads for device collection.
//!
//! A grant is how a device obtains the tenant root key: the key sealed to that
//! device's HPKE public key, wrapped so the server stores it without being able
//! to open it. Grants are written by the root generation endpoints
//! (`routes::v2_root`) from the exact signed record; this lists what a device
//! may collect. Rows of the earlier spike shape stay in
//! `v2_legacy_tenant_root_key_grants` and are not listed.

use crate::error::AppError;
use sqlx::{Row, SqlitePool};

/// A grant as handed back to a device that is collecting its root key.
pub struct StoredGrant {
    pub grant_variant: String,
    pub root_key_id: Vec<u8>,
    pub root_generation: i64,
    pub recipient_hpke_key_id: Vec<u8>,
    pub hpke_info_bytes: Vec<u8>,
    pub hpke_encapped_key_bytes: Vec<u8>,
    pub hpke_wrapped_trk_bytes: Vec<u8>,
    pub exact_signed_container_bytes: Vec<u8>,
    pub created_at: String,
}

/// Fetch the grants issued to one device, newest root generation first.
///
/// shortcut: this v1 route skips the 5.6.4 readback (R2 device session,
/// reparse and column equality), so it lists only grants of an `ACTIVE`
/// generation; a `PREPARING` bootstrap grant is not served here. Replace it
/// with `GET .../root-key-generations/{g}/grants/{replay_id}` when that lands.
///
/// Revoked grants are excluded. Revocation blocks a device that has not yet
/// collected the key; it cannot retract a key already copied, which is why
/// excluding a device means rotating the generation rather than revoking alone.
pub async fn grants_for_device(
    pool: &SqlitePool,
    tenant_id: &[u8; 16],
    device_id: &[u8; 16],
) -> Result<Vec<StoredGrant>, AppError> {
    let rows = sqlx::query(
        "SELECT grant_variant, root_key_id, root_generation, recipient_hpke_key_id,
                hpke_info_bytes, hpke_encapped_key_bytes, hpke_wrapped_trk_bytes,
                exact_signed_container_bytes, created_at
           FROM v2_tenant_root_key_grants r
          WHERE tenant_id = ? AND subject_device_id = ? AND revoked_at IS NULL
            AND EXISTS (SELECT 1 FROM v2_root_key_generations g
                         WHERE g.server_instance_id = r.server_instance_id
                           AND g.tenant_id = r.tenant_id
                           AND g.generation = r.root_generation
                           AND g.state = 'ACTIVE')
          ORDER BY root_generation DESC, created_at DESC",
    )
    .bind(tenant_id.as_slice())
    .bind(device_id.as_slice())
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| StoredGrant {
            grant_variant: r.get("grant_variant"),
            root_key_id: r.get("root_key_id"),
            root_generation: r.get("root_generation"),
            recipient_hpke_key_id: r.get("recipient_hpke_key_id"),
            hpke_info_bytes: r.get("hpke_info_bytes"),
            hpke_encapped_key_bytes: r.get("hpke_encapped_key_bytes"),
            hpke_wrapped_trk_bytes: r.get("hpke_wrapped_trk_bytes"),
            exact_signed_container_bytes: r.get("exact_signed_container_bytes"),
            created_at: r.get("created_at"),
        })
        .collect())
}
