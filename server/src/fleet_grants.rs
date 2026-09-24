//! Persistence for fleet key (FKEK) grants.
//!
//! Same shape as root grant persistence, for the key that actually wraps
//! profile snapshots. Every value written here is read from the *signed* field
//! map, never from the request body: a grant that took its subject or its
//! wrapped key from the body would let a caller present someone else's
//! signature and redirect the custody it authorises.
//!
//! The server stores ciphertext it cannot open. Nothing in this module has
//! access to a fleet key.

use crate::authz::VerifiedRecord;
use crate::error::AppError;
use sqlx::{Row, SqlitePool};

/// The capability a fleet custody grant must carry.
const GRANT_CAPABILITY_FLEET_RECEIVE: &str = "fleet.key.receive";

/// A fleet grant record's fields, all read from the signed container.
pub struct FleetGrantRow {
    pub grant_variant: String,
    pub fleet_id: [u8; 16],
    pub fkek_key_id: [u8; 32],
    pub fleet_generation: u64,
    pub grant_capability: String,
    pub subject_account_id: [u8; 16],
    pub subject_device_id: [u8; 16],
    pub subject_signing_key_id: [u8; 32],
    pub recipient_hpke_key_id: [u8; 32],
    pub hpke_suite_id: u64,
    pub hpke_info_bytes: Vec<u8>,
    pub hpke_encapped_key_bytes: Vec<u8>,
    pub hpke_wrapped_fkek_bytes: Vec<u8>,
    pub issued_at_ms: u64,
    pub not_before_ms: u64,
    pub not_after_ms: u64,
}

/// Read every fleet grant field out of the verified record.
pub fn fleet_grant_row_from_record(record: &VerifiedRecord) -> Result<FleetGrantRow, AppError> {
    fn missing(name: &str) -> AppError {
        AppError::BadRequest(format!("fleet grant record: missing or invalid `{name}`"))
    }

    let grant_capability = record
        .signed_text("grant_capability")
        .ok_or_else(|| missing("grant_capability"))?;

    // A grant that does not claim fleet custody must not be stored as one.
    if grant_capability != GRANT_CAPABILITY_FLEET_RECEIVE {
        return Err(AppError::BadRequest(format!(
            "fleet grant record: capability `{grant_capability}` cannot receive a fleet key"
        )));
    }

    let grant_variant = record
        .signed_text("grant_variant")
        .ok_or_else(|| missing("grant_variant"))?;

    // The column has a CHECK on these two values; rejecting here names the
    // problem instead of surfacing a constraint violation.
    if grant_variant != crate::fleet_generations::VARIANT_FIRST_SELF
        && grant_variant != crate::fleet_generations::VARIANT_DEVICE_HPKE
    {
        return Err(AppError::BadRequest(format!(
            "fleet grant record: unknown grant variant `{grant_variant}`"
        )));
    }

    // Validity window. Section 5.6 requires issued_at <= not_before < not_after,
    // and that the server's clock sits inside the window at filing time. A grant
    // outside its own window is refused rather than stored and honoured later.
    let issued_at_ms = record
        .signed_uint("issued_at_ms")
        .ok_or_else(|| missing("issued_at_ms"))?;
    let not_before_ms = record
        .signed_uint("not_before_ms")
        .ok_or_else(|| missing("not_before_ms"))?;
    let not_after_ms = record
        .signed_uint("not_after_ms")
        .ok_or_else(|| missing("not_after_ms"))?;
    if issued_at_ms > not_before_ms || not_before_ms >= not_after_ms {
        return Err(AppError::BadRequest(
            "fleet grant record: validity window must satisfy issued_at_ms <= not_before_ms < not_after_ms"
                .into(),
        ));
    }
    let now_ms = u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0);
    if now_ms < not_before_ms || now_ms >= not_after_ms {
        return Err(AppError::BadRequest(
            "fleet grant record: not valid at the current server time".into(),
        ));
    }

    Ok(FleetGrantRow {
        grant_variant,
        fleet_id: record
            .signed_id16("fleet_id")
            .ok_or_else(|| missing("fleet_id"))?,
        fkek_key_id: record
            .signed_hash32("fkek_key_id")
            .ok_or_else(|| missing("fkek_key_id"))?,
        fleet_generation: record
            .signed_uint("generation")
            .ok_or_else(|| missing("generation"))?,
        grant_capability,
        subject_account_id: record
            .signed_id16("subject_account_id")
            .ok_or_else(|| missing("subject_account_id"))?,
        subject_device_id: record
            .signed_id16("subject_device_id")
            .ok_or_else(|| missing("subject_device_id"))?,
        subject_signing_key_id: record
            .signed_hash32("subject_signing_key_id")
            .ok_or_else(|| missing("subject_signing_key_id"))?,
        recipient_hpke_key_id: record
            .signed_hash32("recipient_hpke_key_id")
            .ok_or_else(|| missing("recipient_hpke_key_id"))?,
        hpke_suite_id: record
            .signed_uint("hpke_suite_id")
            .ok_or_else(|| missing("hpke_suite_id"))?,
        hpke_info_bytes: record
            .signed_bytes("hpke_info_bytes")
            .ok_or_else(|| missing("hpke_info_bytes"))?,
        hpke_encapped_key_bytes: record
            .signed_bytes("hpke_encapped_key_bytes")
            .ok_or_else(|| missing("hpke_encapped_key_bytes"))?,
        hpke_wrapped_fkek_bytes: record
            .signed_bytes("hpke_wrapped_fkek_bytes")
            .ok_or_else(|| missing("hpke_wrapped_fkek_bytes"))?,
        issued_at_ms,
        not_before_ms,
        not_after_ms,
    })
}

/// Store a verified fleet grant.
#[allow(clippy::too_many_arguments)]
pub async fn insert_fleet_grant(
    pool: &SqlitePool,
    tenant_id: &[u8; 16],
    server_instance_id: &[u8; 16],
    restore_epoch: u64,
    record: &VerifiedRecord,
    exact_signed_container_bytes: &[u8],
    row: &FleetGrantRow,
    now: &str,
) -> Result<(), AppError> {
    // The subject must be enrolled in this tenant. Without this a grant could
    // name a device from elsewhere and park custody where it does not belong.
    let device_exists =
        sqlx::query("SELECT 1 FROM v2_devices WHERE tenant_id = ? AND id = ? LIMIT 1")
            .bind(tenant_id.as_slice())
            .bind(row.subject_device_id.as_slice())
            .fetch_optional(pool)
            .await?
            .is_some();

    if !device_exists {
        return Err(AppError::BadRequest(
            "fleet grant record: subject device is not enrolled in this tenant".into(),
        ));
    }

    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(exact_signed_container_bytes);
    let container_sha: [u8; 32] = h.finalize().into();

    sqlx::query(
        "INSERT INTO v2_fleet_key_grants (
             tenant_id, replay_id, payload_domain, grant_variant,
             fleet_id, fkek_key_id, fleet_generation, grant_capability,
             subject_account_id, subject_device_id, subject_signing_key_id,
             recipient_hpke_key_id,
             hpke_suite_id,
             hpke_info_bytes, hpke_encapped_key_bytes, hpke_wrapped_fkek_bytes,
             issued_at_ms, not_before_ms, not_after_ms,
             server_instance_id, restore_epoch,
             signature_bytes, issuer_signing_key_id,
             signed_container_hash, exact_signed_container_bytes,
             exact_signed_container_bytes_sha256, created_at
         ) VALUES (
             ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
             ?, ?, ?, ?, ?, ?, ?
         )",
    )
    .bind(tenant_id.as_slice())
    .bind(record.replay_id.as_slice())
    .bind(&record.domain)
    .bind(&row.grant_variant)
    .bind(row.fleet_id.as_slice())
    .bind(row.fkek_key_id.as_slice())
    .bind(row.fleet_generation as i64)
    .bind(&row.grant_capability)
    .bind(row.subject_account_id.as_slice())
    .bind(row.subject_device_id.as_slice())
    .bind(row.subject_signing_key_id.as_slice())
    .bind(row.recipient_hpke_key_id.as_slice())
    .bind(row.hpke_suite_id as i64)
    .bind(&row.hpke_info_bytes)
    .bind(&row.hpke_encapped_key_bytes)
    .bind(&row.hpke_wrapped_fkek_bytes)
    .bind(row.issued_at_ms as i64)
    .bind(row.not_before_ms as i64)
    .bind(row.not_after_ms as i64)
    .bind(server_instance_id.as_slice())
    .bind(restore_epoch as i64)
    .bind(record.signature_bytes.as_slice())
    .bind(record.issuer_signing_key_id.as_slice())
    .bind(record.signed_container_hash.as_slice())
    .bind(exact_signed_container_bytes)
    .bind(container_sha.as_slice())
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}

/// A stored fleet grant, as returned to a collecting device.
pub struct StoredFleetGrant {
    pub grant_variant: String,
    pub fleet_id: Vec<u8>,
    pub fkek_key_id: Vec<u8>,
    pub fleet_generation: i64,
    pub recipient_hpke_key_id: Vec<u8>,
    pub hpke_info_bytes: Vec<u8>,
    pub hpke_encapped_key_bytes: Vec<u8>,
    pub hpke_wrapped_fkek_bytes: Vec<u8>,
    pub exact_signed_container_bytes: Vec<u8>,
    pub created_at: String,
}

/// Every fleet grant addressed to one device.
///
/// Ordered newest generation first so a collector can take the newest key it
/// can actually open without scanning the whole set.
pub async fn fleet_grants_for_device(
    pool: &SqlitePool,
    tenant_id: &[u8; 16],
    device_id: &[u8; 16],
) -> Result<Vec<StoredFleetGrant>, AppError> {
    let rows = sqlx::query(
        "SELECT grant_variant, fleet_id, fkek_key_id, fleet_generation, \
                recipient_hpke_key_id, hpke_info_bytes, hpke_encapped_key_bytes, \
                hpke_wrapped_fkek_bytes, exact_signed_container_bytes, created_at \
         FROM v2_fleet_key_grants \
         WHERE tenant_id = ?1 AND subject_device_id = ?2 \
         ORDER BY fleet_generation DESC, created_at DESC",
    )
    .bind(tenant_id.as_slice())
    .bind(device_id.as_slice())
    .fetch_all(pool)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(StoredFleetGrant {
            grant_variant: row.try_get("grant_variant")?,
            fleet_id: row.try_get("fleet_id")?,
            fkek_key_id: row.try_get("fkek_key_id")?,
            fleet_generation: row.try_get("fleet_generation")?,
            recipient_hpke_key_id: row.try_get("recipient_hpke_key_id")?,
            hpke_info_bytes: row.try_get("hpke_info_bytes")?,
            hpke_encapped_key_bytes: row.try_get("hpke_encapped_key_bytes")?,
            hpke_wrapped_fkek_bytes: row.try_get("hpke_wrapped_fkek_bytes")?,
            exact_signed_container_bytes: row.try_get("exact_signed_container_bytes")?,
            created_at: row.try_get("created_at")?,
        });
    }
    Ok(out)
}
