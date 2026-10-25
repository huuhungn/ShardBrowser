//! `POST /v2/capability-grants`: an ACTIVE root custodian files a
//! `TenantCapabilityGrantV2` (plan 5.6.1, 7.2; ADR 0001 D2; ADR 0002 D-2,
//! D-6).
//!
//! The body is the exact `SignedAuthorizationRecordV2<TenantCapabilityGrantV2>`
//! container, signed by the presenting device. One `BEGIN IMMEDIATE` checks
//! that the issuer is an ACTIVE root custodian on a live session, that the
//! grant names this instance and epoch, lies inside its window and the D-6
//! TTL, and names a live subject under its exact keys and an existing scope;
//! then it files the row, every column taken from the verified record, and the
//! audit row together. The same bytes again get the same answer; other bytes
//! under the same replay ID are refused.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use sqlx::SqliteConnection;

use shared::approval_receipt::MAX_CAPABILITY_GRANT_TTL_MS;
use shared::authz_record::{
    AuthorizationRecord, CapabilityScopeKind, GrantSubject, Payload, TenantCapabilityGrantV2,
    DOMAIN_TENANT_CAPABILITY_GRANT,
};

use super::v2_approval::{cbor, coded, column_mismatch, exact_cbor_body, int};
use super::v2_auth::{audit, reload_session, verified, Principal};
use super::v2_root::{insert_row, mismatch, record_error, row_holds, stale, Col};
use super::v2_root_grants::is_active_custodian;
use crate::error::AppError;
use crate::quarantine::{self, Kind, Mark};
use crate::state::AppState;
use crate::util::{now_ms, now_rfc3339};

/// The exact container is stored whole, within the table's bound.
pub const MAX_CAPABILITY_GRANT_BODY: usize = 131_072;
pub(crate) const TABLE: &str = "v2_capability_grants";

/// Every plan 7.2 column of a capability grant row except `created_at` and
/// `revoked_at`, each derived from the verified record. Filing and the retry
/// check both use this list.
fn grant_columns(
    g: &TenantCapabilityGrantV2,
    record: &AuthorizationRecord,
) -> Result<Vec<(&'static str, Col)>, AppError> {
    let c = &g.common;
    let b = |bytes: &[u8]| Col::Blob(bytes.to_vec());
    let (kind, account, device, signing, hpke) = match &g.subject {
        GrantSubject::Account { account_id } => {
            ("account", b(account_id), Col::Null, Col::Null, Col::Null)
        }
        GrantSubject::Device {
            account_id,
            device_id,
            signing_key_id,
            hpke_key_id,
        } => (
            "device",
            b(account_id),
            b(device_id),
            b(signing_key_id),
            b(hpke_key_id),
        ),
    };
    let (suite, version) = record.signature_suite();
    Ok(vec![
        ("server_instance_id", b(&c.server_instance_id)),
        ("tenant_id", b(&c.tenant_id)),
        ("replay_id", b(&c.replay_id)),
        ("payload_domain", Col::Text(DOMAIN_TENANT_CAPABILITY_GRANT)),
        ("payload_version", Col::Int(2)),
        ("subject_kind", Col::Text(kind)),
        ("subject_account_id", account),
        ("subject_device_id", device),
        ("subject_signing_key_id", signing),
        ("subject_hpke_key_id", hpke),
        ("scope_kind", Col::Text(g.scope_kind.as_str())),
        ("scope_id", b(&g.scope_id)),
        ("capability", Col::Text(g.capability.as_str())),
        ("issued_at_ms", Col::Int(int(c.issued_at_ms)?)),
        ("not_before_ms", Col::Int(int(c.not_before_ms)?)),
        ("not_after_ms", Col::Int(int(c.not_after_ms)?)),
        ("restore_epoch", Col::Int(int(c.restore_epoch)?)),
        (
            "canonical_payload_bytes",
            b(record.canonical_payload_bytes()),
        ),
        ("payload_sha256", b(record.payload_sha256())),
        ("signature_suite_id", Col::Int(i64::from(suite))),
        ("signature_version", Col::Int(i64::from(version))),
        ("signature_bytes", b(record.signature_bytes())),
        ("issuer_signing_key_id", b(record.issuer_signing_key_id())),
        ("signed_container_hash", b(record.signed_container_hash())),
        (
            "exact_signed_container_bytes",
            b(record.exact_signed_container_bytes()),
        ),
        (
            "exact_signed_container_bytes_sha256",
            b(record.exact_signed_container_bytes_sha256()),
        ),
    ])
}

/// The subject exists and is live under exactly the keys the grant names: an
/// active account of the tenant, and for a device subject, its active device.
async fn subject_is_live(
    conn: &mut SqliteConnection,
    g: &TenantCapabilityGrantV2,
) -> Result<bool, AppError> {
    let tenant = g.common.tenant_id;
    let (account, device) = match &g.subject {
        GrantSubject::Account { account_id } => (account_id, None),
        GrantSubject::Device {
            account_id,
            device_id,
            signing_key_id,
            hpke_key_id,
        } => (account_id, Some((device_id, signing_key_id, hpke_key_id))),
    };
    let account_ok: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM v2_accounts
                         WHERE tenant_id = ? AND id = ? AND status = 'active')",
    )
    .bind(tenant.as_slice())
    .bind(account.as_slice())
    .fetch_one(&mut *conn)
    .await?;
    let Some((device, signing, hpke)) = device else {
        return Ok(account_ok);
    };
    let device_ok: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM v2_devices
                         WHERE tenant_id = ? AND id = ? AND account_id = ? AND status = 'active'
                           AND signing_key_id = ? AND hpke_key_id = ?)",
    )
    .bind(tenant.as_slice())
    .bind(device.as_slice())
    .bind(account.as_slice())
    .bind(signing.as_slice())
    .bind(hpke.as_slice())
    .fetch_one(&mut *conn)
    .await?;
    Ok(account_ok && device_ok)
}

/// The scope exists: the tenant itself, or an active fleet or profile of it.
async fn scope_exists(
    conn: &mut SqliteConnection,
    g: &TenantCapabilityGrantV2,
) -> Result<bool, AppError> {
    let table = match g.scope_kind {
        // The codec already holds a tenant scope to the grant's tenant.
        CapabilityScopeKind::Tenant => return Ok(true),
        CapabilityScopeKind::Fleet => "v2_fleets",
        CapabilityScopeKind::Profile => "v2_profiles",
    };
    Ok(sqlx::query_scalar(&format!(
        "SELECT EXISTS (SELECT 1 FROM {table}
                         WHERE tenant_id = ? AND id = ? AND status = 'active')"
    ))
    .bind(g.common.tenant_id.as_slice())
    .bind(g.scope_id.as_slice())
    .fetch_one(&mut *conn)
    .await?)
}

/// A replay ID is spent by any grant ever filed under it, spike rows included.
async fn replay_spent(
    conn: &mut SqliteConnection,
    g: &TenantCapabilityGrantV2,
) -> Result<bool, AppError> {
    for table in [TABLE, "v2_legacy_capability_grants"] {
        let spent: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS (SELECT 1 FROM {table}
                             WHERE tenant_id = ? AND payload_domain = ? AND replay_id = ?)"
        ))
        .bind(g.common.tenant_id.as_slice())
        .bind(DOMAIN_TENANT_CAPABILITY_GRANT)
        .bind(g.common.replay_id.as_slice())
        .fetch_one(&mut *conn)
        .await?;
        if spent {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The exact container a row of this table holds under `replay`.
async fn stored_bytes(
    conn: &mut SqliteConnection,
    tenant: &[u8; 16],
    replay: &[u8; 16],
) -> Result<Option<Vec<u8>>, AppError> {
    Ok(sqlx::query_scalar(&format!(
        "SELECT exact_signed_container_bytes FROM {TABLE}
          WHERE tenant_id = ? AND payload_domain = ? AND replay_id = ?"
    ))
    .bind(tenant.as_slice())
    .bind(DOMAIN_TENANT_CAPABILITY_GRANT)
    .bind(replay.as_slice())
    .fetch_optional(&mut *conn)
    .await?)
}

/// Whether the row `(tenant, replay)` holds exactly what its own container
/// says: the container parses, verifies under its issuer device's key, names
/// this row's key, and every column equals the record's. The startup
/// integrity pass quarantines a row for which this is false.
pub(crate) async fn stored_row_matches(
    conn: &mut SqliteConnection,
    instance: &[u8; 16],
    tenant: &[u8; 16],
    replay: &[u8; 16],
) -> Result<bool, AppError> {
    let Some(exact) = stored_bytes(conn, tenant, replay).await? else {
        return Ok(false);
    };
    let Ok(parsed) = AuthorizationRecord::parse(&exact) else {
        return Ok(false);
    };
    let issuer: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT signing_public_key FROM v2_devices WHERE tenant_id = ? AND signing_key_id = ?",
    )
    .bind(tenant.as_slice())
    .bind(parsed.issuer_signing_key_id().as_slice())
    .fetch_optional(&mut *conn)
    .await?;
    let Some(issuer) = issuer.and_then(|k| <[u8; 32]>::try_from(k).ok()) else {
        return Ok(false);
    };
    let Ok(record) = parsed.verify_signature(&issuer) else {
        return Ok(false);
    };
    let Payload::TenantCapabilityGrant(g) = record.payload() else {
        return Ok(false);
    };
    let c = &g.common;
    if (&c.server_instance_id, &c.tenant_id, &c.replay_id) != (instance, tenant, replay) {
        return Ok(false);
    }
    let cols = grant_columns(g, record.record())?;
    row_holds(conn, TABLE, &cols).await
}

pub async fn file_capability_grant(
    State(app): State<AppState>,
    who: Principal,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let v = verified(&app)?;
    // A ticket proves only a password; a grant needs its issuer's session.
    let Principal::Session(presented) = who else {
        return Err(AppError::Forbidden);
    };
    exact_cbor_body(&headers, &body, MAX_CAPABILITY_GRANT_BODY)?;
    let parsed = AuthorizationRecord::parse(&body).map_err(record_error)?;

    let mut tx = app.db.begin_with("BEGIN IMMEDIATE").await?;
    let now = now_ms();
    let s = reload_session(&mut tx, &presented, v, now)
        .await?
        .ok_or(AppError::Unauthorized)?;
    // The issuer is the presenting device, verified under its own key.
    if parsed.issuer_signing_key_id() != &s.signing_key_id {
        return Err(AppError::Forbidden);
    }
    let issuer: Vec<u8> = sqlx::query_scalar(
        "SELECT signing_public_key FROM v2_devices
          WHERE tenant_id = ? AND id = ? AND signing_key_id = ?",
    )
    .bind(s.tenant_id.as_slice())
    .bind(s.device_id.as_slice())
    .bind(s.signing_key_id.as_slice())
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::Unauthorized)?;
    let issuer: [u8; 32] = issuer.try_into().map_err(|_| AppError::Unauthorized)?;
    let record = parsed.verify_signature(&issuer).map_err(record_error)?;
    let Payload::TenantCapabilityGrant(g) = record.payload().clone() else {
        return Err(column_mismatch("the record is not a capability grant"));
    };
    let c = &g.common;
    if c.tenant_id != s.tenant_id || c.server_instance_id != v.server_instance_id {
        return Err(AppError::Forbidden);
    }
    if c.restore_epoch != v.restore_epoch {
        return Err(stale());
    }
    // Custody comes only from root grants (Q-2).
    if !g.is_issuable() {
        return Err(AppError::Forbidden);
    }
    let cols = grant_columns(&g, record.record())?;

    // A lost response: the same bytes, filed as these exact columns, get the
    // same answer, even after the issuer's custody or the grant itself ended,
    // as every stored response does. Anything else under the replay ID is
    // another request; only a custodian learns that the ID is spent.
    if replay_spent(&mut tx, &g).await? {
        let mark = Mark {
            kind: Kind::CapabilityGrant,
            server_instance_id: c.server_instance_id,
            tenant_id: c.tenant_id,
            replay_id: c.replay_id,
        };
        if quarantine::holds(&mut tx, &mark).await? {
            return Err(AppError::Quarantine(Box::new(mark)));
        }
        if !row_holds(&mut tx, TABLE, &cols).await? {
            // The same bytes filed as other columns: the row drifted from its
            // container (plan 5.6.1).
            if stored_bytes(&mut tx, &c.tenant_id, &c.replay_id)
                .await?
                .as_deref()
                == Some(&body[..])
            {
                return Err(AppError::Quarantine(Box::new(mark)));
            }
            if !is_active_custodian(&mut tx, v, &s, now).await? {
                return Err(AppError::Forbidden);
            }
            return Err(mismatch());
        }
        tx.commit().await?;
        return Ok(cbor(StatusCode::CREATED, body.to_vec()));
    }

    // ADR 0001 D2: only an ACTIVE root custodian issues capability grants.
    // shortcut: the first device's `root_setup` session is the only live one
    // until ordinary sessions exist; the custody check, not the class,
    // authorizes (ADR 0001 R2).
    if !is_active_custodian(&mut tx, v, &s, now).await? {
        return Err(AppError::Forbidden);
    }
    if !inside_window(&g, now)? || c.not_after_ms - c.not_before_ms > MAX_CAPABILITY_GRANT_TTL_MS {
        return Err(AppError::Forbidden);
    }
    if !subject_is_live(&mut tx, &g).await? {
        return Err(column_mismatch(
            "the grant names no active subject under these keys",
        ));
    }
    if !scope_exists(&mut tx, &g).await? {
        return Err(coded(
            StatusCode::NOT_FOUND,
            "RESOURCE_NOT_FOUND",
            "the grant names no such fleet or profile",
        ));
    }

    insert_row(&mut tx, TABLE, &cols, &now_rfc3339()).await?;
    audit(
        &mut tx,
        &s.tenant_id,
        &s.account_id,
        &s.device_id,
        "capability.grant",
        "capability_grant",
        &c.replay_id,
    )
    .await?;
    tx.commit().await?;
    Ok(cbor(StatusCode::CREATED, body.to_vec()))
}

fn inside_window(g: &TenantCapabilityGrantV2, now: i64) -> Result<bool, AppError> {
    Ok(int(g.common.not_before_ms)? <= now && now < int(g.common.not_after_ms)?)
}
