//! `POST /v2/devices/{id}/approve`: the D1 first-device approval and its
//! exact-response replay (ADR 0001 D1, R1-R3).
//!
//! The body is the exact `SignedAuthorizationRecordV2<DeviceApprovalV2>`
//! container. A first request runs every D1 guard under one `BEGIN IMMEDIATE`
//! and commits the approval, the `v2_idempotency` row holding the exact
//! receipt, the consumed confirmation, the consumed guard, the active device,
//! the promoted session and the audit row together. A retry with the same
//! bytes by the same actor gets the stored receipt back, unchanged, after the
//! stored row has been checked against the approval it names and the actor's
//! authority has been rechecked live.
//!
//! After D1, an approval is ordinary (ADR 0002 D-2): a root custodian holding
//! a device-scoped `device.approve` over the approval's scope approves a
//! pending device of its tenant, or renews its own live approval. Its receipt
//! names no confirmation, and its retry rechecks that authority live.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use sqlx::{Row, SqliteConnection};

use shared::approval_receipt::{
    device_approve_request_hash, DeviceApprovalReceiptV2, AUTHORIZATION_REPLAY_RETENTION_MS,
    DEVICE_APPROVE_SCOPE, MAX_DEVICE_APPROVAL_TTL_MS,
};
use shared::authz_record::{
    ApprovalScopeKind, AuthorizationRecord, Capability, DeviceApprovalV2, Payload,
    DOMAIN_DEVICE_APPROVAL,
};
use shared::canonical::sha256;

use super::v2_auth::{
    audit, blob, epoch, reload_session, revoke_challenge, unhex, verified, Principal, Session,
    DEVICE_SESSION_CHALLENGES,
};
use super::v2_fleet::holds_capability;
use crate::error::AppError;
use crate::identity::Verified;
use crate::integrity::derive_device_key_ids;
use crate::state::AppState;
use crate::util::{now_ms, now_rfc3339};

/// R3 body cap for the exact signed container.
pub const MAX_APPROVAL_BODY: usize = 262_144;
const RECEIPT_TYPE: &str = "DeviceApprovalReceiptV2";
const CBOR: &str = "application/cbor";

pub(super) fn coded(status: StatusCode, code: &'static str, msg: &str) -> AppError {
    AppError::Coded(status, code, msg.into())
}

fn mismatch() -> AppError {
    coded(
        StatusCode::CONFLICT,
        "IDEMPOTENCY_MISMATCH",
        "this approval replay ID is already used by another request",
    )
}

fn stale() -> AppError {
    coded(
        StatusCode::CONFLICT,
        "STALE_CONTEXT",
        "the approval names another restore epoch",
    )
}

fn closed() -> AppError {
    coded(
        StatusCode::CONFLICT,
        "FIRST_DEVICE_ALREADY_CLOSED",
        "this tenant's first-device approval is no longer open",
    )
}

pub(super) fn column_mismatch(msg: &str) -> AppError {
    coded(
        StatusCode::UNPROCESSABLE_ENTITY,
        "AUTH_CLAIM_COLUMN_MISMATCH",
        msg,
    )
}

pub(super) fn int(n: u64) -> Result<i64, AppError> {
    i64::try_from(n).map_err(|_| {
        coded(
            StatusCode::UNPROCESSABLE_ENTITY,
            "WIRE_INTEGER_OUT_OF_RANGE",
            "an integer is outside the storage range",
        )
    })
}

pub(super) fn cbor(status: StatusCode, bytes: Vec<u8>) -> Response {
    (status, [(header::CONTENT_TYPE, CBOR)], bytes).into_response()
}

/// The body is exact CBOR bytes: no other media type, no content encoding,
/// and within `max`.
pub(super) fn exact_cbor_body(
    headers: &HeaderMap,
    body: &[u8],
    max: usize,
) -> Result<(), AppError> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok());
    if content_type != Some(CBOR) || headers.contains_key(header::CONTENT_ENCODING) {
        return Err(AppError::BadRequest(
            "send the exact bytes as application/cbor, unencoded".into(),
        ));
    }
    if body.is_empty() || body.len() > max {
        return Err(AppError::BadRequest(
            "the body is empty or too large".into(),
        ));
    }
    Ok(())
}

/// The verified approval and the facts every later step compares with.
struct Request {
    record: AuthorizationRecord,
    approval: DeviceApprovalV2,
    request_hash: [u8; 32],
}

pub async fn approve_device(
    State(app): State<AppState>,
    who: Principal,
    Path(device): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let v = verified(&app)?;
    // A ticket proves only a password; approval needs a device session.
    let Principal::Session(presented) = who else {
        return Err(AppError::Forbidden);
    };
    let path_device = unhex::<16>(&device)
        .ok_or_else(|| AppError::BadRequest("device id must be 32 hex digits".into()))?;
    exact_cbor_body(&headers, &body, MAX_APPROVAL_BODY)?;
    let parsed = AuthorizationRecord::parse(&body)
        .map_err(|e| coded(StatusCode::UNPROCESSABLE_ENTITY, e.code(), &e.to_string()))?;
    if parsed.payload_domain() != DOMAIN_DEVICE_APPROVAL {
        return Err(column_mismatch("the record is not a device approval"));
    }

    let mut tx = app.db.begin_with("BEGIN IMMEDIATE").await?;
    let now = now_ms();
    let s = reload_session(&mut tx, &presented, v, now)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let req = verify(&mut tx, parsed, &s, v, &path_device, &body).await?;
    let c = &req.approval.common;

    let row = sqlx::query(
        "SELECT * FROM v2_idempotency
          WHERE server_instance_id = ? AND tenant_id = ? AND actor_device_id = ?
            AND operation_scope = ? AND idempotency_key = ?",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(s.tenant_id.as_slice())
    .bind(s.device_id.as_slice())
    .bind(DEVICE_APPROVE_SCOPE)
    .bind(c.replay_id.as_slice())
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(row) = row {
        return replay(tx, &row, &req, &s, v, &path_device, now).await;
    }
    // The approval key is the global reservation: another actor's request
    // under this replay ID conflicts and learns nothing about the response.
    let reserved: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM v2_device_approvals
                         WHERE tenant_id = ? AND payload_domain = ? AND replay_id = ?)",
    )
    .bind(s.tenant_id.as_slice())
    .bind(DOMAIN_DEVICE_APPROVAL)
    .bind(c.replay_id.as_slice())
    .fetch_one(&mut *tx)
    .await?;
    if reserved {
        return Err(mismatch());
    }
    if req.approval.subject_device_id != path_device {
        return Err(AppError::BadRequest(
            "the path names another device than the approval".into(),
        ));
    }
    if guard_state(&mut tx, v, &s).await?.as_deref() == Some("consumed") {
        return ordinary_approval(tx, &req, &s, v, &path_device, now).await;
    }
    first_approval(tx, &req, &s, v, &path_device, now).await
}

/// The tenant's D1 guard state, if it has one.
async fn guard_state(
    conn: &mut SqliteConnection,
    v: &Verified,
    s: &Session,
) -> Result<Option<String>, AppError> {
    Ok(sqlx::query_scalar(
        "SELECT state FROM v2_bootstrap_guards WHERE server_instance_id = ? AND tenant_id = ?",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(s.tenant_id.as_slice())
    .fetch_optional(&mut *conn)
    .await?)
}

/// The fleet an approval is scoped to, or `None` for the tenant.
fn fleet_of(a: &DeviceApprovalV2) -> Option<&[u8; 16]> {
    (a.approval_scope_kind == ApprovalScopeKind::Fleet).then_some(&a.approval_scope_id)
}

/// Step 1: signature and context, before any lookup. The signature is checked
/// first, so changed bytes under a known replay ID that also fail to verify
/// get a 422 rather than a 409: stricter than R3's order, never weaker.
async fn verify(
    conn: &mut SqliteConnection,
    parsed: AuthorizationRecord,
    s: &Session,
    v: &Verified,
    path_device: &[u8; 16],
    body: &[u8],
) -> Result<Request, AppError> {
    // The issuer key comes from this tenant's devices by its ID; a key that is
    // not enrolled here signs nothing here.
    let issuer: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT signing_public_key FROM v2_devices WHERE tenant_id = ? AND signing_key_id = ?",
    )
    .bind(s.tenant_id.as_slice())
    .bind(parsed.issuer_signing_key_id().as_slice())
    .fetch_optional(&mut *conn)
    .await?;
    let issuer: [u8; 32] = issuer.and_then(|k| k.try_into().ok()).ok_or_else(|| {
        coded(
            StatusCode::UNPROCESSABLE_ENTITY,
            "KEY_SUBSTITUTION_DETECTED",
            "the issuer key is not a device of this tenant",
        )
    })?;
    let record = parsed
        .verify_signature(&issuer)
        .map_err(|e| coded(StatusCode::UNPROCESSABLE_ENTITY, e.code(), &e.to_string()))?;
    let Payload::DeviceApproval(approval) = record.payload().clone() else {
        return Err(column_mismatch("the record is not a device approval"));
    };
    let c = &approval.common;
    if c.server_instance_id != v.server_instance_id || c.tenant_id != s.tenant_id {
        return Err(AppError::Forbidden);
    }
    if c.restore_epoch != v.restore_epoch {
        return Err(stale());
    }
    let request_hash = device_approve_request_hash(
        &v.server_instance_id,
        v.restore_epoch,
        &s.tenant_id,
        &s.account_id,
        &s.device_id,
        path_device,
        body,
    );
    Ok(Request {
        record: record.record().clone(),
        approval,
        request_hash,
    })
}

/// Step 2: an exact retry. The stored row must agree with the request and
/// with the approval it names, and the actor must still hold the authority
/// the first request had; then the stored bytes go back as stored.
async fn replay(
    mut tx: sqlx::Transaction<'_, sqlx::Sqlite>,
    row: &sqlx::sqlite::SqliteRow,
    req: &Request,
    s: &Session,
    v: &Verified,
    path_device: &[u8; 16],
    now: i64,
) -> Result<Response, AppError> {
    let stored_request: Vec<u8> = row.get("exact_request_bytes");
    let same = stored_request == req.record.exact_signed_container_bytes()
        && blob::<32>(row, "canonical_request_hash")? == req.request_hash
        && row
            .get::<Option<Vec<u8>>, _>("subject_device_id")
            .as_deref()
            == Some(&path_device[..])
        && row.get::<Option<Vec<u8>>, _>("actor_account_id").as_deref() == Some(&s.account_id[..])
        && row.get::<Option<i64>, _>("restore_epoch") == Some(epoch(v)?);
    if !same {
        return Err(mismatch());
    }

    let response: Vec<u8> = row
        .get::<Option<Vec<u8>>, _>("exact_response_bytes")
        .unwrap_or_default();
    if !stored_row_is_consistent(&mut tx, row, req, s, v, &response).await? {
        // The ledger disagrees with itself: close the approval path rather
        // than answer from it (R3 step 2).
        sqlx::query(
            "UPDATE v2_bootstrap_guards
                SET state = 'recovery_required', recovery_reason = 'integrity_failure',
                    updated_at = ?
              WHERE server_instance_id = ? AND tenant_id = ? AND state <> 'recovery_required'",
        )
        .bind(now_rfc3339())
        .bind(v.server_instance_id.as_slice())
        .bind(s.tenant_id.as_slice())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        return Err(coded(
            StatusCode::UNPROCESSABLE_ENTITY,
            "MUTATION_RESPONSE_MISMATCH",
            "the stored approval response does not match its approval",
        ));
    }

    // Live authority, as for the first request. For D1: the approval and
    // device are live, and the actor is still the tenant's sole owner on a
    // setup session. For an ordinary approval: the actor still holds
    // `device.approve` over its scope, and the device is active.
    let a = &req.approval;
    let d1 = DeviceApprovalReceiptV2::parse(&response)
        .ok()
        .and_then(|r| r.confirmation_id)
        .is_some();
    if !d1 {
        let live = holds_capability(&mut tx, v, s, fleet_of(a), Capability::DeviceApprove, now)
            .await?
            && subject_is_active(&mut tx, s, a).await?;
        if !live {
            return Err(AppError::Forbidden);
        }
        tx.commit().await?;
        return Ok(cbor(StatusCode::CREATED, response));
    }
    let live = s.class != "pending_setup"
        && super::v2_auth::d1_approval_is_live(
            &mut tx,
            &s.tenant_id,
            path_device,
            &a.subject_signing_key_id,
            &a.subject_hpke_key_id,
            v,
            now,
        )
        .await?
        && device_is(&mut tx, s, path_device, "active").await?
        && sole_owner(&mut tx, s).await?;
    if !live {
        return Err(AppError::Forbidden);
    }
    tx.commit().await?;
    Ok(cbor(StatusCode::CREATED, response))
}

/// Every equality R3 step 2 asks of a stored `DEVICE_APPROVE` row.
async fn stored_row_is_consistent(
    conn: &mut SqliteConnection,
    row: &sqlx::sqlite::SqliteRow,
    req: &Request,
    s: &Session,
    v: &Verified,
    response: &[u8],
) -> Result<bool, AppError> {
    let record = &req.record;
    let outer_sha = *record.exact_signed_container_bytes_sha256();
    let approval = sqlx::query(
        "SELECT exact_signed_container_bytes, exact_signed_container_bytes_sha256,
                payload_sha256, signed_container_hash
           FROM v2_device_approvals
          WHERE tenant_id = ? AND payload_domain = ? AND replay_id = ? AND server_instance_id = ?",
    )
    .bind(s.tenant_id.as_slice())
    .bind(DOMAIN_DEVICE_APPROVAL)
    .bind(req.approval.common.replay_id.as_slice())
    .bind(v.server_instance_id.as_slice())
    .fetch_optional(&mut *conn)
    .await?;
    let Some(approval) = approval else {
        return Ok(false);
    };
    let confirmation: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT confirmation_id FROM v2_first_device_confirmations
          WHERE server_instance_id = ? AND tenant_id = ? AND state = 'consumed'
            AND approval_replay_id = ? AND approval_payload_sha256 = ?
            AND approval_signed_container_hash = ? AND approval_outer_sha256 = ?",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(s.tenant_id.as_slice())
    .bind(req.approval.common.replay_id.as_slice())
    .bind(record.payload_sha256().as_slice())
    .bind(record.signed_container_hash().as_slice())
    .bind(outer_sha.as_slice())
    .fetch_optional(&mut *conn)
    .await?;
    let Ok(receipt) = DeviceApprovalReceiptV2::parse(response) else {
        return Ok(false);
    };
    let expected = DeviceApprovalReceiptV2 {
        server_instance_id: v.server_instance_id,
        restore_epoch: v.restore_epoch,
        tenant_id: s.tenant_id,
        actor_account_id: s.account_id,
        actor_device_id: s.device_id,
        subject_device_id: req.approval.subject_device_id,
        approval_replay_id: req.approval.common.replay_id,
        request_hash: req.request_hash,
        approval_payload_sha256: *record.payload_sha256(),
        approval_signed_container_hash: *record.signed_container_hash(),
        approval_outer_sha256: outer_sha,
        confirmation_id: confirmation.and_then(|c| c.try_into().ok()),
        committed_at_ms: receipt.committed_at_ms,
    };
    let exact = record.exact_signed_container_bytes();
    Ok(receipt == expected
        && approval.get::<Vec<u8>, _>("exact_signed_container_bytes") == exact
        && blob::<32>(&approval, "exact_signed_container_bytes_sha256")? == outer_sha
        && blob::<32>(&approval, "payload_sha256")? == *record.payload_sha256()
        && blob::<32>(&approval, "signed_container_hash")? == *record.signed_container_hash()
        && blob::<32>(row, "exact_request_bytes_sha256")? == outer_sha
        && row
            .get::<Option<String>, _>("response_record_type")
            .as_deref()
            == Some(RECEIPT_TYPE)
        && row
            .get::<Option<Vec<u8>>, _>("exact_response_bytes_sha256")
            .as_deref()
            == Some(&sha256(response)[..]))
}

/// The approval's subject is an active device of the tenant under exactly
/// the keys it approved.
async fn subject_is_active(
    conn: &mut SqliteConnection,
    s: &Session,
    a: &DeviceApprovalV2,
) -> Result<bool, AppError> {
    Ok(sqlx::query_scalar::<_, i64>(
        "SELECT 1 FROM v2_devices
          WHERE tenant_id = ? AND id = ? AND account_id = ? AND status = 'active'
            AND signing_key_id = ? AND hpke_key_id = ?",
    )
    .bind(s.tenant_id.as_slice())
    .bind(a.subject_device_id.as_slice())
    .bind(a.subject_account_id.as_slice())
    .bind(a.subject_signing_key_id.as_slice())
    .bind(a.subject_hpke_key_id.as_slice())
    .fetch_optional(&mut *conn)
    .await?
    .is_some())
}

async fn device_is(
    conn: &mut SqliteConnection,
    s: &Session,
    device: &[u8; 16],
    status: &str,
) -> Result<bool, AppError> {
    Ok(sqlx::query_scalar::<_, i64>(
        "SELECT 1 FROM v2_devices
          WHERE tenant_id = ? AND id = ? AND account_id = ? AND status = ?
            AND signing_key_id = ? AND hpke_key_id = ?",
    )
    .bind(s.tenant_id.as_slice())
    .bind(device.as_slice())
    .bind(s.account_id.as_slice())
    .bind(status)
    .bind(s.signing_key_id.as_slice())
    .bind(s.hpke_key_id.as_slice())
    .fetch_optional(&mut *conn)
    .await?
    .is_some())
}

/// The session's account is the tenant's one active owner.
pub(super) async fn sole_owner(conn: &mut SqliteConnection, s: &Session) -> Result<bool, AppError> {
    let owners: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT m.account_id FROM v2_tenant_memberships m
           JOIN v2_accounts a ON a.tenant_id = m.tenant_id AND a.id = m.account_id
          WHERE m.tenant_id = ? AND m.role = 'owner' AND m.status = 'active'
            AND a.status = 'active'",
    )
    .bind(s.tenant_id.as_slice())
    .fetch_all(&mut *conn)
    .await?;
    Ok(matches!(owners.as_slice(), [only] if only[..] == s.account_id[..]))
}

/// Steps 3 and 4 for D1: every guard, then every write, in one transaction.
async fn first_approval(
    mut tx: sqlx::Transaction<'_, sqlx::Sqlite>,
    req: &Request,
    s: &Session,
    v: &Verified,
    path_device: &[u8; 16],
    now: i64,
) -> Result<Response, AppError> {
    let a = &req.approval;
    let c = &a.common;
    let record = &req.record;

    // Once D1 has run, or was closed, no request reopens it.
    match guard_state(&mut tx, v, s).await?.as_deref() {
        Some("reserved") => {}
        Some("consumed" | "closed") => return Err(closed()),
        _ => return Err(AppError::Forbidden),
    }
    // History counts, revoked rows included (R1).
    for table in [
        "v2_device_approvals",
        "v2_capability_grants",
        "v2_legacy_capability_grants",
        "v2_root_key_generations",
        "v2_tenant_root_key_grants",
        "v2_legacy_tenant_root_key_grants",
    ] {
        let any: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS (SELECT 1 FROM {table} WHERE tenant_id = ?)"
        ))
        .bind(s.tenant_id.as_slice())
        .fetch_one(&mut *tx)
        .await?;
        if any {
            return Err(closed());
        }
    }
    // shortcut: only the D1 self-approval exists; an approval signed by
    // another device needs `device.approve` capability grants (W2 PR5).
    if *record.issuer_signing_key_id() != a.subject_signing_key_id {
        return Err(AppError::Forbidden);
    }
    // D1: the live session is the subject itself, still pending setup.
    if s.device_id != *path_device
        || s.account_id != a.subject_account_id
        || s.signing_key_id != a.subject_signing_key_id
        || s.hpke_key_id != a.subject_hpke_key_id
        || s.class != "pending_setup"
    {
        return Err(AppError::Forbidden);
    }
    if a.approval_scope_kind != ApprovalScopeKind::Tenant {
        return Err(AppError::Forbidden);
    }
    let window = c.not_after_ms - c.not_before_ms;
    if int(c.not_before_ms)? > now
        || now >= int(c.not_after_ms)?
        || window > MAX_DEVICE_APPROVAL_TTL_MS
    {
        return Err(AppError::Forbidden);
    }

    if !sole_owner(&mut tx, s).await? {
        return Err(AppError::Forbidden);
    }

    // The pending device, both keys rederived from its stored public keys.
    let device = sqlx::query(
        "SELECT status, signing_suite, signing_public_key, signing_key_id,
                hpke_suite, hpke_public_key, hpke_key_id
           FROM v2_devices WHERE tenant_id = ? AND id = ? AND account_id = ?",
    )
    .bind(s.tenant_id.as_slice())
    .bind(path_device.as_slice())
    .bind(s.account_id.as_slice())
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::Forbidden)?;
    if device.get::<String, _>("status") != "pending" {
        return Err(AppError::Forbidden);
    }
    let spk: [u8; 32] = blob(&device, "signing_public_key")?;
    let hpk: [u8; 32] = blob(&device, "hpke_public_key")?;
    let derived = derive_device_key_ids(
        device.get("signing_suite"),
        &spk,
        device.get("hpke_suite"),
        &hpk,
    )
    .ok()
    .filter(|ids| {
        blob::<32>(&device, "signing_key_id").ok() == Some(ids.0)
            && blob::<32>(&device, "hpke_key_id").ok() == Some(ids.1)
    });
    if derived != Some((a.subject_signing_key_id, a.subject_hpke_key_id)) {
        return Err(column_mismatch(
            "the approval's key IDs are not the device's keys",
        ));
    }

    // The tenant's one confirmation, pending, for exactly this subject.
    let confirmation = sqlx::query(
        "SELECT confirmation_id, account_id, device_id, signing_key_id,
                hpke_key_id, signing_public_key, hpke_public_key
           FROM v2_first_device_confirmations
          WHERE server_instance_id = ? AND tenant_id = ? AND state = 'pending'",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(s.tenant_id.as_slice())
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::Forbidden)?;
    let matches = blob::<16>(&confirmation, "account_id")? == s.account_id
        && blob::<16>(&confirmation, "device_id")? == *path_device
        && blob::<32>(&confirmation, "signing_key_id")? == a.subject_signing_key_id
        && blob::<32>(&confirmation, "hpke_key_id")? == a.subject_hpke_key_id
        && blob::<32>(&confirmation, "signing_public_key")? == spk
        && blob::<32>(&confirmation, "hpke_public_key")? == hpk;
    if !matches {
        return Err(AppError::Forbidden);
    }
    let confirmation_id: [u8; 16] = blob(&confirmation, "confirmation_id")?;

    // Step 4: every write together; any failure rolls all of them back.
    let outer_sha = *record.exact_signed_container_bytes_sha256();
    insert_approval(&mut tx, req).await?;

    let committed_at_ms = u64::try_from(now).unwrap_or_default();
    let receipt = DeviceApprovalReceiptV2 {
        server_instance_id: v.server_instance_id,
        restore_epoch: v.restore_epoch,
        tenant_id: s.tenant_id,
        actor_account_id: s.account_id,
        actor_device_id: s.device_id,
        subject_device_id: a.subject_device_id,
        approval_replay_id: c.replay_id,
        request_hash: req.request_hash,
        approval_payload_sha256: *record.payload_sha256(),
        approval_signed_container_hash: *record.signed_container_hash(),
        approval_outer_sha256: outer_sha,
        confirmation_id: Some(confirmation_id),
        committed_at_ms,
    }
    .encode();
    store_receipt(&mut tx, req, s, v, &receipt).await?;

    let moved = [
        sqlx::query(
            "UPDATE v2_first_device_confirmations
                SET state = 'consumed', consumed_at_ms = ?, approval_payload_domain = ?,
                    approval_replay_id = ?, approval_payload_sha256 = ?,
                    approval_signed_container_hash = ?, approval_outer_sha256 = ?
              WHERE server_instance_id = ? AND tenant_id = ? AND confirmation_id = ?
                AND state = 'pending'",
        )
        .bind(now)
        .bind(DOMAIN_DEVICE_APPROVAL)
        .bind(c.replay_id.as_slice())
        .bind(record.payload_sha256().as_slice())
        .bind(record.signed_container_hash().as_slice())
        .bind(outer_sha.as_slice())
        .bind(v.server_instance_id.as_slice())
        .bind(s.tenant_id.as_slice())
        .bind(confirmation_id.as_slice())
        .execute(&mut *tx)
        .await?,
        sqlx::query(
            "UPDATE v2_bootstrap_guards SET state = 'consumed', updated_at = ?
              WHERE server_instance_id = ? AND tenant_id = ? AND state = 'reserved'",
        )
        .bind(now_rfc3339())
        .bind(v.server_instance_id.as_slice())
        .bind(s.tenant_id.as_slice())
        .execute(&mut *tx)
        .await?,
        sqlx::query(
            "UPDATE v2_devices SET status = 'active'
              WHERE tenant_id = ? AND id = ? AND status = 'pending'",
        )
        .bind(s.tenant_id.as_slice())
        .bind(path_device.as_slice())
        .execute(&mut *tx)
        .await?,
        // Only the approving session is promoted; the device's other pending
        // sessions stop being live with the status change.
        sqlx::query(
            "UPDATE v2_sessions SET class = 'root_setup'
              WHERE tenant_id = ? AND id = ? AND class = 'pending_setup'
                AND revoked_at_ms IS NULL",
        )
        .bind(s.tenant_id.as_slice())
        .bind(s.id.as_slice())
        .execute(&mut *tx)
        .await?,
    ];
    if moved.iter().any(|r| r.rows_affected() != 1) {
        return Err(AppError::Internal(
            "a D1 transition did not apply exactly once".into(),
        ));
    }
    end_challenges(&mut tx, s, path_device, now).await?;
    audit(
        &mut tx,
        &s.tenant_id,
        &s.account_id,
        &s.device_id,
        "device.approve",
        "device",
        path_device,
    )
    .await?;
    tx.commit().await?;
    Ok(cbor(StatusCode::CREATED, receipt))
}

/// Files the approval row: every column from the verified record.
async fn insert_approval(conn: &mut SqliteConnection, req: &Request) -> Result<(), AppError> {
    let a = &req.approval;
    let c = &a.common;
    let record = &req.record;
    let outer_sha = *record.exact_signed_container_bytes_sha256();
    sqlx::query(
        "INSERT INTO v2_device_approvals
             (tenant_id, replay_id, payload_domain, payload_version, subject_account_id,
              subject_device_id, subject_signing_key_id, subject_hpke_key_id, approval_scope_kind,
              approval_scope_id, approved_use, issued_at_ms, not_before_ms, not_after_ms,
              server_instance_id, restore_epoch, canonical_payload_bytes, payload_sha256,
              signature_suite_id, signature_version, signature_bytes, issuer_signing_key_id,
              signed_container_hash, exact_signed_container_bytes,
              exact_signed_container_bytes_sha256, revoked_at, created_at)
         VALUES (?, ?, ?, 2, ?, ?, ?, ?, ?, ?, 'team.device', ?, ?, ?, ?, ?, ?, ?, ?, ?,
                 ?, ?, ?, ?, ?, NULL, ?)",
    )
    .bind(c.tenant_id.as_slice())
    .bind(c.replay_id.as_slice())
    .bind(DOMAIN_DEVICE_APPROVAL)
    .bind(a.subject_account_id.as_slice())
    .bind(a.subject_device_id.as_slice())
    .bind(a.subject_signing_key_id.as_slice())
    .bind(a.subject_hpke_key_id.as_slice())
    .bind(a.approval_scope_kind.as_str())
    .bind(a.approval_scope_id.as_slice())
    .bind(int(c.issued_at_ms)?)
    .bind(int(c.not_before_ms)?)
    .bind(int(c.not_after_ms)?)
    .bind(c.server_instance_id.as_slice())
    .bind(int(c.restore_epoch)?)
    .bind(record.canonical_payload_bytes())
    .bind(record.payload_sha256().as_slice())
    .bind(i64::from(record.signature_suite().0))
    .bind(i64::from(record.signature_suite().1))
    .bind(record.signature_bytes())
    .bind(record.issuer_signing_key_id().as_slice())
    .bind(record.signed_container_hash().as_slice())
    .bind(record.exact_signed_container_bytes())
    .bind(outer_sha.as_slice())
    .bind(now_rfc3339())
    .execute(&mut *conn)
    .await?;

    Ok(())
}

/// Stores the exact receipt under the approval's replay ID.
async fn store_receipt(
    conn: &mut SqliteConnection,
    req: &Request,
    s: &Session,
    v: &Verified,
    receipt: &[u8],
) -> Result<(), AppError> {
    let a = &req.approval;
    let c = &a.common;
    let record = &req.record;
    let outer_sha = *record.exact_signed_container_bytes_sha256();
    let retained_until = c
        .not_after_ms
        .checked_add(AUTHORIZATION_REPLAY_RETENTION_MS)
        .ok_or(AppError::Forbidden)?;
    sqlx::query(
        "INSERT INTO v2_idempotency
             (server_instance_id, tenant_id, actor_device_id, operation_scope, idempotency_key,
              operation_kind, canonical_request_hash, exact_request_bytes,
              exact_request_bytes_sha256, status, response_record_type, exact_response_bytes,
              exact_response_bytes_sha256, retained_until, approval_payload_domain, restore_epoch,
              actor_account_id, subject_device_id)
         VALUES (?, ?, ?, ?, ?, 'DEVICE_APPROVE', ?, ?, ?, 'succeeded', ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(s.tenant_id.as_slice())
    .bind(s.device_id.as_slice())
    .bind(DEVICE_APPROVE_SCOPE)
    .bind(c.replay_id.as_slice())
    .bind(req.request_hash.as_slice())
    .bind(record.exact_signed_container_bytes())
    .bind(outer_sha.as_slice())
    .bind(RECEIPT_TYPE)
    .bind(receipt)
    .bind(sha256(receipt).as_slice())
    .bind(int(retained_until)?)
    .bind(DOMAIN_DEVICE_APPROVAL)
    .bind(epoch(v)?)
    .bind(s.account_id.as_slice())
    .bind(a.subject_device_id.as_slice())
    .execute(&mut *conn)
    .await?;

    Ok(())
}

/// A status change ends the device's open session challenges (R2).
async fn end_challenges(
    conn: &mut SqliteConnection,
    s: &Session,
    device: &[u8; 16],
    now: i64,
) -> Result<(), AppError> {
    let open: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT id FROM v2_device_session_challenges
          WHERE tenant_id = ? AND device_id = ? AND consumed_at_ms IS NULL
            AND revoked_at_ms IS NULL",
    )
    .bind(s.tenant_id.as_slice())
    .bind(device.as_slice())
    .fetch_all(&mut *conn)
    .await?;
    for id in open {
        if let Ok(id) = <[u8; 16]>::try_from(id) {
            revoke_challenge(conn, DEVICE_SESSION_CHALLENGES, &id, now).await?;
        }
    }
    Ok(())
}

/// Steps 3 and 4 for an ordinary approval: the issuer, scope, window and
/// subject checks, then the approval, the stored receipt, the active device
/// and the audit row together.
async fn ordinary_approval(
    mut tx: sqlx::Transaction<'_, sqlx::Sqlite>,
    req: &Request,
    s: &Session,
    v: &Verified,
    path_device: &[u8; 16],
    now: i64,
) -> Result<Response, AppError> {
    let a = &req.approval;
    let c = &a.common;
    let record = &req.record;
    // The issuer signs with its session's key; a record signed by another
    // device's key is not this session's to file. A pending session's device
    // is no custodian, so the capability check below refuses it.
    if *record.issuer_signing_key_id() != s.signing_key_id {
        return Err(coded(
            StatusCode::UNPROCESSABLE_ENTITY,
            "KEY_SUBSTITUTION_DETECTED",
            "the approval is not signed by the session's device",
        ));
    }
    if let Some(fleet) = fleet_of(a) {
        let known: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM v2_fleets WHERE tenant_id = ? AND id = ?)",
        )
        .bind(s.tenant_id.as_slice())
        .bind(fleet.as_slice())
        .fetch_one(&mut *tx)
        .await?;
        if !known {
            return Err(column_mismatch(
                "the approval names a fleet of no tenant here",
            ));
        }
    }
    if !holds_capability(&mut tx, v, s, fleet_of(a), Capability::DeviceApprove, now).await? {
        return Err(AppError::Forbidden);
    }
    let window = c.not_after_ms - c.not_before_ms;
    if int(c.not_before_ms)? > now
        || now >= int(c.not_after_ms)?
        || window > MAX_DEVICE_APPROVAL_TTL_MS
    {
        return Err(AppError::Forbidden);
    }

    // The subject: a pending device of an active account of this tenant, or
    // the session's own device renewing its approval, under its own keys.
    let renewal = *path_device == s.device_id;
    let device = sqlx::query(
        "SELECT d.status, d.signing_suite, d.signing_public_key, d.signing_key_id,
                d.hpke_suite, d.hpke_public_key, d.hpke_key_id
           FROM v2_devices d
           JOIN v2_accounts acc ON acc.tenant_id = d.tenant_id AND acc.id = d.account_id
          WHERE d.tenant_id = ? AND d.id = ? AND d.account_id = ? AND acc.status = 'active'",
    )
    .bind(s.tenant_id.as_slice())
    .bind(path_device.as_slice())
    .bind(a.subject_account_id.as_slice())
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::Forbidden)?;
    let status: String = device.get("status");
    if status != if renewal { "active" } else { "pending" } {
        return Err(AppError::Forbidden);
    }
    let spk: [u8; 32] = blob(&device, "signing_public_key")?;
    let hpk: [u8; 32] = blob(&device, "hpke_public_key")?;
    let derived = derive_device_key_ids(
        device.get("signing_suite"),
        &spk,
        device.get("hpke_suite"),
        &hpk,
    )
    .ok()
    .filter(|ids| {
        blob::<32>(&device, "signing_key_id").ok() == Some(ids.0)
            && blob::<32>(&device, "hpke_key_id").ok() == Some(ids.1)
    });
    if derived != Some((a.subject_signing_key_id, a.subject_hpke_key_id)) {
        return Err(column_mismatch(
            "the approval's key IDs are not the device's keys",
        ));
    }

    insert_approval(&mut tx, req).await?;
    let receipt = DeviceApprovalReceiptV2 {
        server_instance_id: v.server_instance_id,
        restore_epoch: v.restore_epoch,
        tenant_id: s.tenant_id,
        actor_account_id: s.account_id,
        actor_device_id: s.device_id,
        subject_device_id: a.subject_device_id,
        approval_replay_id: c.replay_id,
        request_hash: req.request_hash,
        approval_payload_sha256: *record.payload_sha256(),
        approval_signed_container_hash: *record.signed_container_hash(),
        approval_outer_sha256: *record.exact_signed_container_bytes_sha256(),
        confirmation_id: None,
        committed_at_ms: u64::try_from(now).unwrap_or_default(),
    }
    .encode();
    store_receipt(&mut tx, req, s, v, &receipt).await?;
    if !renewal {
        let moved = sqlx::query(
            "UPDATE v2_devices SET status = 'active'
              WHERE tenant_id = ? AND id = ? AND status = 'pending'",
        )
        .bind(s.tenant_id.as_slice())
        .bind(path_device.as_slice())
        .execute(&mut *tx)
        .await?;
        if moved.rows_affected() != 1 {
            return Err(AppError::Internal(
                "an approved device did not become active exactly once".into(),
            ));
        }
        end_challenges(&mut tx, s, path_device, now).await?;
    }
    audit(
        &mut tx,
        &s.tenant_id,
        &s.account_id,
        &s.device_id,
        "device.approve",
        "device",
        path_device,
    )
    .await?;
    tx.commit().await?;
    Ok(cbor(StatusCode::CREATED, receipt))
}
