//! `DEVICE_REVOKE` (ADR 0002 Q-13 and C-1): a custodian holding a
//! device-scoped `device.revoke` files a signed `DeviceRevocationV2`. In one
//! transaction the device is revoked, its sessions end, its leases are
//! released and every approval and grant naming it is revoked, so it can
//! neither sign in again nor be handed a key. Rotation follows later: the
//! keys it already holds cannot be recalled (C-1).
//!
//! shortcut: the optional activations C-1 lets a revocation carry are
//! refused by the request codec; accept them when the client sends any.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use sha2::{Digest, Sha256};
use sqlx::SqliteConnection;

use shared::approval_receipt::AUTHORIZATION_REPLAY_RETENTION_MS;
use shared::authz_record::{
    AuthorizationRecord, Capability, DeviceRevocationV2, Payload, VerifiedRecord,
    DOMAIN_DEVICE_REVOCATION,
};
use shared::mutation::{
    DeviceRevokeRequestV2, DeviceRevokedV2, OperationKind, RECORD_TYPE_DEVICE_REVOKED,
};

use super::v2_approval::{approvals_among, cbor, coded, column_mismatch, int};
use super::v2_auth::{audit, reload_session, revoke_session, unhex, verified, Principal, Session};
use super::v2_capability::stored_row_matches;
use super::v2_root::{
    bind, ledger_row, mismatch, record_error, row_holds, same_request, stale, store_response,
    stored_payload, stored_response, Col,
};
use super::v2_root_grants::{at, custodian_besides, is_active_custodian, outer_request};
use crate::error::AppError;
use crate::identity::{hex, Verified};
use crate::quarantine::{self, Kind, Mark};
use crate::state::AppState;
use crate::util::now_ms;

/// ADR 0002 D-6: a revocation's window, checked when it is filed.
pub(super) const MAX_DEVICE_REVOCATION_TTL_MS: u64 = 30 * 86_400_000;

/// ADR 0002 rule 2 tolerance: a client counts a revocation only if its issuer
/// was a custodian at `issued_at_ms`, which the server checks as "now".
const ISSUED_AT_SKEW_MS: i64 = 300_000;

fn response_mismatch() -> AppError {
    coded(
        StatusCode::UNPROCESSABLE_ENTITY,
        "MUTATION_RESPONSE_MISMATCH",
        "the stored response does not match the revocation",
    )
}

const TABLE: &str = "v2_device_revocations";

/// A filed revocation whose row matched its verified container.
pub(crate) struct StoredRevocation {
    pub(crate) revocation: DeviceRevocationV2,
    pub(crate) signed_container_hash: [u8; 32],
}

/// The revocation `replay` of this instance, reparsed, verified under its
/// issuer's key and required to hold exactly the columns its container
/// determines. A row that disagrees refuses the request (422) and is
/// quarantined (plan L507), again if it was marked before. A row that was
/// marked is served again once it verifies; if the mark holds the hash of the
/// container that was quarantined, the row must hold that very container
/// (another genuine one under the same replay ID is not it). A mark has no
/// hash when the container itself was corrupt then (see
/// [`quarantine::record`]). The mark stays as history.
pub(crate) async fn load_revocation(
    conn: &mut SqliteConnection,
    instance: &[u8; 16],
    tenant: &[u8; 16],
    replay: &[u8; 16],
) -> Result<Option<StoredRevocation>, AppError> {
    let exact: Option<Vec<u8>> = sqlx::query_scalar(&format!(
        "SELECT exact_signed_container_bytes FROM {TABLE}
          WHERE server_instance_id = ? AND tenant_id = ? AND replay_id = ?"
    ))
    .bind(instance.as_slice())
    .bind(tenant.as_slice())
    .bind(replay.as_slice())
    .fetch_optional(&mut *conn)
    .await?;
    let Some(exact) = exact else { return Ok(None) };
    let mark = Mark {
        kind: Kind::DeviceRevocation,
        server_instance_id: *instance,
        tenant_id: *tenant,
        replay_id: *replay,
    };
    let broken = || AppError::Quarantine(Box::new(mark.clone()));
    let Some((record, revocation)) = verified_container(conn, tenant, &exact).await? else {
        return Err(broken());
    };
    if let Some(Some(recorded)) = quarantine::recorded_container_sha256(conn, &mark).await? {
        if recorded.as_slice() != Sha256::digest(&exact).as_slice() {
            return Err(broken());
        }
    }
    let c = &revocation.common;
    if (&c.server_instance_id, &c.tenant_id, &c.replay_id) != (instance, tenant, replay) {
        return Err(broken());
    }
    let cols = revocation_columns(&revocation, record.record()).map_err(|_| broken())?;
    // The key is among the columns, so this is a check of that one row.
    if !row_holds(conn, TABLE, &cols).await? {
        return Err(broken());
    }
    Ok(Some(StoredRevocation {
        revocation,
        signed_container_hash: *record.record().signed_container_hash(),
    }))
}

/// Whether a verified container is the one for `mark`'s row: the same server
/// instance, tenant and replay ID. A genuine container of another row is not.
pub(crate) fn names_row(revocation: &DeviceRevocationV2, mark: &Mark) -> bool {
    let c = &revocation.common;
    (c.server_instance_id, c.tenant_id, c.replay_id)
        == (mark.server_instance_id, mark.tenant_id, mark.replay_id)
}

/// The container bytes alone: parsed, signed under the key of one of the
/// tenant's devices and a `DeviceRevocationV2`. `None` if they are not. The
/// issuer's device row outlives its own revocation, so its key stays.
pub(crate) async fn verified_container(
    conn: &mut SqliteConnection,
    tenant: &[u8; 16],
    exact: &[u8],
) -> sqlx::Result<Option<(VerifiedRecord, DeviceRevocationV2)>> {
    let Ok(parsed) = AuthorizationRecord::parse(exact) else {
        return Ok(None);
    };
    let issuer: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT signing_public_key FROM v2_devices WHERE tenant_id = ? AND signing_key_id = ?",
    )
    .bind(tenant.as_slice())
    .bind(parsed.issuer_signing_key_id().as_slice())
    .fetch_optional(&mut *conn)
    .await?;
    let Some(issuer) = issuer.and_then(|k| <[u8; 32]>::try_from(k).ok()) else {
        return Ok(None);
    };
    let Ok(record) = parsed.verify_signature(&issuer) else {
        return Ok(None);
    };
    let Payload::DeviceRevocation(revocation) = record.payload().clone() else {
        return Ok(None);
    };
    Ok(Some((record, revocation)))
}

/// Why a revocation is not being served correctly right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Why {
    /// The row names another server instance, so no check of this one sees it.
    OtherInstance,
    /// The row disagrees with its signed container, or its container does
    /// not verify.
    Mismatch,
    /// The row is intact, but holds another container than the one that was
    /// quarantined.
    OtherContainer,
    /// A quarantine mark names a row that is not there.
    MarkedRowMissing,
}

/// A revocation that is not served correctly right now.
#[derive(Debug, Clone)]
pub(crate) struct Unserved {
    pub(crate) mark: Mark,
    pub(crate) why: Why,
}

impl Unserved {
    /// Which revocation, why, and what clears it, for a log or a refusal.
    pub(crate) fn describe(&self) -> String {
        let (why, clears) = match self.why {
            Why::OtherInstance => (
                "belongs to another server instance",
                "restoring the row and restarting",
            ),
            Why::Mismatch => (
                "does not match its signed container",
                "restoring the row and restarting",
            ),
            Why::OtherContainer => (
                "holds another container than the one that was quarantined",
                "restoring the quarantined container and restarting",
            ),
            Why::MarkedRowMissing => (
                "is quarantined and its row is missing",
                "restoring the row and restarting",
            ),
        };
        format!(
            "device revocation {} of tenant {} {why}; {clears} clears it",
            hex(&self.mark.replay_id),
            hex(&self.mark.tenant_id)
        )
    }
}

/// What a look at the revocations found.
#[derive(Debug, Default)]
pub(crate) struct Findings {
    pub(crate) unserved: Vec<Unserved>,
    /// Marked before, and intact now: served again, the mark kept as history.
    pub(crate) served_again: Vec<Mark>,
}

/// Looks at the revocations that decide whether v2 may run: every row of
/// every instance when `every_row`, and in any case every row a quarantine
/// mark names. A revocation left out of the checks would let a revoked device
/// pass as live, so a row of another instance, one that fails
/// [`load_revocation`] now, or a mark whose row is gone is `unserved`.
pub(crate) async fn look_at_revocations(
    conn: &mut SqliteConnection,
    instance: &[u8; 16],
    every_row: bool,
) -> Result<Findings, AppError> {
    let mut found = Findings::default();
    let other: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = sqlx::query_as(&format!(
        "SELECT server_instance_id, tenant_id, replay_id FROM {TABLE}
          WHERE server_instance_id <> ?"
    ))
    .bind(instance.as_slice())
    .fetch_all(&mut *conn)
    .await?;
    for (other, tenant, replay) in other {
        found.unserved.push(Unserved {
            mark: Mark {
                kind: Kind::DeviceRevocation,
                server_instance_id: other.try_into().map_err(|_| malformed())?,
                tenant_id: tenant.try_into().map_err(|_| malformed())?,
                replay_id: replay.try_into().map_err(|_| malformed())?,
            },
            why: Why::OtherInstance,
        });
    }
    let marked: Vec<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT tenant_id, replay_id FROM v2_grant_quarantine
          WHERE kind = 'device_revocation' AND server_instance_id = ?",
    )
    .bind(instance.as_slice())
    .fetch_all(&mut *conn)
    .await?;
    let mut keys = if every_row {
        sqlx::query_as(&format!(
            "SELECT tenant_id, replay_id FROM {TABLE} WHERE server_instance_id = ?"
        ))
        .bind(instance.as_slice())
        .fetch_all(&mut *conn)
        .await?
    } else {
        Vec::new()
    };
    for key in &marked {
        if !keys.contains(key) {
            keys.push(key.clone());
        }
    }
    for (tenant, replay) in keys {
        let (tenant, replay): ([u8; 16], [u8; 16]) = (
            tenant.try_into().map_err(|_| malformed())?,
            replay.try_into().map_err(|_| malformed())?,
        );
        let mark = Mark {
            kind: Kind::DeviceRevocation,
            server_instance_id: *instance,
            tenant_id: tenant,
            replay_id: replay,
        };
        let was_marked = marked.contains(&(tenant.to_vec(), replay.to_vec()));
        match load_revocation(conn, instance, &tenant, &replay).await {
            Ok(Some(_)) if was_marked => found.served_again.push(mark),
            Ok(Some(_)) => {}
            Ok(None) => found.unserved.push(Unserved {
                mark,
                why: Why::MarkedRowMissing,
            }),
            Err(AppError::Quarantine(mark)) => {
                let why = why_broken(conn, &mark).await?;
                found.unserved.push(Unserved { mark: *mark, why });
            }
            Err(e) => return Err(e),
        }
    }
    Ok(found)
}

/// A row that failed [`load_revocation`]: a row whose container is intact but
/// is not the one the mark recorded is [`Why::OtherContainer`], any other
/// failure [`Why::Mismatch`].
async fn why_broken(conn: &mut SqliteConnection, mark: &Mark) -> Result<Why, AppError> {
    let Some(Some(recorded)) = quarantine::recorded_container_sha256(conn, mark).await? else {
        return Ok(Why::Mismatch);
    };
    let exact: Option<Vec<u8>> = sqlx::query_scalar(&format!(
        "SELECT exact_signed_container_bytes FROM {TABLE}
          WHERE server_instance_id = ? AND tenant_id = ? AND replay_id = ?"
    ))
    .bind(mark.server_instance_id.as_slice())
    .bind(mark.tenant_id.as_slice())
    .bind(mark.replay_id.as_slice())
    .fetch_optional(&mut *conn)
    .await?;
    Ok(match exact {
        Some(exact)
            if recorded.as_slice() != Sha256::digest(&exact).as_slice()
                && verified_container(conn, &mark.tenant_id, &exact)
                    .await?
                    .is_some_and(|(_, r)| names_row(&r, mark)) =>
        {
            Why::OtherContainer
        }
        _ => Why::Mismatch,
    })
}

fn malformed() -> AppError {
    AppError::Internal("a device revocation row has a malformed key".into())
}

/// Whether the row `replay` holds exactly the filed container `hash`.
async fn filed(
    conn: &mut SqliteConnection,
    v: &Verified,
    tenant: &[u8; 16],
    replay: &[u8; 16],
    hash: &[u8; 32],
) -> Result<bool, AppError> {
    Ok(load_revocation(conn, &v.server_instance_id, tenant, replay)
        .await?
        .is_some_and(|r| r.signed_container_hash == *hash))
}

/// The session's device holds a live, device-scoped `device.revoke` grant
/// covering the subject's approval scope (ADR 0002 D-2 issuer rule for Q-13):
/// a tenant-scoped grant covers every device; a fleet-scoped one covers a
/// device all of whose approvals name that fleet. Every candidate grant row
/// must match its own container.
async fn may_revoke(
    conn: &mut SqliteConnection,
    v: &Verified,
    s: &Session,
    subject: &[u8; 16],
    now: i64,
) -> Result<bool, AppError> {
    let grants: Vec<(Vec<u8>, String, Vec<u8>)> = sqlx::query_as(
        "SELECT replay_id, scope_kind, scope_id FROM v2_capability_grants
          WHERE server_instance_id = ? AND tenant_id = ? AND subject_kind = 'device'
            AND subject_device_id = ? AND subject_signing_key_id = ? AND capability = ?
            AND revoked_at IS NULL AND not_before_ms <= ? AND ? < not_after_ms",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(s.tenant_id.as_slice())
    .bind(s.device_id.as_slice())
    .bind(s.signing_key_id.as_slice())
    .bind(Capability::DeviceRevoke.as_str())
    .bind(now)
    .bind(now)
    .fetch_all(&mut *conn)
    .await?;
    let candidates = sqlx::query_scalar(
        "SELECT replay_id FROM v2_device_approvals
          WHERE server_instance_id = ? AND tenant_id = ? AND subject_device_id = ?",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(s.tenant_id.as_slice())
    .bind(subject.as_slice())
    .fetch_all(&mut *conn)
    .await?;
    let scopes: Vec<(String, Vec<u8>)> = approvals_among(conn, v, &s.tenant_id, candidates)
        .await?
        .into_iter()
        .map(|a| {
            let a = a.approval;
            (
                a.approval_scope_kind.as_str().into(),
                a.approval_scope_id.to_vec(),
            )
        })
        .collect();
    let mut covered = false;
    for (replay, kind, id) in &grants {
        let replay: [u8; 16] = replay
            .as_slice()
            .try_into()
            .map_err(|_| column_mismatch("a stored replay id is not 16 bytes"))?;
        if !stored_row_matches(conn, &v.server_instance_id, &s.tenant_id, &replay).await? {
            return Err(column_mismatch(
                "a stored capability grant does not match its signed container",
            ));
        }
        covered |= kind == "tenant"
            || (kind == "fleet"
                && !scopes.is_empty()
                && scopes.iter().all(|(k, i)| k == "fleet" && i == id));
    }
    Ok(covered)
}

/// The columns a verified revocation determines (plan 5.6.1
/// `DeviceRevocationV2`); `filed_at_ms` is the server's own and not among them.
/// Filing and readback both use this list, so a column cannot be written one
/// way and checked another.
fn revocation_columns(
    r: &DeviceRevocationV2,
    record: &AuthorizationRecord,
) -> Result<Vec<(&'static str, Col)>, AppError> {
    let c = &r.common;
    let b = |bytes: &[u8]| Col::Blob(bytes.to_vec());
    let (suite, version) = record.signature_suite();
    Ok(vec![
        ("server_instance_id", b(&c.server_instance_id)),
        ("tenant_id", b(&c.tenant_id)),
        ("replay_id", b(&c.replay_id)),
        ("payload_domain", Col::Text(DOMAIN_DEVICE_REVOCATION)),
        ("payload_version", Col::Int(2)),
        ("subject_account_id", b(&r.subject_account_id)),
        ("subject_device_id", b(&r.subject_device_id)),
        ("subject_signing_key_id", b(&r.subject_signing_key_id)),
        ("subject_hpke_key_id", b(&r.subject_hpke_key_id)),
        ("reason_code", Col::Text(r.reason_code.as_str())),
        ("issuer_signing_key_id", b(record.issuer_signing_key_id())),
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

/// Inserts the revocation row: every column from the verified record.
async fn insert_revocation(
    conn: &mut SqliteConnection,
    r: &DeviceRevocationV2,
    record: &AuthorizationRecord,
    now: i64,
) -> Result<(), AppError> {
    let mut cols = revocation_columns(r, record)?;
    cols.push(("filed_at_ms", Col::Int(now)));
    let names: Vec<&str> = cols.iter().map(|(name, _)| *name).collect();
    let sql = format!(
        "INSERT INTO {TABLE} ({}) VALUES ({})",
        names.join(", "),
        vec!["?"; cols.len()].join(", ")
    );
    let mut q = sqlx::query(&sql);
    for (_, col) in &cols {
        q = bind(q, col);
    }
    q.execute(&mut *conn).await?;
    Ok(())
}

/// Revokes everything that names the device and ends its sessions; returns
/// how many sessions were still usable.
async fn revoke_everything(
    conn: &mut SqliteConnection,
    tenant: &[u8; 16],
    device: &[u8; 16],
    now: i64,
) -> Result<usize, AppError> {
    let stamp = at(now);
    sqlx::query("UPDATE v2_devices SET status = 'revoked' WHERE tenant_id = ? AND id = ?")
        .bind(tenant.as_slice())
        .bind(device.as_slice())
        .execute(&mut *conn)
        .await?;
    for statement in [
        "UPDATE v2_device_approvals SET revoked_at = ?
          WHERE tenant_id = ? AND subject_device_id = ? AND revoked_at IS NULL",
        "UPDATE v2_capability_grants SET revoked_at = ?
          WHERE tenant_id = ? AND subject_kind = 'device' AND subject_device_id = ?
            AND revoked_at IS NULL",
        "UPDATE v2_tenant_root_key_grants SET revoked_at = ?
          WHERE tenant_id = ? AND subject_device_id = ? AND revoked_at IS NULL",
        "UPDATE v2_fleet_device_hpke_grants SET revoked_at = ?
          WHERE tenant_id = ? AND subject_device_id = ? AND revoked_at IS NULL",
        "UPDATE v2_leases SET released_at = ?
          WHERE tenant_id = ? AND holder_device_id = ? AND released_at IS NULL",
    ] {
        sqlx::query(statement)
            .bind(&stamp)
            .bind(tenant.as_slice())
            .bind(device.as_slice())
            .execute(&mut *conn)
            .await?;
    }
    // Its current profile leases end too (C-1); history stays in the audit.
    sqlx::query("DELETE FROM v2_profile_leases WHERE tenant_id = ? AND owner_device_id = ?")
        .bind(tenant.as_slice())
        .bind(device.as_slice())
        .execute(&mut *conn)
        .await?;
    let sessions: Vec<(Vec<u8>, i64)> = sqlx::query_as(
        "SELECT id, absolute_expires_at_ms FROM v2_sessions
          WHERE tenant_id = ? AND device_id = ? AND revoked_at_ms IS NULL",
    )
    .bind(tenant.as_slice())
    .bind(device.as_slice())
    .fetch_all(&mut *conn)
    .await?;
    for (id, _) in &sessions {
        revoke_session(conn, tenant, id, now).await?;
    }
    Ok(sessions.iter().filter(|(_, e)| now < *e).count())
}

/// `POST /v2/devices/{device_id}/revoke` (ADR 0002 Q-13, amends L1125).
pub async fn revoke_device(
    State(app): State<AppState>,
    who: Principal,
    Path(device): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let v = verified(&app)?;
    let Principal::Session(presented) = who else {
        return Err(AppError::Forbidden);
    };
    let device = unhex::<16>(&device)
        .ok_or_else(|| AppError::BadRequest("device id must be 32 hex digits".into()))?;
    let outer = outer_request(v, &headers, &body, OperationKind::DeviceRevoke)?;
    let request =
        DeviceRevokeRequestV2::parse(&outer.canonical_payload_bytes).map_err(record_error)?;
    let parsed = AuthorizationRecord::parse(&request.exact_signed_revocation_container_bytes)
        .map_err(record_error)?;

    let mut tx = app.db.begin_with("BEGIN IMMEDIATE").await?;
    let now = now_ms();
    let s = reload_session(&mut tx, &presented, v, now)
        .await?
        .ok_or(AppError::Unauthorized)?;
    if let Some(row) =
        ledger_row(&mut tx, v, &s, outer.operation_kind, &outer.idempotency_key).await?
    {
        if !same_request(
            &row,
            outer.operation_kind,
            &outer.canonical_request_hash(),
            &body,
        )? {
            return Err(mismatch());
        }
        let (payload, response) = stored_payload(&row, &outer, RECORD_TYPE_DEVICE_REVOKED, v)
            .ok_or_else(response_mismatch)?;
        let revoked = DeviceRevokedV2::parse(&payload).map_err(|_| response_mismatch())?;
        if revoked.subject_device_id != device
            || revoked.signed_container_hash != request.signed_container_hash
            || !filed(
                &mut tx,
                v,
                &s.tenant_id,
                &revoked.replay_id,
                &revoked.signed_container_hash,
            )
            .await?
        {
            return Err(response_mismatch());
        }
        tx.commit().await?;
        return Ok(cbor(StatusCode::CREATED, response));
    }

    // The issuer: an ACTIVE root custodian, signing with its session's key.
    if !is_active_custodian(&mut tx, v, &s, now).await? {
        return Err(AppError::Forbidden);
    }
    if *parsed.issuer_signing_key_id() != s.signing_key_id {
        return Err(coded(
            StatusCode::UNPROCESSABLE_ENTITY,
            "KEY_SUBSTITUTION_DETECTED",
            "the revocation is not signed by the session's device",
        ));
    }
    let issuer: Vec<u8> = sqlx::query_scalar(
        "SELECT signing_public_key FROM v2_devices
          WHERE tenant_id = ? AND id = ? AND signing_key_id = ? AND status = 'active'",
    )
    .bind(s.tenant_id.as_slice())
    .bind(s.device_id.as_slice())
    .bind(s.signing_key_id.as_slice())
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::Forbidden)?;
    let issuer: [u8; 32] = issuer
        .try_into()
        .map_err(|_| AppError::Internal("a stored signing key is not 32 bytes".into()))?;
    let record: VerifiedRecord = parsed.verify_signature(&issuer).map_err(record_error)?;
    let Payload::DeviceRevocation(r) = record.payload().clone() else {
        return Err(column_mismatch(
            "the embedded record is not a device revocation",
        ));
    };
    let c = &r.common;
    if c.tenant_id != s.tenant_id || c.server_instance_id != v.server_instance_id {
        return Err(AppError::Forbidden);
    }
    if c.restore_epoch != v.restore_epoch {
        return Err(stale());
    }
    if r.subject_device_id != device {
        return Err(column_mismatch(
            "the path names another device than the revocation",
        ));
    }
    // D-6: the window is checked now, at filing, and never again.
    if (int(c.issued_at_ms)? - now).abs() > ISSUED_AT_SKEW_MS
        || int(c.not_before_ms)? > now
        || now >= int(c.not_after_ms)?
        || c.not_after_ms - c.not_before_ms > MAX_DEVICE_REVOCATION_TTL_MS
    {
        return Err(AppError::Forbidden);
    }
    if !may_revoke(&mut tx, v, &s, &device, now).await? {
        return Err(AppError::Forbidden);
    }

    // The subject: this tenant's device under exactly the keys revoked.
    let keys: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT account_id, signing_key_id, hpke_key_id FROM v2_devices
          WHERE tenant_id = ? AND id = ?",
    )
    .bind(s.tenant_id.as_slice())
    .bind(device.as_slice())
    .fetch_optional(&mut *tx)
    .await?;
    let Some((account, signing, hpke)) = keys else {
        return Err(coded(
            StatusCode::NOT_FOUND,
            "RESOURCE_NOT_FOUND",
            "no such device",
        ));
    };
    if (account.as_slice(), signing.as_slice(), hpke.as_slice())
        != (
            r.subject_account_id.as_slice(),
            r.subject_signing_key_id.as_slice(),
            r.subject_hpke_key_id.as_slice(),
        )
    {
        return Err(column_mismatch(
            "the revocation names other keys than the device holds",
        ));
    }
    let spent: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM v2_device_revocations
                         WHERE server_instance_id = ? AND tenant_id = ? AND replay_id = ?)",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(s.tenant_id.as_slice())
    .bind(c.replay_id.as_slice())
    .fetch_one(&mut *tx)
    .await?;
    if spent {
        return Err(coded(
            StatusCode::CONFLICT,
            "REPLAY_DETECTED",
            "this replay ID is already spent",
        ));
    }
    // The ACTIVE root keeps a custodian, or no device could sign the
    // RotationGrant that rotates the revoked one out (C-1).
    if !custodian_besides(&mut tx, v, &s.tenant_id, &device, now).await? {
        return Err(coded(
            StatusCode::CONFLICT,
            "LAST_ROOT_CUSTODIAN",
            "the ACTIVE root would be left without a custodian",
        ));
    }

    insert_revocation(&mut tx, &r, record.record(), now).await?;
    let live = revoke_everything(&mut tx, &s.tenant_id, &device, now).await?;
    let revoked_at_ms = u64::try_from(now).unwrap_or_default();
    let payload = DeviceRevokedV2 {
        tenant_id: s.tenant_id,
        subject_device_id: device,
        replay_id: c.replay_id,
        signed_container_hash: request.signed_container_hash,
        reason_code: r.reason_code,
        sessions_invalidated_count: u32::try_from(live).unwrap_or(u32::MAX),
        revoked_at_ms,
    }
    .encode();
    let response = stored_response(
        &outer,
        RECORD_TYPE_DEVICE_REVOKED,
        payload,
        v,
        revoked_at_ms,
    )?;
    let retained_until = c
        .not_after_ms
        .checked_add(AUTHORIZATION_REPLAY_RETENTION_MS)
        .ok_or(AppError::Forbidden)?;
    store_response(
        &mut tx,
        v,
        &s,
        &outer,
        &body,
        RECORD_TYPE_DEVICE_REVOKED,
        &response,
        retained_until,
    )
    .await?;
    audit(
        &mut tx,
        &s.tenant_id,
        &s.account_id,
        &s.device_id,
        "device.revoke",
        "device",
        &device,
    )
    .await?;
    tx.commit().await?;
    Ok(cbor(StatusCode::CREATED, response))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unserved(why: Why) -> String {
        Unserved {
            mark: Mark {
                kind: Kind::DeviceRevocation,
                server_instance_id: [1; 16],
                tenant_id: [2; 16],
                replay_id: [3; 16],
            },
            why,
        }
        .describe()
    }

    #[test]
    fn each_finding_names_the_tenant_and_replay_and_what_clears_it() {
        let row = "restoring the row and restarting clears it";
        for (why, said, clears) in [
            (
                Why::OtherInstance,
                "belongs to another server instance",
                row,
            ),
            (Why::Mismatch, "does not match its signed container", row),
            (
                Why::OtherContainer,
                "holds another container than the one that was quarantined",
                "restoring the quarantined container and restarting clears it",
            ),
            (
                Why::MarkedRowMissing,
                "is quarantined and its row is missing",
                row,
            ),
        ] {
            let text = unserved(why);
            assert!(text.contains(&"03".repeat(16)), "{text}");
            assert!(text.contains(&"02".repeat(16)), "{text}");
            assert!(text.contains(said), "{text}");
            assert!(text.contains(clears), "{text}");
        }
    }
}
