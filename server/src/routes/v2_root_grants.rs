//! Root grant readback, acknowledgement and generation activation (plan 5.6.4
//! exact endpoints, 5.6.5 `ROOT_GRANT_ACK` and `ROOT_GENERATION_ACTIVATE`,
//! ADR 0001 S6).
//!
//! Every read reparses the stored exact container, verifies it under its
//! issuer's device key and requires the row to hold exactly the columns the
//! record determines; a row that disagrees is refused, never served or acted
//! on. After the S6 bootstrap the first device reads its self-grant back,
//! opens it, acknowledges the TRK it got, and activates generation 0 once
//! every required grant is acknowledged and their set is the one generation 0
//! was created with.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use sqlx::{Row, SqliteConnection};

use shared::approval_receipt::AUTHORIZATION_REPLAY_RETENTION_MS;
use shared::authz_record::{
    AuthorizationRecord, Payload, RootGrantVariant, TenantRootKeyGrantV2, VerifiedRecord,
};
use shared::mutation::{
    root_custodian_grant_set_hash, IdempotentMutationRequestV2, OperationKind, RootGenerationState,
    RootGrantState, TenantRootGenerationActivateV2, TenantRootGenerationActivatedV2,
    TenantRootGrantAckV2, TenantRootGrantAckedV2, TenantRootGrantDescriptorV2,
    RECORD_TYPE_ROOT_GENERATION_ACTIVATED, RECORD_TYPE_ROOT_GRANT_ACKED,
};

use super::v2_approval::{cbor, coded, column_mismatch, exact_cbor_body, int, sole_owner};
use super::v2_auth::{audit, blob, reload_session, unhex, verified, Principal, Session};
use super::v2_root::{
    grant_row_matches, ledger_row, mismatch, record_error, same_request, stale, store_response,
    stored_payload, stored_response, MAX_ROOT_REQUEST_BODY,
};
use crate::error::AppError;
use crate::identity::Verified;
use crate::quarantine::{self, Kind, Mark};
use crate::state::AppState;
use crate::util::{now_ms, now_rfc3339};

fn not_found() -> AppError {
    coded(
        StatusCode::NOT_FOUND,
        "RESOURCE_NOT_FOUND",
        "no such root grant or generation",
    )
}

fn generation_mismatch(msg: &str) -> AppError {
    coded(StatusCode::CONFLICT, "ROOT_GENERATION_MISMATCH", msg)
}

fn integrity() -> AppError {
    column_mismatch("the stored root grant does not match its signed container")
}

/// The RFC 3339 form of `ms`, so a row's `*_at` and its response's `*_at_ms`
/// are one instant.
fn at(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .map(|t| t.to_rfc3339())
        .unwrap_or_else(now_rfc3339)
}

fn response_mismatch() -> AppError {
    coded(
        StatusCode::UNPROCESSABLE_ENTITY,
        "MUTATION_RESPONSE_MISMATCH",
        "the stored response does not match the rows it changed",
    )
}

fn path_ids(tenant: &str, generation: &str) -> Result<([u8; 16], u64), AppError> {
    let tenant = unhex::<16>(tenant)
        .ok_or_else(|| AppError::BadRequest("tenant id must be 32 hex digits".into()))?;
    // Canonical decimal only, so one generation has exactly one path.
    let generation = generation
        .parse::<u64>()
        .ok()
        .filter(|g| g.to_string() == generation)
        .ok_or_else(|| AppError::BadRequest("generation must be a decimal integer".into()))?;
    Ok((tenant, generation))
}

fn replay_id(s: &str) -> Result<[u8; 16], AppError> {
    unhex::<16>(s).ok_or_else(|| AppError::BadRequest("replay id must be 32 hex digits".into()))
}

/// A stored grant whose row matched its verified container.
pub(crate) struct StoredGrant {
    record: VerifiedRecord,
    grant: TenantRootKeyGrantV2,
    acked: bool,
    revoked: bool,
}

/// The grant `replay_id` of `generation`, verified against its row; `None`
/// if there is no such row. A row that disagrees with its container, or was
/// quarantined before, is refused and quarantined.
pub(crate) async fn load_grant(
    conn: &mut SqliteConnection,
    v: &Verified,
    tenant: &[u8; 16],
    generation: u64,
    replay: &[u8; 16],
) -> Result<Option<StoredGrant>, AppError> {
    let Some(row) = sqlx::query(
        "SELECT exact_signed_container_bytes, acked_at, revoked_at
           FROM v2_tenant_root_key_grants
          WHERE server_instance_id = ? AND tenant_id = ? AND replay_id = ? AND root_generation = ?",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(tenant.as_slice())
    .bind(replay.as_slice())
    .bind(int(generation)?)
    .fetch_optional(&mut *conn)
    .await?
    else {
        return Ok(None);
    };
    let mark = Mark {
        kind: Kind::RootGrant,
        server_instance_id: v.server_instance_id,
        tenant_id: *tenant,
        replay_id: *replay,
    };
    let broken = || AppError::Quarantine(Box::new(mark.clone()));
    if quarantine::holds(conn, &mark).await? {
        return Err(broken());
    }
    let exact: Vec<u8> = row.get("exact_signed_container_bytes");
    let parsed = AuthorizationRecord::parse(&exact).map_err(|_| broken())?;
    // The issuer is a device of this tenant, revoked or not: a signature
    // stays the one it was when the grant was filed.
    let issuer: Vec<u8> = sqlx::query_scalar(
        "SELECT signing_public_key FROM v2_devices WHERE tenant_id = ? AND signing_key_id = ?",
    )
    .bind(tenant.as_slice())
    .bind(parsed.issuer_signing_key_id().as_slice())
    .fetch_optional(&mut *conn)
    .await?
    .ok_or_else(broken)?;
    let issuer: [u8; 32] = issuer.try_into().map_err(|_| broken())?;
    let record = parsed.verify_signature(&issuer).map_err(|_| broken())?;
    let Payload::TenantRootKeyGrant(grant) = record.payload().clone() else {
        return Err(broken());
    };
    let key = (&v.server_instance_id, tenant, replay);
    if grant.root_generation != generation
        || !grant_row_matches(conn, key, &grant, record.record()).await?
    {
        return Err(broken());
    }
    Ok(Some(StoredGrant {
        record,
        grant,
        acked: row.get::<Option<String>, _>("acked_at").is_some(),
        revoked: row.get::<Option<String>, _>("revoked_at").is_some(),
    }))
}

/// shortcut: only the S6 subject acts on its own gen-0 self-grant; other
/// readers and grants (custodians, `ExistingRootGrant`, rotation) need
/// `ROOT_GRANT_CREATE` and D2 capabilities, which come later.
fn subject_of(s: &Session, g: &TenantRootKeyGrantV2) -> Result<(), AppError> {
    let own = g.variant == RootGrantVariant::FirstRootSelfGrant
        && s.class == "root_setup"
        && g.subject_account_id == s.account_id
        && g.subject_device_id == s.device_id
        && g.subject_signing_key_id == s.signing_key_id
        && g.recipient_hpke_key_id == s.hpke_key_id;
    own.then_some(()).ok_or(AppError::Forbidden)
}

async fn generation_state(
    conn: &mut SqliteConnection,
    v: &Verified,
    tenant: &[u8; 16],
    generation: u64,
) -> Result<Option<RootGenerationState>, AppError> {
    let state: Option<String> = sqlx::query_scalar(
        "SELECT state FROM v2_root_key_generations
          WHERE server_instance_id = ? AND tenant_id = ? AND generation = ?",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(tenant.as_slice())
    .bind(int(generation)?)
    .fetch_optional(&mut *conn)
    .await?;
    state
        .map(|s| {
            RootGenerationState::ALL
                .into_iter()
                .find(|g| g.as_str() == s)
                .ok_or_else(integrity)
        })
        .transpose()
}

/// `GET /v2/tenants/{t}/root-key-generations/{g}/grants/{replay_id}`: the
/// deterministic primary-key readback, answered only after the row matched
/// its container column for column.
pub async fn read_root_grant(
    State(app): State<AppState>,
    who: Principal,
    Path((tenant, generation, replay)): Path<(String, String, String)>,
) -> Result<Response, AppError> {
    let v = verified(&app)?;
    let Principal::Session(presented) = who else {
        return Err(AppError::Forbidden);
    };
    let (tenant, generation) = path_ids(&tenant, &generation)?;
    let replay = replay_id(&replay)?;
    let mut tx = app.db.begin().await?;
    let s = reload_session(&mut tx, &presented, v, now_ms())
        .await?
        .ok_or(AppError::Unauthorized)?;
    // For anyone but the subject the grant does not exist: another tenant's
    // session, and any session but the setup one, learn nothing from a read.
    if s.tenant_id != tenant || s.class != "root_setup" {
        return Err(not_found());
    }
    let g = load_grant(&mut tx, v, &tenant, generation, &replay)
        .await?
        .ok_or_else(not_found)?;
    subject_of(&s, &g.grant).map_err(|_| not_found())?;
    let generation_state = generation_state(&mut tx, v, &tenant, generation)
        .await?
        .ok_or_else(integrity)?;
    let grant_state = match (g.acked, g.revoked) {
        (_, true) => RootGrantState::Revoked,
        (true, false) => RootGrantState::Acknowledged,
        (false, false) => RootGrantState::PendingAck,
    };
    let descriptor = TenantRootGrantDescriptorV2::new(g.record, grant_state, generation_state)
        .ok_or_else(integrity)?;
    tx.commit().await?;
    Ok(cbor(StatusCode::OK, descriptor.encode()))
}

/// Parses an exact outer request of `kind` and checks its instance and epoch.
pub(super) fn outer_request(
    v: &Verified,
    headers: &HeaderMap,
    body: &[u8],
    kind: OperationKind,
) -> Result<IdempotentMutationRequestV2, AppError> {
    exact_cbor_body(headers, body, MAX_ROOT_REQUEST_BODY)?;
    let outer = IdempotentMutationRequestV2::parse(body).map_err(record_error)?;
    if outer.operation_kind != kind {
        return Err(column_mismatch("the request is another operation"));
    }
    if outer.server_instance_id != v.server_instance_id {
        return Err(AppError::Forbidden);
    }
    if outer.restore_epoch != v.restore_epoch {
        return Err(stale());
    }
    Ok(outer)
}

/// `POST .../grants/{replay_id}/ack`: the subject opened its grant and the
/// TRK re-derived the target root key ID.
pub async fn ack_root_grant(
    State(app): State<AppState>,
    who: Principal,
    Path((tenant, generation, replay)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let v = verified(&app)?;
    let Principal::Session(presented) = who else {
        return Err(AppError::Forbidden);
    };
    let (tenant, generation) = path_ids(&tenant, &generation)?;
    let replay = replay_id(&replay)?;
    let outer = outer_request(v, &headers, &body, OperationKind::RootGrantAck)?;
    let ack = TenantRootGrantAckV2::parse(&outer.canonical_payload_bytes).map_err(record_error)?;
    let r = &ack.grant;
    if r.tenant_id != tenant || r.root_generation != generation || r.replay_id != replay {
        return Err(column_mismatch(
            "the path names another grant than the request",
        ));
    }
    if r.server_instance_id != v.server_instance_id {
        return Err(AppError::Forbidden);
    }
    if r.restore_epoch != v.restore_epoch {
        return Err(stale());
    }

    let mut tx = app.db.begin_with("BEGIN IMMEDIATE").await?;
    let now = now_ms();
    let s = reload_session(&mut tx, &presented, v, now)
        .await?
        .ok_or(AppError::Unauthorized)?;
    if s.tenant_id != tenant {
        return Err(AppError::Forbidden);
    }
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
        let (payload, response) = stored_payload(&row, &outer, RECORD_TYPE_ROOT_GRANT_ACKED, v)
            .ok_or_else(response_mismatch)?;
        let acked = TenantRootGrantAckedV2::parse(&payload).map_err(|_| response_mismatch())?;
        let still_acked = load_grant(&mut tx, v, &tenant, generation, &replay)
            .await?
            .is_some_and(|g| g.acked);
        if acked.grant != ack.grant || !still_acked {
            return Err(response_mismatch());
        }
        tx.commit().await?;
        return Ok(cbor(StatusCode::CREATED, response));
    }

    let g = load_grant(&mut tx, v, &tenant, generation, &replay)
        .await?
        .ok_or_else(not_found)?;
    subject_of(&s, &g.grant)?;
    let rec = g.record.record();
    let c = &g.grant.common;
    if r.root_key_id != g.grant.root_key_id
        || r.restore_epoch != c.restore_epoch
        || r.signed_container_hash != *rec.signed_container_hash()
        || r.exact_signed_container_bytes_sha256 != *rec.exact_signed_container_bytes_sha256()
    {
        return Err(column_mismatch("the acknowledgement names another grant"));
    }
    if g.revoked || g.acked {
        return Err(generation_mismatch(
            "this grant is revoked or already acknowledged",
        ));
    }
    if !inside_window(&g.grant, now)? {
        return Err(AppError::Forbidden);
    }
    match generation_state(&mut tx, v, &tenant, generation).await? {
        Some(RootGenerationState::Preparing | RootGenerationState::Active) => {}
        _ => return Err(generation_mismatch("the grant's generation is retired")),
    }

    let acked_at = at(now);
    sqlx::query(
        "UPDATE v2_tenant_root_key_grants SET acked_at = ?
          WHERE server_instance_id = ? AND tenant_id = ? AND replay_id = ? AND acked_at IS NULL",
    )
    .bind(&acked_at)
    .bind(v.server_instance_id.as_slice())
    .bind(tenant.as_slice())
    .bind(replay.as_slice())
    .execute(&mut *tx)
    .await?;
    let acked_at_ms = u64::try_from(now).unwrap_or_default();
    let payload = TenantRootGrantAckedV2 {
        grant: ack.grant.clone(),
        acked_at_ms,
    }
    .encode();
    let response = stored_response(
        &outer,
        RECORD_TYPE_ROOT_GRANT_ACKED,
        payload,
        v,
        acked_at_ms,
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
        RECORD_TYPE_ROOT_GRANT_ACKED,
        &response,
        retained_until,
    )
    .await?;
    audit(
        &mut tx,
        &s.tenant_id,
        &s.account_id,
        &s.device_id,
        "root.grant_ack",
        "root_grant",
        &replay,
    )
    .await?;
    tx.commit().await?;
    Ok(cbor(StatusCode::CREATED, response))
}

/// `POST .../root-key-generations/{g}/activate`: generation 0 becomes ACTIVE
/// once its required grants are all acknowledged and form the set it was
/// created with. The restated `recovery_bundle_sha256` is the client's
/// recovery-bundle readiness acknowledgement (plan 5.6.4 rule 1): it names the
/// bundle it holds, which must be the one the generation was created with.
pub async fn activate_root_generation(
    State(app): State<AppState>,
    who: Principal,
    Path((tenant, generation)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let v = verified(&app)?;
    let Principal::Session(presented) = who else {
        return Err(AppError::Forbidden);
    };
    let (tenant, generation) = path_ids(&tenant, &generation)?;
    let outer = outer_request(v, &headers, &body, OperationKind::RootGenerationActivate)?;
    let activate = TenantRootGenerationActivateV2::parse(&outer.canonical_payload_bytes)
        .map_err(record_error)?;
    let t = &activate.target;
    if t.tenant_id != tenant || t.root_generation != generation {
        return Err(column_mismatch(
            "the path names another generation than the request",
        ));
    }
    if t.server_instance_id != v.server_instance_id {
        return Err(AppError::Forbidden);
    }
    if t.restore_epoch != v.restore_epoch {
        return Err(stale());
    }

    let mut tx = app.db.begin_with("BEGIN IMMEDIATE").await?;
    let now = now_ms();
    let s = reload_session(&mut tx, &presented, v, now)
        .await?
        .ok_or(AppError::Unauthorized)?;
    if s.tenant_id != tenant {
        return Err(AppError::Forbidden);
    }
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
        let (payload, response) =
            stored_payload(&row, &outer, RECORD_TYPE_ROOT_GENERATION_ACTIVATED, v)
                .ok_or_else(response_mismatch)?;
        let activated =
            TenantRootGenerationActivatedV2::parse(&payload).map_err(|_| response_mismatch())?;
        let activated_at: Option<String> = sqlx::query_scalar(
            "SELECT activated_at FROM v2_root_key_generations
              WHERE server_instance_id = ? AND tenant_id = ? AND generation = ?",
        )
        .bind(v.server_instance_id.as_slice())
        .bind(tenant.as_slice())
        .bind(int(generation)?)
        .fetch_optional(&mut *tx)
        .await?
        .flatten();
        // A later rotation retires the generation; the activation still
        // happened, so its response stands.
        if activated.target != *t
            || activated.previous != activate.previous
            || activated_at.is_none()
        {
            return Err(response_mismatch());
        }
        tx.commit().await?;
        return Ok(cbor(StatusCode::CREATED, response));
    }

    // shortcut: only generation 0 activates; a rotation needs D-5 recovery
    // evidence and rotation grants, which come with ROOT_GRANT_CREATE.
    if generation != 0 {
        return Err(AppError::Forbidden);
    }
    if s.class != "root_setup" || !sole_owner(&mut tx, &s).await? {
        return Err(AppError::Forbidden);
    }
    let row = sqlx::query(
        "SELECT root_key_id, state, required_custodian_grant_count,
                required_custodian_grant_set_hash, recovery_bundle_sha256
           FROM v2_root_key_generations
          WHERE server_instance_id = ? AND tenant_id = ? AND generation = ?",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(tenant.as_slice())
    .bind(int(generation)?)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(not_found)?;
    let terms_match = blob::<32>(&row, "root_key_id")? == t.root_key_id
        && row.get::<Option<i64>, _>("required_custodian_grant_count")
            == Some(i64::from(t.required_custodian_grant_count))
        && row
            .get::<Option<Vec<u8>>, _>("required_custodian_grant_set_hash")
            .as_deref()
            == Some(&t.required_custodian_grant_set_hash[..])
        && row
            .get::<Option<Vec<u8>>, _>("recovery_bundle_sha256")
            .as_deref()
            == Some(&t.recovery_bundle_sha256[..]);
    if !terms_match {
        return Err(column_mismatch(
            "the activation names other terms than the generation was created with",
        ));
    }
    if row.get::<String, _>("state") != RootGenerationState::Preparing.as_str()
        || active_pointer(&mut tx, &tenant).await?.is_some()
    {
        return Err(generation_mismatch(
            "the generation is not the next to activate",
        ));
    }

    // The acknowledged, unrevoked grants of the generation, each read back,
    // are exactly the required set (ADR 0002 D-4); the actor holds one.
    let replays: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT replay_id FROM v2_tenant_root_key_grants
          WHERE server_instance_id = ? AND tenant_id = ? AND root_generation = ?
            AND acked_at IS NOT NULL AND revoked_at IS NULL",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(tenant.as_slice())
    .bind(int(generation)?)
    .fetch_all(&mut *tx)
    .await?;
    let mut hashes = Vec::with_capacity(replays.len());
    let mut actor_holds_one = false;
    for replay in replays {
        let replay: [u8; 16] = replay.try_into().map_err(|_| integrity())?;
        let g = load_grant(&mut tx, v, &tenant, generation, &replay)
            .await?
            .ok_or_else(integrity)?;
        if !inside_window(&g.grant, now)? {
            continue;
        }
        actor_holds_one |= subject_of(&s, &g.grant).is_ok();
        hashes.push(*g.record.record().signed_container_hash());
    }
    if hashes.len() != t.required_custodian_grant_count as usize
        || root_custodian_grant_set_hash(&hashes) != Some(t.required_custodian_grant_set_hash)
    {
        return Err(generation_mismatch(
            "the acknowledged grants are not the generation's required set",
        ));
    }
    if !actor_holds_one {
        return Err(AppError::Forbidden);
    }

    let activated_at = at(now);
    sqlx::query(
        "UPDATE v2_root_key_generations SET state = 'ACTIVE', activated_at = ?
          WHERE server_instance_id = ? AND tenant_id = ? AND generation = ? AND state = 'PREPARING'",
    )
    .bind(&activated_at)
    .bind(v.server_instance_id.as_slice())
    .bind(tenant.as_slice())
    .bind(int(generation)?)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE v2_tenants SET active_root_generation = ?
          WHERE id = ? AND active_root_generation IS NULL",
    )
    .bind(int(generation)?)
    .bind(tenant.as_slice())
    .execute(&mut *tx)
    .await?;
    let activated_at_ms = u64::try_from(now).unwrap_or_default();
    let payload = TenantRootGenerationActivatedV2 {
        target: t.clone(),
        previous: activate.previous,
        activated_at_ms,
    }
    .encode();
    let response = stored_response(
        &outer,
        RECORD_TYPE_ROOT_GENERATION_ACTIVATED,
        payload,
        v,
        activated_at_ms,
    )?;
    let retained_until = activated_at_ms
        .checked_add(AUTHORIZATION_REPLAY_RETENTION_MS)
        .ok_or(AppError::Forbidden)?;
    store_response(
        &mut tx,
        v,
        &s,
        &outer,
        &body,
        RECORD_TYPE_ROOT_GENERATION_ACTIVATED,
        &response,
        retained_until,
    )
    .await?;
    audit(
        &mut tx,
        &s.tenant_id,
        &s.account_id,
        &s.device_id,
        "root.activate",
        "root_generation",
        &t.root_key_id,
    )
    .await?;
    tx.commit().await?;
    Ok(cbor(StatusCode::CREATED, response))
}

async fn active_pointer(
    conn: &mut SqliteConnection,
    tenant: &[u8; 16],
) -> Result<Option<i64>, AppError> {
    Ok(
        sqlx::query_scalar("SELECT active_root_generation FROM v2_tenants WHERE id = ?")
            .bind(tenant.as_slice())
            .fetch_one(&mut *conn)
            .await?,
    )
}

/// Whether `now` is inside the grant's validity window.
fn inside_window(g: &TenantRootKeyGrantV2, now: i64) -> Result<bool, AppError> {
    Ok(int(g.common.not_before_ms)? <= now && now < int(g.common.not_after_ms)?)
}

/// ADR 0001 D2, ADR 0002 D-2: the session's device is a root custodian. It
/// holds an acknowledged, unrevoked root grant of the tenant's ACTIVE
/// generation, inside its window and issued to its exact keys, read back like
/// every other grant. Any variant counts: the self-grant, a grant from another
/// custodian, or the rotation grant that became this generation's.
pub(super) async fn is_active_custodian(
    conn: &mut SqliteConnection,
    v: &Verified,
    s: &Session,
    now: i64,
) -> Result<bool, AppError> {
    let Some(pointer) = active_pointer(conn, &s.tenant_id).await? else {
        return Ok(false);
    };
    let generation = u64::try_from(pointer).map_err(|_| integrity())?;
    if generation_state(conn, v, &s.tenant_id, generation).await?
        != Some(RootGenerationState::Active)
    {
        return Ok(false);
    }
    let replays: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT replay_id FROM v2_tenant_root_key_grants
          WHERE server_instance_id = ? AND tenant_id = ? AND root_generation = ?
            AND subject_device_id = ? AND acked_at IS NOT NULL AND revoked_at IS NULL",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(s.tenant_id.as_slice())
    .bind(pointer)
    .bind(s.device_id.as_slice())
    .fetch_all(&mut *conn)
    .await?;
    for replay in replays {
        let replay: [u8; 16] = replay.try_into().map_err(|_| integrity())?;
        // A broken grant refuses the whole check (422) rather than being
        // skipped: custody is never decided past a quarantined row.
        let Some(g) = load_grant(conn, v, &s.tenant_id, generation, &replay).await? else {
            continue;
        };
        let k = &g.grant;
        if g.acked
            && !g.revoked
            && inside_window(k, now)?
            && k.subject_account_id == s.account_id
            && k.subject_device_id == s.device_id
            && k.subject_signing_key_id == s.signing_key_id
            && k.recipient_hpke_key_id == s.hpke_key_id
        {
            return Ok(true);
        }
    }
    Ok(false)
}
