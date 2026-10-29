//! Profile list, publish, checkout and lease routes (plan 8.1 L1136-L1143;
//! G2-21, G2-22, G2-25).
//!
//! Publish, checkout and release take exact `IdempotentMutationRequestV2`
//! bodies (5.6.5, L948/L949/L952). One `BEGIN IMMEDIATE` reloads the session,
//! answers a retry with the stored bytes, checks the live capability and
//! profile state, then writes the mutation, the exact stored response and the
//! audit row together (L1107). A retry returns those bytes even after the
//! lease expired or was released, and never takes a second fence (L962-L970).
//! Renew and force-expire are not idempotent operations (L913 has no kind
//! for them): renew moves the expiry of a live lease its holder still may
//! check out (L1143), force-expire deletes a lease under `lease.force_expire`
//! (L1141).
//!
//! These routes serve only published profiles (a label ciphertext and key
//! generation). The legacy JSON routes (`/v2/fleet/leases`) keep their own
//! `v2_leases` rows and do not see `v2_profile_leases`. A profile past
//! version 0 is checked out against the signed head its last commit stored
//! (`v2_uploads`).

use axum::body::Bytes;
use axum::extract::{Path, RawQuery, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use sqlx::{Row, SqliteConnection};

use shared::approval_receipt::AUTHORIZATION_REPLAY_RETENTION_MS;
use shared::authz_record::Capability;
use shared::fleet_profiles::{FleetProfileHeadV2, FleetProfilePageV2, MAX_FLEET_PROFILE_PAGE};
use shared::mutation::{IdempotentMutationRequestV2, OperationKind};
use shared::profile_lease::{
    LeaseOrigin, LeaseRef, LeaseReleasedV2, LeaseRenewV2, LeaseRenewedV2, ProfileCheckoutV2,
    ProfileLeaseV2, ProfilePublishCreateV2, ProfileRef, ReleaseLeaseV2, RECORD_TYPE_LEASE_RELEASED,
};

use super::v2_approval::{approvals_among, cbor, coded, column_mismatch, exact_cbor_body};
use super::v2_auth::{audit, blob, random, reload_session, unhex, verified, Principal, Session};
use super::v2_capability::stored_row_matches;
use super::v2_root::{
    ledger_row, mismatch, record_error, same_request, store_response, stored_payload,
    stored_response, MAX_ROOT_REQUEST_BODY,
};
use super::v2_root_grants::outer_request;
use crate::error::AppError;
use crate::identity::Verified;
use crate::state::AppState;
use crate::util::{now_ms, now_rfc3339, sql_int, stored_uint};

pub(super) fn id_path(id: &str) -> Result<[u8; 16], AppError> {
    unhex::<16>(id).ok_or_else(|| AppError::BadRequest("ids must be 32 hex digits".into()))
}

pub(super) fn conflict(code: &'static str, msg: &str) -> AppError {
    coded(StatusCode::CONFLICT, code, msg)
}

pub(super) fn not_found() -> AppError {
    coded(
        StatusCode::NOT_FOUND,
        "RESOURCE_NOT_FOUND",
        "no such active published profile or fleet in this tenant",
    )
}

pub(super) fn response_mismatch() -> AppError {
    coded(
        StatusCode::UNPROCESSABLE_ENTITY,
        "MUTATION_RESPONSE_MISMATCH",
        "the stored response does not match the request",
    )
}

pub(super) fn lease_expired() -> AppError {
    conflict(
        "LEASE_EXPIRED",
        "the lease is no longer the profile's lease",
    )
}

pub(super) fn session_of(who: Principal) -> Result<Session, AppError> {
    match who {
        Principal::Session(s) => Ok(s),
        Principal::Ticket(_) => Err(AppError::Forbidden),
    }
}

/// The session holds a live `capability` grant covering `fleet` or `profile`
/// (ADR 0002 D-2 scope table). These are server RBAC, not issuer rules, so no
/// custody is needed and an account-scoped grant of the session's account
/// counts (D-2). Every candidate row must match its own container.
///
/// The device itself must be approved for the tenant or this fleet: a
/// fleet-scoped approval admits a device to that fleet only (plan L459-L460,
/// ADR 0002 Q-22). The session's own liveness already checked the epoch.
///
/// `device_only` counts device-scoped grants alone: a manifest signer must
/// hold `profile.commit` itself (ADR 0002 D-2 issuer matrix).
#[allow(clippy::too_many_arguments)]
pub(super) async fn may(
    conn: &mut SqliteConnection,
    v: &Verified,
    s: &Session,
    fleet: &[u8; 16],
    profile: Option<&[u8; 16]>,
    capability: Capability,
    device_only: bool,
    now: i64,
) -> Result<bool, AppError> {
    let candidates = sqlx::query_scalar(
        "SELECT replay_id FROM v2_device_approvals
          WHERE tenant_id = ? AND subject_device_id = ? AND subject_signing_key_id = ?
            AND subject_hpke_key_id = ? AND server_instance_id = ?
            AND revoked_at IS NULL AND not_before_ms <= ? AND not_after_ms > ?
            AND (approval_scope_kind = 'tenant'
                 OR (approval_scope_kind = 'fleet' AND approval_scope_id = ?))",
    )
    .bind(s.tenant_id.as_slice())
    .bind(s.device_id.as_slice())
    .bind(s.signing_key_id.as_slice())
    .bind(s.hpke_key_id.as_slice())
    .bind(v.server_instance_id.as_slice())
    .bind(now)
    .bind(now)
    .bind(fleet.as_slice())
    .fetch_all(&mut *conn)
    .await?;
    if approvals_among(conn, v, &s.tenant_id, candidates)
        .await?
        .is_empty()
    {
        return Ok(false);
    }
    let replays: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT replay_id FROM v2_capability_grants
          WHERE server_instance_id = ? AND tenant_id = ? AND capability = ?
            AND ((subject_kind = 'account' AND subject_account_id = ?)
                 OR (subject_kind = 'device' AND subject_device_id = ?
                     AND subject_signing_key_id = ?))
            AND (scope_kind = 'tenant' OR (scope_kind = 'fleet' AND scope_id = ?)
                 OR (scope_kind = 'profile' AND scope_id = ?))
            AND revoked_at IS NULL AND not_before_ms <= ? AND ? < not_after_ms
            AND (subject_kind = 'device' OR NOT ?)",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(s.tenant_id.as_slice())
    .bind(capability.as_str())
    .bind(s.account_id.as_slice())
    .bind(s.device_id.as_slice())
    .bind(s.signing_key_id.as_slice())
    .bind(fleet.as_slice())
    .bind(profile.map(|p| p.as_slice()))
    .bind(now)
    .bind(now)
    .bind(device_only)
    .fetch_all(&mut *conn)
    .await?;
    for replay in &replays {
        let replay: [u8; 16] = replay
            .as_slice()
            .try_into()
            .map_err(|_| column_mismatch("a stored replay id is not 16 bytes"))?;
        if !stored_row_matches(conn, &v.server_instance_id, &s.tenant_id, &replay).await? {
            return Err(column_mismatch(
                "a stored capability grant does not match its signed container",
            ));
        }
    }
    Ok(!replays.is_empty())
}

/// The fleet's ACTIVE FKEK generation on this instance and its key ID.
pub(super) async fn active_key(
    conn: &mut SqliteConnection,
    v: &Verified,
    tenant: &[u8; 16],
    fleet: &[u8; 16],
) -> Result<Option<(u64, [u8; 32])>, AppError> {
    let row = sqlx::query(
        "SELECT generation, fkek_key_id FROM v2_fleet_key_generations
          WHERE server_instance_id = ? AND tenant_id = ? AND fleet_id = ? AND state = 'ACTIVE'",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(tenant.as_slice())
    .bind(fleet.as_slice())
    .fetch_optional(&mut *conn)
    .await?;
    let Some(row) = row else { return Ok(None) };
    Ok(Some((
        stored_uint(row.get("generation"))?,
        blob::<32>(&row, "fkek_key_id")?,
    )))
}

pub(super) fn no_active_key() -> AppError {
    conflict(
        "FLEET_GENERATION_NOT_ACTIVE",
        "the fleet has no ACTIVE key generation with this key",
    )
}

/// A published, active profile of an active fleet: its version and last fence.
pub(super) async fn published(
    conn: &mut SqliteConnection,
    p: &ProfileRef,
) -> Result<Option<(u64, u64)>, AppError> {
    let row = sqlx::query(
        "SELECT p.current_version, p.last_fencing_token FROM v2_profiles p
           JOIN v2_fleets f ON f.tenant_id = p.tenant_id AND f.id = p.fleet_id
          WHERE p.tenant_id = ? AND p.id = ? AND p.fleet_id = ? AND p.status = 'active'
            AND p.label_ciphertext IS NOT NULL AND f.status = 'active'",
    )
    .bind(p.tenant_id.as_slice())
    .bind(p.profile_id.as_slice())
    .bind(p.fleet_id.as_slice())
    .fetch_optional(&mut *conn)
    .await?;
    let Some(row) = row else { return Ok(None) };
    Ok(Some((
        stored_uint(row.get("current_version"))?,
        stored_uint(row.get("last_fencing_token"))?,
    )))
}

/// The profile's current lease row: lease ID, owner device, fence, base and
/// expiry.
struct CurrentLease {
    lease: LeaseRef,
    owner_device_id: Vec<u8>,
    expires_at_ms: i64,
}

async fn current_lease(
    conn: &mut SqliteConnection,
    p: &ProfileRef,
) -> Result<Option<CurrentLease>, AppError> {
    let row = sqlx::query(
        "SELECT l.lease_id, l.owner_device_id, l.fencing_token, l.base_version, l.expires_at_ms
           FROM v2_profile_leases l
           JOIN v2_profiles p ON p.tenant_id = l.tenant_id AND p.id = l.profile_id
          WHERE l.tenant_id = ? AND l.profile_id = ? AND p.fleet_id = ?",
    )
    .bind(p.tenant_id.as_slice())
    .bind(p.profile_id.as_slice())
    .bind(p.fleet_id.as_slice())
    .fetch_optional(&mut *conn)
    .await?;
    let Some(row) = row else { return Ok(None) };
    Ok(Some(CurrentLease {
        lease: LeaseRef {
            lease_id: blob::<16>(&row, "lease_id")?,
            fencing_token: stored_uint(row.get("fencing_token"))?,
            base_version: stored_uint(row.get("base_version"))?,
        },
        owner_device_id: row.get("owner_device_id"),
        expires_at_ms: row.get("expires_at_ms"),
    }))
}

/// Refuses unless the caller holds `lease` on `p` right now: the current row,
/// its own device, the exact fence and base, not expired (L1174).
pub(super) async fn held_lease(
    conn: &mut SqliteConnection,
    p: &ProfileRef,
    s: &Session,
    lease: &LeaseRef,
    now: i64,
) -> Result<(), AppError> {
    let held = current_lease(conn, p)
        .await?
        .filter(|l| l.lease.lease_id == lease.lease_id)
        .ok_or_else(lease_expired)?;
    if held.owner_device_id != s.device_id {
        return Err(AppError::Forbidden);
    }
    if held.lease != *lease {
        return Err(conflict(
            "FENCE_STALE",
            "the lease holds another fence or base",
        ));
    }
    if held.expires_at_ms <= now {
        return Err(lease_expired());
    }
    Ok(())
}

/// The signed head the commit of `version` stored; `None` at version 0, and
/// for a version without its snapshot row, which then matches no request.
pub(super) async fn head(
    conn: &mut SqliteConnection,
    v: &Verified,
    p: &ProfileRef,
    version: u64,
) -> Result<Option<[u8; 32]>, AppError> {
    let row = sqlx::query(
        "SELECT head_hash FROM v2_snapshots
          WHERE server_instance_id = ? AND tenant_id = ? AND profile_id = ? AND version = ?",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(p.tenant_id.as_slice())
    .bind(p.profile_id.as_slice())
    .bind(sql_int(version)?)
    .fetch_optional(&mut *conn)
    .await?;
    row.map(|r| blob::<32>(&r, "head_hash")).transpose()
}

/// Sets the profile's fence to `fence` and inserts the lease it grants.
#[allow(clippy::too_many_arguments)]
async fn grant_lease(
    conn: &mut SqliteConnection,
    s: &Session,
    outer: &IdempotentMutationRequestV2,
    p: &ProfileRef,
    lease: &LeaseRef,
    now: i64,
    expires_at_ms: i64,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE v2_profiles SET last_fencing_token = ?, updated_at = ?
          WHERE tenant_id = ? AND id = ?",
    )
    .bind(sql_int(lease.fencing_token)?)
    .bind(now_rfc3339())
    .bind(p.tenant_id.as_slice())
    .bind(p.profile_id.as_slice())
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "INSERT INTO v2_profile_leases
             (tenant_id, profile_id, lease_id, owner_account_id, owner_device_id, fencing_token,
              base_version, acquired_at_ms, expires_at_ms, checkout_request_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(p.tenant_id.as_slice())
    .bind(p.profile_id.as_slice())
    .bind(lease.lease_id.as_slice())
    .bind(s.account_id.as_slice())
    .bind(s.device_id.as_slice())
    .bind(sql_int(lease.fencing_token)?)
    .bind(sql_int(lease.base_version)?)
    .bind(now)
    .bind(expires_at_ms)
    .bind(outer.idempotency_key.as_slice())
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Server time plus a TTL already bounded to 30..900 s by the codec.
fn expiry(now: i64, ttl_seconds: u32) -> i64 {
    now + i64::from(ttl_seconds) * 1000
}

/// Stores the exact response under the actor's key, with the audit row, and
/// commits nothing yet: the caller commits.
#[allow(clippy::too_many_arguments)]
pub(super) async fn finish(
    conn: &mut SqliteConnection,
    v: &Verified,
    s: &Session,
    outer: &IdempotentMutationRequestV2,
    exact_request: &[u8],
    record_type: &str,
    payload: Vec<u8>,
    now: i64,
    action: &str,
    target: (&str, &[u8]),
) -> Result<Vec<u8>, AppError> {
    let committed_at_ms = u64::try_from(now).unwrap_or_default();
    let response = stored_response(outer, record_type, payload, v, committed_at_ms)?;
    let retained_until = committed_at_ms
        .checked_add(AUTHORIZATION_REPLAY_RETENTION_MS)
        .ok_or(AppError::Forbidden)?;
    store_response(
        conn,
        v,
        s,
        outer,
        exact_request,
        record_type,
        &response,
        retained_until,
    )
    .await?;
    audit(
        conn,
        &s.tenant_id,
        &s.account_id,
        &s.device_id,
        action,
        target.0,
        target.1,
    )
    .await?;
    Ok(response)
}

/// The stored response of `row` for this request, if the request is the same
/// exact bytes (else `IDEMPOTENCY_MISMATCH`) and the response is the exact map
/// of `record_type` (else `MUTATION_RESPONSE_MISMATCH`).
pub(super) fn replay(
    row: &sqlx::sqlite::SqliteRow,
    outer: &IdempotentMutationRequestV2,
    body: &[u8],
    record_type: &str,
    v: &Verified,
) -> Result<(Vec<u8>, Vec<u8>), AppError> {
    if !same_request(
        row,
        outer.operation_kind,
        &outer.canonical_request_hash(),
        body,
    )? {
        return Err(mismatch());
    }
    stored_payload(row, outer, record_type, v).ok_or_else(response_mismatch)
}

// ------------------------------------------------------------------- list ---

/// `GET /v2/fleets/{fleet_id}/profiles` (L1136): the heads of the fleet's
/// published profiles, without a lease, at most [`MAX_FLEET_PROFILE_PAGE`] a
/// page in ascending ID order from `?after=<id>`. It shows what a checkout
/// observes (L949), so it needs `profile.checkout` over the whole fleet or
/// tenant (a profile-scoped grant lists nothing) and a tenant or fleet approval.
pub async fn list_profiles(
    State(app): State<AppState>,
    who: Principal,
    Path(fleet): Path<String>,
    RawQuery(raw): RawQuery,
) -> Result<Response, AppError> {
    let v = verified(&app)?;
    let presented = session_of(who)?;
    let fleet = id_path(&fleet)?;
    let after = match raw.as_deref() {
        None | Some("") => None,
        Some(q) => Some(
            q.strip_prefix("after=")
                .and_then(unhex::<16>)
                .ok_or_else(|| AppError::BadRequest("the query takes one after=<id>".into()))?,
        ),
    };

    let mut tx = app.db.begin().await?;
    let now = now_ms();
    let s = reload_session(&mut tx, &presented, v, now)
        .await?
        .ok_or(AppError::Unauthorized)?;
    if !may(
        &mut tx,
        v,
        &s,
        &fleet,
        None,
        Capability::ProfileCheckout,
        false,
        now,
    )
    .await?
    {
        return Err(AppError::Forbidden);
    }
    let fleet_active: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM v2_fleets
                         WHERE tenant_id = ? AND id = ? AND status = 'active')",
    )
    .bind(s.tenant_id.as_slice())
    .bind(fleet.as_slice())
    .fetch_one(&mut *tx)
    .await?;
    if !fleet_active {
        return Err(not_found());
    }
    let rows = sqlx::query(
        "SELECT p.id, p.current_version, p.current_key_generation, p.label_ciphertext,
                s.head_hash
           FROM v2_profiles p
           LEFT JOIN v2_snapshots s
             ON s.server_instance_id = ?1 AND s.tenant_id = p.tenant_id
            AND s.profile_id = p.id AND s.version = p.current_version
          WHERE p.tenant_id = ?2 AND p.fleet_id = ?3 AND p.status = 'active'
            AND p.label_ciphertext IS NOT NULL AND (?4 IS NULL OR p.id > ?4)
          ORDER BY p.id LIMIT ?5",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(s.tenant_id.as_slice())
    .bind(fleet.as_slice())
    .bind(after.as_ref().map(|a| a.as_slice()))
    .bind(MAX_FLEET_PROFILE_PAGE as i64 + 1)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;

    let mut profiles = Vec::with_capacity(rows.len());
    for row in rows.iter().take(MAX_FLEET_PROFILE_PAGE) {
        let current_version = stored_uint(row.get("current_version"))?;
        let head: Option<Vec<u8>> = row.get("head_hash");
        let current_signed_head_hash = match head {
            Some(h) => Some(
                h.try_into()
                    .map_err(|_| column_mismatch("a stored head hash is not 32 bytes"))?,
            ),
            None if current_version == 0 => None,
            None => return Err(column_mismatch("a published version has no stored head")),
        };
        profiles.push(FleetProfileHeadV2 {
            profile_id: blob::<16>(row, "id")?,
            current_version,
            current_signed_head_hash,
            key_generation: stored_uint(row.try_get("current_key_generation")?)?,
            label_ciphertext: row.get("label_ciphertext"),
        });
    }
    let next_after = (rows.len() > MAX_FLEET_PROFILE_PAGE)
        .then(|| profiles.last().map(|p| p.profile_id))
        .flatten();
    let page = FleetProfilePageV2 {
        server_instance_id: v.server_instance_id,
        restore_epoch: v.restore_epoch,
        tenant_id: s.tenant_id,
        fleet_id: fleet,
        profiles,
        next_after,
    };
    Ok(cbor(StatusCode::OK, page.encode()))
}

// ------------------------------------------------- PROFILE_PUBLISH_CREATE ---

/// `POST /v2/fleets/{fleet_id}/profiles` (L1137): the version-0 profile, its
/// first fence and lease, the stored response and the audit row, at once.
pub async fn publish_profile(
    State(app): State<AppState>,
    who: Principal,
    Path(fleet): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let v = verified(&app)?;
    let presented = session_of(who)?;
    let fleet = id_path(&fleet)?;
    let outer = outer_request(v, &headers, &body, OperationKind::ProfilePublishCreate)?;
    let req =
        ProfilePublishCreateV2::parse(&outer.canonical_payload_bytes).map_err(record_error)?;
    let p = req.profile;
    if p.fleet_id != fleet {
        return Err(column_mismatch(
            "the path names another fleet than the request",
        ));
    }

    let mut tx = app.db.begin_with("BEGIN IMMEDIATE").await?;
    let now = now_ms();
    let s = reload_session(&mut tx, &presented, v, now)
        .await?
        .ok_or(AppError::Unauthorized)?;
    if s.tenant_id != p.tenant_id {
        return Err(AppError::Forbidden);
    }
    let origin = LeaseOrigin::PublishCreate;
    if let Some(row) =
        ledger_row(&mut tx, v, &s, outer.operation_kind, &outer.idempotency_key).await?
    {
        let (payload, response) = replay(&row, &outer, &body, origin.record_type(), v)?;
        let granted = ProfileLeaseV2::parse(origin, &payload).map_err(|_| response_mismatch())?;
        if granted.profile != p {
            return Err(response_mismatch());
        }
        tx.commit().await?;
        return Ok(cbor(StatusCode::CREATED, response));
    }

    if !may(
        &mut tx,
        v,
        &s,
        &fleet,
        None,
        Capability::ProfilePublish,
        false,
        now,
    )
    .await?
    {
        return Err(AppError::Forbidden);
    }
    let fleet_active: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM v2_fleets
                         WHERE tenant_id = ? AND id = ? AND status = 'active')",
    )
    .bind(p.tenant_id.as_slice())
    .bind(fleet.as_slice())
    .fetch_one(&mut *tx)
    .await?;
    if !fleet_active {
        return Err(not_found());
    }
    if active_key(&mut tx, v, &p.tenant_id, &fleet).await?
        != Some((req.key_generation, req.fkek_key_id))
    {
        return Err(no_active_key());
    }
    // The row's `name` is the hex ID, which a legacy profile may already use.
    let name = crate::identity::hex(&p.profile_id);
    let taken: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM v2_profiles
                         WHERE tenant_id = ? AND (id = ? OR (fleet_id = ? AND name = ?)))",
    )
    .bind(p.tenant_id.as_slice())
    .bind(p.profile_id.as_slice())
    .bind(fleet.as_slice())
    .bind(&name)
    .fetch_one(&mut *tx)
    .await?;
    if taken {
        return Err(conflict(
            "PROFILE_EXISTS",
            "this profile ID is already in use",
        ));
    }

    let stamp = now_rfc3339();
    sqlx::query(
        "INSERT INTO v2_profiles
             (id, tenant_id, fleet_id, name, current_version, status, created_at, updated_at,
              label_ciphertext, last_fencing_token, current_key_generation)
         VALUES (?, ?, ?, ?, 0, 'active', ?, ?, ?, 0, ?)",
    )
    .bind(p.profile_id.as_slice())
    .bind(p.tenant_id.as_slice())
    .bind(fleet.as_slice())
    .bind(&name)
    .bind(&stamp)
    .bind(&stamp)
    .bind(req.label_ciphertext.as_slice())
    .bind(sql_int(req.key_generation)?)
    .execute(&mut *tx)
    .await?;
    let lease = LeaseRef {
        lease_id: random::<16>()?,
        fencing_token: 1,
        base_version: 0,
    };
    let expires_at_ms = expiry(now, req.requested_lease_ttl_seconds);
    grant_lease(&mut tx, &s, &outer, &p, &lease, now, expires_at_ms).await?;
    let payload = ProfileLeaseV2 {
        profile: p,
        lease,
        expires_at_ms: u64::try_from(expires_at_ms).unwrap_or_default(),
        fkek_key_id: req.fkek_key_id,
        key_generation: req.key_generation,
        current_signed_head_hash: None,
        server_instance_id: v.server_instance_id,
        restore_epoch: v.restore_epoch,
    }
    .encode(origin);
    let response = finish(
        &mut tx,
        v,
        &s,
        &outer,
        &body,
        origin.record_type(),
        payload,
        now,
        "profile.publish_create",
        ("profile", &p.profile_id),
    )
    .await?;
    tx.commit().await?;
    Ok(cbor(StatusCode::CREATED, response))
}

// ------------------------------------------------------- PROFILE_CHECKOUT ---

/// `POST /v2/profiles/{profile_id}/checkout` (L1138): one new fence and lease,
/// replacing an expired lease row.
pub async fn checkout_profile(
    State(app): State<AppState>,
    who: Principal,
    Path(profile): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let v = verified(&app)?;
    let presented = session_of(who)?;
    let profile = id_path(&profile)?;
    let outer = outer_request(v, &headers, &body, OperationKind::ProfileCheckout)?;
    let req = ProfileCheckoutV2::parse(&outer.canonical_payload_bytes).map_err(record_error)?;
    let p = req.profile;
    if p.profile_id != profile {
        return Err(column_mismatch(
            "the path names another profile than the request",
        ));
    }

    let mut tx = app.db.begin_with("BEGIN IMMEDIATE").await?;
    let now = now_ms();
    let s = reload_session(&mut tx, &presented, v, now)
        .await?
        .ok_or(AppError::Unauthorized)?;
    if s.tenant_id != p.tenant_id {
        return Err(AppError::Forbidden);
    }
    let origin = LeaseOrigin::Checkout;
    if let Some(row) =
        ledger_row(&mut tx, v, &s, outer.operation_kind, &outer.idempotency_key).await?
    {
        // L966: the stored bytes, even if that lease has since expired.
        let (payload, response) = replay(&row, &outer, &body, origin.record_type(), v)?;
        let granted = ProfileLeaseV2::parse(origin, &payload).map_err(|_| response_mismatch())?;
        if granted.profile != p {
            return Err(response_mismatch());
        }
        tx.commit().await?;
        return Ok(cbor(StatusCode::CREATED, response));
    }

    if !may(
        &mut tx,
        v,
        &s,
        &p.fleet_id,
        Some(&profile),
        Capability::ProfileCheckout,
        false,
        now,
    )
    .await?
    {
        return Err(AppError::Forbidden);
    }
    let (current_version, last_fence) = published(&mut tx, &p).await?.ok_or_else(not_found)?;
    let current_head = head(&mut tx, v, &p, current_version).await?;
    if req.observed_version != current_version || req.observed_signed_head_hash != current_head {
        return Err(conflict(
            "BASE_VERSION_MISMATCH",
            "the profile is not at the observed version and head",
        ));
    }
    let (key_generation, fkek_key_id) = active_key(&mut tx, v, &p.tenant_id, &p.fleet_id)
        .await?
        .ok_or_else(no_active_key)?;
    if let Some(held) = current_lease(&mut tx, &p).await? {
        if held.expires_at_ms > now {
            return Err(conflict("LEASE_HELD", "the profile is checked out"));
        }
        sqlx::query("DELETE FROM v2_profile_leases WHERE tenant_id = ? AND profile_id = ?")
            .bind(p.tenant_id.as_slice())
            .bind(p.profile_id.as_slice())
            .execute(&mut *tx)
            .await?;
    }

    let lease = LeaseRef {
        lease_id: random::<16>()?,
        // L1098: overflow fails closed (`sql_int` refuses i64::MAX + 1).
        fencing_token: last_fence + 1,
        base_version: current_version,
    };
    let expires_at_ms = expiry(now, req.requested_lease_ttl_seconds);
    grant_lease(&mut tx, &s, &outer, &p, &lease, now, expires_at_ms).await?;
    let payload = ProfileLeaseV2 {
        profile: p,
        lease,
        expires_at_ms: u64::try_from(expires_at_ms).unwrap_or_default(),
        fkek_key_id,
        key_generation,
        current_signed_head_hash: current_head,
        server_instance_id: v.server_instance_id,
        restore_epoch: v.restore_epoch,
    }
    .encode(origin);
    let response = finish(
        &mut tx,
        v,
        &s,
        &outer,
        &body,
        origin.record_type(),
        payload,
        now,
        "profile.checkout",
        ("profile_lease", &lease.lease_id),
    )
    .await?;
    tx.commit().await?;
    Ok(cbor(StatusCode::CREATED, response))
}

// ---------------------------------------------------------- RELEASE_LEASE ---

/// `POST /v2/profiles/{profile_id}/leases/{lease_id}/release` (L1140): the
/// holder deletes its lease; a retry gets the stored bytes after the delete.
pub async fn release_lease(
    State(app): State<AppState>,
    who: Principal,
    Path((profile, lease_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let v = verified(&app)?;
    let presented = session_of(who)?;
    let (profile, lease_id) = (id_path(&profile)?, id_path(&lease_id)?);
    let outer = outer_request(v, &headers, &body, OperationKind::ReleaseLease)?;
    let req = ReleaseLeaseV2::parse(&outer.canonical_payload_bytes).map_err(record_error)?;
    let p = req.profile;
    if p.profile_id != profile || req.lease.lease_id != lease_id {
        return Err(column_mismatch(
            "the path names another lease than the request",
        ));
    }

    let mut tx = app.db.begin_with("BEGIN IMMEDIATE").await?;
    let now = now_ms();
    let s = reload_session(&mut tx, &presented, v, now)
        .await?
        .ok_or(AppError::Unauthorized)?;
    if s.tenant_id != p.tenant_id {
        return Err(AppError::Forbidden);
    }
    if let Some(row) =
        ledger_row(&mut tx, v, &s, outer.operation_kind, &outer.idempotency_key).await?
    {
        let (payload, response) = replay(&row, &outer, &body, RECORD_TYPE_LEASE_RELEASED, v)?;
        let released = LeaseReleasedV2::parse(&payload).map_err(|_| response_mismatch())?;
        if released.profile != p || released.lease != req.lease {
            return Err(response_mismatch());
        }
        tx.commit().await?;
        return Ok(cbor(StatusCode::OK, response));
    }

    // Only the holder releases: giving a lease up needs no capability, and
    // anyone else ends it through force-expire under `lease.force_expire`.
    let held = current_lease(&mut tx, &p)
        .await?
        .filter(|l| l.lease.lease_id == lease_id)
        .ok_or_else(lease_expired)?;
    if held.owner_device_id != s.device_id {
        return Err(AppError::Forbidden);
    }
    if held.lease != req.lease {
        return Err(conflict(
            "FENCE_STALE",
            "the lease holds another fence or base",
        ));
    }
    sqlx::query("DELETE FROM v2_profile_leases WHERE tenant_id = ? AND profile_id = ?")
        .bind(p.tenant_id.as_slice())
        .bind(p.profile_id.as_slice())
        .execute(&mut *tx)
        .await?;
    let payload = LeaseReleasedV2 {
        profile: p,
        lease: req.lease,
        released_at_ms: u64::try_from(now).unwrap_or_default(),
        server_instance_id: v.server_instance_id,
        restore_epoch: v.restore_epoch,
    }
    .encode();
    let response = finish(
        &mut tx,
        v,
        &s,
        &outer,
        &body,
        RECORD_TYPE_LEASE_RELEASED,
        payload,
        now,
        "profile.release_lease",
        ("profile_lease", &lease_id),
    )
    .await?;
    tx.commit().await?;
    Ok(cbor(StatusCode::OK, response))
}

// ------------------------------------------------------------------ renew ---

/// `POST /v2/profiles/{profile_id}/leases/{lease_id}/renew` (L1139, L1143):
/// only the holder, only while the row matches and has not expired, and only
/// while it still may check the profile out.
pub async fn renew_lease(
    State(app): State<AppState>,
    who: Principal,
    Path((profile, lease_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let v = verified(&app)?;
    let presented = session_of(who)?;
    let (profile, lease_id) = (id_path(&profile)?, id_path(&lease_id)?);
    exact_cbor_body(&headers, &body, MAX_ROOT_REQUEST_BODY)?;
    let req = LeaseRenewV2::parse(&body).map_err(record_error)?;
    let p = req.profile;
    if p.profile_id != profile || req.lease.lease_id != lease_id {
        return Err(column_mismatch(
            "the path names another lease than the request",
        ));
    }

    let mut tx = app.db.begin_with("BEGIN IMMEDIATE").await?;
    let now = now_ms();
    let s = reload_session(&mut tx, &presented, v, now)
        .await?
        .ok_or(AppError::Unauthorized)?;
    if s.tenant_id != p.tenant_id {
        return Err(AppError::Forbidden);
    }
    if !may(
        &mut tx,
        v,
        &s,
        &p.fleet_id,
        Some(&profile),
        Capability::ProfileCheckout,
        false,
        now,
    )
    .await?
    {
        return Err(AppError::Forbidden);
    }
    // The profile and its fleet are still active.
    published(&mut tx, &p).await?.ok_or_else(not_found)?;
    let held = current_lease(&mut tx, &p)
        .await?
        .filter(|l| l.lease.lease_id == lease_id)
        .ok_or_else(lease_expired)?;
    if held.owner_device_id != s.device_id {
        return Err(AppError::Forbidden);
    }
    if held.lease != req.lease {
        return Err(conflict(
            "FENCE_STALE",
            "the lease holds another fence or base",
        ));
    }
    // L1143: no relaunch grace.
    if held.expires_at_ms <= now {
        return Err(lease_expired());
    }
    let expires_at_ms = expiry(now, req.requested_lease_ttl_seconds);
    sqlx::query(
        "UPDATE v2_profile_leases SET expires_at_ms = ? WHERE tenant_id = ? AND profile_id = ?",
    )
    .bind(expires_at_ms)
    .bind(p.tenant_id.as_slice())
    .bind(p.profile_id.as_slice())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let renewed = LeaseRenewedV2 {
        profile: p,
        lease: req.lease,
        expires_at_ms: u64::try_from(expires_at_ms).unwrap_or_default(),
    };
    Ok(cbor(StatusCode::OK, renewed.encode()))
}

// ------------------------------------------------------------ force-expire ---

/// `POST /v2/profiles/{profile_id}/leases/{lease_id}/force-expire` (L1141):
/// deletes the lease under `lease.force_expire`, with its audit row.
pub async fn force_expire_lease(
    State(app): State<AppState>,
    who: Principal,
    Path((profile, lease_id)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let v = verified(&app)?;
    let presented = session_of(who)?;
    let (profile, lease_id) = (id_path(&profile)?, id_path(&lease_id)?);

    let mut tx = app.db.begin_with("BEGIN IMMEDIATE").await?;
    let now = now_ms();
    let s = reload_session(&mut tx, &presented, v, now)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let fleet: Vec<u8> =
        sqlx::query_scalar("SELECT fleet_id FROM v2_profiles WHERE tenant_id = ? AND id = ?")
            .bind(s.tenant_id.as_slice())
            .bind(profile.as_slice())
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(not_found)?;
    let fleet: [u8; 16] = fleet
        .try_into()
        .map_err(|_| AppError::Internal("a stored fleet id is not 16 bytes".into()))?;
    if !may(
        &mut tx,
        v,
        &s,
        &fleet,
        Some(&profile),
        Capability::LeaseForceExpire,
        false,
        now,
    )
    .await?
    {
        return Err(AppError::Forbidden);
    }
    let gone = sqlx::query(
        "DELETE FROM v2_profile_leases WHERE tenant_id = ? AND profile_id = ? AND lease_id = ?",
    )
    .bind(s.tenant_id.as_slice())
    .bind(profile.as_slice())
    .bind(lease_id.as_slice())
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if gone == 0 {
        return Err(lease_expired());
    }
    audit(
        &mut tx,
        &s.tenant_id,
        &s.account_id,
        &s.device_id,
        "lease.force_expire",
        "profile_lease",
        &lease_id,
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
