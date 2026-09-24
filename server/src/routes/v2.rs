//! v2 team/fleet endpoints.
//!
//! These carry their own authorization: a v1 session token says who is
//! logged in, but a v2 operation additionally requires a signed record that
//! binds the action to a tenant, a server instance and a restore epoch. The
//! session and the record are checked independently — neither substitutes
//! for the other.

use argon2::password_hash::rand_core::{OsRng, RngCore};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use serde::Deserialize;
use sqlx::Row;

use crate::auth::AuthUser;
use crate::authz::{self, VerificationContext};
use crate::enrollment::{HPKE_SUITE_X25519_HKDF_SHA256, SIGNING_SUITE_ED25519};
use crate::error::AppError;
use crate::fleet;
use crate::idempotency::{self, OperationClaim, ReplayClaim, ReplayTable};
use crate::state::AppState;
use crate::util;

/// Hex-decode a fixed-width id from a request field.
fn parse_id16(hex: &str, field: &'static str) -> Result<[u8; 16], AppError> {
    let bytes = decode_hex(hex).ok_or_else(|| AppError::BadRequest(format!("{field}: not hex")))?;
    bytes
        .try_into()
        .map_err(|_| AppError::BadRequest(format!("{field}: must be 16 bytes")))
}

/// Parse a 32-byte identifier such as a root key id.
fn parse_id32(hex: &str, field: &'static str) -> Result<[u8; 32], AppError> {
    let bytes = decode_hex(hex).ok_or_else(|| AppError::BadRequest(format!("{field}: not hex")))?;
    bytes
        .try_into()
        .map_err(|_| AppError::BadRequest(format!("{field}: expected 32 bytes")))
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Load the server-side facts a signed record is checked against.
///
/// Read from the database on every request rather than cached: the restore
/// epoch changes exactly when a restore happens, and a cached epoch would
/// keep honouring pre-restore records for the lifetime of the cache.
async fn verification_context(
    app: &AppState,
    tenant_id: [u8; 16],
    now_ms: u64,
) -> Result<VerificationContext, AppError> {
    // `v2_server_state` is a singleton: the instance id and restore epoch
    // describe the deployment, not a tenant. Reading it per request keeps the
    // epoch honest — a cached value would keep honouring pre-restore records.
    let row = sqlx::query(
        "SELECT server_instance_id, restore_epoch FROM v2_server_state WHERE singleton = 1",
    )
    .fetch_optional(&app.db)
    .await?
    .ok_or_else(|| AppError::BadRequest("server identity is not initialised".into()))?;

    let instance: Vec<u8> = row.get("server_instance_id");
    let epoch: i64 = row.get("restore_epoch");

    // Only keys this tenant currently trusts. A revoked issuer disappears
    // from this set, so its records stop verifying without any separate
    // revocation check on the hot path.
    let issuer_rows = sqlx::query(
        "SELECT signing_key_id, public_key FROM v2_tenant_issuers
          WHERE tenant_id = ? AND revoked_at IS NULL",
    )
    .bind(tenant_id.as_slice())
    .fetch_all(&app.db)
    .await?;

    let mut trusted = std::collections::HashMap::new();
    for r in issuer_rows {
        let id: Vec<u8> = r.get("signing_key_id");
        let pk: Vec<u8> = r.get("public_key");
        if let (Ok(id), Ok(pk)) = (<[u8; 32]>::try_from(id), <[u8; 32]>::try_from(pk)) {
            trusted.insert(id, pk);
        }
    }

    Ok(VerificationContext {
        tenant_id,
        server_instance_id: instance
            .try_into()
            .map_err(|_| AppError::BadRequest("corrupt server_instance_id".into()))?,
        restore_epoch: epoch as u64,
        now_ms,
        trusted_issuers: trusted,
    })
}

/// Publish the deployment identity a client must bind its signed records to.
///
/// A client cannot construct a valid manifest without `server_instance_id` and
/// `restore_epoch`. The verifier checks both against live deployment state, so
/// a client that guesses them produces records the server refuses. Read-only
/// and derived from the same singleton row the verifier reads.
pub async fn server_identity(
    State(app): State<AppState>,
    _user: AuthUser,
) -> Result<impl IntoResponse, AppError> {
    let row = sqlx::query(
        "SELECT server_instance_id, restore_epoch FROM v2_server_state WHERE singleton = 1",
    )
    .fetch_optional(&app.db)
    .await?
    .ok_or_else(|| AppError::BadRequest("server identity is not initialised".into()))?;

    let instance: Vec<u8> = row.get("server_instance_id");
    let epoch: i64 = row.get("restore_epoch");

    Ok(axum::Json(serde_json::json!({
        "server_instance_id": hex(&instance),
        "restore_epoch": epoch,
    })))
}

#[derive(Deserialize)]
pub struct BeginRootGenerationReq {
    pub tenant_id: String,
    /// Identifier of a root key generated on the caller's device. The key
    /// itself is never sent.
    pub root_key_id: String,
}

#[derive(Deserialize)]
pub struct BeginFleetGenerationReq {
    pub tenant_id: String,
    pub fleet_id: String,
    /// Identifier of a fleet key generated on the caller's device. The key
    /// itself is never sent.
    pub fkek_key_id: String,
}

#[derive(Deserialize)]
pub struct ActivateFleetGenerationReq {
    pub tenant_id: String,
    pub fleet_id: String,
    pub generation: u64,
}

#[derive(Deserialize)]
pub struct ActivateRootGenerationReq {
    pub tenant_id: String,
    pub generation: u64,
}
#[derive(Deserialize)]
pub struct PresentRecordReq {
    /// Tenant this operation targets, hex-encoded.
    pub tenant_id: String,
    /// Hex-encoded exact signed container bytes, verified as received.
    pub record_hex: String,
}

/// Present a signed device approval.
///
/// Verification and consumption are separate steps on purpose: verification
/// is a pure function of bytes and context, while consumption mutates state
/// and can lose a race. Both must succeed.
pub async fn present_device_approval(
    State(app): State<AppState>,
    user: AuthUser,
    headers: HeaderMap,
    axum::Json(req): axum::Json<PresentRecordReq>,
) -> Result<impl IntoResponse, AppError> {
    let tenant_id = parse_id16(&req.tenant_id, "tenant_id")?;
    let record_bytes = decode_hex(&req.record_hex)
        .ok_or_else(|| AppError::BadRequest("record_hex: not hex".into()))?;

    let now_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
    let ctx = verification_context(&app, tenant_id, now_ms).await?;

    let verified = authz::verify_record(&record_bytes, authz::DOMAIN_DEVICE_APPROVAL, &ctx)
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    // Consume after verification: an invalid record must not burn a replay id,
    // or an attacker could disable a legitimate record by submitting a
    // corrupted copy of it first.
    match idempotency::consume_replay_id(
        &app.db,
        &tenant_id,
        ReplayTable::DeviceApprovals,
        &verified,
        &util::now_rfc3339(),
    )
    .await?
    {
        ReplayClaim::Fresh => {}
        ReplayClaim::AlreadyUsed => {
            return Err(AppError::Conflict(
                "authorization record already used".into(),
            ))
        }
    }

    crate::audit::log(
        &app.db,
        Some(&user.id),
        "v2.device_approval.accepted",
        None,
        &hex(&verified.signed_container_hash),
    )
    .await;

    let _ = headers;
    Ok((
        StatusCode::CREATED,
        axum::Json(serde_json::json!({
            "accepted": true,
            "signed_container_hash": hex(&verified.signed_container_hash),
        })),
    ))
}

#[derive(Deserialize)]
pub struct CompleteOpReq {
    pub tenant_id: String,
    pub idempotency_key: String,
    pub status_code: u16,
    /// Hex-encoded exact response bytes to replay on retry.
    pub response_hex: String,
}

/// Record an operation's outcome so subsequent retries replay it verbatim.
pub async fn complete_idempotent_operation(
    State(app): State<AppState>,
    _user: AuthUser,
    axum::Json(req): axum::Json<CompleteOpReq>,
) -> Result<impl IntoResponse, AppError> {
    let tenant_id = parse_id16(&req.tenant_id, "tenant_id")?;
    let key = parse_id16(&req.idempotency_key, "idempotency_key")?;
    let body = decode_hex(&req.response_hex)
        .ok_or_else(|| AppError::BadRequest("response_hex: not hex".into()))?;

    let now_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
    let ctx = verification_context(&app, tenant_id, now_ms).await?;

    idempotency::complete_operation(
        &app.db,
        &tenant_id,
        &key,
        &ctx.server_instance_id,
        ctx.restore_epoch,
        req.status_code,
        &body,
        &util::now_rfc3339(),
    )
    .await?;

    Ok((
        StatusCode::OK,
        axum::Json(serde_json::json!({ "recorded": true })),
    ))
}

/// Present a signed capability grant.
///
/// Same two-step shape as a device approval — verify, then consume — but
/// under its own domain, so a grant and an approval can never be substituted
/// for one another even if they share a replay id.
pub async fn present_capability_grant(
    State(app): State<AppState>,
    user: AuthUser,
    axum::Json(req): axum::Json<PresentRecordReq>,
) -> Result<impl IntoResponse, AppError> {
    let tenant_id = parse_id16(&req.tenant_id, "tenant_id")?;
    let record_bytes = decode_hex(&req.record_hex)
        .ok_or_else(|| AppError::BadRequest("record_hex: not hex".into()))?;

    let now_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
    let ctx = verification_context(&app, tenant_id, now_ms).await?;

    let verified = authz::verify_record(&record_bytes, authz::DOMAIN_CAPABILITY_GRANT, &ctx)
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    match idempotency::consume_replay_id(
        &app.db,
        &tenant_id,
        ReplayTable::CapabilityGrants,
        &verified,
        &util::now_rfc3339(),
    )
    .await?
    {
        ReplayClaim::Fresh => {}
        ReplayClaim::AlreadyUsed => {
            return Err(AppError::Conflict(
                "authorization record already used".into(),
            ))
        }
    }

    crate::audit::log(
        &app.db,
        Some(&user.id),
        "v2.capability_grant.accepted",
        None,
        &hex(&verified.signed_container_hash),
    )
    .await;

    Ok((
        StatusCode::CREATED,
        axum::Json(serde_json::json!({
            "accepted": true,
            "signed_container_hash": hex(&verified.signed_container_hash),
        })),
    ))
}

/// Present a signed tenant root key grant.
///
/// The server verifies and files the grant but cannot read it: the payload is
/// HPKE-sealed to the recipient device's public key, so only that device can
/// recover the tenant root key. Storing it here is a delivery mechanism, not
/// an escrow.
pub async fn present_tenant_root_key_grant(
    State(app): State<AppState>,
    user: AuthUser,
    axum::Json(req): axum::Json<PresentRecordReq>,
) -> Result<impl IntoResponse, AppError> {
    let tenant_id = parse_id16(&req.tenant_id, "tenant_id")?;
    let record_bytes = decode_hex(&req.record_hex)
        .ok_or_else(|| AppError::BadRequest("record_hex: not hex".into()))?;

    let now_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
    let ctx = verification_context(&app, tenant_id, now_ms).await?;

    let verified = authz::verify_record(&record_bytes, authz::DOMAIN_TENANT_ROOT_KEY_GRANT, &ctx)
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    // Only a member may deposit a grant for this tenant. The record's signature
    // proves an issuer wrote it, not that the caller is entitled to file it.
    require_tenant_member(&app, tenant_id, &user).await?;

    // Read the grant out of the signed fields before claiming the replay id, so
    // a malformed record does not burn one.
    let row = crate::grants::grant_row_from_record(&verified)?;

    // A grant names a generation and a root key. Both must match a generation
    // this tenant actually has, and a first self-grant is only accepted while
    // that generation is still preparing and unclaimed. Checked before the
    // replay id is claimed so a rejected grant does not burn one.
    crate::generations::check_grant_against_generation(
        &app.db,
        &tenant_id,
        &row.grant_variant,
        row.root_generation,
        &row.root_key_id,
    )
    .await?;

    match idempotency::consume_replay_id(
        &app.db,
        &tenant_id,
        ReplayTable::TenantRootKeyGrants,
        &verified,
        &util::now_rfc3339(),
    )
    .await?
    {
        ReplayClaim::Fresh => {}
        ReplayClaim::AlreadyUsed => {
            return Err(AppError::Conflict(
                "authorization record already used".into(),
            ))
        }
    }

    // The grant is stored only after the replay id is claimed, so a retry of an
    // already-filed record cannot write a second copy.
    crate::grants::insert_grant(
        &app.db,
        &tenant_id,
        &ctx.server_instance_id,
        ctx.restore_epoch,
        &verified,
        &record_bytes,
        &row,
        &util::now_rfc3339(),
    )
    .await?;

    crate::audit::log(
        &app.db,
        Some(&user.id),
        "v2.tenant_root_key_grant.accepted",
        None,
        &hex(&verified.signed_container_hash),
    )
    .await;

    Ok((
        StatusCode::CREATED,
        axum::Json(serde_json::json!({
            "accepted": true,
            "signed_container_hash": hex(&verified.signed_container_hash),
        })),
    ))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Deserialize)]
pub struct IdempotentOpReq {
    pub tenant_id: String,
    pub idempotency_key: String,
    pub operation_kind: String,
    /// Opaque request body the operation acts on, hex-encoded.
    pub payload_hex: String,
}

/// Begin an idempotent operation, replaying a prior response when the same
/// key and body are retried.
pub async fn begin_idempotent_operation(
    State(app): State<AppState>,
    user: AuthUser,
    axum::Json(req): axum::Json<IdempotentOpReq>,
) -> Result<impl IntoResponse, AppError> {
    let tenant_id = parse_id16(&req.tenant_id, "tenant_id")?;
    let key = parse_id16(&req.idempotency_key, "idempotency_key")?;
    let payload = decode_hex(&req.payload_hex)
        .ok_or_else(|| AppError::BadRequest("payload_hex: not hex".into()))?;

    let now_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
    let ctx = verification_context(&app, tenant_id, now_ms).await?;

    // The request digest is what distinguishes a retry from a key collision.
    let request_sha = shared::canonical::sha256(&payload);

    // Account and device are derived from the authenticated session, never
    // from the request body: a caller must not be able to attribute an
    // operation to someone else.
    let account_id = account_id_for(&app, tenant_id, &user.id).await?;

    match idempotency::begin_operation(
        &app.db,
        &tenant_id,
        &key,
        &ctx.server_instance_id,
        ctx.restore_epoch,
        &account_id,
        &account_id,
        &req.operation_kind,
        &request_sha,
        &util::now_rfc3339(),
    )
    .await?
    {
        OperationClaim::Started => Ok((
            StatusCode::ACCEPTED,
            axum::Json(serde_json::json!({ "status": "started" })),
        )),
        OperationClaim::Completed {
            status_code,
            exact_response_bytes,
        } => Ok((
            StatusCode::from_u16(status_code).unwrap_or(StatusCode::OK),
            axum::Json(serde_json::json!({
                "status": "replayed",
                "response_hex": hex(&exact_response_bytes),
            })),
        )),
        OperationClaim::InFlight => Err(AppError::Conflict("operation already in flight".into())),
        OperationClaim::KeyReusedWithDifferentRequest => Err(AppError::Conflict(
            "idempotency key reused with a different request".into(),
        )),
    }
}

/// Resolve the caller's account in `tenant_id`, refusing the request when the
/// caller has none.
///
/// The fleet endpoints take `tenant_id` from the request body or path. Being
/// authenticated says only that the caller is *some* user of this deployment,
/// not that they belong to the tenant they just named, so every fleet handler
/// has to establish that link before touching tenant data. The signed-record
/// endpoints do not need this — a tenant issuer's signature already covers
/// their fields — but nothing signs a lease or a download.
async fn require_tenant_member(
    app: &AppState,
    tenant_id: [u8; 16],
    user: &AuthUser,
) -> Result<[u8; 16], AppError> {
    account_id_for(app, tenant_id, &user.id).await
}

// ---------------------------------------------------------------------------
// Device enrollment
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ChallengeReq {
    /// Tenant the device will belong to, hex-encoded.
    pub tenant_id: String,
    /// Hex-encoded 32-byte Ed25519 public key the device will sign with.
    pub signing_public_key: String,
    /// Hex-encoded 32-byte HPKE recipient public key.
    pub hpke_public_key: String,
}

/// Issue an enrollment challenge for the calling account.
///
/// The account is taken from the session, never from the body: a caller may
/// only enroll devices for itself.
pub async fn create_enrollment_challenge(
    State(app): State<AppState>,
    user: AuthUser,
    axum::Json(req): axum::Json<ChallengeReq>,
) -> Result<impl IntoResponse, AppError> {
    let tenant_id = parse_id16(&req.tenant_id, "tenant_id")?;
    let account_id = require_tenant_member(&app, tenant_id, &user).await?;

    let signing_public_key: [u8; 32] = decode_hex(&req.signing_public_key)
        .ok_or_else(|| AppError::BadRequest("signing_public_key: not hex".into()))?
        .try_into()
        .map_err(|_| AppError::BadRequest("signing_public_key: must be 32 bytes".into()))?;
    let hpke_public_key: [u8; 32] = decode_hex(&req.hpke_public_key)
        .ok_or_else(|| AppError::BadRequest("hpke_public_key: not hex".into()))?
        .try_into()
        .map_err(|_| AppError::BadRequest("hpke_public_key: must be 32 bytes".into()))?;

    let now = chrono::Utc::now();
    let ctx = verification_context(&app, tenant_id, now.timestamp_millis().max(0) as u64).await?;

    let commitment = crate::enrollment::key_commitment(&signing_public_key, &hpke_public_key);
    let challenge = crate::enrollment::issue_challenge(
        &app.db,
        &tenant_id,
        &commitment,
        &ctx.server_instance_id,
        ctx.restore_epoch as i64,
        now,
    )
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok((
        StatusCode::CREATED,
        axum::Json(serde_json::json!({
            "challenge_id": hex(&challenge.id),
            "nonce": hex(&challenge.nonce),
            "account_id": hex(&account_id),
            "server_instance_id": hex(&ctx.server_instance_id),
            "restore_epoch": ctx.restore_epoch,
            "expires_at": challenge.expires_at,
        })),
    ))
}

#[derive(Deserialize)]
pub struct EnrollReq {
    pub tenant_id: String,
    pub challenge_id: String,
    /// Hex-encoded 32-byte nonce from the challenge response.
    pub nonce: String,
    /// Hex-encoded 32-byte Ed25519 public key the device will sign with.
    pub signing_public_key: String,
    /// Hex-encoded 32-byte HPKE recipient public key.
    pub hpke_public_key: String,
    /// Hex-encoded 64-byte signature over the canonical proof bytes.
    pub proof_signature: String,
    /// Opaque, client-encrypted device label. The server stores it without
    /// reading it, so a device list cannot leak machine names.
    pub label_ciphertext: String,
}

/// Complete enrollment by proving possession of the signing key.
pub async fn enroll_device(
    State(app): State<AppState>,
    user: AuthUser,
    axum::Json(req): axum::Json<EnrollReq>,
) -> Result<impl IntoResponse, AppError> {
    let tenant_id = parse_id16(&req.tenant_id, "tenant_id")?;
    let account_id = require_tenant_member(&app, tenant_id, &user).await?;
    let challenge_id = parse_id16(&req.challenge_id, "challenge_id")?;
    let nonce: [u8; 32] = decode_hex(&req.nonce)
        .ok_or_else(|| AppError::BadRequest("nonce: not hex".into()))?
        .try_into()
        .map_err(|_| AppError::BadRequest("nonce: must be 32 bytes".into()))?;

    let signing_public_key: [u8; 32] = decode_hex(&req.signing_public_key)
        .ok_or_else(|| AppError::BadRequest("signing_public_key: not hex".into()))?
        .try_into()
        .map_err(|_| AppError::BadRequest("signing_public_key: must be 32 bytes".into()))?;
    let hpke_public_key: [u8; 32] = decode_hex(&req.hpke_public_key)
        .ok_or_else(|| AppError::BadRequest("hpke_public_key: not hex".into()))?
        .try_into()
        .map_err(|_| AppError::BadRequest("hpke_public_key: must be 32 bytes".into()))?;
    let proof_signature = decode_hex(&req.proof_signature)
        .ok_or_else(|| AppError::BadRequest("proof_signature: not hex".into()))?;
    let label_ciphertext = decode_hex(&req.label_ciphertext)
        .ok_or_else(|| AppError::BadRequest("label_ciphertext: not hex".into()))?;

    let now = chrono::Utc::now();
    let ctx = verification_context(&app, tenant_id, now.timestamp_millis().max(0) as u64).await?;

    // The device id is minted server-side. Letting the client choose it would
    // let one account claim an id another tenant's device already uses, and
    // nothing in the proof binds it.
    let mut device_id = [0u8; 16];
    OsRng.fill_bytes(&mut device_id);

    crate::enrollment::enroll_device(
        &app.db,
        crate::enrollment::EnrollRequest {
            tenant_id: &tenant_id,
            account_id: &account_id,
            challenge_id: &challenge_id,
            nonce: &nonce,
            device_id: &device_id,
            label_ciphertext: &label_ciphertext,
            signing_public_key: &signing_public_key,
            signing_suite: SIGNING_SUITE_ED25519,
            hpke_public_key: &hpke_public_key,
            hpke_suite: HPKE_SUITE_X25519_HKDF_SHA256,
            signature: &proof_signature,
        },
        &ctx.server_instance_id,
        ctx.restore_epoch as i64,
        &now.to_rfc3339(),
    )
    .await
    .map_err(|e| AppError::BadRequest(e.to_string()))?;

    let signing_key_id = shared::keys::signing_key_id(&signing_public_key);

    crate::audit::log(
        &app.db,
        Some(&user.id),
        "v2.device.enrolled",
        None,
        &hex(&device_id),
    )
    .await;

    Ok((
        StatusCode::CREATED,
        axum::Json(serde_json::json!({
            "device_id": hex(&device_id),
            "signing_key_id": hex(&signing_key_id),
            // Fleet routes are scoped by account. The client cannot infer this
            // and must not invent it, so return the one we authenticated.
            "account_id": hex(&account_id),
        })),
    ))
}

/// Map a v1 session user to a v2 account within a tenant.
async fn account_id_for(
    app: &AppState,
    tenant_id: [u8; 16],
    user_id: &str,
) -> Result<[u8; 16], AppError> {
    let row = sqlx::query("SELECT id FROM v2_accounts WHERE tenant_id = ? AND legacy_user_id = ?")
        .bind(tenant_id.as_slice())
        .bind(user_id)
        .fetch_optional(&app.db)
        .await?
        .ok_or(AppError::Forbidden)?;

    let id: Vec<u8> = row.get("id");
    id.try_into()
        .map_err(|_| AppError::BadRequest("corrupt account id".into()))
}

// ---------------------------------------------------------------------------
// Fleet sync transfer
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct AcquireLeaseReq {
    tenant_id: String,
    profile_id: String,
    lease_id: String,
    account_id: String,
    device_id: String,
    /// Lease lifetime. Bounded server-side so a crashed holder cannot hold a
    /// profile forever by asking for an enormous TTL.
    ttl_seconds: i64,
}

const MIN_LEASE_TTL_SECONDS: i64 = 15;
const MAX_LEASE_TTL_SECONDS: i64 = 3600;

/// Check out a profile for writing.
pub async fn acquire_profile_lease(
    State(app): State<AppState>,
    user: AuthUser,
    axum::Json(req): axum::Json<AcquireLeaseReq>,
) -> Result<impl IntoResponse, AppError> {
    let tenant_id = parse_id16(&req.tenant_id, "tenant_id")?;
    let profile_id = parse_id16(&req.profile_id, "profile_id")?;
    let lease_id = parse_id16(&req.lease_id, "lease_id")?;
    let account_id = parse_id16(&req.account_id, "account_id")?;
    let device_id = parse_id16(&req.device_id, "device_id")?;

    // The body names the account taking the lease; confirm the caller actually
    // holds it, or one member could check out a profile as another.
    let caller_account_id = require_tenant_member(&app, tenant_id, &user).await?;
    if caller_account_id != account_id {
        return Err(AppError::Forbidden);
    }

    if !(MIN_LEASE_TTL_SECONDS..=MAX_LEASE_TTL_SECONDS).contains(&req.ttl_seconds) {
        return Err(AppError::BadRequest(format!(
            "ttl_seconds must be between {MIN_LEASE_TTL_SECONDS} and {MAX_LEASE_TTL_SECONDS}"
        )));
    }

    let now = chrono::Utc::now();
    let expires = now + chrono::Duration::seconds(req.ttl_seconds);
    let ctx = verification_context(&app, tenant_id, now.timestamp_millis().max(0) as u64).await?;

    let lease = fleet::acquire_lease(
        &app.db,
        &tenant_id,
        &profile_id,
        &lease_id,
        &account_id,
        &device_id,
        &ctx.server_instance_id,
        ctx.restore_epoch as i64,
        &now.to_rfc3339(),
        &expires.to_rfc3339(),
    )
    .await
    .map_err(fleet_error)?;

    crate::audit::log(
        &app.db,
        Some(&user.id),
        "v2.lease.acquired",
        None,
        &hex(&lease.id),
    )
    .await;

    Ok((
        StatusCode::CREATED,
        axum::Json(serde_json::json!({
            "lease_id": hex(&lease.id),
            "fencing_token": lease.fencing_token,
            "base_version": lease.base_version,
            "expires_at": lease.expires_at,
        })),
    ))
}

#[derive(Deserialize)]
pub struct ReleaseLeaseReq {
    tenant_id: String,
    lease_id: String,
}

pub async fn release_profile_lease(
    State(app): State<AppState>,
    user: AuthUser,
    axum::Json(req): axum::Json<ReleaseLeaseReq>,
) -> Result<impl IntoResponse, AppError> {
    let tenant_id = parse_id16(&req.tenant_id, "tenant_id")?;
    let lease_id = parse_id16(&req.lease_id, "lease_id")?;

    require_tenant_member(&app, tenant_id, &user).await?;

    fleet::release_lease(&app.db, &tenant_id, &lease_id, &util::now_rfc3339())
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    crate::audit::log(
        &app.db,
        Some(&user.id),
        "v2.lease.released",
        None,
        &hex(&lease_id),
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct OpenUploadReq {
    tenant_id: String,
    profile_id: String,
    session_id: String,
    lease_id: String,
    fencing_token: i64,
    target_version: i64,
    intent_hash: String,
    declared_size: i64,
}

/// Open an upload session. The bytes are streamed in afterwards.
pub async fn open_snapshot_upload(
    State(app): State<AppState>,
    user: AuthUser,
    axum::Json(req): axum::Json<OpenUploadReq>,
) -> Result<impl IntoResponse, AppError> {
    let tenant_id = parse_id16(&req.tenant_id, "tenant_id")?;
    let profile_id = parse_id16(&req.profile_id, "profile_id")?;
    let session_id = parse_id16(&req.session_id, "session_id")?;
    let lease_id = parse_id16(&req.lease_id, "lease_id")?;

    require_tenant_member(&app, tenant_id, &user).await?;

    let intent_hash: [u8; 32] = decode_hex(&req.intent_hash)
        .ok_or_else(|| AppError::BadRequest("intent_hash: not hex".into()))?
        .try_into()
        .map_err(|_| AppError::BadRequest("intent_hash: must be 32 bytes".into()))?;

    if req.declared_size < 0 {
        return Err(AppError::BadRequest(
            "declared_size must not be negative".into(),
        ));
    }

    let now_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
    let ctx = verification_context(&app, tenant_id, now_ms).await?;

    fleet::open_upload(
        &app.db,
        std::path::Path::new(&app.cfg.blob_dir),
        &tenant_id,
        &profile_id,
        &session_id,
        &lease_id,
        &ctx.server_instance_id,
        ctx.restore_epoch as i64,
        req.fencing_token,
        req.target_version,
        &intent_hash,
        req.declared_size,
        &util::now_rfc3339(),
    )
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok((
        StatusCode::CREATED,
        axum::Json(serde_json::json!({
            "session_id": hex(&session_id),
            "received_size": 0,
        })),
    ))
}

/// Append one chunk to an open upload session.
///
/// The offset is explicit so a resumed upload cannot silently duplicate or
/// skip a region: the server rejects anything that is not the current end of
/// the staged file.
pub async fn append_snapshot_chunk(
    State(app): State<AppState>,
    user: AuthUser,
    axum::extract::Path((tenant_hex, session_hex)): axum::extract::Path<(String, String)>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, AppError> {
    let tenant_id = parse_id16(&tenant_hex, "tenant_id")?;
    let session_id = parse_id16(&session_hex, "session_id")?;

    require_tenant_member(&app, tenant_id, &user).await?;

    let offset: i64 = headers
        .get("x-chunk-offset")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| AppError::BadRequest("x-chunk-offset: missing or invalid".into()))?;

    let received = fleet::append_chunk(
        &app.db,
        &tenant_id,
        &session_id,
        offset,
        &body,
        &util::now_rfc3339(),
    )
    .await
    .map_err(fleet_error)?;

    Ok(axum::Json(serde_json::json!({ "received_size": received })))
}

#[derive(Deserialize)]
pub struct CommitUploadReq {
    tenant_id: String,
    profile_id: String,
    session_id: String,
    /// The signed snapshot manifest, hex-encoded. Verified before the version
    /// is published.
    manifest_hex: String,
    snapshot_id: String,
    fleet_id: String,
    base_version: i64,
    key_generation: i64,
    container_sha256: String,
    author_account_id: String,
    author_device_id: String,
}

/// Publish a staged upload as the profile's next version.
pub async fn commit_snapshot_upload(
    State(app): State<AppState>,
    user: AuthUser,
    axum::Json(req): axum::Json<CommitUploadReq>,
) -> Result<impl IntoResponse, AppError> {
    let tenant_id = parse_id16(&req.tenant_id, "tenant_id")?;
    let profile_id = parse_id16(&req.profile_id, "profile_id")?;
    let session_id = parse_id16(&req.session_id, "session_id")?;
    let snapshot_id = parse_id16(&req.snapshot_id, "snapshot_id")?;
    let fleet_id = parse_id16(&req.fleet_id, "fleet_id")?;
    let author_account_id = parse_id16(&req.author_account_id, "author_account_id")?;
    let author_device_id = parse_id16(&req.author_device_id, "author_device_id")?;

    // A signature proves the manifest came from a tenant issuer, not that this
    // caller belongs to the tenant or is the author it claims to be.
    let caller_account_id = require_tenant_member(&app, tenant_id, &user).await?;
    if caller_account_id != author_account_id {
        return Err(AppError::Forbidden);
    }

    let container_sha256: [u8; 32] = decode_hex(&req.container_sha256)
        .ok_or_else(|| AppError::BadRequest("container_sha256: not hex".into()))?
        .try_into()
        .map_err(|_| AppError::BadRequest("container_sha256: must be 32 bytes".into()))?;

    let manifest_bytes = decode_hex(&req.manifest_hex)
        .ok_or_else(|| AppError::BadRequest("manifest_hex: not hex".into()))?;

    let now = chrono::Utc::now();
    let ctx = verification_context(&app, tenant_id, now.timestamp_millis().max(0) as u64).await?;

    // The manifest is signed authorization in its own right: publishing a
    // version is a mutation, so a session token alone must not authorise it.
    let verified = authz::verify_record(&manifest_bytes, authz::DOMAIN_SNAPSHOT_MANIFEST, &ctx)
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    // The signature authorizes the values inside the manifest, not whatever the
    // request body happens to repeat. Without this cross-check a caller could
    // present a valid manifest and publish different bytes under it.
    let signed_mismatch =
        |field: &str| AppError::BadRequest(format!("{field} does not match the signed manifest"));
    if verified.signed_hash32("container_sha256") != Some(container_sha256) {
        return Err(signed_mismatch("container_sha256"));
    }
    if verified.signed_id16("profile_id") != Some(profile_id) {
        return Err(signed_mismatch("profile_id"));
    }
    if verified.signed_id16("snapshot_id") != Some(snapshot_id) {
        return Err(signed_mismatch("snapshot_id"));
    }
    if verified.signed_id16("fleet_id") != Some(fleet_id) {
        return Err(signed_mismatch("fleet_id"));
    }
    if verified.signed_uint("base_version") != Some(req.base_version.max(0) as u64) {
        return Err(signed_mismatch("base_version"));
    }
    if verified.signed_uint("key_generation") != Some(req.key_generation.max(0) as u64) {
        return Err(signed_mismatch("key_generation"));
    }

    let committed = fleet::commit_upload(
        &app.db,
        std::path::Path::new(&app.cfg.blob_dir),
        &tenant_id,
        &profile_id,
        &session_id,
        &fleet::ManifestInput {
            snapshot_id,
            fleet_id,
            base_version: req.base_version,
            key_generation: req.key_generation,
            restore_epoch: ctx.restore_epoch as i64,
            server_instance_id: ctx.server_instance_id,
            // Binds the stored manifest row to the exact verified bytes.
            intent_hash: verified.exact_bytes_sha256,
            container_sha256,
            author_account_id,
            author_device_id,
            signature_bytes: verified.signature_bytes,
            issuer_signing_key_id: verified.issuer_signing_key_id,
            signed_container_hash: verified.signed_container_hash,
            exact_signed_container_bytes: &manifest_bytes,
        },
        &now.to_rfc3339(),
    )
    .await
    .map_err(fleet_error)?;

    crate::audit::log(
        &app.db,
        Some(&user.id),
        "v2.snapshot.committed",
        None,
        &hex(&verified.signed_container_hash),
    )
    .await;

    Ok((
        StatusCode::CREATED,
        axum::Json(serde_json::json!({
            "version": committed.version,
            "container_sha256": hex(&committed.container_sha256),
        })),
    ))
}

#[derive(Deserialize)]
pub struct AbortUploadReq {
    tenant_id: String,
    session_id: String,
}

pub async fn abort_snapshot_upload(
    State(app): State<AppState>,
    user: AuthUser,
    axum::Json(req): axum::Json<AbortUploadReq>,
) -> Result<impl IntoResponse, AppError> {
    let tenant_id = parse_id16(&req.tenant_id, "tenant_id")?;
    let session_id = parse_id16(&req.session_id, "session_id")?;

    require_tenant_member(&app, tenant_id, &user).await?;

    fleet::abort_upload(&app.db, &tenant_id, &session_id, &util::now_rfc3339())
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

/// Describe the snapshot a device would download.
pub async fn head_snapshot(
    State(app): State<AppState>,
    user: AuthUser,
    axum::extract::Path((tenant_hex, profile_hex)): axum::extract::Path<(String, String)>,
    axum::extract::Query(q): axum::extract::Query<VersionQuery>,
) -> Result<impl IntoResponse, AppError> {
    let tenant_id = parse_id16(&tenant_hex, "tenant_id")?;
    let profile_id = parse_id16(&profile_hex, "profile_id")?;

    require_tenant_member(&app, tenant_id, &user).await?;

    let target = fleet::resolve_download(&app.db, &tenant_id, &profile_id, q.version)
        .await
        .map_err(fleet_error)?;

    Ok(axum::Json(serde_json::json!({
        "version": target.version,
        "container_size": target.container_size,
        "container_sha256": hex(&target.container_sha256),
        "manifest_hex": hex(&target.exact_signed_container_bytes),
    })))
}

/// Begin the tenant's first root key generation.
///
/// The caller generates the root key locally and sends only its identifier;
/// the key itself never leaves the device, which is why the server can hold
/// this record without being able to read anything sealed under it.
pub async fn begin_root_generation(
    State(app): State<AppState>,
    user: AuthUser,
    axum::Json(req): axum::Json<BeginRootGenerationReq>,
) -> Result<axum::Json<serde_json::Value>, AppError> {
    let tenant_id = parse_id16(&req.tenant_id, "tenant_id")?;
    require_tenant_member(&app, tenant_id, &user).await?;

    let root_key_id = parse_id32(&req.root_key_id, "root_key_id")?;

    let generation = crate::generations::begin_first_generation(
        &app.db,
        &tenant_id,
        &root_key_id,
        &util::now_rfc3339(),
    )
    .await?;

    Ok(axum::Json(serde_json::json!({
        "generation": generation,
        "state": crate::generations::STATE_PREPARING,
    })))
}

/// Activate a prepared generation once its holder has proven it can unwrap.
///
/// Activation is a separate call because filing a grant only proves it was
/// written, not that anyone can open it. The caller unwraps its own grant
/// first; activating before that could leave a tenant sealed under a key that
/// no device can recover.
pub async fn activate_root_generation(
    State(app): State<AppState>,
    user: AuthUser,
    axum::Json(req): axum::Json<ActivateRootGenerationReq>,
) -> Result<axum::Json<serde_json::Value>, AppError> {
    let tenant_id = parse_id16(&req.tenant_id, "tenant_id")?;
    require_tenant_member(&app, tenant_id, &user).await?;

    crate::generations::activate_generation(
        &app.db,
        &tenant_id,
        req.generation,
        &util::now_rfc3339(),
    )
    .await?;

    Ok(axum::Json(serde_json::json!({
        "generation": req.generation,
        "state": crate::generations::STATE_ACTIVE,
    })))
}

/// Report which generation is in force, so a device knows what to seal under.
pub async fn get_active_root_generation(
    State(app): State<AppState>,
    user: AuthUser,
    axum::extract::Path(tenant_hex): axum::extract::Path<String>,
) -> Result<axum::Json<serde_json::Value>, AppError> {
    let tenant_id = parse_id16(&tenant_hex, "tenant_id")?;
    require_tenant_member(&app, tenant_id, &user).await?;

    match crate::generations::active_generation(&app.db, &tenant_id).await? {
        Some(g) => Ok(axum::Json(serde_json::json!({
            "active": true,
            "generation": g.generation,
            "root_key_id": hex(&g.root_key_id),
            "state": g.state,
            "activated_at": g.activated_at,
        }))),
        None => Ok(axum::Json(serde_json::json!({ "active": false }))),
    }
}
/// List the root key grants issued to one device.
///
/// This is the collection half of custody: a device that was granted the tenant
/// root key fetches the sealed grant here and opens it with its own HPKE
/// private key. The server returns ciphertext it cannot read.
pub async fn list_tenant_root_key_grants(
    State(app): State<AppState>,
    user: AuthUser,
    axum::extract::Path((tenant_hex, device_hex)): axum::extract::Path<(String, String)>,
) -> Result<axum::Json<serde_json::Value>, AppError> {
    let tenant_id = parse_id16(&tenant_hex, "tenant_id")?;
    let device_id = parse_id16(&device_hex, "device_id")?;

    // Membership is checked against the authenticated user rather than the path,
    // so a caller cannot read another tenant's grants by naming that tenant.
    require_tenant_member(&app, tenant_id, &user).await?;

    let grants = crate::grants::grants_for_device(&app.db, &tenant_id, &device_id).await?;

    let items: Vec<_> = grants
        .into_iter()
        .map(|g| {
            serde_json::json!({
                "grant_variant": g.grant_variant,
                "root_key_id": hex(&g.root_key_id),
                "root_generation": g.root_generation,
                "recipient_hpke_key_id": hex(&g.recipient_hpke_key_id),
                "hpke_info_hex": hex(&g.hpke_info_bytes),
                "hpke_encapped_key_hex": hex(&g.hpke_encapped_key_bytes),
                "hpke_wrapped_trk_hex": hex(&g.hpke_wrapped_trk_bytes),
                "signed_container_hex": hex(&g.exact_signed_container_bytes),
                "created_at": g.created_at,
            })
        })
        .collect();

    Ok(axum::Json(serde_json::json!({ "grants": items })))
}

#[derive(Deserialize)]
pub struct VersionQuery {
    version: Option<i64>,
}

#[derive(Deserialize)]
pub struct RangeQuery {
    version: Option<i64>,
    offset: Option<u64>,
    length: Option<usize>,
}

/// Read a bounded range of a stored snapshot.
///
/// Range-based rather than whole-file: a snapshot can be far larger than the
/// server's memory budget, so neither side ever holds the whole container.
pub async fn download_snapshot_range(
    State(app): State<AppState>,
    user: AuthUser,
    axum::extract::Path((tenant_hex, profile_hex)): axum::extract::Path<(String, String)>,
    axum::extract::Query(q): axum::extract::Query<RangeQuery>,
) -> Result<impl IntoResponse, AppError> {
    const MAX_RANGE: usize = 8 * 1024 * 1024;

    let tenant_id = parse_id16(&tenant_hex, "tenant_id")?;
    let profile_id = parse_id16(&profile_hex, "profile_id")?;
    let length = q.length.unwrap_or(1024 * 1024).min(MAX_RANGE);

    require_tenant_member(&app, tenant_id, &user).await?;

    let target = fleet::resolve_download(&app.db, &tenant_id, &profile_id, q.version)
        .await
        .map_err(fleet_error)?;

    let bytes = fleet::read_range(
        std::path::Path::new(&target.blob_path),
        q.offset.unwrap_or(0),
        length,
    )
    .await
    .map_err(fleet_error)?;

    Ok((
        StatusCode::OK,
        [
            ("content-type", "application/octet-stream".to_string()),
            ("x-snapshot-version", target.version.to_string()),
            ("x-container-size", target.container_size.to_string()),
        ],
        bytes,
    ))
}

/// Map a fleet refusal onto the status code that describes it.
///
/// Conflicts and precondition failures are distinct: a client retries the
/// former after re-reading state, but must not retry the latter unchanged.
fn fleet_error(e: fleet::FleetError) -> AppError {
    use fleet::FleetError as F;
    match e {
        F::AlreadyLeased | F::VersionConflict { .. } => AppError::Conflict(e.to_string()),
        F::NoSuchLease | F::NoSuchVersion => AppError::NotFound,
        F::LeaseExpired
        | F::StaleFencingToken { .. }
        | F::SessionNotOpen
        | F::SizeMismatch { .. }
        | F::ContentHashMismatch
        | F::ChunkOutOfOrder { .. }
        | F::DeclaredSizeExceeded { .. } => AppError::BadRequest(e.to_string()),
        F::BlobUnavailable | F::Database(_) => AppError::Internal(e.to_string()),
    }
}

/// Begin a fleet's first key generation.
///
/// The caller generates the fleet key locally and sends only its identifier.
/// The key never leaves the device, which is why the server can coordinate
/// custody without being able to read anything sealed under it.
pub async fn begin_fleet_generation(
    State(app): State<AppState>,
    user: AuthUser,
    axum::Json(req): axum::Json<BeginFleetGenerationReq>,
) -> Result<axum::Json<serde_json::Value>, AppError> {
    let tenant_id = parse_id16(&req.tenant_id, "tenant_id")?;
    require_tenant_member(&app, tenant_id, &user).await?;

    let fleet_id = parse_id16(&req.fleet_id, "fleet_id")?;
    let fkek_key_id = parse_id32(&req.fkek_key_id, "fkek_key_id")?;

    let generation = crate::fleet_generations::begin_first_generation(
        &app.db,
        &tenant_id,
        &fleet_id,
        &fkek_key_id,
        &util::now_rfc3339(),
    )
    .await?;

    Ok(axum::Json(serde_json::json!({
        "generation": generation,
        "state": crate::fleet_generations::STATE_PREPARING,
    })))
}

/// Activate a prepared fleet key generation once its holder has proven it can
/// unwrap the grant it filed.
pub async fn activate_fleet_generation(
    State(app): State<AppState>,
    user: AuthUser,
    axum::Json(req): axum::Json<ActivateFleetGenerationReq>,
) -> Result<axum::Json<serde_json::Value>, AppError> {
    let tenant_id = parse_id16(&req.tenant_id, "tenant_id")?;
    require_tenant_member(&app, tenant_id, &user).await?;

    let fleet_id = parse_id16(&req.fleet_id, "fleet_id")?;

    crate::fleet_generations::activate_generation(
        &app.db,
        &tenant_id,
        &fleet_id,
        req.generation,
        &util::now_rfc3339(),
    )
    .await?;

    Ok(axum::Json(serde_json::json!({
        "generation": req.generation,
        "state": crate::fleet_generations::STATE_ACTIVE,
    })))
}

/// The fleet's active key generation, or null before one is activated.
///
/// A device reads this to learn which key to encrypt under. Null is a real
/// answer: it means no key has been confirmed, and the caller must not fall
/// back to some other key path.
pub async fn get_active_fleet_generation(
    State(app): State<AppState>,
    user: AuthUser,
    axum::extract::Path((tenant_hex, fleet_hex)): axum::extract::Path<(String, String)>,
) -> Result<axum::Json<serde_json::Value>, AppError> {
    let tenant_id = parse_id16(&tenant_hex, "tenant_id")?;
    let fleet_id = parse_id16(&fleet_hex, "fleet_id")?;
    require_tenant_member(&app, tenant_id, &user).await?;

    let active =
        crate::fleet_generations::active_generation(&app.db, &tenant_id, &fleet_id).await?;

    Ok(axum::Json(match active {
        Some(g) => serde_json::json!({
            "generation": g.generation,
            "fkek_key_id": hex(&g.fkek_key_id),
            "state": g.state,
            "activated_at": g.activated_at,
        }),
        None => serde_json::Value::Null,
    }))
}

/// File a fleet key grant.
///
/// The record is verified, then read entirely from its signed fields. The
/// server stores ciphertext it cannot open.
pub async fn present_fleet_key_grant(
    State(app): State<AppState>,
    user: AuthUser,
    axum::Json(req): axum::Json<PresentRecordReq>,
) -> Result<impl IntoResponse, AppError> {
    let tenant_id = parse_id16(&req.tenant_id, "tenant_id")?;
    let record_bytes = decode_hex(&req.record_hex)
        .ok_or_else(|| AppError::BadRequest("record_hex: not hex".into()))?;

    let now_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
    let ctx = verification_context(&app, tenant_id, now_ms).await?;

    let verified = authz::verify_record(&record_bytes, authz::DOMAIN_FLEET_KEY_GRANT, &ctx)
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    // Only a member may file a grant for this tenant. The signature proves an
    // issuer wrote the record, not that the caller may deposit it here.
    require_tenant_member(&app, tenant_id, &user).await?;

    // Read the grant from the signed fields before claiming the replay id, so a
    // malformed record does not burn one.
    let row = crate::fleet_grants::fleet_grant_row_from_record(&verified)?;

    crate::fleet_generations::check_grant_against_generation(
        &app.db,
        &tenant_id,
        &row.fleet_id,
        row.fleet_generation,
        &row.fkek_key_id,
        &row.grant_variant,
    )
    .await?;

    match idempotency::consume_replay_id(
        &app.db,
        &tenant_id,
        ReplayTable::FleetKeyGrants,
        &verified,
        &util::now_rfc3339(),
    )
    .await?
    {
        ReplayClaim::Fresh => {}
        ReplayClaim::AlreadyUsed => {
            return Err(AppError::Conflict(
                "authorization record replay id has already been used".into(),
            ));
        }
    }

    crate::fleet_grants::insert_fleet_grant(
        &app.db,
        &tenant_id,
        &ctx.server_instance_id,
        ctx.restore_epoch,
        &verified,
        &record_bytes,
        &row,
        &util::now_rfc3339(),
    )
    .await?;

    Ok(axum::Json(serde_json::json!({ "stored": true })))
}

/// Every fleet key grant addressed to one device.
pub async fn list_fleet_key_grants(
    State(app): State<AppState>,
    user: AuthUser,
    axum::extract::Path((tenant_hex, device_hex)): axum::extract::Path<(String, String)>,
) -> Result<axum::Json<serde_json::Value>, AppError> {
    let tenant_id = parse_id16(&tenant_hex, "tenant_id")?;
    let device_id = parse_id16(&device_hex, "device_id")?;

    // Membership is checked against the authenticated user, not the path, so a
    // caller cannot read another tenant's grants by naming that tenant.
    require_tenant_member(&app, tenant_id, &user).await?;

    let grants =
        crate::fleet_grants::fleet_grants_for_device(&app.db, &tenant_id, &device_id).await?;

    let items: Vec<_> = grants
        .into_iter()
        .map(|g| {
            serde_json::json!({
                "grant_variant": g.grant_variant,
                "fleet_id": hex(&g.fleet_id),
                "fkek_key_id": hex(&g.fkek_key_id),
                "fleet_generation": g.fleet_generation,
                "recipient_hpke_key_id": hex(&g.recipient_hpke_key_id),
                "hpke_info_hex": hex(&g.hpke_info_bytes),
                "hpke_encapped_key_hex": hex(&g.hpke_encapped_key_bytes),
                "hpke_wrapped_fkek_hex": hex(&g.hpke_wrapped_fkek_bytes),
                "signed_container_hex": hex(&g.exact_signed_container_bytes),
                "created_at": g.created_at,
            })
        })
        .collect();

    Ok(axum::Json(serde_json::json!({ "grants": items })))
}
