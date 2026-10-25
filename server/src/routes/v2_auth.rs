//! Account login, pre-device tickets and proof-bound device sessions
//! (ADR 0001 R2).
//!
//! `POST /v2/auth/login` checks a v2 account's password and returns an
//! account-only ticket. The ticket opens a device-session challenge for one of
//! the account's own pending devices; the device answers with the secret the
//! server sealed to its HPKE key and an Ed25519 signature over the binding and
//! that secret. Only then does a `v2_sessions` row exist, bound to that device
//! and both its keys. A ticket grants nothing else: no approval, no root
//! action, no ordinary mutation.
//!
//! Tokens are 32 random bytes behind a type prefix (`v2t.`, `v2a.`, `v2r.`)
//! and are stored only as SHA-256 hashes. Tickets, secrets and tokens never
//! reach the audit trail or the log.

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, FromRef, FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::{async_trait, Json};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{Row, SqliteConnection};
use zeroize::Zeroizing;

use shared::canonical::sha256;
use shared::keys::fill_random;
use shared::session_binding::{self as sb, BindingFields, DeviceSessionBindingV2};

use crate::auth::{client_ip, verify_slot};
use crate::error::AppError;
use crate::extract::AppJson;
use crate::identity::{hex, Verified};
use crate::integrity::derive_device_key_ids;
use crate::state::AppState;
use crate::util::now_ms;

const TICKET_TTL_MS: i64 = 600_000;
const CHALLENGE_TTL_MS: i64 = 120_000;
const ACCESS_TTL_MS: i64 = 300_000;
/// Pending-setup sessions end 30 minutes after the proof, refresh or not.
const SETUP_SESSION_MS: i64 = 1_800_000;
/// Open challenges per ticket. With the ticket's 10-minute life this bounds
/// the HPKE work one login can cause.
const MAX_OPEN_CHALLENGES: i64 = 5;
/// Live tickets per account. Bounds what one account's successful logins can
/// open: at most this many times `MAX_OPEN_CHALLENGES` challenges.
const MAX_LIVE_TICKETS: i64 = 10;

const TICKET: &str = "v2t.";
const ACCESS: &str = "v2a.";
const REFRESH: &str = "v2r.";

fn verified(app: &AppState) -> Result<&Verified, AppError> {
    app.authority
        .as_ref()
        .as_ref()
        .map_err(|r| AppError::EpochAuthority(r.code))
}

fn epoch(v: &Verified) -> Result<i64, AppError> {
    i64::try_from(v.restore_epoch)
        .map_err(|_| AppError::Internal("restore epoch out of range".into()))
}

fn random<const N: usize>() -> Result<[u8; N], AppError> {
    let mut out = [0u8; N];
    fill_random(&mut out).map_err(|e| AppError::Internal(format!("entropy: {e}")))?;
    Ok(out)
}

fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != 2 * N || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

fn blob<const N: usize>(row: &sqlx::sqlite::SqliteRow, col: &str) -> Result<[u8; N], AppError> {
    row.get::<Vec<u8>, _>(col)
        .try_into()
        .map_err(|_| AppError::Internal(format!("{col} has the wrong length")))
}

/// A new token and the hash that is stored for it.
fn new_token(prefix: &str) -> Result<(Zeroizing<String>, [u8; 32]), AppError> {
    let raw = Zeroizing::new(random::<32>()?);
    Ok((
        Zeroizing::new(format!("{prefix}{}", hex(&*raw))),
        sha256(&*raw),
    ))
}

/// The stored hash for a presented token of the given type.
fn token_hash(token: &str, prefix: &str) -> Option<[u8; 32]> {
    let raw = Zeroizing::new(unhex::<32>(token.strip_prefix(prefix)?)?);
    Some(sha256(&*raw))
}

fn bearer(parts: &Parts) -> Option<&str> {
    parts
        .headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

/// The account may act now: active, same token version, active membership,
/// active tenant.
async fn account_is_live(
    conn: &mut SqliteConnection,
    tenant_id: &[u8; 16],
    account_id: &[u8; 16],
    token_version: i64,
) -> Result<bool, AppError> {
    Ok(sqlx::query_scalar::<_, i64>(
        "SELECT 1 FROM v2_accounts a
           JOIN v2_tenant_memberships m ON m.tenant_id = a.tenant_id AND m.account_id = a.id
           JOIN v2_tenants t ON t.id = a.tenant_id
          WHERE a.tenant_id = ? AND a.id = ? AND a.status = 'active' AND a.token_version = ?
            AND m.status = 'active' AND t.status = 'active'",
    )
    .bind(tenant_id.as_slice())
    .bind(account_id.as_slice())
    .bind(token_version)
    .fetch_optional(&mut *conn)
    .await?
    .is_some())
}

// ------------------------------------------------------------- principals ---

/// A live account-only ticket.
pub struct Ticket {
    pub id: [u8; 16],
    pub tenant_id: [u8; 16],
    pub account_id: [u8; 16],
    pub token_version: i64,
    pub expires_at_ms: i64,
}

/// Loads a ticket by hash or ID and checks every live predicate.
async fn load_ticket(
    conn: &mut SqliteConnection,
    column: &str,
    key: &[u8],
    v: &Verified,
    now: i64,
) -> Result<Option<Ticket>, AppError> {
    let Some(row) = sqlx::query(&format!(
        "SELECT id, tenant_id, account_id, account_token_version, expires_at_ms
           FROM v2_pre_device_sessions
          WHERE {column} = ? AND consumed_at_ms IS NULL AND revoked_at_ms IS NULL
            AND expires_at_ms > ? AND server_instance_id = ? AND restore_epoch = ?"
    ))
    .bind(key)
    .bind(now)
    .bind(v.server_instance_id.as_slice())
    .bind(epoch(v)?)
    .fetch_optional(&mut *conn)
    .await?
    else {
        return Ok(None);
    };
    let ticket = Ticket {
        id: blob(&row, "id")?,
        tenant_id: blob(&row, "tenant_id")?,
        account_id: blob(&row, "account_id")?,
        token_version: row.get("account_token_version"),
        expires_at_ms: row.get("expires_at_ms"),
    };
    let live = account_is_live(
        conn,
        &ticket.tenant_id,
        &ticket.account_id,
        ticket.token_version,
    )
    .await?;
    Ok(live.then_some(ticket))
}

/// A live device session.
pub struct Session {
    pub id: [u8; 16],
    pub tenant_id: [u8; 16],
    pub account_id: [u8; 16],
    pub device_id: [u8; 16],
    pub class: String,
    pub signing_key_id: [u8; 32],
    pub hpke_key_id: [u8; 32],
    pub access_expires_at_ms: i64,
    pub absolute_expires_at_ms: i64,
}

const SESSION_COLUMNS: &str = "id, tenant_id, account_id, device_id, class, signing_key_id, \
     hpke_key_id, account_token_version, access_expires_at_ms, refresh_expires_at_ms, \
     absolute_expires_at_ms, server_instance_id, restore_epoch";

fn session_from(row: &sqlx::sqlite::SqliteRow) -> Result<Session, AppError> {
    Ok(Session {
        id: blob(row, "id")?,
        tenant_id: blob(row, "tenant_id")?,
        account_id: blob(row, "account_id")?,
        device_id: blob(row, "device_id")?,
        class: row.get("class"),
        signing_key_id: blob(row, "signing_key_id")?,
        hpke_key_id: blob(row, "hpke_key_id")?,
        access_expires_at_ms: row.get("access_expires_at_ms"),
        absolute_expires_at_ms: row.get("absolute_expires_at_ms"),
    })
}

/// The predicates R2 rechecks on every use and refresh: this instance and
/// epoch, the account, and a device still in the state the class needs with
/// the same two keys.
async fn session_is_live(
    conn: &mut SqliteConnection,
    row: &sqlx::sqlite::SqliteRow,
    s: &Session,
    v: &Verified,
) -> Result<bool, AppError> {
    let instance: Vec<u8> = row.get("server_instance_id");
    if instance != v.server_instance_id || row.get::<i64, _>("restore_epoch") != epoch(v)? {
        return Ok(false);
    }
    if !account_is_live(
        conn,
        &s.tenant_id,
        &s.account_id,
        row.get("account_token_version"),
    )
    .await?
    {
        return Ok(false);
    }
    let device_status = if s.class == "pending_setup" {
        "pending"
    } else {
        "active"
    };
    Ok(sqlx::query_scalar::<_, i64>(
        "SELECT 1 FROM v2_devices
          WHERE tenant_id = ? AND id = ? AND account_id = ? AND status = ?
            AND signing_key_id = ? AND hpke_key_id = ?",
    )
    .bind(s.tenant_id.as_slice())
    .bind(s.device_id.as_slice())
    .bind(s.account_id.as_slice())
    .bind(device_status)
    .bind(s.signing_key_id.as_slice())
    .bind(s.hpke_key_id.as_slice())
    .fetch_optional(&mut *conn)
    .await?
    .is_some())
}

/// Whoever a v2 bearer token names: a ticket or a device session.
pub enum Principal {
    Ticket(Ticket),
    Session(Session),
}

#[async_trait]
impl<S> FromRequestParts<S> for Principal
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app = AppState::from_ref(state);
        let v = verified(&app)?;
        let token = bearer(parts).ok_or(AppError::Unauthorized)?;
        let now = now_ms();
        let mut conn = app.db.acquire().await?;
        if let Some(hash) = token_hash(token, TICKET) {
            return load_ticket(&mut conn, "token_hash", &hash, v, now)
                .await?
                .map(Principal::Ticket)
                .ok_or(AppError::Unauthorized);
        }
        let hash = token_hash(token, ACCESS).ok_or(AppError::Unauthorized)?;
        let row = sqlx::query(&format!(
            "SELECT {SESSION_COLUMNS} FROM v2_sessions
              WHERE access_token_hash = ? AND revoked_at_ms IS NULL AND access_expires_at_ms > ?"
        ))
        .bind(hash.as_slice())
        .bind(now)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or(AppError::Unauthorized)?;
        let session = session_from(&row)?;
        if !session_is_live(&mut conn, &row, &session, v).await? {
            return Err(AppError::Unauthorized);
        }
        Ok(Principal::Session(session))
    }
}

/// A principal that must be a ticket.
pub struct TicketAuth(pub Ticket);

#[async_trait]
impl<S> FromRequestParts<S> for TicketAuth
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match Principal::from_request_parts(parts, state).await? {
            Principal::Ticket(t) => Ok(TicketAuth(t)),
            Principal::Session(_) => Err(AppError::Forbidden),
        }
    }
}

/// A structured audit row for an online v2 action by a device.
#[allow(clippy::too_many_arguments)]
async fn audit(
    conn: &mut SqliteConnection,
    tenant_id: &[u8],
    account_id: &[u8],
    device_id: &[u8],
    action: &str,
    target_type: &str,
    target_id: &[u8],
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO v2_audit_events
             (tenant_id, id, actor_account_id, actor_device_id, action, target_type, target_id,
              outcome, reason_code, request_id, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, 'success', NULL, ?, ?)",
    )
    .bind(tenant_id)
    .bind(random::<16>()?.as_slice())
    .bind(account_id)
    .bind(device_id)
    .bind(action)
    .bind(target_type)
    .bind(target_id)
    .bind(random::<16>()?.as_slice())
    .bind(crate::util::now_rfc3339())
    .execute(&mut *conn)
    .await?;
    Ok(())
}

// --------------------------------------------------------------- handlers ---

#[derive(Deserialize)]
pub struct LoginReq {
    tenant: String,
    username: String,
    password: String,
}

/// `POST /v2/auth/login`: an account-only ticket, never a session.
pub async fn login(
    State(app): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    AppJson(req): AppJson<LoginReq>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let v = verified(&app)?;
    let ip = client_ip(&app, &headers, peer);
    // Its own key space: a v2 account is named by tenant and username.
    let user_key = format!("v2:{}/{}", req.tenant, req.username);
    if let Some(retry) = app.login_throttle.locked_for(&ip, &user_key) {
        return Err(AppError::TooManyRequests(retry));
    }
    let failed = |app: &AppState| {
        app.login_throttle.record_failure(&ip, &user_key);
        AppError::Unauthorized
    };

    let row = sqlx::query(
        "SELECT a.tenant_id, a.id, a.pw_hash, a.token_version
           FROM v2_accounts a JOIN v2_tenants t ON t.id = a.tenant_id
          WHERE t.slug = ? AND a.username = ?",
    )
    .bind(&req.tenant)
    .bind(&req.username)
    .fetch_optional(&app.db)
    .await?;
    let Some(row) = row else {
        // Same work as a wrong password, so timing does not tell which
        // tenants and usernames exist.
        static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        let dummy = match DUMMY.get() {
            Some(h) => h.clone(),
            None => {
                let h = crate::auth::hash_password(&hex(&random::<16>()?))?;
                DUMMY.get_or_init(|| h).clone()
            }
        };
        let _ = verify_slot(&app, req.password.clone(), dummy).await?;
        crate::audit::log(
            &app.db,
            None,
            "v2_login_failed",
            None,
            &format!("from {ip}"),
        )
        .await;
        return Err(failed(&app));
    };
    if !verify_slot(&app, req.password.clone(), row.get("pw_hash")).await? {
        crate::audit::log(
            &app.db,
            None,
            "v2_login_failed",
            None,
            &format!("from {ip}"),
        )
        .await;
        return Err(failed(&app));
    }
    let tenant_id: [u8; 16] = blob(&row, "tenant_id")?;
    let account_id: [u8; 16] = blob(&row, "id")?;
    let token_version: i64 = row.get("token_version");
    let mut conn = app.db.begin_with("BEGIN IMMEDIATE").await?;
    if !account_is_live(&mut conn, &tenant_id, &account_id, token_version).await? {
        return Err(AppError::Unauthorized);
    }
    app.login_throttle.record_success(&ip, &user_key);

    let now = now_ms();
    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM v2_pre_device_sessions
          WHERE tenant_id = ? AND account_id = ? AND consumed_at_ms IS NULL
            AND revoked_at_ms IS NULL AND expires_at_ms > ?",
    )
    .bind(tenant_id.as_slice())
    .bind(account_id.as_slice())
    .bind(now)
    .fetch_one(&mut *conn)
    .await?;
    if live >= MAX_LIVE_TICKETS {
        return Err(AppError::TooManyRequests((TICKET_TTL_MS / 1000) as u64));
    }
    let (token, hash) = new_token(TICKET)?;
    let id = random::<16>()?;
    sqlx::query(
        "INSERT INTO v2_pre_device_sessions
             (id, token_hash, server_instance_id, restore_epoch, tenant_id, account_id,
              account_token_version, created_at_ms, expires_at_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id.as_slice())
    .bind(hash.as_slice())
    .bind(v.server_instance_id.as_slice())
    .bind(epoch(v)?)
    .bind(tenant_id.as_slice())
    .bind(account_id.as_slice())
    .bind(token_version)
    .bind(now)
    .bind(now + TICKET_TTL_MS)
    .execute(&mut *conn)
    .await?;
    conn.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "ticket": token.as_str(),
            "ticket_id": hex(&id),
            "expires_at_ms": now + TICKET_TTL_MS,
            "tenant_id": hex(&tenant_id),
            "account_id": hex(&account_id),
            "server_instance_id": hex(&v.server_instance_id),
            "restore_epoch": v.restore_epoch,
        })),
    ))
}

#[derive(Deserialize)]
pub struct ChallengeReq {
    device_id: String,
}

/// `POST /v2/auth/device-session-challenges`: seals a fresh secret to one of
/// the ticket's own pending devices.
pub async fn create_device_session_challenge(
    State(app): State<AppState>,
    TicketAuth(ticket): TicketAuth,
    AppJson(req): AppJson<ChallengeReq>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let v = verified(&app)?;
    let device_id = unhex::<16>(&req.device_id)
        .ok_or_else(|| AppError::BadRequest("device_id must be 32 hex digits".into()))?;
    // One write lock from the count to the insert, so concurrent requests
    // cannot all pass the cap.
    let mut conn = app.db.begin_with("BEGIN IMMEDIATE").await?;
    let now = now_ms();
    let open: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM v2_device_session_challenges
          WHERE pre_device_session_id = ? AND consumed_at_ms IS NULL AND revoked_at_ms IS NULL
            AND expires_at_ms > ?",
    )
    .bind(ticket.id.as_slice())
    .bind(now)
    .fetch_one(&mut *conn)
    .await?;
    if open >= MAX_OPEN_CHALLENGES {
        return Err(AppError::TooManyRequests((CHALLENGE_TTL_MS / 1000) as u64));
    }

    // Another account's or tenant's device is indistinguishable from none.
    let row = sqlx::query(
        "SELECT status, signing_suite, signing_public_key, signing_key_id,
                hpke_suite, hpke_public_key, hpke_key_id
           FROM v2_devices WHERE tenant_id = ? AND id = ? AND account_id = ?",
    )
    .bind(ticket.tenant_id.as_slice())
    .bind(device_id.as_slice())
    .bind(ticket.account_id.as_slice())
    .fetch_optional(&mut *conn)
    .await?
    .ok_or(AppError::NotFound)?;
    let status: String = row.get("status");
    if status != "pending" {
        // An active device needs its live approval to start a session; that
        // path arrives with approvals (W2 PR4).
        return Err(AppError::Conflict(format!(
            "the device is {status}, not pending"
        )));
    }
    let spk: [u8; 32] = blob(&row, "signing_public_key")?;
    let hpk: [u8; 32] = blob(&row, "hpke_public_key")?;
    let ids = derive_device_key_ids(row.get("signing_suite"), &spk, row.get("hpke_suite"), &hpk);
    let (signing_key_id, hpke_key_id) = match ids {
        Ok(ids)
            if ids.0 == blob(&row, "signing_key_id")? && ids.1 == blob(&row, "hpke_key_id")? =>
        {
            ids
        }
        _ => {
            return Err(AppError::Conflict(
                "the device keys need reconciliation".into(),
            ))
        }
    };

    let challenge_id = random::<16>()?;
    let expires_at_ms = now + CHALLENGE_TTL_MS;
    let binding = DeviceSessionBindingV2 {
        device_id,
        fields: BindingFields {
            server_instance_id: v.server_instance_id,
            restore_epoch: v.restore_epoch,
            tenant_id: ticket.tenant_id,
            account_id: ticket.account_id,
            pre_device_session_id: ticket.id,
            challenge_id,
            nonce: random::<16>()?,
            signing_suite: 1,
            signing_public_key: spk,
            signing_key_id,
            hpke_suite: 1,
            hpke_public_key: hpk,
            hpke_key_id,
            expires_at_ms: expires_at_ms as u64,
        },
    }
    .encode()
    .map_err(|_| AppError::Conflict("the device keys cannot hold a session".into()))?;
    let secret = sb::fresh_pop_secret().map_err(|e| AppError::Internal(format!("entropy: {e}")))?;
    let (encapped, ciphertext) = sb::seal_pop_secret(&hpk, &binding, &secret)
        .map_err(|_| AppError::Conflict("the device keys cannot hold a session".into()))?;
    sqlx::query(
        "INSERT INTO v2_device_session_challenges
             (id, pre_device_session_id, tenant_id, account_id, device_id, binding_bytes,
              secret_hash, created_at_ms, expires_at_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(challenge_id.as_slice())
    .bind(ticket.id.as_slice())
    .bind(ticket.tenant_id.as_slice())
    .bind(ticket.account_id.as_slice())
    .bind(device_id.as_slice())
    .bind(&binding)
    .bind(sb::pop_secret_hash(&secret).as_slice())
    .bind(now)
    .bind(expires_at_ms)
    .execute(&mut *conn)
    .await?;
    conn.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "challenge_id": hex(&challenge_id),
            "binding": hex(&binding),
            "encapsulated_key": hex(&encapped),
            "ciphertext": hex(&ciphertext),
            "expires_at_ms": expires_at_ms,
        })),
    ))
}

#[derive(Deserialize)]
pub struct ProofReq {
    challenge_id: String,
    secret: String,
    signature: String,
}

async fn revoke_challenge(
    conn: &mut SqliteConnection,
    id: &[u8; 16],
    now: i64,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE v2_device_session_challenges SET revoked_at_ms = ?
          WHERE id = ? AND consumed_at_ms IS NULL AND revoked_at_ms IS NULL",
    )
    .bind(now)
    .bind(id.as_slice())
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// `POST /v2/auth/device-session-proofs`: both proofs, then one transaction
/// that consumes the challenge and the ticket and creates the session.
pub async fn prove_device_session(
    State(app): State<AppState>,
    TicketAuth(presented): TicketAuth,
    AppJson(req): AppJson<ProofReq>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let v = verified(&app)?;
    let bad =
        |what: &str| AppError::BadRequest(format!("{what} has the wrong length or is not hex"));
    let challenge_id = unhex::<16>(&req.challenge_id).ok_or_else(|| bad("challenge_id"))?;
    let secret = Zeroizing::new(unhex::<32>(&req.secret).ok_or_else(|| bad("secret"))?);
    let signature = unhex::<64>(&req.signature).ok_or_else(|| bad("signature"))?;

    let mut tx = app.db.begin_with("BEGIN IMMEDIATE").await?;
    let now = now_ms();
    let ticket = load_ticket(&mut tx, "id", &presented.id, v, now)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let row = sqlx::query(
        "SELECT device_id, binding_bytes, secret_hash, expires_at_ms, consumed_at_ms, revoked_at_ms
           FROM v2_device_session_challenges WHERE id = ? AND pre_device_session_id = ?",
    )
    .bind(challenge_id.as_slice())
    .bind(ticket.id.as_slice())
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::NotFound)?;
    if row.get::<Option<i64>, _>("consumed_at_ms").is_some()
        || row.get::<Option<i64>, _>("revoked_at_ms").is_some()
        || row.get::<i64, _>("expires_at_ms") <= now
    {
        return Err(AppError::Unauthorized);
    }
    let binding_bytes: Vec<u8> = row.get("binding_bytes");
    let stored_hash: [u8; 32] = blob(&row, "secret_hash")?;
    let binding = DeviceSessionBindingV2::parse(&binding_bytes)
        .map_err(|_| AppError::Internal("a stored binding does not parse".into()))?;
    let f = &binding.fields;
    let proven = sb::pop_secret_matches(&stored_hash, &secret)
        && sb::verify_pop(&f.signing_public_key, &binding_bytes, &secret, &signature).is_ok();
    if !proven {
        // One attempt per challenge: a wrong answer burns it.
        revoke_challenge(&mut tx, &challenge_id, now).await?;
        tx.commit().await?;
        return Err(AppError::Unauthorized);
    }

    // The device must still be what the binding named.
    let live_device = sqlx::query_scalar::<_, i64>(
        "SELECT 1 FROM v2_devices
          WHERE tenant_id = ? AND id = ? AND account_id = ? AND status = 'pending'
            AND signing_public_key = ? AND signing_key_id = ?
            AND hpke_public_key = ? AND hpke_key_id = ?",
    )
    .bind(ticket.tenant_id.as_slice())
    .bind(binding.device_id.as_slice())
    .bind(ticket.account_id.as_slice())
    .bind(f.signing_public_key.as_slice())
    .bind(f.signing_key_id.as_slice())
    .bind(f.hpke_public_key.as_slice())
    .bind(f.hpke_key_id.as_slice())
    .fetch_optional(&mut *tx)
    .await?
    .is_some();
    let bound = f.server_instance_id == v.server_instance_id
        && f.restore_epoch == v.restore_epoch
        && f.tenant_id == ticket.tenant_id
        && f.account_id == ticket.account_id
        && f.pre_device_session_id == ticket.id
        && f.challenge_id == challenge_id
        && binding.device_id == blob::<16>(&row, "device_id")?;
    if !live_device || !bound {
        revoke_challenge(&mut tx, &challenge_id, now).await?;
        tx.commit().await?;
        return Err(AppError::Conflict(
            "the device changed since the challenge".into(),
        ));
    }

    let used = sqlx::query(
        "UPDATE v2_device_session_challenges SET consumed_at_ms = ?
          WHERE id = ? AND consumed_at_ms IS NULL AND revoked_at_ms IS NULL",
    )
    .bind(now)
    .bind(challenge_id.as_slice())
    .execute(&mut *tx)
    .await?;
    let spent = sqlx::query(
        "UPDATE v2_pre_device_sessions SET consumed_at_ms = ?
          WHERE id = ? AND consumed_at_ms IS NULL AND revoked_at_ms IS NULL",
    )
    .bind(now)
    .bind(ticket.id.as_slice())
    .execute(&mut *tx)
    .await?;
    if used.rows_affected() != 1 || spent.rows_affected() != 1 {
        return Err(AppError::Unauthorized);
    }

    let session_id = random::<16>()?;
    let (access, access_hash) = new_token(ACCESS)?;
    let (refresh, refresh_hash) = new_token(REFRESH)?;
    let absolute = now + SETUP_SESSION_MS;
    let access_expires = now + ACCESS_TTL_MS;
    sqlx::query(
        "INSERT INTO v2_sessions
             (id, tenant_id, account_id, device_id, server_instance_id, restore_epoch,
              signing_key_id, hpke_key_id, account_token_version, class, pre_device_session_id,
              device_session_challenge_id, pop_at_ms, access_token_hash, access_expires_at_ms,
              refresh_token_hash, refresh_expires_at_ms, absolute_expires_at_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending_setup', ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(session_id.as_slice())
    .bind(ticket.tenant_id.as_slice())
    .bind(ticket.account_id.as_slice())
    .bind(binding.device_id.as_slice())
    .bind(v.server_instance_id.as_slice())
    .bind(epoch(v)?)
    .bind(f.signing_key_id.as_slice())
    .bind(f.hpke_key_id.as_slice())
    .bind(ticket.token_version)
    .bind(ticket.id.as_slice())
    .bind(challenge_id.as_slice())
    .bind(now)
    .bind(access_hash.as_slice())
    .bind(access_expires)
    .bind(refresh_hash.as_slice())
    .bind(absolute)
    .bind(absolute)
    .execute(&mut *tx)
    .await?;
    audit(
        &mut tx,
        &ticket.tenant_id,
        &ticket.account_id,
        &binding.device_id,
        "auth.device_session",
        "session",
        &session_id,
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "session_id": hex(&session_id),
            "class": "pending_setup",
            "device_id": hex(&binding.device_id),
            "access_token": access.as_str(),
            "access_expires_at_ms": access_expires,
            "refresh_token": refresh.as_str(),
            "refresh_expires_at_ms": absolute,
            "absolute_expires_at_ms": absolute,
        })),
    ))
}

#[derive(Deserialize)]
pub struct RefreshReq {
    refresh_token: String,
}

/// `POST /v2/auth/refresh`: single-use rotation that rechecks every live
/// predicate and never moves past the session's absolute bound.
pub async fn refresh(
    State(app): State<AppState>,
    AppJson(req): AppJson<RefreshReq>,
) -> Result<Json<Value>, AppError> {
    let v = verified(&app)?;
    let hash = token_hash(&req.refresh_token, REFRESH).ok_or(AppError::Unauthorized)?;
    let mut tx = app.db.begin_with("BEGIN IMMEDIATE").await?;
    // Read after the lock: time spent waiting for it must not extend a token.
    let now = now_ms();
    let row = sqlx::query(&format!(
        "SELECT {SESSION_COLUMNS} FROM v2_sessions
          WHERE refresh_token_hash = ? AND revoked_at_ms IS NULL"
    ))
    .bind(hash.as_slice())
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = row else {
        // A token the last rotation replaced: someone else holds a copy, so
        // neither holder keeps the session.
        sqlx::query(
            "UPDATE v2_sessions SET revoked_at_ms = ?
              WHERE previous_refresh_token_hash = ? AND revoked_at_ms IS NULL",
        )
        .bind(now)
        .bind(hash.as_slice())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        return Err(AppError::Unauthorized);
    };
    let session = session_from(&row)?;
    let fresh =
        now < row.get::<i64, _>("refresh_expires_at_ms") && now < session.absolute_expires_at_ms;
    if !fresh || !session_is_live(&mut tx, &row, &session, v).await? {
        sqlx::query("UPDATE v2_sessions SET revoked_at_ms = ? WHERE tenant_id = ? AND id = ?")
            .bind(now)
            .bind(session.tenant_id.as_slice())
            .bind(session.id.as_slice())
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        return Err(AppError::Unauthorized);
    }
    let (access, access_hash) = new_token(ACCESS)?;
    let (refresh, refresh_hash) = new_token(REFRESH)?;
    let access_expires = (now + ACCESS_TTL_MS).min(session.absolute_expires_at_ms);
    let rotated = sqlx::query(
        "UPDATE v2_sessions
            SET access_token_hash = ?, access_expires_at_ms = ?, refresh_token_hash = ?,
                previous_refresh_token_hash = refresh_token_hash
          WHERE tenant_id = ? AND id = ? AND refresh_token_hash = ? AND revoked_at_ms IS NULL",
    )
    .bind(access_hash.as_slice())
    .bind(access_expires)
    .bind(refresh_hash.as_slice())
    .bind(session.tenant_id.as_slice())
    .bind(session.id.as_slice())
    .bind(hash.as_slice())
    .execute(&mut *tx)
    .await?;
    if rotated.rows_affected() != 1 {
        return Err(AppError::Unauthorized);
    }
    tx.commit().await?;
    Ok(Json(json!({
        "session_id": hex(&session.id),
        "class": session.class,
        "access_token": access.as_str(),
        "access_expires_at_ms": access_expires,
        "refresh_token": refresh.as_str(),
        "refresh_expires_at_ms": row.get::<i64, _>("refresh_expires_at_ms"),
        "absolute_expires_at_ms": session.absolute_expires_at_ms,
    })))
}

/// `POST /v2/auth/logout`: ends the ticket (and its open challenges) or the
/// session the bearer token names.
pub async fn logout(State(app): State<AppState>, who: Principal) -> Result<StatusCode, AppError> {
    let now = now_ms();
    let mut tx = app.db.begin_with("BEGIN IMMEDIATE").await?;
    match who {
        Principal::Ticket(t) => {
            sqlx::query(
                "UPDATE v2_pre_device_sessions SET revoked_at_ms = ?
                  WHERE id = ? AND consumed_at_ms IS NULL AND revoked_at_ms IS NULL",
            )
            .bind(now)
            .bind(t.id.as_slice())
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE v2_device_session_challenges SET revoked_at_ms = ?
                  WHERE pre_device_session_id = ? AND consumed_at_ms IS NULL
                    AND revoked_at_ms IS NULL",
            )
            .bind(now)
            .bind(t.id.as_slice())
            .execute(&mut *tx)
            .await?;
        }
        Principal::Session(s) => {
            sqlx::query(
                "UPDATE v2_sessions SET revoked_at_ms = ?
                  WHERE tenant_id = ? AND id = ? AND revoked_at_ms IS NULL",
            )
            .bind(now)
            .bind(s.tenant_id.as_slice())
            .bind(s.id.as_slice())
            .execute(&mut *tx)
            .await?;
        }
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /v2/me`: the binding the token carries, read from current rows. For a
/// ticket it also lists the account's devices, which is how a client learns
/// the outcome of an enrollment whose response it lost.
pub async fn me(State(app): State<AppState>, who: Principal) -> Result<Json<Value>, AppError> {
    let v = verified(&app)?;
    let common = json!({
        "server_instance_id": hex(&v.server_instance_id),
        "restore_epoch": v.restore_epoch,
    });
    let mut out = match who {
        Principal::Ticket(t) => {
            let devices: Vec<Value> = sqlx::query(
                "SELECT id, status, signing_key_id, hpke_key_id FROM v2_devices
                  WHERE tenant_id = ? AND account_id = ? ORDER BY created_at, id",
            )
            .bind(t.tenant_id.as_slice())
            .bind(t.account_id.as_slice())
            .fetch_all(&app.db)
            .await?
            .iter()
            .map(|r| {
                json!({
                    "device_id": hex(&r.get::<Vec<u8>, _>("id")),
                    "status": r.get::<String, _>("status"),
                    "signing_key_id": hex(&r.get::<Vec<u8>, _>("signing_key_id")),
                    "hpke_key_id": hex(&r.get::<Vec<u8>, _>("hpke_key_id")),
                })
            })
            .collect();
            json!({
                "kind": "pre_device",
                "ticket_id": hex(&t.id),
                "tenant_id": hex(&t.tenant_id),
                "account_id": hex(&t.account_id),
                "expires_at_ms": t.expires_at_ms,
                "devices": devices,
            })
        }
        Principal::Session(s) => json!({
            "kind": "session",
            "session_id": hex(&s.id),
            "class": s.class,
            "tenant_id": hex(&s.tenant_id),
            "account_id": hex(&s.account_id),
            "device_id": hex(&s.device_id),
            "signing_key_id": hex(&s.signing_key_id),
            "hpke_key_id": hex(&s.hpke_key_id),
            "access_expires_at_ms": s.access_expires_at_ms,
            "absolute_expires_at_ms": s.absolute_expires_at_ms,
        }),
    };
    if let (Some(o), Some(c)) = (out.as_object_mut(), common.as_object()) {
        o.extend(c.clone());
    }
    Ok(Json(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_typed_and_only_their_hash_is_kept() {
        let (token, hash) = new_token(TICKET).unwrap();
        assert!(token.starts_with(TICKET) && token.len() == TICKET.len() + 64);
        assert_eq!(token_hash(&token, TICKET), Some(hash));
        // A ticket is not an access token, and a mangled one is nothing.
        assert_eq!(token_hash(&token, ACCESS), None);
        assert_eq!(token_hash(&token[..token.len() - 1], TICKET), None);
        assert_eq!(
            token_hash(&format!("{}g", &token[..token.len() - 1]), TICKET),
            None
        );
        assert_ne!(new_token(TICKET).unwrap().1, hash);
    }
}
