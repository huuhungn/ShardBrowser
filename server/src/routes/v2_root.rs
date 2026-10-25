//! `POST /v2/tenants/{tenant_id}/root-key-generations`: the S6 first root
//! bootstrap (plan 5.6.4 rule 1, ADR 0001 S6).
//!
//! The body is an exact `IdempotentMutationRequestV2` (plan 5.6.5) whose
//! payload is a `TenantRootGenerationCreateV2` in bootstrap mode, carrying the
//! exact `FirstRootSelfGrant` container. One `BEGIN IMMEDIATE` checks that D1
//! completed and nothing root-related exists yet, that the actor is the
//! approved first device on its `root_setup` session, and that the self-grant
//! names exactly that device, its approval and the target key; then it writes
//! generation 0 as `PREPARING`, the grant, the exact stored response and the
//! audit row together. A retry with the same bytes by the same actor gets the
//! stored response back, unchanged. Activation waits for readback and
//! acknowledgement, which come later.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use sqlx::{Row, SqliteConnection};

use shared::approval_receipt::{AUTHORIZATION_REPLAY_RETENTION_MS, MAX_DEVICE_APPROVAL_TTL_MS};
use shared::authz_record::{
    AuthorizationRecord, Payload, RecordError, RootGrantVariant, TenantRootKeyGrantV2,
    DOMAIN_DEVICE_APPROVAL, DOMAIN_TENANT_ROOT_KEY_GRANT,
};
use shared::canonical::sha256;
use shared::mutation::{
    EmbeddedSelfGrant, IdempotentMutationRequestV2, IdempotentStoredResponseV2, OperationKind,
    RootGenerationMode, SelfGrantIdentity, TenantRootGenerationCreateV2,
    TenantRootGenerationCreatedV2, RECORD_TYPE_ROOT_GENERATION_CREATED,
};

use super::v2_approval::{cbor, coded, column_mismatch, exact_cbor_body, int, sole_owner};
use super::v2_auth::{
    audit, blob, d1_approval_replay_id, random, reload_session, unhex, verified, Principal, Session,
};
use crate::error::AppError;
use crate::identity::Verified;
use crate::state::AppState;
use crate::util::{now_ms, now_rfc3339};

/// The 5.6.5 outer request is stored whole in `v2_idempotency`, whose bound
/// this is.
pub const MAX_ROOT_REQUEST_BODY: usize = 262_144;
/// ADR 0002 D-6: every root grant variant has the device approval's 730 days.
const MAX_ROOT_GRANT_TTL_MS: u64 = MAX_DEVICE_APPROVAL_TTL_MS;

pub(super) fn record_error(e: RecordError) -> AppError {
    coded(StatusCode::UNPROCESSABLE_ENTITY, e.code(), &e.to_string())
}

pub(super) fn mismatch() -> AppError {
    coded(
        StatusCode::CONFLICT,
        "IDEMPOTENCY_MISMATCH",
        "this idempotency key is already used by another request",
    )
}

pub(super) fn stale() -> AppError {
    coded(
        StatusCode::CONFLICT,
        "STALE_CONTEXT",
        "the request names another restore epoch",
    )
}

fn already_exists() -> AppError {
    coded(
        StatusCode::CONFLICT,
        "ROOT_BOOTSTRAP_ALREADY_EXISTS",
        "this tenant already has a root key generation or grant",
    )
}

/// The parsed request and the facts every later step compares with.
struct Request {
    outer: IdempotentMutationRequestV2,
    create: TenantRootGenerationCreateV2,
    request_hash: [u8; 32],
}

pub async fn create_root_generation(
    State(app): State<AppState>,
    who: Principal,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let v = verified(&app)?;
    // A ticket proves only a password; custody needs a device session.
    let Principal::Session(presented) = who else {
        return Err(AppError::Forbidden);
    };
    let path_tenant = unhex::<16>(&tenant)
        .ok_or_else(|| AppError::BadRequest("tenant id must be 32 hex digits".into()))?;
    exact_cbor_body(&headers, &body, MAX_ROOT_REQUEST_BODY)?;
    let outer = IdempotentMutationRequestV2::parse(&body).map_err(record_error)?;
    if outer.operation_kind != OperationKind::RootGenerationCreate {
        return Err(column_mismatch(
            "the request is not a root generation create",
        ));
    }
    let create = TenantRootGenerationCreateV2::parse(&outer.canonical_payload_bytes)
        .map_err(record_error)?;
    let t = &create.target;
    if t.tenant_id != path_tenant {
        return Err(column_mismatch(
            "the path names another tenant than the request",
        ));
    }
    if outer.server_instance_id != v.server_instance_id
        || t.server_instance_id != v.server_instance_id
    {
        return Err(AppError::Forbidden);
    }
    if outer.restore_epoch != v.restore_epoch || t.restore_epoch != v.restore_epoch {
        return Err(stale());
    }
    let req = Request {
        request_hash: outer.canonical_request_hash(),
        outer,
        create,
    };

    let mut tx = app.db.begin_with("BEGIN IMMEDIATE").await?;
    let now = now_ms();
    let s = reload_session(&mut tx, &presented, v, now)
        .await?
        .ok_or(AppError::Unauthorized)?;
    if s.tenant_id != path_tenant {
        return Err(AppError::Forbidden);
    }

    let row = ledger_row(
        &mut tx,
        v,
        &s,
        OperationKind::RootGenerationCreate,
        &req.outer.idempotency_key,
    )
    .await?;
    if let Some(row) = row {
        return replay(tx, &row, &req, &s, v, &body).await;
    }

    match &req.create.mode {
        RootGenerationMode::Bootstrap(g) => bootstrap(tx, &req, g, &s, v, &body, now).await,
        // shortcut: only the bootstrap exists; a rotation needs an ACTIVE root
        // and a custodian of it (plan 5.6.4 rule 3), which come with W3.
        RootGenerationMode::Rotation { .. } => Err(AppError::Forbidden),
    }
}

/// An exact retry: the stored request and response must agree with this
/// request and with the generation they created, and then the stored bytes go
/// back unchanged.
async fn replay(
    mut tx: sqlx::Transaction<'_, sqlx::Sqlite>,
    row: &sqlx::sqlite::SqliteRow,
    req: &Request,
    s: &Session,
    v: &Verified,
    exact_request: &[u8],
) -> Result<Response, AppError> {
    if !same_request(
        row,
        OperationKind::RootGenerationCreate,
        &req.request_hash,
        exact_request,
    )? {
        return Err(mismatch());
    }
    let response: Vec<u8> = row
        .get::<Option<Vec<u8>>, _>("exact_response_bytes")
        .unwrap_or_default();
    if !stored_response_is_consistent(&mut tx, row, req, s, v, &response).await? {
        return Err(coded(
            StatusCode::UNPROCESSABLE_ENTITY,
            "MUTATION_RESPONSE_MISMATCH",
            "the stored response does not match the generation it created",
        ));
    }
    tx.commit().await?;
    Ok(cbor(StatusCode::CREATED, response))
}

/// Every equality a stored `ROOT_GENERATION_CREATE` row must hold: the
/// response is the exact map for this request, and the generation and grant it
/// names exist with the same terms.
async fn stored_response_is_consistent(
    conn: &mut SqliteConnection,
    row: &sqlx::sqlite::SqliteRow,
    req: &Request,
    s: &Session,
    v: &Verified,
    response: &[u8],
) -> Result<bool, AppError> {
    let Ok(stored) = IdempotentStoredResponseV2::parse(response) else {
        return Ok(false);
    };
    let Ok(created) =
        TenantRootGenerationCreatedV2::parse(&stored.canonical_response_payload_bytes)
    else {
        return Ok(false);
    };
    let RootGenerationMode::Bootstrap(identity) = &created.mode else {
        return Ok(false);
    };
    let t = &req.create.target;
    let generation = sqlx::query(
        "SELECT root_key_id, required_custodian_grant_count, required_custodian_grant_set_hash,
                recovery_bundle_sha256
           FROM v2_root_key_generations
          WHERE server_instance_id = ? AND tenant_id = ? AND generation = ?",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(s.tenant_id.as_slice())
    .bind(int(t.root_generation)?)
    .fetch_optional(&mut *conn)
    .await?;
    let grant = sqlx::query(
        "SELECT signed_container_hash, exact_signed_container_bytes_sha256
           FROM v2_tenant_root_key_grants
          WHERE server_instance_id = ? AND tenant_id = ? AND replay_id = ?
            AND grant_variant = 'FirstRootSelfGrant' AND subject_device_id = ?",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(s.tenant_id.as_slice())
    .bind(identity.replay_id.as_slice())
    .bind(s.device_id.as_slice())
    .fetch_optional(&mut *conn)
    .await?;
    let (Some(generation), Some(grant)) = (generation, grant) else {
        return Ok(false);
    };
    Ok(stored.operation_kind == OperationKind::RootGenerationCreate
        && stored.idempotency_key == req.outer.idempotency_key
        && stored.exact_request_hash == req.request_hash
        && stored.response_record_type == RECORD_TYPE_ROOT_GENERATION_CREATED
        && stored.server_instance_id == v.server_instance_id
        && stored.restore_epoch == v.restore_epoch
        && created.target == *t
        && blob::<32>(&generation, "root_key_id")? == t.root_key_id
        && generation.get::<Option<i64>, _>("required_custodian_grant_count")
            == Some(i64::from(t.required_custodian_grant_count))
        && generation
            .get::<Option<Vec<u8>>, _>("required_custodian_grant_set_hash")
            .as_deref()
            == Some(&t.required_custodian_grant_set_hash[..])
        && generation
            .get::<Option<Vec<u8>>, _>("recovery_bundle_sha256")
            .as_deref()
            == Some(&t.recovery_bundle_sha256[..])
        && blob::<32>(&grant, "signed_container_hash")? == identity.signed_container_hash
        && blob::<32>(&grant, "exact_signed_container_bytes_sha256")?
            == identity.container_bytes_sha256
        && row
            .get::<Option<String>, _>("response_record_type")
            .as_deref()
            == Some(RECORD_TYPE_ROOT_GENERATION_CREATED)
        && row
            .get::<Option<Vec<u8>>, _>("exact_response_bytes_sha256")
            .as_deref()
            == Some(&sha256(response)[..]))
}

/// Plan 5.6.4 rule 1: every guard, then every write, in one transaction.
async fn bootstrap(
    mut tx: sqlx::Transaction<'_, sqlx::Sqlite>,
    req: &Request,
    embedded: &EmbeddedSelfGrant,
    s: &Session,
    v: &Verified,
    exact_request: &[u8],
    now: i64,
) -> Result<Response, AppError> {
    let t = &req.create.target;

    // No root history of any kind, on any instance (rule 1).
    for table in [
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
            return Err(already_exists());
        }
    }
    // Nor an active custodian capability from the spike table; the exact
    // table refuses `root.custody`, and D1 refuses a tenant with any.
    let custodian: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM v2_legacy_capability_grants
                         WHERE tenant_id = ? AND capability = 'root.custody'
                           AND revoked_at IS NULL)",
    )
    .bind(s.tenant_id.as_slice())
    .fetch_one(&mut *tx)
    .await?;
    if custodian {
        return Err(already_exists());
    }
    // The actor is the approved first device on its setup session, and the
    // tenant's sole owner, as at D1. `d1_approval_replay_id` also requires the
    // guard to be still `consumed`. The class check repeats what session
    // liveness already holds today (no `ordinary` session is live), so a
    // later class cannot reach the bootstrap.
    if s.class != "root_setup" || !sole_owner(&mut tx, s).await? {
        return Err(AppError::Forbidden);
    }
    let approval = d1_approval_replay_id(
        &mut tx,
        &s.tenant_id,
        &s.device_id,
        &s.signing_key_id,
        &s.hpke_key_id,
        v,
        now,
    )
    .await?
    .ok_or(AppError::Forbidden)?;

    // The embedded container, signed by the actor's own key.
    let parsed = AuthorizationRecord::parse(&embedded.container_bytes).map_err(record_error)?;
    if parsed.payload_domain() != DOMAIN_TENANT_ROOT_KEY_GRANT {
        return Err(column_mismatch(
            "the embedded record is not a root key grant",
        ));
    }
    if *parsed.signed_container_hash() != embedded.signed_container_hash {
        return Err(column_mismatch(
            "the embedded container hash differs from the request",
        ));
    }
    if *parsed.issuer_signing_key_id() != s.signing_key_id {
        return Err(coded(
            StatusCode::UNPROCESSABLE_ENTITY,
            "KEY_SUBSTITUTION_DETECTED",
            "the self-grant is not signed by the session's device",
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
    let record = parsed.verify_signature(&issuer).map_err(record_error)?;
    let Payload::TenantRootKeyGrant(g) = record.payload().clone() else {
        return Err(column_mismatch(
            "the embedded record is not a root key grant",
        ));
    };
    let record = record.record();

    // The self-grant names exactly this device, its approval and the target.
    let c = &g.common;
    let names_target = g.variant == RootGrantVariant::FirstRootSelfGrant
        && c.tenant_id == t.tenant_id
        && c.server_instance_id == t.server_instance_id
        && c.restore_epoch == t.restore_epoch
        && g.root_key_id == t.root_key_id
        && g.root_generation == t.root_generation
        && g.subject_account_id == s.account_id
        && g.subject_device_id == s.device_id
        && g.subject_signing_key_id == s.signing_key_id
        && g.recipient_hpke_key_id == s.hpke_key_id
        && g.subject_device_approval_replay_id == approval;
    if !names_target {
        return Err(column_mismatch(
            "the self-grant does not name this device, its approval and the target key",
        ));
    }
    // The custodian set is the self-grant alone (ADR 0002 D-4): the codec
    // checked it against `embedded.signed_container_hash`, which equals the
    // parsed container's hash above.
    if int(c.not_before_ms)? > now
        || now >= int(c.not_after_ms)?
        || c.not_after_ms - c.not_before_ms > MAX_ROOT_GRANT_TTL_MS
    {
        return Err(AppError::Forbidden);
    }

    // Every write together; any failure rolls all of them back.
    let created_at = now_rfc3339();
    sqlx::query(
        "INSERT INTO v2_root_key_generations
             (server_instance_id, tenant_id, generation, root_key_id, state, created_at,
              required_custodian_grant_count, required_custodian_grant_set_hash,
              recovery_bundle_sha256)
         VALUES (?, ?, ?, ?, 'PREPARING', ?, ?, ?, ?)",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(s.tenant_id.as_slice())
    .bind(int(t.root_generation)?)
    .bind(t.root_key_id.as_slice())
    .bind(&created_at)
    .bind(i64::from(t.required_custodian_grant_count))
    .bind(t.required_custodian_grant_set_hash.as_slice())
    .bind(t.recovery_bundle_sha256.as_slice())
    .execute(&mut *tx)
    .await?;
    insert_grant(&mut tx, &g, record, &created_at).await?;

    let committed_at_ms = u64::try_from(now).unwrap_or_default();
    let created = TenantRootGenerationCreatedV2 {
        target: t.clone(),
        mode: RootGenerationMode::Bootstrap(SelfGrantIdentity {
            replay_id: c.replay_id,
            signed_container_hash: *record.signed_container_hash(),
            container_bytes_sha256: *record.exact_signed_container_bytes_sha256(),
        }),
        created_at_ms: committed_at_ms,
    };
    let response = stored_response(
        &req.outer,
        RECORD_TYPE_ROOT_GENERATION_CREATED,
        created.encode(),
        v,
        committed_at_ms,
    )?;
    let retained_until = c
        .not_after_ms
        .checked_add(AUTHORIZATION_REPLAY_RETENTION_MS)
        .ok_or(AppError::Forbidden)?;
    store_response(
        &mut tx,
        v,
        s,
        &req.outer,
        exact_request,
        RECORD_TYPE_ROOT_GENERATION_CREATED,
        &response,
        retained_until,
    )
    .await?;
    audit(
        &mut tx,
        &s.tenant_id,
        &s.account_id,
        &s.device_id,
        "root.bootstrap",
        "root_generation",
        &t.root_key_id,
    )
    .await?;
    tx.commit().await?;
    Ok(cbor(StatusCode::CREATED, response))
}

/// The value of one grant column.
pub(super) enum Col {
    Blob(Vec<u8>),
    Int(i64),
    Text(&'static str),
    Null,
}

type Query<'q> = sqlx::query::Query<'q, sqlx::Sqlite, sqlx::sqlite::SqliteArguments<'q>>;

fn bind<'q>(q: Query<'q>, col: &'q Col) -> Query<'q> {
    match col {
        Col::Blob(b) => q.bind(b.as_slice()),
        Col::Int(n) => q.bind(*n),
        Col::Text(t) => q.bind(*t),
        Col::Null => q.bind(Option::<i64>::None),
    }
}

/// Every plan 7.2 column of a grant row except `created_at` and the two
/// marks, each derived from the verified record. Filing and readback both use
/// this list, so a column cannot be written one way and checked another.
fn grant_columns(
    g: &TenantRootKeyGrantV2,
    record: &AuthorizationRecord,
) -> Result<Vec<(&'static str, Col)>, AppError> {
    let c = &g.common;
    let b = |bytes: &[u8]| Col::Blob(bytes.to_vec());
    let (previous_key, previous_generation) = match g.variant {
        RootGrantVariant::RotationGrant {
            previous_root_key_id,
            previous_root_generation,
        } => (
            b(&previous_root_key_id),
            Col::Int(int(previous_root_generation)?),
        ),
        _ => (Col::Null, Col::Null),
    };
    let (suite, version) = record.signature_suite();
    Ok(vec![
        ("server_instance_id", b(&c.server_instance_id)),
        ("tenant_id", b(&c.tenant_id)),
        ("replay_id", b(&c.replay_id)),
        (
            "container_domain",
            Col::Text(shared::authz_record::CONTAINER_DOMAIN),
        ),
        (
            "container_version",
            Col::Int(i64::from(shared::authz_record::CONTAINER_VERSION)),
        ),
        ("payload_domain", Col::Text(DOMAIN_TENANT_ROOT_KEY_GRANT)),
        ("payload_version", Col::Int(2)),
        ("grant_variant", Col::Text(g.variant.as_str())),
        ("root_key_id", b(&g.root_key_id)),
        ("root_generation", Col::Int(int(g.root_generation)?)),
        ("grant_capability", Col::Text("root.custody")),
        ("subject_account_id", b(&g.subject_account_id)),
        ("subject_device_id", b(&g.subject_device_id)),
        ("subject_signing_key_id", b(&g.subject_signing_key_id)),
        (
            "subject_device_approval_payload_domain",
            Col::Text(DOMAIN_DEVICE_APPROVAL),
        ),
        (
            "subject_device_approval_replay_id",
            b(&g.subject_device_approval_replay_id),
        ),
        ("recipient_hpke_key_id", b(&g.recipient_hpke_key_id)),
        ("hpke_suite_id", Col::Int(1)),
        ("hpke_mode_id", Col::Int(0)),
        ("hpke_kem_id", Col::Int(32)),
        ("hpke_kdf_id", Col::Int(1)),
        ("hpke_aead_id", Col::Int(3)),
        ("hpke_info_bytes", Col::Blob(g.hpke_info_bytes())),
        ("hpke_encapped_key_bytes", b(&g.hpke_encapped_key_bytes)),
        ("hpke_wrapped_trk_bytes", b(&g.hpke_wrapped_trk_bytes)),
        ("previous_root_key_id", previous_key),
        ("previous_root_generation", previous_generation),
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
        ("issuer_signing_key_id", b(record.issuer_signing_key_id())),
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

/// Inserts one row of `table` holding exactly `cols` and `created_at`.
pub(super) async fn insert_row(
    conn: &mut SqliteConnection,
    table: &str,
    cols: &[(&'static str, Col)],
    created_at: &str,
) -> Result<(), AppError> {
    let names: Vec<&str> = cols.iter().map(|(name, _)| *name).collect();
    let sql = format!(
        "INSERT INTO {table} ({}, created_at) VALUES ({}?)",
        names.join(", "),
        "?, ".repeat(cols.len())
    );
    let mut q = sqlx::query(&sql);
    for (_, col) in cols {
        q = bind(q, col);
    }
    q.bind(created_at).execute(&mut *conn).await?;
    Ok(())
}

/// Whether some row of `table` holds exactly `cols`. A caller that means one
/// row puts that row's key among `cols`.
pub(super) async fn row_holds(
    conn: &mut SqliteConnection,
    table: &str,
    cols: &[(&'static str, Col)],
) -> Result<bool, AppError> {
    let condition: Vec<String> = cols
        .iter()
        .map(|(name, _)| format!("{name} IS ?"))
        .collect();
    let sql = format!(
        "SELECT EXISTS (SELECT 1 FROM {table} WHERE {})",
        condition.join(" AND ")
    );
    let mut q = sqlx::query_scalar::<_, bool>(&sql);
    for (_, col) in cols {
        q = match col {
            Col::Blob(b) => q.bind(b.as_slice()),
            Col::Int(n) => q.bind(*n),
            Col::Text(t) => q.bind(*t),
            Col::Null => q.bind(Option::<i64>::None),
        };
    }
    Ok(q.fetch_one(&mut *conn).await?)
}

/// Files the exact grant row: every column from the verified record.
async fn insert_grant(
    conn: &mut SqliteConnection,
    g: &TenantRootKeyGrantV2,
    record: &AuthorizationRecord,
    created_at: &str,
) -> Result<(), AppError> {
    let cols = grant_columns(g, record)?;
    insert_row(conn, "v2_tenant_root_key_grants", &cols, created_at).await
}

/// The primary key of a root grant row: instance, tenant, replay ID.
pub(super) type GrantKey<'a> = (&'a [u8; 16], &'a [u8; 16], &'a [u8; 16]);

/// Whether the row stored under `key` holds exactly the columns the verified
/// record determines (plan 5.6.4: every read reparses and compares one for
/// one). A record naming another key is never this row's, even if some other
/// row holds it.
pub(super) async fn grant_row_matches(
    conn: &mut SqliteConnection,
    key: GrantKey<'_>,
    g: &TenantRootKeyGrantV2,
    record: &AuthorizationRecord,
) -> Result<bool, AppError> {
    let c = &g.common;
    if (&c.server_instance_id, &c.tenant_id, &c.replay_id) != key {
        return Ok(false);
    }
    // The key is among the columns, so the check below is of that one row.
    let cols = grant_columns(g, record)?;
    row_holds(conn, "v2_tenant_root_key_grants", &cols).await
}

// ------------------------------------------------- the idempotency ledger ---

/// The ledger row of `kind` under the actor's key, if any.
pub(super) async fn ledger_row(
    conn: &mut SqliteConnection,
    v: &Verified,
    s: &Session,
    kind: OperationKind,
    key: &[u8; 16],
) -> Result<Option<sqlx::sqlite::SqliteRow>, AppError> {
    Ok(sqlx::query(
        "SELECT * FROM v2_idempotency
          WHERE server_instance_id = ? AND tenant_id = ? AND actor_device_id = ?
            AND operation_scope = ? AND idempotency_key = ?",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(s.tenant_id.as_slice())
    .bind(s.device_id.as_slice())
    .bind(kind.scope())
    .bind(key.as_slice())
    .fetch_optional(&mut *conn)
    .await?)
}

/// A ledger row answers this request only if it is the same committed
/// request, byte for byte.
pub(super) fn same_request(
    row: &sqlx::sqlite::SqliteRow,
    kind: OperationKind,
    request_hash: &[u8; 32],
    exact_request: &[u8],
) -> Result<bool, AppError> {
    Ok(row.get::<String, _>("operation_kind") == kind.as_str()
        && row.get::<String, _>("status") == "succeeded"
        && blob::<32>(row, "canonical_request_hash")? == *request_hash
        && blob::<32>(row, "exact_request_bytes_sha256")? == sha256(exact_request)
        && row.get::<Vec<u8>, _>("exact_request_bytes") == exact_request)
}

/// The stored response a ledger row holds, if it is the exact map of `kind`
/// for this request on this instance and epoch, with its record type and
/// hash; `None` for anything else.
pub(super) fn stored_payload(
    row: &sqlx::sqlite::SqliteRow,
    outer: &IdempotentMutationRequestV2,
    record_type: &str,
    v: &Verified,
) -> Option<(Vec<u8>, Vec<u8>)> {
    let response: Vec<u8> = row.get::<Option<Vec<u8>>, _>("exact_response_bytes")?;
    let stored = IdempotentStoredResponseV2::parse(&response).ok()?;
    let ok = stored.operation_kind == outer.operation_kind
        && stored.idempotency_key == outer.idempotency_key
        && stored.exact_request_hash == outer.canonical_request_hash()
        && stored.response_record_type == record_type
        && stored.server_instance_id == v.server_instance_id
        && stored.restore_epoch == v.restore_epoch
        && row
            .get::<Option<String>, _>("response_record_type")
            .as_deref()
            == Some(record_type)
        && row
            .get::<Option<Vec<u8>>, _>("exact_response_bytes_sha256")
            .as_deref()
            == Some(&sha256(&response)[..]);
    ok.then_some((stored.canonical_response_payload_bytes, response))
}

/// The exact stored response map for `outer`.
pub(super) fn stored_response(
    outer: &IdempotentMutationRequestV2,
    record_type: &str,
    payload: Vec<u8>,
    v: &Verified,
    committed_at_ms: u64,
) -> Result<Vec<u8>, AppError> {
    Ok(IdempotentStoredResponseV2 {
        operation_kind: outer.operation_kind,
        idempotency_key: outer.idempotency_key,
        exact_request_hash: outer.canonical_request_hash(),
        response_record_type: record_type.into(),
        canonical_response_payload_bytes: payload,
        server_instance_id: v.server_instance_id,
        restore_epoch: v.restore_epoch,
        committed_at_ms,
        receipt_id: random::<16>()?,
    }
    .encode())
}

/// Writes the committed ledger row, in the caller's transaction.
#[allow(clippy::too_many_arguments)]
pub(super) async fn store_response(
    conn: &mut SqliteConnection,
    v: &Verified,
    s: &Session,
    outer: &IdempotentMutationRequestV2,
    exact_request: &[u8],
    record_type: &str,
    response: &[u8],
    retained_until: u64,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO v2_idempotency
             (server_instance_id, tenant_id, actor_device_id, operation_scope, idempotency_key,
              operation_kind, canonical_request_hash, exact_request_bytes,
              exact_request_bytes_sha256, status, response_record_type, exact_response_bytes,
              exact_response_bytes_sha256, retained_until)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'succeeded', ?, ?, ?, ?)",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(s.tenant_id.as_slice())
    .bind(s.device_id.as_slice())
    .bind(outer.operation_kind.scope())
    .bind(outer.idempotency_key.as_slice())
    .bind(outer.operation_kind.as_str())
    .bind(outer.canonical_request_hash().as_slice())
    .bind(exact_request)
    .bind(sha256(exact_request).as_slice())
    .bind(record_type)
    .bind(response)
    .bind(sha256(response).as_slice())
    .bind(int(retained_until)?)
    .execute(&mut *conn)
    .await?;
    Ok(())
}
