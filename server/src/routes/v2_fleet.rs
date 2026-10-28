//! ADR 0002 D-9 fleet key-generation lifecycle: `FLEET_GENERATION_CREATE`
//! (`POST /v2/fleets/{fleet_id}/key-generations`) and `FLEET_GRANT_CREATE`
//! (`POST /v2/fleets/{fleet_id}/key-generations/{generation}/grants`).
//!
//! Both bodies are exact `IdempotentMutationRequestV2` maps. One
//! `BEGIN IMMEDIATE` checks the actor (an ACTIVE root custodian holding the
//! D-2 capability for the fleet), the live state the payload names, and for a
//! grant the embedded container, signed by the actor; then it writes the row,
//! the exact stored response and the audit row together. A retry with the same
//! bytes by the same actor gets the stored response back. Acknowledgement and
//! activation come with the next routes.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use sqlx::{Row, SqliteConnection};

use shared::approval_receipt::{
    AUTHORIZATION_REPLAY_RETENTION_MS, MAX_FLEET_DEVICE_GRANT_TTL_MS,
    MAX_FLEET_RECOVERY_GRANT_TTL_MS, MAX_FLEET_ROTATION_GRANT_TTL_MS,
};
use shared::authz_record::{
    AuthorizationRecord, Capability, CommonFields, Payload, VerifiedRecord,
    DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE, DOMAIN_FLEET_KEY_GRANT_RECOVERY,
    DOMAIN_FLEET_KEY_GRANT_ROTATION,
};
use shared::fleet_lifecycle::{
    FleetGenerationTerms, FleetGrantRevokeV2, FleetGrantRevokedV2, FleetGrantTarget,
    FleetGrantVariant, FleetKeyGenerationActivateV2, FleetKeyGenerationActivatedV2,
    FleetKeyGenerationCreateV2, FleetKeyGenerationCreatedV2, FleetKeyGrantAckV2,
    FleetKeyGrantAckedV2, FleetKeyGrantCreateV2, FleetKeyGrantCreatedV2,
    RECORD_TYPE_FLEET_GENERATION_ACTIVATED, RECORD_TYPE_FLEET_GENERATION_CREATED,
    RECORD_TYPE_FLEET_GRANT_ACKED, RECORD_TYPE_FLEET_GRANT_CREATED,
    RECORD_TYPE_FLEET_GRANT_REVOKED,
};
use shared::mutation::{
    fleet_device_grant_set_hash, FleetDeviceGrantDescriptorV2, IdempotentMutationRequestV2,
    OperationKind, RootGenerationState, RootGrantState,
};

use super::v2_approval::{cbor, coded, column_mismatch, int};
use super::v2_auth::{audit, blob, reload_session, unhex, verified, Principal, Session};
use super::v2_capability::stored_row_matches;
use super::v2_root::{
    insert_row, ledger_row, mismatch, record_error, row_holds, same_request, stale, store_response,
    stored_payload, stored_response, Col,
};
use super::v2_root_grants::{at, is_active_custodian, outer_request};
use crate::error::AppError;
use crate::identity::Verified;
use crate::state::AppState;
use crate::util::{now_ms, now_rfc3339};

fn fleet_path(fleet: &str) -> Result<[u8; 16], AppError> {
    unhex::<16>(fleet).ok_or_else(|| AppError::BadRequest("fleet id must be 32 hex digits".into()))
}

fn generation_path(generation: &str) -> Result<u64, AppError> {
    // Canonical decimal only, so one generation has exactly one path.
    generation
        .parse::<u64>()
        .ok()
        .filter(|g| g.to_string() == generation)
        .ok_or_else(|| AppError::BadRequest("generation must be a decimal integer".into()))
}

fn conflict(code: &'static str, msg: &str) -> AppError {
    coded(StatusCode::CONFLICT, code, msg)
}

fn response_mismatch() -> AppError {
    coded(
        StatusCode::UNPROCESSABLE_ENTITY,
        "MUTATION_RESPONSE_MISMATCH",
        "the stored response does not match what it created",
    )
}

/// The session's device is an ACTIVE root custodian and holds a live,
/// device-scoped `capability` grant covering `fleet` (ADR 0002 D-2). Every
/// candidate grant row must match its own container; a broken one refuses the
/// whole check rather than being skipped.
pub(crate) async fn holds_fleet_capability(
    conn: &mut SqliteConnection,
    v: &Verified,
    s: &Session,
    fleet: &[u8; 16],
    capability: Capability,
    now: i64,
) -> Result<bool, AppError> {
    holds_capability(conn, v, s, Some(fleet), capability, now).await
}

/// The same for a scope that is the tenant (`fleet` is `None`), which only a
/// tenant-scoped grant covers, or one fleet.
pub(crate) async fn holds_capability(
    conn: &mut SqliteConnection,
    v: &Verified,
    s: &Session,
    fleet: Option<&[u8; 16]>,
    capability: Capability,
    now: i64,
) -> Result<bool, AppError> {
    if !is_active_custodian(conn, v, s, now).await? {
        return Ok(false);
    }
    let replays: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT replay_id FROM v2_capability_grants
          WHERE server_instance_id = ? AND tenant_id = ? AND subject_kind = 'device'
            AND subject_device_id = ? AND subject_signing_key_id = ? AND capability = ?
            AND (scope_kind = 'tenant' OR (scope_kind = 'fleet' AND scope_id = ?))
            AND revoked_at IS NULL AND not_before_ms <= ? AND ? < not_after_ms",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(s.tenant_id.as_slice())
    .bind(s.device_id.as_slice())
    .bind(s.signing_key_id.as_slice())
    .bind(capability.as_str())
    .bind(fleet.map(|f| f.as_slice()))
    .bind(now)
    .bind(now)
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

/// The tenant's ACTIVE root generation and its key, if the pointer names this
/// instance's ACTIVE row (ADR 0001 L419-L423).
pub(crate) async fn active_root(
    conn: &mut SqliteConnection,
    v: &Verified,
    tenant: &[u8; 16],
) -> Result<Option<(u64, [u8; 32])>, AppError> {
    let row = sqlx::query(
        "SELECT g.generation, g.root_key_id FROM v2_tenants t
           JOIN v2_root_key_generations g
             ON g.tenant_id = t.id AND g.generation = t.active_root_generation
          WHERE t.id = ? AND g.server_instance_id = ? AND g.state = 'ACTIVE'",
    )
    .bind(tenant.as_slice())
    .bind(v.server_instance_id.as_slice())
    .fetch_optional(&mut *conn)
    .await?;
    let Some(row) = row else { return Ok(None) };
    let generation = u64::try_from(row.get::<i64, _>("generation"))
        .map_err(|_| column_mismatch("a stored generation is negative"))?;
    Ok(Some((generation, blob::<32>(&row, "root_key_id")?)))
}

async fn fleet_is_active(
    conn: &mut SqliteConnection,
    tenant: &[u8; 16],
    fleet: &[u8; 16],
) -> Result<bool, AppError> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM v2_fleets
                         WHERE tenant_id = ? AND id = ? AND status = 'active')",
    )
    .bind(tenant.as_slice())
    .bind(fleet.as_slice())
    .fetch_one(&mut *conn)
    .await?)
}

/// A fleet generation row as D-9 reads it.
struct GenerationRow {
    fkek_key_id: [u8; 32],
    state: String,
    required_device_grant_count: Option<i64>,
    required_grant_set_hash: Option<Vec<u8>>,
    recovery_grant_hash: Option<Vec<u8>>,
    previous_fkek_key_id: Option<Vec<u8>>,
    rotation_grant_hash: Option<Vec<u8>>,
}

impl GenerationRow {
    /// The row was created with exactly `t`.
    fn holds_terms(&self, t: &FleetGenerationTerms) -> bool {
        let rotation = t.rotation.as_ref();
        self.fkek_key_id == t.generation.fkek_key_id
            && self.required_device_grant_count == Some(i64::from(t.required_device_grant_count))
            && self.required_grant_set_hash.as_deref()
                == Some(&t.required_device_grant_set_hash[..])
            && self.recovery_grant_hash.as_deref()
                == Some(&t.recovery_grant_signed_container_hash[..])
            && self.previous_fkek_key_id.as_deref() == rotation.map(|r| &r.previous_fkek_key_id[..])
            && self.rotation_grant_hash.as_deref()
                == rotation.map(|r| &r.rotation_grant_signed_container_hash[..])
    }
}

/// The session's device holds `generation` of `fleet`: an acknowledged, live
/// device grant of it names the device under its current keys (D-2).
async fn holds_generation(
    conn: &mut SqliteConnection,
    v: &Verified,
    s: &Session,
    fleet: &[u8; 16],
    generation: u64,
    now: i64,
) -> Result<bool, AppError> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM v2_fleet_device_hpke_grants
                         WHERE server_instance_id = ? AND tenant_id = ? AND fleet_id = ?
                           AND generation = ? AND subject_device_id = ?
                           AND subject_signing_key_id = ? AND recipient_hpke_key_id = ?
                           AND acked_at IS NOT NULL AND revoked_at IS NULL
                           AND not_before_ms <= ? AND ? < not_after_ms)",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(s.tenant_id.as_slice())
    .bind(fleet.as_slice())
    .bind(int(generation)?)
    .bind(s.device_id.as_slice())
    .bind(s.signing_key_id.as_slice())
    .bind(s.hpke_key_id.as_slice())
    .bind(now)
    .bind(now)
    .fetch_one(&mut *conn)
    .await?)
}

/// Whether this device filed the `FLEET_GENERATION_CREATE` of `fkek_key_id`:
/// its audit event names the key, which is unique within the tenant.
async fn created_generation(
    conn: &mut SqliteConnection,
    s: &Session,
    fkek_key_id: &[u8; 32],
) -> Result<bool, AppError> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM v2_audit_events
                         WHERE tenant_id = ? AND actor_device_id = ?
                           AND action = 'fleet.key_generation.create'
                           AND target_type = 'fleet_key_generation' AND target_id = ?
                           AND outcome = 'success')",
    )
    .bind(s.tenant_id.as_slice())
    .bind(s.device_id.as_slice())
    .bind(fkek_key_id.as_slice())
    .fetch_one(&mut *conn)
    .await?)
}

/// Whether any grant of `generation` was ever filed for this device.
async fn has_grant(
    conn: &mut SqliteConnection,
    v: &Verified,
    s: &Session,
    fleet: &[u8; 16],
    generation: u64,
) -> Result<bool, AppError> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM v2_fleet_device_hpke_grants
                         WHERE server_instance_id = ? AND tenant_id = ? AND fleet_id = ?
                           AND generation = ? AND subject_device_id = ?)",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(s.tenant_id.as_slice())
    .bind(fleet.as_slice())
    .bind(int(generation)?)
    .bind(s.device_id.as_slice())
    .fetch_one(&mut *conn)
    .await?)
}

async fn generation_row(
    conn: &mut SqliteConnection,
    v: &Verified,
    tenant: &[u8; 16],
    fleet: &[u8; 16],
    generation: u64,
) -> Result<Option<GenerationRow>, AppError> {
    let row = sqlx::query(
        "SELECT fkek_key_id, state, required_device_grant_count, required_grant_set_hash,
                recovery_grant_hash, previous_fkek_key_id, rotation_grant_hash
           FROM v2_fleet_key_generations
          WHERE server_instance_id = ? AND tenant_id = ? AND fleet_id = ? AND generation = ?",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(tenant.as_slice())
    .bind(fleet.as_slice())
    .bind(int(generation)?)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(row) = row else { return Ok(None) };
    Ok(Some(GenerationRow {
        fkek_key_id: blob::<32>(&row, "fkek_key_id")?,
        state: row.get("state"),
        required_device_grant_count: row.get("required_device_grant_count"),
        required_grant_set_hash: row.get("required_grant_set_hash"),
        recovery_grant_hash: row.get("recovery_grant_hash"),
        previous_fkek_key_id: row.get("previous_fkek_key_id"),
        rotation_grant_hash: row.get("rotation_grant_hash"),
    }))
}

// ------------------------------------------------- FLEET_GENERATION_CREATE ---

pub async fn create_fleet_generation(
    State(app): State<AppState>,
    who: Principal,
    Path(fleet): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let v = verified(&app)?;
    // A ticket proves only a password; custody needs a device session.
    let Principal::Session(presented) = who else {
        return Err(AppError::Forbidden);
    };
    let fleet = fleet_path(&fleet)?;
    let outer = outer_request(v, &headers, &body, OperationKind::FleetGenerationCreate)?;
    let create =
        FleetKeyGenerationCreateV2::parse(&outer.canonical_payload_bytes).map_err(record_error)?;
    let t = &create.terms;
    let g = &t.generation;
    if g.fleet_id != fleet {
        return Err(column_mismatch(
            "the path names another fleet than the request",
        ));
    }
    if g.server_instance_id != v.server_instance_id {
        return Err(AppError::Forbidden);
    }
    if g.restore_epoch != v.restore_epoch {
        return Err(stale());
    }

    let mut tx = app.db.begin_with("BEGIN IMMEDIATE").await?;
    let now = now_ms();
    let s = reload_session(&mut tx, &presented, v, now)
        .await?
        .ok_or(AppError::Unauthorized)?;
    if s.tenant_id != g.tenant_id {
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
            stored_payload(&row, &outer, RECORD_TYPE_FLEET_GENERATION_CREATED, v)
                .ok_or_else(response_mismatch)?;
        let created =
            FleetKeyGenerationCreatedV2::parse(&payload).map_err(|_| response_mismatch())?;
        let still = generation_row(&mut tx, v, &s.tenant_id, &fleet, g.generation)
            .await?
            .is_some_and(|r| r.holds_terms(t));
        if created.create != create || !still {
            return Err(response_mismatch());
        }
        tx.commit().await?;
        return Ok(cbor(StatusCode::CREATED, response));
    }

    // D-9: `fleet.manage` bootstraps, `key.rotate` rotates.
    let capability = match t.rotation {
        None => Capability::FleetManage,
        Some(_) => Capability::KeyRotate,
    };
    if !holds_fleet_capability(&mut tx, v, &s, &fleet, capability, now).await? {
        return Err(AppError::Forbidden);
    }
    if !fleet_is_active(&mut tx, &s.tenant_id, &fleet).await? {
        return Err(coded(
            StatusCode::NOT_FOUND,
            "RESOURCE_NOT_FOUND",
            "no such active fleet in this tenant",
        ));
    }
    // The recovery grant is wrapped under the ACTIVE root.
    if active_root(&mut tx, v, &s.tenant_id).await?.map(|r| r.0) != Some(create.root_generation) {
        return Err(conflict(
            "ROOT_GENERATION_NOT_ACTIVE",
            "root_generation is not the tenant's ACTIVE root generation",
        ));
    }
    match &t.rotation {
        None => {
            // Bootstrap iff the fleet has no generation, on any instance.
            let any: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM v2_fleet_key_generations
                                 WHERE tenant_id = ? AND fleet_id = ?)",
            )
            .bind(s.tenant_id.as_slice())
            .bind(fleet.as_slice())
            .fetch_one(&mut *tx)
            .await?;
            if any {
                return Err(conflict(
                    "FLEET_GENERATION_EXISTS",
                    "this fleet already has a key generation",
                ));
            }
        }
        Some(r) => {
            let previous =
                generation_row(&mut tx, v, &s.tenant_id, &fleet, r.previous_generation).await?;
            if !previous
                .is_some_and(|p| p.state == "ACTIVE" && p.fkek_key_id == r.previous_fkek_key_id)
            {
                return Err(conflict(
                    "FLEET_GENERATION_NOT_ACTIVE",
                    "the previous generation is not this fleet's ACTIVE one under that key",
                ));
            }
            if generation_row(&mut tx, v, &s.tenant_id, &fleet, g.generation)
                .await?
                .is_some()
            {
                return Err(conflict(
                    "FLEET_GENERATION_EXISTS",
                    "the target generation already exists",
                ));
            }
        }
    }
    // A fleet key belongs to one generation (0007).
    let reused: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM v2_fleet_key_generations
                         WHERE tenant_id = ? AND fkek_key_id = ?)",
    )
    .bind(s.tenant_id.as_slice())
    .bind(g.fkek_key_id.as_slice())
    .fetch_one(&mut *tx)
    .await?;
    if reused {
        return Err(conflict(
            "FLEET_KEY_REUSED",
            "this fleet key already belongs to a generation",
        ));
    }

    let created_at = now_rfc3339();
    let rotation = t.rotation.as_ref();
    sqlx::query(
        "INSERT INTO v2_fleet_key_generations
             (server_instance_id, tenant_id, fleet_id, generation, fkek_key_id, root_generation,
              state, created_at, required_device_grant_count, required_grant_set_hash,
              recovery_grant_hash, previous_fkek_key_id, rotation_grant_hash)
         VALUES (?, ?, ?, ?, ?, ?, 'PREPARING', ?, ?, ?, ?, ?, ?)",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(s.tenant_id.as_slice())
    .bind(fleet.as_slice())
    .bind(int(g.generation)?)
    .bind(g.fkek_key_id.as_slice())
    .bind(int(create.root_generation)?)
    .bind(&created_at)
    .bind(i64::from(t.required_device_grant_count))
    .bind(t.required_device_grant_set_hash.as_slice())
    .bind(t.recovery_grant_signed_container_hash.as_slice())
    .bind(rotation.map(|r| r.previous_fkek_key_id.to_vec()))
    .bind(rotation.map(|r| r.rotation_grant_signed_container_hash.to_vec()))
    .execute(&mut *tx)
    .await?;

    let committed_at_ms = u64::try_from(now).unwrap_or_default();
    let created = FleetKeyGenerationCreatedV2 {
        create: create.clone(),
        created_at_ms: committed_at_ms,
    };
    let response = stored_response(
        &outer,
        RECORD_TYPE_FLEET_GENERATION_CREATED,
        created.encode(),
        v,
        committed_at_ms,
    )?;
    let retained_until = committed_at_ms
        .checked_add(AUTHORIZATION_REPLAY_RETENTION_MS)
        .ok_or(AppError::Forbidden)?;
    store_response(
        &mut tx,
        v,
        &s,
        &outer,
        &body,
        RECORD_TYPE_FLEET_GENERATION_CREATED,
        &response,
        retained_until,
    )
    .await?;
    audit(
        &mut tx,
        &s.tenant_id,
        &s.account_id,
        &s.device_id,
        "fleet.key_generation.create",
        "fleet_key_generation",
        &g.fkek_key_id,
    )
    .await?;
    tx.commit().await?;
    Ok(cbor(StatusCode::CREATED, response))
}

// ------------------------------------------------------ FLEET_GRANT_CREATE ---

const GRANT_TABLES: [&str; 3] = [
    "v2_fleet_device_hpke_grants",
    "v2_fleet_recovery_grants",
    "v2_fleet_rotation_grants",
];

fn table_of(variant: FleetGrantVariant) -> &'static str {
    match variant {
        FleetGrantVariant::DeviceHpke => GRANT_TABLES[0],
        FleetGrantVariant::Recovery => GRANT_TABLES[1],
        FleetGrantVariant::Rotation => GRANT_TABLES[2],
    }
}

/// The columns every fleet grant table shares, from the verified record.
fn common_columns(
    c: &CommonFields,
    record: &AuthorizationRecord,
    domain: &'static str,
    variant: FleetGrantVariant,
    capability: Capability,
    fleet: ([u8; 16], [u8; 32], u64),
) -> Result<Vec<(&'static str, Col)>, AppError> {
    let b = |bytes: &[u8]| Col::Blob(bytes.to_vec());
    let (suite, version) = record.signature_suite();
    Ok(vec![
        ("server_instance_id", b(&c.server_instance_id)),
        ("tenant_id", b(&c.tenant_id)),
        ("replay_id", b(&c.replay_id)),
        ("payload_domain", Col::Text(domain)),
        ("payload_version", Col::Int(2)),
        ("grant_variant", Col::Text(variant.as_str())),
        ("fleet_id", b(&fleet.0)),
        ("fkek_key_id", b(&fleet.1)),
        ("generation", Col::Int(int(fleet.2)?)),
        ("grant_capability", Col::Text(capability.as_str())),
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

/// What the embedded record contributes: its common fields, its fleet
/// triple, its row columns, the D-6 bound of its kind and what the created
/// response names.
struct Filing {
    common: CommonFields,
    fleet: ([u8; 16], [u8; 32], u64),
    cols: Vec<(&'static str, Col)>,
    max_ttl_ms: u64,
    target: FleetGrantTarget,
}

fn filing(payload: &Payload, record: &AuthorizationRecord) -> Result<Filing, AppError> {
    let b = |bytes: &[u8]| Col::Blob(bytes.to_vec());
    Ok(match payload {
        Payload::DeviceHpkeGrant(p) => {
            let fleet = (p.fleet_id, p.fkek_key_id, p.generation);
            let mut cols = common_columns(
                &p.common,
                record,
                DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE,
                FleetGrantVariant::DeviceHpke,
                Capability::FleetKeyReceive,
                fleet,
            )?;
            cols.extend([
                ("subject_account_id", b(&p.subject_account_id)),
                ("subject_device_id", b(&p.subject_device_id)),
                ("subject_signing_key_id", b(&p.subject_signing_key_id)),
                ("recipient_hpke_key_id", b(&p.recipient_hpke_key_id)),
                ("hpke_suite_id", Col::Int(1)),
                ("hpke_info_bytes", Col::Blob(p.hpke_info_bytes())),
                ("hpke_encapped_key_bytes", b(&p.hpke_encapped_key_bytes)),
                (
                    "hpke_wrapped_fleet_key_bytes",
                    b(&p.hpke_wrapped_fleet_key_bytes),
                ),
            ]);
            Filing {
                common: p.common.clone(),
                fleet,
                cols,
                max_ttl_ms: MAX_FLEET_DEVICE_GRANT_TTL_MS,
                target: FleetGrantTarget::Device {
                    subject_device_id: p.subject_device_id,
                },
            }
        }
        Payload::RecoveryGrant(p) => {
            let fleet = (p.fleet_id, p.fkek_key_id, p.generation);
            let mut cols = common_columns(
                &p.common,
                record,
                DOMAIN_FLEET_KEY_GRANT_RECOVERY,
                FleetGrantVariant::Recovery,
                Capability::FleetKeyRecover,
                fleet,
            )?;
            cols.extend([
                ("recipient_root_key_id", b(&p.recipient_root_key_id)),
                (
                    "recipient_root_generation",
                    Col::Int(int(p.recipient_root_generation)?),
                ),
                ("root_wrap_suite_id", Col::Int(1)),
                ("root_wrap_nonce_bytes", b(&p.root_wrap_nonce_bytes)),
                (
                    "root_wrap_context_bytes",
                    Col::Blob(p.root_wrap_context_bytes()),
                ),
                ("wrapped_fleet_key_bytes", b(&p.wrapped_fleet_key_bytes)),
            ]);
            Filing {
                common: p.common.clone(),
                fleet,
                cols,
                max_ttl_ms: MAX_FLEET_RECOVERY_GRANT_TTL_MS,
                target: FleetGrantTarget::Root {
                    recipient_root_generation: p.recipient_root_generation,
                },
            }
        }
        Payload::RotationGrant(p) => {
            let fleet = (p.fleet_id, p.fkek_key_id, p.generation);
            let mut cols = common_columns(
                &p.common,
                record,
                DOMAIN_FLEET_KEY_GRANT_ROTATION,
                FleetGrantVariant::Rotation,
                Capability::KeyRotate,
                fleet,
            )?;
            cols.extend([
                ("previous_fkek_key_id", b(&p.previous_fkek_key_id)),
                ("previous_generation", Col::Int(int(p.previous_generation)?)),
                (
                    "required_device_grant_count",
                    Col::Int(i64::from(p.required_device_grant_count)),
                ),
                (
                    "required_device_grant_set_hash",
                    b(&p.required_device_grant_set_hash),
                ),
                (
                    "recovery_grant_signed_container_hash",
                    b(&p.recovery_grant_signed_container_hash),
                ),
                (
                    "activation_not_before_ms",
                    Col::Int(int(p.activation_not_before_ms)?),
                ),
            ]);
            Filing {
                common: p.common.clone(),
                fleet,
                cols,
                max_ttl_ms: MAX_FLEET_ROTATION_GRANT_TTL_MS,
                target: FleetGrantTarget::Rotation,
            }
        }
        _ => {
            return Err(column_mismatch(
                "the embedded record is not a fleet key grant",
            ))
        }
    })
}

fn variant_of(payload: &Payload) -> Option<FleetGrantVariant> {
    match payload {
        Payload::DeviceHpkeGrant(_) => Some(FleetGrantVariant::DeviceHpke),
        Payload::RecoveryGrant(_) => Some(FleetGrantVariant::Recovery),
        Payload::RotationGrant(_) => Some(FleetGrantVariant::Rotation),
        _ => None,
    }
}

pub async fn file_fleet_grant(
    State(app): State<AppState>,
    who: Principal,
    Path((fleet, generation)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let v = verified(&app)?;
    let Principal::Session(presented) = who else {
        return Err(AppError::Forbidden);
    };
    let fleet = fleet_path(&fleet)?;
    let generation = generation_path(&generation)?;
    let outer = outer_request(v, &headers, &body, OperationKind::FleetGrantCreate)?;
    let create =
        FleetKeyGrantCreateV2::parse(&outer.canonical_payload_bytes).map_err(record_error)?;
    let r = &create.grant;
    let g = &r.generation;
    if g.fleet_id != fleet || g.generation != generation {
        return Err(column_mismatch(
            "the path names another generation than the request",
        ));
    }
    if g.server_instance_id != v.server_instance_id {
        return Err(AppError::Forbidden);
    }
    if g.restore_epoch != v.restore_epoch {
        return Err(stale());
    }

    let mut tx = app.db.begin_with("BEGIN IMMEDIATE").await?;
    let now = now_ms();
    let s = reload_session(&mut tx, &presented, v, now)
        .await?
        .ok_or(AppError::Unauthorized)?;
    if s.tenant_id != g.tenant_id {
        return Err(AppError::Forbidden);
    }
    let table = table_of(r.grant_variant);

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
        let (payload, response) = stored_payload(&row, &outer, RECORD_TYPE_FLEET_GRANT_CREATED, v)
            .ok_or_else(response_mismatch)?;
        let created = FleetKeyGrantCreatedV2::parse(&payload).map_err(|_| response_mismatch())?;
        let filed: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS (SELECT 1 FROM {table}
                             WHERE server_instance_id = ? AND tenant_id = ? AND replay_id = ?
                               AND signed_container_hash = ?
                               AND exact_signed_container_bytes_sha256 = ?)"
        ))
        .bind(v.server_instance_id.as_slice())
        .bind(s.tenant_id.as_slice())
        .bind(r.replay_id.as_slice())
        .bind(r.signed_container_hash.as_slice())
        .bind(r.exact_signed_grant_container_bytes_sha256.as_slice())
        .fetch_one(&mut *tx)
        .await?;
        if created.grant != *r || !filed {
            return Err(response_mismatch());
        }
        tx.commit().await?;
        return Ok(cbor(StatusCode::CREATED, response));
    }

    // The embedded container: signed by the actor, exactly the named variant,
    // with the request's common and replay fields.
    let parsed = AuthorizationRecord::parse(&create.exact_signed_grant_container_bytes)
        .map_err(record_error)?;
    if *parsed.signed_container_hash() != r.signed_container_hash {
        return Err(column_mismatch(
            "the embedded container hash differs from the request",
        ));
    }
    if *parsed.issuer_signing_key_id() != s.signing_key_id {
        return Err(coded(
            StatusCode::UNPROCESSABLE_ENTITY,
            "KEY_SUBSTITUTION_DETECTED",
            "the grant is not signed by the session's device",
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
    let verified_record = parsed.verify_signature(&issuer).map_err(record_error)?;
    let payload = verified_record.payload().clone();
    let record = verified_record.record();
    if variant_of(&payload) != Some(r.grant_variant) {
        return Err(column_mismatch(
            "the embedded record is not the named grant variant",
        ));
    }
    let f = filing(&payload, record)?;
    let c = &f.common;
    if (
        c.tenant_id,
        c.server_instance_id,
        c.restore_epoch,
        c.replay_id,
    ) != (
        g.tenant_id,
        g.server_instance_id,
        g.restore_epoch,
        r.replay_id,
    ) || f.fleet != (g.fleet_id, g.fkek_key_id, g.generation)
    {
        return Err(column_mismatch(
            "the embedded grant names another context than the request",
        ));
    }
    if int(c.not_before_ms)? > now
        || now >= int(c.not_after_ms)?
        || c.not_after_ms - c.not_before_ms > f.max_ttl_ms
    {
        return Err(AppError::Forbidden);
    }

    let gen = generation_row(&mut tx, v, &s.tenant_id, &fleet, generation)
        .await?
        .filter(|row| row.fkek_key_id == g.fkek_key_id)
        .ok_or_else(|| {
            coded(
                StatusCode::NOT_FOUND,
                "RESOURCE_NOT_FOUND",
                "no such fleet key generation under this key",
            )
        })?;
    // D-2 issuers and D-9 generation states, per variant.
    match &payload {
        Payload::DeviceHpkeGrant(p) => {
            // The issuer holds the generation it hands out (D-2), except for
            // the device that created it filing its own first grant of it,
            // which it acknowledges afterwards. A revoked or expired grant is
            // not replaced this way.
            let own = p.subject_device_id == s.device_id
                && p.subject_signing_key_id == s.signing_key_id
                && p.recipient_hpke_key_id == s.hpke_key_id
                && created_generation(&mut tx, &s, &gen.fkek_key_id).await?
                && !has_grant(&mut tx, v, &s, &fleet, generation).await?;
            if !holds_fleet_capability(&mut tx, v, &s, &fleet, Capability::FleetManage, now).await?
                || !(own || holds_generation(&mut tx, v, &s, &fleet, generation, now).await?)
            {
                return Err(AppError::Forbidden);
            }
            if !fleet_is_active(&mut tx, &s.tenant_id, &fleet).await? {
                return Err(conflict(
                    "FLEET_ARCHIVED",
                    "an archived fleet takes no new member",
                ));
            }
            if gen.state != "PREPARING" && gen.state != "ACTIVE" {
                return Err(conflict(
                    "FLEET_GENERATION_RETIRED",
                    "a device grant needs a PREPARING or ACTIVE generation",
                ));
            }
            let subject_live: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM v2_devices
                                 WHERE tenant_id = ? AND id = ? AND account_id = ?
                                   AND status = 'active' AND signing_key_id = ? AND hpke_key_id = ?)",
            )
            .bind(s.tenant_id.as_slice())
            .bind(p.subject_device_id.as_slice())
            .bind(p.subject_account_id.as_slice())
            .bind(p.subject_signing_key_id.as_slice())
            .bind(p.recipient_hpke_key_id.as_slice())
            .fetch_one(&mut *tx)
            .await?;
            if !subject_live {
                return Err(column_mismatch(
                    "the grant names no active device under these keys",
                ));
            }
            // D-2 subject eligibility: an active account and a live approval
            // of exactly these keys, tenant-wide or for this fleet.
            // shortcut: fleet membership is not checked, there is no member
            // table yet; add it with the L1126 membership routes.
            let eligible: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM v2_accounts
                                 WHERE tenant_id = ? AND id = ? AND status = 'active')
                    AND EXISTS (SELECT 1 FROM v2_device_approvals
                                 WHERE server_instance_id = ? AND tenant_id = ?
                                   AND subject_account_id = ? AND subject_device_id = ?
                                   AND subject_signing_key_id = ? AND subject_hpke_key_id = ?
                                   AND revoked_at IS NULL
                                   AND not_before_ms <= ? AND ? < not_after_ms
                                   AND (approval_scope_kind = 'tenant'
                                        OR (approval_scope_kind = 'fleet'
                                            AND approval_scope_id = ?)))",
            )
            .bind(s.tenant_id.as_slice())
            .bind(p.subject_account_id.as_slice())
            .bind(v.server_instance_id.as_slice())
            .bind(s.tenant_id.as_slice())
            .bind(p.subject_account_id.as_slice())
            .bind(p.subject_device_id.as_slice())
            .bind(p.subject_signing_key_id.as_slice())
            .bind(p.recipient_hpke_key_id.as_slice())
            .bind(now)
            .bind(now)
            .bind(fleet.as_slice())
            .fetch_one(&mut *tx)
            .await?;
            if !eligible {
                return Err(conflict(
                    "SUBJECT_NOT_ELIGIBLE",
                    "the subject has no active account or live approval for this fleet",
                ));
            }
        }
        Payload::RecoveryGrant(p) => {
            // shortcut: only the ACTIVE root is a recipient; the D-5 rewrap
            // under a PREPARING root comes with root rotation.
            if !is_active_custodian(&mut tx, v, &s, now).await?
                || active_root(&mut tx, v, &s.tenant_id).await?
                    != Some((p.recipient_root_generation, p.recipient_root_key_id))
            {
                return Err(AppError::Forbidden);
            }
        }
        Payload::RotationGrant(p) => {
            // The issuer holds the generation it rotates away from (D-2).
            if !holds_fleet_capability(&mut tx, v, &s, &fleet, Capability::KeyRotate, now).await?
                || !holds_generation(&mut tx, v, &s, &fleet, p.previous_generation, now).await?
            {
                return Err(AppError::Forbidden);
            }
            if !fleet_is_active(&mut tx, &s.tenant_id, &fleet).await? {
                return Err(conflict(
                    "FLEET_ARCHIVED",
                    "an archived fleet is not rotated",
                ));
            }
            let matches = gen.state == "PREPARING"
                && gen.previous_fkek_key_id.as_deref() == Some(&p.previous_fkek_key_id[..])
                && gen.required_device_grant_count
                    == Some(i64::from(p.required_device_grant_count))
                && gen.required_grant_set_hash.as_deref()
                    == Some(&p.required_device_grant_set_hash[..])
                && gen.recovery_grant_hash.as_deref()
                    == Some(&p.recovery_grant_signed_container_hash[..])
                && gen.rotation_grant_hash.as_deref() == Some(&r.signed_container_hash[..]);
            if !matches {
                return Err(conflict(
                    "ROTATION_GRANT_MISMATCH",
                    "the rotation grant differs from the generation it targets",
                ));
            }
        }
        _ => unreachable!("variant_of checked the payload"),
    }
    // A replay ID is spent by any fleet grant ever filed under it.
    for t in GRANT_TABLES {
        let spent: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS (SELECT 1 FROM {t}
                             WHERE server_instance_id = ? AND tenant_id = ? AND replay_id = ?)"
        ))
        .bind(v.server_instance_id.as_slice())
        .bind(s.tenant_id.as_slice())
        .bind(r.replay_id.as_slice())
        .fetch_one(&mut *tx)
        .await?;
        if spent {
            return Err(conflict(
                "REPLAY_DETECTED",
                "this replay id is already spent by a fleet grant",
            ));
        }
    }

    insert_row(&mut tx, table, &f.cols, &now_rfc3339()).await?;
    let committed_at_ms = u64::try_from(now).unwrap_or_default();
    let created = FleetKeyGrantCreatedV2 {
        grant: *r,
        target: f.target,
        created_at_ms: committed_at_ms,
    };
    let response = stored_response(
        &outer,
        RECORD_TYPE_FLEET_GRANT_CREATED,
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
        &s,
        &outer,
        &body,
        RECORD_TYPE_FLEET_GRANT_CREATED,
        &response,
        retained_until,
    )
    .await?;
    audit(
        &mut tx,
        &s.tenant_id,
        &s.account_id,
        &s.device_id,
        "fleet.key_grant.create",
        "fleet_key_grant",
        &r.replay_id,
    )
    .await?;
    tx.commit().await?;
    Ok(cbor(StatusCode::CREATED, response))
}

// ------------------------------------------------------ stored fleet grants ---

fn integrity() -> AppError {
    column_mismatch("a stored fleet grant does not match its signed container")
}

/// A filed fleet grant whose row matched its verified container.
struct StoredFleetGrant {
    record: VerifiedRecord,
    payload: Payload,
    fleet: ([u8; 16], [u8; 32], u64),
    signed_container_hash: [u8; 32],
    exact_sha256: [u8; 32],
    acked: bool,
    revoked: bool,
}

/// The grant `replay` of `variant` on this instance, reparsed, verified under
/// its issuer's key and required to hold exactly the columns its container
/// determines; a row that disagrees refuses the request (422).
async fn load_fleet_grant(
    conn: &mut SqliteConnection,
    v: &Verified,
    tenant: &[u8; 16],
    variant: FleetGrantVariant,
    replay: &[u8; 16],
) -> Result<Option<StoredFleetGrant>, AppError> {
    let table = table_of(variant);
    let row = sqlx::query(&format!(
        "SELECT exact_signed_container_bytes, acked_at, revoked_at FROM {table}
          WHERE server_instance_id = ? AND tenant_id = ? AND replay_id = ?"
    ))
    .bind(v.server_instance_id.as_slice())
    .bind(tenant.as_slice())
    .bind(replay.as_slice())
    .fetch_optional(&mut *conn)
    .await?;
    let Some(row) = row else { return Ok(None) };
    let exact: Vec<u8> = row.get("exact_signed_container_bytes");
    let parsed = AuthorizationRecord::parse(&exact).map_err(|_| integrity())?;
    let issuer: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT signing_public_key FROM v2_devices WHERE tenant_id = ? AND signing_key_id = ?",
    )
    .bind(tenant.as_slice())
    .bind(parsed.issuer_signing_key_id().as_slice())
    .fetch_optional(&mut *conn)
    .await?;
    let issuer: [u8; 32] = issuer
        .and_then(|k| k.try_into().ok())
        .ok_or_else(integrity)?;
    let record = parsed.verify_signature(&issuer).map_err(|_| integrity())?;
    let payload = record.payload().clone();
    let f = filing(&payload, record.record())?;
    let c = &f.common;
    if variant_of(&payload) != Some(variant)
        || (&c.server_instance_id, &c.tenant_id, &c.replay_id)
            != (&v.server_instance_id, tenant, replay)
        || !row_holds(conn, table, &f.cols).await?
    {
        return Err(integrity());
    }
    Ok(Some(StoredFleetGrant {
        fleet: f.fleet,
        signed_container_hash: *record.record().signed_container_hash(),
        exact_sha256: *record.record().exact_signed_container_bytes_sha256(),
        acked: row.get::<Option<String>, _>("acked_at").is_some(),
        revoked: row.get::<Option<String>, _>("revoked_at").is_some(),
        payload,
        record,
    }))
}

fn common_of(payload: &Payload) -> &CommonFields {
    match payload {
        Payload::DeviceHpkeGrant(p) => &p.common,
        Payload::RecoveryGrant(p) => &p.common,
        Payload::RotationGrant(p) => &p.common,
        _ => unreachable!("load_fleet_grant holds only fleet grants"),
    }
}

/// The stored payload and response for this idempotency key, `None` when the
/// key is new, or a refusal when the key holds another request.
async fn replay_or_none(
    conn: &mut SqliteConnection,
    v: &Verified,
    s: &Session,
    outer: &IdempotentMutationRequestV2,
    body: &[u8],
    record_type: &str,
) -> Result<Option<(Vec<u8>, Vec<u8>)>, AppError> {
    let Some(row) = ledger_row(conn, v, s, outer.operation_kind, &outer.idempotency_key).await?
    else {
        return Ok(None);
    };
    if !same_request(
        &row,
        outer.operation_kind,
        &outer.canonical_request_hash(),
        body,
    )? {
        return Err(mismatch());
    }
    stored_payload(&row, outer, record_type, v)
        .map(Some)
        .ok_or_else(response_mismatch)
}

// ---------------------------------------------------------- FLEET_GRANT_ACK ---

/// `POST .../key-generations/{generation}/ack`: one grant per request (D-9).
/// The actor opened the grant and the FKEK it got re-derived `fkek_key_id`.
pub async fn ack_fleet_grant(
    State(app): State<AppState>,
    who: Principal,
    Path((fleet, generation)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let v = verified(&app)?;
    let Principal::Session(presented) = who else {
        return Err(AppError::Forbidden);
    };
    let fleet = fleet_path(&fleet)?;
    let generation = generation_path(&generation)?;
    let outer = outer_request(v, &headers, &body, OperationKind::FleetGrantAck)?;
    let ack = FleetKeyGrantAckV2::parse(&outer.canonical_payload_bytes).map_err(record_error)?;
    let r = &ack.grant;
    let g = &r.generation;
    if g.fleet_id != fleet || g.generation != generation {
        return Err(column_mismatch(
            "the path names another generation than the request",
        ));
    }
    if g.server_instance_id != v.server_instance_id {
        return Err(AppError::Forbidden);
    }
    if g.restore_epoch != v.restore_epoch {
        return Err(stale());
    }

    let mut tx = app.db.begin_with("BEGIN IMMEDIATE").await?;
    let now = now_ms();
    let s = reload_session(&mut tx, &presented, v, now)
        .await?
        .ok_or(AppError::Unauthorized)?;
    if s.tenant_id != g.tenant_id {
        return Err(AppError::Forbidden);
    }
    if let Some((payload, response)) =
        replay_or_none(&mut tx, v, &s, &outer, &body, RECORD_TYPE_FLEET_GRANT_ACKED).await?
    {
        let acked = FleetKeyGrantAckedV2::parse(&payload).map_err(|_| response_mismatch())?;
        let still = load_fleet_grant(&mut tx, v, &s.tenant_id, r.grant_variant, &r.replay_id)
            .await?
            .is_some_and(|stored| stored.acked);
        if acked.grant != *r || !still {
            return Err(response_mismatch());
        }
        tx.commit().await?;
        return Ok(cbor(StatusCode::CREATED, response));
    }

    let stored = load_fleet_grant(&mut tx, v, &s.tenant_id, r.grant_variant, &r.replay_id)
        .await?
        .ok_or_else(|| {
            coded(
                StatusCode::NOT_FOUND,
                "RESOURCE_NOT_FOUND",
                "no such fleet grant",
            )
        })?;
    let c = common_of(&stored.payload);
    let names_grant = stored.signed_container_hash == r.signed_container_hash
        && stored.exact_sha256 == r.exact_signed_grant_container_bytes_sha256
        && c.restore_epoch == g.restore_epoch;
    if !names_grant || stored.fleet != (g.fleet_id, g.fkek_key_id, g.generation) {
        return Err(column_mismatch("the acknowledgement names another grant"));
    }
    if stored.revoked || stored.acked {
        return Err(conflict(
            "FLEET_GRANT_NOT_PENDING",
            "this grant is revoked or already acknowledged",
        ));
    }
    if int(c.not_before_ms)? > now || now >= int(c.not_after_ms)? {
        return Err(AppError::Forbidden);
    }
    // D-9 ack actors.
    let actor_ok = match &stored.payload {
        Payload::DeviceHpkeGrant(p) => {
            p.subject_account_id == s.account_id
                && p.subject_device_id == s.device_id
                && p.subject_signing_key_id == s.signing_key_id
                && p.recipient_hpke_key_id == s.hpke_key_id
        }
        // shortcut: only a custodian of the ACTIVE recipient root acks; the
        // PREPARING-root case comes with root rotation (D-5).
        Payload::RecoveryGrant(p) => {
            is_active_custodian(&mut tx, v, &s, now).await?
                && active_root(&mut tx, v, &s.tenant_id).await?
                    == Some((p.recipient_root_generation, p.recipient_root_key_id))
        }
        Payload::RotationGrant(_) => {
            holds_fleet_capability(&mut tx, v, &s, &fleet, Capability::KeyRotate, now).await?
        }
        _ => unreachable!("load_fleet_grant holds only fleet grants"),
    };
    if !actor_ok {
        return Err(AppError::Forbidden);
    }
    let state = generation_row(&mut tx, v, &s.tenant_id, &fleet, generation)
        .await?
        .map(|row| row.state);
    let ackable = match r.grant_variant {
        // A recovery grant of any retained generation (D-9).
        FleetGrantVariant::Recovery => state.is_some(),
        FleetGrantVariant::DeviceHpke => {
            matches!(state.as_deref(), Some("PREPARING" | "ACTIVE"))
        }
        FleetGrantVariant::Rotation => state.as_deref() == Some("PREPARING"),
    };
    if !ackable {
        return Err(conflict(
            "FLEET_GENERATION_STATE",
            "the grant's generation does not take this acknowledgement",
        ));
    }

    sqlx::query(&format!(
        "UPDATE {} SET acked_at = ?
          WHERE server_instance_id = ? AND tenant_id = ? AND replay_id = ? AND acked_at IS NULL",
        table_of(r.grant_variant)
    ))
    .bind(at(now))
    .bind(v.server_instance_id.as_slice())
    .bind(s.tenant_id.as_slice())
    .bind(r.replay_id.as_slice())
    .execute(&mut *tx)
    .await?;
    let acked_at_ms = u64::try_from(now).unwrap_or_default();
    let payload = FleetKeyGrantAckedV2 {
        grant: *r,
        acked_at_ms,
    }
    .encode();
    let response = stored_response(
        &outer,
        RECORD_TYPE_FLEET_GRANT_ACKED,
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
        RECORD_TYPE_FLEET_GRANT_ACKED,
        &response,
        retained_until,
    )
    .await?;
    audit(
        &mut tx,
        &s.tenant_id,
        &s.account_id,
        &s.device_id,
        "fleet.key_grant.ack",
        "fleet_key_grant",
        &r.replay_id,
    )
    .await?;
    tx.commit().await?;
    Ok(cbor(StatusCode::CREATED, response))
}

// ------------------------------------------------ FLEET_GENERATION_ACTIVATE ---

/// The acknowledged, live grants of `variant` for one generation, each
/// reverified, with the container hash of each.
async fn live_acked_grants(
    conn: &mut SqliteConnection,
    v: &Verified,
    s: &Session,
    variant: FleetGrantVariant,
    fleet: &[u8; 16],
    generation: u64,
    now: i64,
) -> Result<Vec<StoredFleetGrant>, AppError> {
    let replays: Vec<Vec<u8>> = sqlx::query_scalar(&format!(
        "SELECT replay_id FROM {}
          WHERE server_instance_id = ? AND tenant_id = ? AND fleet_id = ? AND generation = ?
            AND acked_at IS NOT NULL AND revoked_at IS NULL",
        table_of(variant)
    ))
    .bind(v.server_instance_id.as_slice())
    .bind(s.tenant_id.as_slice())
    .bind(fleet.as_slice())
    .bind(int(generation)?)
    .fetch_all(&mut *conn)
    .await?;
    let mut out = Vec::with_capacity(replays.len());
    for replay in replays {
        let replay: [u8; 16] = replay.try_into().map_err(|_| integrity())?;
        let g = load_fleet_grant(conn, v, &s.tenant_id, variant, &replay)
            .await?
            .ok_or_else(integrity)?;
        let c = common_of(&g.payload);
        // A grant outside its window holds nothing now.
        if int(c.not_before_ms)? <= now && now < int(c.not_after_ms)? {
            out.push(g);
        }
    }
    Ok(out)
}

/// `POST .../key-generations/{generation}/activate`: PREPARING -> ACTIVE, and
/// the previous ACTIVE generation -> RETIRED, once the required device set,
/// the recovery grant and, for a rotation, the rotation grant are in (D-9).
pub async fn activate_fleet_generation(
    State(app): State<AppState>,
    who: Principal,
    Path((fleet, generation)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let v = verified(&app)?;
    let Principal::Session(presented) = who else {
        return Err(AppError::Forbidden);
    };
    let fleet = fleet_path(&fleet)?;
    let generation = generation_path(&generation)?;
    let outer = outer_request(v, &headers, &body, OperationKind::FleetGenerationActivate)?;
    let activate = FleetKeyGenerationActivateV2::parse(&outer.canonical_payload_bytes)
        .map_err(record_error)?;
    let t = &activate.terms;
    let g = &t.generation;
    if g.fleet_id != fleet || g.generation != generation {
        return Err(column_mismatch(
            "the path names another generation than the request",
        ));
    }
    if g.server_instance_id != v.server_instance_id {
        return Err(AppError::Forbidden);
    }
    if g.restore_epoch != v.restore_epoch {
        return Err(stale());
    }

    let mut tx = app.db.begin_with("BEGIN IMMEDIATE").await?;
    let now = now_ms();
    let s = reload_session(&mut tx, &presented, v, now)
        .await?
        .ok_or(AppError::Unauthorized)?;
    if s.tenant_id != g.tenant_id {
        return Err(AppError::Forbidden);
    }
    if let Some((payload, response)) = replay_or_none(
        &mut tx,
        v,
        &s,
        &outer,
        &body,
        RECORD_TYPE_FLEET_GENERATION_ACTIVATED,
    )
    .await?
    {
        let activated =
            FleetKeyGenerationActivatedV2::parse(&payload).map_err(|_| response_mismatch())?;
        let still = generation_row(&mut tx, v, &s.tenant_id, &fleet, generation)
            .await?
            .is_some_and(|row| row.state != "PREPARING" && row.fkek_key_id == g.fkek_key_id);
        if activated.terms != *t || !still {
            return Err(response_mismatch());
        }
        tx.commit().await?;
        return Ok(cbor(StatusCode::CREATED, response));
    }

    let capability = match t.rotation {
        None => Capability::FleetManage,
        Some(_) => Capability::KeyRotate,
    };
    if !holds_fleet_capability(&mut tx, v, &s, &fleet, capability, now).await? {
        return Err(AppError::Forbidden);
    }
    let row = generation_row(&mut tx, v, &s.tenant_id, &fleet, generation)
        .await?
        .ok_or_else(|| {
            coded(
                StatusCode::NOT_FOUND,
                "RESOURCE_NOT_FOUND",
                "no such fleet key generation",
            )
        })?;
    let rotation = t.rotation.as_ref();
    if !row.holds_terms(t) {
        return Err(conflict(
            "FLEET_GENERATION_MISMATCH",
            "the activation restates other terms than the generation was created with",
        ));
    }
    if row.state != "PREPARING" {
        return Err(conflict(
            "FLEET_GENERATION_STATE",
            "only a PREPARING generation activates",
        ));
    }
    if let Some(r) = rotation {
        let previous =
            generation_row(&mut tx, v, &s.tenant_id, &fleet, r.previous_generation).await?;
        if !previous.is_some_and(|p| p.state == "ACTIVE" && p.fkek_key_id == r.previous_fkek_key_id)
        {
            return Err(conflict(
                "FLEET_GENERATION_NOT_ACTIVE",
                "the previous generation is no longer ACTIVE under that key",
            ));
        }
    }

    // D-4: the acknowledged live device grants are exactly the required set.
    let devices = live_acked_grants(
        &mut tx,
        v,
        &s,
        FleetGrantVariant::DeviceHpke,
        &fleet,
        generation,
        now,
    )
    .await?;
    let hashes: Vec<[u8; 32]> = devices.iter().map(|d| d.signed_container_hash).collect();
    let recovery = live_acked_grants(
        &mut tx,
        v,
        &s,
        FleetGrantVariant::Recovery,
        &fleet,
        generation,
        now,
    )
    .await?;
    let rotations = live_acked_grants(
        &mut tx,
        v,
        &s,
        FleetGrantVariant::Rotation,
        &fleet,
        generation,
        now,
    )
    .await?;
    if hashes.len() != t.required_device_grant_count as usize
        || fleet_device_grant_set_hash(&hashes) != Some(t.required_device_grant_set_hash)
    {
        return Err(conflict(
            "FLEET_GRANTS_INCOMPLETE",
            "the acknowledged device grants are not the generation's required set",
        ));
    }
    if !recovery
        .iter()
        .any(|g| g.signed_container_hash == t.recovery_grant_signed_container_hash)
    {
        return Err(conflict(
            "FLEET_GRANTS_INCOMPLETE",
            "the generation's recovery grant is not acknowledged",
        ));
    }
    if let Some(r) = rotation {
        let due = rotations.iter().any(|g| {
            g.signed_container_hash == r.rotation_grant_signed_container_hash
                && matches!(&g.payload, Payload::RotationGrant(p)
                    if i64::try_from(p.activation_not_before_ms).is_ok_and(|nb| nb <= now))
        });
        if !due {
            return Err(conflict(
                "FLEET_GRANTS_INCOMPLETE",
                "the rotation grant is not acknowledged or not yet due",
            ));
        }
    }

    let stamp = at(now);
    if let Some(r) = rotation {
        // Retire first: at most one generation of a fleet is ACTIVE (0007).
        sqlx::query(
            "UPDATE v2_fleet_key_generations SET state = 'RETIRED', retired_at = ?
              WHERE server_instance_id = ? AND tenant_id = ? AND fleet_id = ? AND generation = ?
                AND state = 'ACTIVE'",
        )
        .bind(&stamp)
        .bind(v.server_instance_id.as_slice())
        .bind(s.tenant_id.as_slice())
        .bind(fleet.as_slice())
        .bind(int(r.previous_generation)?)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query(
        "UPDATE v2_fleet_key_generations SET state = 'ACTIVE', activated_at = ?
          WHERE server_instance_id = ? AND tenant_id = ? AND fleet_id = ? AND generation = ?
            AND state = 'PREPARING'",
    )
    .bind(&stamp)
    .bind(v.server_instance_id.as_slice())
    .bind(s.tenant_id.as_slice())
    .bind(fleet.as_slice())
    .bind(int(generation)?)
    .execute(&mut *tx)
    .await?;

    let activated_at_ms = u64::try_from(now).unwrap_or_default();
    let payload = FleetKeyGenerationActivatedV2 {
        terms: *t,
        activated_at_ms,
    }
    .encode();
    let response = stored_response(
        &outer,
        RECORD_TYPE_FLEET_GENERATION_ACTIVATED,
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
        RECORD_TYPE_FLEET_GENERATION_ACTIVATED,
        &response,
        retained_until,
    )
    .await?;
    audit(
        &mut tx,
        &s.tenant_id,
        &s.account_id,
        &s.device_id,
        "fleet.key_generation.activate",
        "fleet_key_generation",
        &g.fkek_key_id,
    )
    .await?;
    tx.commit().await?;
    Ok(cbor(StatusCode::CREATED, response))
}

// ------------------------------------------------------- FLEET_GRANT_REVOKE ---

/// `POST .../key-generations/{generation}/grants/{replay_id}/revoke`: one
/// grant is marked revoked, never deleted; the fleet is left
/// `rotation_required`, which clients derive (D-9, C-1).
pub async fn revoke_fleet_grant(
    State(app): State<AppState>,
    who: Principal,
    Path((fleet, generation, replay)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let v = verified(&app)?;
    let Principal::Session(presented) = who else {
        return Err(AppError::Forbidden);
    };
    let fleet = fleet_path(&fleet)?;
    let generation = generation_path(&generation)?;
    let replay = unhex::<16>(&replay)
        .ok_or_else(|| AppError::BadRequest("replay id must be 32 hex digits".into()))?;
    let outer = outer_request(v, &headers, &body, OperationKind::FleetGrantRevoke)?;
    let revoke = FleetGrantRevokeV2::parse(&outer.canonical_payload_bytes).map_err(record_error)?;
    let rv = &revoke.revocation;
    let g = &rv.generation;
    if g.fleet_id != fleet || g.generation != generation || rv.replay_id != replay {
        return Err(column_mismatch(
            "the path names another grant than the request",
        ));
    }
    if g.server_instance_id != v.server_instance_id {
        return Err(AppError::Forbidden);
    }
    if g.restore_epoch != v.restore_epoch {
        return Err(stale());
    }

    let mut tx = app.db.begin_with("BEGIN IMMEDIATE").await?;
    let now = now_ms();
    let s = reload_session(&mut tx, &presented, v, now)
        .await?
        .ok_or(AppError::Unauthorized)?;
    if s.tenant_id != g.tenant_id {
        return Err(AppError::Forbidden);
    }
    if let Some((payload, response)) = replay_or_none(
        &mut tx,
        v,
        &s,
        &outer,
        &body,
        RECORD_TYPE_FLEET_GRANT_REVOKED,
    )
    .await?
    {
        let revoked = FleetGrantRevokedV2::parse(&payload).map_err(|_| response_mismatch())?;
        let still = load_fleet_grant(&mut tx, v, &s.tenant_id, rv.grant_variant, &replay)
            .await?
            .is_some_and(|stored| stored.revoked);
        if revoked.revocation != *rv || !still {
            return Err(response_mismatch());
        }
        tx.commit().await?;
        return Ok(cbor(StatusCode::CREATED, response));
    }

    if !holds_fleet_capability(&mut tx, v, &s, &fleet, Capability::FleetManage, now).await? {
        return Err(AppError::Forbidden);
    }
    let stored = load_fleet_grant(&mut tx, v, &s.tenant_id, rv.grant_variant, &replay)
        .await?
        .ok_or_else(|| {
            coded(
                StatusCode::NOT_FOUND,
                "RESOURCE_NOT_FOUND",
                "no such fleet grant",
            )
        })?;
    if stored.signed_container_hash != rv.signed_container_hash
        || stored.fleet != (g.fleet_id, g.fkek_key_id, g.generation)
        || common_of(&stored.payload).restore_epoch != g.restore_epoch
    {
        return Err(column_mismatch("the revocation names another grant"));
    }
    if stored.revoked {
        return Err(conflict(
            "FLEET_GRANT_REVOKED",
            "this grant is already revoked",
        ));
    }

    sqlx::query(&format!(
        "UPDATE {} SET revoked_at = ?
          WHERE server_instance_id = ? AND tenant_id = ? AND replay_id = ? AND revoked_at IS NULL",
        table_of(rv.grant_variant)
    ))
    .bind(at(now))
    .bind(v.server_instance_id.as_slice())
    .bind(s.tenant_id.as_slice())
    .bind(replay.as_slice())
    .execute(&mut *tx)
    .await?;
    let revoked_at_ms = u64::try_from(now).unwrap_or_default();
    let payload = FleetGrantRevokedV2 {
        revocation: *rv,
        revoked_at_ms,
        // shortcut: a fleet grant backs no session or lease yet, so nothing
        // else is invalidated; count those once leases check fleet grants.
        invalidation_count: 0,
    }
    .encode();
    let response = stored_response(
        &outer,
        RECORD_TYPE_FLEET_GRANT_REVOKED,
        payload,
        v,
        revoked_at_ms,
    )?;
    let retained_until = common_of(&stored.payload)
        .not_after_ms
        .max(revoked_at_ms)
        .checked_add(AUTHORIZATION_REPLAY_RETENTION_MS)
        .ok_or(AppError::Forbidden)?;
    store_response(
        &mut tx,
        v,
        &s,
        &outer,
        &body,
        RECORD_TYPE_FLEET_GRANT_REVOKED,
        &response,
        retained_until,
    )
    .await?;
    audit(
        &mut tx,
        &s.tenant_id,
        &s.account_id,
        &s.device_id,
        "fleet.key_grant.revoke",
        "fleet_key_grant",
        &replay,
    )
    .await?;
    tx.commit().await?;
    Ok(cbor(StatusCode::CREATED, response))
}

/// `GET /v2/fleets/{f}/key-generations/{g}/grants/{device_id}` (plan L1131):
/// the device's newest `DeviceHpkeGrant` of that generation as its exact
/// `FleetDeviceGrantDescriptorV2`. Only the subject device's own session reads
/// it; for any other session the grant does not exist.
pub async fn read_fleet_device_grant(
    State(app): State<AppState>,
    who: Principal,
    Path((fleet, generation, device)): Path<(String, String, String)>,
) -> Result<Response, AppError> {
    let v = verified(&app)?;
    let Principal::Session(presented) = who else {
        return Err(AppError::Forbidden);
    };
    let fleet = fleet_path(&fleet)?;
    let generation = generation_path(&generation)?;
    let device = unhex::<16>(&device)
        .ok_or_else(|| AppError::BadRequest("device id must be 32 hex digits".into()))?;
    let not_found = || {
        coded(
            StatusCode::NOT_FOUND,
            "RESOURCE_NOT_FOUND",
            "no such fleet grant",
        )
    };
    let mut tx = app.db.begin().await?;
    let s = reload_session(&mut tx, &presented, v, now_ms())
        .await?
        .ok_or(AppError::Unauthorized)?;
    if s.device_id != device {
        return Err(not_found());
    }
    // A revoked grant may be followed by a new one; the newest is current.
    let replay: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT replay_id FROM v2_fleet_device_hpke_grants
          WHERE server_instance_id = ? AND tenant_id = ? AND fleet_id = ? AND generation = ?
            AND subject_device_id = ?
          ORDER BY created_at DESC, rowid DESC LIMIT 1",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(s.tenant_id.as_slice())
    .bind(fleet.as_slice())
    .bind(int(generation)?)
    .bind(device.as_slice())
    .fetch_optional(&mut *tx)
    .await?;
    let Some(replay) = replay else {
        return Err(not_found());
    };
    let replay: [u8; 16] = replay.try_into().map_err(|_| integrity())?;
    let g = load_fleet_grant(
        &mut tx,
        v,
        &s.tenant_id,
        FleetGrantVariant::DeviceHpke,
        &replay,
    )
    .await?
    .ok_or_else(integrity)?;
    let state = generation_row(&mut tx, v, &s.tenant_id, &fleet, generation)
        .await?
        .ok_or_else(integrity)?
        .state;
    let generation_state = RootGenerationState::ALL
        .into_iter()
        .find(|g| g.as_str() == state)
        .ok_or_else(integrity)?;
    let grant_state = match (g.acked, g.revoked) {
        (_, true) => RootGrantState::Revoked,
        (true, false) => RootGrantState::Acknowledged,
        (false, false) => RootGrantState::PendingAck,
    };
    let descriptor = FleetDeviceGrantDescriptorV2::new(g.record, grant_state, generation_state)
        .ok_or_else(integrity)?;
    tx.commit().await?;
    Ok(cbor(StatusCode::OK, descriptor.encode()))
}
