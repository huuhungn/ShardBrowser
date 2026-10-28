//! `POST /v2/recovery/restore-epoch-transitions` and its two readbacks (plan
//! 8.1 L1131; contracts 5.6.3 L667-L749; rules L374, L1112; ADR 0002 D-1 and
//! the D-2 issuer row L724).
//!
//! The body is a closed `RestoreEpochTransitionFilingV2` map carrying the
//! exact `SignedRestoreEpochTransitionV2` bytes and one exact
//! `RestoreEpochInclusionProofV2` per leaf, in leaf order. One
//! `BEGIN IMMEDIATE` checks that the signer is the presenting device, an
//! ACTIVE root custodian of the transition's own tenant, that the transition
//! is `E -> E+1` for the server's current epoch `E+1`, and that the proofs
//! are exactly the signed sorted leaf set; then it files the transition, its
//! proofs and the audit row together. The same bytes again get the same
//! answer; other bytes under the same epochs, replay ID or nonce are refused.
//! Readback returns the exact stored bytes to any live session of the tenant.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use sqlx::SqliteConnection;

use shared::canonical::{self as c, Value};
use shared::restore_epoch::{
    mapping_root, verify_inclusion, RestoreEpochInclusionProofV2, SignedRestoreEpochTransitionV2,
    MAPPING_CODEC,
};
use shared::signing::{SIGNATURE_SUITE_ID_ED25519, SIGNATURE_VERSION};

use super::v2_approval::{cbor, coded, exact_cbor_body};
use super::v2_auth::{audit, reload_session, unhex, verified, Principal};
use super::v2_root::{insert_row, mismatch, record_error, stale, Col};
use super::v2_root_grants::is_active_custodian;
use crate::error::AppError;
use crate::state::AppState;
use crate::util::{now_ms, now_rfc3339, sql_int};

pub const DOMAIN_RESTORE_EPOCH_TRANSITION_FILING: &str =
    "shardx.restore-epoch.transition-filing.v2";
/// shortcut: every proof rides in one body, which fits about ten thousand
/// leaves; page the proofs when a tenant covers more profiles than that.
pub const MAX_FILING_BODY: usize = 16 * 1024 * 1024;
const TRANSITIONS: &str = "v2_restore_epoch_transitions";
const PROOFS: &str = "v2_restore_epoch_transition_proofs";

/// Plan L1237: a transition or proof that cannot unquarantine a binding.
fn locked(code: &'static str, msg: &str) -> AppError {
    coded(StatusCode::LOCKED, code, msg)
}

fn not_found() -> AppError {
    coded(
        StatusCode::NOT_FOUND,
        "RESOURCE_NOT_FOUND",
        "no such restore-epoch transition",
    )
}

/// The exact transition and proof bytes of a closed filing map.
fn parse_filing(body: &[u8]) -> Result<(Vec<u8>, Vec<Vec<u8>>), AppError> {
    let bad = || {
        coded(
            StatusCode::UNPROCESSABLE_ENTITY,
            "NON_CANONICAL_RECORD",
            "the body is not a closed RestoreEpochTransitionFilingV2 map",
        )
    };
    // The strict decoder refuses duplicate keys, so four known keys are all four.
    let Ok(Value::Map(entries)) = c::decode(body) else {
        return Err(bad());
    };
    if entries.len() != 4 {
        return Err(bad());
    }
    let (mut transition, mut proofs) = (None, None);
    for (key, value) in entries {
        match (key.as_str(), value) {
            ("domain", Value::Text(d)) if d == DOMAIN_RESTORE_EPOCH_TRANSITION_FILING => {}
            ("version", Value::Uint(2)) => {}
            ("exact_signed_transition_bytes", Value::Bytes(b)) => transition = Some(b),
            ("canonical_inclusion_proofs", Value::Array(items)) => {
                let items = items.into_iter().map(|item| match item {
                    Value::Bytes(b) => Some(b),
                    _ => None,
                });
                proofs = Some(items.collect::<Option<Vec<_>>>().ok_or_else(bad)?);
            }
            _ => return Err(bad()),
        }
    }
    Ok((transition.ok_or_else(bad)?, proofs.ok_or_else(bad)?))
}

/// The exact proof bytes filed under one transition, in leaf order.
async fn stored_proofs(
    conn: &mut SqliteConnection,
    instance: &[u8; 16],
    tenant: &[u8; 16],
    previous: i64,
    new: i64,
) -> Result<Vec<Vec<u8>>, AppError> {
    Ok(sqlx::query_scalar(&format!(
        "SELECT canonical_inclusion_proof_bytes FROM {PROOFS}
          WHERE server_instance_id = ? AND tenant_id = ? AND previous_epoch = ? AND new_epoch = ?
          ORDER BY leaf_index"
    ))
    .bind(instance.as_slice())
    .bind(tenant.as_slice())
    .bind(previous)
    .bind(new)
    .fetch_all(&mut *conn)
    .await?)
}

pub async fn file_restore_epoch_transition(
    State(app): State<AppState>,
    who: Principal,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let v = verified(&app)?;
    let Principal::Session(presented) = who else {
        return Err(AppError::Forbidden);
    };
    exact_cbor_body(&headers, &body, MAX_FILING_BODY)?;
    let (exact, proof_bytes) = parse_filing(&body)?;
    let parsed = SignedRestoreEpochTransitionV2::parse(&exact).map_err(record_error)?;
    let proofs = proof_bytes
        .iter()
        .map(|p| RestoreEpochInclusionProofV2::parse(p))
        .collect::<Result<Vec<_>, _>>()
        .map_err(record_error)?;

    let mut tx = app.db.begin_with("BEGIN IMMEDIATE").await?;
    let now = now_ms();
    let s = reload_session(&mut tx, &presented, v, now)
        .await?
        .ok_or(AppError::Unauthorized)?;
    // The approver is the presenting device, verified under its own key.
    if parsed.approver_signing_key_id() != &s.signing_key_id {
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
    let transition = parsed.verify_signature(&issuer).map_err(record_error)?;
    let t = transition.payload();
    // L733, L1131: the session's own device of the transition's own tenant.
    if t.tenant_id != s.tenant_id
        || t.server_instance_id != v.server_instance_id
        || t.approver_account_id != s.account_id
        || t.approver_device_id != s.device_id
    {
        return Err(AppError::Forbidden);
    }
    // L2251, L2254 (ADR 0002 D-1 step 5): the set for `E -> E+1` is filed
    // once the authority is at `E+1`.
    if t.new_epoch != v.restore_epoch || t.new_epoch - t.previous_epoch != 1 {
        return Err(stale());
    }
    let (instance, tenant) = (&v.server_instance_id, &t.tenant_id);
    let (previous, new) = (sql_int(t.previous_epoch)?, sql_int(t.new_epoch)?);

    // A lost response: the same transition and proofs get the same answer.
    // Anything else under these epochs, replay ID or nonce is another
    // request; only a custodian learns that they are spent.
    let filed: Vec<Vec<u8>> = sqlx::query_scalar(&format!(
        "SELECT exact_signed_transition_bytes FROM {TRANSITIONS}
          WHERE server_instance_id = ? AND tenant_id = ?
            AND ((previous_epoch = ? AND new_epoch = ?) OR transition_replay_id = ? OR nonce = ?)"
    ))
    .bind(instance.as_slice())
    .bind(tenant.as_slice())
    .bind(previous)
    .bind(new)
    .bind(t.transition_replay_id.as_slice())
    .bind(t.nonce.as_slice())
    .fetch_all(&mut *tx)
    .await?;
    if !filed.is_empty() {
        // The uniques leave the identical row, if any, as the only match.
        if filed[0] == exact
            && stored_proofs(&mut tx, instance, tenant, previous, new).await? == proof_bytes
        {
            tx.commit().await?;
            return Ok(cbor(StatusCode::CREATED, exact));
        }
        if !is_active_custodian(&mut tx, v, &s, now).await? {
            return Err(AppError::Forbidden);
        }
        return Err(mismatch());
    }

    // ADR 0002 D-2 (L724): an ACTIVE root custodian, which is what
    // `root.custody` means (Q-2).
    if !is_active_custodian(&mut tx, v, &s, now).await? {
        return Err(AppError::Forbidden);
    }
    // L1112: one proof per signed leaf, each against the signed root, and
    // together exactly the sorted unique leaf set the root commits to.
    if proofs.len() as u64 != t.mapping_count {
        return Err(locked(
            "RESTORE_EPOCH_PROOF_MISSING",
            "the filing does not carry one proof per signed leaf",
        ));
    }
    for p in &proofs {
        verify_inclusion(&transition, p, &p.leaf.profile_id)
            .map_err(|e| locked(e.code(), &e.to_string()))?;
    }
    let leaves: Vec<_> = proofs.iter().map(|p| p.leaf.clone()).collect();
    if mapping_root(&t.tenant_id, &leaves).ok() != Some(t.profile_head_mapping_root) {
        return Err(locked(
            "RESTORE_EPOCH_TRANSITION_INVALID",
            "the proofs are not the sorted leaf set the transition signs",
        ));
    }

    let created_at = now_rfc3339();
    let b = |bytes: &[u8]| Col::Blob(bytes.to_vec());
    let container = transition.container();
    let row = vec![
        ("server_instance_id", b(instance)),
        ("tenant_id", b(tenant)),
        ("previous_epoch", Col::Int(previous)),
        ("new_epoch", Col::Int(new)),
        ("transition_replay_id", b(&t.transition_replay_id)),
        ("mapping_codec", Col::Text(MAPPING_CODEC)),
        ("mapping_count", Col::Int(sql_int(t.mapping_count)?)),
        ("profile_head_mapping_root", b(&t.profile_head_mapping_root)),
        ("reason_code", Col::Text(t.reason_code.as_str())),
        ("approver_account_id", b(&t.approver_account_id)),
        ("approver_device_id", b(&t.approver_device_id)),
        ("approver_signing_key_id", b(&t.approver_signing_key_id)),
        ("issued_at_ms", Col::Int(sql_int(t.issued_at_ms)?)),
        ("nonce", b(&t.nonce)),
        (
            "canonical_transition_payload_bytes",
            b(container.canonical_transition_payload_bytes()),
        ),
        (
            "transition_payload_sha256",
            b(container.transition_payload_sha256()),
        ),
        // The parser admits only this suite and version.
        (
            "signature_suite_id",
            Col::Int(i64::from(SIGNATURE_SUITE_ID_ED25519)),
        ),
        ("signature_version", Col::Int(i64::from(SIGNATURE_VERSION))),
        ("signature_bytes", b(container.signature_bytes())),
        (
            "signed_transition_container_hash",
            b(container.signed_transition_container_hash()),
        ),
        ("exact_signed_transition_bytes", b(&exact)),
        (
            "exact_signed_transition_bytes_sha256",
            b(container.exact_signed_transition_bytes_sha256()),
        ),
    ];
    insert_row(&mut tx, TRANSITIONS, &row, &created_at).await?;
    for (p, exact_proof) in proofs.iter().zip(&proof_bytes) {
        let leaf = p.leaf.encode();
        let proof_row = vec![
            ("server_instance_id", b(instance)),
            ("tenant_id", b(tenant)),
            ("previous_epoch", Col::Int(previous)),
            ("new_epoch", Col::Int(new)),
            ("profile_id", b(&p.leaf.profile_id)),
            (
                "previous_signed_head_hash",
                b(&p.leaf.previous_signed_head_hash),
            ),
            ("new_signed_head_hash", b(&p.leaf.new_signed_head_hash)),
            ("leaf_index", Col::Int(sql_int(p.leaf_index)?)),
            ("leaf_count", Col::Int(sql_int(p.leaf_count)?)),
            ("leaf_hash", b(&p.leaf.hash())),
            ("canonical_leaf_bytes", Col::Blob(leaf)),
            ("canonical_inclusion_proof_bytes", b(exact_proof)),
            (
                "proof_sha256",
                b(&c::domain_hash(c::L_RESTORE_EPOCH_PROOF, exact_proof)),
            ),
        ];
        insert_row(&mut tx, PROOFS, &proof_row, &created_at).await?;
    }
    audit(
        &mut tx,
        &s.tenant_id,
        &s.account_id,
        &s.device_id,
        "tenant.restore_epoch_transition",
        "restore_epoch_transition",
        &t.transition_replay_id,
    )
    .await?;
    tx.commit().await?;
    Ok(cbor(StatusCode::CREATED, exact))
}

/// One decimal spelling per epoch, so one transition has exactly one path.
fn epoch_path(epoch: &str) -> Result<i64, AppError> {
    let e = epoch
        .parse::<u64>()
        .ok()
        .filter(|e| e.to_string() == epoch)
        .ok_or_else(|| AppError::BadRequest("an epoch must be a decimal integer".into()))?;
    sql_int(e)
}

/// The exact stored bytes the path names: the transition, or with `profile`
/// that profile's proof. Another tenant's are not found (L1131, L1226).
async fn read_back(
    app: &AppState,
    who: Principal,
    (tenant, previous, new): (String, String, String),
    profile: Option<String>,
) -> Result<Response, AppError> {
    let v = verified(app)?;
    let Principal::Session(presented) = who else {
        return Err(AppError::Forbidden);
    };
    let tenant = unhex::<16>(&tenant)
        .ok_or_else(|| AppError::BadRequest("tenant id must be 32 hex digits".into()))?;
    let (previous, new) = (epoch_path(&previous)?, epoch_path(&new)?);
    let profile = profile
        .map(|p| {
            unhex::<16>(&p)
                .ok_or_else(|| AppError::BadRequest("profile id must be 32 hex digits".into()))
        })
        .transpose()?;
    let mut conn = app.db.acquire().await?;
    let s = reload_session(&mut conn, &presented, v, now_ms())
        .await?
        .ok_or(AppError::Unauthorized)?;
    if s.tenant_id != tenant {
        return Err(not_found());
    }
    let (column, table, extra) = match profile {
        None => ("exact_signed_transition_bytes", TRANSITIONS, ""),
        Some(_) => (
            "canonical_inclusion_proof_bytes",
            PROOFS,
            " AND profile_id = ?",
        ),
    };
    let sql = format!(
        "SELECT {column} FROM {table}
          WHERE server_instance_id = ? AND tenant_id = ? AND previous_epoch = ? AND new_epoch = ?{extra}"
    );
    let mut q = sqlx::query_scalar::<_, Vec<u8>>(&sql)
        .bind(v.server_instance_id.as_slice())
        .bind(s.tenant_id.as_slice())
        .bind(previous)
        .bind(new);
    if let Some(p) = &profile {
        q = q.bind(p.as_slice());
    }
    let bytes = q.fetch_optional(&mut *conn).await?.ok_or_else(not_found)?;
    Ok(cbor(StatusCode::OK, bytes))
}

pub async fn read_restore_epoch_transition(
    State(app): State<AppState>,
    who: Principal,
    Path(key): Path<(String, String, String)>,
) -> Result<Response, AppError> {
    read_back(&app, who, key, None).await
}

pub async fn read_restore_epoch_proof(
    State(app): State<AppState>,
    who: Principal,
    Path((tenant, previous, new, profile)): Path<(String, String, String, String)>,
) -> Result<Response, AppError> {
    read_back(&app, who, (tenant, previous, new), Some(profile)).await
}
