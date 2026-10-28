//! Profile uploads: `CREATE_UPLOAD`, chunk `PATCH`/`HEAD`, `FINALIZE_UPLOAD`,
//! `COMMIT` and the snapshot readback (plan 8.1 L1145-L1176; G2-23, G2-24).
//!
//! Create-upload and finalize take exact `IdempotentMutationRequestV2` bodies
//! (5.6.5, L950/L951); commit takes the exact `CommitRequestV2` and stores its
//! exact `CommitReceiptBindingV2` as the response (5.6.2, L541-L587, L1105).
//! Every upload route needs the caller's current lease with its exact fence
//! (L1174). Create-upload, finalize and commit also need a device-scoped
//! `profile.commit`, and the manifest verifies under the caller's own device
//! key: the signer is the lease holder (ADR 0002 D-2, L1412).
//!
//! Bytes live in the blob store of the legacy upload path: staging at
//! [`fleet::staging_path`], immutable objects keyed by `snapshot_id` and never
//! overwritten (ADR 0002 C-2). One process-local writer per upload runs a
//! PATCH or a finalize (L1159); neither holds a transaction across its file
//! I/O. A PATCH reads its offset, writes and flushes the chunk, then
//! re-checks and records it in a short `BEGIN IMMEDIATE` (L1163-L1166).
//! Finalize hashes and promotes between its `OPEN -> FINALIZING` and
//! `FINALIZING -> READY` writes.
//!
//! An upload row is looked up under the current restore epoch, and a replay
//! whose upload or snapshot a restore dropped gets the ADR 0002 D-1 error,
//! never its stored bytes.
//!
//! shortcut: no startup reconciler or GC (L1177-L1215). PATCH drops a tail
//! past the committed offset and quarantines a short file, the next finalize
//! of a FINALIZING upload finishes it, and create-upload aborts the tenant's
//! expired OPEN uploads and deletes their staging files. Quarantined
//! evidence, expired FINALIZING files and READY objects that never commit
//! stay on disk; add the reconciliation matrix with restore and GC.

use std::collections::BTreeSet;
use std::path::{Path as FsPath, PathBuf};
use std::sync::Mutex;

use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use sqlx::{Row, SqliteConnection};

use shared::authz_record::Capability;
use shared::canonical::sha256;
use shared::envelope_v2::{self, EnvelopeError, Expected, Scope};
use shared::mutation::OperationKind;
use shared::profile_lease::{
    CreateUploadV2, LeaseRef, ProfileRef, UploadCreatedV2, UploadFinalizedV2,
    RECORD_TYPE_UPLOAD_CREATED, RECORD_TYPE_UPLOAD_FINALIZED,
};
use shared::snapshot_v2::{
    CommitReceiptBindingV2, CommitRequestV2, FinalizeUploadV2, LeaseReleaseOutcome, SnapshotError,
    SnapshotManifestV2, VerifiedCommitRequestV2, MAX_COMMIT_REQUEST_BYTES, OPERATION_SCOPE_COMMIT,
};

use super::v2_approval::{cbor, coded, column_mismatch, exact_cbor_body};
use super::v2_auth::{audit, blob, random, reload_session, unhex, verified, Principal, Session};
use super::v2_profiles::{
    active_key, conflict, finish, head, held_lease, id_path, may, no_active_key, not_found,
    published, replay, response_mismatch, session_of,
};
use super::v2_root::{ledger_row, mismatch, record_error};
use super::v2_root_grants::outer_request;
use crate::error::AppError;
use crate::fleet;
use crate::identity::Verified;
use crate::state::AppState;
use crate::util::{now_ms, sql_int, stored_uint};

/// An upload must finalize within a day of its creation.
const UPLOAD_TTL_MS: i64 = 86_400_000;
/// The chunk cap of L1159, and the most one ranged read returns.
pub const MAX_CHUNK_BYTES: usize = 8 * 1024 * 1024;
/// L1105: the record type of a commit's stored response.
const RECORD_TYPE_COMMIT_RECEIPT: &str = "CommitReceiptBindingV2";

fn offset_mismatch() -> AppError {
    conflict(
        "UPLOAD_OFFSET_MISMATCH",
        "the upload is not at this offset or state; HEAD it and resume",
    )
}

/// The uploads a PATCH or finalize is working on (L1159).
static WRITERS: Mutex<BTreeSet<[u8; 16]>> = Mutex::new(BTreeSet::new());

/// The one writer of an upload, until dropped. A second is refused, not
/// queued: its client HEADs and resumes.
struct Writer([u8; 16]);

impl Drop for Writer {
    fn drop(&mut self) {
        WRITERS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.0);
    }
}

fn writer(upload_id: [u8; 16]) -> Result<Writer, AppError> {
    let mut held = WRITERS.lock().unwrap_or_else(|e| e.into_inner());
    if !held.insert(upload_id) {
        return Err(offset_mismatch());
    }
    Ok(Writer(upload_id))
}

fn quarantined() -> AppError {
    coded(
        StatusCode::UNPROCESSABLE_ENTITY,
        "UPLOAD_QUARANTINED",
        "the upload is quarantined",
    )
}

fn replay_mismatch(field: &str) -> AppError {
    coded(
        StatusCode::UNPROCESSABLE_ENTITY,
        "MANIFEST_REPLAY_MISMATCH",
        &format!("{field} does not match the upload"),
    )
}

fn snapshot_error(e: SnapshotError) -> AppError {
    match e {
        SnapshotError::Record(r) => record_error(r),
        other => coded(
            StatusCode::UNPROCESSABLE_ENTITY,
            other.code(),
            &other.to_string(),
        ),
    }
}

/// A `v2_uploads` row with the terms CREATE_UPLOAD bound.
struct Upload {
    p: ProfileRef,
    snapshot_id: [u8; 16],
    manifest_replay_id: [u8; 16],
    lease: LeaseRef,
    intent_hash: [u8; 32],
    preamble_sha256: [u8; 32],
    dek_slot_sha256: [u8; 32],
    fkek_key_id: [u8; 32],
    key_generation: u64,
    size: u64,
    sha256: [u8; 32],
    committed_offset: u64,
    staging_path: String,
    immutable_path: Option<String>,
    state: String,
    commit_request: Option<Vec<u8>>,
    expires_at_ms: i64,
}

/// The upload under this instance and the current restore epoch: one from
/// before a restore is gone (ADR 0002 D-1).
async fn load(
    conn: &mut SqliteConnection,
    v: &Verified,
    tenant: &[u8; 16],
    upload_id: &[u8; 16],
) -> Result<Option<Upload>, AppError> {
    let row = sqlx::query(
        "SELECT * FROM v2_uploads
          WHERE server_instance_id = ? AND tenant_id = ? AND upload_id = ? AND restore_epoch = ?",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(tenant.as_slice())
    .bind(upload_id.as_slice())
    .bind(sql_int(v.restore_epoch)?)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(r) = row else { return Ok(None) };
    Ok(Some(Upload {
        p: ProfileRef {
            tenant_id: *tenant,
            fleet_id: blob::<16>(&r, "fleet_id")?,
            profile_id: blob::<16>(&r, "profile_id")?,
        },
        snapshot_id: blob::<16>(&r, "snapshot_id")?,
        manifest_replay_id: blob::<16>(&r, "manifest_replay_id")?,
        lease: LeaseRef {
            lease_id: blob::<16>(&r, "lease_id")?,
            fencing_token: stored_uint(r.get("fencing_token"))?,
            base_version: stored_uint(r.get("base_version"))?,
        },
        intent_hash: blob::<32>(&r, "intent_hash")?,
        preamble_sha256: blob::<32>(&r, "preamble_sha256")?,
        dek_slot_sha256: blob::<32>(&r, "dek_slot_sha256")?,
        fkek_key_id: blob::<32>(&r, "fkek_key_id")?,
        key_generation: stored_uint(r.get("key_generation"))?,
        size: stored_uint(r.get("expected_ciphertext_size"))?,
        sha256: blob::<32>(&r, "expected_ciphertext_sha256")?,
        committed_offset: stored_uint(r.get("committed_offset"))?,
        staging_path: r.get("staging_path"),
        immutable_path: r.get("immutable_path"),
        state: r.get("state"),
        commit_request: r.get("exact_commit_request_bytes"),
        expires_at_ms: r.get("expires_at_ms"),
    }))
}

/// `OPEN`/`FINALIZING -> QUARANTINED` with its audit row: the evidence stays
/// where it is (L1162, L1189).
async fn quarantine(
    conn: &mut SqliteConnection,
    v: &Verified,
    s: &Session,
    upload_id: &[u8; 16],
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE v2_uploads SET state = 'QUARANTINED'
          WHERE server_instance_id = ? AND tenant_id = ? AND upload_id = ?",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(s.tenant_id.as_slice())
    .bind(upload_id.as_slice())
    .execute(&mut *conn)
    .await?;
    audit(
        conn,
        &s.tenant_id,
        &s.account_id,
        &s.device_id,
        "upload.quarantine",
        "upload",
        upload_id,
    )
    .await
}

/// The manifest's signature under the caller's own device key. A manifest
/// another device signed is `KEY_SUBSTITUTION_DETECTED` (ADR 0002 D-2).
async fn verify_signed(
    conn: &mut SqliteConnection,
    s: &Session,
    req: CommitRequestV2,
) -> Result<VerifiedCommitRequestV2, AppError> {
    let key: Vec<u8> = sqlx::query_scalar(
        "SELECT signing_public_key FROM v2_devices WHERE tenant_id = ? AND id = ?",
    )
    .bind(s.tenant_id.as_slice())
    .bind(s.device_id.as_slice())
    .fetch_one(&mut *conn)
    .await?;
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| AppError::Internal("a stored signing key is not 32 bytes".into()))?;
    req.verify_signature(&key).map_err(snapshot_error)
}

/// The verified manifest names exactly this upload, on this instance and
/// epoch (L1170, L1174). The tenant was checked against the session.
fn bind(u: &Upload, m: &SnapshotManifestV2, v: &Verified) -> Result<(), AppError> {
    let fields = [
        ("profile_id", m.profile_id == u.p.profile_id),
        ("fleet_id", m.fleet_id == u.p.fleet_id),
        ("snapshot_id", m.snapshot_id == u.snapshot_id),
        (
            "manifest_replay_id",
            m.manifest_replay_id == u.manifest_replay_id,
        ),
        ("lease_id", m.lease_id == u.lease.lease_id),
        ("fencing_token", m.fencing_token == u.lease.fencing_token),
        ("base_version", m.base_version == u.lease.base_version),
        ("intent_hash", m.intent_hash == u.intent_hash),
        ("preamble_sha256", m.preamble_sha256 == u.preamble_sha256),
        ("dek_slot_sha256", m.dek_slot_sha256 == u.dek_slot_sha256),
        ("fkek_key_id", m.fkek_key_id == u.fkek_key_id),
        ("key_generation", m.key_generation == u.key_generation),
        ("ciphertext_size", m.ciphertext_size == u.size),
        ("ciphertext_sha256", m.ciphertext_sha256 == u.sha256),
        (
            "server_instance_id",
            m.server_instance_id == v.server_instance_id,
        ),
        ("restore_epoch", m.restore_epoch == v.restore_epoch),
    ];
    match fields.iter().find(|(_, equal)| !equal) {
        Some((field, _)) => Err(replay_mismatch(field)),
        None => Ok(()),
    }
}

// ---------------------------------------------------------- CREATE_UPLOAD ---

/// `POST /v2/profiles/{profile_id}/uploads` (L1145): binds the snapshot,
/// replay ID, envelope hashes, FKEK generation and expected object to the
/// caller's lease, with the stored response and audit row, at once.
pub async fn create_upload(
    State(app): State<AppState>,
    who: Principal,
    Path(profile): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let v = verified(&app)?;
    let presented = session_of(who)?;
    let profile = id_path(&profile)?;
    let outer = outer_request(v, &headers, &body, OperationKind::CreateUpload)?;
    let req = CreateUploadV2::parse(&outer.canonical_payload_bytes).map_err(record_error)?;
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
    if let Some(row) =
        ledger_row(&mut tx, v, &s, outer.operation_kind, &outer.idempotency_key).await?
    {
        // L970: the same upload ID, unless a restore dropped it (D-1).
        let (payload, response) = replay(&row, &outer, &body, RECORD_TYPE_UPLOAD_CREATED, v)?;
        let created = UploadCreatedV2::parse(&payload).map_err(|_| response_mismatch())?;
        load(&mut tx, v, &s.tenant_id, &created.upload_id)
            .await?
            .ok_or_else(not_found)?;
        tx.commit().await?;
        return Ok(cbor(StatusCode::CREATED, response));
    }

    if !may(
        &mut tx,
        v,
        &s,
        &p.fleet_id,
        Some(&profile),
        Capability::ProfileCommit,
        true,
        now,
    )
    .await?
    {
        return Err(AppError::Forbidden);
    }
    // The lease's base is the profile's version: only a commit moves it, and
    // a commit deletes the lease.
    published(&mut tx, &p).await?.ok_or_else(not_found)?;
    held_lease(&mut tx, &p, &s, &req.lease, now).await?;
    if active_key(&mut tx, v, &p.tenant_id, &p.fleet_id).await?
        != Some((req.key_generation, req.fkek_key_id))
    {
        return Err(no_active_key());
    }
    // The tenant's expired OPEN uploads are dead (PATCH and finalize refuse
    // them): ABORTED here, and their staging files go once this commits.
    let aborted: Vec<String> = sqlx::query_scalar(
        "UPDATE v2_uploads SET state = 'ABORTED'
          WHERE server_instance_id = ? AND tenant_id = ? AND state = 'OPEN'
            AND expires_at_ms <= ?
         RETURNING staging_path",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(p.tenant_id.as_slice())
    .bind(now)
    .fetch_all(&mut *tx)
    .await?;
    // L1102: one snapshot ID and one manifest replay ID per upload.
    let bound: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM v2_uploads
                         WHERE server_instance_id = ? AND tenant_id = ? AND profile_id = ?
                           AND (snapshot_id = ? OR manifest_replay_id = ?))",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(p.tenant_id.as_slice())
    .bind(p.profile_id.as_slice())
    .bind(req.snapshot_id.as_slice())
    .bind(req.manifest_replay_id.as_slice())
    .fetch_one(&mut *tx)
    .await?;
    if bound {
        return Err(coded(
            StatusCode::UNPROCESSABLE_ENTITY,
            "SNAPSHOT_REPLAY_MISMATCH",
            "this snapshot or manifest replay ID is already bound",
        ));
    }
    // L1155 upload slots: one OPEN or FINALIZING upload per lease, so at most
    // one object size of live staging each. The sweep above frees an expired
    // OPEN one.
    let busy: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM v2_uploads
                         WHERE server_instance_id = ? AND tenant_id = ? AND lease_id = ?
                           AND state IN ('OPEN', 'FINALIZING'))",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(p.tenant_id.as_slice())
    .bind(req.lease.lease_id.as_slice())
    .fetch_one(&mut *tx)
    .await?;
    if busy {
        // Plan L1244: UPLOAD_CAPACITY is a 429.
        // shortcut: no Retry-After header yet; add one when the reconciler
        // (L1177-L1215) can say when a slot frees.
        return Err(coded(
            StatusCode::TOO_MANY_REQUESTS,
            "UPLOAD_CAPACITY",
            "this lease already has an open upload; finish it or let it expire",
        ));
    }

    let upload_id = random::<16>()?;
    let staging = fleet::staging_path(FsPath::new(&app.cfg.blob_dir), &p.tenant_id, &upload_id);
    let expires_at_ms = now + UPLOAD_TTL_MS;
    sqlx::query(
        "INSERT INTO v2_uploads
             (server_instance_id, tenant_id, upload_id, fleet_id, profile_id, snapshot_id,
              manifest_replay_id, lease_id, fencing_token, base_version, restore_epoch,
              operation_scope, idempotency_key, canonical_request_hash, intent_hash,
              preamble_sha256, dek_slot_sha256, fkek_key_id, key_generation,
              expected_ciphertext_size, expected_ciphertext_sha256, staging_path, state,
              expires_at_ms, created_at_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'OPEN', ?, ?)",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(p.tenant_id.as_slice())
    .bind(upload_id.as_slice())
    .bind(p.fleet_id.as_slice())
    .bind(p.profile_id.as_slice())
    .bind(req.snapshot_id.as_slice())
    .bind(req.manifest_replay_id.as_slice())
    .bind(req.lease.lease_id.as_slice())
    .bind(sql_int(req.lease.fencing_token)?)
    .bind(sql_int(req.lease.base_version)?)
    .bind(sql_int(v.restore_epoch)?)
    .bind(outer.operation_kind.scope())
    .bind(outer.idempotency_key.as_slice())
    .bind(outer.canonical_request_hash().as_slice())
    .bind(req.intent_hash.as_slice())
    .bind(req.preamble_sha256.as_slice())
    .bind(req.dek_slot_sha256.as_slice())
    .bind(req.fkek_key_id.as_slice())
    .bind(sql_int(req.key_generation)?)
    .bind(sql_int(req.expected_ciphertext_size)?)
    .bind(req.expected_ciphertext_sha256.as_slice())
    .bind(staging.to_string_lossy().to_string())
    .bind(expires_at_ms)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    // The row goes in first, as in `fleet::open_upload`; a failed file
    // rolls it back.
    let created = async {
        if let Some(dir) = staging.parent() {
            tokio::fs::create_dir_all(dir).await?;
        }
        tokio::fs::File::create(&staging).await.map(drop)
    };
    created
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let payload = UploadCreatedV2 {
        terms: req,
        upload_id,
        expires_at_ms: u64::try_from(expires_at_ms).unwrap_or_default(),
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
        RECORD_TYPE_UPLOAD_CREATED,
        payload,
        now,
        "profile.create_upload",
        ("upload", &upload_id),
    )
    .await?;
    tx.commit().await?;
    for path in aborted {
        // A file left behind costs only disk; its row is ABORTED for good.
        let _ = tokio::fs::remove_file(path).await;
    }
    Ok(cbor(StatusCode::CREATED, response))
}

// -------------------------------------------------------------- PATCH/HEAD ---

fn offset_response(offset: u64, status: StatusCode) -> Response {
    (status, [("upload-offset", offset.to_string())]).into_response()
}

/// Writes `bytes` at `offset` of the staging file and flushes them (L1164,
/// L1165). `Ok(false)` when the file is missing or shorter than the committed
/// offset: that upload cannot resume (L1167).
fn write_at(path: &str, offset: u64, bytes: &[u8]) -> std::io::Result<bool> {
    use std::io::{Seek, Write};
    let mut f = match std::fs::OpenOptions::new().write(true).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    if f.metadata()?.len() < offset {
        return Ok(false);
    }
    // L1167: a crashed write's tail past the committed offset goes first.
    f.set_len(offset)?;
    f.seek(std::io::SeekFrom::Start(offset))?;
    f.write_all(bytes)?;
    f.sync_data()?;
    Ok(true)
}

/// [`write_at`] off the async runtime. The writer goes with it, so a dropped
/// request cannot free the upload while its write still runs.
async fn write_chunk(
    w: Writer,
    path: String,
    offset: u64,
    bytes: Bytes,
) -> Result<(Writer, bool), AppError> {
    let (w, written) = tokio::task::spawn_blocking(move || (w, write_at(&path, offset, &bytes)))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok((w, written.map_err(|e| AppError::Internal(e.to_string()))?))
}

/// The caller's OPEN, unexpired upload under its held lease.
async fn writable(
    conn: &mut SqliteConnection,
    v: &Verified,
    presented: &Session,
    upload_id: &[u8; 16],
) -> Result<(Session, Upload), AppError> {
    let now = now_ms();
    let s = reload_session(conn, presented, v, now)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let u = load(conn, v, &s.tenant_id, upload_id)
        .await?
        .filter(|u| u.expires_at_ms > now)
        .ok_or_else(not_found)?;
    held_lease(conn, &u.p, &s, &u.lease, now).await?;
    if u.state == "QUARANTINED" {
        return Err(quarantined());
    }
    if u.state != "OPEN" {
        return Err(offset_mismatch());
    }
    Ok((s, u))
}

/// `PATCH /v2/uploads/{upload_id}` (L1147, L1163-L1167): one chunk at
/// `Upload-Offset`, checked against `Upload-Chunk-SHA256`, written and
/// flushed before the offset and its receipt commit. An older offset is a
/// duplicate success only with the same receipt.
pub async fn patch_upload(
    State(app): State<AppState>,
    who: Principal,
    Path(upload): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let v = verified(&app)?;
    let presented = session_of(who)?;
    let upload_id = id_path(&upload)?;
    let field = |name: &str| headers.get(name).and_then(|h| h.to_str().ok());
    let offset: u64 = field("upload-offset")
        .and_then(|h| h.parse().ok())
        .ok_or_else(|| AppError::BadRequest("Upload-Offset must be a decimal offset".into()))?;
    let digest = field("upload-chunk-sha256")
        .and_then(unhex::<32>)
        .ok_or_else(|| AppError::BadRequest("Upload-Chunk-SHA256 must be 64 hex digits".into()))?;
    if body.is_empty() {
        return Err(AppError::BadRequest("a chunk is not empty".into()));
    }
    if sha256(&body) != digest {
        return Err(coded(
            StatusCode::UNPROCESSABLE_ENTITY,
            "CIPHERTEXT_HASH_MISMATCH",
            "the chunk does not match Upload-Chunk-SHA256",
        ));
    }

    let w = writer(upload_id)?;
    let mut conn = app.db.acquire().await?;
    let (s, u) = writable(&mut conn, v, &presented, &upload_id).await?;
    let length = body.len() as u64;
    if offset < u.committed_offset {
        let same: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM v2_upload_chunks
                             WHERE server_instance_id = ? AND tenant_id = ? AND upload_id = ?
                               AND chunk_offset = ? AND chunk_length = ? AND chunk_sha256 = ?)",
        )
        .bind(v.server_instance_id.as_slice())
        .bind(s.tenant_id.as_slice())
        .bind(upload_id.as_slice())
        .bind(sql_int(offset)?)
        .bind(sql_int(length)?)
        .bind(digest.as_slice())
        .fetch_one(&mut *conn)
        .await?;
        if !same {
            return Err(offset_mismatch());
        }
        return Ok(offset_response(u.committed_offset, StatusCode::OK));
    }
    if offset != u.committed_offset {
        return Err(offset_mismatch());
    }
    let end = offset + length;
    if end > u.size {
        return Err(coded(
            StatusCode::PAYLOAD_TOO_LARGE,
            "SNAPSHOT_TOO_LARGE",
            "the chunk runs past the expected ciphertext size",
        ));
    }
    drop(conn);
    let path = u.staging_path;
    let (w, written) = write_chunk(w, path.clone(), offset, body).await?;

    // L1166: the CAS re-checks all the write did not hold. A chunk that does
    // not record is cut back to the committed offset.
    let mut tx = app.db.begin_with("BEGIN IMMEDIATE").await?;
    let s = match writable(&mut tx, v, &presented, &upload_id).await {
        Ok((s, u)) if u.committed_offset == offset => s,
        refused => {
            drop(tx);
            // Best effort: the next write drops a tail too.
            let _ = write_chunk(w, path, offset, Bytes::new()).await;
            return Err(refused.err().unwrap_or_else(offset_mismatch));
        }
    };
    if !written {
        quarantine(&mut tx, v, &s, &upload_id).await?;
        tx.commit().await?;
        return Err(quarantined());
    }
    sqlx::query(
        "UPDATE v2_uploads SET committed_offset = ?
          WHERE server_instance_id = ? AND tenant_id = ? AND upload_id = ?",
    )
    .bind(sql_int(end)?)
    .bind(v.server_instance_id.as_slice())
    .bind(s.tenant_id.as_slice())
    .bind(upload_id.as_slice())
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO v2_upload_chunks
             (server_instance_id, tenant_id, upload_id, chunk_offset, chunk_length, chunk_sha256)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(s.tenant_id.as_slice())
    .bind(upload_id.as_slice())
    .bind(sql_int(offset)?)
    .bind(sql_int(length)?)
    .bind(digest.as_slice())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    drop(w);
    Ok(offset_response(end, StatusCode::OK))
}

/// `HEAD /v2/uploads/{upload_id}` (L1146): the committed offset and state,
/// for the lease holder to resume from.
pub async fn head_upload(
    State(app): State<AppState>,
    who: Principal,
    Path(upload): Path<String>,
) -> Result<Response, AppError> {
    let v = verified(&app)?;
    let presented = session_of(who)?;
    let upload_id = id_path(&upload)?;
    let mut conn = app.db.acquire().await?;
    let now = now_ms();
    let s = reload_session(&mut conn, &presented, v, now)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let u = load(&mut conn, v, &s.tenant_id, &upload_id)
        .await?
        .ok_or_else(not_found)?;
    held_lease(&mut conn, &u.p, &s, &u.lease, now).await?;
    Ok((
        StatusCode::OK,
        [
            ("upload-offset", u.committed_offset.to_string()),
            ("upload-state", u.state),
        ],
    )
        .into_response())
}

// -------------------------------------------------------- FINALIZE_UPLOAD ---

/// Checks the object's bytes and public envelope grammar, then makes it
/// immutable at `object` (L1170-L1172). `Ok(Err(code))` refuses the bytes;
/// an I/O error leaves the upload FINALIZING for the next finalize.
fn promote(
    staging: &FsPath,
    object: &FsPath,
    u: &Upload,
) -> std::io::Result<Result<(), &'static str>> {
    // A finalize that crashed after its rename left the object in place.
    let promoted = object.exists();
    let mut f = std::fs::File::open(if promoted { object } else { staging })?;
    let scope = Scope {
        snapshot_id: u.snapshot_id,
        tenant_id: u.p.tenant_id,
        fleet_id: u.p.fleet_id,
        profile_id: u.p.profile_id,
        target_version: u.lease.base_version + 1,
        key_generation: u.key_generation,
    };
    let expected = Expected {
        ciphertext_sha256: &u.sha256,
        ciphertext_size: u.size,
        preamble_sha256: &u.preamble_sha256,
        intent_hash: &u.intent_hash,
        dek_slot_sha256: &u.dek_slot_sha256,
        scope: &scope,
    };
    match envelope_v2::check_public(&mut f, &expected) {
        Err(EnvelopeError::Io(e)) => return Err(e),
        Err(EnvelopeError::Mismatch("ciphertext_size" | "ciphertext_sha256")) => {
            return Ok(Err("CIPHERTEXT_HASH_MISMATCH"))
        }
        Err(_) => return Ok(Err("UPLOAD_QUARANTINED")),
        Ok(intent) if intent.manifest_replay_id != u.manifest_replay_id => {
            return Ok(Err("UPLOAD_QUARANTINED"))
        }
        Ok(_) => {}
    }
    drop(f);
    if !promoted {
        // Each chunk was flushed when written; the rename and its directory
        // are flushed here (L1171-L1172).
        let dir = object
            .parent()
            .ok_or_else(|| std::io::Error::other("an object path has a directory"))?;
        std::fs::create_dir_all(dir)?;
        std::fs::rename(staging, object)?;
        crate::identity::sync_dir(dir)?;
    }
    Ok(Ok(()))
}

/// `POST /v2/uploads/{upload_id}/finalize` (L1148, L1168-L1174): the exact
/// manifest and commit request bind this upload, the whole object hashes to
/// its terms and passes the public envelope grammar, and it becomes immutable
/// before `READY` and the stored response commit. The version does not move.
pub async fn finalize_upload(
    State(app): State<AppState>,
    who: Principal,
    Path(upload): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let v = verified(&app)?;
    let presented = session_of(who)?;
    let upload_id = id_path(&upload)?;
    let outer = outer_request(v, &headers, &body, OperationKind::FinalizeUpload)?;
    let req = FinalizeUploadV2::parse(&outer.canonical_payload_bytes).map_err(snapshot_error)?;
    if req.commit().upload_id() != &upload_id {
        return Err(column_mismatch(
            "the path names another upload than the request",
        ));
    }

    let w = writer(upload_id)?;
    let mut tx = app.db.begin_with("BEGIN IMMEDIATE").await?;
    let now = now_ms();
    let s = reload_session(&mut tx, &presented, v, now)
        .await?
        .ok_or(AppError::Unauthorized)?;
    if &s.tenant_id != req.tenant_id() {
        return Err(AppError::Forbidden);
    }
    if let Some(row) =
        ledger_row(&mut tx, v, &s, outer.operation_kind, &outer.idempotency_key).await?
    {
        // L970: the same READY receipt, unless a restore dropped the upload.
        let (_, response) = replay(&row, &outer, &body, RECORD_TYPE_UPLOAD_FINALIZED, v)?;
        load(&mut tx, v, &s.tenant_id, &upload_id)
            .await?
            .ok_or_else(not_found)?;
        tx.commit().await?;
        return Ok(cbor(StatusCode::OK, response));
    }

    let u = load(&mut tx, v, &s.tenant_id, &upload_id)
        .await?
        .filter(|u| u.expires_at_ms > now)
        .ok_or_else(not_found)?;
    if u.state == "QUARANTINED" {
        return Err(quarantined());
    }
    // FINALIZING is a finalize that failed after its first write.
    if !(u.state == "OPEN" || u.state == "FINALIZING") || u.committed_offset != u.size {
        return Err(offset_mismatch());
    }
    if !may(
        &mut tx,
        v,
        &s,
        &u.p.fleet_id,
        Some(&u.p.profile_id),
        Capability::ProfileCommit,
        true,
        now,
    )
    .await?
    {
        return Err(AppError::Forbidden);
    }
    held_lease(&mut tx, &u.p, &s, &u.lease, now).await?;
    let request = verify_signed(&mut tx, &s, req.into_commit()).await?;
    bind(&u, request.manifest(), v)?;
    sqlx::query(
        "UPDATE v2_uploads SET state = 'FINALIZING'
          WHERE server_instance_id = ? AND tenant_id = ? AND upload_id = ?",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(s.tenant_id.as_slice())
    .bind(upload_id.as_slice())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    let object: PathBuf = fleet::object_path(
        FsPath::new(&app.cfg.blob_dir),
        &s.tenant_id,
        &u.p.profile_id,
        &u.snapshot_id,
    );
    let staging = PathBuf::from(&u.staging_path);
    // The writer goes with the blocking task and is held to the READY write.
    let (outcome, u, _w) =
        tokio::task::spawn_blocking(move || (promote(&staging, &object, &u), u, w))
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
    let refused = match outcome {
        Err(e) => return Err(AppError::Internal(e.to_string())),
        Ok(refused) => refused,
    };
    let mut tx = app.db.begin_with("BEGIN IMMEDIATE").await?;
    if let Err(code) = refused {
        quarantine(&mut tx, v, &s, &upload_id).await?;
        tx.commit().await?;
        return Err(coded(
            StatusCode::UNPROCESSABLE_ENTITY,
            code,
            "the uploaded object does not match its terms",
        ));
    }

    let now = now_ms();
    let payload = UploadFinalizedV2 {
        upload_id,
        snapshot_id: u.snapshot_id,
        manifest_replay_id: u.manifest_replay_id,
        ciphertext_size: u.size,
        ciphertext_sha256: u.sha256,
        object_receipt_id: random::<16>()?,
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
        RECORD_TYPE_UPLOAD_FINALIZED,
        payload,
        now,
        "profile.finalize_upload",
        ("upload", &upload_id),
    )
    .await?;
    let c = request.request();
    let object = fleet::object_path(
        FsPath::new(&app.cfg.blob_dir),
        &s.tenant_id,
        &u.p.profile_id,
        &u.snapshot_id,
    );
    sqlx::query(
        "UPDATE v2_uploads
            SET state = 'READY', immutable_path = ?, signed_manifest_container_bytes = ?,
                signed_manifest_container_hash = ?, signed_manifest_container_bytes_sha256 = ?,
                exact_commit_request_bytes = ?, exact_commit_request_bytes_sha256 = ?,
                exact_finalize_response_bytes = ?
          WHERE server_instance_id = ? AND tenant_id = ? AND upload_id = ?",
    )
    .bind(object.to_string_lossy().to_string())
    .bind(c.manifest().exact_bytes())
    .bind(c.manifest().signed_container_hash().as_slice())
    .bind(c.manifest().exact_bytes_sha256().as_slice())
    .bind(c.exact_bytes())
    .bind(c.exact_bytes_sha256().as_slice())
    .bind(&response)
    .bind(v.server_instance_id.as_slice())
    .bind(s.tenant_id.as_slice())
    .bind(upload_id.as_slice())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(cbor(StatusCode::OK, response))
}

// ----------------------------------------------------------------- COMMIT ---

/// `POST /v2/uploads/{upload_id}/commit` (L1151, L1174): the exact request
/// finalize stored, signed by the lease holder under the fleet's ACTIVE
/// generation, on the profile's current version and head. One transaction
/// inserts the snapshot through the upload FK, moves the version, deletes the
/// lease, marks the upload `COMMITTED`, and stores the exact receipt and the
/// audit row. A retry gets the stored receipt, even after the lease is gone.
pub async fn commit_upload(
    State(app): State<AppState>,
    who: Principal,
    Path(upload): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let v = verified(&app)?;
    let presented = session_of(who)?;
    let upload_id = id_path(&upload)?;
    exact_cbor_body(&headers, &body, MAX_COMMIT_REQUEST_BYTES)?;
    let req = CommitRequestV2::parse(&body).map_err(snapshot_error)?;
    if req.upload_id() != &upload_id {
        return Err(column_mismatch(
            "the path names another upload than the request",
        ));
    }

    let mut tx = app.db.begin_with("BEGIN IMMEDIATE").await?;
    let now = now_ms();
    let s = reload_session(&mut tx, &presented, v, now)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let stored = sqlx::query(
        "SELECT canonical_request_hash, exact_response_bytes FROM v2_idempotency
          WHERE server_instance_id = ? AND tenant_id = ? AND actor_device_id = ?
            AND operation_scope = ? AND idempotency_key = ?",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(s.tenant_id.as_slice())
    .bind(s.device_id.as_slice())
    .bind(OPERATION_SCOPE_COMMIT)
    .bind(req.idempotency_key().as_slice())
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(row) = stored {
        // L561: the same key answers only the same request; a canonical
        // request has one encoding.
        if blob::<32>(&row, "canonical_request_hash")? != *req.canonical_request_hash() {
            return Err(mismatch());
        }
        let receipt: Vec<u8> = row.get("exact_response_bytes");
        let bound = CommitReceiptBindingV2::parse(&receipt).map_err(snapshot_error)?;
        bound.check_binds(&req).map_err(snapshot_error)?;
        // ADR 0002 D-1: a commit a restore rolled back is not replayed.
        let kept: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM v2_snapshots
                             WHERE server_instance_id = ? AND tenant_id = ? AND upload_id = ?
                               AND version = ? AND snapshot_id = ?)",
        )
        .bind(v.server_instance_id.as_slice())
        .bind(s.tenant_id.as_slice())
        .bind(req.upload_id().as_slice())
        .bind(sql_int(bound.resulting_version)?)
        .bind(bound.snapshot_id.as_slice())
        .fetch_one(&mut *tx)
        .await?;
        if !kept {
            return Err(conflict(
                "BASE_VERSION_MISMATCH",
                "a restore rolled this commit back",
            ));
        }
        tx.commit().await?;
        return Ok(cbor(StatusCode::CREATED, receipt));
    }

    let u = load(&mut tx, v, &s.tenant_id, &upload_id)
        .await?
        .filter(|u| u.expires_at_ms > now)
        .ok_or_else(not_found)?;
    // L1174: byte-identical to the request finalize bound to this upload.
    if u.commit_request.as_deref() != Some(&body[..]) {
        return Err(replay_mismatch("exact_commit_request_bytes"));
    }
    if !may(
        &mut tx,
        v,
        &s,
        &u.p.fleet_id,
        Some(&u.p.profile_id),
        Capability::ProfileCommit,
        true,
        now,
    )
    .await?
    {
        return Err(AppError::Forbidden);
    }
    held_lease(&mut tx, &u.p, &s, &u.lease, now).await?;
    let request = verify_signed(&mut tx, &s, req).await?;
    let m = request.manifest();
    // The generation must still be the fleet's ACTIVE one (plan L517-L518).
    if active_key(&mut tx, v, &s.tenant_id, &u.p.fleet_id).await?
        != Some((m.key_generation, m.fkek_key_id))
    {
        return Err(no_active_key());
    }
    let (current_version, _) = published(&mut tx, &u.p).await?.ok_or_else(not_found)?;
    if current_version != m.base_version
        || head(&mut tx, v, &u.p, current_version).await? != m.previous_signed_head_hash
    {
        return Err(conflict(
            "BASE_VERSION_MISMATCH",
            "the profile is not at the manifest's base version and head",
        ));
    }

    let c = request.request();
    let container = c.manifest();
    let receipt = CommitReceiptBindingV2::for_request(
        &request,
        LeaseReleaseOutcome::Released,
        u64::try_from(now).unwrap_or_default(),
        random::<16>()?,
    )
    .encode();
    sqlx::query(
        "INSERT INTO v2_snapshots
             (server_instance_id, tenant_id, fleet_id, profile_id, version, snapshot_id,
              manifest_replay_id, upload_id, fkek_key_id, key_generation, envelope_version,
              intent_hash, preamble_sha256, dek_slot_sha256, immutable_blob_path,
              ciphertext_sha256, ciphertext_size, signed_manifest_container_bytes,
              signed_manifest_container_hash, signed_manifest_container_bytes_sha256,
              previous_head_hash, head_hash, signing_key_id, signature_suite_id,
              signature_version, signature_bytes, restore_epoch, created_by_device,
              created_at_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 2, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                 ?, ?)",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(s.tenant_id.as_slice())
    .bind(m.fleet_id.as_slice())
    .bind(m.profile_id.as_slice())
    .bind(sql_int(m.target_version)?)
    .bind(m.snapshot_id.as_slice())
    .bind(m.manifest_replay_id.as_slice())
    .bind(upload_id.as_slice())
    .bind(m.fkek_key_id.as_slice())
    .bind(sql_int(m.key_generation)?)
    .bind(m.intent_hash.as_slice())
    .bind(m.preamble_sha256.as_slice())
    .bind(m.dek_slot_sha256.as_slice())
    .bind(u.immutable_path.as_deref())
    .bind(m.ciphertext_sha256.as_slice())
    .bind(sql_int(m.ciphertext_size)?)
    .bind(container.exact_bytes())
    .bind(container.signed_container_hash().as_slice())
    .bind(container.exact_bytes_sha256().as_slice())
    .bind(m.previous_signed_head_hash.as_ref().map(|h| h.as_slice()))
    .bind(container.head_hash().as_slice())
    .bind(m.signer_signing_key_id.as_slice())
    .bind(i64::from(shared::signing::SIGNATURE_SUITE_ID_ED25519))
    .bind(i64::from(shared::signing::SIGNATURE_VERSION))
    .bind(container.signature_bytes())
    .bind(sql_int(m.restore_epoch)?)
    .bind(s.device_id.as_slice())
    .bind(now)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE v2_profiles SET current_version = ?, updated_at = ? WHERE tenant_id = ? AND id = ?",
    )
    .bind(sql_int(m.target_version)?)
    .bind(crate::util::now_rfc3339())
    .bind(s.tenant_id.as_slice())
    .bind(m.profile_id.as_slice())
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM v2_profile_leases WHERE tenant_id = ? AND profile_id = ?")
        .bind(s.tenant_id.as_slice())
        .bind(m.profile_id.as_slice())
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE v2_uploads
            SET state = 'COMMITTED', exact_commit_receipt_binding_bytes = ?,
                commit_receipt_binding_bytes_sha256 = ?
          WHERE server_instance_id = ? AND tenant_id = ? AND upload_id = ?",
    )
    .bind(&receipt)
    .bind(sha256(&receipt).as_slice())
    .bind(v.server_instance_id.as_slice())
    .bind(s.tenant_id.as_slice())
    .bind(upload_id.as_slice())
    .execute(&mut *tx)
    .await?;
    // L1106: kept as long as its snapshot, never by time alone.
    sqlx::query(
        "INSERT INTO v2_idempotency
             (server_instance_id, tenant_id, actor_device_id, operation_scope, idempotency_key,
              operation_kind, canonical_request_hash, exact_request_bytes,
              exact_request_bytes_sha256, status, response_record_type, exact_response_bytes,
              exact_response_bytes_sha256, retained_until)
         VALUES (?, ?, ?, ?, ?, 'COMMIT', ?, ?, ?, 'succeeded', ?, ?, ?, ?)",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(s.tenant_id.as_slice())
    .bind(s.device_id.as_slice())
    .bind(OPERATION_SCOPE_COMMIT)
    .bind(c.idempotency_key().as_slice())
    .bind(c.canonical_request_hash().as_slice())
    .bind(c.exact_bytes())
    .bind(c.exact_bytes_sha256().as_slice())
    .bind(RECORD_TYPE_COMMIT_RECEIPT)
    .bind(&receipt)
    .bind(sha256(&receipt).as_slice())
    .bind(i64::MAX)
    .execute(&mut *tx)
    .await?;
    audit(
        &mut tx,
        &s.tenant_id,
        &s.account_id,
        &s.device_id,
        "profile.commit",
        "snapshot",
        &m.snapshot_id,
    )
    .await?;
    tx.commit().await?;
    Ok(cbor(StatusCode::CREATED, receipt))
}

// ------------------------------------------------------------- readback ---

/// A committed version's stored object and exact signed manifest.
struct Committed {
    path: String,
    size: u64,
    sha256: [u8; 32],
    key_generation: u64,
    fkek_key_id: [u8; 32],
    manifest: Vec<u8>,
}

/// The snapshot row of `version`, for a session holding `profile.checkout`
/// on the profile or its fleet.
async fn committed(
    app: &AppState,
    who: Principal,
    profile: &str,
    version: &str,
) -> Result<Committed, AppError> {
    let v = verified(app)?;
    let presented = session_of(who)?;
    let profile = id_path(profile)?;
    let version: u64 = version
        .parse()
        .map_err(|_| AppError::BadRequest("a version is a decimal number".into()))?;
    let mut conn = app.db.acquire().await?;
    let now = now_ms();
    let s = reload_session(&mut conn, &presented, v, now)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let row = sqlx::query(
        "SELECT * FROM v2_snapshots
          WHERE server_instance_id = ? AND tenant_id = ? AND profile_id = ? AND version = ?",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(s.tenant_id.as_slice())
    .bind(profile.as_slice())
    .bind(sql_int(version)?)
    .fetch_optional(&mut *conn)
    .await?
    .ok_or_else(not_found)?;
    let fleet = blob::<16>(&row, "fleet_id")?;
    if !may(
        &mut conn,
        v,
        &s,
        &fleet,
        Some(&profile),
        Capability::ProfileCheckout,
        false,
        now,
    )
    .await?
    {
        return Err(AppError::Forbidden);
    }
    Ok(Committed {
        path: row.get("immutable_blob_path"),
        size: stored_uint(row.get("ciphertext_size"))?,
        sha256: blob::<32>(&row, "ciphertext_sha256")?,
        key_generation: stored_uint(row.get("key_generation"))?,
        fkek_key_id: blob::<32>(&row, "fkek_key_id")?,
        manifest: row.get("signed_manifest_container_bytes"),
    })
}

/// `GET /v2/profiles/{profile_id}/snapshots/{version}/manifest`: the exact
/// detached signed manifest, verified by the client before it decrypts.
pub async fn read_snapshot_manifest(
    State(app): State<AppState>,
    who: Principal,
    Path((profile, version)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let c = committed(&app, who, &profile, &version).await?;
    Ok(cbor(StatusCode::OK, c.manifest))
}

/// One `bytes=start-end` or `bytes=start-` range inside an object of `size`
/// bytes, at most [`MAX_CHUNK_BYTES`] long.
fn range(headers: &HeaderMap, size: u64) -> Result<Option<(u64, u64)>, AppError> {
    let Some(h) = headers.get(header::RANGE) else {
        return Ok(None);
    };
    let unsatisfiable = || {
        coded(
            StatusCode::RANGE_NOT_SATISFIABLE,
            "RANGE_NOT_SATISFIABLE",
            "send one range inside the object",
        )
    };
    let (start, end) = h
        .to_str()
        .ok()
        .and_then(|h| h.strip_prefix("bytes="))
        .and_then(|r| r.split_once('-'))
        .ok_or_else(unsatisfiable)?;
    let start: u64 = start.parse().map_err(|_| unsatisfiable())?;
    let end: u64 = match end {
        "" => size - 1,
        e => e.parse().map_err(|_| unsatisfiable())?,
    };
    if start >= size || end < start {
        return Err(unsatisfiable());
    }
    let end = end.min(size - 1).min(start + MAX_CHUNK_BYTES as u64 - 1);
    Ok(Some((start, end)))
}

/// `GET /v2/profiles/{profile_id}/snapshots/{version}` (L1153): the immutable
/// ciphertext, whole or one `Range`, with `ETag` = its SHA-256 and its FKEK
/// generation. The manifest is at `.../manifest`.
pub async fn read_snapshot(
    State(app): State<AppState>,
    who: Principal,
    Path((profile, version)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let c = committed(&app, who, &profile, &version).await?;
    let etag = format!("\"{}\"", crate::identity::hex(&c.sha256));
    let meta = [
        ("etag", etag),
        ("shardx-key-generation", c.key_generation.to_string()),
        ("shardx-fkek-key-id", crate::identity::hex(&c.fkek_key_id)),
        (
            "shardx-signed-manifest-url",
            format!("/v2/profiles/{profile}/snapshots/{version}/manifest"),
        ),
    ];
    let mut response = match range(&headers, c.size)? {
        Some((start, end)) => {
            let len = usize::try_from(end - start + 1).unwrap_or(MAX_CHUNK_BYTES);
            let bytes = fleet::read_range(FsPath::new(&c.path), start, len)
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?;
            let mut r = (StatusCode::PARTIAL_CONTENT, bytes).into_response();
            r.headers_mut().insert(
                header::CONTENT_RANGE,
                format!("bytes {start}-{end}/{}", c.size)
                    .parse()
                    .map_err(|_| AppError::Internal("a content range".into()))?,
            );
            r
        }
        None => {
            let file = tokio::fs::File::open(&c.path)
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?;
            let stream = tokio_util::io::ReaderStream::new(file);
            let mut r = (StatusCode::OK, Body::from_stream(stream)).into_response();
            r.headers_mut()
                .insert(header::CONTENT_LENGTH, c.size.into());
            r
        }
    };
    for (name, value) in meta {
        response.headers_mut().insert(
            header::HeaderName::from_static(name),
            value
                .parse()
                .map_err(|_| AppError::Internal("a header value".into()))?,
        );
    }
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/octet-stream"),
    );
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::writer;

    #[test]
    fn one_writer_holds_an_upload_until_it_drops() {
        let first = writer([0x71; 16]);
        assert!(first.is_ok());
        assert!(writer([0x71; 16]).is_err());
        assert!(writer([0x72; 16]).is_ok());
        drop(first);
        assert!(writer([0x71; 16]).is_ok());
    }
}
