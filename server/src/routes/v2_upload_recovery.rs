//! The startup upload reconciler and GC (plan 8.1 L1157-L1216).
//!
//! Before v2 writes open, every `OPEN`, `FINALIZING`, `READY` and `COMMITTED`
//! upload is classified by its receipt `R`, immutable object `I` and staging
//! file `S` (L1182-L1185) and gets the one action its row of the L1187-L1214
//! table names ([`decide`]). An upload is re-read after each write and settles
//! in a few steps; a failed step is retried a bounded number of times, with a
//! short backoff, and then quarantines the upload with a reason code (L1216).
//! No pass deletes quarantined evidence or an immutable object, so a second
//! pass changes nothing.
//!
//! A COMMITTED upload keeps its state when it quarantines: 0026 binds that
//! state to the exact receipt. Its `v2_upload_quarantine` row is the
//! quarantine, and its snapshot is no longer served. A quarantine row is never
//! removed, so the pass fails closed instead, writing none, when the evidence
//! may only be out of reach: the blob root is missing (a volume not mounted,
//! another data directory), a COMMITTED object is missing, or a COMMITTED
//! upload keeps failing. v2 writes stay off until an operator fixes it.
//!
//! GC (L1175-L1176): expired OPEN uploads are ABORTED and every ABORTED
//! upload's staging file goes.
//!
//! shortcut: an unreferenced immutable object (a READY upload aborted or never
//! committed) stays on disk. L1176 deletes one only "after grace + audit", the
//! plan sets no grace, and `v2_audit_events` takes an actor-less row only from
//! the offline CLI (0010); add that GC with a grace value and a system actor.
//! shortcut: every start re-hashes every COMMITTED object before the listener
//! binds, so startup time grows with the stored ciphertext; move to
//! incremental verification (a verified-at mark per object, re-hashed on
//! change or on a schedule) once that exceeds the readiness budget.

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail};
use sha2::{Digest, Sha256};
use sqlx::sqlite::SqliteRow;
use sqlx::{Row, SqliteConnection, SqlitePool};

use shared::canonical::sha256;
use shared::snapshot_v2::{CommitReceiptBindingV2, CommitRequestV2, OPERATION_SCOPE_COMMIT};

use super::v2_uploads::{promote, ready, upload, writer, Upload};
use crate::error::AppError;
use crate::fleet;
use crate::identity::Verified;
use crate::util::{now_ms, stored_uint};

/// Tries per upload before its failure quarantines it (L1216).
const ATTEMPTS: usize = 3;
/// The wait before try `n + 1` is `n` times this: a file another process
/// holds for a moment (an antivirus scan) is not a quarantine.
const BACKOFF_MS: u64 = 200;
/// The longest chain of rows one upload walks: L1197, L1206, L1213, L1212.
const STEPS: usize = 4;

/// One input of the L1182-L1184 classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum C {
    /// `Ø`
    Absent,
    /// `V`
    Valid,
    /// `X`
    Invalid,
}

use C::{Absent, Invalid, Valid};

#[derive(Debug, PartialEq, Eq)]
enum Action {
    Keep,
    /// The reason code, and whether it is a security incident.
    Quarantine(&'static str, bool),
    /// Re-hash, rename if still staged, flush file and directory, then store
    /// the READY response and CAS `READY` ([`ready`]).
    Promote,
    /// CAS `COMMITTED` with the exact receipt.
    Commit,
    /// Delete the staging file, which a re-read then shows gone.
    DropStaging,
}

/// The L1187-L1214 table, read top-down within the state. The next re-read
/// does what an action leaves to "after durable CAS/readback".
fn decide(state: &str, r: C, i: C, s: C) -> Action {
    use Action::*;
    match (state, r, i, s) {
        // L1189
        ("OPEN", Valid | Invalid, _, _) => Quarantine("receipt_before_finalize", true),
        // L1190
        ("OPEN", Absent, Valid | Invalid, _) => Quarantine("object_before_finalize", false),
        // L1191
        ("OPEN", Absent, Absent, Invalid) => Quarantine("staging_invalid", false),
        // L1192, L1193 (`S` is `Ø` only at offset 0: see `staged`)
        ("OPEN", Absent, Absent, Valid | Absent) => Keep,
        // L1194
        ("FINALIZING", Invalid, _, _) => Quarantine("receipt_invalid", true),
        // L1195
        ("FINALIZING", _, Invalid, _) => Quarantine("object_invalid", false),
        // L1196
        ("FINALIZING", _, _, Invalid) => Quarantine("staging_invalid", false),
        // L1197: READY first, then L1206 commits and L1213 drops the staging.
        ("FINALIZING", Valid, Valid, _) => Promote,
        // L1198
        ("FINALIZING", Valid, Absent, _) => Quarantine("receipt_without_object", true),
        // L1199, L1200 (the object wins; L1208 then drops the staging)
        ("FINALIZING", Absent, Valid, _) => Promote,
        // L1201
        ("FINALIZING", Absent, Absent, Valid) => Promote,
        // L1202
        ("FINALIZING", Absent, Absent, Absent) => Quarantine("bytes_missing", false),
        // L1203
        ("READY", Invalid, _, _) => Quarantine("receipt_invalid", true),
        // L1204
        ("READY", _, Invalid | Absent, _) => Quarantine("object_invalid", false),
        // L1205
        ("READY", _, Valid, Invalid) => Quarantine("staging_invalid", false),
        // L1206
        ("READY", Valid, Valid, _) => Commit,
        // L1207
        ("READY", Absent, Valid, Absent) => Keep,
        // L1208
        ("READY", Absent, Valid, Valid) => DropStaging,
        // L1209
        ("COMMITTED", Invalid | Absent, _, _) => Quarantine("receipt_invalid", true),
        // L1210 (`I = Ø` fails the pass first: see `run`)
        ("COMMITTED", Valid, Invalid | Absent, _) => Quarantine("object_invalid", true),
        // L1211
        ("COMMITTED", Valid, Valid, Invalid) => Quarantine("staging_invalid", false),
        // L1212
        ("COMMITTED", Valid, Valid, Absent) => Keep,
        // L1213
        ("COMMITTED", Valid, Valid, Valid) => DropStaging,
        // L1214: QUARANTINED and ABORTED never reach the table, and the arms
        // above cover every other input (a test enumerates them). Fail closed.
        _ => Quarantine("unclassified", true),
    }
}

/// What a pass did, for the startup log.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub kept: usize,
    pub promoted: usize,
    pub committed: usize,
    pub quarantined: usize,
    /// Failed steps tried again (L1216).
    pub retried: usize,
    pub staging_removed: usize,
    pub aborted: usize,
}

/// One pass over every upload of this instance, then GC; an error keeps v2
/// writes off (L1216).
pub async fn run(pool: &SqlitePool, v: &Verified, blob_dir: &str) -> anyhow::Result<Report> {
    let root = Path::new(blob_dir);
    let mut report = Report::default();
    // L1214: a QUARANTINED upload, or one with a quarantine row, stays as it
    // is; ABORTED is GC's.
    let ids: Vec<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT tenant_id, upload_id FROM v2_uploads u
          WHERE server_instance_id = ? AND state IN ('OPEN', 'FINALIZING', 'READY', 'COMMITTED')
            AND NOT EXISTS (SELECT 1 FROM v2_upload_quarantine q
                             WHERE q.server_instance_id = u.server_instance_id
                               AND q.tenant_id = u.tenant_id AND q.upload_id = u.upload_id)",
    )
    .bind(v.server_instance_id.as_slice())
    .fetch_all(pool)
    .await?;
    if !ids.is_empty() && !root.try_exists()? {
        bail!(
            "the blob root {} is missing; mount it or fix SHARDX_DATA_DIR",
            root.display()
        );
    }
    out_of_reach(pool, v).await?;
    for (tenant, id) in ids {
        let mut attempt = 0;
        loop {
            attempt += 1;
            let mut conn = pool.acquire().await?;
            let Err(e) = settle(&mut conn, v, root, &tenant, &id, &mut report).await else {
                break;
            };
            if attempt < ATTEMPTS {
                report.retried += 1;
                tracing::warn!("upload reconciliation retry {attempt}: {e:#}");
                drop(conn);
                tokio::time::sleep(Duration::from_millis(BACKOFF_MS * attempt as u64)).await;
                continue;
            }
            let state: String = sqlx::query_scalar(
                "SELECT state FROM v2_uploads
                  WHERE server_instance_id = ? AND tenant_id = ? AND upload_id = ?",
            )
            .bind(v.server_instance_id.as_slice())
            .bind(&tenant)
            .bind(&id)
            .fetch_one(&mut *conn)
            .await?;
            if state == "COMMITTED" {
                return Err(e.context("a COMMITTED upload keeps failing; v2 writes stay off"));
            }
            tracing::warn!("upload reconciliation failed: {e:#}");
            quarantine(
                &mut conn,
                v,
                &tenant,
                &id,
                &state,
                "reconcile_failed",
                false,
            )
            .await?;
            report.quarantined += 1;
            break;
        }
    }
    gc(pool, v, &mut report).await?;
    gate(pool, v).await?;
    Ok(report)
}

/// Fails the pass when a COMMITTED object is missing (L1210 `I = Ø`): that is
/// more often a path out of reach than a lost object, and its quarantine
/// could never be undone.
async fn out_of_reach(pool: &SqlitePool, v: &Verified) -> anyhow::Result<()> {
    let paths: Vec<String> = sqlx::query_scalar(
        "SELECT immutable_path FROM v2_uploads u
          WHERE server_instance_id = ? AND state = 'COMMITTED'
            AND NOT EXISTS (SELECT 1 FROM v2_upload_quarantine q
                             WHERE q.server_instance_id = u.server_instance_id
                               AND q.tenant_id = u.tenant_id AND q.upload_id = u.upload_id)",
    )
    .bind(v.server_instance_id.as_slice())
    .fetch_all(pool)
    .await?;
    let missing = tokio::task::spawn_blocking(move || {
        paths
            .iter()
            .map(|p| Path::new(p).try_exists())
            .filter(|e| !matches!(e, Ok(true)))
            .count()
    })
    .await?;
    if missing > 0 {
        bail!("{missing} committed object(s) are missing or unreadable; is the blob root right?");
    }
    Ok(())
}

/// L1216: v2 writes stay off until no FINALIZING upload is left.
async fn gate(pool: &SqlitePool, v: &Verified) -> anyhow::Result<()> {
    let left: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM v2_uploads WHERE server_instance_id = ? AND state = 'FINALIZING'",
    )
    .bind(v.server_instance_id.as_slice())
    .fetch_one(pool)
    .await?;
    if left > 0 {
        bail!("{left} FINALIZING upload(s) left after reconciliation");
    }
    Ok(())
}

/// GC (L1175): expired OPEN uploads are dead and become ABORTED; an ABORTED
/// upload's staging file has no use. Immutable objects are not touched.
async fn gc(pool: &SqlitePool, v: &Verified, report: &mut Report) -> anyhow::Result<()> {
    report.aborted += sqlx::query(
        "UPDATE v2_uploads SET state = 'ABORTED'
          WHERE server_instance_id = ? AND state = 'OPEN' AND expires_at_ms <= ?",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(now_ms())
    .execute(pool)
    .await?
    .rows_affected() as usize;
    let staged: Vec<String> = sqlx::query_scalar(
        "SELECT staging_path FROM v2_uploads WHERE server_instance_id = ? AND state = 'ABORTED'",
    )
    .bind(v.server_instance_id.as_slice())
    .fetch_all(pool)
    .await?;
    for path in staged {
        match std::fs::remove_file(&path) {
            Ok(()) => report.staging_removed += 1,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            // A file left behind costs only disk; the next start tries again.
            Err(e) => tracing::warn!("could not remove an aborted staging file: {e}"),
        }
    }
    Ok(())
}

fn app(e: AppError) -> anyhow::Error {
    anyhow!("{e:?}")
}

/// Walks one upload through the table until an action keeps it or it
/// quarantines, under its writer (L1216). File work runs off the runtime.
async fn settle(
    conn: &mut SqliteConnection,
    v: &Verified,
    root: &Path,
    tenant: &[u8],
    id: &[u8],
    report: &mut Report,
) -> anyhow::Result<()> {
    let upload_id: [u8; 16] = id.try_into()?;
    let _w = writer(upload_id).map_err(app)?;
    for _ in 0..STEPS {
        let row: SqliteRow = sqlx::query(
            "SELECT * FROM v2_uploads
              WHERE server_instance_id = ? AND tenant_id = ? AND upload_id = ?",
        )
        .bind(v.server_instance_id.as_slice())
        .bind(tenant)
        .bind(id)
        .fetch_one(&mut *conn)
        .await?;
        let u = upload(&row).map_err(app)?;
        let object = match &u.immutable_path {
            Some(p) => PathBuf::from(p),
            None => fleet::object_path(root, &u.p.tenant_id, &u.p.profile_id, &u.snapshot_id),
        };
        let staging = PathBuf::from(&u.staging_path);
        let (r, receipt) = receipt(conn, v, &row, &u).await?;
        let chunks = chunks(conn, v, id, &u).await?;
        fault(id, "io")?;
        let (files, u) = blocking({
            let (object, staging) = (object.clone(), staging.clone());
            move || (files(&object, &staging, &u, chunks), u)
        })
        .await?;
        let (i, s) = files?;
        match decide(&u.state, r, i, s) {
            Action::Keep => {
                report.kept += 1;
                return Ok(());
            }
            Action::Quarantine(reason, security) => {
                quarantine(conn, v, tenant, id, &u.state, reason, security).await?;
                report.quarantined += 1;
                return Ok(());
            }
            Action::Promote => {
                let (promoted, u) = blocking({
                    let (object, staging) = (object.clone(), staging.clone());
                    move || (promote(&staging, &object, &u), u)
                })
                .await?;
                if let Err(code) = promoted? {
                    quarantine(conn, v, tenant, id, &u.state, code, false).await?;
                    report.quarantined += 1;
                    return Ok(());
                }
                fault(id, "cas")?;
                let mut tx = sqlx::Connection::begin(&mut *conn).await?;
                ready(&mut tx, v, &u, &upload_id).await.map_err(app)?;
                tx.commit().await?;
                report.promoted += 1;
            }
            Action::Commit => {
                let receipt = receipt.ok_or_else(|| anyhow!("a valid receipt has bytes"))?;
                fault(id, "cas")?;
                commit(conn, v, tenant, id, &receipt).await?;
                report.committed += 1;
            }
            Action::DropStaging => {
                std::fs::remove_file(&staging)?;
                if let Some(dir) = staging.parent() {
                    crate::identity::sync_dir(dir)?;
                }
                report.staging_removed += 1;
            }
        }
    }
    bail!("an upload did not settle in {STEPS} steps")
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> anyhow::Result<T> {
    Ok(tokio::task::spawn_blocking(f).await?)
}

/// `READY -> COMMITTED`, storing the exact receipt the ledger holds (L1206).
/// A CAS that misses is seen by the next re-read.
async fn commit(
    conn: &mut SqliteConnection,
    v: &Verified,
    tenant: &[u8],
    id: &[u8],
    receipt: &[u8],
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE v2_uploads
            SET state = 'COMMITTED', exact_commit_receipt_binding_bytes = ?,
                commit_receipt_binding_bytes_sha256 = ?
          WHERE server_instance_id = ? AND tenant_id = ? AND upload_id = ? AND state = 'READY'",
    )
    .bind(receipt)
    .bind(sha256(receipt).as_slice())
    .bind(v.server_instance_id.as_slice())
    .bind(tenant)
    .bind(id)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Quarantines with `reason` (L1216). The state moves where 0026/0027 let it;
/// a COMMITTED upload is quarantined by its row alone. Evidence stays.
async fn quarantine(
    conn: &mut SqliteConnection,
    v: &Verified,
    tenant: &[u8],
    id: &[u8],
    from: &str,
    reason: &str,
    security: bool,
) -> anyhow::Result<()> {
    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    sqlx::query(
        "UPDATE v2_uploads SET state = 'QUARANTINED'
          WHERE server_instance_id = ? AND tenant_id = ? AND upload_id = ?
            AND state IN ('OPEN', 'FINALIZING', 'READY')",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(tenant)
    .bind(id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO v2_upload_quarantine
             (server_instance_id, tenant_id, upload_id, from_state, reason, security_incident,
              created_at_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(tenant)
    .bind(id)
    .bind(from)
    .bind(reason)
    .bind(i64::from(security))
    .bind(now_ms())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    if security {
        tracing::error!(reason, from, "security incident: quarantined an upload");
    } else {
        tracing::warn!(reason, from, "quarantined an upload");
    }
    Ok(())
}

/// `R` (L1184): `V` only when the ledger holds the exact receipt, any stored
/// copy is the same bytes and hash, it binds the exact request, and the one
/// snapshot of this upload has its version, head, manifest, object path and
/// ciphertext hash, at or below the profile's version. Returns the receipt
/// bytes when `V`.
async fn receipt(
    conn: &mut SqliteConnection,
    v: &Verified,
    row: &SqliteRow,
    u: &Upload,
) -> anyhow::Result<(C, Option<Vec<u8>>)> {
    let id: Vec<u8> = row.get("upload_id");
    let snapshots = sqlx::query(
        "SELECT version, head_hash, signed_manifest_container_bytes, immutable_blob_path,
                ciphertext_sha256
           FROM v2_snapshots
          WHERE server_instance_id = ? AND tenant_id = ? AND upload_id = ?",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(u.p.tenant_id.as_slice())
    .bind(&id)
    .fetch_all(&mut *conn)
    .await?;
    let request = u
        .commit_request
        .as_deref()
        .and_then(|r| CommitRequestV2::parse(r).ok());
    // By the commit's key (0027's index), then its exact bytes.
    let ledger: Option<Vec<u8>> = match &request {
        Some(request) => sqlx::query_scalar(
            "SELECT exact_response_bytes FROM v2_idempotency
              WHERE server_instance_id = ? AND tenant_id = ? AND operation_scope = ?
                AND idempotency_key = ? AND exact_request_bytes = ?",
        )
        .bind(v.server_instance_id.as_slice())
        .bind(u.p.tenant_id.as_slice())
        .bind(OPERATION_SCOPE_COMMIT)
        .bind(request.idempotency_key().as_slice())
        .bind(request.exact_bytes())
        .fetch_optional(&mut *conn)
        .await?
        .flatten(),
        None => None,
    };
    // Only a COMMITTED upload stores the receipt (0026), and its Ø and X are
    // one row (L1209).
    if snapshots.is_empty() && ledger.is_none() {
        return Ok((Absent, None));
    }
    let stored: Option<Vec<u8>> = row.get("exact_commit_receipt_binding_bytes");
    let current: Option<i64> = sqlx::query_scalar(
        "SELECT current_version FROM v2_profiles WHERE tenant_id = ? AND id = ?",
    )
    .bind(u.p.tenant_id.as_slice())
    .bind(u.p.profile_id.as_slice())
    .fetch_optional(&mut *conn)
    .await?;
    let manifest: Option<Vec<u8>> = row.get("signed_manifest_container_bytes");
    let stored_sha: Option<Vec<u8>> = row.get("commit_receipt_binding_bytes_sha256");
    let valid = || -> Option<Vec<u8>> {
        let receipt = ledger?;
        if let Some(stored) = &stored {
            if *stored != receipt || stored_sha.as_deref() != Some(&sha256(stored)[..]) {
                return None;
            }
        }
        let bound = CommitReceiptBindingV2::parse(&receipt).ok()?;
        bound.check_binds(request.as_ref()?).ok()?;
        let [snapshot] = snapshots.as_slice() else {
            return None;
        };
        let version: i64 = snapshot.get("version");
        let head: Vec<u8> = snapshot.get("head_hash");
        let bytes: Vec<u8> = snapshot.get("signed_manifest_container_bytes");
        let path: String = snapshot.get("immutable_blob_path");
        let ciphertext: Vec<u8> = snapshot.get("ciphertext_sha256");
        let linked = stored_uint(version).ok()? == bound.resulting_version
            && head == bound.resulting_head_hash
            && manifest.as_deref() == Some(&bytes[..])
            && u.immutable_path.as_deref() == Some(path.as_str())
            && ciphertext == u.sha256
            && current? >= version;
        linked.then_some(receipt)
    };
    Ok(match valid() {
        Some(receipt) => (Valid, Some(receipt)),
        None => (Invalid, None),
    })
}

/// An OPEN upload's chunk receipts, by offset; none for another state.
async fn chunks(
    conn: &mut SqliteConnection,
    v: &Verified,
    id: &[u8],
    u: &Upload,
) -> anyhow::Result<Vec<(i64, i64, Vec<u8>)>> {
    if u.state != "OPEN" {
        return Ok(Vec::new());
    }
    Ok(sqlx::query_as(
        "SELECT chunk_offset, chunk_length, chunk_sha256 FROM v2_upload_chunks
          WHERE server_instance_id = ? AND tenant_id = ? AND upload_id = ?
          ORDER BY chunk_offset",
    )
    .bind(v.server_instance_id.as_slice())
    .bind(u.p.tenant_id.as_slice())
    .bind(id)
    .fetch_all(&mut *conn)
    .await?)
}

/// `I` and `S` of one upload, by blocking file I/O.
fn files(
    object: &Path,
    staging: &Path,
    u: &Upload,
    chunks: Vec<(i64, i64, Vec<u8>)>,
) -> anyhow::Result<(C, C)> {
    Ok((immutable(object, u)?, staged(staging, u, chunks)?))
}

/// `I` (L1183): the object at its path keyed by `snapshot_id` (ADR 0002
/// C-2), with the expected size and hash.
fn immutable(object: &Path, u: &Upload) -> anyhow::Result<C> {
    let keyed = fleet::object_path(
        Path::new(""),
        &u.p.tenant_id,
        &u.p.profile_id,
        &u.snapshot_id,
    );
    if !object.ends_with(keyed) {
        return Ok(Invalid);
    }
    whole(object, u)
}

/// The file at `path` against the upload's expected size and hash.
fn whole(path: &Path, u: &Upload) -> anyhow::Result<C> {
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Absent),
        Err(e) => return Err(e.into()),
    };
    // The hash covers the size.
    let mut h = Sha256::new();
    std::io::copy(&mut f, &mut h)?;
    Ok(if h.finalize()[..] == u.sha256 {
        Valid
    } else {
        Invalid
    })
}

/// `S` (L1182). For OPEN, a tail past the committed offset is cut and flushed
/// first (L1167), and `V` is a prefix whose chunk receipts tile it exactly;
/// a missing file is `Ø` only at offset 0. Otherwise `S` is [`whole`].
fn staged(staging: &Path, u: &Upload, chunks: Vec<(i64, i64, Vec<u8>)>) -> anyhow::Result<C> {
    if u.state != "OPEN" {
        return whole(staging, u);
    }
    let opened = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(staging);
    let mut f = match opened {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(if u.committed_offset == 0 {
                Absent
            } else {
                Invalid
            })
        }
        Err(e) => return Err(e.into()),
    };
    let len = f.metadata()?.len();
    if len > u.committed_offset {
        f.set_len(u.committed_offset)?;
        f.sync_all()?;
    }
    if len < u.committed_offset {
        return Ok(Invalid);
    }
    let mut at = 0u64;
    for (offset, length, digest) in chunks {
        let (offset, length) = (
            stored_uint(offset).map_err(app)?,
            stored_uint(length).map_err(app)?,
        );
        if offset != at || offset + length > u.committed_offset {
            return Ok(Invalid);
        }
        let mut bytes = vec![0; usize::try_from(length)?];
        f.seek(SeekFrom::Start(offset))?;
        f.read_exact(&mut bytes)?;
        if sha256(&bytes)[..] != digest[..] {
            return Ok(Invalid);
        }
        at += length;
    }
    Ok(if at == u.committed_offset {
        Valid
    } else {
        Invalid
    })
}

#[cfg(test)]
static FAULTS: std::sync::Mutex<Vec<(Vec<u8>, &'static str, u32)>> =
    std::sync::Mutex::new(Vec::new());

/// A failure injected at `point` for upload `id` (tests only).
fn fault(id: &[u8], point: &'static str) -> anyhow::Result<()> {
    #[cfg(test)]
    {
        let mut faults = FAULTS.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(f) = faults
            .iter_mut()
            .find(|f| f.0 == id && f.1 == point && f.2 > 0)
        {
            f.2 -= 1;
            bail!("injected fault at {point}");
        }
    }
    let _ = (id, point);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::envelope::{build_dek_slot, IntentIds, IntentNumbers, SlotIds};
    use shared::envelope_v2::{build_intent_v2, seal, MAX_OBJECT_SIZE, MIN_FRAME_PLAINTEXT_SIZE};
    use shared::keys::signing_key_id;
    use shared::mutation::{IdempotentMutationRequestV2, OperationKind};
    use shared::signing::Ed25519SigningKey;
    use shared::snapshot_v2::FinalizeUploadV2;
    use shared::snapshot_v2::{LeaseReleaseOutcome, SignedSnapshotManifestV2, SnapshotManifestV2};
    use sqlx::sqlite::SqlitePoolOptions;

    const INSTANCE: [u8; 16] = [7; 16];
    const TENANT: [u8; 16] = [0x41; 16];
    const FLEET: [u8; 16] = [0xf5; 16];
    const LEASE: [u8; 16] = [0x1e; 16];
    const FKEK: [u8; 32] = [0xe0; 32];
    const DEK: [u8; 32] = [0x2d; 32];
    /// The account and device a finalize ran as.
    const ACTOR: [u8; 16] = [0x5a; 16];
    /// An OPEN upload's committed prefix, one chunk.
    const PREFIX: usize = 500;

    fn identity() -> Verified {
        Verified {
            server_instance_id: INSTANCE,
            restore_epoch: 0,
            external_record_sha256: [0; 32],
        }
    }

    /// A blob root that cleans up after itself.
    struct Dir(PathBuf);

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn dir(tag: &str) -> Dir {
        let d = std::env::temp_dir().join(format!(
            "shardx-upload-recovery-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Dir(d)
    }

    /// The schema with its CHECKs and triggers, without the FK graph above
    /// an upload.
    async fn pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        shardx_team_server::run_migrations(&pool).await.unwrap();
        sqlx::query("PRAGMA foreign_keys = OFF")
            .execute(&pool)
            .await
            .unwrap();
        pool
    }

    /// One upload `[tag; 16]` of profile and snapshot `[tag; 16]`: its sealed
    /// object, exact commit request and exact receipt.
    struct Fixture {
        tag: u8,
        object: Vec<u8>,
        manifest: SnapshotManifestV2,
        request: CommitRequestV2,
        receipt: Vec<u8>,
        bound: CommitReceiptBindingV2,
        /// The exact FINALIZE_UPLOAD request a FINALIZING upload stores.
        finalize: Vec<u8>,
    }

    fn fixture(tag: u8) -> Fixture {
        let (profile_id, snapshot_id, manifest_replay_id) = ([tag; 16], [tag; 16], [!tag; 16]);
        let slot = build_dek_slot(
            &[0x3e; 32],
            &DEK,
            &[tag; shared::keys::WRAP_NONCE_LEN],
            &SlotIds {
                tenant_id: &TENANT,
                fleet_id: &FLEET,
                profile_id: &profile_id,
                snapshot_id: &snapshot_id,
                fkek_key_id: &FKEK,
                envelope_context_nonce: &[tag; 16],
            },
            0,
        )
        .unwrap();
        let sk = Ed25519SigningKey::from_bytes(&[0x6c; 32]);
        let pk = sk.verifying_key().to_bytes();
        let intent = build_intent_v2(
            &IntentIds {
                snapshot_id,
                tenant_id: TENANT,
                fleet_id: FLEET,
                profile_id,
                lease_id: LEASE,
                manifest_replay_id,
                server_instance_id: INSTANCE,
                fkek_key_id: FKEK,
                intended_signer_signing_key_id: signing_key_id(&pk),
            },
            &IntentNumbers {
                target_version: 1,
                base_version: 0,
                fencing_token: 1,
                key_generation: 0,
                restore_epoch: 0,
                frame_plaintext_size: MIN_FRAME_PLAINTEXT_SIZE,
                max_plaintext_size: MAX_OBJECT_SIZE,
                max_ciphertext_size: MAX_OBJECT_SIZE,
                created_at_ms: 1,
            },
            &[tag; 20],
            None,
            &slot,
        )
        .unwrap();
        let mut object = Vec::new();
        let d = seal(
            &mut std::io::Cursor::new(vec![tag; 2000]),
            &mut object,
            &DEK,
            &intent,
            &slot,
        )
        .unwrap();
        let manifest = SnapshotManifestV2 {
            snapshot_id,
            tenant_id: TENANT,
            fleet_id: FLEET,
            profile_id,
            lease_id: LEASE,
            target_version: 1,
            base_version: 0,
            fencing_token: 1,
            key_generation: 0,
            fkek_key_id: FKEK,
            preamble_sha256: d.preamble_sha256,
            intent_hash: intent.intent_hash,
            dek_slot_sha256: slot.dek_slot_sha256,
            ciphertext_sha256: d.ciphertext_sha256,
            ciphertext_size: d.ciphertext_size,
            previous_signed_head_hash: None,
            signer_signing_key_id: signing_key_id(&pk),
            server_instance_id: INSTANCE,
            restore_epoch: 0,
            manifest_replay_id,
            created_at_ms: 1,
        };
        let signed = SignedSnapshotManifestV2::sign(&sk, &manifest).unwrap();
        let request = CommitRequestV2::build(&signed, [tag; 16], [tag; 16], [tag; 16]);
        let verified = request.clone().verify_signature(&pk).unwrap();
        let bound = CommitReceiptBindingV2::for_request(
            &verified,
            LeaseReleaseOutcome::Released,
            2,
            [tag; 16],
        );
        let finalize = IdempotentMutationRequestV2 {
            operation_kind: OperationKind::FinalizeUpload,
            idempotency_key: [tag; 16],
            canonical_payload_bytes: FinalizeUploadV2::new(request.clone()).encode(),
            client_request_nonce: [tag; 16],
            server_instance_id: INSTANCE,
            restore_epoch: 0,
        }
        .encode();
        Fixture {
            tag,
            object,
            manifest,
            request,
            receipt: bound.encode(),
            bound,
            finalize,
        }
    }

    impl Fixture {
        fn id(&self) -> [u8; 16] {
            [self.tag; 16]
        }

        fn staging(&self, root: &Path) -> PathBuf {
            fleet::staging_path(root, &TENANT, &self.id())
        }

        fn object_file(&self, root: &Path) -> PathBuf {
            fleet::object_path(root, &TENANT, &self.id(), &self.id())
        }
    }

    /// The upload row of `f` in `state`, its bytes stored as 0026 needs them
    /// for that state. An OPEN one has `offset` committed in one chunk.
    async fn insert(pool: &SqlitePool, root: &Path, f: &Fixture, state: &str, offset: usize) {
        let m = &f.manifest;
        let open = state == "OPEN";
        let committed = state == "COMMITTED";
        let ready = committed || state == "READY";
        let c = f.request.manifest();
        sqlx::query(
            "INSERT INTO v2_uploads
                 (server_instance_id, tenant_id, upload_id, fleet_id, profile_id, snapshot_id,
                  manifest_replay_id, lease_id, fencing_token, base_version, restore_epoch,
                  operation_scope, idempotency_key, canonical_request_hash, intent_hash,
                  preamble_sha256, dek_slot_sha256, fkek_key_id, key_generation,
                  expected_ciphertext_size, expected_ciphertext_sha256, committed_offset,
                  staging_path, immutable_path, state, signed_manifest_container_bytes,
                  signed_manifest_container_hash, signed_manifest_container_bytes_sha256,
                  exact_commit_request_bytes, exact_commit_request_bytes_sha256,
                  exact_finalize_response_bytes, exact_commit_receipt_binding_bytes,
                  commit_receipt_binding_bytes_sha256, expires_at_ms, created_at_ms,
                  exact_finalize_request_bytes, finalize_actor_account_id,
                  finalize_actor_device_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 0, 0, 'profile.create-upload.v2', ?, ?, ?, ?, ?,
                     ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)",
        )
        .bind(INSTANCE.as_slice())
        .bind(TENANT.as_slice())
        .bind(f.id().as_slice())
        .bind(FLEET.as_slice())
        .bind(m.profile_id.as_slice())
        .bind(m.snapshot_id.as_slice())
        .bind(m.manifest_replay_id.as_slice())
        .bind(LEASE.as_slice())
        .bind(f.id().as_slice())
        .bind([0u8; 32].as_slice())
        .bind(m.intent_hash.as_slice())
        .bind(m.preamble_sha256.as_slice())
        .bind(m.dek_slot_sha256.as_slice())
        .bind(FKEK.as_slice())
        .bind(f.object.len() as i64)
        .bind(m.ciphertext_sha256.as_slice())
        .bind((if open { offset } else { f.object.len() }) as i64)
        .bind(f.staging(root).to_string_lossy().to_string())
        .bind((!open).then(|| f.object_file(root).to_string_lossy().to_string()))
        .bind(state)
        .bind((!open).then(|| c.exact_bytes().to_vec()))
        .bind((!open).then(|| c.signed_container_hash().to_vec()))
        .bind((!open).then(|| c.exact_bytes_sha256().to_vec()))
        .bind((!open).then(|| f.request.exact_bytes().to_vec()))
        .bind((!open).then(|| f.request.exact_bytes_sha256().to_vec()))
        .bind(ready.then(|| b"finalized".to_vec()))
        .bind(committed.then(|| f.receipt.clone()))
        .bind(committed.then(|| sha256(&f.receipt).to_vec()))
        .bind(i64::MAX)
        .bind((!open).then(|| f.finalize.clone()))
        .bind((!open).then(|| ACTOR.to_vec()))
        .bind((!open).then(|| ACTOR.to_vec()))
        .execute(pool)
        .await
        .unwrap();
        if open && offset > 0 {
            sqlx::query("INSERT INTO v2_upload_chunks VALUES (?, ?, ?, 0, ?, ?)")
                .bind(INSTANCE.as_slice())
                .bind(TENANT.as_slice())
                .bind(f.id().as_slice())
                .bind(offset as i64)
                .bind(sha256(&f.object[..offset]).as_slice())
                .execute(pool)
                .await
                .unwrap();
        }
    }

    /// What a commit of `f` leaves: its snapshot, its ledger row with the
    /// exact receipt and its profile at `version`.
    async fn commit_rows(pool: &SqlitePool, root: &Path, f: &Fixture, version: i64) {
        let m = &f.manifest;
        let c = f.request.manifest();
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
             VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, 0, 2, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, 1, 1,
                     ?, 0, ?, 1)",
        )
        .bind(INSTANCE.as_slice())
        .bind(TENANT.as_slice())
        .bind(FLEET.as_slice())
        .bind(m.profile_id.as_slice())
        .bind(m.snapshot_id.as_slice())
        .bind(m.manifest_replay_id.as_slice())
        .bind(f.id().as_slice())
        .bind(FKEK.as_slice())
        .bind(m.intent_hash.as_slice())
        .bind(m.preamble_sha256.as_slice())
        .bind(m.dek_slot_sha256.as_slice())
        .bind(f.object_file(root).to_string_lossy().to_string())
        .bind(m.ciphertext_sha256.as_slice())
        .bind(f.object.len() as i64)
        .bind(c.exact_bytes())
        .bind(c.signed_container_hash().as_slice())
        .bind(c.exact_bytes_sha256().as_slice())
        .bind(c.head_hash().as_slice())
        .bind(m.signer_signing_key_id.as_slice())
        .bind(c.signature_bytes())
        .bind([1u8; 16].as_slice())
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO v2_idempotency
                 (server_instance_id, tenant_id, actor_device_id, operation_scope, idempotency_key,
                  operation_kind, canonical_request_hash, exact_request_bytes,
                  exact_request_bytes_sha256, status, response_record_type, exact_response_bytes,
                  exact_response_bytes_sha256, retained_until)
             VALUES (?, ?, ?, ?, ?, 'COMMIT', ?, ?, ?, 'succeeded', 'CommitReceiptBindingV2', ?, ?,
                     ?)",
        )
        .bind(INSTANCE.as_slice())
        .bind(TENANT.as_slice())
        .bind([1u8; 16].as_slice())
        .bind(OPERATION_SCOPE_COMMIT)
        .bind(f.request.idempotency_key().as_slice())
        .bind(f.request.canonical_request_hash().as_slice())
        .bind(f.request.exact_bytes())
        .bind(f.request.exact_bytes_sha256().as_slice())
        .bind(&f.receipt)
        .bind(sha256(&f.receipt).as_slice())
        .bind(i64::MAX)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO v2_profiles (id, tenant_id, fleet_id, name, current_version, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'active', 't', 't')")
            .bind(m.profile_id.as_slice())
            .bind(TENANT.as_slice())
            .bind(FLEET.as_slice())
            .bind(format!("p{}", f.tag))
            .bind(version)
            .execute(pool)
            .await
            .unwrap();
    }

    fn write(path: &Path, bytes: &[u8]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    /// `bytes` with one byte flipped.
    fn flipped(bytes: &[u8]) -> Vec<u8> {
        let mut b = bytes.to_vec();
        b[bytes.len() / 2] ^= 1;
        b
    }

    /// Upload `f` in `state` with receipt `r`, object `i` and staging `s`.
    /// `R = X` is a commit whose profile never reached its version; an OPEN
    /// upload with `S = Ø` is at offset 0.
    async fn setup(pool: &SqlitePool, root: &Path, f: &Fixture, state: &str, r: C, i: C, s: C) {
        let open = state == "OPEN";
        let offset = if open && s == Absent { 0 } else { PREFIX };
        insert(pool, root, f, state, offset).await;
        match r {
            Absent => {}
            Valid => commit_rows(pool, root, f, 1).await,
            Invalid => commit_rows(pool, root, f, 0).await,
        }
        match i {
            Absent => {}
            Valid => write(&f.object_file(root), &f.object),
            Invalid => write(&f.object_file(root), &f.object[1..]),
        }
        let staged = if open {
            &f.object[..PREFIX]
        } else {
            &f.object[..]
        };
        match s {
            Absent => {}
            Valid => write(&f.staging(root), staged),
            Invalid => write(&f.staging(root), &flipped(staged)),
        }
    }

    /// The upload's state, its quarantine row and which of its files exist.
    async fn outcome(
        pool: &SqlitePool,
        root: &Path,
        f: &Fixture,
    ) -> (String, Option<(String, bool)>, bool, bool) {
        let state: String = sqlx::query_scalar("SELECT state FROM v2_uploads WHERE upload_id = ?")
            .bind(f.id().as_slice())
            .fetch_one(pool)
            .await
            .unwrap();
        let mark: Option<(String, bool)> = sqlx::query_as(
            "SELECT reason, security_incident FROM v2_upload_quarantine WHERE upload_id = ?",
        )
        .bind(f.id().as_slice())
        .fetch_optional(pool)
        .await
        .unwrap();
        (
            state,
            mark,
            f.staging(root).exists(),
            f.object_file(root).exists(),
        )
    }

    struct Row {
        line: u32,
        state: &'static str,
        r: C,
        i: C,
        s: C,
        want: &'static str,
        mark: Option<(&'static str, bool)>,
        staging: bool,
        object: bool,
    }

    const fn row(
        line: u32,
        state: &'static str,
        (r, i, s): (C, C, C),
        want: &'static str,
        mark: Option<(&'static str, bool)>,
        (staging, object): (bool, bool),
    ) -> Row {
        Row {
            line,
            state,
            r,
            i,
            s,
            want,
            mark,
            staging,
            object,
        }
    }

    const Q: &str = "QUARANTINED";

    /// Every row of L1187-L1214, by its line, with what it must leave.
    const TABLE: &[Row] = &[
        row(
            1189,
            "OPEN",
            (Invalid, Absent, Valid),
            Q,
            Some(("receipt_before_finalize", true)),
            (true, false),
        ),
        row(
            1190,
            "OPEN",
            (Absent, Valid, Valid),
            Q,
            Some(("object_before_finalize", false)),
            (true, true),
        ),
        row(
            1190,
            "OPEN",
            (Absent, Invalid, Absent),
            Q,
            Some(("object_before_finalize", false)),
            (false, true),
        ),
        row(
            1191,
            "OPEN",
            (Absent, Absent, Invalid),
            Q,
            Some(("staging_invalid", false)),
            (true, false),
        ),
        row(
            1192,
            "OPEN",
            (Absent, Absent, Valid),
            "OPEN",
            None,
            (true, false),
        ),
        row(
            1193,
            "OPEN",
            (Absent, Absent, Absent),
            "OPEN",
            None,
            (false, false),
        ),
        row(
            1194,
            "FINALIZING",
            (Invalid, Valid, Absent),
            Q,
            Some(("receipt_invalid", true)),
            (false, true),
        ),
        row(
            1195,
            "FINALIZING",
            (Absent, Invalid, Valid),
            Q,
            Some(("object_invalid", false)),
            (true, true),
        ),
        row(
            1196,
            "FINALIZING",
            (Absent, Absent, Invalid),
            Q,
            Some(("staging_invalid", false)),
            (true, false),
        ),
        row(
            1197,
            "FINALIZING",
            (Valid, Valid, Absent),
            "COMMITTED",
            None,
            (false, true),
        ),
        row(
            1197,
            "FINALIZING",
            (Valid, Valid, Valid),
            "COMMITTED",
            None,
            (false, true),
        ),
        row(
            1198,
            "FINALIZING",
            (Valid, Absent, Valid),
            Q,
            Some(("receipt_without_object", true)),
            (true, false),
        ),
        row(
            1199,
            "FINALIZING",
            (Absent, Valid, Absent),
            "READY",
            None,
            (false, true),
        ),
        row(
            1200,
            "FINALIZING",
            (Absent, Valid, Valid),
            "READY",
            None,
            (false, true),
        ),
        row(
            1201,
            "FINALIZING",
            (Absent, Absent, Valid),
            "READY",
            None,
            (false, true),
        ),
        row(
            1202,
            "FINALIZING",
            (Absent, Absent, Absent),
            Q,
            Some(("bytes_missing", false)),
            (false, false),
        ),
        row(
            1203,
            "READY",
            (Invalid, Valid, Absent),
            Q,
            Some(("receipt_invalid", true)),
            (false, true),
        ),
        row(
            1204,
            "READY",
            (Absent, Invalid, Absent),
            Q,
            Some(("object_invalid", false)),
            (false, true),
        ),
        row(
            1204,
            "READY",
            (Valid, Absent, Valid),
            Q,
            Some(("object_invalid", false)),
            (true, false),
        ),
        row(
            1205,
            "READY",
            (Absent, Valid, Invalid),
            Q,
            Some(("staging_invalid", false)),
            (true, true),
        ),
        row(
            1206,
            "READY",
            (Valid, Valid, Absent),
            "COMMITTED",
            None,
            (false, true),
        ),
        row(
            1206,
            "READY",
            (Valid, Valid, Valid),
            "COMMITTED",
            None,
            (false, true),
        ),
        row(
            1207,
            "READY",
            (Absent, Valid, Absent),
            "READY",
            None,
            (false, true),
        ),
        row(
            1208,
            "READY",
            (Absent, Valid, Valid),
            "READY",
            None,
            (false, true),
        ),
        row(
            1209,
            "COMMITTED",
            (Absent, Valid, Absent),
            "COMMITTED",
            Some(("receipt_invalid", true)),
            (false, true),
        ),
        row(
            1209,
            "COMMITTED",
            (Invalid, Valid, Valid),
            "COMMITTED",
            Some(("receipt_invalid", true)),
            (true, true),
        ),
        row(
            1210,
            "COMMITTED",
            (Valid, Invalid, Absent),
            "COMMITTED",
            Some(("object_invalid", true)),
            (false, true),
        ),
        row(
            1211,
            "COMMITTED",
            (Valid, Valid, Invalid),
            "COMMITTED",
            Some(("staging_invalid", false)),
            (true, true),
        ),
        row(
            1212,
            "COMMITTED",
            (Valid, Valid, Absent),
            "COMMITTED",
            None,
            (false, true),
        ),
        row(
            1213,
            "COMMITTED",
            (Valid, Valid, Valid),
            "COMMITTED",
            None,
            (false, true),
        ),
        row(
            1214,
            "QUARANTINED",
            (Valid, Invalid, Invalid),
            Q,
            None,
            (true, true),
        ),
    ];

    #[tokio::test]
    async fn every_row_of_the_table_takes_its_action_and_a_second_pass_changes_nothing() {
        let pool = pool().await;
        let d = dir("table");
        let root = d.0.as_path();
        let fixtures: Vec<Fixture> = (1..=TABLE.len() as u8).map(fixture).collect();
        for (t, f) in TABLE.iter().zip(&fixtures) {
            setup(&pool, root, f, t.state, t.r, t.i, t.s).await;
        }
        let v = identity();
        let first = run(&pool, &v, &root.to_string_lossy()).await.unwrap();
        let mut after = Vec::new();
        for (t, f) in TABLE.iter().zip(&fixtures) {
            let got = outcome(&pool, root, f).await;
            let want = (
                t.want.to_string(),
                t.mark.map(|(r, s)| (r.to_string(), s)),
                t.staging,
                t.object,
            );
            assert_eq!(got, want, "L{} {:?}", t.line, (t.state, t.r, t.i, t.s));
            after.push(got);
        }
        let marks = TABLE.iter().filter(|t| t.mark.is_some()).count();
        assert_eq!(first.quarantined, marks);
        assert_eq!((first.promoted, first.committed, first.retried), (5, 4, 0));
        assert_eq!(first.staging_removed, 5);
        // A committed upload's receipt is the ledger's exact bytes.
        for f in &fixtures[9..11] {
            let stored: Vec<u8> = sqlx::query_scalar(
                "SELECT exact_commit_receipt_binding_bytes FROM v2_uploads WHERE upload_id = ?",
            )
            .bind(f.id().as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(stored, f.receipt);
        }

        // L1150: each finalize the pass finished stored its exact READY
        // response once, with its ledger and audit rows, as its own actor.
        let finished: Vec<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT i.exact_response_bytes, u.exact_finalize_response_bytes
               FROM v2_idempotency i JOIN v2_uploads u
                 ON i.exact_request_bytes = u.exact_finalize_request_bytes
              WHERE i.operation_kind = 'FINALIZE_UPLOAD' AND i.actor_device_id = ?",
        )
        .bind(ACTOR.as_slice())
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(finished.len(), first.promoted);
        assert!(finished.iter().all(|(ledger, stored)| ledger == stored));
        let audited: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM v2_audit_events
              WHERE action = 'profile.finalize_upload' AND actor_account_id = ?",
        )
        .bind(ACTOR.as_slice())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(audited as usize, first.promoted);

        let second = run(&pool, &v, &root.to_string_lossy()).await.unwrap();
        let kept = after
            .iter()
            .filter(|(state, mark, ..)| mark.is_none() && state != Q)
            .count();
        assert_eq!(
            second,
            Report {
                kept,
                ..Report::default()
            }
        );
        for ((t, f), before) in TABLE.iter().zip(&fixtures).zip(&after) {
            assert_eq!(&outcome(&pool, root, f).await, before, "L{}", t.line);
        }
    }

    #[tokio::test]
    async fn an_open_upload_is_cut_to_its_offset_or_quarantined_when_its_prefix_is_not_whole() {
        let pool = pool().await;
        let d = dir("open");
        let root = d.0.as_path();
        let f: Vec<Fixture> = (0x60..0x66).map(fixture).collect();
        // A write that crashed before its offset committed left a tail.
        setup(&pool, root, &f[0], "OPEN", Absent, Absent, Valid).await;
        let mut tail = f[0].object[..PREFIX].to_vec();
        tail.extend_from_slice(&[0x5c; 300]);
        write(&f[0].staging(root), &tail);
        // L1193: no file past offset 0.
        insert(&pool, root, &f[1], "OPEN", PREFIX).await;
        // Shorter than the committed offset.
        setup(&pool, root, &f[2], "OPEN", Absent, Absent, Valid).await;
        write(&f[2].staging(root), &f[2].object[..PREFIX - 1]);
        // Chunk receipts that do not reach the committed offset.
        setup(&pool, root, &f[3], "OPEN", Absent, Absent, Valid).await;
        sqlx::query("UPDATE v2_uploads SET committed_offset = ? WHERE upload_id = ?")
            .bind(PREFIX as i64 + 1)
            .bind(f[3].id().as_slice())
            .execute(&pool)
            .await
            .unwrap();
        write(&f[3].staging(root), &f[3].object[..PREFIX + 1]);
        // A chunk receipt past the committed offset.
        setup(&pool, root, &f[4], "OPEN", Absent, Absent, Valid).await;
        sqlx::query("UPDATE v2_upload_chunks SET chunk_length = ? WHERE upload_id = ?")
            .bind(PREFIX as i64 + 1)
            .bind(f[4].id().as_slice())
            .execute(&pool)
            .await
            .unwrap();
        write(&f[4].staging(root), &f[4].object[..PREFIX + 1]);
        // Receipts that add up to the offset but overlap, leaving a gap.
        setup(&pool, root, &f[5], "OPEN", Absent, Absent, Valid).await;
        sqlx::query("DELETE FROM v2_upload_chunks WHERE upload_id = ?")
            .bind(f[5].id().as_slice())
            .execute(&pool)
            .await
            .unwrap();
        for (at, len) in [(0, 300), (100, 200)] {
            sqlx::query("INSERT INTO v2_upload_chunks VALUES (?, ?, ?, ?, ?, ?)")
                .bind(INSTANCE.as_slice())
                .bind(TENANT.as_slice())
                .bind(f[5].id().as_slice())
                .bind(at as i64)
                .bind(len as i64)
                .bind(sha256(&f[5].object[at..at + len]).as_slice())
                .execute(&pool)
                .await
                .unwrap();
        }

        run(&pool, &identity(), &root.to_string_lossy())
            .await
            .unwrap();
        assert_eq!(
            outcome(&pool, root, &f[0]).await,
            ("OPEN".into(), None, true, false)
        );
        assert_eq!(
            std::fs::read(f[0].staging(root)).unwrap(),
            &f[0].object[..PREFIX]
        );
        let bad = Some(("staging_invalid".to_string(), false));
        assert_eq!(
            outcome(&pool, root, &f[1]).await,
            (Q.into(), bad.clone(), false, false)
        );
        for f in &f[2..] {
            assert_eq!(
                outcome(&pool, root, f).await,
                (Q.into(), bad.clone(), true, false)
            );
        }
    }

    /// A COMMITTED upload whose receipt evidence differs in one link.
    #[tokio::test]
    async fn a_receipt_is_valid_only_when_every_link_matches() {
        let pool = pool().await;
        let d = dir("receipt");
        let root = d.0.as_path();
        for t in [
            "v2_snapshots_are_immutable",
            "v2_idempotency_succeeded_is_fixed",
            "v2_uploads_artifacts_are_written_once",
        ] {
            sqlx::query(&format!("DROP TRIGGER {t}"))
                .execute(&pool)
                .await
                .unwrap();
        }
        let f: Vec<Fixture> = (0x70..0x7a).map(fixture).collect();
        for f in &f {
            setup(&pool, root, f, "COMMITTED", Valid, Valid, Absent).await;
        }
        let other = CommitReceiptBindingV2 {
            server_receipt_id: [0x99; 16],
            ..f[0].bound.clone()
        }
        .encode();
        let unbound = CommitReceiptBindingV2 {
            exact_request_hash: [0x99; 32],
            ..f[5].bound.clone()
        }
        .encode();
        let tampers: [(&str, Vec<u8>); 10] = [
            // The ledger holds other bytes than the upload.
            ("UPDATE v2_idempotency SET exact_response_bytes = ? WHERE exact_request_bytes = (SELECT exact_commit_request_bytes FROM v2_uploads WHERE upload_id = x'70707070707070707070707070707070')", other),
            ("UPDATE v2_uploads SET commit_receipt_binding_bytes_sha256 = ? WHERE upload_id = x'71717171717171717171717171717171'", vec![0; 32]),
            ("UPDATE v2_snapshots SET head_hash = ? WHERE upload_id = x'72727272727272727272727272727272'", vec![0; 32]),
            ("UPDATE v2_snapshots SET signed_manifest_container_bytes = ? WHERE upload_id = x'73737373737373737373737373737373'", vec![1]),
            ("UPDATE v2_snapshots SET version = 2, previous_head_hash = ? WHERE upload_id = x'74747474747474747474747474747474'", vec![0; 32]),
            // Bytes that bind another request, stored and ledgered alike.
            ("UPDATE v2_idempotency SET exact_response_bytes = ?1 WHERE exact_request_bytes = (SELECT exact_commit_request_bytes FROM v2_uploads WHERE upload_id = x'75757575757575757575757575757575')", unbound.clone()),
            ("DELETE FROM v2_idempotency WHERE length(?) = 1 AND exact_request_bytes = (SELECT exact_commit_request_bytes FROM v2_uploads WHERE upload_id = x'76767676767676767676767676767676')", vec![1]),
            // A second snapshot names the upload, every link matching.
            ("INSERT INTO v2_snapshots SELECT server_instance_id, tenant_id, fleet_id, ?1, version, ?1, ?1, upload_id, fkek_key_id, key_generation, envelope_version, intent_hash, preamble_sha256, dek_slot_sha256, immutable_blob_path, ciphertext_sha256, ciphertext_size, signed_manifest_container_bytes, signed_manifest_container_hash, signed_manifest_container_bytes_sha256, previous_head_hash, head_hash, signing_key_id, signature_suite_id, signature_version, signature_bytes, restore_epoch, created_by_device, created_at_ms FROM v2_snapshots WHERE upload_id = x'77777777777777777777777777777777'", vec![0x99; 16]),
            // The snapshot names another object or ciphertext than the upload.
            ("UPDATE v2_snapshots SET immutable_blob_path = CAST(? AS TEXT) WHERE upload_id = x'78787878787878787878787878787878'", b"elsewhere.bin".to_vec()),
            ("UPDATE v2_snapshots SET ciphertext_sha256 = ? WHERE upload_id = x'79797979797979797979797979797979'", vec![0; 32]),
        ];
        for (sql, bytes) in &tampers {
            sqlx::query(sql).bind(bytes).execute(&pool).await.unwrap();
        }
        let unbound_upload = "UPDATE v2_uploads SET exact_commit_receipt_binding_bytes = ?,
                              commit_receipt_binding_bytes_sha256 = ? WHERE upload_id = ?";
        sqlx::query(unbound_upload)
            .bind(&unbound)
            .bind(sha256(&unbound).as_slice())
            .bind(f[5].id().as_slice())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE v2_profiles SET current_version = 2 WHERE id = ?")
            .bind(f[4].id().as_slice())
            .execute(&pool)
            .await
            .unwrap();

        run(&pool, &identity(), &root.to_string_lossy())
            .await
            .unwrap();
        for (n, f) in f.iter().enumerate() {
            assert_eq!(
                outcome(&pool, root, f).await,
                (
                    "COMMITTED".into(),
                    Some(("receipt_invalid".into(), true)),
                    false,
                    true
                ),
                "tamper {n}"
            );
        }
    }

    /// ADR 0002 C-2: an object is at the path keyed by its snapshot, or it is
    /// not the upload's, whatever its bytes.
    #[tokio::test]
    async fn an_object_off_its_snapshot_path_is_invalid() {
        let pool = pool().await;
        let d = dir("path");
        let root = d.0.as_path();
        let f = fixture(0x81);
        setup(&pool, root, &f, "READY", Absent, Valid, Absent).await;
        let elsewhere = root.join("elsewhere.bin");
        write(&elsewhere, &f.object);
        sqlx::query("DROP TRIGGER v2_uploads_artifacts_are_written_once")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE v2_uploads SET immutable_path = ? WHERE upload_id = ?")
            .bind(elsewhere.to_string_lossy().to_string())
            .bind(f.id().as_slice())
            .execute(&pool)
            .await
            .unwrap();
        run(&pool, &identity(), &root.to_string_lossy())
            .await
            .unwrap();
        assert_eq!(
            outcome(&pool, root, &f).await,
            (
                Q.into(),
                Some(("object_invalid".into(), false)),
                false,
                true
            )
        );
        assert!(elsewhere.exists());
    }

    #[tokio::test]
    async fn an_object_the_envelope_grammar_refuses_quarantines_with_its_code() {
        let pool = pool().await;
        let d = dir("grammar");
        let root = d.0.as_path();
        let f = fixture(0x80);
        setup(&pool, root, &f, "FINALIZING", Absent, Absent, Valid).await;
        sqlx::query("DROP TRIGGER v2_uploads_terms_are_fixed")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE v2_uploads SET intent_hash = ? WHERE upload_id = ?")
            .bind([0u8; 32].as_slice())
            .bind(f.id().as_slice())
            .execute(&pool)
            .await
            .unwrap();
        run(&pool, &identity(), &root.to_string_lossy())
            .await
            .unwrap();
        // Refused before the rename: the staged evidence stays.
        assert_eq!(
            outcome(&pool, root, &f).await,
            (
                Q.into(),
                Some(("UPLOAD_QUARANTINED".into(), false)),
                true,
                false
            )
        );
    }

    /// L1216: a failing step is retried, and quarantines once the tries run
    /// out. A reconciler that crashed after its rename left `FINALIZING` with
    /// the object in place (L1199), which the next try finishes.
    #[tokio::test]
    async fn a_failing_step_is_retried_and_then_quarantined() {
        let pool = pool().await;
        let d = dir("retry");
        let root = d.0.as_path();
        let (eased, stuck) = (fixture(0x90), fixture(0x91));
        for f in [&eased, &stuck] {
            setup(&pool, root, f, "FINALIZING", Absent, Absent, Valid).await;
        }
        {
            let mut faults = FAULTS.lock().unwrap();
            faults.push((eased.id().to_vec(), "cas", ATTEMPTS as u32 - 1));
            faults.push((stuck.id().to_vec(), "cas", ATTEMPTS as u32));
        }
        let report = run(&pool, &identity(), &root.to_string_lossy())
            .await
            .unwrap();
        assert_eq!((report.promoted, report.quarantined), (1, 1));
        assert_eq!(report.retried, 2 * (ATTEMPTS - 1));
        assert_eq!(
            outcome(&pool, root, &eased).await,
            ("READY".into(), None, false, true)
        );
        assert_eq!(
            outcome(&pool, root, &stuck).await,
            (
                Q.into(),
                Some(("reconcile_failed".into(), false)),
                false,
                true
            )
        );
        let from: String =
            sqlx::query_scalar("SELECT from_state FROM v2_upload_quarantine WHERE upload_id = ?")
                .bind(stuck.id().as_slice())
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(from, "FINALIZING");
    }

    #[tokio::test]
    async fn gc_aborts_expired_uploads_and_removes_only_aborted_staging() {
        let pool = pool().await;
        let d = dir("gc");
        let root = d.0.as_path();
        let f: Vec<Fixture> = (0xa0..0xa4).map(fixture).collect();
        // An expired OPEN upload, an ABORTED one with its file, an ABORTED
        // READY one with its object, and a quarantined one.
        setup(&pool, root, &f[0], "OPEN", Absent, Absent, Valid).await;
        sqlx::query("DROP TRIGGER v2_uploads_terms_are_fixed")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE v2_uploads SET expires_at_ms = 1 WHERE upload_id = ?")
            .bind(f[0].id().as_slice())
            .execute(&pool)
            .await
            .unwrap();
        setup(&pool, root, &f[1], "OPEN", Absent, Absent, Valid).await;
        setup(&pool, root, &f[2], "READY", Absent, Valid, Absent).await;
        setup(&pool, root, &f[3], "OPEN", Absent, Absent, Valid).await;
        for (f, state) in [(&f[1], "ABORTED"), (&f[2], "ABORTED"), (&f[3], Q)] {
            sqlx::query("UPDATE v2_uploads SET state = ? WHERE upload_id = ?")
                .bind(state)
                .bind(f.id().as_slice())
                .execute(&pool)
                .await
                .unwrap();
        }
        write(&f[2].staging(root), b"left behind");

        let v = identity();
        let report = run(&pool, &v, &root.to_string_lossy()).await.unwrap();
        assert_eq!((report.aborted, report.staging_removed), (1, 3));
        let aborted = ("ABORTED".to_string(), None, false, false);
        assert_eq!(outcome(&pool, root, &f[0]).await, aborted);
        assert_eq!(outcome(&pool, root, &f[1]).await, aborted);
        assert_eq!(
            outcome(&pool, root, &f[2]).await,
            ("ABORTED".into(), None, false, true)
        );
        assert_eq!(
            outcome(&pool, root, &f[3]).await,
            (Q.into(), None, true, false)
        );
        assert_eq!(
            run(&pool, &v, &root.to_string_lossy()).await.unwrap(),
            Report::default()
        );
    }

    #[tokio::test]
    async fn the_gate_holds_writes_while_a_finalizing_upload_is_left() {
        let pool = pool().await;
        let d = dir("gate");
        let root = d.0.as_path();
        let f = fixture(0xb0);
        setup(&pool, root, &f, "FINALIZING", Absent, Absent, Valid).await;
        let v = identity();
        assert!(gate(&pool, &v).await.is_err());
        run(&pool, &v, &root.to_string_lossy()).await.unwrap();
        gate(&pool, &v).await.unwrap();
    }

    /// Every input of the four states the table covers has its own arm: the
    /// fail-closed fallback is never reached.
    #[test]
    fn the_table_covers_every_input() {
        let all = [Absent, Valid, Invalid];
        for state in ["OPEN", "FINALIZING", "READY", "COMMITTED"] {
            for r in all {
                for i in all {
                    for s in all {
                        assert_ne!(
                            decide(state, r, i, s),
                            Action::Quarantine("unclassified", true),
                            "{state} {r:?} {i:?} {s:?}"
                        );
                    }
                }
            }
        }
        assert_eq!(
            decide("ABORTED", Absent, Absent, Absent),
            Action::Quarantine("unclassified", true)
        );
    }

    /// The quarantine rows and states of every upload, to prove a failed pass
    /// wrote nothing.
    async fn snapshot_of(pool: &SqlitePool) -> (i64, Vec<String>) {
        let marks = sqlx::query_scalar("SELECT count(*) FROM v2_upload_quarantine")
            .fetch_one(pool)
            .await
            .unwrap();
        let states = sqlx::query_scalar("SELECT state FROM v2_uploads ORDER BY upload_id")
            .fetch_all(pool)
            .await
            .unwrap();
        (marks, states)
    }

    /// A blob root that is not there (a volume not mounted yet, another
    /// spelling of the data directory) fails the pass and quarantines nothing;
    /// with no upload to reconcile there is nothing to fail.
    #[tokio::test]
    async fn a_missing_blob_root_fails_the_pass_without_a_quarantine() {
        let pool = pool().await;
        let d = dir("root");
        let root = d.0.as_path();
        let gone = root.join("unmounted");
        let v = identity();
        run(&pool, &v, &gone.to_string_lossy()).await.unwrap();
        let (open, done) = (fixture(0xc0), fixture(0xc1));
        setup(&pool, &gone, &open, "OPEN", Absent, Absent, Absent).await;
        insert(&pool, &gone, &done, "COMMITTED", 0).await;
        commit_rows(&pool, &gone, &done, 1).await;
        let before = snapshot_of(&pool).await;
        let e = run(&pool, &v, &gone.to_string_lossy()).await.unwrap_err();
        assert!(e.to_string().contains("is missing; mount it"), "{e:#}");
        assert_eq!(snapshot_of(&pool).await, before);
    }

    /// L1210 with `I = Ø`: a missing COMMITTED object fails the whole pass
    /// before any upload is touched, so not even another upload's quarantine
    /// is written.
    #[tokio::test]
    async fn a_missing_committed_object_fails_the_pass_without_a_quarantine() {
        let pool = pool().await;
        let d = dir("missing");
        let root = d.0.as_path();
        let (bad, gone) = (fixture(0xc2), fixture(0xc3));
        setup(&pool, root, &bad, "OPEN", Absent, Absent, Invalid).await;
        setup(&pool, root, &gone, "COMMITTED", Valid, Absent, Absent).await;
        let before = snapshot_of(&pool).await;
        let e = run(&pool, &identity(), &root.to_string_lossy())
            .await
            .unwrap_err();
        assert!(e.to_string().contains("committed object"), "{e:#}");
        assert_eq!(snapshot_of(&pool).await, before);
        // Put back, the object is reconciled like any other.
        write(&gone.object_file(root), &gone.object);
        run(&pool, &identity(), &root.to_string_lossy())
            .await
            .unwrap();
        assert_eq!(
            outcome(&pool, root, &gone).await,
            ("COMMITTED".into(), None, false, true)
        );
    }

    /// A COMMITTED upload whose reads fail for a moment is kept after the
    /// backoff; one that keeps failing fails the pass, never quarantined.
    #[tokio::test]
    async fn a_committed_upload_that_keeps_failing_fails_the_pass() {
        let pool = pool().await;
        let d = dir("committed-io");
        let root = d.0.as_path();
        let (eased, stuck) = (fixture(0xc4), fixture(0xc5));
        setup(&pool, root, &eased, "COMMITTED", Valid, Valid, Absent).await;
        FAULTS
            .lock()
            .unwrap()
            .push((eased.id().to_vec(), "io", ATTEMPTS as u32 - 1));
        let report = run(&pool, &identity(), &root.to_string_lossy())
            .await
            .unwrap();
        assert_eq!((report.kept, report.retried), (1, ATTEMPTS - 1));
        setup(&pool, root, &stuck, "COMMITTED", Valid, Valid, Absent).await;
        FAULTS
            .lock()
            .unwrap()
            .push((stuck.id().to_vec(), "io", ATTEMPTS as u32));
        let before = snapshot_of(&pool).await;
        let e = run(&pool, &identity(), &root.to_string_lossy())
            .await
            .unwrap_err();
        assert!(e.to_string().contains("keeps failing"), "{e:#}");
        assert_eq!(snapshot_of(&pool).await, before);
    }
}
