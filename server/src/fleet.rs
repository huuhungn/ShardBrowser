//! Fleet sync: exclusive checkout, chunked upload, atomic commit, download.
//!
//! The transfer path for encrypted profile snapshots. The server moves and
//! stores ciphertext it cannot read: the container is sealed on the device,
//! and the server only ever sees opaque bytes plus a signed manifest that
//! describes them.
//!
//! Three things make concurrent editing safe:
//!
//! * **Leases** — a profile is checked out by exactly one device at a time,
//!   enforced by a partial unique index rather than by application logic.
//! * **Fencing tokens** — a lease carries a monotonic token. A delayed write
//!   from a holder whose lease has since expired arrives with a stale token
//!   and is rejected. Expiry alone is not enough: the holder may not know it
//!   lost the lease, and its write may already be in flight.
//! * **Version preconditions** — a commit declares the version it was based
//!   on. If the profile moved on, the commit is refused instead of silently
//!   overwriting another device's work.
//!
//! Uploads land in a staging file and are promoted only after the declared
//! size and content hash both match. A partial or corrupted upload therefore
//! never becomes the current version.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool};
use tokio::io::AsyncWriteExt;

/// Why a fleet-sync operation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FleetError {
    /// The profile is already checked out by someone else.
    AlreadyLeased,
    /// No live lease matches the presented id.
    NoSuchLease,
    /// The lease exists but has passed its expiry.
    LeaseExpired,
    /// The fencing token is not the one the live lease holds.
    StaleFencingToken { presented: i64, current: i64 },
    /// The commit's base version is no longer the profile's current version.
    VersionConflict { base: i64, current: i64 },
    /// The upload session is not open.
    SessionNotOpen,
    /// Received byte count does not match what the session declared.
    SizeMismatch { declared: i64, received: i64 },
    /// The staged bytes do not hash to the manifest's container hash.
    ContentHashMismatch,
    /// A chunk arrived at an offset that is not the current end of the file.
    ChunkOutOfOrder { expected: i64, got: i64 },
    /// The chunk would push the upload past its declared size.
    DeclaredSizeExceeded { declared: i64, would_be: i64 },
    /// The requested snapshot version does not exist.
    NoSuchVersion,
    /// The stored blob is missing or unreadable.
    BlobUnavailable,
    /// The database refused the write. Carried verbatim rather than folded
    /// into a business error, so a schema or constraint fault is not
    /// misreported as a version conflict.
    Database(String),
}

impl From<sqlx::Error> for FleetError {
    fn from(e: sqlx::Error) -> Self {
        Self::Database(e.to_string())
    }
}

impl std::fmt::Display for FleetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyLeased => write!(f, "profile is already checked out"),
            Self::NoSuchLease => write!(f, "no live lease with that id"),
            Self::LeaseExpired => write!(f, "lease has expired"),
            Self::StaleFencingToken { presented, current } => write!(
                f,
                "stale fencing token: presented {presented}, live lease holds {current}"
            ),
            Self::VersionConflict { base, current } => write!(
                f,
                "version conflict: commit is based on {base}, profile is at {current}"
            ),
            Self::SessionNotOpen => write!(f, "upload session is not open"),
            Self::SizeMismatch { declared, received } => {
                write!(f, "size mismatch: declared {declared}, received {received}")
            }
            Self::ContentHashMismatch => write!(f, "staged content hash does not match manifest"),
            Self::ChunkOutOfOrder { expected, got } => {
                write!(
                    f,
                    "chunk out of order: expected offset {expected}, got {got}"
                )
            }
            Self::DeclaredSizeExceeded { declared, would_be } => write!(
                f,
                "chunk exceeds declared size: declared {declared}, would be {would_be}"
            ),
            Self::NoSuchVersion => write!(f, "no such snapshot version"),
            Self::BlobUnavailable => write!(f, "snapshot blob is unavailable"),
            Self::Database(e) => write!(f, "database error: {e}"),
        }
    }
}

impl std::error::Error for FleetError {}

/// A granted exclusive checkout.
#[derive(Debug, Clone)]
pub struct Lease {
    pub id: [u8; 16],
    pub fencing_token: i64,
    pub base_version: i64,
    pub expires_at: String,
}

/// Acquire an exclusive lease on a profile.
///
/// The partial unique index `v2_leases_one_live_per_profile` is what actually
/// prevents a double checkout: two concurrent acquirers both pass any
/// application-level "is it free?" read, and exactly one of them survives the
/// insert. We surface the constraint violation as `AlreadyLeased` rather than
/// checking first, because the check-then-insert version has a race window.
///
/// The fencing token is drawn from a per-profile monotonic counter, so it
/// keeps increasing across lease generations. A holder that comes back after
/// losing its lease presents an older token and is rejected.
#[allow(clippy::too_many_arguments)]
pub async fn acquire_lease(
    db: &SqlitePool,
    tenant_id: &[u8; 16],
    profile_id: &[u8; 16],
    lease_id: &[u8; 16],
    holder_account_id: &[u8; 16],
    holder_device_id: &[u8; 16],
    server_instance_id: &[u8; 16],
    restore_epoch: i64,
    now: &str,
    expires_at: &str,
) -> Result<Lease, FleetError> {
    let mut tx = db.begin().await?;

    let current_version: i64 =
        sqlx::query("SELECT current_version FROM v2_profiles WHERE tenant_id = ? AND id = ?")
            .bind(tenant_id.as_slice())
            .bind(profile_id.as_slice())
            .fetch_one(&mut *tx)
            .await?
            .get(0);

    // Monotonic across lease generations: take one above the highest token
    // this profile has ever issued, including released leases.
    let next_token: i64 = sqlx::query(
        "SELECT COALESCE(MAX(fencing_token), 0) + 1 FROM v2_leases
         WHERE tenant_id = ? AND profile_id = ?",
    )
    .bind(tenant_id.as_slice())
    .bind(profile_id.as_slice())
    .fetch_one(&mut *tx)
    .await?
    .get(0);

    let res = sqlx::query(
        "INSERT INTO v2_leases
           (id, tenant_id, profile_id, holder_account_id, holder_device_id,
            fencing_token, base_version, server_instance_id, restore_epoch,
            acquired_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(lease_id.as_slice())
    .bind(tenant_id.as_slice())
    .bind(profile_id.as_slice())
    .bind(holder_account_id.as_slice())
    .bind(holder_device_id.as_slice())
    .bind(next_token)
    .bind(current_version)
    .bind(server_instance_id.as_slice())
    .bind(restore_epoch)
    .bind(now)
    .bind(expires_at)
    .execute(&mut *tx)
    .await;

    match res {
        Ok(_) => {}
        // A live lease already exists for this profile. Reported as its own
        // refusal rather than a raw database error, so the caller can tell
        // "someone else holds it" apart from "the database is broken".
        Err(sqlx::Error::Database(e)) if is_unique_violation(&*e) => {
            let _ = e;
            return Err(FleetError::AlreadyLeased);
        }
        Err(e) => return Err(FleetError::Database(e.to_string())),
    }

    tx.commit().await?;
    Ok(Lease {
        id: *lease_id,
        fencing_token: next_token,
        base_version: current_version,
        expires_at: expires_at.to_string(),
    })
}

/// True when a database error is a UNIQUE constraint violation (SQLite 2067).
fn is_unique_violation(e: &dyn sqlx::error::DatabaseError) -> bool {
    e.code().map(|c| c == "2067").unwrap_or(false)
}

/// Check that a presented lease is live, unexpired, and holds this token.
///
/// `now` is compared as an ISO-8601 string, which sorts correctly because the
/// timestamps are zero-padded UTC.
pub async fn validate_lease(
    db: &SqlitePool,
    tenant_id: &[u8; 16],
    profile_id: &[u8; 16],
    lease_id: &[u8; 16],
    fencing_token: i64,
    now: &str,
) -> Result<(), FleetError> {
    let row = sqlx::query(
        "SELECT fencing_token, expires_at FROM v2_leases
         WHERE tenant_id = ? AND profile_id = ? AND id = ? AND released_at IS NULL",
    )
    .bind(tenant_id.as_slice())
    .bind(profile_id.as_slice())
    .bind(lease_id.as_slice())
    .fetch_optional(db)
    .await
    .map_err(|_| FleetError::NoSuchLease)?
    .ok_or(FleetError::NoSuchLease)?;

    let live_token: i64 = row.get(0);
    let expires_at: String = row.get(1);

    if live_token != fencing_token {
        return Err(FleetError::StaleFencingToken {
            presented: fencing_token,
            current: live_token,
        });
    }
    if now >= expires_at.as_str() {
        return Err(FleetError::LeaseExpired);
    }
    Ok(())
}

/// Release a lease so the profile can be checked out again.
pub async fn release_lease(
    db: &SqlitePool,
    tenant_id: &[u8; 16],
    lease_id: &[u8; 16],
    now: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE v2_leases SET released_at = ?
         WHERE tenant_id = ? AND id = ? AND released_at IS NULL",
    )
    .bind(now)
    .bind(tenant_id.as_slice())
    .bind(lease_id.as_slice())
    .execute(db)
    .await?;
    Ok(())
}

/// Open a chunked upload session backed by a staging file.
#[allow(clippy::too_many_arguments)]
pub async fn open_upload(
    db: &SqlitePool,
    blob_root: &Path,
    tenant_id: &[u8; 16],
    profile_id: &[u8; 16],
    session_id: &[u8; 16],
    lease_id: &[u8; 16],
    server_instance_id: &[u8; 16],
    restore_epoch: i64,
    fencing_token: i64,
    target_version: i64,
    intent_hash: &[u8; 32],
    declared_size: i64,
    now: &str,
) -> Result<PathBuf, sqlx::Error> {
    let staging = staging_path(blob_root, tenant_id, session_id);
    if let Some(parent) = staging.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(io_err)?;
    }
    // Truncate any leftover file: a session id is unique, but a crashed
    // earlier attempt with the same id must not contribute stale bytes.
    tokio::fs::File::create(&staging).await.map_err(io_err)?;

    sqlx::query(
        "INSERT INTO v2_upload_sessions
           (id, tenant_id, profile_id, lease_id, server_instance_id, restore_epoch,
            fencing_token, target_version, intent_hash, declared_size, received_size,
            staging_path, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, 'open', ?, ?)",
    )
    .bind(session_id.as_slice())
    .bind(tenant_id.as_slice())
    .bind(profile_id.as_slice())
    .bind(lease_id.as_slice())
    .bind(server_instance_id.as_slice())
    .bind(restore_epoch)
    .bind(fencing_token)
    .bind(target_version)
    .bind(intent_hash.as_slice())
    .bind(declared_size)
    .bind(staging.to_string_lossy().to_string())
    .bind(now)
    .bind(now)
    .execute(db)
    .await?;

    Ok(staging)
}

/// Append one chunk at `offset`.
///
/// Chunks must arrive in order and may not exceed the declared size. Both are
/// checked before any byte is written, so a rejected chunk leaves the staging
/// file exactly as it was and the client can retry from the reported offset.
pub async fn append_chunk(
    db: &SqlitePool,
    tenant_id: &[u8; 16],
    session_id: &[u8; 16],
    offset: i64,
    bytes: &[u8],
    now: &str,
) -> Result<i64, FleetError> {
    let row = sqlx::query(
        "SELECT staging_path, received_size, declared_size, status
         FROM v2_upload_sessions WHERE tenant_id = ? AND id = ?",
    )
    .bind(tenant_id.as_slice())
    .bind(session_id.as_slice())
    .fetch_optional(db)
    .await
    .map_err(|_| FleetError::SessionNotOpen)?
    .ok_or(FleetError::SessionNotOpen)?;

    let staging: String = row.get(0);
    let received: i64 = row.get(1);
    let declared: i64 = row.get(2);
    let status: String = row.get(3);

    if status != "open" {
        return Err(FleetError::SessionNotOpen);
    }
    if offset != received {
        return Err(FleetError::ChunkOutOfOrder {
            expected: received,
            got: offset,
        });
    }
    let would_be = received + bytes.len() as i64;
    if would_be > declared {
        return Err(FleetError::DeclaredSizeExceeded { declared, would_be });
    }

    let mut f = tokio::fs::OpenOptions::new()
        .append(true)
        .open(&staging)
        .await
        .map_err(|_| FleetError::BlobUnavailable)?;
    f.write_all(bytes)
        .await
        .map_err(|_| FleetError::BlobUnavailable)?;
    // Flush before recording progress: if the process dies between the two,
    // the ledger must never claim more bytes than are actually on disk.
    f.flush().await.map_err(|_| FleetError::BlobUnavailable)?;
    drop(f);

    sqlx::query(
        "UPDATE v2_upload_sessions SET received_size = ?, updated_at = ?
         WHERE tenant_id = ? AND id = ?",
    )
    .bind(would_be)
    .bind(now)
    .bind(tenant_id.as_slice())
    .bind(session_id.as_slice())
    .execute(db)
    .await
    .map_err(|_| FleetError::BlobUnavailable)?;

    Ok(would_be)
}

/// A verified, committed snapshot version.
#[derive(Debug, Clone)]
pub struct Committed {
    pub version: i64,
    pub container_sha256: [u8; 32],
}

/// Commit a staged upload as the profile's next version.
///
/// Everything that can reject the commit is checked before anything is made
/// visible: lease and fencing token, declared vs. received size, the content
/// hash of the staged bytes, and the base-version precondition. Only then is
/// the blob promoted and the manifest written, in one transaction.
///
/// The size and hash checks are not redundant. A truncated upload can still
/// hash to something; a full-size upload can still be corrupt. The first
/// catches an incomplete transfer cheaply, the second catches a wrong one.
#[allow(clippy::too_many_arguments)]
pub async fn commit_upload(
    db: &SqlitePool,
    blob_root: &Path,
    tenant_id: &[u8; 16],
    profile_id: &[u8; 16],
    session_id: &[u8; 16],
    manifest: &ManifestInput<'_>,
    now: &str,
) -> Result<Committed, FleetError> {
    let row = sqlx::query(
        "SELECT staging_path, received_size, declared_size, status, target_version,
                lease_id, fencing_token
         FROM v2_upload_sessions WHERE tenant_id = ? AND id = ?",
    )
    .bind(tenant_id.as_slice())
    .bind(session_id.as_slice())
    .fetch_optional(db)
    .await
    .map_err(|_| FleetError::SessionNotOpen)?
    .ok_or(FleetError::SessionNotOpen)?;

    let staging: String = row.get(0);
    let received: i64 = row.get(1);
    let declared: i64 = row.get(2);
    let status: String = row.get(3);
    let target_version: i64 = row.get(4);
    let lease_id: Vec<u8> = row.get(5);
    let fencing_token: i64 = row.get(6);

    if status != "open" {
        return Err(FleetError::SessionNotOpen);
    }
    if received != declared {
        return Err(FleetError::SizeMismatch { declared, received });
    }

    let lease_arr: [u8; 16] = lease_id
        .as_slice()
        .try_into()
        .map_err(|_| FleetError::NoSuchLease)?;
    validate_lease(db, tenant_id, profile_id, &lease_arr, fencing_token, now).await?;

    // Hash the staged file in bounded chunks: a profile snapshot can be large
    // and must never be read into memory whole.
    let digest = hash_file(Path::new(&staging)).await?;
    if digest != manifest.container_sha256 {
        return Err(FleetError::ContentHashMismatch);
    }

    let mut tx = db.begin().await.map_err(|_| FleetError::BlobUnavailable)?;

    let current: i64 =
        sqlx::query("SELECT current_version FROM v2_profiles WHERE tenant_id = ? AND id = ?")
            .bind(tenant_id.as_slice())
            .bind(profile_id.as_slice())
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| FleetError::NoSuchVersion)?
            .get(0);

    if current != manifest.base_version {
        return Err(FleetError::VersionConflict {
            base: manifest.base_version,
            current,
        });
    }

    let final_path = blob_path(blob_root, tenant_id, profile_id, target_version);
    if let Some(parent) = final_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|_| FleetError::BlobUnavailable)?;
    }
    // `rename` onto an existing file errors on Windows, and the target can
    // exist if an earlier attempt promoted the blob but died before the
    // manifest insert committed. Clearing it first makes the retry succeed.
    let _ = tokio::fs::remove_file(&final_path).await;
    tokio::fs::rename(&staging, &final_path)
        .await
        .map_err(|_| FleetError::BlobUnavailable)?;

    let blob_str = final_path.to_string_lossy().to_string();

    // Computed here, never taken from the caller: the column is the integrity
    // check on the stored manifest bytes, so a client-supplied value would let
    // a tampered row certify itself.
    let manifest_bytes_sha256: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(manifest.exact_signed_container_bytes);
        h.finalize().into()
    };

    sqlx::query(
        "INSERT INTO v2_snapshot_manifests
           (tenant_id, profile_id, version, snapshot_id, fleet_id, base_version,
            key_generation, restore_epoch, server_instance_id, fencing_token,
            intent_hash, container_sha256, container_size, blob_path,
            author_account_id, author_device_id, signature_bytes,
            issuer_signing_key_id, signed_container_hash,
            exact_signed_container_bytes, exact_signed_container_bytes_sha256,
            created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(tenant_id.as_slice())
    .bind(profile_id.as_slice())
    .bind(target_version)
    .bind(manifest.snapshot_id.as_slice())
    .bind(manifest.fleet_id.as_slice())
    .bind(manifest.base_version)
    .bind(manifest.key_generation)
    .bind(manifest.restore_epoch)
    .bind(manifest.server_instance_id.as_slice())
    .bind(fencing_token)
    .bind(manifest.intent_hash.as_slice())
    .bind(manifest.container_sha256.as_slice())
    .bind(declared)
    .bind(&blob_str)
    .bind(manifest.author_account_id.as_slice())
    .bind(manifest.author_device_id.as_slice())
    .bind(manifest.signature_bytes.as_slice())
    .bind(manifest.issuer_signing_key_id.as_slice())
    .bind(manifest.signed_container_hash.as_slice())
    .bind(manifest.exact_signed_container_bytes)
    .bind(manifest_bytes_sha256.as_slice())
    .bind(now)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        "UPDATE v2_profiles SET current_version = ?, updated_at = ?
         WHERE tenant_id = ? AND id = ?",
    )
    .bind(target_version)
    .bind(now)
    .bind(tenant_id.as_slice())
    .bind(profile_id.as_slice())
    .execute(&mut *tx)
    .await
    .map_err(|_| FleetError::BlobUnavailable)?;

    sqlx::query(
        "UPDATE v2_upload_sessions SET status = 'committed', updated_at = ?
         WHERE tenant_id = ? AND id = ?",
    )
    .bind(now)
    .bind(tenant_id.as_slice())
    .bind(session_id.as_slice())
    .execute(&mut *tx)
    .await
    .map_err(|_| FleetError::BlobUnavailable)?;

    tx.commit().await.map_err(|_| FleetError::BlobUnavailable)?;

    Ok(Committed {
        version: target_version,
        container_sha256: manifest.container_sha256,
    })
}

/// Signed manifest fields a commit must supply.
pub struct ManifestInput<'a> {
    pub snapshot_id: [u8; 16],
    pub fleet_id: [u8; 16],
    pub base_version: i64,
    pub key_generation: i64,
    pub restore_epoch: i64,
    pub server_instance_id: [u8; 16],
    pub intent_hash: [u8; 32],
    pub container_sha256: [u8; 32],
    pub author_account_id: [u8; 16],
    pub author_device_id: [u8; 16],
    pub signature_bytes: [u8; 64],
    pub issuer_signing_key_id: [u8; 32],
    pub signed_container_hash: [u8; 32],
    pub exact_signed_container_bytes: &'a [u8],
}

/// Abort an open session and remove its staging file.
pub async fn abort_upload(
    db: &SqlitePool,
    tenant_id: &[u8; 16],
    session_id: &[u8; 16],
    now: &str,
) -> Result<(), sqlx::Error> {
    let row = sqlx::query(
        "SELECT staging_path FROM v2_upload_sessions
         WHERE tenant_id = ? AND id = ? AND status = 'open'",
    )
    .bind(tenant_id.as_slice())
    .bind(session_id.as_slice())
    .fetch_optional(db)
    .await?;

    if let Some(r) = row {
        let staging: String = r.get(0);
        let _ = tokio::fs::remove_file(&staging).await;
    }

    sqlx::query(
        "UPDATE v2_upload_sessions SET status = 'aborted', updated_at = ?
         WHERE tenant_id = ? AND id = ? AND status = 'open'",
    )
    .bind(now)
    .bind(tenant_id.as_slice())
    .bind(session_id.as_slice())
    .execute(db)
    .await?;
    Ok(())
}

/// What a download needs to serve one version.
#[derive(Debug, Clone)]
pub struct DownloadTarget {
    /// The resolved version, so a caller that asked for "latest" learns which
    /// version it actually got and can pin subsequent range reads to it.
    pub version: i64,
    pub blob_path: String,
    pub container_size: i64,
    pub container_sha256: [u8; 32],
    pub exact_signed_container_bytes: Vec<u8>,
}

/// Resolve a snapshot version for download.
///
/// `version = None` means "current". The manifest bytes are returned alongside
/// the blob so the client can verify the signature over what it is about to
/// decrypt, rather than trusting the server's framing of it.
pub async fn resolve_download(
    db: &SqlitePool,
    tenant_id: &[u8; 16],
    profile_id: &[u8; 16],
    version: Option<i64>,
) -> Result<DownloadTarget, FleetError> {
    let want = match version {
        Some(v) => v,
        None => {
            sqlx::query("SELECT current_version FROM v2_profiles WHERE tenant_id = ? AND id = ?")
                .bind(tenant_id.as_slice())
                .bind(profile_id.as_slice())
                .fetch_optional(db)
                .await
                .map_err(|_| FleetError::NoSuchVersion)?
                .ok_or(FleetError::NoSuchVersion)?
                .get(0)
        }
    };

    let row = sqlx::query(
        "SELECT blob_path, container_size, container_sha256, exact_signed_container_bytes
         FROM v2_snapshot_manifests
         WHERE tenant_id = ? AND profile_id = ? AND version = ?",
    )
    .bind(tenant_id.as_slice())
    .bind(profile_id.as_slice())
    .bind(want)
    .fetch_optional(db)
    .await
    .map_err(|_| FleetError::NoSuchVersion)?
    .ok_or(FleetError::NoSuchVersion)?;

    let blob_path: String = row.get(0);
    let container_size: i64 = row.get(1);
    let hash_vec: Vec<u8> = row.get(2);
    let manifest_bytes: Vec<u8> = row.get(3);

    let container_sha256: [u8; 32] = hash_vec
        .as_slice()
        .try_into()
        .map_err(|_| FleetError::ContentHashMismatch)?;

    Ok(DownloadTarget {
        version: want,
        blob_path,
        container_size,
        container_sha256,
        exact_signed_container_bytes: manifest_bytes,
    })
}

/// Read one bounded range of a stored blob.
///
/// Downloads are ranged so a large profile never has to be held in memory on
/// either side. The caller loops until it has `container_size` bytes.
pub async fn read_range(path: &Path, offset: u64, len: usize) -> Result<Vec<u8>, FleetError> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    let mut f = tokio::fs::File::open(path)
        .await
        .map_err(|_| FleetError::BlobUnavailable)?;
    f.seek(std::io::SeekFrom::Start(offset))
        .await
        .map_err(|_| FleetError::BlobUnavailable)?;

    let mut buf = vec![0u8; len];
    let mut filled = 0usize;
    while filled < len {
        let n = f
            .read(&mut buf[filled..])
            .await
            .map_err(|_| FleetError::BlobUnavailable)?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    buf.truncate(filled);
    Ok(buf)
}

/// SHA-256 of a file, read in bounded chunks.
async fn hash_file(path: &Path) -> Result<[u8; 32], FleetError> {
    use tokio::io::AsyncReadExt;

    let mut f = tokio::fs::File::open(path)
        .await
        .map_err(|_| FleetError::BlobUnavailable)?;
    let mut hasher = Sha256::new();
    // 64 KiB: large enough to keep syscall overhead down, small enough that
    // peak memory does not scale with the snapshot.
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f
            .read(&mut buf)
            .await
            .map_err(|_| FleetError::BlobUnavailable)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

fn io_err(e: std::io::Error) -> sqlx::Error {
    sqlx::Error::Io(e)
}

fn hex16(b: &[u8; 16]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn staging_path(root: &Path, tenant_id: &[u8; 16], session_id: &[u8; 16]) -> PathBuf {
    root.join(hex16(tenant_id))
        .join("staging")
        .join(format!("{}.part", hex16(session_id)))
}

fn blob_path(root: &Path, tenant_id: &[u8; 16], profile_id: &[u8; 16], version: i64) -> PathBuf {
    root.join(hex16(tenant_id))
        .join("blobs")
        .join(hex16(profile_id))
        .join(format!("{version}.bin"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::str::FromStr;

    const TENANT: [u8; 16] = [1u8; 16];
    const OTHER_TENANT: [u8; 16] = [9u8; 16];
    const FLEET: [u8; 16] = [2u8; 16];
    const PROFILE: [u8; 16] = [3u8; 16];
    const ACCOUNT: [u8; 16] = [4u8; 16];
    const DEVICE: [u8; 16] = [5u8; 16];
    const DEVICE_B: [u8; 16] = [6u8; 16];
    const SERVER: [u8; 16] = [7u8; 16];

    /// A scratch directory that cleans up after itself.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "shardx-v2-fleet-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct Harness {
        db: SqlitePool,
        root: PathBuf,
        _dir: TempDir,
    }

    /// Open a real on-disk database with production pragmas. `foreign_keys`
    /// matters: without it the composite keys are inert and the isolation
    /// assertions below would pass for the wrong reason.
    async fn setup(tag: &str) -> Harness {
        let dir = TempDir::new(tag);
        let db_path = dir.0.join("server.db");
        let root = dir.0.join("blobs");

        let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", db_path.display()))
            .unwrap()
            .create_if_missing(true)
            .foreign_keys(true)
            .busy_timeout(std::time::Duration::from_secs(5));
        let db = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(opts)
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&db).await.unwrap();

        for (t, slug) in [(TENANT, "acme"), (OTHER_TENANT, "other")] {
            sqlx::query(
                "INSERT INTO v2_tenants (id, slug, status, active_root_generation, created_at)
                 VALUES (?, ?, 'active', 1, '2026-09-02T00:00:00+00:00')",
            )
            .bind(t.as_slice())
            .bind(slug)
            .execute(&db)
            .await
            .unwrap();

            sqlx::query(
                "INSERT INTO v2_fleets (id, tenant_id, name, status, created_at)
                 VALUES (?, ?, 'fleet', 'active', '2026-09-02T00:00:00+00:00')",
            )
            .bind(FLEET.as_slice())
            .bind(t.as_slice())
            .execute(&db)
            .await
            .unwrap();

            sqlx::query(
                "INSERT INTO v2_profiles (id, tenant_id, fleet_id, name, current_version, status, created_at, updated_at)
                 VALUES (?, ?, ?, 'profile', 0, 'active', '2026-09-02T00:00:00+00:00', '2026-09-02T00:00:00+00:00')",
            )
            .bind(PROFILE.as_slice())
            .bind(t.as_slice())
            .bind(FLEET.as_slice())
            .execute(&db)
            .await
            .unwrap();
        }

        Harness {
            db,
            root,
            _dir: dir,
        }
    }

    struct ManifestOwned {
        container_sha256: [u8; 32],
        base_version: i64,
        snapshot_id: [u8; 16],
        manifest_bytes: Vec<u8>,
    }

    fn manifest_for(bytes: &[u8], base_version: i64, snapshot_id: [u8; 16]) -> ManifestOwned {
        let mut h = Sha256::new();
        h.update(bytes);
        ManifestOwned {
            container_sha256: h.finalize().into(),
            base_version,
            snapshot_id,
            manifest_bytes: b"exact-signed-manifest-bytes".to_vec(),
        }
    }

    fn input_of(m: &ManifestOwned) -> ManifestInput<'_> {
        ManifestInput {
            snapshot_id: m.snapshot_id,
            fleet_id: FLEET,
            base_version: m.base_version,
            key_generation: 1,
            restore_epoch: 0,
            server_instance_id: SERVER,
            intent_hash: [0xAB; 32],
            container_sha256: m.container_sha256,
            author_account_id: ACCOUNT,
            author_device_id: DEVICE,
            signature_bytes: [0xCD; 64],
            issuer_signing_key_id: [0xEF; 32],
            signed_container_hash: [0x11; 32],
            exact_signed_container_bytes: &m.manifest_bytes,
        }
    }

    async fn try_acquire(
        h: &Harness,
        lease_id: [u8; 16],
        device: [u8; 16],
        expires: &str,
    ) -> Result<Lease, FleetError> {
        acquire_lease(
            &h.db,
            &TENANT,
            &PROFILE,
            &lease_id,
            &ACCOUNT,
            &device,
            &SERVER,
            0,
            "2026-09-02T00:00:00+00:00",
            expires,
        )
        .await
    }

    async fn acquire(h: &Harness, lease_id: [u8; 16], device: [u8; 16], expires: &str) -> Lease {
        try_acquire(h, lease_id, device, expires).await.unwrap()
    }

    async fn open_session(
        h: &Harness,
        session: [u8; 16],
        lease_id: [u8; 16],
        token: i64,
        target_version: i64,
        declared: i64,
    ) -> PathBuf {
        open_upload(
            &h.db,
            &h.root,
            &TENANT,
            &PROFILE,
            &session,
            &lease_id,
            &SERVER,
            0,
            token,
            target_version,
            &[0xAB; 32],
            declared,
            "2026-09-02T00:00:00+00:00",
        )
        .await
        .unwrap()
    }

    async fn append(
        h: &Harness,
        session: [u8; 16],
        offset: i64,
        bytes: &[u8],
    ) -> Result<i64, FleetError> {
        append_chunk(
            &h.db,
            &TENANT,
            &session,
            offset,
            bytes,
            "2026-09-02T00:00:01+00:00",
        )
        .await
    }

    async fn commit_at(
        h: &Harness,
        session: [u8; 16],
        m: &ManifestOwned,
        now: &str,
    ) -> Result<Committed, FleetError> {
        commit_upload(
            &h.db,
            &h.root,
            &TENANT,
            &PROFILE,
            &session,
            &input_of(m),
            now,
        )
        .await
    }

    async fn commit(
        h: &Harness,
        session: [u8; 16],
        m: &ManifestOwned,
    ) -> Result<Committed, FleetError> {
        commit_at(h, session, m, "2026-09-02T00:30:00+00:00").await
    }

    /// Full path: lease, chunked upload, commit, download the exact bytes back.
    #[tokio::test]
    async fn upload_then_download_round_trips_exact_bytes() {
        let h = setup("roundtrip").await;
        let payload: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();

        let lease = acquire(&h, [10u8; 16], DEVICE, "2026-09-02T01:00:00+00:00").await;
        let session = [20u8; 16];
        open_session(
            &h,
            session,
            lease.id,
            lease.fencing_token,
            1,
            payload.len() as i64,
        )
        .await;

        // Uneven chunks: offset bookkeeping must not assume a fixed size.
        let mut offset = 0i64;
        for chunk in payload.chunks(1234) {
            offset = append(&h, session, offset, chunk).await.unwrap();
        }
        assert_eq!(offset, payload.len() as i64);

        let m = manifest_for(&payload, 0, [30u8; 16]);
        let committed = commit(&h, session, &m).await.unwrap();
        assert_eq!(committed.version, 1);

        let target = resolve_download(&h.db, &TENANT, &PROFILE, None)
            .await
            .unwrap();
        assert_eq!(target.container_size, payload.len() as i64);
        assert_eq!(target.container_sha256, m.container_sha256);
        assert_eq!(target.exact_signed_container_bytes, m.manifest_bytes);

        let mut got = Vec::new();
        let mut at = 0u64;
        while (got.len() as i64) < target.container_size {
            let part = read_range(Path::new(&target.blob_path), at, 1000)
                .await
                .unwrap();
            if part.is_empty() {
                break;
            }
            at += part.len() as u64;
            got.extend_from_slice(&part);
        }
        assert_eq!(got, payload, "downloaded bytes must equal uploaded bytes");
    }

    #[tokio::test]
    async fn second_lease_on_same_profile_is_refused() {
        let h = setup("second-lease").await;
        acquire(&h, [10u8; 16], DEVICE, "2026-09-02T01:00:00+00:00").await;
        let second = try_acquire(&h, [11u8; 16], DEVICE_B, "2026-09-02T01:00:00+00:00").await;
        assert!(second.is_err(), "a live lease must block a second checkout");
    }

    #[tokio::test]
    async fn fencing_token_increases_across_lease_generations() {
        let h = setup("fencing").await;
        let first = acquire(&h, [10u8; 16], DEVICE, "2026-09-02T01:00:00+00:00").await;
        release_lease(&h.db, &TENANT, &first.id, "2026-09-02T00:30:00+00:00")
            .await
            .unwrap();
        let second = acquire(&h, [11u8; 16], DEVICE_B, "2026-09-02T02:00:00+00:00").await;
        assert!(
            second.fencing_token > first.fencing_token,
            "token must be monotonic: {} then {}",
            first.fencing_token,
            second.fencing_token
        );
    }

    /// The case the fencing token exists for: the lease disappears mid-upload.
    #[tokio::test]
    async fn stale_lease_holder_cannot_commit() {
        let h = setup("stale").await;
        let payload = b"stale-holder-payload".to_vec();
        let lease = acquire(&h, [10u8; 16], DEVICE, "2026-09-02T01:00:00+00:00").await;
        let session = [20u8; 16];
        open_session(
            &h,
            session,
            lease.id,
            lease.fencing_token,
            1,
            payload.len() as i64,
        )
        .await;
        append(&h, session, 0, &payload).await.unwrap();

        release_lease(&h.db, &TENANT, &lease.id, "2026-09-02T00:20:00+00:00")
            .await
            .unwrap();

        let err = commit(&h, session, &manifest_for(&payload, 0, [30u8; 16]))
            .await
            .expect_err("must refuse");
        assert!(
            matches!(err, FleetError::NoSuchLease),
            "expected NoSuchLease, got {err:?}"
        );
    }

    #[tokio::test]
    async fn expired_lease_is_refused() {
        let h = setup("expired").await;
        let payload = b"expired".to_vec();
        let lease = acquire(&h, [10u8; 16], DEVICE, "2026-09-02T01:00:00+00:00").await;
        let session = [20u8; 16];
        open_session(
            &h,
            session,
            lease.id,
            lease.fencing_token,
            1,
            payload.len() as i64,
        )
        .await;
        append(&h, session, 0, &payload).await.unwrap();

        let err = commit_at(
            &h,
            session,
            &manifest_for(&payload, 0, [30u8; 16]),
            "2026-09-02T09:00:00+00:00",
        )
        .await
        .expect_err("must refuse");
        assert!(
            matches!(err, FleetError::LeaseExpired),
            "expected LeaseExpired, got {err:?}"
        );
    }

    /// A stale writer must not silently overwrite a newer version.
    #[tokio::test]
    async fn commit_with_stale_base_version_is_refused() {
        let h = setup("version").await;

        let p1 = b"first-version-bytes".to_vec();
        let l1 = acquire(&h, [10u8; 16], DEVICE, "2026-09-02T01:00:00+00:00").await;
        let s1 = [20u8; 16];
        open_session(&h, s1, l1.id, l1.fencing_token, 1, p1.len() as i64).await;
        append(&h, s1, 0, &p1).await.unwrap();
        commit(&h, s1, &manifest_for(&p1, 0, [30u8; 16]))
            .await
            .unwrap();
        release_lease(&h.db, &TENANT, &l1.id, "2026-09-02T00:31:00+00:00")
            .await
            .unwrap();

        let p2 = b"second-version-bytes".to_vec();
        let l2 = acquire(&h, [11u8; 16], DEVICE_B, "2026-09-02T02:00:00+00:00").await;
        let s2 = [21u8; 16];
        open_session(&h, s2, l2.id, l2.fencing_token, 2, p2.len() as i64).await;
        append(&h, s2, 0, &p2).await.unwrap();

        let err = commit_at(
            &h,
            s2,
            &manifest_for(&p2, 0, [31u8; 16]),
            "2026-09-02T01:30:00+00:00",
        )
        .await
        .expect_err("must refuse");
        assert!(
            matches!(
                err,
                FleetError::VersionConflict {
                    base: 0,
                    current: 1
                }
            ),
            "expected VersionConflict base 0 current 1, got {err:?}"
        );

        let target = resolve_download(&h.db, &TENANT, &PROFILE, None)
            .await
            .unwrap();
        assert_eq!(
            target.container_size,
            p1.len() as i64,
            "the winning version must be untouched"
        );
    }

    #[tokio::test]
    async fn content_hash_mismatch_is_refused() {
        let h = setup("hash").await;
        let payload = b"the-real-bytes".to_vec();
        let lease = acquire(&h, [10u8; 16], DEVICE, "2026-09-02T01:00:00+00:00").await;
        let session = [20u8; 16];
        open_session(
            &h,
            session,
            lease.id,
            lease.fencing_token,
            1,
            payload.len() as i64,
        )
        .await;
        append(&h, session, 0, &payload).await.unwrap();

        // Same length, different content: the size check cannot catch this.
        let mut wrong = manifest_for(&payload, 0, [30u8; 16]);
        wrong.container_sha256[0] ^= 0xFF;

        let err = commit(&h, session, &wrong).await.expect_err("must refuse");
        assert!(
            matches!(err, FleetError::ContentHashMismatch),
            "expected ContentHashMismatch, got {err:?}"
        );

        let v: i64 =
            sqlx::query("SELECT current_version FROM v2_profiles WHERE tenant_id = ? AND id = ?")
                .bind(TENANT.as_slice())
                .bind(PROFILE.as_slice())
                .fetch_one(&h.db)
                .await
                .unwrap()
                .get(0);
        assert_eq!(v, 0, "a failed commit must not advance the version");
    }

    #[tokio::test]
    async fn short_upload_is_refused() {
        let h = setup("short").await;
        let payload = b"0123456789".to_vec();
        let lease = acquire(&h, [10u8; 16], DEVICE, "2026-09-02T01:00:00+00:00").await;
        let session = [20u8; 16];
        open_session(
            &h,
            session,
            lease.id,
            lease.fencing_token,
            1,
            payload.len() as i64,
        )
        .await;
        append(&h, session, 0, &payload[..4]).await.unwrap();

        let err = commit(&h, session, &manifest_for(&payload, 0, [30u8; 16]))
            .await
            .expect_err("must refuse");
        assert!(
            matches!(
                err,
                FleetError::SizeMismatch {
                    declared: 10,
                    received: 4
                }
            ),
            "expected SizeMismatch 10 4, got {err:?}"
        );
    }

    #[tokio::test]
    async fn out_of_order_chunk_is_refused_and_upload_can_resume() {
        let h = setup("order").await;
        let lease = acquire(&h, [10u8; 16], DEVICE, "2026-09-02T01:00:00+00:00").await;
        let session = [20u8; 16];
        open_session(&h, session, lease.id, lease.fencing_token, 1, 100).await;

        append(&h, session, 0, b"aaaa").await.unwrap();

        let err = append(&h, session, 99, b"bbbb").await.expect_err("gap");
        assert!(
            matches!(
                err,
                FleetError::ChunkOutOfOrder {
                    expected: 4,
                    got: 99
                }
            ),
            "expected ChunkOutOfOrder 4 99, got {err:?}"
        );

        // The rejected chunk must not have been written.
        let n = append(&h, session, 4, b"bbbb").await.unwrap();
        assert_eq!(n, 8, "resume from the reported offset must work");
    }

    #[tokio::test]
    async fn oversized_upload_is_refused() {
        let h = setup("oversize").await;
        let lease = acquire(&h, [10u8; 16], DEVICE, "2026-09-02T01:00:00+00:00").await;
        let session = [20u8; 16];
        open_session(&h, session, lease.id, lease.fencing_token, 1, 4).await;

        let err = append(&h, session, 0, b"aaaaaaaa")
            .await
            .expect_err("too big");
        assert!(
            matches!(
                err,
                FleetError::DeclaredSizeExceeded {
                    declared: 4,
                    would_be: 8
                }
            ),
            "expected DeclaredSizeExceeded 4 8, got {err:?}"
        );
    }

    /// Same profile id in another tenant must not resolve.
    #[tokio::test]
    async fn download_is_tenant_scoped() {
        let h = setup("tenant").await;
        let payload = b"tenant-a-container".to_vec();
        let lease = acquire(&h, [10u8; 16], DEVICE, "2026-09-02T01:00:00+00:00").await;
        let session = [20u8; 16];
        open_session(
            &h,
            session,
            lease.id,
            lease.fencing_token,
            1,
            payload.len() as i64,
        )
        .await;
        append(&h, session, 0, &payload).await.unwrap();
        commit(&h, session, &manifest_for(&payload, 0, [30u8; 16]))
            .await
            .unwrap();

        let err = resolve_download(&h.db, &OTHER_TENANT, &PROFILE, Some(1))
            .await
            .expect_err("must not resolve across tenants");
        assert!(
            matches!(err, FleetError::NoSuchVersion),
            "expected NoSuchVersion, got {err:?}"
        );
    }

    #[tokio::test]
    async fn abort_removes_staging_and_closes_session() {
        let h = setup("abort").await;
        let lease = acquire(&h, [10u8; 16], DEVICE, "2026-09-02T01:00:00+00:00").await;
        let session = [20u8; 16];
        let staging = open_session(&h, session, lease.id, lease.fencing_token, 1, 100).await;
        append(&h, session, 0, b"partial").await.unwrap();
        assert!(staging.exists(), "staging file should exist before abort");

        abort_upload(&h.db, &TENANT, &session, "2026-09-02T00:10:00+00:00")
            .await
            .unwrap();

        assert!(!staging.exists(), "staging file must be removed on abort");
        let err = append(&h, session, 7, b"more").await.expect_err("closed");
        assert!(
            matches!(err, FleetError::SessionNotOpen),
            "expected SessionNotOpen, got {err:?}"
        );
    }

    /// Fencing tokens exist for the case a lease check alone cannot catch: a
    /// writer that opened its session under an older lease generation, while a
    /// *live* lease now belongs to someone else. The lease lookup succeeds and
    /// has not expired, so only the token comparison stands between the stale
    /// writer and a clobbered version.
    #[tokio::test]
    async fn commit_with_superseded_fencing_token_is_refused() {
        let h = setup("superseded").await;
        let payload = b"stale-generation-write".to_vec();

        let first = acquire(&h, [10u8; 16], DEVICE, "2026-09-02T01:00:00+00:00").await;
        let session = [20u8; 16];
        open_session(
            &h,
            session,
            first.id,
            first.fencing_token,
            1,
            payload.len() as i64,
        )
        .await;
        append(&h, session, 0, &payload).await.unwrap();

        // The first holder loses the lease and a second device takes it: a new
        // generation with a higher token is now live.
        release_lease(&h.db, &TENANT, &first.id, "2026-09-02T00:10:00+00:00")
            .await
            .unwrap();
        let second = acquire(&h, [11u8; 16], DEVICE_B, "2026-09-02T03:00:00+00:00").await;
        assert!(second.fencing_token > first.fencing_token);

        // Point the stale session at the live lease row while keeping its old
        // token — the delayed write of a holder that never learned it lost the
        // lease. Without the token comparison this commit lands.
        sqlx::query("UPDATE v2_upload_sessions SET lease_id = ? WHERE tenant_id = ? AND id = ?")
            .bind(second.id.as_slice())
            .bind(TENANT.as_slice())
            .bind(session.as_slice())
            .execute(&h.db)
            .await
            .unwrap();

        let err = commit(&h, session, &manifest_for(&payload, 0, [30u8; 16]))
            .await
            .expect_err("a superseded fencing token must not commit");
        assert!(
            matches!(
                err,
                FleetError::StaleFencingToken {
                    presented: p,
                    current: c,
                } if p == first.fencing_token && c == second.fencing_token
            ),
            "expected StaleFencingToken, got {err:?}"
        );

        let v: i64 =
            sqlx::query("SELECT current_version FROM v2_profiles WHERE tenant_id = ? AND id = ?")
                .bind(TENANT.as_slice())
                .bind(PROFILE.as_slice())
                .fetch_one(&h.db)
                .await
                .unwrap()
                .get(0);
        assert_eq!(v, 0, "a refused commit must not advance the version");
    }

    /// Eight devices race for the same profile; exactly one may win.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_checkout_has_exactly_one_winner() {
        let h = setup("race").await;
        let mut handles = Vec::new();

        for i in 0..8u8 {
            let db = h.db.clone();
            handles.push(tokio::spawn(async move {
                let mut lease_id = [0u8; 16];
                lease_id[0] = 100 + i;
                let mut device = [0u8; 16];
                device[0] = 200 + i;
                acquire_lease(
                    &db,
                    &TENANT,
                    &PROFILE,
                    &lease_id,
                    &ACCOUNT,
                    &device,
                    &SERVER,
                    0,
                    "2026-09-02T00:00:00+00:00",
                    "2026-09-02T01:00:00+00:00",
                )
                .await
                .is_ok()
            }));
        }

        let mut winners = 0;
        for handle in handles {
            if handle.await.unwrap() {
                winners += 1;
            }
        }
        assert_eq!(winners, 1, "exactly one concurrent checkout may succeed");

        let live: i64 = sqlx::query(
            "SELECT COUNT(*) FROM v2_leases
             WHERE tenant_id = ? AND profile_id = ? AND released_at IS NULL",
        )
        .bind(TENANT.as_slice())
        .bind(PROFILE.as_slice())
        .fetch_one(&h.db)
        .await
        .unwrap()
        .get(0);
        assert_eq!(live, 1, "exactly one live lease row may exist");
    }

    // -----------------------------------------------------------------------
    // G7: two-device drill
    //
    // The unit tests above each pin one invariant. These exercise the whole
    // interleaving instead: two devices, one profile, one server, sharing the
    // real lease/fencing/commit path end to end. Everything is disposable --
    // a fresh database and blob root per test, removed on drop.
    // -----------------------------------------------------------------------

    /// A device runs a complete cycle: check out, upload in chunks, commit.
    async fn device_cycle(
        h: &Harness,
        lease_id: [u8; 16],
        device: [u8; 16],
        session: [u8; 16],
        snapshot: [u8; 16],
        base_version: i64,
        payload: &[u8],
    ) -> Result<Committed, FleetError> {
        let lease = try_acquire(h, lease_id, device, "2026-09-02T01:00:00+00:00").await?;
        open_session(
            h,
            session,
            lease.id,
            lease.fencing_token,
            base_version + 1,
            payload.len() as i64,
        )
        .await;
        let mut offset = 0i64;
        for chunk in payload.chunks(512) {
            offset = append(h, session, offset, chunk).await?;
        }
        let m = manifest_for(payload, base_version, snapshot);
        commit(h, session, &m).await
    }

    async fn current_version(h: &Harness, tenant: &[u8; 16]) -> i64 {
        sqlx::query("SELECT current_version FROM v2_profiles WHERE tenant_id = ? AND id = ?")
            .bind(tenant.as_slice())
            .bind(PROFILE.as_slice())
            .fetch_one(&h.db)
            .await
            .unwrap()
            .get::<i64, _>(0)
    }

    /// Device A publishes, hands the profile over, and device B publishes on
    /// top. Versions advance one at a time and neither snapshot is lost.
    #[tokio::test]
    async fn g7_two_devices_hand_over_and_both_snapshots_survive() {
        let h = setup("g7-handover").await;
        let a_payload: Vec<u8> = (0..3000u32).map(|i| (i % 97) as u8).collect();
        let b_payload: Vec<u8> = (0..4096u32).map(|i| (i % 61) as u8).collect();

        let a = device_cycle(&h, [10; 16], DEVICE, [20; 16], [30; 16], 0, &a_payload)
            .await
            .expect("device A publish");
        assert_eq!(a.version, 1);

        release_lease(&h.db, &TENANT, &[10; 16], "2026-09-02T00:40:00+00:00")
            .await
            .unwrap();

        let b = device_cycle(&h, [11; 16], DEVICE_B, [21; 16], [31; 16], 1, &b_payload)
            .await
            .expect("device B publish");
        assert_eq!(
            b.version, 2,
            "the second device advances the version by one"
        );
        assert_eq!(current_version(&h, &TENANT).await, 2);

        // Both versions stay downloadable byte-for-byte: publishing a new
        // snapshot must not disturb the previous one.
        for (version, expected) in [(1i64, &a_payload), (2i64, &b_payload)] {
            let t = resolve_download(&h.db, &TENANT, &PROFILE, Some(version))
                .await
                .unwrap_or_else(|e| panic!("resolve v{version}: {e:?}"));
            assert_eq!(t.version, version);
            let bytes = read_range(
                std::path::Path::new(&t.blob_path),
                0,
                t.container_size as usize,
            )
            .await
            .unwrap();
            assert_eq!(
                bytes.as_slice(),
                expected.as_slice(),
                "version {version} bytes"
            );
        }
    }

    /// Device A stalls mid-upload while B takes over. When A wakes and tries
    /// to finish, it must lose: this is the split-brain the fencing token is
    /// for, driven here through the full two-device path.
    #[tokio::test]
    async fn g7_stalled_device_cannot_publish_after_handover() {
        let h = setup("g7-split").await;
        let payload = vec![7u8; 2048];

        let a = acquire(&h, [10; 16], DEVICE, "2026-09-02T01:00:00+00:00").await;
        open_session(&h, [20; 16], a.id, a.fencing_token, 1, payload.len() as i64).await;
        append(&h, [20; 16], 0, &payload).await.unwrap();

        // A is presumed gone; B takes the profile.
        release_lease(&h.db, &TENANT, &[10; 16], "2026-09-02T00:40:00+00:00")
            .await
            .unwrap();
        let b = acquire(&h, [11; 16], DEVICE_B, "2026-09-02T01:00:00+00:00").await;
        assert!(
            b.fencing_token > a.fencing_token,
            "a new lease must carry a strictly higher fencing token"
        );

        // A wakes up and tries to commit the work it still believes is valid.
        let m = manifest_for(&payload, 0, [30; 16]);
        let err = commit(&h, [20; 16], &m)
            .await
            .expect_err("a fenced device must not be able to commit");
        assert!(
            matches!(
                err,
                FleetError::StaleFencingToken { .. } | FleetError::NoSuchLease
            ),
            "expected a fencing rejection, got {err:?}"
        );
        assert_eq!(
            current_version(&h, &TENANT).await,
            0,
            "a fenced commit must not advance the profile"
        );

        // The token comparison itself must be load-bearing. Above, A's lease row
        // was gone, so NoSuchLease could answer before any token was compared.
        // Here a live lease exists and only the *token* on the session is stale,
        // which is the one path that isolates the fencing check.
        open_session(&h, [23; 16], b.id, a.fencing_token, 1, payload.len() as i64).await;
        append(&h, [23; 16], 0, &payload).await.unwrap();
        let m_stale = manifest_for(&payload, 0, [32; 16]);
        match commit(&h, [23; 16], &m_stale).await {
            Err(FleetError::StaleFencingToken { presented, current }) => {
                assert_eq!(presented, a.fencing_token);
                assert_eq!(current, b.fencing_token);
            }
            other => panic!("a live lease with a stale token must be fenced, got {other:?}"),
        }
        assert_eq!(current_version(&h, &TENANT).await, 0);

        // The profile is not wedged: B, which legitimately holds the lease,
        // still completes normally. (A third lease id would be refused here --
        // correctly -- because B's checkout is still live.)
        open_session(&h, [22; 16], b.id, b.fencing_token, 1, payload.len() as i64).await;
        append(&h, [22; 16], 0, &payload).await.unwrap();
        let m2 = manifest_for(&payload, 0, [31; 16]);
        let ok = commit(&h, [22; 16], &m2).await;
        assert!(ok.is_ok(), "profile wedged after fencing: {ok:?}");
        assert_eq!(current_version(&h, &TENANT).await, 1);
    }

    /// A commit whose base version is no longer current must be refused, even
    /// when every other input is valid. Without this the second writer would
    /// silently overwrite the first writer's snapshot (lost update).
    #[tokio::test]
    async fn g7_stale_base_version_is_refused() {
        let h = setup("g7-stale-base").await;
        let payload: Vec<u8> = (0..600u32).map(|i| (i % 97) as u8).collect();

        // First device publishes version 1.
        let a = acquire(&h, [10; 16], DEVICE, "2026-09-02T01:00:00+00:00").await;
        open_session(&h, [20; 16], a.id, a.fencing_token, 1, payload.len() as i64).await;
        append(&h, [20; 16], 0, &payload).await.unwrap();
        commit(&h, [20; 16], &manifest_for(&payload, 0, [30; 16]))
            .await
            .unwrap();
        release_lease(&h.db, &TENANT, &[10; 16], "2026-09-02T00:40:00+00:00")
            .await
            .unwrap();
        assert_eq!(current_version(&h, &TENANT).await, 1);

        // Second device still believes the profile sits at version 0.
        let b = acquire(&h, [11; 16], DEVICE_B, "2026-09-02T02:00:00+00:00").await;
        open_session(&h, [21; 16], b.id, b.fencing_token, 2, payload.len() as i64).await;
        append(&h, [21; 16], 0, &payload).await.unwrap();
        let stale = manifest_for(&payload, 0, [31; 16]);
        match commit(&h, [21; 16], &stale).await {
            Err(FleetError::VersionConflict { base, current }) => {
                assert_eq!(base, 0);
                assert_eq!(current, 1);
            }
            other => panic!("a stale base version must conflict, got {other:?}"),
        }
        assert_eq!(
            current_version(&h, &TENANT).await,
            1,
            "a refused commit must not advance the profile"
        );
    }

    /// A device that uploads fewer bytes than it declared must not be able to
    /// publish a truncated snapshot, and chunks must arrive in order.
    #[tokio::test]
    async fn g7_short_upload_and_out_of_order_chunks_are_refused() {
        let h = setup("g7-short-upload").await;
        let payload: Vec<u8> = (0..4000u32).map(|i| (i % 251) as u8).collect();

        let lease = acquire(&h, [10; 16], DEVICE, "2026-09-02T01:00:00+00:00").await;
        open_session(
            &h,
            [20; 16],
            lease.id,
            lease.fencing_token,
            1,
            payload.len() as i64,
        )
        .await;

        // A chunk that skips ahead leaves a hole; it must be refused outright.
        match append(&h, [20; 16], 100, &payload[..50]).await {
            Err(FleetError::ChunkOutOfOrder { expected, got }) => {
                assert_eq!(expected, 0);
                assert_eq!(got, 100);
            }
            other => panic!("an out-of-order chunk must be refused, got {other:?}"),
        }

        // Upload only part of what was declared, then try to publish.
        let sent = &payload[..1000];
        append(&h, [20; 16], 0, sent).await.unwrap();
        let m = manifest_for(sent, 0, [30; 16]);
        match commit(&h, [20; 16], &m).await {
            Err(FleetError::SizeMismatch { declared, received }) => {
                assert_eq!(declared, payload.len() as i64);
                assert_eq!(received, sent.len() as i64);
            }
            other => panic!("a short upload must not publish, got {other:?}"),
        }
        assert_eq!(current_version(&h, &TENANT).await, 0);
    }

    /// Many devices race for one checkout. Exactly one may win.
    #[tokio::test]
    async fn g7_concurrent_checkout_admits_exactly_one_device() {
        let h = setup("g7-race").await;
        let mut set = tokio::task::JoinSet::new();
        for i in 0..8u8 {
            let db = h.db.clone();
            set.spawn(async move {
                let mut lease_id = [0u8; 16];
                lease_id[0] = 100 + i;
                let mut device = [0u8; 16];
                device[0] = 200 + i;
                acquire_lease(
                    &db,
                    &TENANT,
                    &PROFILE,
                    &lease_id,
                    &ACCOUNT,
                    &device,
                    &SERVER,
                    0,
                    "2026-09-02T00:00:00+00:00",
                    "2026-09-02T01:00:00+00:00",
                )
                .await
                .is_ok()
            });
        }
        let mut winners = 0;
        while let Some(r) = set.join_next().await {
            if r.unwrap() {
                winners += 1;
            }
        }
        assert_eq!(winners, 1, "exactly one device may hold the checkout");
    }

    /// A rejected commit must roll back completely and leave the profile
    /// usable: no version bump, no manifest, and the next device succeeds.
    #[tokio::test]
    async fn g7_rejected_commit_rolls_back_and_profile_stays_usable() {
        let h = setup("g7-rollback").await;
        let payload = vec![3u8; 1024];

        let lease = acquire(&h, [10; 16], DEVICE, "2026-09-02T01:00:00+00:00").await;
        open_session(
            &h,
            [20; 16],
            lease.id,
            lease.fencing_token,
            1,
            payload.len() as i64,
        )
        .await;
        append(&h, [20; 16], 0, &payload).await.unwrap();

        // Manifest describes different bytes than were uploaded.
        let mut m = manifest_for(&payload, 0, [30; 16]);
        m.container_sha256 = [0xFF; 32];
        let err = commit(&h, [20; 16], &m)
            .await
            .expect_err("content hash mismatch must be rejected");
        assert!(
            matches!(err, FleetError::ContentHashMismatch),
            "expected ContentHashMismatch, got {err:?}"
        );

        assert_eq!(
            current_version(&h, &TENANT).await,
            0,
            "version must not move"
        );
        let manifests: i64 =
            sqlx::query("SELECT COUNT(*) FROM v2_snapshot_manifests WHERE tenant_id = ?")
                .bind(TENANT.as_slice())
                .fetch_one(&h.db)
                .await
                .unwrap()
                .get(0);
        assert_eq!(manifests, 0, "no manifest may survive a rejected commit");

        // Recovery: a fresh cycle on the same profile still works.
        release_lease(&h.db, &TENANT, &[10; 16], "2026-09-02T00:40:00+00:00")
            .await
            .unwrap();
        let ok = device_cycle(&h, [11; 16], DEVICE_B, [21; 16], [31; 16], 0, &payload)
            .await
            .expect("profile must remain usable after a rejected commit");
        assert_eq!(ok.version, 1);
    }

    /// Two tenants own a profile with the same id. Neither may read the
    /// other's snapshot, and one publishing must not move the other.
    #[tokio::test]
    async fn g7_tenants_cannot_reach_each_others_snapshots() {
        let h = setup("g7-tenant").await;
        let payload = vec![5u8; 800];

        device_cycle(&h, [10; 16], DEVICE, [20; 16], [30; 16], 0, &payload)
            .await
            .expect("tenant one publish");

        let err = resolve_download(&h.db, &OTHER_TENANT, &PROFILE, Some(1))
            .await
            .expect_err("cross-tenant download must fail");
        assert!(
            matches!(err, FleetError::NoSuchVersion),
            "expected NoSuchVersion, got {err:?}"
        );
        assert_eq!(
            current_version(&h, &OTHER_TENANT).await,
            0,
            "the other tenant's profile must be untouched"
        );
    }

    /// Restart the server: close the pool, reopen the same file, and confirm
    /// the committed snapshot is still there and still readable. An in-memory
    /// check would not catch an uncommitted transaction.
    #[tokio::test]
    async fn g7_committed_state_survives_restart() {
        let h = setup("g7-restart").await;
        let payload: Vec<u8> = (0..2500u32).map(|i| (i % 89) as u8).collect();

        let c = device_cycle(&h, [10; 16], DEVICE, [20; 16], [30; 16], 0, &payload)
            .await
            .expect("publish");

        let db_path = h._dir.0.join("server.db");
        h.db.close().await;

        let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", db_path.display()))
            .unwrap()
            .foreign_keys(true);
        let reopened = SqlitePoolOptions::new()
            .max_connections(2)
            .connect_with(opts)
            .await
            .unwrap();

        let after: i64 =
            sqlx::query("SELECT current_version FROM v2_profiles WHERE tenant_id = ? AND id = ?")
                .bind(TENANT.as_slice())
                .bind(PROFILE.as_slice())
                .fetch_one(&reopened)
                .await
                .unwrap()
                .get(0);
        assert_eq!(after, c.version, "version must survive a restart");

        let t = resolve_download(&reopened, &TENANT, &PROFILE, None)
            .await
            .expect("resolve after restart");
        let bytes = read_range(
            std::path::Path::new(&t.blob_path),
            0,
            t.container_size as usize,
        )
        .await
        .unwrap();
        assert_eq!(bytes, payload, "blob must survive a restart");

        reopened.close().await;
    }
}
