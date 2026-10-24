//! Epoch authority for the v2 control plane (ADR 0001 S1-S3, Option A).
//!
//! The external identity record is the authority for `server_instance_id +
//! restore_epoch`; `v2_server_state` only mirrors it. The server reads both at
//! startup and keeps v2 writes off unless they agree. It never creates,
//! repairs or rewrites the record: only `identity init` writes it, with the
//! server stopped.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::Context;
use shardx_team_server::identity_record::{self, IdentityRecordV2, RECORD_LEN};
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{Row, SqlitePool};

use crate::config::Config;

pub const RECORD_FILE: &str = "identity-record-v2.bin";
pub const TMP_FILE: &str = "identity-record-v2.bin.tmp";

/// Why v2 writes are disabled. The names are the plan's codes (L1238).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasonCode {
    Missing,
    Corrupt,
    BehindDb,
    ReconciliationRequired,
}

impl ReasonCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "EPOCH_AUTHORITY_MISSING",
            Self::Corrupt => "EPOCH_AUTHORITY_CORRUPT",
            Self::BehindDb => "EPOCH_AUTHORITY_BEHIND_DB",
            Self::ReconciliationRequired => "EPOCH_RECONCILIATION_REQUIRED",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Refusal {
    pub code: ReasonCode,
    pub detail: String,
}

/// A record that parsed and matches its mirror exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub server_instance_id: [u8; 16],
    pub restore_epoch: u64,
    pub external_record_sha256: [u8; 32],
}

pub type Authority = Result<Verified, Refusal>;

/// The `v2_server_state` row as stored.
pub struct Mirror {
    pub server_instance_id: Vec<u8>,
    pub restore_epoch: i64,
    pub external_record_sha256: Vec<u8>,
}

fn refuse(code: ReasonCode, detail: impl Into<String>) -> Refusal {
    Refusal {
        code,
        detail: detail.into(),
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// P1 preflight: the identity directory exists, is local, and is neither the
/// data directory nor inside or around it, because the data directory is in
/// the DB backup and rollback scope the record must stay out of.
pub fn preflight(identity_dir: &str, data_dir: &str) -> Result<PathBuf, String> {
    let identity = std::fs::canonicalize(identity_dir)
        .map_err(|e| format!("SHARDX_IDENTITY_DIR {identity_dir:?}: {e}"))?;
    if !identity.is_dir() {
        return Err(format!(
            "SHARDX_IDENTITY_DIR {identity_dir:?} is not a directory"
        ));
    }
    let data = std::fs::canonicalize(data_dir)
        .map_err(|e| format!("SHARDX_DATA_DIR {data_dir:?}: {e}"))?;
    if identity.starts_with(&data) || data.starts_with(&identity) {
        return Err(
            "SHARDX_IDENTITY_DIR must not equal, contain or sit inside SHARDX_DATA_DIR".into(),
        );
    }
    if is_network_path(&identity) {
        return Err("SHARDX_IDENTITY_DIR is on a network share, which is not supported".into());
    }
    Ok(identity)
}

#[cfg(windows)]
fn is_network_path(path: &Path) -> bool {
    // `canonicalize` resolves both UNC paths and mapped network drives to this
    // form.
    path.as_os_str().to_string_lossy().starts_with(r"\\?\UNC\")
}

#[cfg(target_os = "linux")]
fn is_network_path(path: &Path) -> bool {
    const NETWORK_FS: &[&str] = &[
        "nfs",
        "nfs4",
        "cifs",
        "smb3",
        "smbfs",
        "ncpfs",
        "afs",
        "ceph",
        "glusterfs",
        "fuse.sshfs",
        "fuse.davfs2",
    ];
    // Unknown is treated as remote: the record's durability cannot be assumed.
    let Ok(mounts) = std::fs::read_to_string("/proc/self/mounts") else {
        return true;
    };
    let mut best: Option<(usize, String)> = None;
    for line in mounts.lines() {
        let mut fields = line.split(' ');
        let (Some(_), Some(mount), Some(fstype)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let mount = unescape_mount(mount);
        if path.starts_with(&mount) && best.as_ref().is_none_or(|(len, _)| mount.len() >= *len) {
            best = Some((mount.len(), fstype.to_string()));
        }
    }
    best.is_none_or(|(_, fstype)| NETWORK_FS.contains(&fstype.as_str()))
}

/// `/proc/self/mounts` writes space, tab, newline and backslash as `\ooo`.
#[cfg(target_os = "linux")]
fn unescape_mount(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let octal = bytes.get(i + 1..i + 4).and_then(|d| {
            std::str::from_utf8(d)
                .ok()
                .and_then(|d| u8::from_str_radix(d, 8).ok())
        });
        match (bytes[i], octal) {
            (b'\\', Some(b)) => {
                out.push(b);
                i += 4;
            }
            (b, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// shortcut: no network-filesystem probe outside Windows and Linux, the only
// platforms the server ships for; add one before supporting another.
#[cfg(not(any(windows, target_os = "linux")))]
fn is_network_path(_path: &Path) -> bool {
    false
}

/// Read and parse the record under the P1 rules. Reads at most one byte past
/// the fixed size, so an oversized file is rejected without loading it.
fn read_record(dir: &Path) -> Result<(IdentityRecordV2, [u8; 32]), Refusal> {
    let path = dir.join(RECORD_FILE);
    let mut bytes = Vec::with_capacity(RECORD_LEN + 1);
    let read = std::fs::File::open(&path)
        .and_then(|f| f.take(RECORD_LEN as u64 + 1).read_to_end(&mut bytes));
    match read {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(refuse(
                ReasonCode::Missing,
                format!("{} does not exist", path.display()),
            ))
        }
        Err(e) => {
            return Err(refuse(
                ReasonCode::Corrupt,
                format!("cannot read {}: {e}", path.display()),
            ))
        }
    }
    let record = identity_record::parse(&bytes)
        .map_err(|r| refuse(ReasonCode::Corrupt, format!("record rejected: {r:?}")))?;
    let fixed: [u8; RECORD_LEN] = bytes.try_into().expect("parse checked the length");
    Ok((record, identity_record::external_record_sha256(&fixed)))
}

/// Compare a parsed record with the mirror, following the plan's startup
/// crash table (L2256-L2265). Restore preparation is not supported yet, so a
/// record ahead of the mirror can only be resolved by the operator.
pub fn reconcile(
    record: &IdentityRecordV2,
    record_sha256: [u8; 32],
    mirror: Option<&Mirror>,
) -> Authority {
    let Some(mirror) = mirror else {
        return Err(refuse(
            ReasonCode::ReconciliationRequired,
            "the identity record exists but v2_server_state has no mirror row",
        ));
    };
    if mirror.server_instance_id != record.server_instance_id {
        return Err(refuse(
            ReasonCode::BehindDb,
            "the record's server_instance_id differs from the database mirror",
        ));
    }
    let Ok(mirror_epoch) = u64::try_from(mirror.restore_epoch) else {
        return Err(refuse(
            ReasonCode::ReconciliationRequired,
            "the database mirror holds a negative restore_epoch",
        ));
    };
    if mirror_epoch > record.restore_epoch {
        return Err(refuse(
            ReasonCode::BehindDb,
            "the record's restore_epoch is behind the database mirror",
        ));
    }
    if mirror_epoch < record.restore_epoch {
        return Err(refuse(
            ReasonCode::ReconciliationRequired,
            "the record's restore_epoch is ahead of the database mirror",
        ));
    }
    // Same instance and epoch but another record: the authority file was
    // replaced, which the mirror attests and nothing may silently accept.
    if mirror.external_record_sha256 != record_sha256 {
        return Err(refuse(
            ReasonCode::BehindDb,
            "the record differs from the one the database mirror attests",
        ));
    }
    Ok(Verified {
        server_instance_id: record.server_instance_id,
        restore_epoch: record.restore_epoch,
        external_record_sha256: record_sha256,
    })
}

/// Decide the authority from configuration, the record on disk and the mirror.
pub fn authority(cfg: &Config, mirror: Option<&Mirror>) -> Authority {
    let Some(dir) = cfg.identity_dir.as_deref() else {
        return Err(refuse(
            ReasonCode::Missing,
            "SHARDX_IDENTITY_DIR is not set",
        ));
    };
    let dir = preflight(dir, &cfg.data_dir).map_err(|e| refuse(ReasonCode::Missing, e))?;
    let (record, sha256) = read_record(&dir)?;
    reconcile(&record, sha256, mirror)
}

async fn table_exists(pool: &SqlitePool, table: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?)",
    )
    .bind(table)
    .fetch_one(pool)
    .await
}

/// The mirror row, or None when the row (or, before migrations, the table) is
/// absent.
pub async fn read_mirror(pool: &SqlitePool) -> Result<Option<Mirror>, sqlx::Error> {
    if !table_exists(pool, "v2_server_state").await? {
        return Ok(None);
    }
    let row = sqlx::query(
        "SELECT server_instance_id, restore_epoch, external_record_sha256 \
         FROM v2_server_state WHERE singleton = 1",
    )
    .fetch_optional(pool)
    .await?;
    row.map(|r| {
        Ok(Mirror {
            server_instance_id: r.try_get("server_instance_id")?,
            restore_epoch: r.try_get("restore_epoch")?,
            external_record_sha256: r.try_get("external_record_sha256")?,
        })
    })
    .transpose()
}

/// Fail unless `path` is absent. Any error other than NotFound counts as
/// present, so an unreadable leftover is never overwritten.
fn ensure_absent(path: &Path) -> anyhow::Result<()> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => anyhow::bail!("refusing: {} already exists", path.display()),
        Err(e) => anyhow::bail!("refusing: cannot check {}: {e}", path.display()),
    }
}

async fn ensure_no_rows(pool: &SqlitePool, table: &str) -> anyhow::Result<()> {
    if table_exists(pool, table).await? {
        let any: bool = sqlx::query_scalar(&format!("SELECT EXISTS (SELECT 1 FROM {table})"))
            .fetch_one(pool)
            .await?;
        anyhow::ensure!(!any, "refusing: {table} already has a row");
    }
    Ok(())
}

/// temp -> flush -> fsync -> atomic replace -> fsync the directory (plan
/// L1055, L2252).
fn write_record(dir: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let tmp = dir.join(TMP_FILE);
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .and_then(|mut f| {
            f.write_all(bytes)?;
            f.flush()?;
            f.sync_all()
        });
    if let Err(e) = written {
        // Only a temp file this call created can be here, and it is not the
        // authority.
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            let _ = std::fs::remove_file(&tmp);
        }
        return Err(e).with_context(|| format!("writing {}", tmp.display()));
    }
    std::fs::rename(&tmp, dir.join(RECORD_FILE))
        .with_context(|| format!("replacing {}", dir.join(RECORD_FILE).display()))?;
    sync_dir(dir).with_context(|| format!("fsync of {}", dir.display()))
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

#[cfg(windows)]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    // FILE_FLAG_BACKUP_SEMANTICS opens the directory itself; FlushFileBuffers
    // on it needs write access.
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(dir)?
        .sync_all()
}

/// `identity init` (ADR 0001 Option A, command 1). The caller holds the data
/// directory lock.
pub async fn init(cfg: &Config) -> anyhow::Result<()> {
    let dir = cfg
        .identity_dir
        .as_deref()
        .context("SHARDX_IDENTITY_DIR must be set")?;
    let dir = preflight(dir, &cfg.data_dir).map_err(anyhow::Error::msg)?;
    ensure_absent(&dir.join(RECORD_FILE))?;
    ensure_absent(&dir.join(TMP_FILE))?;

    let pool = crate::db::open_pool(cfg).await?;
    ensure_no_rows(&pool, "v2_server_state").await?;
    ensure_no_rows(&pool, "v2_tenants").await?;
    shardx_team_server::run_migrations(&pool).await?;

    let instance = uuid::Uuid::new_v4().into_bytes();
    let now_ms = u64::try_from(chrono::Utc::now().timestamp_millis())?;
    let bytes = IdentityRecordV2::genesis(instance, now_ms)
        .encode()
        .map_err(|r| anyhow::anyhow!("cannot encode the record: {r:?}"))?;
    let sha256 = identity_record::external_record_sha256(&bytes);

    // Record first, mirror second (L2252). A crash in between leaves a record
    // without a mirror, which startup reports instead of repairing.
    write_record(&dir, &bytes)?;

    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO v2_server_state \
         (singleton, server_instance_id, restore_epoch, external_record_sha256, updated_at) \
         VALUES (1, ?, 0, ?, ?)",
    )
    .bind(instance.as_slice())
    .bind(sha256.as_slice())
    .bind(crate::util::now_rfc3339())
    .execute(&mut *tx)
    .await
    .context("the record was written but the mirror insert failed")?;
    tx.commit()
        .await
        .context("the record was written but the mirror commit failed")?;

    let mirror = read_mirror(&pool).await?;
    let verified = authority(cfg, mirror.as_ref())
        .map_err(|r| anyhow::anyhow!("readback failed: {}: {}", r.code.as_str(), r.detail))?;
    anyhow::ensure!(
        verified.server_instance_id == instance && verified.external_record_sha256 == sha256,
        "readback returned a different record"
    );
    pool.close().await;

    println!("server_instance_id={}", hex(&instance));
    println!("restore_epoch=0");
    println!("external_record_sha256={}", hex(&sha256));
    Ok(())
}

/// Open the existing database read-only, or None if there is none yet.
async fn open_read_only(cfg: &Config) -> anyhow::Result<Option<SqlitePool>> {
    if !Path::new(&cfg.db_path).exists() {
        return Ok(None);
    }
    let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", cfg.db_path))?
        .read_only(true)
        .create_if_missing(false);
    Ok(Some(SqlitePool::connect_with(opts).await?))
}

/// `identity show`: report whether the record verifies against the mirror.
/// Read-only; returns whether it verified.
pub async fn show(cfg: &Config) -> anyhow::Result<bool> {
    let mirror = match open_read_only(cfg).await? {
        Some(pool) => {
            let mirror = read_mirror(&pool).await?;
            pool.close().await;
            mirror
        }
        None => None,
    };
    match authority(cfg, mirror.as_ref()) {
        Ok(v) => {
            println!("status=OK");
            println!("server_instance_id={}", hex(&v.server_instance_id));
            println!("restore_epoch={}", v.restore_epoch);
            println!("external_record_sha256={}", hex(&v.external_record_sha256));
            Ok(true)
        }
        Err(r) => {
            println!("status={}", r.code.as_str());
            println!("reason={}", r.detail);
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(epoch: u64) -> (IdentityRecordV2, [u8; 32]) {
        let mut r = IdentityRecordV2::genesis([5u8; 16], 1);
        if epoch > 0 {
            r.restore_epoch = epoch;
            r.restore_txn_id = [1; 16];
            r.restored_db_sha256 = [2; 32];
            r.transition_set_sha256 = [3; 32];
        }
        let bytes = r.encode().unwrap();
        (r, identity_record::external_record_sha256(&bytes))
    }

    fn mirror(instance: [u8; 16], epoch: i64, sha: [u8; 32]) -> Mirror {
        Mirror {
            server_instance_id: instance.to_vec(),
            restore_epoch: epoch,
            external_record_sha256: sha.to_vec(),
        }
    }

    fn code(a: Authority) -> ReasonCode {
        a.unwrap_err().code
    }

    #[test]
    fn crash_table_rows_map_to_one_code_each() {
        let (r, sha) = record(1);
        assert_eq!(
            reconcile(&r, sha, Some(&mirror([5; 16], 1, sha))).unwrap(),
            Verified {
                server_instance_id: [5; 16],
                restore_epoch: 1,
                external_record_sha256: sha,
            }
        );
        // Interrupted init: record without mirror.
        assert_eq!(
            code(reconcile(&r, sha, None)),
            ReasonCode::ReconciliationRequired
        );
        // Record ahead of the mirror without a preparation manifest.
        assert_eq!(
            code(reconcile(&r, sha, Some(&mirror([5; 16], 0, sha)))),
            ReasonCode::ReconciliationRequired
        );
        // Record behind the mirror, or from another instance.
        assert_eq!(
            code(reconcile(&r, sha, Some(&mirror([5; 16], 2, sha)))),
            ReasonCode::BehindDb
        );
        assert_eq!(
            code(reconcile(&r, sha, Some(&mirror([6; 16], 1, sha)))),
            ReasonCode::BehindDb
        );
        // Same instance and epoch, different record bytes.
        assert_eq!(
            code(reconcile(&r, sha, Some(&mirror([5; 16], 1, [9; 32])))),
            ReasonCode::BehindDb
        );
    }

    #[test]
    fn preflight_refuses_the_data_directory_and_anything_around_it() {
        let base = std::env::temp_dir().join(format!("shardx-preflight-{}", std::process::id()));
        let data = base.join("data");
        let inside = data.join("identity");
        let outside = base.join("identity");
        for d in [&inside, &outside] {
            std::fs::create_dir_all(d).unwrap();
        }
        let s = |p: &Path| p.to_string_lossy().into_owned();
        assert!(preflight(&s(&data), &s(&data)).is_err());
        assert!(preflight(&s(&inside), &s(&data)).is_err());
        assert!(preflight(&s(&base), &s(&data)).is_err());
        assert!(preflight(&s(&base.join("absent")), &s(&data)).is_err());
        assert!(preflight(&s(&outside), &s(&data)).is_ok());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mount_fields_are_unescaped() {
        assert_eq!(unescape_mount(r"/mnt/a\040b"), "/mnt/a b");
        assert_eq!(unescape_mount(r"/plain"), "/plain");
    }
}
