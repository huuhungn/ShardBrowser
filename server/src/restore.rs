//! Offline restore of the v2 data plane across a restore epoch (plan 12.4
//! L2246-L2267; ADR 0002 D-1).
//!
//! `restore prepare` builds a candidate DB (the live DB with heads, snapshots
//! and their committed uploads taken from a backup), the artifacts of the
//! staged `E -> E+1` transitions, and the preparation manifest. `restore
//! commit` then writes record `E+1` (the authority commit point), installs the
//! candidate, rebuilds the mirror in one transaction, and retires the bundle.
//! Every step is classified K1-K12 from the files alone, so a crash anywhere
//! resumes from exactly one row of the plan's table. The server never resumes
//! a restore; it only classifies, and opens the DB read-only while one is in
//! progress.
//!
//! The online filing route stages each tenant's signed transition in the
//! live DB at `E`; prepare takes the set from there instead of a
//! `--transitions` directory.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context};
use sha2::{Digest, Sha256};
use shardx_team_server::identity_record::IdentityRecordV2;
use shardx_team_server::restore_manifest::{
    self as rm, IndexEntry, PreparationManifestV2, State, TransitionSetIndexV2, MANIFEST_FILE,
};
use shared::canonical as c;
use shared::mutation::IdempotentStoredResponseV2;
use shared::profile_lease::{
    LeaseOrigin, ProfileLeaseV2, UploadCreatedV2, UploadFinalizedV2, RECORD_TYPE_UPLOAD_CREATED,
    RECORD_TYPE_UPLOAD_FINALIZED,
};
use shared::restore_epoch::{
    mapping_root, verify_inclusion, RestoreEpochInclusionProofV2, RestoreEpochLeafV2,
    SignedRestoreEpochTransitionV2,
};
use shared::snapshot_v2::{CommitReceiptBindingV2, CommitRequestV2};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqliteSynchronous};
use sqlx::{ConnectOptions, Connection, Row, SqliteConnection};

use crate::config::Config;
use crate::identity::{self, hex, Mirror, Verified, RECORD_FILE};
use crate::routes::v2_auth::Session;
use crate::routes::v2_root_grants::is_active_custodian;
use crate::util;

/// Where each table of the candidate comes from (D-1 restore-scope table).
/// Prepare refuses a schema with a table missing here.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Source {
    /// The live row set, unchanged.
    Live,
    /// Rebuilt from the backup's data plane.
    Backup,
    /// Every row removed.
    Cleared,
}

const SCOPE: &[(&str, Source)] = &[
    ("_sqlx_migrations", Source::Live),
    ("users", Source::Live),
    ("folders", Source::Live),
    ("proxies", Source::Live),
    ("environments", Source::Live),
    ("acl", Source::Live),
    ("locks", Source::Live),
    ("snapshots", Source::Live),
    ("audit_log", Source::Live),
    ("v2_server_state", Source::Live),
    ("v2_tenants", Source::Live),
    ("v2_accounts", Source::Live),
    ("v2_tenant_memberships", Source::Live),
    ("v2_devices", Source::Live),
    ("v2_device_quarantine", Source::Live),
    ("v2_device_approvals", Source::Live),
    ("v2_device_revocations", Source::Live),
    ("v2_capability_grants", Source::Live),
    ("v2_legacy_capability_grants", Source::Live),
    ("v2_grant_quarantine", Source::Live),
    ("v2_root_key_generations", Source::Live),
    ("v2_tenant_root_key_grants", Source::Live),
    ("v2_legacy_tenant_root_key_grants", Source::Live),
    ("v2_fleets", Source::Live),
    ("v2_fleet_key_generations", Source::Live),
    ("v2_fleet_key_grants", Source::Live),
    ("v2_fleet_device_hpke_grants", Source::Live),
    ("v2_fleet_recovery_grants", Source::Live),
    ("v2_fleet_rotation_grants", Source::Live),
    ("v2_restore_epoch_transitions", Source::Live),
    ("v2_restore_epoch_transition_proofs", Source::Live),
    ("v2_audit_events", Source::Live),
    ("v2_idempotency", Source::Live),
    ("v2_bootstrap_guards", Source::Live),
    ("v2_first_device_confirmations", Source::Live),
    ("v2_replay_ledger", Source::Live),
    ("v2_operations", Source::Live),
    ("v2_tenant_issuers", Source::Live),
    ("v2_upload_quarantine", Source::Live),
    // Pre-0025 tables with no v2 writer; kept as they are.
    ("v2_leases", Source::Live),
    ("v2_snapshot_manifests", Source::Live),
    ("v2_upload_sessions", Source::Live),
    ("v2_profiles", Source::Backup),
    ("v2_snapshots", Source::Backup),
    ("v2_uploads", Source::Backup),
    // Children before parents: these are deleted in this order.
    ("v2_profile_leases", Source::Cleared),
    ("v2_upload_chunks", Source::Cleared),
    ("v2_spent_refresh_tokens", Source::Cleared),
    ("v2_sessions", Source::Cleared),
    ("v2_device_session_challenges", Source::Cleared),
    ("v2_enrollment_challenges", Source::Cleared),
    ("v2_pre_device_sessions", Source::Cleared),
];

/// The D-1 classes, evaluated before any SQLite write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    K1,
    K2,
    K3,
    K4,
    K5a,
    K5b,
    K6,
    K7,
    K8,
    K9,
    K10,
    K11,
    K12,
}

impl Class {
    /// The plan's crash-table row (12.4).
    pub fn row(self) -> &'static str {
        match self {
            Self::K1 => "L2258",
            Self::K3 => "L2259",
            Self::K5a | Self::K7 => "L2260",
            Self::K8 => "L2261",
            Self::K9 => "L2262",
            Self::K4 | Self::K6 | Self::K12 => "L2263",
            Self::K2 => "L2264",
            Self::K5b | Self::K10 | Self::K11 => "L2265",
        }
    }

    /// A restore is in progress, or K2's security incident (C-3, ADR 0002
    /// L520): the server opens the DB read-only, so no write of any kind
    /// changes it before `restore commit` or `abort`.
    pub fn read_only(self) -> bool {
        !matches!(self, Self::K1 | Self::K3 | Self::K4)
    }
}

/// `M`: the mirror read with `mode=ro`.
pub enum Mirrored {
    /// No file at the DB path.
    Absent,
    /// A file that cannot be read (for example a hot journal blocks it).
    Unreadable,
    /// A readable file without the mirror row.
    Rowless,
    Row(Mirror),
}

/// `P`: the preparation manifest.
pub enum Prep {
    Absent,
    Unparsable,
    Parsed(PreparationManifestV2),
}

pub struct Observed {
    /// `X`, or None when missing or corrupt.
    pub x: Option<(IdentityRecordV2, [u8; 32])>,
    pub m: Mirrored,
    /// A `-journal` sidecar is at the DB path.
    pub hot_journal: bool,
    pub p: Prep,
    /// `C`: the candidate file is present.
    pub c: bool,
    /// `Dx`: the artifact directory of `X.restore_txn_id` exists.
    pub dx: bool,
}

fn mirror_is(m: &Mirror, instance: &[u8; 16], epoch: u64, sha: &[u8; 32]) -> bool {
    m.server_instance_id == instance
        && u64::try_from(m.restore_epoch) == Ok(epoch)
        && m.external_record_sha256 == sha
}

/// The D-1 classification; the first matching class wins.
pub fn classify(o: &Observed) -> Class {
    let Some((x, xsha)) = &o.x else {
        return Class::K1;
    };
    let row = match &o.m {
        Mirrored::Row(m) => Some(m),
        _ => None,
    };
    if let Some(m) = row {
        let behind = u64::try_from(m.restore_epoch).is_ok_and(|e| x.restore_epoch < e);
        if m.server_instance_id != x.server_instance_id || behind {
            return Class::K2;
        }
    }
    let m_is_x = row.is_some_and(|m| mirror_is(m, &x.server_instance_id, x.restore_epoch, xsha));
    let p = match &o.p {
        Prep::Absent if m_is_x => return Class::K3,
        // K4 is every other no-manifest record: how to recover (operator
        // only). `identity show` keeps ADR 0001's finer reason code, such as
        // EPOCH_AUTHORITY_BEHIND_DB for the same epoch with other bytes,
        // which says why v2 is off.
        Prep::Absent => return Class::K4,
        Prep::Unparsable => {
            return match (m_is_x, o.dx, o.c) {
                (true, false, _) => Class::K5a,
                (true, true, false) => Class::K5b,
                _ => Class::K6,
            }
        }
        Prep::Parsed(p) => p,
    };
    let pre = x.restore_epoch == p.previous_epoch && xsha == &p.previous_record_sha256;
    let post = x.restore_epoch == p.new_epoch
        && x.server_instance_id == p.server_instance_id
        && x.restore_txn_id == p.restore_txn_id
        && x.restored_db_sha256 == p.candidate_db_sha256
        && x.transition_set_sha256 == p.transition_set_sha256;
    let prepared = p.state == State::Prepared;
    let m_is_e = row.is_some_and(|m| {
        mirror_is(
            m,
            &p.server_instance_id,
            p.previous_epoch,
            &p.previous_record_sha256,
        )
    });
    let m_behind = row.is_some_and(|m| u64::try_from(m.restore_epoch).is_ok_and(|e| e < p.new_epoch))
        // A crash inside the step-5 transaction leaves a hot journal that a
        // read-only open cannot roll back; commit proves the rollback restores
        // the exact candidate before it continues.
        || (o.hot_journal && matches!(o.m, Mirrored::Unreadable));
    if pre && m_is_x && prepared {
        Class::K7
    } else if post && prepared && o.c && (m_is_e || matches!(o.m, Mirrored::Absent)) {
        Class::K8
    } else if post && prepared && !o.c && m_behind {
        Class::K9
    } else if post && m_is_x && prepared {
        Class::K10
    } else if post && m_is_x && !prepared {
        Class::K11
    } else {
        Class::K12
    }
}

/// Test-only crash injection: a debug build exits at the named write point,
/// leaving the files exactly as a killed process would (G2-52).
fn crash(point: &str) {
    #[cfg(debug_assertions)]
    if std::env::var_os("SHARDX_TEST_CRASH_AT").is_some_and(|v| v == point) {
        eprintln!("injected crash at {point}");
        std::process::exit(86);
    }
    #[cfg(not(debug_assertions))]
    let _ = point;
}

struct Site {
    identity: PathBuf,
    data: PathBuf,
    db: PathBuf,
}

impl Site {
    fn new(cfg: &Config) -> anyhow::Result<Self> {
        let dir = cfg
            .identity_dir
            .as_deref()
            .context("SHARDX_IDENTITY_DIR must be set")?;
        Ok(Self {
            identity: identity::preflight(dir, &cfg.data_dir).map_err(anyhow::Error::msg)?,
            data: PathBuf::from(&cfg.data_dir),
            db: PathBuf::from(&cfg.db_path),
        })
    }

    fn candidate(&self, txn: &[u8; 16]) -> PathBuf {
        self.data.join(format!("restore-candidate-{}.db", hex(txn)))
    }

    fn artifacts(&self, txn: &[u8; 16]) -> PathBuf {
        self.identity.join(format!("restore-{}", hex(txn)))
    }

    fn archive(&self, txn: &[u8; 16], suffix: &str) -> PathBuf {
        self.data
            .join(format!("pre-restore-{}.db{suffix}", hex(txn)))
    }

    fn sidecar(&self, suffix: &str) -> PathBuf {
        let mut s = self.db.clone().into_os_string();
        s.push(suffix);
        s.into()
    }
}

const SIDECARS: [&str; 3] = ["-wal", "-shm", "-journal"];

/// Present unless the entry is certainly absent: an unreadable entry is never
/// taken for a missing one.
fn sidecar(db: &Path, suffix: &str) -> PathBuf {
    let mut s = db.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

fn exists(path: &Path) -> bool {
    !matches!(std::fs::symlink_metadata(path), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
}

fn sha256_file(path: &Path) -> anyhow::Result<[u8; 32]> {
    let mut f = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            return Ok(h.finalize().into());
        }
        h.update(&buf[..n]);
    }
}

/// The P1 primitive: `<name>.tmp`, flush, fsync, replace, fsync the directory.
/// `point` names the crash points `<point>.tmp` and `<point>.replaced`.
fn write_replace(dir: &Path, name: &str, bytes: &[u8], point: &str) -> anyhow::Result<()> {
    let tmp = dir.join(format!("{name}.tmp"));
    let mut f =
        std::fs::File::create(&tmp).with_context(|| format!("writing {}", tmp.display()))?;
    f.write_all(bytes)?;
    f.flush()?;
    f.sync_all()?;
    drop(f);
    crash(&format!("{point}.tmp"));
    std::fs::rename(&tmp, dir.join(name)).with_context(|| format!("installing {name}"))?;
    crash(&format!("{point}.replaced"));
    identity::sync_dir(dir).with_context(|| format!("fsync of {}", dir.display()))
}

fn sync_file(path: &Path) -> anyhow::Result<()> {
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .and_then(|f| f.sync_all())
        .with_context(|| format!("fsync of {}", path.display()))
}

async fn connect(path: &Path, read_only: bool) -> anyhow::Result<SqliteConnection> {
    let opts = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(false)
        .foreign_keys(true);
    let opts = if read_only {
        opts.read_only(true)
    } else {
        opts.journal_mode(SqliteJournalMode::Delete)
            .synchronous(SqliteSynchronous::Full)
    };
    opts.connect()
        .await
        .with_context(|| format!("opening {}", path.display()))
}

async fn observe_mirror(cfg: &Config) -> Mirrored {
    if !exists(Path::new(&cfg.db_path)) {
        return Mirrored::Absent;
    }
    let Ok(Some(pool)) = identity::open_read_only(cfg).await else {
        return Mirrored::Unreadable;
    };
    let read = identity::read_mirror(&pool).await;
    pool.close().await;
    match read {
        Ok(Some(m)) => Mirrored::Row(m),
        Ok(None) => Mirrored::Rowless,
        Err(_) => Mirrored::Unreadable,
    }
}

fn read_manifest(site: &Site) -> Prep {
    let path = site.identity.join(MANIFEST_FILE);
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Prep::Absent,
        Ok(m) if m.file_type().is_file() => {
            let mut bytes = Vec::new();
            let read = std::fs::File::open(&path)
                .and_then(|f| f.take(rm::MANIFEST_LEN as u64 + 1).read_to_end(&mut bytes));
            match read.ok().and_then(|_| rm::parse(&bytes).ok()) {
                Some(p) => Prep::Parsed(p),
                None => Prep::Unparsable,
            }
        }
        _ => Prep::Unparsable,
    }
}

fn names_in(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .map(|it| {
            it.filter_map(|e| e.ok()?.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default()
}

fn is_candidate(name: &str) -> bool {
    name.starts_with("restore-candidate-")
}

fn is_archive(name: &str) -> bool {
    name.starts_with("pre-restore-")
}

/// Everything K3 lists as a stray: never evidence, removed by `--orphans`
/// except the `pre-restore-*` archives, the only copy of a pre-restore live
/// DB, which only `--delete-archives` removes.
fn orphans(site: &Site) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = names_in(&site.data)
        .into_iter()
        .filter(|n| is_candidate(n) || is_archive(n))
        .map(|n| site.data.join(n))
        .collect();
    out.extend(
        names_in(&site.identity)
            .into_iter()
            .filter(|n| n.starts_with("restore-") || n.ends_with(".tmp"))
            .map(|n| site.identity.join(n)),
    );
    out.sort();
    out
}

async fn observe(cfg: &Config) -> (Option<Site>, Observed) {
    let site = Site::new(cfg).ok();
    let m = observe_mirror(cfg).await;
    let Some(site) = site else {
        let o = Observed {
            x: None,
            m,
            hot_journal: false,
            p: Prep::Absent,
            c: false,
            dx: false,
        };
        return (None, o);
    };
    let x = identity::read_record(&site.identity).ok();
    let p = read_manifest(&site);
    let c = match &p {
        Prep::Parsed(p) => exists(&site.candidate(&p.restore_txn_id)),
        _ => names_in(&site.data)
            .iter()
            .any(|n| is_candidate(n) && n.ends_with(".db")),
    };
    let dx = x
        .as_ref()
        .is_some_and(|(x, _)| exists(&site.artifacts(&x.restore_txn_id)));
    let o = Observed {
        x,
        m,
        hot_journal: exists(&site.sidecar("-journal")),
        p,
        c,
        dx,
    };
    (Some(site), o)
}

/// The class the server starts in.
pub async fn startup_class(cfg: &Config) -> Class {
    classify(&observe(cfg).await.1)
}

/// [`startup_class`], refusing a K1 or K4 start that would create an empty
/// DB at the DB path while files of a restore are left (round-4 B7).
pub async fn startup_gate(cfg: &Config) -> anyhow::Result<Class> {
    let (site, o) = observe(cfg).await;
    let class = classify(&o);
    if let (Class::K1 | Class::K4, Mirrored::Absent, Some(site)) = (class, &o.m, &site) {
        ensure!(
            matches!(o.p, Prep::Absent) && orphans(site).is_empty(),
            "refusing to start: no database is at the DB path and files of a restore are \
             left ({class:?}, plan {}); run `restore status`",
            class.row()
        );
    }
    Ok(class)
}

/// `restore status`: read-only; prints the class and the plan row.
pub async fn status(cfg: &Config) -> anyhow::Result<()> {
    let (site, o) = observe(cfg).await;
    let class = classify(&o);
    println!("class={class:?}");
    println!("row={}", class.row());
    if class.read_only() {
        // WI-AUDIT-RO: v1 audit writes the read-only DB refused since it opened.
        println!(
            "audit_write_failures={}",
            crate::audit::read_only_failures(&cfg.data_dir)?
        );
    }
    if let (Class::K3, Some(site)) = (class, &site) {
        for path in orphans(site) {
            println!("orphan={}", path.display());
        }
    }
    Ok(())
}

fn refuse_release_build() -> anyhow::Result<()> {
    // ADR 0002 D-1: production restore waits for the v0.2.2 signing workflow.
    ensure!(
        cfg!(debug_assertions),
        "restore export-heads and restore prepare are refused before v0.2.2"
    );
    Ok(())
}

/// K3 with no manifest, candidate or `restore-*` directory left (step 1').
fn require_clean_k3(site: &Site, o: &Observed) -> anyhow::Result<(IdentityRecordV2, [u8; 32])> {
    let class = classify(o);
    ensure!(
        class == Class::K3,
        "refusing: the server is in {class:?} ({}), not K3",
        class.row()
    );
    let stray: Vec<_> = orphans(site)
        .into_iter()
        .filter(|p| {
            let n = p.file_name().and_then(|n| n.to_str()).unwrap_or_default();
            is_candidate(n) || p.is_dir()
        })
        .collect();
    ensure!(
        stray.is_empty(),
        "refusing: leftovers of an earlier restore exist ({stray:?}); run `restore abort --orphans`"
    );
    Ok(o.x.clone().expect("K3 has a record"))
}

async fn integrity(conn: &mut SqliteConnection, schema: &str) -> anyhow::Result<()> {
    let rows: Vec<String> = sqlx::query_scalar(&format!("PRAGMA {schema}.integrity_check"))
        .fetch_all(&mut *conn)
        .await?;
    ensure!(
        rows == ["ok"],
        "refusing: integrity_check of {schema} failed: {rows:?}"
    );
    let fk = sqlx::query(&format!("PRAGMA {schema}.foreign_key_check"))
        .fetch_all(&mut *conn)
        .await?;
    ensure!(
        fk.is_empty(),
        "refusing: foreign_key_check of {schema} lists {} rows",
        fk.len()
    );
    Ok(())
}

/// Step 1': checkpoint, close, require no journal and an empty WAL, drop the
/// shared-memory file, and hash the live DB.
async fn quiesce_live(site: &Site) -> anyhow::Result<[u8; 32]> {
    let mut conn = connect(&site.db, false).await?;
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .fetch_all(&mut conn)
        .await?;
    conn.close().await?;
    ensure!(
        !exists(&site.sidecar("-journal")),
        "refusing: the live DB has a -journal"
    );
    let wal = site.sidecar("-wal");
    ensure!(
        !exists(&wal) || std::fs::metadata(&wal)?.len() == 0,
        "refusing: the live DB has a non-empty -wal after the checkpoint"
    );
    let shm = site.sidecar("-shm");
    if exists(&shm) {
        std::fs::remove_file(&shm)?;
    }
    sha256_file(&site.db)
}

/// v1 `audit_log`, which is server-wide: v2 audit rows are tenant-scoped and a
/// restore is not. Unlike `audit::log`, a failed write fails the command.
async fn server_audit(
    conn: &mut SqliteConnection,
    action: &str,
    txn: &[u8; 16],
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO audit_log (actor, action, env_id, detail, at) VALUES (NULL, ?, NULL, ?, ?)",
    )
    .bind(action)
    .bind(format!(
        "restore_txn_id={} reason_code=offline_operator_cli",
        hex(txn)
    ))
    .bind(util::now_rfc3339())
    .execute(&mut *conn)
    .await
    .with_context(|| format!("writing the {action} audit"))?;
    Ok(())
}

type Heads = BTreeMap<([u8; 16], [u8; 16]), Option<[u8; 32]>>;

/// Every profile of `schema` with its current head hash, or None without one.
async fn heads(
    conn: &mut SqliteConnection,
    schema: &str,
    instance: &[u8; 16],
) -> anyhow::Result<Heads> {
    let rows = sqlx::query(&format!(
        "SELECT p.tenant_id, p.id, p.current_version, s.head_hash
           FROM {schema}.v2_profiles p
           LEFT JOIN {schema}.v2_snapshots s
             ON s.server_instance_id = ? AND s.tenant_id = p.tenant_id
            AND s.profile_id = p.id AND s.version = p.current_version"
    ))
    .bind(instance.as_slice())
    .fetch_all(&mut *conn)
    .await?;
    let mut out = Heads::new();
    for r in rows {
        let tenant: Vec<u8> = r.get(0);
        let profile: Vec<u8> = r.get(1);
        let version: i64 = r.get(2);
        let head: Option<Vec<u8>> = r.get(3);
        let key: ([u8; 16], [u8; 16]) = (
            tenant
                .try_into()
                .map_err(|_| anyhow::anyhow!("bad tenant id"))?,
            profile
                .try_into()
                .map_err(|_| anyhow::anyhow!("bad profile id"))?,
        );
        let head = match (version, head) {
            (0, None) => None,
            (v, Some(h)) if v > 0 => Some(h.try_into().map_err(|_| anyhow::anyhow!("bad head"))?),
            _ => bail!(
                "refusing: {schema} profile {} has no head snapshot at its current version",
                hex(&key.1)
            ),
        };
        out.insert(key, head);
    }
    Ok(out)
}

/// The leaves each tenant needs (D-1 coverage). Strict where D-1 drops: a
/// profile in only one DB, or with a head in only one, refuses, because
/// `--drop-unreferenced` is not offered.
fn coverage(
    live: &Heads,
    backup: &Heads,
) -> anyhow::Result<BTreeMap<[u8; 16], Vec<RestoreEpochLeafV2>>> {
    ensure!(
        live.keys().eq(backup.keys()),
        "refusing: the backup and the live DB hold different profiles"
    );
    let mut out: BTreeMap<[u8; 16], Vec<RestoreEpochLeafV2>> = BTreeMap::new();
    for ((tenant, profile), previous) in live {
        match (previous, &backup[&(*tenant, *profile)]) {
            (None, None) => {}
            (Some(previous), Some(new)) => {
                out.entry(*tenant).or_default().push(RestoreEpochLeafV2 {
                    tenant_id: *tenant,
                    profile_id: *profile,
                    previous_signed_head_hash: *previous,
                    new_signed_head_hash: *new,
                })
            }
            _ => bail!(
                "refusing: profile {} has a head in only one of the backup and the live DB",
                hex(profile)
            ),
        }
    }
    Ok(out)
}

async fn attach_backup(conn: &mut SqliteConnection, backup: &Path) -> anyhow::Result<()> {
    sqlx::query("ATTACH DATABASE ? AS bk")
        .bind(backup.to_string_lossy().into_owned())
        .execute(&mut *conn)
        .await
        .context("attaching the backup")?;
    integrity(conn, "bk").await?;
    for sql in [
        "SELECT CAST(version AS TEXT) FROM {s}._sqlx_migrations ORDER BY version",
        "SELECT type || ' ' || name || ' ' || replace(sql, char(13), '') FROM {s}.sqlite_master
          WHERE sql IS NOT NULL ORDER BY type, name",
    ] {
        let live: Vec<String> = sqlx::query_scalar(&sql.replace("{s}", "main"))
            .fetch_all(&mut *conn)
            .await?;
        let bk: Vec<String> = sqlx::query_scalar(&sql.replace("{s}", "bk"))
            .fetch_all(&mut *conn)
            .await?;
        ensure!(
            live == bk,
            "refusing: the backup's schema differs from the live DB's"
        );
    }
    Ok(())
}

/// `restore export-heads`: one transition request per tenant needing
/// coverage, for its custodians to sign and file at `E`.
pub async fn export_heads(cfg: &Config, backup: &Path, out: &Path) -> anyhow::Result<()> {
    refuse_release_build()?;
    let (site, o) = observe(cfg).await;
    let site = site.context("SHARDX_IDENTITY_DIR must be set")?;
    let (x, _) = require_clean_k3(&site, &o)?;
    let backup_sha = sha256_file(backup)?;
    let mut conn = connect(&site.db, true).await?;
    integrity(&mut conn, "main").await?;
    attach_backup(&mut conn, backup).await?;
    let live = heads(&mut conn, "main", &x.server_instance_id).await?;
    let new = heads(&mut conn, "bk", &x.server_instance_id).await?;
    conn.close().await?;
    let tenants = coverage(&live, &new)?;
    let txn = uuid::Uuid::new_v4().into_bytes();
    std::fs::create_dir_all(out)?;
    for (tenant, leaves) in &tenants {
        let bytes = rm::encode_request(
            &x.server_instance_id,
            tenant,
            x.restore_epoch,
            &txn,
            &backup_sha,
            &leaves
                .iter()
                .map(RestoreEpochLeafV2::encode)
                .collect::<Vec<_>>(),
        );
        std::fs::write(out.join(format!("request-{}.cbor", hex(tenant))), bytes)?;
    }
    println!("restore_txn_id={}", hex(&txn));
    println!("backup_db_sha256={}", hex(&backup_sha));
    println!("tenants={}", tenants.len());
    Ok(())
}

/// One verified tenant transition with its exact bytes, in leaf order.
struct Staged {
    entry: IndexEntry,
    transition: Vec<u8>,
    proofs: Vec<Vec<u8>>,
}

fn proof_sha(exact: &[u8]) -> [u8; 32] {
    c::domain_hash(c::L_RESTORE_EPOCH_PROOF, exact)
}

/// The staged `E -> E+1` transitions must be exactly one per covered tenant,
/// each signed over exactly the computed leaves by a live unrevoked device
/// that is still an ACTIVE root custodian of its tenant at `E` (ADR 0002
/// L561), by the route's own predicate.
async fn staged(
    conn: &mut SqliteConnection,
    v: &Verified,
    x: &IdentityRecordV2,
    tenants: &BTreeMap<[u8; 16], Vec<RestoreEpochLeafV2>>,
) -> anyhow::Result<Vec<Staged>> {
    let (instance, previous) = (x.server_instance_id, x.restore_epoch);
    let rows = sqlx::query(
        "SELECT tenant_id, exact_signed_transition_bytes, approver_device_id, approver_signing_key_id
           FROM v2_restore_epoch_transitions
          WHERE server_instance_id = ? AND previous_epoch = ? AND new_epoch = ?
          ORDER BY tenant_id",
    )
    .bind(instance.as_slice())
    .bind(i64::try_from(previous)?)
    .bind(i64::try_from(previous + 1)?)
    .fetch_all(&mut *conn)
    .await?;
    let filed: Vec<[u8; 16]> = rows
        .iter()
        .map(|r| r.get::<Vec<u8>, _>(0).try_into().unwrap_or([0; 16]))
        .collect();
    ensure!(
        filed.iter().eq(tenants.keys()),
        "refusing: the staged transitions do not cover exactly the tenants that need one \
         (staged {}, needed {})",
        filed.len(),
        tenants.len()
    );
    let mut out = Vec::new();
    for (r, (tenant, leaves)) in rows.iter().zip(tenants) {
        let exact: Vec<u8> = r.get(1);
        let device: Vec<u8> = r.get(2);
        let key: Vec<u8> = r.get(3);
        let signer = sqlx::query(
            "SELECT d.signing_public_key, d.account_id, d.hpke_key_id FROM v2_devices d
              WHERE d.tenant_id = ? AND d.id = ? AND d.signing_key_id = ? AND d.status = 'active'
                AND NOT EXISTS (SELECT 1 FROM v2_device_revocations r
                                 WHERE r.tenant_id = d.tenant_id
                                   AND (r.subject_device_id = d.id
                                        OR r.subject_signing_key_id = d.signing_key_id))",
        )
        .bind(tenant.as_slice())
        .bind(device.as_slice())
        .bind(key.as_slice())
        .fetch_optional(&mut *conn)
        .await?
        .with_context(|| {
            format!(
                "refusing: tenant {}'s transition signer is not a live device",
                hex(tenant)
            )
        })?;
        let blob = |i: usize| signer.get::<Vec<u8>, _>(i);
        let bad = || anyhow::anyhow!("bad key");
        let public: [u8; 32] = blob(0).try_into().map_err(|_| bad())?;
        let account: [u8; 16] = blob(1).try_into().map_err(|_| bad())?;
        let as_device = Session::of_device(
            *tenant,
            account,
            device.clone().try_into().map_err(|_| bad())?,
            key.clone().try_into().map_err(|_| bad())?,
            blob(2).try_into().map_err(|_| bad())?,
        );
        ensure!(
            is_active_custodian(conn, v, &as_device, util::now_ms())
                .await
                .map_err(|e| anyhow::anyhow!(
                    "refusing: custody of tenant {}: {e:?}",
                    hex(tenant)
                ))?,
            "refusing: tenant {}'s transition signer is not an ACTIVE root custodian at E",
            hex(tenant)
        );
        let verified = SignedRestoreEpochTransitionV2::parse(&exact)
            .and_then(|t| t.verify_signature(&public))
            .map_err(|e| anyhow::anyhow!("refusing: tenant {}'s transition: {e:?}", hex(tenant)))?;
        let t = verified.payload();
        ensure!(
            t.tenant_id == *tenant
                && t.server_instance_id == instance
                && t.previous_epoch == previous
                && t.new_epoch == previous + 1
                && t.mapping_count == leaves.len() as u64
                && mapping_root(tenant, leaves).ok() == Some(t.profile_head_mapping_root),
            "refusing: tenant {}'s transition does not sign the computed leaves",
            hex(tenant)
        );
        let proofs: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT canonical_inclusion_proof_bytes FROM v2_restore_epoch_transition_proofs
              WHERE server_instance_id = ? AND tenant_id = ? AND previous_epoch = ? AND new_epoch = ?
              ORDER BY leaf_index",
        )
        .bind(instance.as_slice())
        .bind(tenant.as_slice())
        .bind(i64::try_from(previous)?)
        .bind(i64::try_from(previous + 1)?)
        .fetch_all(&mut *conn)
        .await?;
        ensure!(
            proofs.len() == leaves.len(),
            "refusing: tenant {} has {} proofs for {} leaves",
            hex(tenant),
            proofs.len(),
            leaves.len()
        );
        for (i, (exact_proof, leaf)) in proofs.iter().zip(leaves).enumerate() {
            let p = RestoreEpochInclusionProofV2::parse(exact_proof)
                .map_err(|e| anyhow::anyhow!("refusing: proof {i}: {e:?}"))?;
            verify_inclusion(&verified, &p, &leaf.profile_id)
                .map_err(|e| anyhow::anyhow!("refusing: proof {i}: {e}"))?;
            ensure!(
                p.leaf == *leaf && p.leaf_index == i as u64,
                "refusing: proof {i} of tenant {} is not the computed leaf",
                hex(tenant)
            );
        }
        let sums: Vec<[u8; 32]> = proofs.iter().map(|p| proof_sha(p)).collect();
        out.push(Staged {
            entry: IndexEntry {
                tenant_id: *tenant,
                exact_signed_transition_bytes_sha256: *verified
                    .container()
                    .exact_signed_transition_bytes_sha256(),
                mapping_count: leaves.len() as u64,
                proof_set_sha256: rm::proof_set_sha256(&sums),
            },
            transition: exact,
            proofs,
        });
    }
    Ok(out)
}

async fn count(conn: &mut SqliteConnection, sql: &str) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar(sql).fetch_one(&mut *conn).await?)
}

/// Step 2a.3: the restore-scope merge, in one transaction on the live copy.
/// D-1, replays after a restore (ADR 0002 L377-L389): the merge keeps every
/// ledger row and marks those whose result it rolled back with `next`. Each
/// kind uses the predicate its replay route uses; an unreadable result fails
/// closed.
async fn supersede(conn: &mut SqliteConnection, next: u64) -> anyhow::Result<()> {
    let rows = sqlx::query(
        "SELECT rowid, tenant_id, operation_kind, exact_request_bytes, exact_response_bytes
           FROM v2_idempotency
          WHERE status = 'succeeded' AND operation_kind IN
                ('COMMIT', 'CREATE_UPLOAD', 'FINALIZE_UPLOAD', 'PROFILE_PUBLISH_CREATE')",
    )
    .fetch_all(&mut *conn)
    .await?;
    for r in rows {
        let (rowid, tenant, kind): (i64, Vec<u8>, String) = (r.get(0), r.get(1), r.get(2));
        let request: Vec<u8> = r.get(3);
        let response: Vec<u8> = r.get::<Option<Vec<u8>>, _>(4).unwrap_or_default();
        let bad =
            || anyhow::anyhow!("refusing: the {kind} ledger row {rowid} has no readable result");
        let payload = |record_type: &str| {
            IdempotentStoredResponseV2::parse(&response)
                .ok()
                .filter(|s| s.response_record_type == record_type)
                .map(|s| s.canonical_response_payload_bytes)
                .ok_or_else(bad)
        };
        let kept: bool = match kind.as_str() {
            // The commit's upload fixes its profile.
            "COMMIT" => {
                let req = CommitRequestV2::parse(&request).map_err(|_| bad())?;
                let b = CommitReceiptBindingV2::parse(&response).map_err(|_| bad())?;
                sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM v2_snapshots WHERE tenant_id = ? AND upload_id = ?
                                       AND version = ? AND snapshot_id = ?)",
                )
                .bind(&tenant)
                .bind(req.upload_id().as_slice())
                .bind(i64::try_from(b.resulting_version)?)
                .bind(b.snapshot_id.as_slice())
                .fetch_one(&mut *conn)
                .await?
            }
            "PROFILE_PUBLISH_CREATE" => {
                let origin = LeaseOrigin::PublishCreate;
                let l = ProfileLeaseV2::parse(origin, &payload(origin.record_type())?)
                    .map_err(|_| bad())?;
                sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM v2_profiles WHERE tenant_id = ? AND id = ?)",
                )
                .bind(&tenant)
                .bind(l.profile.profile_id.as_slice())
                .fetch_one(&mut *conn)
                .await?
            }
            _ => {
                let upload = if kind == "CREATE_UPLOAD" {
                    UploadCreatedV2::parse(&payload(RECORD_TYPE_UPLOAD_CREATED)?)
                        .map_err(|_| bad())?
                        .upload_id
                } else {
                    UploadFinalizedV2::parse(&payload(RECORD_TYPE_UPLOAD_FINALIZED)?)
                        .map_err(|_| bad())?
                        .upload_id
                };
                sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM v2_uploads WHERE tenant_id = ? AND upload_id = ?)",
                )
                .bind(&tenant)
                .bind(upload.as_slice())
                .fetch_one(&mut *conn)
                .await?
            }
        };
        if !kept {
            sqlx::query(
                "UPDATE v2_idempotency SET superseded_by_restore_epoch = ? WHERE rowid = ?",
            )
            .bind(i64::try_from(next)?)
            .bind(rowid)
            .execute(&mut *conn)
            .await?;
        }
    }
    Ok(())
}

async fn merge(conn: &mut SqliteConnection, x: &IdentityRecordV2) -> anyhow::Result<()> {
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM main.sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
    )
    .fetch_all(&mut *conn)
    .await?;
    for t in &tables {
        ensure!(
            SCOPE.iter().any(|(name, _)| name == t),
            "refusing: table {t} has no restore-scope assignment"
        );
    }
    let mut tx = conn.begin().await?;
    for sql in [
        "DELETE FROM v2_snapshots",
        "DELETE FROM v2_upload_chunks",
        "DELETE FROM v2_uploads",
        // A kept snapshot keeps its COMMITTED upload (L1089, L1102).
        "INSERT INTO v2_uploads SELECT * FROM bk.v2_uploads u
          WHERE u.state = 'COMMITTED' AND EXISTS (
                SELECT 1 FROM bk.v2_snapshots s
                 WHERE s.server_instance_id = u.server_instance_id
                   AND s.tenant_id = u.tenant_id AND s.upload_id = u.upload_id)",
        "INSERT INTO v2_snapshots SELECT * FROM bk.v2_snapshots",
        "UPDATE v2_profiles SET current_version = (
                SELECT b.current_version FROM bk.v2_profiles b
                 WHERE b.tenant_id = v2_profiles.tenant_id AND b.id = v2_profiles.id)",
        // max(live, backup): the fence only moves forward (L1098).
        "UPDATE v2_profiles SET last_fencing_token = (
                SELECT b.last_fencing_token FROM bk.v2_profiles b
                 WHERE b.tenant_id = v2_profiles.tenant_id AND b.id = v2_profiles.id)
          WHERE last_fencing_token < (
                SELECT b.last_fencing_token FROM bk.v2_profiles b
                 WHERE b.tenant_id = v2_profiles.tenant_id AND b.id = v2_profiles.id)",
    ] {
        sqlx::query(sql)
            .execute(&mut *tx)
            .await
            .with_context(|| format!("merge: {sql}"))?;
    }
    sqlx::query("UPDATE v2_profiles SET updated_at = ?")
        .bind(util::now_rfc3339())
        .execute(&mut *tx)
        .await?;
    for (table, source) in SCOPE {
        if *source == Source::Cleared {
            sqlx::query(&format!("DELETE FROM {table}"))
                .execute(&mut *tx)
                .await
                .with_context(|| format!("clearing {table}"))?;
        }
    }
    supersede(&mut tx, x.restore_epoch + 1).await?;
    tx.commit().await?;

    let instance = hex(&x.server_instance_id);
    for (what, sql) in [
        (
            "a data-plane row of another server instance",
            format!(
                "SELECT (SELECT count(*) FROM v2_snapshots WHERE hex(server_instance_id) <> upper('{instance}'))
                      + (SELECT count(*) FROM v2_uploads WHERE hex(server_instance_id) <> upper('{instance}'))"
            ),
        ),
        (
            "a snapshot outside its profile's fleet or above its head",
            "SELECT count(*) FROM v2_snapshots s JOIN v2_profiles p
               ON p.tenant_id = s.tenant_id AND p.id = s.profile_id
             WHERE s.fleet_id <> p.fleet_id OR s.version > p.current_version"
                .into(),
        ),
        (
            "a snapshot signed by a device that is revoked or unknown in the live DB",
            "SELECT count(*) FROM v2_snapshots s WHERE NOT EXISTS (
               SELECT 1 FROM v2_devices d
                WHERE d.tenant_id = s.tenant_id AND d.signing_key_id = s.signing_key_id
                  AND d.status = 'active'
                  AND NOT EXISTS (SELECT 1 FROM v2_device_revocations r
                                   WHERE r.tenant_id = d.tenant_id
                                     AND (r.subject_device_id = d.id
                                          OR r.subject_signing_key_id = d.signing_key_id)))"
                .into(),
        ),
    ] {
        let n = count(conn, &sql).await?;
        ensure!(n == 0, "refusing: the merge keeps {n} rows with {what}");
    }
    integrity(conn, "main").await?;

    // Blobs are never restored: each kept snapshot's object must already be
    // in the live store, byte for byte.
    let blobs = sqlx::query(
        "SELECT immutable_blob_path, ciphertext_size, ciphertext_sha256 FROM v2_snapshots",
    )
    .fetch_all(&mut *conn)
    .await?;
    for b in blobs {
        let path: String = b.get(0);
        let size: i64 = b.get(1);
        let sum: Vec<u8> = b.get(2);
        let ok = std::fs::metadata(&path).is_ok_and(|m| i64::try_from(m.len()) == Ok(size))
            && sha256_file(Path::new(&path)).is_ok_and(|s| s[..] == sum[..]);
        ensure!(
            ok,
            "refusing: the snapshot object {path} is missing or differs"
        );
    }
    Ok(())
}

/// `restore prepare`: steps 1'-2c.
pub async fn prepare(cfg: &Config, backup: &Path, txn: [u8; 16]) -> anyhow::Result<()> {
    refuse_release_build()?;
    ensure!(txn != [0; 16], "--txn must not be zero");
    let (site, o) = observe(cfg).await;
    let site = site.context("SHARDX_IDENTITY_DIR must be set")?;
    let (x, xsha) = require_clean_k3(&site, &o)?;

    // 1': the live DB must be readable and consistent; the prepare audit goes
    // in before the hash, so the candidate and the archive both carry it.
    let mut live = connect(&site.db, false).await?;
    integrity(&mut live, "main").await?;
    server_audit(&mut live, "server.restore_prepare", &txn).await?;
    live.close().await?;
    let live_sha = quiesce_live(&site).await?;
    let backup_sha = sha256_file(backup)?;

    // 2a: the candidate is a copy of the live DB whose data plane is replaced
    // from the backup (D-1 restore scope: the control plane stays live).
    let candidate = site.candidate(&txn);
    let tmp = candidate.with_extension("db.tmp");
    std::fs::copy(&site.db, &tmp).context("copying the live DB")?;
    let mut conn = connect(&tmp, false).await?;
    let built = async {
        attach_backup(&mut conn, backup).await?;
        let live_heads = heads(&mut conn, "main", &x.server_instance_id).await?;
        let backup_heads = heads(&mut conn, "bk", &x.server_instance_id).await?;
        let tenants = coverage(&live_heads, &backup_heads)?;
        let v = Verified {
            server_instance_id: x.server_instance_id,
            restore_epoch: x.restore_epoch,
            external_record_sha256: xsha,
        };
        let staged = staged(&mut conn, &v, &x, &tenants).await?;
        merge(&mut conn, &x).await?;
        sqlx::query("DETACH DATABASE bk").execute(&mut conn).await?;
        anyhow::Ok(staged)
    }
    .await;
    // Closed before any removal: Windows cannot delete an open file.
    let closed = conn.close().await;
    let checked = built
        .and_then(|s| closed.map(|()| s).map_err(Into::into))
        .and_then(|s| {
            ensure!(
                sha256_file(backup)? == backup_sha,
                "refusing: the backup changed while it was read"
            );
            for suffix in SIDECARS {
                ensure!(
                    !exists(&sidecar(&tmp, suffix)),
                    "refusing: the candidate has a {suffix} sidecar"
                );
            }
            sync_file(&tmp)?;
            Ok(s)
        });
    // A refused prepare leaves nothing of its own for `--orphans` to clean.
    let staged = match checked {
        Ok(s) => s,
        Err(e) => {
            for suffix in SIDECARS {
                let _ = std::fs::remove_file(sidecar(&tmp, suffix));
            }
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
    };
    crash("prepare.2a.tmp");
    std::fs::rename(&tmp, &candidate)?;
    identity::sync_dir(&site.data)?;
    crash("prepare.2a");
    let candidate_sha = sha256_file(&candidate)?;

    // 2b: the artifacts, each named by its SHA-256, then the index.
    let index = TransitionSetIndexV2 {
        server_instance_id: x.server_instance_id,
        previous_epoch: x.restore_epoch,
        new_epoch: x.restore_epoch + 1,
        restore_txn_id: txn,
        backup_db_sha256: backup_sha,
        live_db_sha256: live_sha,
        entries: staged.iter().map(|s| s.entry.clone()).collect(),
    }
    .encode()
    .context("the transition-set index does not encode")?;
    let dir = site.artifacts(&txn);
    std::fs::create_dir(&dir)?;
    identity::sync_dir(&site.identity)?;
    let artifacts = staged
        .iter()
        .flat_map(|s| std::iter::once(&s.transition).chain(&s.proofs))
        .chain(std::iter::once(&index));
    for bytes in artifacts {
        write_replace(&dir, &hex(&c::sha256(bytes)), bytes, "prepare.2b.artifact")?;
    }
    identity::sync_dir(&dir)?;
    crash("prepare.2b");

    // 2c: preparation is durable after this directory fsync.
    let manifest = PreparationManifestV2 {
        state: State::Prepared,
        server_instance_id: x.server_instance_id,
        previous_epoch: x.restore_epoch,
        new_epoch: x.restore_epoch + 1,
        restore_txn_id: txn,
        candidate_db_sha256: candidate_sha,
        transition_set_sha256: rm::transition_set_sha256(&index),
        previous_record_sha256: xsha,
        prepared_at_ms: u64::try_from(util::now_ms())?,
    };
    let bytes = manifest
        .encode()
        .map_err(|e| anyhow::anyhow!("the manifest does not encode: {e:?}"))?;
    write_replace(&site.identity, MANIFEST_FILE, &bytes, "prepare.2c")?;
    println!("restore_txn_id={}", hex(&txn));
    println!("candidate_db_sha256={}", hex(&candidate_sha));
    println!(
        "transition_set_sha256={}",
        hex(&manifest.transition_set_sha256)
    );
    println!("class=K7");
    Ok(())
}

/// The artifacts of `p`, each checked against its name, and the index.
fn read_artifacts(
    site: &Site,
    p: &PreparationManifestV2,
) -> anyhow::Result<(BTreeMap<String, Vec<u8>>, TransitionSetIndexV2)> {
    let dir = site.artifacts(&p.restore_txn_id);
    let mut files = BTreeMap::new();
    for name in names_in(&dir) {
        let bytes = std::fs::read(dir.join(&name))?;
        ensure!(
            hex(&c::sha256(&bytes)) == name,
            "the artifact {name} differs from its name"
        );
        files.insert(name, bytes);
    }
    let index = files
        .values()
        .find(|b| rm::transition_set_sha256(b) == p.transition_set_sha256)
        .and_then(|b| TransitionSetIndexV2::parse(b))
        .context("the transition-set index the manifest names is missing")?;
    ensure!(
        index.server_instance_id == p.server_instance_id
            && index.previous_epoch == p.previous_epoch
            && index.new_epoch == p.new_epoch
            && index.restore_txn_id == p.restore_txn_id,
        "the transition-set index is for another restore"
    );
    Ok((files, index))
}

/// Step 5 verification of the installed DB: its filed transitions and proofs
/// are exactly the artifacts, and the leaves cover exactly its heads.
async fn verify_installed(
    conn: &mut SqliteConnection,
    site: &Site,
    p: &PreparationManifestV2,
) -> anyhow::Result<Vec<([u8; 16], Vec<u8>)>> {
    let (files, index) = read_artifacts(site, p)?;
    let present = |bytes: &[u8]| {
        files
            .get(&hex(&c::sha256(bytes)))
            .is_some_and(|f| f == bytes)
    };
    let (prev, new) = (
        i64::try_from(p.previous_epoch)?,
        i64::try_from(p.new_epoch)?,
    );
    let rows = sqlx::query(
        "SELECT tenant_id, exact_signed_transition_bytes, mapping_count, transition_replay_id
           FROM v2_restore_epoch_transitions
          WHERE server_instance_id = ? AND previous_epoch = ? AND new_epoch = ?
          ORDER BY tenant_id",
    )
    .bind(p.server_instance_id.as_slice())
    .bind(prev)
    .bind(new)
    .fetch_all(&mut *conn)
    .await?;
    ensure!(
        rows.len() == index.entries.len(),
        "the installed DB holds {} transitions, the index {}",
        rows.len(),
        index.entries.len()
    );
    let installed = heads(conn, "main", &p.server_instance_id).await?;
    let mut covered = BTreeMap::new();
    let mut audit = Vec::new();
    for (r, e) in rows.iter().zip(&index.entries) {
        let tenant: Vec<u8> = r.get(0);
        let exact: Vec<u8> = r.get(1);
        let count: i64 = r.get(2);
        let container = SignedRestoreEpochTransitionV2::parse(&exact)
            .map_err(|e| anyhow::anyhow!("an installed transition does not parse: {e:?}"))?;
        ensure!(
            tenant == e.tenant_id
                && container.exact_signed_transition_bytes_sha256()
                    == &e.exact_signed_transition_bytes_sha256
                && u64::try_from(count) == Ok(e.mapping_count)
                && present(&exact),
            "tenant {}'s installed transition is not its artifact",
            hex(&e.tenant_id)
        );
        let proofs: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT canonical_inclusion_proof_bytes FROM v2_restore_epoch_transition_proofs
              WHERE server_instance_id = ? AND tenant_id = ? AND previous_epoch = ? AND new_epoch = ?
              ORDER BY leaf_index",
        )
        .bind(p.server_instance_id.as_slice())
        .bind(e.tenant_id.as_slice())
        .bind(prev)
        .bind(new)
        .fetch_all(&mut *conn)
        .await?;
        let sums: Vec<[u8; 32]> = proofs.iter().map(|b| proof_sha(b)).collect();
        ensure!(
            proofs.len() as u64 == e.mapping_count
                && rm::proof_set_sha256(&sums) == e.proof_set_sha256
                && proofs.iter().all(|b| present(b)),
            "tenant {}'s installed proofs are not its artifacts",
            hex(&e.tenant_id)
        );
        for b in &proofs {
            let leaf = RestoreEpochInclusionProofV2::parse(b)
                .map_err(|e| anyhow::anyhow!("an installed proof does not parse: {e:?}"))?
                .leaf;
            ensure!(
                leaf.tenant_id == e.tenant_id,
                "a proof leaf is for another tenant"
            );
            covered.insert((leaf.tenant_id, leaf.profile_id), leaf.new_signed_head_hash);
        }
        audit.push((e.tenant_id, r.get::<Vec<u8>, _>(3)));
    }
    let with_heads: BTreeMap<_, _> = installed
        .into_iter()
        .filter_map(|(k, h)| Some((k, h?)))
        .collect();
    ensure!(
        with_heads == covered,
        "the transition leaves do not cover exactly the installed heads"
    );
    Ok(audit)
}

fn mirror_matches(m: Option<&Mirror>, x: &IdentityRecordV2, xsha: &[u8; 32]) -> bool {
    m.is_some_and(|m| mirror_is(m, &x.server_instance_id, x.restore_epoch, xsha))
}

async fn read_mirror(conn: &mut SqliteConnection) -> anyhow::Result<Option<Mirror>> {
    let row = sqlx::query(
        "SELECT server_instance_id, restore_epoch, external_record_sha256
           FROM v2_server_state WHERE singleton = 1",
    )
    .fetch_optional(&mut *conn)
    .await?;
    Ok(row.map(|r| Mirror {
        server_instance_id: r.get(0),
        restore_epoch: r.get(1),
        external_record_sha256: r.get(2),
    }))
}

/// Step 3: record `E+1`, the authority commit point.
fn write_record(site: &Site, p: &PreparationManifestV2) -> anyhow::Result<()> {
    let record = IdentityRecordV2 {
        server_instance_id: p.server_instance_id,
        restore_epoch: p.new_epoch,
        restore_txn_id: p.restore_txn_id,
        restored_db_sha256: p.candidate_db_sha256,
        transition_set_sha256: p.transition_set_sha256,
        written_at_ms: u64::try_from(util::now_ms())?,
    }
    .encode()
    .map_err(|e| anyhow::anyhow!("record E+1 does not encode: {e:?}"))?;
    write_replace(&site.identity, RECORD_FILE, &record, "commit.3")?;
    crash("commit.3.synced");
    Ok(())
}

/// Move `from` to `to`. An existing target is accepted only if it is empty
/// or identical; anything else needs the operator (K12).
fn archive_move(from: &Path, to: &Path) -> anyhow::Result<()> {
    if exists(to) {
        let same = std::fs::metadata(to)?.len() == 0 || std::fs::read(to)? == std::fs::read(from)?;
        ensure!(
            same,
            "K12: the archive {} already exists and differs",
            to.display()
        );
    }
    std::fs::rename(from, to).with_context(|| format!("archiving {}", from.display()))
}

/// Step 4, each sub-step idempotent.
async fn install(site: &Site, p: &PreparationManifestV2) -> anyhow::Result<()> {
    let txn = &p.restore_txn_id;
    if exists(&site.db) {
        let mut conn = connect(&site.db, false).await?;
        sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .fetch_all(&mut conn)
            .await?;
        conn.close().await?;
    }
    crash("commit.4.i");
    for suffix in SIDECARS {
        let sidecar = site.sidecar(suffix);
        if exists(&sidecar) {
            archive_move(&sidecar, &site.archive(txn, suffix))?;
        }
    }
    crash("commit.4.ii");
    if exists(&site.db) {
        archive_move(&site.db, &site.archive(txn, ""))?;
    }
    crash("commit.4.iii");
    ensure!(
        !exists(&site.db) && SIDECARS.iter().all(|s| !exists(&site.sidecar(s))),
        "K12: the DB path is not clear before the install"
    );
    std::fs::rename(site.candidate(txn), &site.db).context("installing the candidate")?;
    crash("commit.4.v");
    identity::sync_dir(&site.data)?;
    crash("commit.4.vi");
    Ok(())
}

/// K9: let SQLite roll back an interrupted step-5 transaction, then require
/// the exact candidate bytes.
async fn rolled_back_candidate(site: &Site, p: &PreparationManifestV2) -> anyhow::Result<()> {
    if exists(&site.sidecar("-journal")) {
        let mut conn = connect(&site.db, false).await?;
        sqlx::query("SELECT count(*) FROM sqlite_master")
            .fetch_one(&mut conn)
            .await?;
        sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .fetch_all(&mut conn)
            .await?;
        conn.close().await?;
    }
    ensure!(
        sha256_file(&site.db)? == p.candidate_db_sha256,
        "K12: the installed DB is not the prepared candidate"
    );
    Ok(())
}

/// Step 5: verify, then one transaction that invalidates sessions, rebuilds
/// the mirror to record `E+1` and writes the audit; then read back.
async fn reconcile(site: &Site, p: &PreparationManifestV2, xsha: &[u8; 32]) -> anyhow::Result<()> {
    let mut conn = connect(&site.db, false).await?;
    let tenants = verify_installed(&mut conn, site, p).await?;
    let mut tx = conn.begin().await?;
    for (table, source) in SCOPE {
        if *source == Source::Cleared {
            sqlx::query(&format!("DELETE FROM {table}"))
                .execute(&mut *tx)
                .await?;
        }
    }
    let updated = sqlx::query(
        "UPDATE v2_server_state SET restore_epoch = ?, external_record_sha256 = ?, updated_at = ?
          WHERE singleton = 1 AND server_instance_id = ?",
    )
    .bind(i64::try_from(p.new_epoch)?)
    .bind(xsha.as_slice())
    .bind(util::now_rfc3339())
    .bind(p.server_instance_id.as_slice())
    .execute(&mut *tx)
    .await?;
    ensure!(
        updated.rows_affected() == 1,
        "the installed DB has no mirror row to rebuild"
    );
    server_audit(&mut tx, "server.restore_commit", &p.restore_txn_id).await?;
    for (tenant, replay) in &tenants {
        crate::audit::insert_offline(
            &mut tx,
            tenant,
            "tenant.restore_epoch_transition",
            "restore_epoch_transition",
            replay,
            &p.restore_txn_id,
        )
        .await?;
    }
    crash("commit.5.tx");
    tx.commit().await?;
    crash("commit.5.committed");
    readback(&mut conn, site, p, xsha).await?;
    conn.close().await?;
    Ok(())
}

async fn readback(
    conn: &mut SqliteConnection,
    site: &Site,
    p: &PreparationManifestV2,
    xsha: &[u8; 32],
) -> anyhow::Result<()> {
    let (x, sha) = identity::read_record(&site.identity)
        .map_err(|r| anyhow::anyhow!("{}: {}", r.code.as_str(), r.detail))?;
    verify_installed(conn, site, p).await?;
    ensure!(
        sha == *xsha && mirror_matches(read_mirror(conn).await?.as_ref(), &x, &sha),
        "readback: the mirror is not record E+1"
    );
    Ok(())
}

/// Step 6.
fn terminal(site: &Site, p: &PreparationManifestV2) -> anyhow::Result<()> {
    let bytes = PreparationManifestV2 {
        state: State::Terminal,
        ..p.clone()
    }
    .encode()
    .map_err(|e| anyhow::anyhow!("the manifest does not encode: {e:?}"))?;
    write_replace(&site.identity, MANIFEST_FILE, &bytes, "commit.6")
}

/// Step 7: artifacts, then the manifest, then the directory, each removal
/// followed by an fsync of its directory.
fn retire(site: &Site, txn: &[u8; 16]) -> anyhow::Result<()> {
    let dir = site.artifacts(txn);
    for name in names_in(&dir) {
        std::fs::remove_file(dir.join(&name))?;
        identity::sync_dir(&dir)?;
        crash("commit.7.artifact");
    }
    let manifest = site.identity.join(MANIFEST_FILE);
    if exists(&manifest) {
        std::fs::remove_file(&manifest)?;
        identity::sync_dir(&site.identity)?;
    }
    crash("commit.7.manifest");
    if exists(&dir) {
        std::fs::remove_dir(&dir)?;
        identity::sync_dir(&site.identity)?;
    }
    Ok(())
}

/// `restore commit [--retire]`: the remaining steps from the current class.
pub async fn commit(cfg: &Config, retire_only: bool) -> anyhow::Result<()> {
    let (site, o) = observe(cfg).await;
    let site = site.context("SHARDX_IDENTITY_DIR must be set")?;
    let class = classify(&o);
    let x = o.x.clone();
    match (class, &o.p, retire_only) {
        (Class::K5b, _, true) => {
            let (x, _) = x.expect("K5b has a record");
            let mut conn = connect(&site.db, false).await?;
            server_audit(&mut conn, "server.restore_retire", &x.restore_txn_id).await?;
            conn.close().await?;
            retire(&site, &x.restore_txn_id)?;
        }
        (_, _, true) => bail!("refusing: --retire is only for K5b, not {class:?}"),
        (Class::K7 | Class::K8 | Class::K9 | Class::K10 | Class::K11, Prep::Parsed(p), false) => {
            let (_, xsha) = x.expect("a parsed class has a record");
            let txn = p.restore_txn_id;
            if class == Class::K7 {
                ensure!(
                    sha256_file(&site.candidate(&txn))? == p.candidate_db_sha256,
                    "refusing: the candidate is not the prepared one; abort"
                );
                let (_, index) = read_artifacts(&site, p)?;
                ensure!(
                    quiesce_live(&site).await? == index.live_db_sha256,
                    "refusing: the live DB changed after prepare; abort, then prepare again"
                );
                write_record(&site, p)?;
            }
            // Record E+1 is the authority from here; its hash is the mirror's.
            let xsha = if class == Class::K7 {
                identity::read_record(&site.identity)
                    .map_err(|r| anyhow::anyhow!("{}: {}", r.code.as_str(), r.detail))?
                    .1
            } else {
                xsha
            };
            if matches!(class, Class::K7 | Class::K8) {
                install(&site, p).await?;
            }
            if matches!(class, Class::K7 | Class::K8 | Class::K9) {
                rolled_back_candidate(&site, p).await?;
                reconcile(&site, p, &xsha).await?;
            }
            if class == Class::K10 {
                let mut conn = connect(&site.db, false).await?;
                readback(&mut conn, &site, p, &xsha).await?;
                conn.close().await?;
            }
            if class != Class::K11 {
                terminal(&site, p)?;
            }
            retire(&site, &txn)?;
        }
        _ => bail!(
            "refusing: restore commit is not allowed in {class:?} ({})",
            class.row()
        ),
    }
    println!("class={:?}", startup_class(cfg).await);
    Ok(())
}

/// `restore withdraw-transitions --tenant <id>` (offline, audited): removes
/// the tenant's staged `E -> E+1` transition and its proofs, so a filing no
/// restore can use (other leaves, or a tenant that needs none) never blocks
/// every restore at `E`. Only in K3: a prepared restore has bound its set.
pub async fn withdraw_transitions(cfg: &Config, tenant: [u8; 16]) -> anyhow::Result<()> {
    let (site, o) = observe(cfg).await;
    let site = site.context("SHARDX_IDENTITY_DIR must be set")?;
    let class = classify(&o);
    ensure!(
        class == Class::K3,
        "refusing: withdraw-transitions is only for K3, not {class:?} ({})",
        class.row()
    );
    let (x, _) = o.x.context("no identity record")?;
    let epoch = i64::try_from(x.restore_epoch)?;
    let mut conn = connect(&site.db, false).await?;
    let mut tx = conn.begin().await?;
    let mut removed = [0u64; 2];
    for (n, table) in [
        "v2_restore_epoch_transition_proofs",
        "v2_restore_epoch_transitions",
    ]
    .iter()
    .enumerate()
    {
        removed[n] = sqlx::query(&format!(
            "DELETE FROM {table} WHERE server_instance_id = ? AND tenant_id = ?
               AND previous_epoch = ? AND new_epoch = previous_epoch + 1"
        ))
        .bind(x.server_instance_id.as_slice())
        .bind(tenant.as_slice())
        .bind(epoch)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    }
    ensure!(
        removed[1] == 1,
        "refusing: tenant {} has no staged transition at E",
        hex(&tenant)
    );
    sqlx::query(
        "INSERT INTO audit_log (actor, action, env_id, detail, at) VALUES (NULL, ?, NULL, ?, ?)",
    )
    .bind("server.restore_withdraw_transitions")
    .bind(format!(
        "tenant_id={} previous_epoch={epoch} proofs={} reason_code=offline_operator_cli",
        hex(&tenant),
        removed[0]
    ))
    .bind(util::now_rfc3339())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    conn.close().await?;
    println!("withdrawn={}", hex(&tenant));
    Ok(())
}

/// `restore abort [--orphans [--delete-archives]]`: only while the authority
/// is still `E`.
pub async fn abort(cfg: &Config, orphans_only: bool, delete_archives: bool) -> anyhow::Result<()> {
    let (site, o) = observe(cfg).await;
    let site = site.context("SHARDX_IDENTITY_DIR must be set")?;
    let class = classify(&o);
    if orphans_only {
        ensure!(
            class == Class::K3,
            "refusing: --orphans is only for K3, not {class:?}"
        );
        for path in orphans(&site) {
            let archive = path.parent() == Some(site.data.as_path())
                && path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(is_archive);
            if archive && !delete_archives {
                println!("kept={}", path.display());
                continue;
            }
            if path.is_dir() {
                std::fs::remove_dir_all(&path)?;
            } else {
                std::fs::remove_file(&path)?;
            }
            println!("removed={}", path.display());
        }
        identity::sync_dir(&site.identity)?;
        identity::sync_dir(&site.data)?;
        return Ok(());
    }
    ensure!(
        matches!(class, Class::K5a | Class::K7),
        "refusing: restore abort is only for K5a and K7, not {class:?} ({})",
        class.row()
    );
    let txn = match &o.p {
        Prep::Parsed(p) => p.restore_txn_id,
        _ => [0; 16],
    };
    let mut conn = connect(&site.db, false).await?;
    server_audit(&mut conn, "server.restore_abort", &txn).await?;
    conn.close().await?;
    for name in names_in(&site.data).into_iter().filter(|n| is_candidate(n)) {
        std::fs::remove_file(site.data.join(name))?;
    }
    identity::sync_dir(&site.data)?;
    for name in names_in(&site.identity) {
        let path = site.identity.join(&name);
        if name.starts_with("restore-") && path.is_dir() {
            std::fs::remove_dir_all(&path)?;
        } else if name.ends_with(".tmp") {
            std::fs::remove_file(&path)?;
        }
    }
    identity::sync_dir(&site.identity)?;
    std::fs::remove_file(site.identity.join(MANIFEST_FILE))?;
    identity::sync_dir(&site.identity)?;
    println!("class={:?}", startup_class(cfg).await);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use shardx_team_server::identity_record;

    fn record(epoch: u64, txn: u8) -> (IdentityRecordV2, [u8; 32]) {
        let mut r = IdentityRecordV2::genesis([5; 16], 1);
        if epoch > 0 {
            r.restore_epoch = epoch;
            r.restore_txn_id = [txn; 16];
            r.restored_db_sha256 = [2; 32];
            r.transition_set_sha256 = [3; 32];
        }
        let sha = identity_record::external_record_sha256(&r.encode().unwrap());
        (r, sha)
    }

    fn row(epoch: i64, sha: [u8; 32]) -> Mirrored {
        Mirrored::Row(Mirror {
            server_instance_id: vec![5; 16],
            restore_epoch: epoch,
            external_record_sha256: sha.to_vec(),
        })
    }

    fn manifest(state: State, previous: [u8; 32]) -> Prep {
        Prep::Parsed(PreparationManifestV2 {
            state,
            server_instance_id: [5; 16],
            previous_epoch: 0,
            new_epoch: 1,
            restore_txn_id: [9; 16],
            candidate_db_sha256: [2; 32],
            transition_set_sha256: [3; 32],
            previous_record_sha256: previous,
            prepared_at_ms: 1,
        })
    }

    #[test]
    fn every_observation_maps_to_exactly_one_class() {
        let (e, esha) = record(0, 0);
        let (e1, e1sha) = record(1, 9);
        let obs = |x: Option<&(IdentityRecordV2, [u8; 32])>, m, p, c, dx, hot| Observed {
            x: x.cloned(),
            m,
            hot_journal: hot,
            p,
            c,
            dx,
        };
        let at_e = Some(&(e.clone(), esha));
        let at_e1 = Some(&(e1.clone(), e1sha));
        let prepared = || manifest(State::Prepared, esha);
        let cases = [
            (
                obs(None, row(0, esha), Prep::Absent, false, false, false),
                Class::K1,
            ),
            (
                obs(at_e, row(1, esha), Prep::Absent, false, false, false),
                Class::K2,
            ),
            (
                obs(
                    at_e,
                    Mirrored::Row(Mirror {
                        server_instance_id: vec![6; 16],
                        restore_epoch: 0,
                        external_record_sha256: esha.to_vec(),
                    }),
                    Prep::Absent,
                    false,
                    false,
                    false,
                ),
                Class::K2,
            ),
            (
                obs(at_e, row(0, esha), Prep::Absent, true, true, false),
                Class::K3,
            ),
            (
                obs(at_e1, row(0, esha), Prep::Absent, false, false, false),
                Class::K4,
            ),
            (
                obs(at_e, Mirrored::Absent, Prep::Absent, false, false, false),
                Class::K4,
            ),
            (
                obs(at_e, row(0, esha), Prep::Unparsable, true, false, false),
                Class::K5a,
            ),
            (
                obs(at_e1, row(1, e1sha), Prep::Unparsable, false, true, false),
                Class::K5b,
            ),
            (
                obs(at_e1, row(1, e1sha), Prep::Unparsable, true, true, false),
                Class::K6,
            ),
            (
                obs(at_e1, row(0, esha), Prep::Unparsable, false, true, false),
                Class::K6,
            ),
            (
                obs(at_e, row(0, esha), prepared(), true, false, false),
                Class::K7,
            ),
            (
                obs(at_e1, row(0, esha), prepared(), true, true, false),
                Class::K8,
            ),
            (
                obs(at_e1, Mirrored::Absent, prepared(), true, true, false),
                Class::K8,
            ),
            (
                obs(at_e1, row(0, esha), prepared(), false, true, false),
                Class::K9,
            ),
            (
                obs(at_e1, Mirrored::Unreadable, prepared(), false, true, true),
                Class::K9,
            ),
            (
                obs(at_e1, row(1, e1sha), prepared(), false, true, false),
                Class::K10,
            ),
            (
                obs(
                    at_e1,
                    row(1, e1sha),
                    manifest(State::Terminal, esha),
                    false,
                    true,
                    false,
                ),
                Class::K11,
            ),
            // `pre` with TERMINAL, an unreadable mirror without a journal, a
            // mirror from neither epoch, and C present with M at E+1.
            (
                obs(
                    at_e,
                    row(0, esha),
                    manifest(State::Terminal, esha),
                    true,
                    false,
                    false,
                ),
                Class::K12,
            ),
            (
                obs(at_e1, Mirrored::Unreadable, prepared(), false, true, false),
                Class::K12,
            ),
            (
                obs(at_e1, row(0, [7; 32]), prepared(), true, true, false),
                Class::K12,
            ),
            (
                obs(at_e1, row(1, e1sha), prepared(), true, true, false),
                Class::K10,
            ),
            (
                obs(at_e1, Mirrored::Rowless, prepared(), false, true, false),
                Class::K12,
            ),
            // A manifest for another record E.
            (
                obs(
                    at_e,
                    row(0, esha),
                    manifest(State::Prepared, [8; 32]),
                    true,
                    false,
                    false,
                ),
                Class::K12,
            ),
            // Record E+1 names another candidate than the manifest: not `post`.
            (
                obs(
                    at_e1,
                    row(0, esha),
                    {
                        let Prep::Parsed(mut m) = prepared() else {
                            unreachable!()
                        };
                        m.candidate_db_sha256 = [4; 32];
                        Prep::Parsed(m)
                    },
                    true,
                    true,
                    false,
                ),
                Class::K12,
            ),
        ];
        for (i, (o, want)) in cases.iter().enumerate() {
            assert_eq!(classify(o), *want, "case {i}");
        }
        assert!(!Class::K3.read_only() && !Class::K1.read_only());
        assert!(!Class::K4.read_only());
        for k in [
            Class::K2,
            Class::K5a,
            Class::K5b,
            Class::K6,
            Class::K7,
            Class::K8,
            Class::K9,
            Class::K10,
            Class::K11,
            Class::K12,
        ] {
            assert!(k.read_only(), "{k:?}");
        }
    }

    #[tokio::test]
    async fn every_table_of_the_schema_has_a_restore_scope_assignment() {
        let dir = std::env::temp_dir().join(format!("shardx-scope-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s.db");
        let opts = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true);
        let pool = sqlx::SqlitePool::connect_with(opts).await.unwrap();
        shardx_team_server::run_migrations(&pool).await.unwrap();
        let tables: Vec<String> = sqlx::query_scalar(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        pool.close().await;
        let mut assigned: Vec<&str> = SCOPE.iter().map(|(n, _)| *n).collect();
        assigned.sort_unstable();
        assert_eq!(tables, assigned);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
