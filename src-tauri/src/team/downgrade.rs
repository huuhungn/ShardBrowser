//! The launcher downgrade (plan 12.4 L2240-L2243, probe 9 L2044).
//!
//! v0.1.28 knows no Team binding and would launch a bound profile without
//! its lease guard, so a launcher goes back only when no profile is still
//! bound. Each binding finishes exactly one flow: an explicit unbind
//! ([`unbind_profile`]), a downgrade clone ([`start_clone`]) or a full pre-v2
//! restore (journal and refusal states only here, see [`readiness`]).
//!
//! The clone flow moves the original profile out of every path v0.1.28 reads
//! and gives the user a clone it can open, under a durable `CLONE` journal
//! (`team::journal`):
//!
//! 1. the journal is written, naming the clone's random ID and the exact
//!    archive paths, before any path moves;
//! 2. the stopped original is claimed;
//! 3. `profiles/<id>.json` and then `user-data/<id>` move, each in one
//!    same-volume rename that is flushed before the phase is stored;
//! 4. a scan of what v0.1.28 discovers proves the old ID is gone;
//! 5. the clone's user data and metadata are written under the new ID with no
//!    Team marker, remote identifier or `team-sync` file;
//! 6. after the database is closed and reopened, a second scan and the
//!    launcher's own profile listing read the clone back, and the original
//!    stays absent.
//!
//! Every step is safe to repeat: a start after a crash reads the journal and
//! the disk and continues, or, for a state it cannot explain, marks the
//! journal `ROLLBACK_REQUIRED` and puts the original back. `downgrade_ready`
//! is not a stored flag: [`readiness`] derives it from the database and the
//! disk each time, so it can never outlive the facts it rests on.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use shardx_core::canonical::sha256;

use super::db::Db;
use super::journal::{
    self, DowngradeJournal, DowngradePhase as Phase, Mode, Patch, Resume as Next,
};
use crate::errcode::{code, code_with, has_code};
use crate::fleet_client::hex;
use crate::{durable, profile, store};

/// Next to `profiles/` and `user-data/`, in the data root: the same volume,
/// and no directory v0.1.28 lists.
const ARCHIVE_DIR: &str = "downgrade-archive";
const READBACK_DOMAIN: &[u8] = b"SHARDX-DOWNGRADE-CLONE-READBACK-V1\0";
/// Keys a Team binding could have left in a profile's JSON.
const MARKER_KEYS: [&str; 11] = [
    "team",
    "team_binding",
    "team_sync",
    "remote_profile_id",
    "remote_lineage",
    "server_instance_id",
    "fleet_id",
    "lease_id",
    "fencing_token",
    "credential_ref",
    "credential_reference",
];

#[cfg(test)]
thread_local! {
    static CRASH_AT: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// A place the tests cut the flow off: by an injected error, or, under the
/// crash harness, by a kill of the process (G2-49). Nothing in a release
/// build.
#[cfg(test)]
fn point(name: &str) -> Result<()> {
    crate::crash_harness::pause_if(name);
    if CRASH_AT.with(|c| c.borrow().as_deref() == Some(name)) {
        bail!("injected crash at {name}");
    }
    Ok(())
}

#[cfg(not(test))]
fn point(_name: &str) -> Result<()> {
    Ok(())
}

// ----------------------------------------------------------- discovery ----

/// What the v0.1.28 launcher can find of a profile ID. It is a superset of
/// `profile::list_all`: every `*.json` under `profiles/` (an unreadable one
/// counts for any ID its text contains), every `user-data/` directory and
/// every `trash/` entry. A profile counts as listed only when its record is
/// `profiles/<id>.json` with the same ID inside, as `profile::load_raw`
/// needs.
#[derive(Default)]
pub(crate) struct Discovery {
    records: BTreeSet<(String, String)>,
    data: BTreeSet<String>,
    trash: BTreeSet<String>,
    unparsed: Vec<String>,
}

pub(crate) fn discover() -> Result<Discovery> {
    let mut found = Discovery::default();
    for entry in std::fs::read_dir(store::profiles_dir()?)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string();
        let body = std::fs::read_to_string(&path)?;
        match serde_json::from_str::<profile::StoredProfile>(&body) {
            Ok(stored) => {
                found.records.insert((stem, stored.meta.id));
            }
            Err(_) => found.unparsed.push(body),
        }
    }
    for entry in std::fs::read_dir(store::user_data_root()?)? {
        found.data.insert(name_of(&entry?.path()));
    }
    for entry in std::fs::read_dir(store::trash_dir()?)? {
        let path = entry?.path();
        found.trash.insert(
            path.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_string(),
        );
    }
    Ok(found)
}

fn name_of(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_string()
}

impl Discovery {
    /// Whether v0.1.28 would show `id` anywhere.
    pub(crate) fn mentions(&self, id: &str) -> bool {
        self.records
            .iter()
            .any(|(stem, inner)| stem == id || inner == id)
            || self.data.contains(id)
            || self.trash.contains(id)
            || self.unparsed.iter().any(|body| body.contains(id))
    }

    /// Whether `id` is a profile v0.1.28 can load.
    pub(crate) fn lists(&self, id: &str) -> bool {
        self.records.contains(&(id.to_string(), id.to_string()))
    }
}

/// `path` lies under none of the directories v0.1.28 reads profiles from.
fn outside_discovery(path: &Path) -> Result<()> {
    let inside = std::fs::canonicalize(path)?;
    for root in [
        store::profiles_dir()?,
        store::user_data_root()?,
        store::trash_dir()?,
        store::extensions_dir()?,
    ] {
        if inside.starts_with(std::fs::canonicalize(root)?) {
            bail!(code("downgrade.archiveDiscoverable"));
        }
    }
    Ok(())
}

// --------------------------------------------------------------- paths ----

fn archive_root() -> Result<PathBuf> {
    Ok(store::data_root()?.join(ARCHIVE_DIR))
}

fn valid_id(id: &str) -> Result<()> {
    if id.is_empty() || id.contains(['/', '\\', '.']) {
        bail!(code("profile.invalidId"));
    }
    Ok(())
}

/// Every path the flow touches, from the journal alone.
struct Places {
    dir: PathBuf,
    metadata_src: PathBuf,
    metadata_dst: PathBuf,
    data_src: PathBuf,
    data_dst: PathBuf,
    clone_metadata: PathBuf,
    clone_data: PathBuf,
    clone_staging: PathBuf,
}

fn places(j: &DowngradeJournal) -> Result<Places> {
    let (Some(metadata), Some(data), Some(new)) = (
        &j.original_metadata_archive_path,
        &j.original_user_data_archive_path,
        &j.new_local_profile_id,
    ) else {
        bail!(code_with(
            "journal.missingField",
            &[("phase", j.phase.as_str())]
        ));
    };
    valid_id(&j.original_local_profile_id)?;
    valid_id(new)?;
    let root = archive_root()?;
    let dir = root.join(&j.journal_id);
    let (metadata_dst, data_dst) = (PathBuf::from(metadata), PathBuf::from(data));
    // A journal whose paths lead anywhere but its own archive directory is
    // not ours to follow.
    let tidy = |p: &Path| p.starts_with(&dir) && !p.components().any(|c| c.as_os_str() == "..");
    if j.journal_id.is_empty()
        || j.journal_id.contains(['/', '\\', '.'])
        || !tidy(&metadata_dst)
        || !tidy(&data_dst)
    {
        bail!(code("downgrade.archiveOutside"));
    }
    Ok(Places {
        metadata_src: store::profiles_dir()?.join(format!("{}.json", j.original_local_profile_id)),
        data_src: store::user_data_root()?.join(&j.original_local_profile_id),
        clone_metadata: store::profiles_dir()?.join(format!("{new}.json")),
        clone_data: store::user_data_root()?.join(new),
        clone_staging: dir.join("clone-user-data.partial"),
        dir,
        metadata_dst,
        data_dst,
    })
}

fn exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// Makes `dir` and flushes it into its parents.
fn make_dir(dir: &Path) -> Result<()> {
    let mut missing = Vec::new();
    let mut at = Some(dir);
    while let Some(d) = at.filter(|d| !exists(d)) {
        missing.push(d.to_path_buf());
        at = d.parent();
    }
    std::fs::create_dir_all(dir)?;
    for d in missing.iter().rev() {
        durable::sync_parent(d)?;
    }
    Ok(())
}

/// One same-volume rename, flushed at both ends. A repeat after the rename
/// finds the destination and nothing at the source and does nothing.
fn move_path(src: &Path, dst: &Path, missing: &str) -> Result<()> {
    match (exists(src), exists(dst)) {
        (true, false) => {
            if let Some(parent) = dst.parent() {
                make_dir(parent)?;
            }
            durable::replace_file(src, dst).with_context(|| {
                code_with(
                    "downgrade.moveFailed",
                    &[("path", &src.display().to_string())],
                )
            })?;
            durable::sync_parent(src)?;
            durable::sync_parent(dst)?;
            Ok(())
        }
        (false, true) => Ok(()),
        (true, true) => bail!(code("downgrade.archiveConflict")),
        (false, false) => bail!(code(missing)),
    }
}

// ----------------------------------------------------------- the clone ----

/// What a started or resumed clone flow reached.
#[derive(Debug, Clone, Serialize)]
pub struct CloneDone {
    pub journal_id: String,
    pub original_local_profile_id: String,
    pub new_local_profile_id: String,
    pub phase: String,
}

fn done(j: &DowngradeJournal) -> CloneDone {
    CloneDone {
        journal_id: j.journal_id.clone(),
        original_local_profile_id: j.original_local_profile_id.clone(),
        new_local_profile_id: j.new_local_profile_id.clone().unwrap_or_default(),
        phase: j.phase.as_str().to_string(),
    }
}

fn random_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    // `getrandom` is Windows-only in this crate; shared has it everywhere.
    shardx_core::keys::fill_random(&mut bytes).map_err(|e| anyhow!("{e}"))?;
    Ok(uuid::Builder::from_random_bytes(bytes)
        .into_uuid()
        .to_string())
}

/// What the binding of `local` forbids a downgrade, and the identifiers a
/// clone must not carry.
fn binding_facts(db: &Db, local: &str) -> Result<Vec<String>> {
    let (ids, lease): (Vec<String>, Option<String>) = db
        .conn
        .query_row(
            "SELECT server_instance_id, tenant_id, fleet_id, remote_profile_id, lease_id
             FROM profile_bindings WHERE local_profile_id = ?1",
            [local],
            |r| {
                Ok((
                    (0..4)
                        .map(|i| r.get::<_, String>(i))
                        .collect::<rusqlite::Result<Vec<_>>>()?,
                    r.get(4)?,
                ))
            },
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => anyhow!(code("journal.notBound")),
            other => other.into(),
        })?;
    if lease.is_some() {
        bail!(code("downgrade.leaseHeld"));
    }
    Ok(ids)
}

fn pending_work(db: &Db, local: &str) -> Result<u64> {
    let count: i64 = db.conn.query_row(
        "SELECT (SELECT count(*) FROM operations WHERE local_profile_id = ?1
                   AND state IN ('PENDING', 'RUNNING', 'AWAITING_RETRY'))
              + (SELECT count(*) FROM upload_sessions WHERE local_profile_id = ?1
                   AND state IN ('OPEN', 'FINALIZING', 'READY'))",
        [local],
        |r| r.get(0),
    )?;
    Ok(count as u64)
}

/// Starts the downgrade clone of the bound, stopped profile `local` and runs
/// it to the end.
pub(crate) fn start_clone(local: &str) -> Result<CloneDone> {
    valid_id(local)?;
    let _claim = profile::begin_user_mutation([local], &code("downgrade.actionDowngrade"))?;
    let db = Db::open()?;
    binding_facts(&db, local)?;
    if pending_work(&db, local)? > 0 {
        bail!(code("downgrade.operationPending"));
    }
    if !profile::load_raw(local).is_ok_and(|p| p.meta.id == local && !p.meta.temporary) {
        bail!(code("downgrade.originalUnreadable"));
    }
    let archive = archive_root()?;
    make_dir(&archive)?;
    store::require_local_ntfs(&archive)?;
    outside_discovery(&archive)?;
    let new = random_id()?;
    if discover()?.mentions(&new) {
        bail!(code("downgrade.archiveConflict"));
    }
    let mut id = [0u8; 16];
    shardx_core::keys::fill_random(&mut id).map_err(|e| anyhow!("{e}"))?;
    let journal_id = hex(&id);
    let dir = archive.join(&journal_id);
    let journal = DowngradeJournal {
        journal_id: journal_id.clone(),
        mode: Mode::Clone,
        original_local_profile_id: local.to_string(),
        new_local_profile_id: Some(new),
        phase: Phase::Created,
        original_metadata_archive_path: Some(
            dir.join(format!("{local}.json.archived"))
                .display()
                .to_string(),
        ),
        original_user_data_archive_path: Some(dir.join("user-data").display().to_string()),
        pre_v2_manifest_sha256: None,
        discovery_readback_sha256: None,
    };
    journal::downgrade_create(&db, &journal)?;
    drop(db);
    point("created")?;
    drop(_claim);
    run_clone(&journal_id)
}

/// Runs the clone journal `journal_id` from the phase it is at to the end (or
/// to its rollback), as a start after a crash does.
pub(crate) fn run_clone(journal_id: &str) -> Result<CloneDone> {
    let mut db = Db::open()?;
    let mut j = journal::downgrade_get(&db, journal_id)?
        .ok_or_else(|| anyhow!(code("journal.notFound")))?;
    if j.mode != Mode::Clone {
        bail!(code("downgrade.notClone"));
    }
    if j.phase.resume() == Next::Settled {
        return Ok(done(&j));
    }
    let _claim = profile::begin_user_mutation(
        [&j.original_local_profile_id],
        &code("downgrade.actionDowngrade"),
    )?;
    let w = places(&j)?;
    loop {
        let step: Result<DowngradeJournal> = (|| {
            Ok(match j.phase {
                Phase::Created => {
                    binding_facts(&db, &j.original_local_profile_id)?;
                    advance(&db, &j, Phase::Claimed, Patch::default())?
                }
                Phase::Claimed => {
                    make_dir(&w.dir)?;
                    store::require_local_ntfs(&w.dir)?;
                    outside_discovery(&w.dir)?;
                    move_path(&w.metadata_src, &w.metadata_dst, "downgrade.originalGone")?;
                    advance(&db, &j, Phase::OriginalMetadataMoved, Patch::default())?
                }
                Phase::OriginalMetadataMoved => {
                    move_data(&w)?;
                    advance(&db, &j, Phase::OriginalUserDataMoved, Patch::default())?
                }
                Phase::OriginalUserDataMoved => {
                    prove_gone(&j, &w)?;
                    advance(&db, &j, Phase::DiscoveryScanPassed, Patch::default())?
                }
                Phase::DiscoveryScanPassed => {
                    write_clone(&db, &j, &w)?;
                    advance(&db, &j, Phase::CloneWritten, Patch::default())?
                }
                Phase::CloneWritten => {
                    // The readback is made on a database opened afresh.
                    drop(std::mem::replace(&mut db, Db::open()?));
                    let again = journal::downgrade_get(&db, &j.journal_id)?
                        .ok_or_else(|| anyhow!(code("journal.notFound")))?;
                    let sha = read_back(&db, &again, &w)?;
                    advance(
                        &db,
                        &again,
                        Phase::ReadbackPassed,
                        Patch {
                            discovery_readback_sha256: Some(sha),
                            ..Patch::default()
                        },
                    )?
                }
                Phase::ReadbackPassed => advance(&db, &j, Phase::Completed, Patch::default())?,
                Phase::RollbackRequired => roll_back(&db, &j, &w)?,
                Phase::Completed | Phase::RolledBack => j.clone(),
                other => bail!(code_with(
                    "journal.badTransition",
                    &[("from", other.as_str()), ("to", "-")]
                )),
            })
        })();
        match step {
            Ok(next) => j = next,
            // A state nothing here can explain: put the original back rather
            // than guess.
            Err(e) if CONFLICTS.iter().any(|key| has_code(&format!("{e:#}"), key)) => {
                let _ = journal::downgrade_advance(
                    &db,
                    &j.journal_id,
                    Phase::RollbackRequired,
                    Patch::default(),
                );
                return Err(e);
            }
            Err(e) => return Err(e),
        }
        if j.phase.is_terminal() {
            return Ok(done(&j));
        }
    }
}

/// Failures after which the disk cannot be trusted to continue forward.
const CONFLICTS: [&str; 6] = [
    "downgrade.archiveConflict",
    "downgrade.originalGone",
    "downgrade.stillDiscoverable",
    "downgrade.cloneTeamMarker",
    "downgrade.cloneMismatch",
    "downgrade.userDataLink",
];

fn advance(db: &Db, j: &DowngradeJournal, to: Phase, patch: Patch) -> Result<DowngradeJournal> {
    point(&format!("before:{}", to.as_str()))?;
    let next = journal::downgrade_advance(db, &j.journal_id, to, patch)?;
    point(&format!("after:{}", to.as_str()))?;
    Ok(next)
}

fn move_data(w: &Places) -> Result<()> {
    if let Ok(meta) = std::fs::symlink_metadata(&w.data_src) {
        if meta.file_type().is_symlink() {
            bail!(code("downgrade.userDataLink"));
        }
    }
    if !exists(&w.data_src) && !exists(&w.data_dst) {
        // The profile never ran: its archive records an empty user-data.
        return make_dir(&w.data_dst);
    }
    move_path(&w.data_src, &w.data_dst, "downgrade.originalGone")
}

/// The discovery scan of L2242: the original is archived whole, outside
/// everything v0.1.28 reads, and v0.1.28 no longer sees its ID.
fn prove_gone(j: &DowngradeJournal, w: &Places) -> Result<()> {
    if !exists(&w.metadata_dst) || !exists(&w.data_dst) {
        bail!(code("downgrade.originalGone"));
    }
    outside_discovery(&w.dir)?;
    if discover()?.mentions(&j.original_local_profile_id) {
        bail!(code("downgrade.stillDiscoverable"));
    }
    Ok(())
}

/// Every file and directory under `root` with its size, by relative path.
/// `skip_team` leaves out the `team-sync*` entries of the top level.
fn listing(root: &Path, skip_team: bool) -> Result<BTreeMap<String, u64>> {
    fn walk(
        root: &Path,
        dir: &Path,
        skip_team: bool,
        out: &mut BTreeMap<String, u64>,
    ) -> Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let name = name_of(&entry.path());
            if skip_team && dir == root && name.starts_with("team-sync") {
                continue;
            }
            let kind = entry.file_type()?;
            if kind.is_symlink() {
                bail!(code("downgrade.userDataLink"));
            }
            let rel = entry
                .path()
                .strip_prefix(root)?
                .to_string_lossy()
                .replace('\\', "/");
            if kind.is_dir() {
                out.insert(format!("{rel}/"), 0);
                walk(root, &entry.path(), skip_team, out)?;
            } else {
                out.insert(rel, entry.metadata()?.len());
            }
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    walk(root, root, skip_team, &mut out)?;
    Ok(out)
}

/// Copies `src` to `dst` and flushes every file, leaving out the `team-sync*`
/// entries of the top level.
fn copy_tree(src: &Path, dst: &Path, top: bool) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let name = name_of(&entry.path());
        if top && name.starts_with("team-sync") {
            continue;
        }
        let kind = entry.file_type()?;
        let target = dst.join(&name);
        if kind.is_symlink() {
            bail!(code("downgrade.userDataLink"));
        } else if kind.is_dir() {
            copy_tree(&entry.path(), &target, false)?;
        } else {
            std::fs::copy(entry.path(), &target)?;
            // Windows flushes only a handle opened for writing.
            std::fs::OpenOptions::new()
                .write(true)
                .open(&target)?
                .sync_all()?;
        }
    }
    Ok(())
}

fn strings_of(value: &serde_json::Value, out: &mut Vec<String>, keys: &mut Vec<String>) {
    match value {
        serde_json::Value::String(s) => out.push(s.clone()),
        serde_json::Value::Array(items) => items.iter().for_each(|v| strings_of(v, out, keys)),
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                keys.push(k.clone());
                strings_of(v, out, keys);
            }
        }
        _ => {}
    }
}

/// A clone's record must carry no Team marker key, no identifier of the
/// binding and no trace of the original's ID.
fn require_clean(body: &[u8], forbidden: &[String]) -> Result<profile::StoredProfile> {
    let dirty = || anyhow!(code("downgrade.cloneTeamMarker"));
    let stored: profile::StoredProfile = serde_json::from_slice(body).map_err(|_| dirty())?;
    let (mut values, mut keys) = (Vec::new(), Vec::new());
    strings_of(
        &serde_json::from_slice(body).map_err(|_| dirty())?,
        &mut values,
        &mut keys,
    );
    if keys.iter().any(|k| MARKER_KEYS.contains(&k.as_str()))
        || values.iter().any(|v| {
            forbidden
                .iter()
                .any(|bad| !bad.is_empty() && v.contains(bad.as_str()))
        })
    {
        return Err(dirty());
    }
    Ok(stored)
}

/// The clone's record: the original's, under the new ID, without any
/// top-level Team marker.
fn clone_record(original: &[u8], new: &str, forbidden: &[String]) -> Result<Vec<u8>> {
    let mut stored: profile::StoredProfile = serde_json::from_slice(original)
        .map_err(|_| anyhow!(code("downgrade.originalUnreadable")))?;
    stored.meta.id = new.to_string();
    if stored.meta.created_at.is_none() {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        stored.meta.created_at = Some(format!("@{secs}"));
    }
    for key in MARKER_KEYS {
        stored.config.remove(key);
    }
    let body = serde_json::to_vec_pretty(&stored)?;
    require_clean(&body, forbidden)?;
    Ok(body)
}

/// Writes the clone: its user data first, then its record, so v0.1.28 never
/// lists a profile without data. Repeats find what is done and check it.
fn write_clone(db: &Db, j: &DowngradeJournal, w: &Places) -> Result<()> {
    let new = j.new_local_profile_id.as_deref().unwrap_or_default();
    let mut forbidden = binding_facts(db, &j.original_local_profile_id)?;
    forbidden.push(j.original_local_profile_id.clone());
    let archived = listing(&w.data_dst, true)?;
    if !exists(&w.clone_data) {
        if exists(&w.clone_staging) {
            std::fs::remove_dir_all(&w.clone_staging)?;
        }
        copy_tree(&w.data_dst, &w.clone_staging, true)?;
        point("clone_copied")?;
        if listing(&w.clone_staging, false)? != archived {
            bail!(code("downgrade.cloneMismatch"));
        }
        durable::replace_file(&w.clone_staging, &w.clone_data)?;
        durable::sync_parent(&w.clone_staging)?;
        durable::sync_parent(&w.clone_data)?;
    } else if listing(&w.clone_data, false)? != archived {
        bail!(code("downgrade.cloneMismatch"));
    }
    if exists(&w.clone_metadata) {
        let body = std::fs::read(&w.clone_metadata)?;
        if require_clean(&body, &forbidden)?.meta.id != new {
            bail!(code("downgrade.cloneMismatch"));
        }
    } else {
        let original = std::fs::read(&w.metadata_dst)?;
        let body = clone_record(&original, new, &forbidden)?;
        durable::write_private(&w.clone_metadata, &body)?;
    }
    Ok(())
}

/// The readback of L2242, on a fresh database and a fresh scan: v0.1.28 lists
/// the clone, lists nothing of the original, and the archive holds the
/// original. Returns the digest the journal pins.
fn read_back(db: &Db, j: &DowngradeJournal, w: &Places) -> Result<[u8; 32]> {
    let new = j.new_local_profile_id.as_deref().unwrap_or_default();
    let found = discover()?;
    if !found.lists(new)
        || !found.data.contains(new)
        || found.mentions(&j.original_local_profile_id)
    {
        bail!(code("downgrade.readbackFailed"));
    }
    let listed = profile::list_all()?;
    if !listed.iter().any(|p| p.id == new)
        || listed.iter().any(|p| p.id == j.original_local_profile_id)
    {
        bail!(code("downgrade.readbackFailed"));
    }
    let mut forbidden = binding_facts(db, &j.original_local_profile_id)?;
    forbidden.push(j.original_local_profile_id.clone());
    require_clean(&std::fs::read(&w.clone_metadata)?, &forbidden)?;
    if !exists(&w.metadata_dst) || !exists(&w.data_dst) {
        bail!(code("downgrade.originalGone"));
    }
    Ok(readback_digest(j))
}

fn readback_digest(j: &DowngradeJournal) -> [u8; 32] {
    let mut input = READBACK_DOMAIN.to_vec();
    for part in [
        Some(&j.journal_id),
        Some(&j.original_local_profile_id),
        j.new_local_profile_id.as_ref(),
        j.original_metadata_archive_path.as_ref(),
        j.original_user_data_archive_path.as_ref(),
    ] {
        let text = part.map_or("", |s| s.as_str());
        input.extend((text.len() as u64).to_be_bytes());
        input.extend(text.as_bytes());
    }
    sha256(&input)
}

/// Puts the original back and removes what the clone wrote. Both moves back
/// refuse to overwrite anything, so a state with the original in two places
/// stays `ROLLBACK_REQUIRED` for a person.
fn roll_back(db: &Db, j: &DowngradeJournal, w: &Places) -> Result<DowngradeJournal> {
    let j = if j.phase == Phase::RollbackRequired {
        j.clone()
    } else {
        journal::downgrade_advance(db, &j.journal_id, Phase::RollbackRequired, Patch::default())?
    };
    if exists(&w.clone_metadata) {
        let body = std::fs::read(&w.clone_metadata)?;
        let ours = serde_json::from_slice::<profile::StoredProfile>(&body)
            .is_ok_and(|p| Some(p.meta.id) == j.new_local_profile_id);
        if !ours {
            bail!(code("downgrade.rollbackConflict"));
        }
        std::fs::remove_file(&w.clone_metadata)?;
        durable::sync_parent(&w.clone_metadata)?;
    }
    for dir in [&w.clone_data, &w.clone_staging] {
        if exists(dir) {
            std::fs::remove_dir_all(dir)?;
            durable::sync_parent(dir)?;
        }
    }
    point("rollback:clone_removed")?;
    for (src, dst) in [
        (&w.data_src, &w.data_dst),
        (&w.metadata_src, &w.metadata_dst),
    ] {
        if exists(dst) {
            if exists(src) {
                bail!(code("downgrade.rollbackConflict"));
            }
            durable::replace_file(dst, src)?;
            durable::sync_parent(dst)?;
            durable::sync_parent(src)?;
        }
    }
    point("rollback:restored")?;
    let next = journal::downgrade_advance(db, &j.journal_id, Phase::RolledBack, Patch::default())?;
    // The archive directory is empty now; a leftover is harmless.
    let _ = std::fs::remove_dir(&w.dir);
    Ok(next)
}

/// Rolls the journal `journal_id` back on request.
pub(crate) fn roll_back_clone(journal_id: &str) -> Result<CloneDone> {
    let db = Db::open()?;
    let j = journal::downgrade_get(&db, journal_id)?
        .ok_or_else(|| anyhow!(code("journal.notFound")))?;
    if j.mode != Mode::Clone || j.phase == Phase::Completed {
        bail!(code_with(
            "journal.badTransition",
            &[("from", j.phase.as_str()), ("to", "ROLLED_BACK")]
        ));
    }
    let _claim = profile::begin_user_mutation(
        [&j.original_local_profile_id],
        &code("downgrade.actionDowngrade"),
    )?;
    Ok(done(&roll_back(&db, &j, &places(&j)?)?))
}

/// What a resume found for one open journal.
#[derive(Debug, Serialize)]
pub struct Resumed {
    pub journal_id: String,
    pub original_local_profile_id: String,
    pub phase: String,
    /// The error key of the journal that could not finish, if any.
    pub error: Option<String>,
}

/// Finishes (or rolls back) every open clone journal. A journal of the
/// pre-v2 restore flow is reported, not touched.
pub(crate) fn resume_open() -> Result<Vec<Resumed>> {
    if !Db::path()?.exists() {
        return Ok(Vec::new());
    }
    let open = journal::downgrade_open(&Db::open()?)?;
    let mut out = Vec::new();
    for j in open {
        let result = match j.mode {
            Mode::Clone => run_clone(&j.journal_id),
            Mode::PreV2Restore => Err(anyhow!(code("downgrade.preV2Unsupported"))),
        };
        out.push(match result {
            Ok(d) => Resumed {
                journal_id: j.journal_id,
                original_local_profile_id: j.original_local_profile_id,
                phase: d.phase,
                error: None,
            },
            Err(e) => Resumed {
                journal_id: j.journal_id,
                original_local_profile_id: j.original_local_profile_id,
                phase: j.phase.as_str().to_string(),
                error: Some(format!("{e:#}")),
            },
        });
    }
    Ok(out)
}

// -------------------------------------------------------------- unbind ----

/// What an explicit unbind reached.
#[derive(Debug, Serialize)]
pub struct Unbound {
    pub local_profile_id: String,
    pub response_sha256: String,
    /// The profile is still a local profile v0.1.28 lists.
    pub discoverable: bool,
}

/// The explicit unbind flow (L2239): the stopped profile, outside any other
/// flow, is unbound in `team::sync::unbind` (its tombstone outlives the
/// binding), then the binding is read back as gone and the profile re-scanned.
pub(crate) fn unbind_profile(local: &str, server_url: &str, now: u64) -> Result<Unbound> {
    valid_id(local)?;
    let _claim = profile::begin_user_mutation([local], &code("downgrade.actionUnbind"))?;
    if Db::path()?.exists() && journal::flow_taken(&Db::open()?, local)? {
        bail!(code("downgrade.flowTaken"));
    }
    let response = super::sync::unbind(local, server_url, now)?;
    if super::sync::is_published(local)? {
        bail!(code("downgrade.unbindReadback"));
    }
    Ok(Unbound {
        local_profile_id: local.to_string(),
        response_sha256: hex(&sha256(&response)),
        discoverable: discover()?.lists(local),
    })
}

// ----------------------------------------------------------- readiness ----

/// One reason a downgrade is not ready; `code` is a locale key.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Blocker {
    pub code: &'static str,
    pub count: u64,
}

#[derive(Debug, Serialize)]
pub struct Readiness {
    pub ready: bool,
    pub blockers: Vec<Blocker>,
}

/// `downgrade_ready` (L2240), derived now: no running browser, no lease, no
/// non-terminal operation, upload or spool file, no restore journal or open
/// downgrade journal, and every binding that is left has completed exactly
/// one flow whose evidence still reads back. A binding that was unbound has
/// no row; an unbind on top of a clone is a mixed flow.
pub(crate) fn readiness() -> Result<Readiness> {
    let mut blockers = Vec::new();
    let mut block = |code: &'static str, count: u64| {
        if count > 0 {
            blockers.push(Blocker { code, count });
        }
    };
    block(
        "downgrade.blockRunning",
        crate::process::Tracker::shared().running().len() as u64,
    );
    if Db::path()?.exists() {
        let db = Db::open()?;
        let count = |sql: &str| -> Result<u64> {
            Ok(db.conn.query_row(sql, [], |r| r.get::<_, i64>(0))? as u64)
        };
        block(
            "downgrade.blockLease",
            count("SELECT count(*) FROM profile_bindings WHERE lease_id IS NOT NULL")?,
        );
        block(
            "downgrade.blockOperation",
            count(
                "SELECT (SELECT count(*) FROM operations
                          WHERE state IN ('PENDING', 'RUNNING', 'AWAITING_RETRY'))
                      + (SELECT count(*) FROM upload_sessions
                          WHERE state IN ('OPEN', 'FINALIZING', 'READY'))",
            )?,
        );
        let spool = store::config_root()?.join("team-sync").join("spool");
        block(
            "downgrade.blockSpool",
            std::fs::read_dir(&spool).map_or(0, |entries| entries.count() as u64),
        );
        block(
            "downgrade.blockRestoreJournal",
            count("SELECT count(*) FROM restore_journals")?,
        );
        block(
            "downgrade.blockDowngradeJournal",
            count(
                "SELECT count(*) FROM downgrade_journals
                 WHERE phase NOT IN ('COMPLETED', 'ROLLED_BACK')",
            )?,
        );
        block(
            "downgrade.blockUnfinishedBinding",
            count(
                "SELECT count(*) FROM profile_bindings b WHERE NOT EXISTS (
                   SELECT 1 FROM downgrade_journals d
                   WHERE d.original_local_profile_id = b.local_profile_id
                     AND d.phase = 'COMPLETED')",
            )?,
        );
        block(
            "downgrade.blockMixedFlows",
            count(
                "SELECT (SELECT count(*) FROM (
                           SELECT original_local_profile_id FROM downgrade_journals
                           WHERE phase = 'COMPLETED'
                           GROUP BY original_local_profile_id HAVING count(*) > 1))
                      + (SELECT count(*) FROM downgrade_journals d WHERE d.phase = 'COMPLETED'
                           AND EXISTS (SELECT 1 FROM operations o
                             WHERE o.kind = 'UNBIND' AND o.state = 'COMPLETED'
                               AND o.local_profile_id_at_request = d.original_local_profile_id))",
            )?,
        );
        let mut broken = 0;
        let found = discover()?;
        for j in journal::downgrade_for_phase(&db, Phase::Completed)? {
            if j.mode == Mode::Clone && !clone_holds(&j, &found) {
                broken += 1;
            }
        }
        block("downgrade.blockCloneEvidence", broken);
    }
    Ok(Readiness {
        ready: blockers.is_empty(),
        blockers,
    })
}

/// A completed clone journal still reads back: its digest matches its fields,
/// the archive holds the original, and v0.1.28 lists the clone and not the
/// original.
fn clone_holds(j: &DowngradeJournal, found: &Discovery) -> bool {
    let Some(new) = j.new_local_profile_id.as_deref() else {
        return false;
    };
    j.discovery_readback_sha256 == Some(readback_digest(j))
        && places(j).is_ok_and(|w| exists(&w.metadata_dst) && exists(&w.data_dst))
        && found.lists(new)
        && !found.mentions(&j.original_local_profile_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crash_harness::kill_at;
    use journal::DowngradePhase as P;
    use rusqlite::params;
    use std::sync::MutexGuard;

    const LOCAL: &str = "11111111-1111-4111-8111-111111111111";
    const OTHER: &str = "22222222-2222-4222-8222-222222222222";
    const SERVER: &str = "https://fleet.test";
    const CHILD: &str = "team::downgrade::tests::child_clone";

    struct Env {
        _config: MutexGuard<'static, ()>,
        _lifecycle: MutexGuard<'static, ()>,
        dir: tempfile::TempDir,
    }

    impl Drop for Env {
        fn drop(&mut self) {
            CRASH_AT.with(|c| *c.borrow_mut() = None);
            crate::process::Tracker::shared().set_running_for_test("another-profile", false);
            store::set_config_root(None);
            store::set_data_root(None);
        }
    }

    fn env() -> Env {
        let config = store::config_root_test_lock()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let lifecycle = profile::lifecycle_test_guard();
        let dir = tempfile::tempdir().unwrap();
        store::set_config_root(Some(dir.path().join("config")));
        store::set_data_root(Some(dir.path().join("data")));
        Env {
            _config: config,
            _lifecycle: lifecycle,
            dir,
        }
    }

    /// What a profile holds before the flow touches it.
    struct Snapshot {
        metadata: Vec<u8>,
        data: [u8; 32],
    }

    fn tree_digest(root: &Path) -> [u8; 32] {
        fn walk(root: &Path, dir: &Path, out: &mut Vec<u8>) {
            let mut names: Vec<_> = std::fs::read_dir(dir)
                .unwrap()
                .map(|e| e.unwrap().path())
                .collect();
            names.sort();
            for path in names {
                let rel = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                if path.is_dir() {
                    out.extend(format!("D {rel}\n").bytes());
                    walk(root, &path, out);
                } else {
                    out.extend(format!("F {rel} ").bytes());
                    out.extend(sha256(&std::fs::read(&path).unwrap()));
                    out.push(b'\n');
                }
            }
        }
        let mut out = Vec::new();
        walk(root, root, &mut out);
        sha256(&out)
    }

    fn record(id: &str) -> serde_json::Value {
        serde_json::json!({
            "_meta": {"id": id, "created_at": "@100", "folder": "work", "pinned": true,
                      "tags": ["a"], "total_runtime_ms": 7},
            "name": "Profile one",
            "notes": "keep me",
            "team_binding": {"fleet": "x"},
            "remote_profile_id": "ab".repeat(16),
        })
    }

    fn seed(id: &str, with_data: bool) -> Snapshot {
        let metadata = serde_json::to_vec_pretty(&record(id)).unwrap();
        std::fs::write(
            store::profiles_dir().unwrap().join(format!("{id}.json")),
            &metadata,
        )
        .unwrap();
        if with_data {
            let data = store::user_data_root().unwrap().join(id);
            std::fs::create_dir_all(data.join("Default").join("sub")).unwrap();
            std::fs::create_dir_all(data.join("Empty")).unwrap();
            std::fs::create_dir_all(data.join("team-sync")).unwrap();
            std::fs::write(data.join("Default").join("Cookies"), b"cookie-bytes").unwrap();
            std::fs::write(
                data.join("Default").join("sub").join("deep.bin"),
                [7u8; 5000],
            )
            .unwrap();
            std::fs::write(data.join("Local State"), b"{}").unwrap();
            std::fs::write(data.join("team-sync").join("marker.txt"), b"team").unwrap();
            return Snapshot {
                metadata,
                data: tree_digest(&data),
            };
        }
        Snapshot {
            metadata,
            data: [0; 32],
        }
    }

    fn bind(id: &str) {
        let db = Db::open().unwrap();
        db.conn
            .execute(
                "INSERT INTO profile_bindings(local_profile_id, server_instance_id, tenant_id,
                   fleet_id, remote_profile_id, remote_version, accepted_restore_epoch, sync_state)
                 VALUES (?1, ?2, ?3, ?4, ?5, 0, 0, 'AVAILABLE')",
                params![
                    id,
                    "03".repeat(16),
                    "02".repeat(16),
                    "04".repeat(16),
                    hex(&sha256(id.as_bytes()))[..32].to_string()
                ],
            )
            .unwrap();
    }

    fn seeded() -> (Env, Snapshot) {
        let e = env();
        let snap = seed(LOCAL, true);
        bind(LOCAL);
        (e, snap)
    }

    fn has(e: &anyhow::Error, key: &str) -> bool {
        has_code(&format!("{e:#}"), key)
    }

    fn crash_at(point: &str) {
        CRASH_AT.with(|c| *c.borrow_mut() = Some(point.to_string()));
    }

    fn no_crash() {
        CRASH_AT.with(|c| *c.borrow_mut() = None);
    }

    fn the_journal() -> DowngradeJournal {
        let mut all = journal::downgrade_for(&Db::open().unwrap(), LOCAL).unwrap();
        assert_eq!(all.len(), 1, "{all:?}");
        all.remove(0)
    }

    /// Everything that must hold once the clone flow finished, however it
    /// got there.
    fn assert_cloned(before: &Snapshot) -> DowngradeJournal {
        let j = the_journal();
        assert_eq!(j.phase, P::Completed);
        let new = j.new_local_profile_id.clone().unwrap();
        assert_ne!(new, LOCAL);
        let parsed = uuid::Uuid::parse_str(&new).unwrap();
        assert_eq!(parsed.get_version_num(), 4, "{new}");
        assert_eq!(j.discovery_readback_sha256, Some(readback_digest(&j)));
        let w = places(&j).unwrap();
        // The original sits whole in the archive, outside everything listed.
        assert!(!exists(&w.metadata_src) && !exists(&w.data_src));
        assert_eq!(std::fs::read(&w.metadata_dst).unwrap(), before.metadata);
        assert_eq!(tree_digest(&w.data_dst), before.data);
        outside_discovery(&w.dir).unwrap();
        let found = discover().unwrap();
        assert!(!found.mentions(LOCAL));
        assert!(found.lists(&new) && found.data.contains(&new));
        let listed = profile::list_all().unwrap();
        assert!(listed.iter().any(|p| p.id == new));
        assert!(listed.iter().all(|p| p.id != LOCAL));
        // The clone carries nothing of the binding.
        let text = std::fs::read_to_string(&w.clone_metadata).unwrap();
        for bad in [LOCAL, "team_binding", "remote_profile_id", &"03".repeat(16)] {
            assert!(!text.contains(bad), "{bad} in {text}");
        }
        let stored: profile::StoredProfile = serde_json::from_str(&text).unwrap();
        assert_eq!(stored.meta.id, new);
        assert_eq!(stored.meta.folder, "work");
        assert!(stored.meta.pinned);
        assert_eq!(stored.config["notes"], "keep me");
        assert!(!w.clone_data.join("team-sync").exists());
        assert_eq!(
            listing(&w.clone_data, false).unwrap(),
            listing(&w.data_dst, true).unwrap()
        );
        assert!(!exists(&w.clone_staging));
        j
    }

    fn ready_codes() -> Vec<&'static str> {
        readiness()
            .unwrap()
            .blockers
            .iter()
            .map(|b| b.code)
            .filter(|c| *c != "downgrade.blockRunning")
            .collect()
    }

    // ------------------------------------------------------- discovery ----

    #[test]
    fn discovery_sees_every_place_v0_1_28_reads_and_nothing_in_the_archive() {
        let _e = env();
        seed(LOCAL, true);
        let found = discover().unwrap();
        assert!(found.lists(LOCAL) && found.mentions(LOCAL) && found.data.contains(LOCAL));
        assert!(!found.mentions(OTHER));
        // A record under another file name, a trash entry and an unreadable
        // record each still mention the ID.
        let profiles = store::profiles_dir().unwrap();
        std::fs::write(
            profiles.join("renamed.json"),
            serde_json::to_vec(&record(OTHER)).unwrap(),
        )
        .unwrap();
        let found = discover().unwrap();
        assert!(found.mentions(OTHER) && !found.lists(OTHER));
        std::fs::remove_file(profiles.join("renamed.json")).unwrap();
        let zip = store::trash_dir().unwrap().join(format!("{OTHER}.zip"));
        std::fs::write(&zip, b"z").unwrap();
        assert!(discover().unwrap().mentions(OTHER));
        std::fs::remove_file(&zip).unwrap();
        std::fs::write(profiles.join("junk.json"), format!("not json {OTHER}")).unwrap();
        assert!(discover().unwrap().mentions(OTHER));
        std::fs::remove_file(profiles.join("junk.json")).unwrap();
        assert!(!discover().unwrap().mentions(OTHER));
        // The archive root is outside all four roots; a directory inside one is not.
        let archive = archive_root().unwrap();
        make_dir(&archive).unwrap();
        outside_discovery(&archive).unwrap();
        for inside in [
            store::profiles_dir().unwrap(),
            store::user_data_root().unwrap().join(LOCAL),
            store::trash_dir().unwrap(),
            store::extensions_dir().unwrap(),
        ] {
            let e = outside_discovery(&inside).unwrap_err();
            assert!(has(&e, "downgrade.archiveDiscoverable"), "{e:#}");
        }
    }

    // ----------------------------------------------------- the clone flow --

    #[test]
    fn the_clone_flow_archives_the_original_and_lists_only_a_clean_clone() {
        let (_e, before) = seeded();
        assert_eq!(ready_codes(), ["downgrade.blockUnfinishedBinding"]);
        let done = start_clone(LOCAL).unwrap();
        assert_eq!(done.phase, "COMPLETED");
        assert_eq!(done.original_local_profile_id, LOCAL);
        let j = assert_cloned(&before);
        let e = roll_back_clone(&j.journal_id).unwrap_err();
        assert!(has(&e, "journal.badTransition"), "{e:#}");
        assert_eq!(done.new_local_profile_id, j.new_local_profile_id.unwrap());
        assert!(ready_codes().is_empty(), "{:?}", ready_codes());
        // The original's binding stays, so a return to v0.2 can still recover.
        assert!(super::super::sync::is_published(LOCAL).unwrap());
    }

    #[test]
    fn two_clones_get_different_random_ids() {
        let (_e, _) = seeded();
        seed(OTHER, false);
        bind(OTHER);
        let a = start_clone(LOCAL).unwrap().new_local_profile_id;
        let b = start_clone(OTHER).unwrap().new_local_profile_id;
        assert_ne!(a, b);
        assert!(ready_codes().is_empty());
    }

    #[test]
    fn a_profile_that_never_ran_clones_with_empty_user_data() {
        let _e = env();
        let before = seed(LOCAL, false);
        bind(LOCAL);
        start_clone(LOCAL).unwrap();
        let j = the_journal();
        let w = places(&j).unwrap();
        assert_eq!(std::fs::read(&w.metadata_dst).unwrap(), before.metadata);
        assert!(w.data_dst.is_dir() && w.clone_data.is_dir());
        assert!(listing(&w.clone_data, false).unwrap().is_empty());
    }

    /// Where the flow stands when each crash point fires: the journal phase
    /// the next start reads, and what is on disk (original metadata moved,
    /// user data moved, clone data in place, clone record written).
    const POINTS: [(&str, P, [bool; 4]); 16] = [
        ("created", P::Created, [false, false, false, false]),
        ("before:CLAIMED", P::Created, [false, false, false, false]),
        ("after:CLAIMED", P::Claimed, [false, false, false, false]),
        (
            "before:ORIGINAL_METADATA_MOVED",
            P::Claimed,
            [true, false, false, false],
        ),
        (
            "after:ORIGINAL_METADATA_MOVED",
            P::OriginalMetadataMoved,
            [true, false, false, false],
        ),
        (
            "before:ORIGINAL_USER_DATA_MOVED",
            P::OriginalMetadataMoved,
            [true, true, false, false],
        ),
        (
            "after:ORIGINAL_USER_DATA_MOVED",
            P::OriginalUserDataMoved,
            [true, true, false, false],
        ),
        (
            "before:DISCOVERY_SCAN_PASSED",
            P::OriginalUserDataMoved,
            [true, true, false, false],
        ),
        (
            "after:DISCOVERY_SCAN_PASSED",
            P::DiscoveryScanPassed,
            [true, true, false, false],
        ),
        (
            "clone_copied",
            P::DiscoveryScanPassed,
            [true, true, false, false],
        ),
        (
            "before:CLONE_WRITTEN",
            P::DiscoveryScanPassed,
            [true, true, true, true],
        ),
        (
            "after:CLONE_WRITTEN",
            P::CloneWritten,
            [true, true, true, true],
        ),
        (
            "before:READBACK_PASSED",
            P::CloneWritten,
            [true, true, true, true],
        ),
        (
            "after:READBACK_PASSED",
            P::ReadbackPassed,
            [true, true, true, true],
        ),
        (
            "before:COMPLETED",
            P::ReadbackPassed,
            [true, true, true, true],
        ),
        ("after:COMPLETED", P::Completed, [true, true, true, true]),
    ];

    fn assert_crash_state(point: &str, phase: P, disk: [bool; 4]) {
        let j = the_journal();
        assert_eq!(j.phase, phase, "{point}");
        let w = places(&j).unwrap();
        assert_eq!(
            !exists(&w.metadata_src) && exists(&w.metadata_dst),
            disk[0],
            "{point}"
        );
        assert_eq!(
            !exists(&w.data_src) && exists(&w.data_dst),
            disk[1],
            "{point}"
        );
        assert_eq!(exists(&w.clone_data), disk[2], "{point}");
        assert_eq!(exists(&w.clone_metadata), disk[3], "{point}");
        // The original is in one place at a time, never both and never neither.
        assert_ne!(exists(&w.metadata_src), exists(&w.metadata_dst), "{point}");
        assert_ne!(exists(&w.data_src), exists(&w.data_dst), "{point}");
        let blocked = ready_codes();
        assert_eq!(
            blocked.contains(&"downgrade.blockDowngradeJournal"),
            phase != P::Completed,
            "{point}: {blocked:?}"
        );
        assert!(!blocked.is_empty() || phase == P::Completed, "{point}");
    }

    #[test]
    fn a_cut_off_at_every_step_resumes_to_the_same_finished_clone() {
        for (point, phase, disk) in POINTS {
            let (_e, before) = seeded();
            crash_at(point);
            let e = start_clone(LOCAL).unwrap_err();
            assert!(
                format!("{e:#}").contains(&format!("injected crash at {point}")),
                "{e:#}"
            );
            no_crash();
            assert_crash_state(point, phase, disk);
            let id = the_journal().journal_id;
            let done = run_clone(&id).unwrap();
            assert_eq!(done.phase, "COMPLETED", "{point}");
            assert_cloned(&before);
            // A second start has nothing left to do.
            assert_eq!(run_clone(&id).unwrap().phase, "COMPLETED");
            assert_cloned(&before);
        }
    }

    #[test]
    fn a_cut_off_twice_still_finishes_once() {
        let (_e, before) = seeded();
        crash_at("after:ORIGINAL_METADATA_MOVED");
        start_clone(LOCAL).unwrap_err();
        let id = the_journal().journal_id;
        crash_at("clone_copied");
        run_clone(&id).unwrap_err();
        crash_at("before:READBACK_PASSED");
        run_clone(&id).unwrap_err();
        no_crash();
        run_clone(&id).unwrap();
        assert_cloned(&before);
    }

    /// `child_clone` is the crash harness's child: it runs the flow and the
    /// parent kills the process at `SHARDX_CRASH_POINT`.
    #[test]
    #[ignore = "child process of the crash harness"]
    fn child_clone() {
        let Some(root) = std::env::var_os("SHARDX_W13_ROOT") else {
            return;
        };
        let root = std::path::PathBuf::from(root);
        store::set_config_root(Some(root.join("config")));
        store::set_data_root(Some(root.join("data")));
        let _ = start_clone(LOCAL);
    }

    #[test]
    fn a_process_killed_at_every_step_resumes_to_the_same_finished_clone() {
        for (point, phase, disk) in POINTS {
            let (e, before) = seeded();
            assert!(
                kill_at(CHILD, point, &[("SHARDX_W13_ROOT", e.dir.path())]),
                "{point}: the child never reached it"
            );
            assert_crash_state(point, phase, disk);
            let id = the_journal().journal_id;
            run_clone(&id).unwrap();
            assert_cloned(&before);
        }
    }

    #[test]
    fn a_rollback_from_every_step_puts_the_original_back_and_frees_the_profile() {
        for &(point, ..) in POINTS.iter().filter(|t| t.0 != "after:COMPLETED") {
            let (_e, before) = seeded();
            crash_at(point);
            start_clone(LOCAL).unwrap_err();
            no_crash();
            let j = the_journal();
            let done = roll_back_clone(&j.journal_id).unwrap();
            assert_eq!(done.phase, "ROLLED_BACK", "{point}");
            let w = places(&j).unwrap();
            assert_eq!(
                std::fs::read(&w.metadata_src).unwrap(),
                before.metadata,
                "{point}"
            );
            assert_eq!(tree_digest(&w.data_src), before.data, "{point}");
            assert!(!exists(&w.metadata_dst) && !exists(&w.data_dst), "{point}");
            assert!(
                !exists(&w.clone_metadata) && !exists(&w.clone_data),
                "{point}"
            );
            assert!(!exists(&w.clone_staging), "{point}");
            let found = discover().unwrap();
            let new = j.new_local_profile_id.as_ref().unwrap();
            assert!(found.lists(LOCAL) && !found.mentions(new), "{point}");
            // Not downgrade-ready: the binding finished no flow. And the
            // rolled-back profile may start over.
            assert!(
                ready_codes().contains(&"downgrade.blockUnfinishedBinding"),
                "{point}"
            );
            start_clone(LOCAL).unwrap();
            let all = journal::downgrade_for(&Db::open().unwrap(), LOCAL).unwrap();
            assert_eq!(all.len(), 2, "{point}");
        }
    }

    #[test]
    fn a_rollback_cut_off_resumes_to_the_same_restored_original() {
        for point in ["rollback:clone_removed", "rollback:restored"] {
            let (_e, before) = seeded();
            crash_at("after:CLONE_WRITTEN");
            start_clone(LOCAL).unwrap_err();
            let j = the_journal();
            crash_at(point);
            roll_back_clone(&j.journal_id).unwrap_err();
            no_crash();
            assert_eq!(the_journal().phase, P::RollbackRequired, "{point}");
            // The next start finishes it: a journal asking for rollback rolls back.
            let done = run_clone(&j.journal_id).unwrap();
            assert_eq!(done.phase, "ROLLED_BACK", "{point}");
            let w = places(&j).unwrap();
            assert_eq!(
                std::fs::read(&w.metadata_src).unwrap(),
                before.metadata,
                "{point}"
            );
            assert_eq!(tree_digest(&w.data_src), before.data, "{point}");
        }
    }

    #[test]
    fn an_original_in_two_places_stops_the_flow_and_asks_for_a_person() {
        let (_e, before) = seeded();
        crash_at("after:CLAIMED");
        start_clone(LOCAL).unwrap_err();
        no_crash();
        let j = the_journal();
        let w = places(&j).unwrap();
        std::fs::create_dir_all(w.metadata_dst.parent().unwrap()).unwrap();
        std::fs::write(&w.metadata_dst, b"stray").unwrap();
        let e = run_clone(&j.journal_id).unwrap_err();
        assert!(has(&e, "downgrade.archiveConflict"), "{e:#}");
        assert_eq!(the_journal().phase, P::RollbackRequired);
        // Nothing was overwritten, and the next start refuses the rollback too.
        assert_eq!(std::fs::read(&w.metadata_src).unwrap(), before.metadata);
        assert_eq!(std::fs::read(&w.metadata_dst).unwrap(), b"stray");
        let e = run_clone(&j.journal_id).unwrap_err();
        assert!(has(&e, "downgrade.rollbackConflict"), "{e:#}");
        assert!(ready_codes().contains(&"downgrade.blockDowngradeJournal"));
        std::fs::remove_file(&w.metadata_dst).unwrap();
        assert_eq!(run_clone(&j.journal_id).unwrap().phase, "ROLLED_BACK");
    }

    #[test]
    fn an_original_that_vanished_is_rolled_back_not_guessed() {
        let (_e, _) = seeded();
        crash_at("after:CLAIMED");
        start_clone(LOCAL).unwrap_err();
        no_crash();
        let j = the_journal();
        let w = places(&j).unwrap();
        std::fs::remove_file(&w.metadata_src).unwrap();
        let e = run_clone(&j.journal_id).unwrap_err();
        assert!(has(&e, "downgrade.originalGone"), "{e:#}");
        assert_eq!(the_journal().phase, P::RollbackRequired);
        assert_eq!(run_clone(&j.journal_id).unwrap().phase, "ROLLED_BACK");
    }

    #[test]
    fn an_archive_that_lost_the_original_stops_the_flow_before_the_clone() {
        for lost in ["record", "data"] {
            let (_e, _) = seeded();
            crash_at("after:ORIGINAL_USER_DATA_MOVED");
            start_clone(LOCAL).unwrap_err();
            no_crash();
            let j = the_journal();
            let w = places(&j).unwrap();
            if lost == "record" {
                std::fs::remove_file(&w.metadata_dst).unwrap();
            } else {
                std::fs::remove_dir_all(&w.data_dst).unwrap();
            }
            let e = run_clone(&j.journal_id).unwrap_err();
            assert!(has(&e, "downgrade.originalGone"), "{lost}: {e:#}");
            assert!(
                !exists(&w.clone_metadata) && !exists(&w.clone_data),
                "{lost}"
            );
        }
    }

    #[test]
    fn a_trace_of_the_old_id_after_the_move_fails_the_discovery_scan() {
        for trace in ["trash", "unparsed", "user-data"] {
            let (_e, before) = seeded();
            crash_at("after:ORIGINAL_USER_DATA_MOVED");
            start_clone(LOCAL).unwrap_err();
            no_crash();
            match trace {
                "trash" => std::fs::write(
                    store::trash_dir().unwrap().join(format!("{LOCAL}.zip")),
                    b"z",
                ),
                "unparsed" => std::fs::write(
                    store::profiles_dir().unwrap().join("broken.json"),
                    format!("{{ {LOCAL}"),
                ),
                _ => std::fs::create_dir_all(store::user_data_root().unwrap().join(LOCAL)),
            }
            .unwrap();
            let j = the_journal();
            let e = run_clone(&j.journal_id).unwrap_err();
            assert!(has(&e, "downgrade.stillDiscoverable"), "{trace}: {e:#}");
            assert_eq!(the_journal().phase, P::RollbackRequired, "{trace}");
            // The rollback refuses to overwrite a stray directory, and
            // restores around the other traces.
            let w = places(&j).unwrap();
            if trace == "user-data" {
                let e = run_clone(&j.journal_id).unwrap_err();
                assert!(has(&e, "downgrade.rollbackConflict"), "{e:#}");
                std::fs::remove_dir_all(&w.data_src).unwrap();
            }
            run_clone(&j.journal_id).unwrap();
            assert_eq!(
                std::fs::read(&w.metadata_src).unwrap(),
                before.metadata,
                "{trace}"
            );
            assert_eq!(the_journal().phase, P::RolledBack);
        }
    }

    #[test]
    fn a_journal_that_points_outside_its_archive_is_not_followed() {
        let (_e, before) = seeded();
        let profiles = store::profiles_dir().unwrap();
        let archive = archive_root().unwrap().join("evil");
        let evil = DowngradeJournal {
            journal_id: "evil".into(),
            mode: Mode::Clone,
            original_local_profile_id: LOCAL.into(),
            new_local_profile_id: Some(OTHER.into()),
            phase: P::Created,
            original_metadata_archive_path: Some(
                profiles.join("x.json.archived").display().to_string(),
            ),
            original_user_data_archive_path: Some(archive.join("user-data").display().to_string()),
            pre_v2_manifest_sha256: None,
            discovery_readback_sha256: None,
        };
        journal::downgrade_create(&Db::open().unwrap(), &evil).unwrap();
        let e = run_clone("evil").unwrap_err();
        assert!(has(&e, "downgrade.archiveOutside"), "{e:#}");
        let dotted = DowngradeJournal {
            original_metadata_archive_path: Some(
                archive.join("..").join("x").display().to_string(),
            ),
            ..evil.clone()
        };
        assert!(places(&dotted).is_err());
        assert_eq!(
            std::fs::read(profiles.join(format!("{LOCAL}.json"))).unwrap(),
            before.metadata
        );
        // An ID that is a path, with paths that agree with it, is not followed
        // either, nor are IDs of the profiles that are paths.
        let nested = archive_root().unwrap().join("a").join("b");
        let traversal = DowngradeJournal {
            journal_id: "a/b".into(),
            original_metadata_archive_path: Some(nested.join("m").display().to_string()),
            original_user_data_archive_path: Some(nested.join("d").display().to_string()),
            ..evil.clone()
        };
        assert!(has(
            &places(&traversal).err().unwrap(),
            "downgrade.archiveOutside"
        ));
        let tidy = DowngradeJournal {
            journal_id: "tidy".into(),
            original_metadata_archive_path: Some(
                archive_root()
                    .unwrap()
                    .join("tidy")
                    .join("m")
                    .display()
                    .to_string(),
            ),
            original_user_data_archive_path: Some(
                archive_root()
                    .unwrap()
                    .join("tidy")
                    .join("d")
                    .display()
                    .to_string(),
            ),
            ..evil
        };
        assert!(places(&tidy).is_ok());
        for (original, new) in [
            ("a/b", OTHER),
            (LOCAL, "a/b"),
            ("..", OTHER),
            (LOCAL, "x.y"),
        ] {
            let bad = DowngradeJournal {
                original_local_profile_id: original.into(),
                new_local_profile_id: Some(new.into()),
                ..tidy.clone()
            };
            assert!(
                has(&places(&bad).err().unwrap(), "profile.invalidId"),
                "{original} {new}"
            );
        }
    }

    fn insert_op(db: &Db, op: &str, kind: &str, state: &str) {
        db.conn
            .execute(
                "INSERT INTO operations(op_id, local_profile_id, local_profile_id_at_request,
                   server_instance_id, restore_epoch, tenant_id, operation_scope, kind,
                   idempotency_key, canonical_request_hash, exact_request_bytes,
                   exact_request_bytes_sha256, state, created_at, updated_at)
                 VALUES (?1, ?2, ?2, 'i', 0, 't', 's', ?3, ?1, zeroblob(32), x'01', zeroblob(32),
                   ?4, 't', 't')",
                params![op, LOCAL, kind, state],
            )
            .unwrap();
    }

    fn insert_upload(db: &Db, state: &str) {
        db.conn
            .execute(
                "INSERT INTO operations(op_id, local_profile_id, local_profile_id_at_request,
                   server_instance_id, restore_epoch, tenant_id, operation_scope, kind,
                   idempotency_key, canonical_request_hash, exact_request_bytes,
                   exact_request_bytes_sha256, state, remote_upload_id, lease_id, fencing_token,
                   base_version, snapshot_id, manifest_replay_id, intent_hash, ciphertext_sha256,
                   signed_manifest_container_bytes, signed_manifest_container_hash,
                   signed_manifest_container_bytes_sha256, created_at, updated_at)
                 VALUES ('commit', ?1, ?1, 'i', 0, 't', 's', 'COMMIT', 'k', zeroblob(32), x'01',
                   zeroblob(32), 'FAILED', 'u', 'l', 1, 0, zeroblob(16), zeroblob(16),
                   zeroblob(32), zeroblob(32), x'01', zeroblob(32), zeroblob(32), 't', 't')",
                params![LOCAL],
            )
            .unwrap();
        db.conn
            .execute(
                "INSERT INTO upload_sessions(upload_local_id, local_profile_id,
                   local_profile_id_at_request, commit_op_id, server_instance_id, restore_epoch,
                   tenant_id, fleet_id, remote_profile_id, remote_upload_id, snapshot_id,
                   manifest_replay_id, intent_hash, preamble_sha256, dek_slot_sha256,
                   fkek_key_id, key_generation, expected_ciphertext_sha256,
                   expected_ciphertext_size, spool_ref, state, created_at, updated_at)
                 VALUES ('up', ?1, ?1, 'commit', 'i', 0, 't', 'f', 'r', 'u', zeroblob(16),
                   zeroblob(16), zeroblob(32), zeroblob(32), zeroblob(32), 'k', 1, zeroblob(32),
                   0, 'spool', ?2, 't', 't')",
                params![LOCAL, state],
            )
            .unwrap();
    }

    #[test]
    fn start_refuses_a_profile_that_is_not_ready_to_move() {
        let (_e, before) = seeded();
        let refuse = |id: &str, key: &str| {
            let e = start_clone(id).unwrap_err();
            assert!(has(&e, key), "{key}: {e:#}");
        };
        refuse("a/b", "profile.invalidId");
        refuse("..", "profile.invalidId");
        refuse(OTHER, "journal.notBound");
        // A running browser.
        crate::process::Tracker::shared().set_running_for_test(LOCAL, true);
        refuse(LOCAL, "profile.stopRunningBrowser");
        crate::process::Tracker::shared().set_running_for_test(LOCAL, false);
        // A lease.
        let db = Db::open().unwrap();
        db.conn
            .execute(
                "UPDATE profile_bindings SET lease_id = 'aa', fencing_token = 1",
                [],
            )
            .unwrap();
        refuse(LOCAL, "downgrade.leaseHeld");
        db.conn
            .execute(
                "UPDATE profile_bindings SET lease_id = NULL, fencing_token = NULL",
                [],
            )
            .unwrap();
        // A request not finished, then an upload not finished.
        insert_op(&db, "op1", "PUBLISH", "RUNNING");
        refuse(LOCAL, "downgrade.operationPending");
        db.conn.execute("DELETE FROM operations", []).unwrap();
        insert_upload(&db, "OPEN");
        refuse(LOCAL, "downgrade.operationPending");
        db.conn.execute("DELETE FROM upload_sessions", []).unwrap();
        db.conn.execute("DELETE FROM operations", []).unwrap();
        // A temporary profile, an unreadable record, a record under another ID.
        let path = store::profiles_dir().unwrap().join(format!("{LOCAL}.json"));
        let mut temp = record(LOCAL);
        temp["_meta"]["temporary"] = true.into();
        std::fs::write(&path, serde_json::to_vec(&temp).unwrap()).unwrap();
        refuse(LOCAL, "downgrade.originalUnreadable");
        std::fs::write(&path, b"{").unwrap();
        refuse(LOCAL, "downgrade.originalUnreadable");
        std::fs::write(&path, serde_json::to_vec(&record(OTHER)).unwrap()).unwrap();
        refuse(LOCAL, "downgrade.originalUnreadable");
        std::fs::write(&path, &before.metadata).unwrap();
        // No refusal moved or journaled anything.
        assert!(journal::downgrade_for(&db, LOCAL).unwrap().is_empty());
        let archived = std::fs::read_dir(archive_root().unwrap());
        assert!(archived.map_or(true, |entries| entries.count() == 0));
        start_clone(LOCAL).unwrap();
    }

    // ----------------------------------------------------- the clone ------

    #[test]
    fn a_clone_record_drops_marker_keys_and_refuses_what_it_cannot_drop() {
        let original = serde_json::to_vec(&record(LOCAL)).unwrap();
        let forbidden = vec!["ab".repeat(16), LOCAL.to_string(), String::new()];
        let body = clone_record(&original, OTHER, &forbidden).unwrap();
        let text = String::from_utf8(body).unwrap();
        assert!(text.contains(OTHER) && !text.contains("team_binding"));
        // A binding identifier in a value, a marker key below the top level,
        // or the original's ID in a value cannot be dropped: the record is refused.
        for bad in [
            serde_json::json!({"notes": format!("see {}", "ab".repeat(16))}),
            serde_json::json!({"nested": {"lease_id": "x"}}),
            serde_json::json!({"nested": [{"credential_ref": "x"}]}),
            serde_json::json!({"notes": format!("copy of {LOCAL}")}),
        ] {
            let mut value = record(LOCAL);
            value
                .as_object_mut()
                .unwrap()
                .extend(bad.as_object().unwrap().clone());
            let body = serde_json::to_vec(&value).unwrap();
            let e = clone_record(&body, OTHER, &forbidden).unwrap_err();
            assert!(has(&e, "downgrade.cloneTeamMarker"), "{bad}: {e:#}");
        }
        let e = clone_record(b"{", OTHER, &forbidden).unwrap_err();
        assert!(has(&e, "downgrade.originalUnreadable"), "{e:#}");
        // A record without a creation time gets one, so listing never rewrites it.
        let mut bare = record(LOCAL);
        bare["_meta"].as_object_mut().unwrap().remove("created_at");
        let body = clone_record(&serde_json::to_vec(&bare).unwrap(), OTHER, &forbidden).unwrap();
        assert!(String::from_utf8(body)
            .unwrap()
            .contains("\"created_at\": \"@"));
    }

    #[test]
    fn a_clone_that_would_carry_a_marker_is_not_written_and_is_rolled_back() {
        let (_e, before) = seeded();
        let path = store::profiles_dir().unwrap().join(format!("{LOCAL}.json"));
        let mut value = record(LOCAL);
        value["notes"] = format!("bound as {}", "02".repeat(16)).into();
        std::fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        let e = start_clone(LOCAL).unwrap_err();
        assert!(has(&e, "downgrade.cloneTeamMarker"), "{e:#}");
        assert_eq!(the_journal().phase, P::RollbackRequired);
        let j = the_journal();
        assert!(!exists(&places(&j).unwrap().clone_metadata));
        run_clone(&j.journal_id).unwrap();
        assert_eq!(the_journal().phase, P::RolledBack);
        assert_eq!(tree_digest(&places(&j).unwrap().data_src), before.data);
    }

    #[test]
    fn a_clone_copy_that_differs_from_the_archive_is_refused() {
        let (_e, _) = seeded();
        crash_at("after:DISCOVERY_SCAN_PASSED");
        start_clone(LOCAL).unwrap_err();
        no_crash();
        let j = the_journal();
        let w = places(&j).unwrap();
        // A clone data directory already there with other contents.
        std::fs::create_dir_all(&w.clone_data).unwrap();
        std::fs::write(w.clone_data.join("extra"), b"x").unwrap();
        let e = run_clone(&j.journal_id).unwrap_err();
        assert!(has(&e, "downgrade.cloneMismatch"), "{e:#}");
        assert_eq!(the_journal().phase, P::RollbackRequired);
    }

    #[test]
    fn a_record_at_the_clone_path_under_another_id_is_refused() {
        let (_e, _) = seeded();
        crash_at("after:DISCOVERY_SCAN_PASSED");
        start_clone(LOCAL).unwrap_err();
        no_crash();
        let j = the_journal();
        let w = places(&j).unwrap();
        let other = serde_json::json!({"_meta": {"id": OTHER}, "name": "Other"});
        std::fs::write(&w.clone_metadata, serde_json::to_vec(&other).unwrap()).unwrap();
        let e = run_clone(&j.journal_id).unwrap_err();
        assert!(has(&e, "downgrade.cloneMismatch"), "{e:#}");
        assert_eq!(the_journal().phase, P::RollbackRequired);
    }

    #[cfg(unix)]
    #[test]
    fn a_link_in_the_user_data_is_not_followed() {
        let (_e, _) = seeded();
        let data = store::user_data_root().unwrap().join(LOCAL);
        std::os::unix::fs::symlink("/", data.join("link")).unwrap();
        let e = start_clone(LOCAL).unwrap_err();
        assert!(has(&e, "downgrade.userDataLink"), "{e:#}");
        let j = the_journal();
        run_clone(&j.journal_id).unwrap();
        assert!(places(&j).unwrap().metadata_src.exists());
    }

    #[test]
    fn a_readback_that_v0_1_28_would_not_agree_with_fails_the_flow() {
        for trace in [
            "old id back",
            "clone hidden",
            "clone gone",
            "clone record gone",
        ] {
            let (_e, before) = seeded();
            crash_at("after:CLONE_WRITTEN");
            start_clone(LOCAL).unwrap_err();
            no_crash();
            let j = the_journal();
            let w = places(&j).unwrap();
            match trace {
                "old id back" => {
                    let zip = store::trash_dir().unwrap().join(format!("{LOCAL}.zip"));
                    std::fs::write(zip, b"z").unwrap();
                }
                // Hidden from the listing, as a temporary profile is.
                "clone hidden" => {
                    let mut stored: serde_json::Value =
                        serde_json::from_slice(&std::fs::read(&w.clone_metadata).unwrap()).unwrap();
                    stored["_meta"]["temporary"] = true.into();
                    std::fs::write(&w.clone_metadata, serde_json::to_vec(&stored).unwrap())
                        .unwrap();
                }
                "clone record gone" => std::fs::remove_file(&w.clone_metadata).unwrap(),
                _ => std::fs::remove_dir_all(&w.clone_data).unwrap(),
            }
            let e = run_clone(&j.journal_id).unwrap_err();
            assert!(has(&e, "downgrade.readbackFailed"), "{trace}: {e:#}");
            assert_eq!(the_journal().phase, P::CloneWritten, "{trace}");
            assert!(ready_codes().contains(&"downgrade.blockDowngradeJournal"));
            // The original is still whole in the archive for recovery.
            assert_eq!(std::fs::read(&w.metadata_dst).unwrap(), before.metadata);
        }
    }

    #[test]
    fn a_rollback_leaves_a_record_at_the_clone_path_that_is_not_the_clone() {
        let (_e, _) = seeded();
        crash_at("after:CLONE_WRITTEN");
        start_clone(LOCAL).unwrap_err();
        no_crash();
        let j = the_journal();
        let w = places(&j).unwrap();
        std::fs::write(
            &w.clone_metadata,
            serde_json::to_vec(&record(OTHER)).unwrap(),
        )
        .unwrap();
        let e = roll_back_clone(&j.journal_id).unwrap_err();
        assert!(has(&e, "downgrade.rollbackConflict"), "{e:#}");
        assert!(w.clone_metadata.exists() && w.metadata_dst.exists());
        assert_eq!(the_journal().phase, P::RollbackRequired);
    }

    #[test]
    fn a_stale_partial_copy_is_discarded_and_redone() {
        let (_e, before) = seeded();
        crash_at("after:DISCOVERY_SCAN_PASSED");
        start_clone(LOCAL).unwrap_err();
        no_crash();
        let j = the_journal();
        let w = places(&j).unwrap();
        std::fs::create_dir_all(w.clone_staging.join("half")).unwrap();
        std::fs::write(w.clone_staging.join("half").join("file"), b"torn").unwrap();
        run_clone(&j.journal_id).unwrap();
        assert_cloned(&before);
    }

    // ------------------------------------------------------- readiness ----

    #[test]
    fn a_launcher_with_nothing_bound_is_ready_without_creating_a_database() {
        let _e = env();
        assert!(ready_codes().is_empty());
        assert!(!Db::path().unwrap().exists());
    }

    #[test]
    fn a_running_browser_blocks_the_downgrade() {
        let _e = env();
        crate::process::Tracker::shared().set_running_for_test("another-profile", true);
        let r = readiness().unwrap();
        assert!(!r.ready);
        assert!(r
            .blockers
            .iter()
            .any(|b| b.code == "downgrade.blockRunning" && b.count >= 1));
        crate::process::Tracker::shared().set_running_for_test("another-profile", false);
    }

    fn restore_journal(local: &str) -> journal::RestoreJournal {
        journal::RestoreJournal {
            local_profile_id: local.into(),
            journal_id: "restore-1".into(),
            phase: journal::RestorePhase::Created,
            staged_path: "s".into(),
            backup_path: "b".into(),
            old_binding_json: "{}".into(),
            target_version: 0,
            target_head_hash: [1; 32],
        }
    }

    #[test]
    fn each_open_fact_blocks_the_downgrade_by_name() {
        let (_e, _) = seeded();
        start_clone(LOCAL).unwrap();
        assert!(ready_codes().is_empty());
        let db = Db::open().unwrap();
        let blocked = |key: &str| ready_codes().contains(&key);
        // A lease.
        db.conn
            .execute(
                "UPDATE profile_bindings SET lease_id = 'aa', fencing_token = 1",
                [],
            )
            .unwrap();
        assert!(blocked("downgrade.blockLease"));
        db.conn
            .execute(
                "UPDATE profile_bindings SET lease_id = NULL, fencing_token = NULL",
                [],
            )
            .unwrap();
        assert!(!blocked("downgrade.blockLease"));
        // Non-terminal operations count; terminal ones do not.
        for state in ["PENDING", "RUNNING", "AWAITING_RETRY"] {
            insert_op(&db, "op", "PUBLISH", state);
            assert!(blocked("downgrade.blockOperation"), "{state}");
            db.conn.execute("DELETE FROM operations", []).unwrap();
        }
        for state in ["FAILED", "QUARANTINED"] {
            insert_op(&db, "op", "PUBLISH", state);
            assert!(!blocked("downgrade.blockOperation"), "{state}");
            db.conn.execute("DELETE FROM operations", []).unwrap();
        }
        // Uploads likewise.
        for state in ["OPEN", "FINALIZING"] {
            insert_upload(&db, state);
            assert!(blocked("downgrade.blockOperation"), "{state}");
            db.conn.execute("DELETE FROM upload_sessions", []).unwrap();
            db.conn.execute("DELETE FROM operations", []).unwrap();
        }
        insert_upload(&db, "ABORTED");
        assert!(!blocked("downgrade.blockOperation"));
        db.conn.execute("DELETE FROM upload_sessions", []).unwrap();
        db.conn.execute("DELETE FROM operations", []).unwrap();
        // An encrypted spool file.
        let spool = store::config_root()
            .unwrap()
            .join("team-sync")
            .join("spool");
        std::fs::create_dir_all(&spool).unwrap();
        assert!(!blocked("downgrade.blockSpool"));
        std::fs::write(spool.join("x.part"), b"c").unwrap();
        assert!(blocked("downgrade.blockSpool"));
        std::fs::remove_file(spool.join("x.part")).unwrap();
        assert!(!blocked("downgrade.blockSpool"));
        // A restore journal, even a finished one, until it is retired.
        seed(OTHER, false);
        bind(OTHER);
        journal::restore_create(&db, &restore_journal(OTHER)).unwrap();
        assert!(blocked("downgrade.blockRestoreJournal"));
        assert!(blocked("downgrade.blockUnfinishedBinding"));
        for p in [
            journal::RestorePhase::RollbackRequired,
            journal::RestorePhase::RolledBack,
        ] {
            journal::restore_advance(&db, OTHER, p).unwrap();
        }
        assert!(blocked("downgrade.blockRestoreJournal"));
        journal::restore_retire(&db, OTHER).unwrap();
        assert!(!blocked("downgrade.blockRestoreJournal"));
        // A binding that finished no flow blocks until it is unbound.
        assert!(blocked("downgrade.blockUnfinishedBinding"));
        unbind_profile(OTHER, SERVER, 1_800_000_000_000).unwrap();
        assert!(ready_codes().is_empty(), "{:?}", ready_codes());
    }

    #[test]
    fn an_unfinished_downgrade_journal_blocks_until_it_completes_or_rolls_back() {
        let (_e, _) = seeded();
        crash_at("after:CLAIMED");
        start_clone(LOCAL).unwrap_err();
        no_crash();
        assert!(ready_codes().contains(&"downgrade.blockDowngradeJournal"));
        let id = the_journal().journal_id;
        roll_back_clone(&id).unwrap();
        assert!(!ready_codes().contains(&"downgrade.blockDowngradeJournal"));
        assert!(ready_codes().contains(&"downgrade.blockUnfinishedBinding"));
    }

    #[test]
    fn an_unbind_on_top_of_a_clone_or_a_second_clone_is_a_mixed_flow() {
        let (_e, _) = seeded();
        start_clone(LOCAL).unwrap();
        assert!(ready_codes().is_empty());
        // A second completed journal for the same profile.
        let db = Db::open().unwrap();
        db.conn
            .execute(
                "INSERT INTO downgrade_journals SELECT 'second', mode, original_local_profile_id,
                   'other-new', phase, original_metadata_archive_path,
                   original_user_data_archive_path, pre_v2_manifest_sha256,
                   discovery_readback_sha256, created_at, updated_at FROM downgrade_journals",
                [],
            )
            .unwrap();
        assert!(ready_codes().contains(&"downgrade.blockMixedFlows"));
        db.conn
            .execute(
                "DELETE FROM downgrade_journals WHERE journal_id = 'second'",
                [],
            )
            .unwrap();
        assert!(ready_codes().is_empty());
        // The binding unbound after the clone: the clone's flow plus an unbind.
        super::super::sync::unbind(LOCAL, SERVER, 1_800_000_000_000).unwrap();
        assert!(
            ready_codes().contains(&"downgrade.blockMixedFlows"),
            "{:?}",
            ready_codes()
        );
    }

    #[test]
    fn a_finished_clone_that_no_longer_reads_back_blocks_by_name() {
        for damage in [
            "archived record",
            "archived data",
            "clone record",
            "digest",
            "old id back",
        ] {
            let (_e, _) = seeded();
            start_clone(LOCAL).unwrap();
            assert!(ready_codes().is_empty(), "{damage}");
            let j = the_journal();
            let w = places(&j).unwrap();
            match damage {
                "archived record" => std::fs::remove_file(&w.metadata_dst).unwrap(),
                "archived data" => std::fs::remove_dir_all(&w.data_dst).unwrap(),
                "clone record" => std::fs::remove_file(&w.clone_metadata).unwrap(),
                "digest" => {
                    Db::open()
                        .unwrap()
                        .conn
                        .execute(
                            "UPDATE downgrade_journals SET discovery_readback_sha256 = zeroblob(32)",
                            [],
                        )
                        .unwrap();
                }
                _ => std::fs::write(&w.metadata_src, b"{}").unwrap(),
            }
            assert_eq!(ready_codes(), ["downgrade.blockCloneEvidence"], "{damage}");
        }
    }

    // ---------------------------------------------------------- unbind ----

    #[test]
    fn an_explicit_unbind_finishes_the_binding_and_leaves_the_profile_local() {
        let (_e, _) = seeded();
        let done = unbind_profile(LOCAL, SERVER, 1_800_000_000_000).unwrap();
        assert_eq!(done.local_profile_id, LOCAL);
        assert_eq!(done.response_sha256.len(), 64);
        assert!(done.discoverable);
        assert!(!super::super::sync::is_published(LOCAL).unwrap());
        assert!(ready_codes().is_empty());
        // A retry answers with the stored response.
        let again = unbind_profile(LOCAL, SERVER, 1_800_000_999_999).unwrap();
        assert_eq!(again.response_sha256, done.response_sha256);
    }

    #[test]
    fn an_unbind_is_refused_inside_another_flow_a_lease_or_a_running_browser() {
        let (_e, _) = seeded();
        crate::process::Tracker::shared().set_running_for_test(LOCAL, true);
        let e = unbind_profile(LOCAL, SERVER, 1).unwrap_err();
        assert!(has(&e, "profile.stopRunningBrowser"), "{e:#}");
        crate::process::Tracker::shared().set_running_for_test(LOCAL, false);
        let db = Db::open().unwrap();
        db.conn
            .execute(
                "UPDATE profile_bindings SET lease_id = ?1, fencing_token = 1",
                [&"aa".repeat(16)],
            )
            .unwrap();
        let e = unbind_profile(LOCAL, SERVER, 1).unwrap_err();
        assert!(has(&e, "sync.unbindLeaseHeld"), "{e:#}");
        db.conn
            .execute(
                "UPDATE profile_bindings SET lease_id = NULL, fencing_token = NULL",
                [],
            )
            .unwrap();
        crash_at("after:CLAIMED");
        start_clone(LOCAL).unwrap_err();
        no_crash();
        let e = unbind_profile(LOCAL, SERVER, 1).unwrap_err();
        assert!(has(&e, "downgrade.flowTaken"), "{e:#}");
        assert!(super::super::sync::is_published(LOCAL).unwrap());
        let e = unbind_profile("a/b", SERVER, 1).unwrap_err();
        assert!(has(&e, "profile.invalidId"), "{e:#}");
        let e = unbind_profile(OTHER, SERVER, 1).unwrap_err();
        assert!(has(&e, "sync.unbindNotBound"), "{e:#}");
    }

    // ---------------------------------------------------------- resume ----

    fn pre_v2(local: &str) -> DowngradeJournal {
        DowngradeJournal {
            journal_id: "pre-v2".into(),
            mode: Mode::PreV2Restore,
            original_local_profile_id: local.into(),
            new_local_profile_id: None,
            phase: P::Created,
            original_metadata_archive_path: None,
            original_user_data_archive_path: None,
            pre_v2_manifest_sha256: None,
            discovery_readback_sha256: None,
        }
    }

    #[test]
    fn a_start_finishes_every_open_clone_and_reports_a_pre_v2_journal() {
        let _e = env();
        assert!(resume_open().unwrap().is_empty());
        let before = seed(LOCAL, true);
        bind(LOCAL);
        seed(OTHER, false);
        bind(OTHER);
        crash_at("after:ORIGINAL_USER_DATA_MOVED");
        start_clone(LOCAL).unwrap_err();
        no_crash();
        journal::downgrade_create(&Db::open().unwrap(), &pre_v2(OTHER)).unwrap();
        let resumed = resume_open().unwrap();
        assert_eq!(resumed.len(), 2);
        let clone = resumed
            .iter()
            .find(|r| r.original_local_profile_id == LOCAL)
            .unwrap();
        assert_eq!(
            (clone.phase.as_str(), clone.error.as_deref()),
            ("COMPLETED", None)
        );
        let other = resumed
            .iter()
            .find(|r| r.original_local_profile_id == OTHER)
            .unwrap();
        assert!(has_code(
            other.error.as_deref().unwrap(),
            "downgrade.preV2Unsupported"
        ));
        assert_eq!(other.phase, "CREATED");
        assert_cloned(&before);
        let still = journal::downgrade_get(&Db::open().unwrap(), "pre-v2")
            .unwrap()
            .unwrap();
        assert_eq!(still.phase, P::Created);
    }

    #[test]
    fn a_pre_v2_journal_never_runs_as_a_clone() {
        let _e = env();
        seed(LOCAL, false);
        bind(LOCAL);
        journal::downgrade_create(&Db::open().unwrap(), &pre_v2(LOCAL)).unwrap();
        let e = run_clone("pre-v2").unwrap_err();
        assert!(has(&e, "downgrade.notClone"), "{e:#}");
        let e = run_clone("missing").unwrap_err();
        assert!(has(&e, "journal.notFound"), "{e:#}");
        assert!(ready_codes().contains(&"downgrade.blockDowngradeJournal"));
    }
}
