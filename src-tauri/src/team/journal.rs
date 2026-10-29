//! The restore and downgrade journals of `team-sync.db` (plan DDL L1933-L1962,
//! probe 9 at L2044, 12.3 at L2235).
//!
//! A journal row is written before the path mutation it describes, in one
//! transaction that reads the row back and compares it with what was meant to
//! be stored. A phase moves only along the chain its mode allows, in one
//! transaction that checks the phase it leaves, so a replayed or reordered
//! step cannot skip one. A phase this binary does not know fails closed.
//!
//! The two flows never share a journal: a profile with a restore journal, or
//! with a downgrade journal that has not been rolled back, takes no second
//! flow (L2240: "do not mix steps between flows").

use anyhow::{anyhow, bail, Result};
use rusqlite::{params, OptionalExtension, Row, Transaction, TransactionBehavior};

use super::db::Db;
use crate::errcode::{code, code_with};

const NOW: &str = "strftime('%Y-%m-%dT%H:%M:%fZ', 'now')";

macro_rules! phases {
    ($(#[$meta:meta])* $name:ident { $($variant:ident = $text:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum $name { $($variant),+ }

        impl $name {
            pub fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $text),+ }
            }

            /// A phase this binary does not know is a newer journal's
            /// (L2235): refused, not skipped.
            pub fn parse(text: &str) -> Result<Self> {
                match text {
                    $($text => Ok(Self::$variant),)+
                    _ => Err(anyhow!(code_with("journal.unknownPhase", &[("phase", text)]))),
                }
            }
        }
    };
}

phases! {
    /// `restore_journals.phase`.
    RestorePhase {
        Created = "CREATED",
        Downloading = "DOWNLOADING",
        Verified = "VERIFIED",
        Extracting = "EXTRACTING",
        Validated = "VALIDATED",
        Resealed = "RESEALED",
        SwapStarted = "SWAP_STARTED",
        Swapped = "SWAPPED",
        SmokePassed = "SMOKE_PASSED",
        RollbackRequired = "ROLLBACK_REQUIRED",
        RolledBack = "ROLLED_BACK",
        Completed = "COMPLETED",
    }
}

phases! {
    /// `downgrade_journals.phase`.
    DowngradePhase {
        Created = "CREATED",
        Claimed = "CLAIMED",
        OriginalMetadataMoved = "ORIGINAL_METADATA_MOVED",
        OriginalUserDataMoved = "ORIGINAL_USER_DATA_MOVED",
        DiscoveryScanPassed = "DISCOVERY_SCAN_PASSED",
        CloneWritten = "CLONE_WRITTEN",
        PreV2SetRestored = "PRE_V2_SET_RESTORED",
        TeamArtifactsRetired = "TEAM_ARTIFACTS_RETIRED",
        ReadbackPassed = "READBACK_PASSED",
        Completed = "COMPLETED",
        RollbackRequired = "ROLLBACK_REQUIRED",
        RolledBack = "ROLLED_BACK",
    }
}

phases! {
    /// `downgrade_journals.mode`.
    Mode {
        Clone = "CLONE",
        PreV2Restore = "PRE_V2_RESTORE",
    }
}

/// What a crash leaves for the next start to do with a journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resume {
    /// Nothing outside the staging area was touched: delete the staging and
    /// mark the journal rolled back.
    Abort,
    /// The destination may be half replaced: restore it from the backup.
    Rollback,
    /// Run the next step again; every step is safe to repeat.
    Continue,
    /// Terminal: nothing to do.
    Settled,
}

const RESTORE_FORWARD: [RestorePhase; 10] = [
    RestorePhase::Created,
    RestorePhase::Downloading,
    RestorePhase::Verified,
    RestorePhase::Extracting,
    RestorePhase::Validated,
    RestorePhase::Resealed,
    RestorePhase::SwapStarted,
    RestorePhase::Swapped,
    RestorePhase::SmokePassed,
    RestorePhase::Completed,
];

impl RestorePhase {
    /// Whether the journal may move from `self` to `to`: the next phase of the
    /// chain, or `ROLLBACK_REQUIRED` from any open phase, then `ROLLED_BACK`.
    pub fn allows(self, to: Self) -> bool {
        match (self, to) {
            (Self::RollbackRequired, Self::RolledBack) => true,
            (Self::Completed | Self::RolledBack | Self::RollbackRequired, _) => false,
            (_, Self::RollbackRequired) => true,
            _ => {
                let at = RESTORE_FORWARD.iter().position(|p| *p == self);
                at.and_then(|i| RESTORE_FORWARD.get(i + 1)) == Some(&to)
            }
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::RolledBack)
    }

    /// What the next start does with a journal left at this phase.
    pub fn resume(self) -> Resume {
        match self {
            Self::Created
            | Self::Downloading
            | Self::Verified
            | Self::Extracting
            | Self::Validated
            | Self::Resealed => Resume::Abort,
            Self::SwapStarted | Self::RollbackRequired => Resume::Rollback,
            Self::Swapped | Self::SmokePassed => Resume::Continue,
            Self::Completed | Self::RolledBack => Resume::Settled,
        }
    }
}

const CLONE_CHAIN: [DowngradePhase; 8] = [
    DowngradePhase::Created,
    DowngradePhase::Claimed,
    DowngradePhase::OriginalMetadataMoved,
    DowngradePhase::OriginalUserDataMoved,
    DowngradePhase::DiscoveryScanPassed,
    DowngradePhase::CloneWritten,
    DowngradePhase::ReadbackPassed,
    DowngradePhase::Completed,
];

const PRE_V2_CHAIN: [DowngradePhase; 6] = [
    DowngradePhase::Created,
    DowngradePhase::Claimed,
    DowngradePhase::PreV2SetRestored,
    DowngradePhase::TeamArtifactsRetired,
    DowngradePhase::ReadbackPassed,
    DowngradePhase::Completed,
];

impl DowngradePhase {
    /// As [`RestorePhase::allows`], on the chain of `mode`: a phase of the
    /// other flow is never next.
    pub fn allows(self, mode: Mode, to: Self) -> bool {
        match (self, to) {
            (Self::RollbackRequired, Self::RolledBack) => true,
            (Self::Completed | Self::RolledBack | Self::RollbackRequired, _) => false,
            (_, Self::RollbackRequired) => true,
            _ => {
                let chain: &[Self] = match mode {
                    Mode::Clone => &CLONE_CHAIN,
                    Mode::PreV2Restore => &PRE_V2_CHAIN,
                };
                let at = chain.iter().position(|p| *p == self);
                at.and_then(|i| chain.get(i + 1)) == Some(&to)
            }
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::RolledBack)
    }

    /// What the next start does with a clone journal left at this phase. The
    /// original is safe in the archive from the first move on and nothing
    /// before it is lost, so every open phase continues; only a journal that
    /// asked for rollback is rolled back.
    pub fn resume(self) -> Resume {
        match self {
            Self::RollbackRequired => Resume::Rollback,
            Self::Completed | Self::RolledBack => Resume::Settled,
            _ => Resume::Continue,
        }
    }
}

/// A `restore_journals` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreJournal {
    pub local_profile_id: String,
    pub journal_id: String,
    pub phase: RestorePhase,
    pub staged_path: String,
    pub backup_path: String,
    pub old_binding_json: String,
    /// 0..=`i64::MAX`.
    pub target_version: u64,
    pub target_head_hash: [u8; 32],
}

/// A `downgrade_journals` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DowngradeJournal {
    pub journal_id: String,
    pub mode: Mode,
    pub original_local_profile_id: String,
    pub new_local_profile_id: Option<String>,
    pub phase: DowngradePhase,
    pub original_metadata_archive_path: Option<String>,
    pub original_user_data_archive_path: Option<String>,
    pub pre_v2_manifest_sha256: Option<[u8; 32]>,
    pub discovery_readback_sha256: Option<[u8; 32]>,
}

/// What a step may set on a downgrade journal when it advances the phase.
#[derive(Clone, Copy, Default)]
pub struct Patch {
    pub pre_v2_manifest_sha256: Option<[u8; 32]>,
    pub discovery_readback_sha256: Option<[u8; 32]>,
}

fn unreadable() -> anyhow::Error {
    anyhow!(code("team.trustLedgerUnreadable"))
}

fn mismatch(field: &str) -> anyhow::Error {
    anyhow!(code_with("journal.readbackMismatch", &[("field", field)]))
}

fn txn(db: &Db) -> Result<Transaction<'_>> {
    Ok(Transaction::new_unchecked(
        &db.conn,
        TransactionBehavior::Immediate,
    )?)
}

fn digest(value: Option<Vec<u8>>) -> Result<Option<[u8; 32]>> {
    value
        .map(|bytes| bytes.try_into().map_err(|_| unreadable()))
        .transpose()
}

// ------------------------------------------------------------- restore ----

const RESTORE_COLUMNS: &str = "local_profile_id, journal_id, phase, staged_path, backup_path,
  old_binding_json, target_version, target_head_hash";

fn restore_row(r: &Row<'_>) -> Result<RestoreJournal> {
    let version: i64 = r.get(6)?;
    let hash: Vec<u8> = r.get(7)?;
    Ok(RestoreJournal {
        local_profile_id: r.get(0)?,
        journal_id: r.get(1)?,
        phase: RestorePhase::parse(&r.get::<_, String>(2)?)?,
        staged_path: r.get(3)?,
        backup_path: r.get(4)?,
        old_binding_json: r.get(5)?,
        target_version: u64::try_from(version).map_err(|_| unreadable())?,
        target_head_hash: hash.try_into().map_err(|_| unreadable())?,
    })
}

fn restore_in(tx: &Transaction<'_>, local: &str) -> Result<Option<RestoreJournal>> {
    tx.query_row(
        &format!("SELECT {RESTORE_COLUMNS} FROM restore_journals WHERE local_profile_id = ?1"),
        [local],
        |r| Ok(restore_row(r)),
    )
    .optional()?
    .transpose()
}

pub fn restore_get(db: &Db, local: &str) -> Result<Option<RestoreJournal>> {
    restore_in(&txn(db)?, local)
}

/// Every restore journal that is not terminal, oldest first.
pub fn restore_open(db: &Db) -> Result<Vec<RestoreJournal>> {
    let mut stmt = db.conn.prepare(&format!(
        "SELECT {RESTORE_COLUMNS} FROM restore_journals ORDER BY created_at, rowid"
    ))?;
    let rows = stmt.query_map([], |r| Ok(restore_row(r)))?;
    let mut open = Vec::new();
    for row in rows {
        let journal = row??;
        if !journal.phase.is_terminal() {
            open.push(journal);
        }
    }
    Ok(open)
}

/// Writes a new journal at `CREATED` and reads it back. The profile must be
/// bound (the table's foreign key) and take no other flow.
pub fn restore_create(db: &Db, journal: &RestoreJournal) -> Result<()> {
    if journal.phase != RestorePhase::Created {
        bail!(code_with(
            "journal.badTransition",
            &[("from", "-"), ("to", journal.phase.as_str())]
        ));
    }
    let version = i64::try_from(journal.target_version).map_err(|_| {
        anyhow!(code_with(
            "journal.outOfRange",
            &[("field", "target_version")]
        ))
    })?;
    let tx = txn(db)?;
    refuse_second_flow(&tx, &journal.local_profile_id)?;
    tx.execute(
        &format!(
            "INSERT INTO restore_journals({RESTORE_COLUMNS}, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, {NOW}, {NOW})"
        ),
        params![
            journal.local_profile_id,
            journal.journal_id,
            journal.phase.as_str(),
            journal.staged_path,
            journal.backup_path,
            journal.old_binding_json,
            version,
            journal.target_head_hash.to_vec()
        ],
    )?;
    let stored = restore_in(&tx, &journal.local_profile_id)?.ok_or_else(|| mismatch("row"))?;
    if &stored != journal {
        bail!(mismatch("journal"));
    }
    tx.commit()?;
    Ok(())
}

/// Moves the journal of `local` to `to`, if its stored phase may move there.
pub fn restore_advance(db: &Db, local: &str, to: RestorePhase) -> Result<RestoreJournal> {
    let tx = txn(db)?;
    let current = restore_in(&tx, local)?.ok_or_else(|| anyhow!(code("journal.notFound")))?;
    if !current.phase.allows(to) {
        bail!(code_with(
            "journal.badTransition",
            &[("from", current.phase.as_str()), ("to", to.as_str())]
        ));
    }
    tx.execute(
        &format!(
            "UPDATE restore_journals SET phase = ?2, updated_at = {NOW}
             WHERE local_profile_id = ?1 AND phase = ?3"
        ),
        params![local, to.as_str(), current.phase.as_str()],
    )?;
    let stored = restore_in(&tx, local)?.ok_or_else(|| mismatch("row"))?;
    if stored.phase != to
        || stored
            != (RestoreJournal {
                phase: to,
                ..current
            })
    {
        bail!(mismatch("phase"));
    }
    tx.commit()?;
    Ok(stored)
}

/// Deletes a journal that reached `COMPLETED` or `ROLLED_BACK` (probe 9:
/// retired before the profile is unbound). An open one is never deleted.
pub fn restore_retire(db: &Db, local: &str) -> Result<()> {
    let tx = txn(db)?;
    let current = restore_in(&tx, local)?.ok_or_else(|| anyhow!(code("journal.notFound")))?;
    if !current.phase.is_terminal() {
        bail!(code_with(
            "journal.notSettled",
            &[("phase", current.phase.as_str())]
        ));
    }
    tx.execute(
        "DELETE FROM restore_journals WHERE local_profile_id = ?1",
        [local],
    )?;
    if restore_in(&tx, local)?.is_some() {
        bail!(mismatch("row"));
    }
    tx.commit()?;
    Ok(())
}

// ----------------------------------------------------------- downgrade ----

const DOWNGRADE_COLUMNS: &str = "journal_id, mode, original_local_profile_id,
  new_local_profile_id, phase, original_metadata_archive_path,
  original_user_data_archive_path, pre_v2_manifest_sha256, discovery_readback_sha256";

fn downgrade_row(r: &Row<'_>) -> Result<DowngradeJournal> {
    Ok(DowngradeJournal {
        journal_id: r.get(0)?,
        mode: Mode::parse(&r.get::<_, String>(1)?)?,
        original_local_profile_id: r.get(2)?,
        new_local_profile_id: r.get(3)?,
        phase: DowngradePhase::parse(&r.get::<_, String>(4)?)?,
        original_metadata_archive_path: r.get(5)?,
        original_user_data_archive_path: r.get(6)?,
        pre_v2_manifest_sha256: digest(r.get(7)?)?,
        discovery_readback_sha256: digest(r.get(8)?)?,
    })
}

fn downgrade_in(tx: &Transaction<'_>, id: &str) -> Result<Option<DowngradeJournal>> {
    tx.query_row(
        &format!("SELECT {DOWNGRADE_COLUMNS} FROM downgrade_journals WHERE journal_id = ?1"),
        [id],
        |r| Ok(downgrade_row(r)),
    )
    .optional()?
    .transpose()
}

pub fn downgrade_get(db: &Db, id: &str) -> Result<Option<DowngradeJournal>> {
    downgrade_in(&txn(db)?, id)
}

/// Every downgrade journal of the profile `original`, oldest first.
pub fn downgrade_for(db: &Db, original: &str) -> Result<Vec<DowngradeJournal>> {
    let mut stmt = db.conn.prepare(&format!(
        "SELECT {DOWNGRADE_COLUMNS} FROM downgrade_journals
         WHERE original_local_profile_id = ?1 ORDER BY created_at, rowid"
    ))?;
    let rows = stmt.query_map([original], |r| Ok(downgrade_row(r)))?;
    rows.map(|row| row?).collect()
}

/// Every downgrade journal that is not terminal, oldest first.
pub fn downgrade_open(db: &Db) -> Result<Vec<DowngradeJournal>> {
    let mut stmt = db.conn.prepare(&format!(
        "SELECT {DOWNGRADE_COLUMNS} FROM downgrade_journals ORDER BY created_at, rowid"
    ))?;
    let rows = stmt.query_map([], |r| Ok(downgrade_row(r)))?;
    let mut open = Vec::new();
    for row in rows {
        let journal = row??;
        if !journal.phase.is_terminal() {
            open.push(journal);
        }
    }
    Ok(open)
}

/// What each phase needs stored before the journal may enter it.
fn requires(journal: &DowngradeJournal) -> Result<()> {
    use DowngradePhase as P;
    let (metadata, data) = (
        journal.original_metadata_archive_path.is_some(),
        journal.original_user_data_archive_path.is_some(),
    );
    let ok = match (journal.mode, journal.phase) {
        (_, P::OriginalMetadataMoved) => metadata,
        (_, P::OriginalUserDataMoved | P::DiscoveryScanPassed) => metadata && data,
        (_, P::CloneWritten) => metadata && data && journal.new_local_profile_id.is_some(),
        (Mode::Clone, P::ReadbackPassed | P::Completed) => {
            journal.new_local_profile_id.is_some() && journal.discovery_readback_sha256.is_some()
        }
        (_, P::PreV2SetRestored | P::TeamArtifactsRetired) => {
            journal.pre_v2_manifest_sha256.is_some()
        }
        (Mode::PreV2Restore, P::ReadbackPassed | P::Completed) => {
            journal.pre_v2_manifest_sha256.is_some() && journal.discovery_readback_sha256.is_some()
        }
        _ => true,
    };
    if !ok {
        bail!(code_with(
            "journal.missingField",
            &[("phase", journal.phase.as_str())]
        ));
    }
    Ok(())
}

/// A profile takes one flow: no restore journal, and no downgrade journal that
/// is not rolled back. A rolled-back one leaves the profile free to start over.
fn refuse_second_flow(tx: &Transaction<'_>, local: &str) -> Result<()> {
    if flow_taken_in(tx, local)? {
        bail!(code("journal.flowTaken"));
    }
    Ok(())
}

fn flow_taken_in(tx: &Transaction<'_>, local: &str) -> Result<bool> {
    Ok(tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM restore_journals WHERE local_profile_id = ?1)
           OR EXISTS (SELECT 1 FROM downgrade_journals
                      WHERE original_local_profile_id = ?1 AND phase <> 'ROLLED_BACK')",
        [local],
        |r| r.get(0),
    )?)
}

/// Whether `local` has a restore journal, or a downgrade journal that was not
/// rolled back: a profile in a flow takes no other.
pub fn flow_taken(db: &Db, local: &str) -> Result<bool> {
    flow_taken_in(&txn(db)?, local)
}

/// Every downgrade journal at `phase`, oldest first.
pub fn downgrade_for_phase(db: &Db, phase: DowngradePhase) -> Result<Vec<DowngradeJournal>> {
    let mut stmt = db.conn.prepare(&format!(
        "SELECT {DOWNGRADE_COLUMNS} FROM downgrade_journals WHERE phase = ?1
         ORDER BY created_at, rowid"
    ))?;
    let rows = stmt.query_map([phase.as_str()], |r| Ok(downgrade_row(r)))?;
    rows.map(|row| row?).collect()
}

/// Writes a new downgrade journal at `CREATED`, naming everything the flow
/// will move, and reads it back. The profile must be bound.
pub fn downgrade_create(db: &Db, journal: &DowngradeJournal) -> Result<()> {
    if journal.phase != DowngradePhase::Created {
        bail!(code_with(
            "journal.badTransition",
            &[("from", "-"), ("to", journal.phase.as_str())]
        ));
    }
    let tx = txn(db)?;
    let bound: bool = tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM profile_bindings WHERE local_profile_id = ?1)",
        [&journal.original_local_profile_id],
        |r| r.get(0),
    )?;
    if !bound {
        bail!(code("journal.notBound"));
    }
    refuse_second_flow(&tx, &journal.original_local_profile_id)?;
    tx.execute(
        &format!(
            "INSERT INTO downgrade_journals({DOWNGRADE_COLUMNS}, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, {NOW}, {NOW})"
        ),
        params![
            journal.journal_id,
            journal.mode.as_str(),
            journal.original_local_profile_id,
            journal.new_local_profile_id,
            journal.phase.as_str(),
            journal.original_metadata_archive_path,
            journal.original_user_data_archive_path,
            journal.pre_v2_manifest_sha256.map(|h| h.to_vec()),
            journal.discovery_readback_sha256.map(|h| h.to_vec()),
        ],
    )?;
    let stored = downgrade_in(&tx, &journal.journal_id)?.ok_or_else(|| mismatch("row"))?;
    if &stored != journal {
        bail!(mismatch("journal"));
    }
    tx.commit()?;
    Ok(())
}

/// Moves the journal `id` to `to` along its mode's chain, setting `patch`, and
/// reads the row back.
pub fn downgrade_advance(
    db: &Db,
    id: &str,
    to: DowngradePhase,
    patch: Patch,
) -> Result<DowngradeJournal> {
    let tx = txn(db)?;
    let current = downgrade_in(&tx, id)?.ok_or_else(|| anyhow!(code("journal.notFound")))?;
    if !current.phase.allows(current.mode, to) {
        bail!(code_with(
            "journal.badTransition",
            &[("from", current.phase.as_str()), ("to", to.as_str())]
        ));
    }
    let next = DowngradeJournal {
        phase: to,
        pre_v2_manifest_sha256: patch
            .pre_v2_manifest_sha256
            .or(current.pre_v2_manifest_sha256),
        discovery_readback_sha256: patch
            .discovery_readback_sha256
            .or(current.discovery_readback_sha256),
        ..current.clone()
    };
    requires(&next)?;
    tx.execute(
        &format!(
            "UPDATE downgrade_journals SET phase = ?2, pre_v2_manifest_sha256 = ?3,
               discovery_readback_sha256 = ?4, updated_at = {NOW}
             WHERE journal_id = ?1 AND phase = ?5"
        ),
        params![
            id,
            to.as_str(),
            next.pre_v2_manifest_sha256.map(|h| h.to_vec()),
            next.discovery_readback_sha256.map(|h| h.to_vec()),
            current.phase.as_str()
        ],
    )?;
    let stored = downgrade_in(&tx, id)?.ok_or_else(|| mismatch("row"))?;
    if stored != next {
        bail!(mismatch("phase"));
    }
    tx.commit()?;
    Ok(stored)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::team::db::Db;

    const LOCAL: &str = "local-a";

    fn db() -> (tempfile::TempDir, std::path::PathBuf, Db) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("team-sync.db");
        let db = Db::open_at(&path).unwrap();
        bind(&db, LOCAL);
        (dir, path, db)
    }

    pub(crate) fn bind(db: &Db, local: &str) {
        crate::team::db::fixtures::seed_binding(
            &db.conn,
            "s",
            local,
            &"03".repeat(16),
            &"02".repeat(16),
            &"04".repeat(16),
            &crate::fleet_client::hex(&shardx_core::canonical::sha256(local.as_bytes()))[..32],
            0,
        );
    }

    fn restore() -> RestoreJournal {
        RestoreJournal {
            local_profile_id: LOCAL.into(),
            journal_id: "r1".into(),
            phase: RestorePhase::Created,
            staged_path: "staged".into(),
            backup_path: "backup".into(),
            old_binding_json: "{}".into(),
            target_version: i64::MAX as u64,
            target_head_hash: [7; 32],
        }
    }

    fn clone_journal() -> DowngradeJournal {
        DowngradeJournal {
            journal_id: "d1".into(),
            mode: Mode::Clone,
            original_local_profile_id: LOCAL.into(),
            new_local_profile_id: Some("local-b".into()),
            phase: DowngradePhase::Created,
            original_metadata_archive_path: Some("a/meta".into()),
            original_user_data_archive_path: Some("a/data".into()),
            pre_v2_manifest_sha256: None,
            discovery_readback_sha256: None,
        }
    }

    fn pre_v2() -> DowngradeJournal {
        DowngradeJournal {
            journal_id: "d2".into(),
            mode: Mode::PreV2Restore,
            new_local_profile_id: None,
            original_metadata_archive_path: None,
            original_user_data_archive_path: None,
            ..clone_journal()
        }
    }

    fn reopen(path: &std::path::Path) -> Db {
        Db::open_at(path).unwrap()
    }

    fn err(e: anyhow::Error) -> String {
        format!("{e:#}")
    }

    #[test]
    fn every_restore_phase_survives_close_and_reopen_in_order() {
        let (_dir, path, db) = db();
        restore_create(&db, &restore()).unwrap();
        drop(db);
        let mut want = restore();
        for next in &RESTORE_FORWARD[1..] {
            let db = reopen(&path);
            assert_eq!(restore_get(&db, LOCAL).unwrap().unwrap(), want);
            want = RestoreJournal {
                phase: *next,
                ..want
            };
            assert_eq!(restore_advance(&db, LOCAL, *next).unwrap(), want);
            drop(db);
            assert_eq!(restore_get(&reopen(&path), LOCAL).unwrap().unwrap(), want);
        }
        let db = reopen(&path);
        assert!(restore_open(&db).unwrap().is_empty());
        restore_retire(&db, LOCAL).unwrap();
        assert!(restore_get(&db, LOCAL).unwrap().is_none());
    }

    #[test]
    fn a_restore_phase_cannot_skip_repeat_or_leave_a_terminal_one() {
        let (_dir, _path, db) = db();
        restore_create(&db, &restore()).unwrap();
        for skip in [
            RestorePhase::Verified,
            RestorePhase::Created,
            RestorePhase::Completed,
            RestorePhase::RolledBack,
        ] {
            let e = err(restore_advance(&db, LOCAL, skip).unwrap_err());
            assert!(e.contains("journal.badTransition"), "{skip:?}: {e}");
        }
        restore_advance(&db, LOCAL, RestorePhase::RollbackRequired).unwrap();
        let e = err(restore_advance(&db, LOCAL, RestorePhase::Downloading).unwrap_err());
        assert!(e.contains("journal.badTransition"), "{e}");
        restore_advance(&db, LOCAL, RestorePhase::RolledBack).unwrap();
        let e = err(restore_advance(&db, LOCAL, RestorePhase::RollbackRequired).unwrap_err());
        assert!(e.contains("journal.badTransition"), "{e}");
    }

    #[test]
    fn a_restore_journal_retires_only_when_settled() {
        let (_dir, _path, db) = db();
        restore_create(&db, &restore()).unwrap();
        let e = err(restore_retire(&db, LOCAL).unwrap_err());
        assert!(e.contains("journal.notSettled"), "{e}");
        assert_eq!(restore_open(&db).unwrap().len(), 1);
        restore_advance(&db, LOCAL, RestorePhase::RollbackRequired).unwrap();
        restore_advance(&db, LOCAL, RestorePhase::RolledBack).unwrap();
        restore_retire(&db, LOCAL).unwrap();
    }

    #[test]
    fn the_restore_resume_table_is_fixed_per_crash_point() {
        use RestorePhase::*;
        let table = [
            (Created, Resume::Abort),
            (Downloading, Resume::Abort),
            (Verified, Resume::Abort),
            (Extracting, Resume::Abort),
            (Validated, Resume::Abort),
            (Resealed, Resume::Abort),
            (SwapStarted, Resume::Rollback),
            (Swapped, Resume::Continue),
            (SmokePassed, Resume::Continue),
            (RollbackRequired, Resume::Rollback),
            (RolledBack, Resume::Settled),
            (Completed, Resume::Settled),
        ];
        for (phase, want) in table {
            assert_eq!(phase.resume(), want, "{phase:?}");
        }
    }

    #[test]
    fn restore_integers_hold_zero_and_max_and_refuse_beyond() {
        for version in [0u64, 1, i64::MAX as u64] {
            let (_dir, path, db) = db();
            restore_create(
                &db,
                &RestoreJournal {
                    target_version: version,
                    ..restore()
                },
            )
            .unwrap();
            drop(db);
            let got = restore_get(&reopen(&path), LOCAL).unwrap().unwrap();
            assert_eq!(got.target_version, version);
        }
        let (_dir, _path, db) = db();
        for over in [i64::MAX as u64 + 1, u64::MAX] {
            let e = err(restore_create(
                &db,
                &RestoreJournal {
                    target_version: over,
                    ..restore()
                },
            )
            .unwrap_err());
            assert!(e.contains("journal.outOfRange"), "{over}: {e}");
        }
        // The table refuses a negative the Rust side never writes.
        let e = db
            .conn
            .execute(
                "INSERT INTO restore_journals VALUES ('local-a','x','CREATED','s','b','{}',-1,
                   zeroblob(32),'t','t')",
                [],
            )
            .unwrap_err();
        assert!(e.to_string().contains("CHECK"), "{e}");
        assert!(restore_get(&db, LOCAL).unwrap().is_none());
    }

    #[test]
    fn a_restore_journal_needs_a_binding_and_no_other_flow() {
        let (_dir, _path, db) = db();
        let stranger = RestoreJournal {
            local_profile_id: "unbound".into(),
            journal_id: "r9".into(),
            ..restore()
        };
        restore_create(&db, &stranger).unwrap_err();
        downgrade_create(&db, &clone_journal()).unwrap();
        let e = err(restore_create(&db, &restore()).unwrap_err());
        assert!(e.contains("journal.flowTaken"), "{e}");
    }

    #[test]
    fn a_clone_journal_walks_its_chain_with_every_phase_surviving_reopen() {
        let (_dir, path, db) = db();
        downgrade_create(&db, &clone_journal()).unwrap();
        drop(db);
        let mut want = clone_journal();
        for next in &CLONE_CHAIN[1..] {
            let db = reopen(&path);
            assert_eq!(downgrade_get(&db, "d1").unwrap().unwrap(), want);
            let patch = Patch {
                discovery_readback_sha256: (*next == DowngradePhase::ReadbackPassed)
                    .then_some([9; 32]),
                ..Patch::default()
            };
            want = DowngradeJournal {
                phase: *next,
                discovery_readback_sha256: patch
                    .discovery_readback_sha256
                    .or(want.discovery_readback_sha256),
                ..want
            };
            assert_eq!(downgrade_advance(&db, "d1", *next, patch).unwrap(), want);
            drop(db);
            let again = downgrade_get(&reopen(&path), "d1").unwrap().unwrap();
            assert_eq!(again, want);
        }
        let db = reopen(&path);
        assert!(downgrade_open(&db).unwrap().is_empty());
        assert_eq!(downgrade_for(&db, LOCAL).unwrap(), vec![want]);
    }

    #[test]
    fn a_pre_v2_journal_walks_its_own_chain() {
        let (_dir, path, db) = db();
        downgrade_create(&db, &pre_v2()).unwrap();
        drop(db);
        for next in &PRE_V2_CHAIN[1..] {
            let db = reopen(&path);
            let patch = Patch {
                pre_v2_manifest_sha256: Some([5; 32]),
                discovery_readback_sha256: Some([6; 32]),
            };
            let got = downgrade_advance(&db, "d2", *next, patch).unwrap();
            assert_eq!(got.phase, *next);
        }
    }

    #[test]
    fn the_two_flows_never_borrow_each_others_phases() {
        let (_dir, _path, db) = db();
        downgrade_create(&db, &pre_v2()).unwrap();
        for clone_phase in [
            DowngradePhase::OriginalMetadataMoved,
            DowngradePhase::CloneWritten,
        ] {
            let e = err(downgrade_advance(&db, "d2", clone_phase, Patch::default()).unwrap_err());
            assert!(e.contains("journal.badTransition"), "{clone_phase:?}: {e}");
        }
        let (_dir, _path, db) = self::db();
        downgrade_create(&db, &clone_journal()).unwrap();
        for restore_phase in [
            DowngradePhase::PreV2SetRestored,
            DowngradePhase::TeamArtifactsRetired,
        ] {
            let e = err(downgrade_advance(&db, "d1", restore_phase, Patch::default()).unwrap_err());
            assert!(
                e.contains("journal.badTransition"),
                "{restore_phase:?}: {e}"
            );
        }
    }

    #[test]
    fn a_downgrade_phase_cannot_skip_and_a_rollback_is_always_open() {
        let (_dir, _path, db) = db();
        downgrade_create(&db, &clone_journal()).unwrap();
        for skip in [
            DowngradePhase::OriginalMetadataMoved,
            DowngradePhase::Completed,
            DowngradePhase::Created,
        ] {
            let e = err(downgrade_advance(&db, "d1", skip, Patch::default()).unwrap_err());
            assert!(e.contains("journal.badTransition"), "{skip:?}: {e}");
        }
        for phase in &CLONE_CHAIN[1..CLONE_CHAIN.len() - 1] {
            let (_dir, _path, db) = self::db();
            downgrade_create(&db, &clone_journal()).unwrap();
            for step in &CLONE_CHAIN[1..] {
                if step == phase {
                    break;
                }
                let patch = Patch {
                    discovery_readback_sha256: Some([1; 32]),
                    ..Patch::default()
                };
                downgrade_advance(&db, "d1", *step, patch).unwrap();
            }
            downgrade_advance(&db, "d1", *phase, Patch::default()).unwrap();
            downgrade_advance(
                &db,
                "d1",
                DowngradePhase::RollbackRequired,
                Patch::default(),
            )
            .unwrap();
            downgrade_advance(&db, "d1", DowngradePhase::RolledBack, Patch::default()).unwrap();
        }
    }

    #[test]
    fn a_phase_is_refused_until_the_fields_it_needs_are_stored() {
        let (_dir, _path, db) = db();
        let bare = DowngradeJournal {
            original_metadata_archive_path: None,
            original_user_data_archive_path: None,
            new_local_profile_id: None,
            ..clone_journal()
        };
        downgrade_create(&db, &bare).unwrap();
        downgrade_advance(&db, "d1", DowngradePhase::Claimed, Patch::default()).unwrap();
        let e = err(downgrade_advance(
            &db,
            "d1",
            DowngradePhase::OriginalMetadataMoved,
            Patch::default(),
        )
        .unwrap_err());
        assert!(e.contains("journal.missingField"), "{e}");
        let (_dir, _path, db) = self::db();
        downgrade_create(&db, &clone_journal()).unwrap();
        for step in &CLONE_CHAIN[1..6] {
            downgrade_advance(&db, "d1", *step, Patch::default()).unwrap();
        }
        let e = err(
            downgrade_advance(&db, "d1", DowngradePhase::ReadbackPassed, Patch::default())
                .unwrap_err(),
        );
        assert!(e.contains("journal.missingField"), "{e}");
    }

    #[test]
    fn a_profile_takes_one_flow_until_it_is_rolled_back() {
        let (_dir, _path, db) = db();
        downgrade_create(&db, &clone_journal()).unwrap();
        let second = DowngradeJournal {
            journal_id: "d3".into(),
            ..clone_journal()
        };
        let e = err(downgrade_create(&db, &second).unwrap_err());
        assert!(e.contains("journal.flowTaken"), "{e}");
        let e = err(downgrade_create(&db, &pre_v2()).unwrap_err());
        assert!(e.contains("journal.flowTaken"), "{e}");
        downgrade_advance(
            &db,
            "d1",
            DowngradePhase::RollbackRequired,
            Patch::default(),
        )
        .unwrap();
        downgrade_advance(&db, "d1", DowngradePhase::RolledBack, Patch::default()).unwrap();
        downgrade_create(&db, &second).unwrap();
        let unbound = DowngradeJournal {
            journal_id: "d4".into(),
            original_local_profile_id: "nobody".into(),
            ..clone_journal()
        };
        let e = err(downgrade_create(&db, &unbound).unwrap_err());
        assert!(e.contains("journal.notBound"), "{e}");
    }

    #[test]
    fn the_new_id_must_differ_from_the_original() {
        let (_dir, _path, db) = db();
        let same = DowngradeJournal {
            new_local_profile_id: Some(LOCAL.into()),
            ..clone_journal()
        };
        let e = err(downgrade_create(&db, &same).unwrap_err());
        assert!(e.contains("CHECK"), "{e}");
        assert!(downgrade_for(&db, LOCAL).unwrap().is_empty());
    }

    #[test]
    fn an_unknown_phase_or_mode_fails_closed_without_a_change() {
        let (_dir, path, db) = db();
        downgrade_create(&db, &clone_journal()).unwrap();
        restore_create(&db, &restore()).unwrap_err();
        // A newer binary's phase: the CHECK is bypassed to stand in for it.
        db.conn
            .execute_batch(
                "PRAGMA ignore_check_constraints = ON;
                 UPDATE downgrade_journals SET phase = 'FUTURE_PHASE';",
            )
            .unwrap();
        drop(db);
        let db = reopen(&path);
        for e in [
            err(downgrade_get(&db, "d1").unwrap_err()),
            err(downgrade_open(&db).unwrap_err()),
            err(
                downgrade_advance(&db, "d1", DowngradePhase::Claimed, Patch::default())
                    .unwrap_err(),
            ),
        ] {
            assert!(e.contains("journal.unknownPhase"), "{e}");
        }
        let phase: String = db
            .conn
            .query_row("SELECT phase FROM downgrade_journals", [], |r| r.get(0))
            .unwrap();
        assert_eq!(phase, "FUTURE_PHASE");
        assert!(DowngradePhase::parse("future").is_err());
        assert!(RestorePhase::parse("").is_err());
        assert!(Mode::parse("clone").is_err());
    }

    /// A trigger stands in for any fault that stores something other than what
    /// was written: the write must notice on its read back and roll back.
    #[test]
    fn a_write_that_does_not_read_back_as_written_is_rolled_back() {
        let (_dir, _path, db) = db();
        db.conn
            .execute_batch(
                "CREATE TRIGGER skew_down AFTER INSERT ON downgrade_journals BEGIN
                   UPDATE downgrade_journals SET original_user_data_archive_path = 'elsewhere'
                   WHERE journal_id = NEW.journal_id; END;
                 CREATE TRIGGER skew_restore AFTER INSERT ON restore_journals BEGIN
                   UPDATE restore_journals SET backup_path = 'elsewhere'
                   WHERE journal_id = NEW.journal_id; END;",
            )
            .unwrap();
        let e = err(downgrade_create(&db, &clone_journal()).unwrap_err());
        assert!(e.contains("journal.readbackMismatch"), "{e}");
        assert!(downgrade_get(&db, "d1").unwrap().is_none());
        let e = err(restore_create(&db, &restore()).unwrap_err());
        assert!(e.contains("journal.readbackMismatch"), "{e}");
        assert!(restore_get(&db, LOCAL).unwrap().is_none());
        db.conn
            .execute_batch("DROP TRIGGER skew_down; DROP TRIGGER skew_restore;")
            .unwrap();
        downgrade_create(&db, &clone_journal()).unwrap();
        db.conn
            .execute_batch(
                "CREATE TRIGGER skew_down AFTER UPDATE OF phase ON downgrade_journals BEGIN
                   UPDATE downgrade_journals SET discovery_readback_sha256 = zeroblob(32)
                   WHERE journal_id = NEW.journal_id; END;",
            )
            .unwrap();
        let e = err(
            downgrade_advance(&db, "d1", DowngradePhase::Claimed, Patch::default()).unwrap_err(),
        );
        assert!(e.contains("journal.readbackMismatch"), "{e}");
        let kept = downgrade_get(&db, "d1").unwrap().unwrap();
        assert_eq!(kept.phase, DowngradePhase::Created);
        db.conn.execute_batch("DROP TRIGGER skew_down;").unwrap();
        db.conn
            .execute_batch("DELETE FROM downgrade_journals;")
            .unwrap();
        restore_create(&db, &restore()).unwrap();
        db.conn
            .execute_batch(
                "CREATE TRIGGER skew_restore AFTER UPDATE OF phase ON restore_journals BEGIN
                   UPDATE restore_journals SET staged_path = 'elsewhere'
                   WHERE journal_id = NEW.journal_id; END;",
            )
            .unwrap();
        let e = err(restore_advance(&db, LOCAL, RestorePhase::Downloading).unwrap_err());
        assert!(e.contains("journal.readbackMismatch"), "{e}");
        let kept = restore_get(&db, LOCAL).unwrap().unwrap();
        assert_eq!(
            (kept.phase, kept.staged_path.as_str()),
            (RestorePhase::Created, "staged")
        );
        db.conn.execute_batch("DROP TRIGGER skew_restore;").unwrap();
        // A retire whose delete does not hold is refused and keeps the row.
        restore_advance(&db, LOCAL, RestorePhase::RollbackRequired).unwrap();
        restore_advance(&db, LOCAL, RestorePhase::RolledBack).unwrap();
        db.conn
            .execute_batch(
                "CREATE TRIGGER keep AFTER DELETE ON restore_journals BEGIN
                   INSERT INTO restore_journals VALUES (OLD.local_profile_id, OLD.journal_id,
                     OLD.phase, OLD.staged_path, OLD.backup_path, OLD.old_binding_json,
                     OLD.target_version, OLD.target_head_hash, OLD.created_at, OLD.updated_at);
                 END;",
            )
            .unwrap();
        let e = err(restore_retire(&db, LOCAL).unwrap_err());
        assert!(e.contains("journal.readbackMismatch"), "{e}");
        assert!(restore_get(&db, LOCAL).unwrap().is_some());
    }

    #[test]
    fn a_pre_v2_phase_is_refused_without_its_manifest_digest() {
        let (_dir, _path, db) = db();
        downgrade_create(&db, &pre_v2()).unwrap();
        downgrade_advance(&db, "d2", DowngradePhase::Claimed, Patch::default()).unwrap();
        let e = err(downgrade_advance(
            &db,
            "d2",
            DowngradePhase::PreV2SetRestored,
            Patch::default(),
        )
        .unwrap_err());
        assert!(e.contains("journal.missingField"), "{e}");
        let manifest = Patch {
            pre_v2_manifest_sha256: Some([3; 32]),
            ..Patch::default()
        };
        downgrade_advance(&db, "d2", DowngradePhase::PreV2SetRestored, manifest).unwrap();
        downgrade_advance(
            &db,
            "d2",
            DowngradePhase::TeamArtifactsRetired,
            Patch::default(),
        )
        .unwrap();
        let e = err(
            downgrade_advance(&db, "d2", DowngradePhase::ReadbackPassed, Patch::default())
                .unwrap_err(),
        );
        assert!(e.contains("journal.missingField"), "{e}");
    }

    #[test]
    fn the_resume_table_for_a_downgrade_journal_continues_every_open_phase() {
        for phase in &CLONE_CHAIN[..CLONE_CHAIN.len() - 1] {
            assert_eq!(phase.resume(), Resume::Continue, "{phase:?}");
        }
        assert_eq!(
            DowngradePhase::TeamArtifactsRetired.resume(),
            Resume::Continue
        );
        assert_eq!(DowngradePhase::RollbackRequired.resume(), Resume::Rollback);
        assert_eq!(DowngradePhase::Completed.resume(), Resume::Settled);
        assert_eq!(DowngradePhase::RolledBack.resume(), Resume::Settled);
    }

    #[test]
    fn the_digests_survive_reopen_byte_for_byte() {
        let (_dir, path, db) = db();
        downgrade_create(&db, &pre_v2()).unwrap();
        let patch = Patch {
            pre_v2_manifest_sha256: Some([0xab; 32]),
            discovery_readback_sha256: Some([0xcd; 32]),
        };
        downgrade_advance(&db, "d2", DowngradePhase::Claimed, Patch::default()).unwrap();
        downgrade_advance(&db, "d2", DowngradePhase::PreV2SetRestored, patch).unwrap();
        drop(db);
        let got = downgrade_get(&reopen(&path), "d2").unwrap().unwrap();
        assert_eq!(got.pre_v2_manifest_sha256, Some([0xab; 32]));
        assert_eq!(got.discovery_readback_sha256, Some([0xcd; 32]));
    }
}
