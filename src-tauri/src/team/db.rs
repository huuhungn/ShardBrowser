//! `team-sync.db`, the launcher's local team database (plan 11.1).
//!
//! Every reader goes through [`Db::open`], which creates the schema on an
//! empty file and otherwise runs the plan's startup compatibility query
//! (L2032): exactly one `schema_meta` row, `migration_state = 'CLEAN'`, a
//! `schema_version` this binary reads and a `min_reader_version` it meets.
//! Anything else is refused before any row is read, and the file is left as
//! it was (probe 8, L2043).
//!
//! The journal stays in rollback mode with `synchronous = FULL`: the plan
//! enables WAL only once the Windows crash, checkpoint and busy tests pass
//! (11.3, L2061).
//!
//! The tables so far are `schema_meta`, exactly as the plan's reference DDL
//! (L1450-L1458), and the W6 trust ledger (ADR 0002 D-6, Q-12, Q-13), which
//! the plan's DDL leaves to W6. The ledger keeps hashes, key IDs and times,
//! the exact bytes of counted revocations, and the exact grant behind each
//! collected fleet key with its evidence (G2-35), never a key (L2048).

use anyhow::{bail, Context, Result};
use rusqlite::{Connection, TransactionBehavior};
use std::path::Path;

/// The schema this binary writes, and the newest one it reads.
pub const SCHEMA_VERSION: i64 = 2;

/// Version 1, as #188 shipped it.
const SCHEMA_V1: &str = r#"
CREATE TABLE schema_meta (
  singleton           INTEGER PRIMARY KEY CHECK (singleton = 1),
  schema_version      INTEGER NOT NULL CHECK (schema_version BETWEEN 1 AND 9223372036854775807),
  min_reader_version  INTEGER NOT NULL CHECK (min_reader_version BETWEEN 1 AND 9223372036854775807),
  migration_state     TEXT NOT NULL CHECK (migration_state IN ('CLEAN','MIGRATING','RECOVERY_REQUIRED')),
  applied_at          TEXT NOT NULL
) STRICT;
INSERT INTO schema_meta(singleton, schema_version, min_reader_version, migration_state, applied_at)
VALUES (1, 1, 1, 'CLEAN', '1970-01-01T00:00:00Z');

-- The anchor A0 pinned per (instance, tenant). BOOTSTRAP: the device that
-- bootstrapped custody. JOIN: the Q-12 join ceremony, which has not shipped.
-- A pin never changes: a server-supplied new anchor is never accepted.
CREATE TABLE trust_anchors (
  server_instance_id TEXT NOT NULL CHECK (length(server_instance_id) = 32 AND server_instance_id NOT GLOB '*[^0-9a-f]*'),
  tenant_id          TEXT NOT NULL CHECK (length(tenant_id) = 32 AND tenant_id NOT GLOB '*[^0-9a-f]*'),
  anchor_key_id      TEXT NOT NULL CHECK (length(anchor_key_id) = 64 AND anchor_key_id NOT GLOB '*[^0-9a-f]*'),
  source             TEXT NOT NULL CHECK (source IN ('BOOTSTRAP','JOIN')),
  pinned_at_ms       INTEGER NOT NULL CHECK (pinned_at_ms BETWEEN 0 AND 9223372036854775807),
  PRIMARY KEY(server_instance_id, tenant_id)
) STRICT;

-- One row per trust-evidence evaluation; its ID orders first sightings
-- against counted revocations (ADR 0002 rule 1, "Order").
CREATE TABLE trust_evaluations (
  evaluation_id      INTEGER PRIMARY KEY AUTOINCREMENT,
  server_instance_id TEXT NOT NULL,
  tenant_id          TEXT NOT NULL,
  evaluated_at_ms    INTEGER NOT NULL CHECK (evaluated_at_ms BETWEEN 0 AND 9223372036854775807),
  FOREIGN KEY(server_instance_id, tenant_id)
    REFERENCES trust_anchors(server_instance_id, tenant_id) ON DELETE RESTRICT
) STRICT;

-- The first local sighting of each container (D-6 (d), (e)).
CREATE TABLE trust_sightings (
  server_instance_id    TEXT NOT NULL,
  tenant_id             TEXT NOT NULL,
  signed_container_hash TEXT NOT NULL CHECK (length(signed_container_hash) = 64 AND signed_container_hash NOT GLOB '*[^0-9a-f]*'),
  issuer_signing_key_id TEXT NOT NULL CHECK (length(issuer_signing_key_id) = 64 AND issuer_signing_key_id NOT GLOB '*[^0-9a-f]*'),
  first_seen_evaluation INTEGER NOT NULL REFERENCES trust_evaluations(evaluation_id) ON DELETE RESTRICT,
  first_seen_ms         INTEGER NOT NULL CHECK (first_seen_ms BETWEEN 0 AND 9223372036854775807),
  PRIMARY KEY(server_instance_id, tenant_id, signed_container_hash),
  FOREIGN KEY(server_instance_id, tenant_id)
    REFERENCES trust_anchors(server_instance_id, tenant_id) ON DELETE RESTRICT
) STRICT;

-- Server revocation reports, kept at their earliest time: they only tighten.
CREATE TABLE trust_reported_revocations (
  server_instance_id TEXT NOT NULL,
  tenant_id          TEXT NOT NULL,
  payload_domain     TEXT NOT NULL,
  replay_id          TEXT NOT NULL CHECK (length(replay_id) = 32 AND replay_id NOT GLOB '*[^0-9a-f]*'),
  revoked_at_ms      INTEGER NOT NULL CHECK (revoked_at_ms BETWEEN 0 AND 9223372036854775807),
  PRIMARY KEY(server_instance_id, tenant_id, payload_domain, replay_id),
  FOREIGN KEY(server_instance_id, tenant_id)
    REFERENCES trust_anchors(server_instance_id, tenant_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE trust_reported_device_revocations (
  server_instance_id TEXT NOT NULL,
  tenant_id          TEXT NOT NULL,
  device_id          TEXT NOT NULL CHECK (length(device_id) = 32 AND device_id NOT GLOB '*[^0-9a-f]*'),
  revoked_at_ms      INTEGER NOT NULL CHECK (revoked_at_ms BETWEEN 0 AND 9223372036854775807),
  PRIMARY KEY(server_instance_id, tenant_id, device_id),
  FOREIGN KEY(server_instance_id, tenant_id)
    REFERENCES trust_anchors(server_instance_id, tenant_id) ON DELETE RESTRICT
) STRICT;

-- Keys this device holds as proven revoked: a counted DeviceRevocationV2
-- (Q-13, with its exact container) or local distrust (D-6 (d)). Records by
-- the key first seen after `counted_evaluation` are unusable.
CREATE TABLE trust_proven_revocations (
  server_instance_id           TEXT NOT NULL,
  tenant_id                    TEXT NOT NULL,
  signing_key_id               TEXT NOT NULL CHECK (length(signing_key_id) = 64 AND signing_key_id NOT GLOB '*[^0-9a-f]*'),
  source                       TEXT NOT NULL CHECK (source IN ('DEVICE_REVOCATION','LOCAL_DISTRUST')),
  counted_evaluation           INTEGER NOT NULL CHECK (counted_evaluation BETWEEN 0 AND 9223372036854775807),
  counted_at_ms                INTEGER NOT NULL CHECK (counted_at_ms BETWEEN 0 AND 9223372036854775807),
  exact_signed_container_bytes BLOB,
  PRIMARY KEY(server_instance_id, tenant_id, signing_key_id, source),
  FOREIGN KEY(server_instance_id, tenant_id)
    REFERENCES trust_anchors(server_instance_id, tenant_id) ON DELETE RESTRICT,
  CHECK ((source = 'DEVICE_REVOCATION') = (exact_signed_container_bytes IS NOT NULL))
) STRICT;

-- ADR 0002 "Fleet generation freshness": the highest generation verified
-- per fleet.
CREATE TABLE trust_fleet_generations (
  server_instance_id          TEXT NOT NULL,
  tenant_id                   TEXT NOT NULL,
  fleet_id                    TEXT NOT NULL CHECK (length(fleet_id) = 32 AND fleet_id NOT GLOB '*[^0-9a-f]*'),
  highest_verified_generation INTEGER NOT NULL CHECK (highest_verified_generation BETWEEN 0 AND 9223372036854775807),
  PRIMARY KEY(server_instance_id, tenant_id, fleet_id),
  FOREIGN KEY(server_instance_id, tenant_id)
    REFERENCES trust_anchors(server_instance_id, tenant_id) ON DELETE RESTRICT
) STRICT;

-- What the ledger learns is never taken back.
CREATE TRIGGER trust_anchors_fixed BEFORE UPDATE ON trust_anchors
BEGIN SELECT RAISE(ABORT, 'a pinned anchor never changes'); END;
CREATE TRIGGER trust_anchors_kept BEFORE DELETE ON trust_anchors
BEGIN SELECT RAISE(ABORT, 'a pinned anchor is never forgotten'); END;
CREATE TRIGGER trust_evaluations_kept BEFORE DELETE ON trust_evaluations
BEGIN SELECT RAISE(ABORT, 'an evaluation is never forgotten'); END;
CREATE TRIGGER trust_sightings_kept BEFORE DELETE ON trust_sightings
BEGIN SELECT RAISE(ABORT, 'a first sighting is never forgotten'); END;
CREATE TRIGGER trust_fleet_generations_kept BEFORE DELETE ON trust_fleet_generations
BEGIN SELECT RAISE(ABORT, 'a verified generation is never forgotten'); END;
CREATE TRIGGER trust_proven_revocations_fixed BEFORE UPDATE ON trust_proven_revocations
BEGIN SELECT RAISE(ABORT, 'a proven revocation never changes'); END;
CREATE TRIGGER trust_proven_revocations_kept BEFORE DELETE ON trust_proven_revocations
BEGIN SELECT RAISE(ABORT, 'a proven revocation is never forgotten'); END;
CREATE TRIGGER trust_reported_revocations_kept BEFORE DELETE ON trust_reported_revocations
BEGIN SELECT RAISE(ABORT, 'a reported revocation is never forgotten'); END;
CREATE TRIGGER trust_reported_revocations_earlier BEFORE UPDATE ON trust_reported_revocations
WHEN NEW.revoked_at_ms > OLD.revoked_at_ms
BEGIN SELECT RAISE(ABORT, 'a reported revocation only moves earlier'); END;
CREATE TRIGGER trust_reported_device_revocations_kept BEFORE DELETE ON trust_reported_device_revocations
BEGIN SELECT RAISE(ABORT, 'a reported revocation is never forgotten'); END;
CREATE TRIGGER trust_reported_device_revocations_earlier BEFORE UPDATE ON trust_reported_device_revocations
WHEN NEW.revoked_at_ms > OLD.revoked_at_ms
BEGIN SELECT RAISE(ABORT, 'a reported revocation only moves earlier'); END;
CREATE TRIGGER trust_fleet_generations_forward BEFORE UPDATE ON trust_fleet_generations
WHEN NEW.highest_verified_generation < OLD.highest_verified_generation
BEGIN SELECT RAISE(ABORT, 'a verified generation never goes backwards'); END;
"#;

/// Version 1 to 2: the custodian keys of D-6 (a)-(c) and the fleet key
/// grants of G2-35. A version 1 reader would skip them, so 2 is also the
/// minimum reader.
const MIGRATE_V2: &str = r#"
-- D-6 (a)-(c): each key a counted root grant made a custodian. The earliest
-- not_before and latest end of its counted root grants: the first starts the
-- 1095-day clip and only moves earlier, the second only moves later. The
-- first evaluation that found that known custody ended, and its local time,
-- is the key's sticky lapse.
CREATE TABLE trust_custodian_keys (
  server_instance_id    TEXT NOT NULL,
  tenant_id             TEXT NOT NULL,
  signing_key_id        TEXT NOT NULL CHECK (length(signing_key_id) = 64 AND signing_key_id NOT GLOB '*[^0-9a-f]*'),
  first_seen_evaluation INTEGER NOT NULL REFERENCES trust_evaluations(evaluation_id) ON DELETE RESTRICT,
  first_not_before_ms   INTEGER NOT NULL CHECK (first_not_before_ms BETWEEN 0 AND 9223372036854775807),
  latest_not_after_ms   INTEGER NOT NULL CHECK (latest_not_after_ms BETWEEN 0 AND 9223372036854775807),
  lapsed_evaluation     INTEGER REFERENCES trust_evaluations(evaluation_id) ON DELETE RESTRICT,
  observed_lapsed_at_ms INTEGER CHECK (observed_lapsed_at_ms BETWEEN 0 AND 9223372036854775807),
  PRIMARY KEY(server_instance_id, tenant_id, signing_key_id),
  FOREIGN KEY(server_instance_id, tenant_id)
    REFERENCES trust_anchors(server_instance_id, tenant_id) ON DELETE RESTRICT,
  CHECK ((lapsed_evaluation IS NULL) = (observed_lapsed_at_ms IS NULL))
) STRICT;

-- G2-35 (plan L2056): the exact DeviceHpkeGrant behind each fleet key this
-- device collected, and the pages it verified against, so sync can reverify
-- it before using the key; the key itself is never here.
CREATE TABLE trust_fleet_key_grants (
  server_instance_id           TEXT NOT NULL,
  tenant_id                    TEXT NOT NULL,
  fleet_id                     TEXT NOT NULL CHECK (length(fleet_id) = 32 AND fleet_id NOT GLOB '*[^0-9a-f]*'),
  generation                   INTEGER NOT NULL CHECK (generation BETWEEN 0 AND 9223372036854775807),
  fkek_key_id                  TEXT NOT NULL CHECK (length(fkek_key_id) = 64 AND fkek_key_id NOT GLOB '*[^0-9a-f]*'),
  verified_evaluation          INTEGER NOT NULL REFERENCES trust_evaluations(evaluation_id) ON DELETE RESTRICT,
  exact_signed_container_bytes BLOB NOT NULL,
  evidence_pages               BLOB NOT NULL,
  PRIMARY KEY(server_instance_id, tenant_id, fleet_id, generation),
  FOREIGN KEY(server_instance_id, tenant_id)
    REFERENCES trust_anchors(server_instance_id, tenant_id) ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER trust_custodian_keys_kept BEFORE DELETE ON trust_custodian_keys
BEGIN SELECT RAISE(ABORT, 'a custodian key is never forgotten'); END;
CREATE TRIGGER trust_custodian_keys_earlier BEFORE UPDATE ON trust_custodian_keys
WHEN NEW.first_not_before_ms > OLD.first_not_before_ms
  OR NEW.first_seen_evaluation IS NOT OLD.first_seen_evaluation
BEGIN SELECT RAISE(ABORT, 'a cached first_not_before only moves earlier'); END;
CREATE TRIGGER trust_custodian_keys_later BEFORE UPDATE ON trust_custodian_keys
WHEN NEW.latest_not_after_ms < OLD.latest_not_after_ms
BEGIN SELECT RAISE(ABORT, 'a known custody end only moves later'); END;
CREATE TRIGGER trust_custodian_keys_lapse_kept BEFORE UPDATE ON trust_custodian_keys
WHEN OLD.lapsed_evaluation IS NOT NULL
  AND (NEW.lapsed_evaluation IS NOT OLD.lapsed_evaluation
       OR NEW.observed_lapsed_at_ms IS NOT OLD.observed_lapsed_at_ms)
BEGIN SELECT RAISE(ABORT, 'an observed lapse never changes'); END;
UPDATE schema_meta SET schema_version = 2, min_reader_version = 2,
  applied_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now');
"#;

/// An open `team-sync.db` whose schema this binary reads.
pub struct Db {
    pub(crate) conn: Connection,
}

impl Db {
    /// `<config_root>/team-sync/team-sync.db` (plan L1440).
    pub fn open() -> Result<Self> {
        let dir = crate::store::config_root()?.join("team-sync");
        std::fs::create_dir_all(&dir)?;
        Self::open_at(&dir.join("team-sync.db"))
    }

    /// Opens `path`, creating the schema only when the file holds nothing, and
    /// migrating a clean version 1 file forward.
    pub fn open_at(path: &Path) -> Result<Self> {
        let unreadable = || crate::errcode::code("team.trustLedgerUnreadable");
        let mut conn = Connection::open(path).with_context(unreadable)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .with_context(unreadable)?;
        conn.pragma_update(None, "foreign_keys", true)
            .with_context(unreadable)?;
        // SQLite refuses to leave WAL while another connection reads, with an
        // error rather than another mode.
        conn.pragma_update_and_check(None, "journal_mode", "DELETE", |r| r.get::<_, String>(0))
            .with_context(unreadable)?;
        conn.pragma_update(None, "synchronous", "FULL")
            .with_context(unreadable)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .with_context(unreadable)?;
        let objects: i64 = tx
            .query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))
            .with_context(unreadable)?;
        if objects == 0 {
            tx.execute_batch(SCHEMA_V1).with_context(unreadable)?;
        }
        // Only from exactly one clean version 1 row: anything else is left as
        // it is for `compatible` to refuse, and a step that fails rolls the
        // whole migration back.
        if matches!(meta(&tx).as_deref(), Ok([(1, 1, state)]) if state == "CLEAN") {
            tx.execute_batch(MIGRATE_V2).with_context(unreadable)?;
        }
        tx.commit().with_context(unreadable)?;
        if !compatible(&conn) {
            bail!(crate::errcode::code("team.trustLedgerUnsupported"));
        }
        Ok(Self { conn })
    }
}

/// The startup compatibility query (plan L2032): exactly one row, clean, of a
/// version this binary reads and whose minimum reader it meets.
fn compatible(conn: &Connection) -> bool {
    matches!(
        meta(conn).as_deref(),
        Ok([(version, min_reader, state)])
            if *version <= SCHEMA_VERSION && *min_reader <= SCHEMA_VERSION && state == "CLEAN"
    )
}

/// Every `schema_meta` row: version, minimum reader and migration state.
fn meta(conn: &Connection) -> rusqlite::Result<Vec<(i64, i64, String)>> {
    conn.prepare("SELECT schema_version, min_reader_version, migration_state FROM schema_meta")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("team-sync.db");
        drop(Db::open_at(&path).unwrap());
        (dir, path)
    }

    /// A new file gets the schema once, rollback journal and full fsync, and
    /// reopens as it was.
    #[test]
    fn a_new_database_reopens_with_its_schema_and_settings() {
        let (_dir, path) = fresh();
        let db = Db::open_at(&path).unwrap();
        let meta: (i64, i64, String) = db
            .conn
            .query_row(
                "SELECT schema_version, min_reader_version, migration_state FROM schema_meta",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(meta, (2, 2, "CLEAN".into()));
        let pragma = |name: &str| -> String {
            db.conn
                .query_row(&format!("SELECT * FROM pragma_{name}"), [], |r| {
                    r.get::<_, rusqlite::types::Value>(0)
                })
                .map(|v| format!("{v:?}"))
                .unwrap()
        };
        assert_eq!(pragma("journal_mode"), "Text(\"delete\")");
        assert_eq!(pragma("synchronous"), "Integer(2)");
        assert_eq!(pragma("foreign_keys"), "Integer(1)");
    }

    /// Probe 8 (plan L2043, G2-40): a newer schema, a higher minimum reader,
    /// an unclean migration, no row or two rows, or a file whose tables are
    /// not ours: Team is refused on every reopen and nothing is rewritten.
    #[test]
    fn an_unknown_schema_fails_closed_and_is_left_as_it_was() {
        let mutations = [
            "UPDATE schema_meta SET schema_version = 3",
            "UPDATE schema_meta SET min_reader_version = 3",
            "UPDATE schema_meta SET migration_state = 'MIGRATING'",
            "UPDATE schema_meta SET migration_state = 'RECOVERY_REQUIRED'",
            "DELETE FROM schema_meta",
            "PRAGMA ignore_check_constraints = 1; \
             INSERT INTO schema_meta VALUES (2, 1, 1, 'CLEAN', 'x')",
            "DROP TABLE schema_meta",
        ];
        for sql in mutations {
            let (_dir, path) = fresh();
            Connection::open(&path).unwrap().execute_batch(sql).unwrap();
            let before = std::fs::read(&path).unwrap();
            for _ in 0..2 {
                let err = Db::open_at(&path).err().expect(sql).to_string();
                assert!(
                    crate::errcode::has_code(&err, "team.trustLedgerUnsupported"),
                    "{sql}: {err}"
                );
            }
            assert_eq!(std::fs::read(&path).unwrap(), before, "{sql}");
        }
        // A file that is not a database is refused, never replaced.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("team-sync.db");
        std::fs::write(&path, b"not a database at all, not even close").unwrap();
        let err = Db::open_at(&path).err().unwrap().to_string();
        assert!(crate::errcode::has_code(&err, "team.trustLedgerUnreadable"));
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"not a database at all, not even close"
        );
    }

    /// A version 1 file, as #188 wrote it, moves to version 2 in one
    /// transaction and keeps its rows; it then reopens as version 2.
    #[test]
    fn a_version_1_file_migrates_to_version_2_and_reopens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("team-sync.db");
        let pin = format!(
            "INSERT INTO trust_anchors VALUES ('{}', '{}', '{}', 'BOOTSTRAP', 0);",
            "11".repeat(16),
            "22".repeat(16),
            "33".repeat(32)
        );
        let v1 = Connection::open(&path).unwrap();
        v1.execute_batch(SCHEMA_V1).unwrap();
        v1.execute_batch(&pin).unwrap();
        drop(v1);
        for _ in 0..2 {
            let db = Db::open_at(&path).unwrap();
            let rows = meta(&db.conn).unwrap();
            assert_eq!(rows, [(2, 2, "CLEAN".to_string())]);
            let count = |table: &str| -> i64 {
                let sql = format!("SELECT count(*) FROM {table}");
                db.conn.query_row(&sql, [], |r| r.get(0)).unwrap()
            };
            assert_eq!(count("trust_anchors"), 1, "kept");
            assert_eq!(count("trust_custodian_keys"), 0);
            assert_eq!(count("trust_fleet_key_grants"), 0);
        }
    }

    /// A version 1 file that is not clean, or already holds a table the
    /// migration adds, is not migrated: it is refused and left as it was.
    #[test]
    fn an_unexpected_version_1_file_is_not_migrated() {
        for (sql, code) in [
            (
                "UPDATE schema_meta SET migration_state = 'MIGRATING'",
                "team.trustLedgerUnsupported",
            ),
            (
                "CREATE TABLE trust_fleet_key_grants (x INTEGER)",
                "team.trustLedgerUnreadable",
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("team-sync.db");
            let v1 = Connection::open(&path).unwrap();
            v1.execute_batch(SCHEMA_V1).unwrap();
            v1.execute_batch(sql).unwrap();
            drop(v1);
            let before = std::fs::read(&path).unwrap();
            for _ in 0..2 {
                let err = Db::open_at(&path).err().expect(sql).to_string();
                assert!(crate::errcode::has_code(&err, code), "{sql}: {err}");
            }
            assert_eq!(std::fs::read(&path).unwrap(), before, "{sql}");
        }
    }

    /// A file another connection holds in WAL mode cannot leave it, and is
    /// refused rather than used under a journal the plan has not cleared.
    #[test]
    fn a_database_held_in_wal_mode_is_refused() {
        let (_dir, path) = fresh();
        let other = Connection::open(&path).unwrap();
        let mode: String = other
            .pragma_update_and_check(None, "journal_mode", "WAL", |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
        // A read transaction keeps it there.
        other
            .execute_batch("BEGIN; SELECT * FROM schema_meta;")
            .unwrap();
        let err = Db::open_at(&path).err().unwrap().to_string();
        assert!(crate::errcode::has_code(&err, "team.trustLedgerUnreadable"));
        drop(other);
        assert!(Db::open_at(&path).is_ok(), "back to the rollback journal");
    }

    /// The ledger's triggers keep what it learned: a pin, a proven or reported
    /// revocation, and the highest verified generation never go back.
    #[test]
    fn the_ledger_never_takes_back_what_it_learned() {
        let (_dir, path) = fresh();
        let db = Db::open_at(&path).unwrap();
        let (i, t) = ("11".repeat(16), "22".repeat(16));
        db.conn
            .execute_batch(&format!(
                "INSERT INTO trust_anchors VALUES ('{i}', '{t}', '{k}', 'BOOTSTRAP', 0);
                 INSERT INTO trust_proven_revocations VALUES
                   ('{i}', '{t}', '{k}', 'LOCAL_DISTRUST', 0, 0, NULL);
                 INSERT INTO trust_reported_revocations VALUES ('{i}', '{t}', 'd', '{i}', 5);
                 INSERT INTO trust_reported_device_revocations VALUES ('{i}', '{t}', '{i}', 5);
                 INSERT INTO trust_fleet_generations VALUES ('{i}', '{t}', '{i}', 3);
                 INSERT INTO trust_evaluations VALUES (1, '{i}', '{t}', 0);
                 INSERT INTO trust_evaluations VALUES (2, '{i}', '{t}', 0);
                 INSERT INTO trust_custodian_keys VALUES ('{i}', '{t}', '{k}', 1, 5, 9, 1, 7);",
                k = "33".repeat(32)
            ))
            .unwrap();
        for sql in [
            "UPDATE trust_custodian_keys SET first_not_before_ms = 6",
            "UPDATE trust_custodian_keys SET first_seen_evaluation = 2",
            "UPDATE trust_custodian_keys SET latest_not_after_ms = 8",
            "UPDATE trust_custodian_keys SET observed_lapsed_at_ms = 8",
            "UPDATE trust_custodian_keys SET lapsed_evaluation = 2",
            "UPDATE trust_custodian_keys SET lapsed_evaluation = NULL, observed_lapsed_at_ms = NULL",
            "DELETE FROM trust_custodian_keys",
            "UPDATE trust_anchors SET anchor_key_id = lower(hex(zeroblob(32)))",
            "UPDATE trust_proven_revocations SET counted_evaluation = 9",
            "DELETE FROM trust_proven_revocations",
            "DELETE FROM trust_reported_revocations",
            "UPDATE trust_reported_revocations SET revoked_at_ms = 6",
            "DELETE FROM trust_reported_device_revocations",
            "UPDATE trust_reported_device_revocations SET revoked_at_ms = 6",
            "UPDATE trust_fleet_generations SET highest_verified_generation = 2",
            "DELETE FROM trust_anchors",
        ] {
            assert!(db.conn.execute_batch(sql).is_err(), "{sql}");
        }
        // Moving forward is allowed.
        db.conn
            .execute_batch(
                "UPDATE trust_reported_revocations SET revoked_at_ms = 4;
                 UPDATE trust_reported_device_revocations SET revoked_at_ms = 4;
                 UPDATE trust_fleet_generations SET highest_verified_generation = 4;
                 UPDATE trust_custodian_keys SET first_not_before_ms = 4;
                 UPDATE trust_custodian_keys SET latest_not_after_ms = 10;",
            )
            .unwrap();
        // Each row on its own, so only its trigger can refuse the delete.
        let anchor = format!(
            "INSERT INTO trust_anchors VALUES ('{i}', '{t}', '{}', 'BOOTSTRAP', 0);",
            "33".repeat(32)
        );
        let evaluation =
            format!("{anchor} INSERT INTO trust_evaluations VALUES (1, '{i}', '{t}', 0);");
        for (rows, table) in [
            (anchor.clone(), "trust_anchors"),
            (evaluation.clone(), "trust_evaluations"),
            (
                format!(
                    "{evaluation} INSERT INTO trust_sightings VALUES ('{i}', '{t}', '{k}', '{k}', 1, 0);",
                    k = "44".repeat(32)
                ),
                "trust_sightings",
            ),
            (
                format!("{anchor} INSERT INTO trust_fleet_generations VALUES ('{i}', '{t}', '{i}', 3);"),
                "trust_fleet_generations",
            ),
        ] {
            let (_dir, path) = fresh();
            let db = Db::open_at(&path).unwrap();
            db.conn.execute_batch(&rows).unwrap();
            let sql = format!("DELETE FROM {table}");
            assert!(db.conn.execute_batch(&sql).is_err(), "{sql}");
        }
    }
}
