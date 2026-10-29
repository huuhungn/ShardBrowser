//! Process-kill harness for the G2 durability rows (G2-49, G2-50; ADR 0002
//! Q-30: crash evidence is a process kill at injected points, not a power
//! pull).
//!
//! A child is this test binary running one `#[ignore]`d test with
//! `SHARDX_CRASH_POINT` set. When it reaches that point it says so on stdout
//! and waits; the parent then kills it (`TerminateProcess` on Windows) and
//! checks what is on disk.

use std::io::{BufRead, Write};
use std::process::{Child, Command, Stdio};

/// Stops this process at `point` when the harness asked for it: prints the
/// marker the parent waits for and sleeps until killed.
pub(crate) fn pause_if(point: &str) {
    if std::env::var("SHARDX_CRASH_POINT").as_deref() == Ok(point) {
        println!("SHARDX-CRASH-AT {point}");
        let _ = std::io::stdout().flush();
        loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    }
}

/// Runs the ignored test `test` in a child process with `env`.
pub(crate) fn spawn(test: &str, point: &str, env: &[(&str, &std::path::Path)]) -> Child {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args([
        "--exact",
        test,
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ])
    .env("SHARDX_CRASH_POINT", point)
    .stdout(Stdio::piped())
    .stderr(Stdio::null());
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.spawn().unwrap()
}

/// Reads the child's stdout until a line contains `marker`, then kills it.
/// False when the child ended without printing it.
pub(crate) fn kill_after(mut child: Child, marker: &str) -> bool {
    let out = child.stdout.take().unwrap();
    let seen = std::io::BufReader::new(out)
        .lines()
        .map_while(Result::ok)
        .any(|line| line.contains(marker));
    let _ = child.kill();
    child.wait().unwrap();
    seen
}

/// Kills `test` at `point`; true when it got there.
pub(crate) fn kill_at(test: &str, point: &str, env: &[(&str, &std::path::Path)]) -> bool {
    kill_after(spawn(test, point, env), &format!("SHARDX-CRASH-AT {point}"))
}

/// G2-50 for `team-sync.db`: the launcher's own connection settings
/// (`team::db::Db::open_at`: rollback journal, `synchronous=FULL`, a 5 s busy
/// timeout) under a kill at every statement boundary of a write transaction.
mod team_sync_db {
    use super::*;
    use crate::team::db::Db;
    use rusqlite::TransactionBehavior;

    const CHILD: &str = "crash_harness::team_sync_db::child_writes_one_transaction";
    const LOOP_CHILD: &str = "crash_harness::team_sync_db::child_commits_in_a_loop";

    /// Enough rows to overflow a two-page cache.
    const SPILL: &str =
        "WITH RECURSIVE n(i) AS (SELECT 3 UNION ALL SELECT i + 1 FROM n WHERE i < 400)
         INSERT INTO g2_harness SELECT i, hex(randomblob(2000)) FROM n;";

    /// SQLite's journal magic: written only once the journal is synced, which
    /// is what makes a journal hot.
    const HOT_JOURNAL: [u8; 8] = [0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7];

    fn seeded() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("team-sync.db");
        let db = Db::open_at(&path).unwrap();
        db.conn
            .execute_batch(
                "CREATE TABLE g2_harness (k INTEGER PRIMARY KEY, v TEXT NOT NULL);
                 INSERT INTO g2_harness VALUES (1, 'old');",
            )
            .unwrap();
        (dir, path)
    }

    fn rows(db: &Db) -> Vec<(i64, String)> {
        db.conn
            .prepare("SELECT k, v FROM g2_harness ORDER BY k")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    }

    fn integrity(db: &Db) -> String {
        db.conn
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .unwrap()
    }

    #[test]
    #[ignore = "child process of the crash harness"]
    fn child_writes_one_transaction() {
        let Some(path) = std::env::var_os("SHARDX_CRASH_DB") else {
            return;
        };
        let mut db = Db::open_at(std::path::Path::new(&path)).unwrap();
        // A tiny page cache makes the transaction spill pages into the
        // database file before COMMIT, behind a synced (hot) journal.
        db.conn.pragma_update(None, "cache_size", 2).unwrap();
        let tx = db
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        pause_if("begun");
        tx.execute("UPDATE g2_harness SET v = 'new' WHERE k = 1", [])
            .unwrap();
        pause_if("updated");
        tx.execute("INSERT INTO g2_harness VALUES (2, 'new')", [])
            .unwrap();
        pause_if("inserted");
        tx.execute_batch(SPILL).unwrap();
        pause_if("spilled");
        tx.commit().unwrap();
        pause_if("committed");
    }

    /// Killed before its commit returns, a transaction is wholly absent after
    /// the reopen rolls back the hot journal; killed after, wholly present.
    #[test]
    fn a_killed_transaction_reopens_old_or_new_never_half() {
        for (point, committed) in [
            ("begun", false),
            ("updated", false),
            ("inserted", false),
            ("spilled", false),
            ("committed", true),
        ] {
            let (dir, path) = seeded();
            assert!(
                kill_at(CHILD, point, &[("SHARDX_CRASH_DB", &path)]),
                "{point}"
            );
            let journal = dir.path().join("team-sync.db-journal");
            if point == "inserted" {
                assert!(journal.exists(), "the kill left no journal");
            }
            if point == "spilled" {
                let head = std::fs::read(&journal).unwrap();
                assert_eq!(
                    head.get(..8),
                    Some(&HOT_JOURNAL[..]),
                    "the journal is not hot"
                );
            }
            let db = Db::open_at(&path).unwrap();
            let got = rows(&db);
            if committed {
                assert_eq!(got.len(), 400, "{point}");
                assert_eq!(got[..2], [(1, "new".into()), (2, "new".into())], "{point}");
            } else {
                assert_eq!(got, [(1, "old".to_string())], "{point}");
            }
            assert_eq!(integrity(&db), "ok", "{point}");
            // A journal whose header was never synced is not hot: SQLite
            // leaves it until the next write, which must still go through.
            db.conn
                .execute("INSERT INTO g2_harness VALUES (1000, 'after')", [])
                .unwrap();
            assert!(!journal.exists(), "{point}: journal left after a write");
            assert!(!dir.path().join("team-sync.db-wal").exists());
        }
    }

    #[test]
    #[ignore = "child process of the crash harness"]
    fn child_commits_in_a_loop() {
        let Some(path) = std::env::var_os("SHARDX_CRASH_DB") else {
            return;
        };
        let db = Db::open_at(std::path::Path::new(&path)).unwrap();
        for k in 2_i64..i64::MAX {
            db.conn
                .execute(
                    "INSERT INTO g2_harness VALUES (?1, 'loop')",
                    rusqlite::params![k],
                )
                .unwrap();
            println!("COMMITTED {k}");
        }
    }

    /// Killed at an arbitrary moment of a run of commits, every commit that
    /// returned is there and nothing past one more.
    #[test]
    fn a_kill_between_commits_keeps_every_returned_commit() {
        for target in [3_i64, 17, 60] {
            let (_dir, path) = seeded();
            let child = spawn(LOOP_CHILD, "-", &[("SHARDX_CRASH_DB", &path)]);
            assert!(kill_after(child, &format!("COMMITTED {target}")));
            let db = Db::open_at(&path).unwrap();
            let keys: Vec<i64> = rows(&db).into_iter().map(|(k, _)| k).collect();
            let last = *keys.last().unwrap();
            assert!(last >= target, "returned commit {target} lost: last {last}");
            assert_eq!(keys, (1..=last).collect::<Vec<_>>(), "a gap or a torn row");
            assert_eq!(integrity(&db), "ok");
        }
    }

    /// A second writer waits for the first instead of failing (plan L102:
    /// one writer at a time), and a lock held past the busy timeout surfaces
    /// as `SQLITE_BUSY` instead of a hang or a silent drop.
    #[test]
    fn a_second_writer_waits_for_the_lock_and_is_refused_after_the_timeout() {
        let (_dir, path) = seeded();
        let mut holder = Db::open_at(&path).unwrap();
        let waiter = Db::open_at(&path).unwrap();
        let tx = holder
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        tx.execute("INSERT INTO g2_harness VALUES (2, 'first')", [])
            .unwrap();
        let started = std::time::Instant::now();
        let second = std::thread::spawn(move || {
            waiter
                .conn
                .execute("INSERT INTO g2_harness VALUES (3, 'second')", [])
                .map(|_| started.elapsed())
        });
        std::thread::sleep(std::time::Duration::from_millis(400));
        tx.commit().unwrap();
        let waited = second.join().unwrap().unwrap();
        assert!(
            waited >= std::time::Duration::from_millis(350),
            "{waited:?}"
        );
        assert_eq!(rows(&holder).len(), 3);

        let tx = holder
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let started = std::time::Instant::now();
        // Opening runs its own write transaction, which now times out.
        let err = Db::open_at(&path)
            .err()
            .map(|e| format!("{e:#}"))
            .unwrap_or_default();
        assert!(err.contains("database is locked"), "{err}");
        assert!(started.elapsed() >= std::time::Duration::from_millis(4500));
        drop(tx);
    }
}
