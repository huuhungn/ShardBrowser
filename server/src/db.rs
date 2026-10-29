use std::str::FromStr;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::SqlitePool;

use crate::config::Config;
use crate::models::User;
use crate::{auth, util};

/// Open (creating if needed) the SQLite DB and run migrations.
pub async fn init_pool(cfg: &Config) -> anyhow::Result<SqlitePool> {
    let pool = open_pool(cfg).await?;
    shardx_team_server::run_migrations(&pool).await?;
    Ok(pool)
}

/// Open (creating if needed) the SQLite DB without migrating it, so
/// `identity init` can refuse on existing rows before writing anything.
/// How long a statement waits for the write lock before failing. Every write
/// serializes on it, and on a loaded host (CI ran 20 concurrent challenge
/// requests while other servers shared its disk) five seconds ran out and the
/// waiters failed with 500. Clients wait two minutes for a reply, so waiting
/// longer here only turns those failures into slower successes.
const BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub async fn open_pool(cfg: &Config) -> anyhow::Result<SqlitePool> {
    tokio::fs::create_dir_all(&cfg.data_dir).await?;
    tokio::fs::create_dir_all(&cfg.blob_dir).await?;
    refuse_network_storage(cfg)?;

    let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", cfg.db_path))?
        .create_if_missing(true)
        .foreign_keys(true)
        // The storage policy (G2-50; plan L2061): a rollback journal with full
        // syncs, so a commit is on disk when it returns and a crash rolls back
        // the hot journal on the next open. WAL comes only once the crash,
        // checkpoint, busy and rollback harness passes on Windows. Pinned here
        // so a library default can never switch it silently.
        .journal_mode(SqliteJournalMode::Delete)
        .synchronous(SqliteSynchronous::Full)
        // Writers queue instead of failing fast while another transaction
        // holds the write lock.
        .busy_timeout(BUSY_TIMEOUT);
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(opts)
        .await?;
    Ok(pool)
}

/// The database and blobs must be on a local disk: SQLite locking is not
/// reliable on network filesystems, and the plan rejects them (L1110, L2061,
/// L2335). On Windows only local NTFS passes (ADR 0002 Q-29); elsewhere the
/// mount allowlist in `identity::is_network_path` is the whole check.
fn refuse_network_storage(cfg: &Config) -> anyhow::Result<()> {
    let db_dir = std::path::Path::new(&cfg.db_path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(
            || cfg.data_dir.clone(),
            |p| p.to_string_lossy().into_owned(),
        );
    for (name, dir) in [
        ("SHARDX_DATA_DIR", cfg.data_dir.as_str()),
        ("the database directory", db_dir.as_str()),
        ("the blob directory", cfg.blob_dir.as_str()),
    ] {
        let resolved =
            std::fs::canonicalize(dir).map_err(|e| anyhow::anyhow!("{name} {dir:?}: {e}"))?;
        if crate::identity::is_network_path(&resolved) {
            anyhow::bail!("{name} {dir:?} is on a network share, which is not supported");
        }
        if let Err(refusal) = shared::volume::require_local_ntfs(&resolved) {
            anyhow::bail!("{name} {dir:?} {refusal}, which is not supported");
        }
    }
    Ok(())
}

/// On an empty DB, create the initial admin from config.
pub async fn bootstrap_admin(pool: &SqlitePool, cfg: &Config) -> anyhow::Result<()> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await?;
    // On a network-facing bind, a weak/default admin password is remote-takeover
    // by default. Loopback only exposes it locally (a warning suffices) and an
    // explicit opt-out covers exposed-dev setups.
    let guard_exposed = !cfg.bind_is_loopback()
        && !std::env::var("SHARDX_ALLOW_INSECURE_ADMIN").is_ok_and(|v| v == "1");

    if count == 0 {
        // Creating the first admin: we have the plaintext, so reject empty /
        // too-short / placeholder passwords up front.
        if guard_exposed && is_weak_password(&cfg.admin_pass) {
            anyhow::bail!(
                "refusing to bootstrap the admin account with a weak/default password on a \
                 non-loopback bind ({}). Set SHARDX_ADMIN_PASS to a strong secret \
                 (recommended), bind 127.0.0.1, or set SHARDX_ALLOW_INSECURE_ADMIN=1 to \
                 override.",
                cfg.bind
            );
        }
        let hash = auth::hash_password(&cfg.admin_pass).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        sqlx::query(
            "INSERT INTO users (id, username, pw_hash, role, created_at) VALUES (?, ?, ?, 'admin', ?)",
        )
        .bind(util::new_id())
        .bind(&cfg.admin_user)
        .bind(hash)
        .bind(util::now_rfc3339())
        .execute(pool)
        .await?;
        tracing::warn!(
            "bootstrapped admin user '{}' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, \
             then change the password",
            cfg.admin_user
        );
    }

    // Also catch an already-seeded weak admin (e.g. a DB first bootstrapped with
    // admin/admin, or set up on loopback then later exposed). Only placeholder
    // passwords are testable from a stored hash — length-only-weak ones set on an
    // existing install aren't caught here, nor are case variants of a placeholder
    // (the hash pins the exact bytes; we only test the canonical spellings); the
    // bootstrap check above covers new installs case-insensitively. An admin whose
    // password was changed to a strong one passes.
    if guard_exposed {
        let hashes: Vec<String> =
            sqlx::query_scalar("SELECT pw_hash FROM users WHERE role = 'admin'")
                .fetch_all(pool)
                .await?;
        let weak = hashes.iter().any(|h| {
            WEAK_PASSWORDS
                .iter()
                .any(|w| auth::verify_password(w, h).is_ok())
        });
        if weak {
            anyhow::bail!(
                "an admin account still uses a weak/default password while binding a \
                 non-loopback address ({}). Change it (POST /me/password or an admin \
                 reset), bind 127.0.0.1, or set SHARDX_ALLOW_INSECURE_ADMIN=1 to override.",
                cfg.bind
            );
        }
    }
    Ok(())
}

/// Well-known placeholder passwords we refuse to expose. Also used to detect an
/// already-bootstrapped weak admin from its stored hash.
const WEAK_PASSWORDS: &[&str] = &[
    "admin",
    "admin123",
    "password",
    "password123",
    "secret",
    "change-me",
    "changeme",
    "changeme123",
    "changethis",
    "root",
    "test",
    "letmein",
    "qwerty",
    "123456",
];

/// A password too weak to expose on a public bind: empty, too short, or a known
/// placeholder.
pub fn is_weak_password(pw: &str) -> bool {
    pw.len() < 8 || WEAK_PASSWORDS.iter().any(|w| pw.eq_ignore_ascii_case(w))
}

pub async fn find_user(pool: &SqlitePool, id: &str) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn find_user_by_name(pool: &SqlitePool, name: &str) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = ?")
        .bind(name)
        .fetch_optional(pool)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weak_password_detection() {
        // Placeholders (case-insensitive) and too-short/empty are weak.
        for w in [
            "admin",
            "ADMIN",
            "secret",
            "change-me",
            "changethis",
            "123456",
            "",
            "short7",
        ] {
            assert!(is_weak_password(w), "{w:?} should be weak");
        }
        // A long, non-placeholder secret is fine.
        for ok in [
            "a-strong-unique-pass",
            "Xk9$2mQ!vz7Lp",
            "correct horse battery staple",
        ] {
            assert!(!is_weak_password(ok), "{ok:?} should be accepted");
        }
    }

    fn cfg(bind: &str) -> Config {
        Config {
            bind: bind.into(),
            data_dir: String::new(),
            db_path: String::new(),
            blob_dir: String::new(),
            token_secret: "t".into(),
            token_ttl_secs: 3600,
            admin_user: "admin".into(),
            admin_pass: "unused-here".into(),
            lease_ttl_secs: 90,
            snapshot_keep: 5,
            max_snapshot_bytes: 1024,
            trust_proxy: false,
            identity_dir: None,
        }
    }

    async fn mem_pool() -> SqlitePool {
        // max_connections(1) so every query hits the same in-memory database.
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        shardx_team_server::run_migrations(&pool).await.unwrap();
        pool
    }

    async fn seed_admin(pool: &SqlitePool, password: &str) {
        let hash = auth::hash_password(password).unwrap();
        sqlx::query("INSERT INTO users (id, username, pw_hash, role, created_at) VALUES ('a1','admin',?,'admin','2020-01-01T00:00:00+00:00')")
            .bind(hash)
            .execute(pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn exposed_bind_rejects_existing_weak_admin() {
        let pool = mem_pool().await;
        seed_admin(&pool, "admin").await; // the classic default
                                          // Network-facing bind + an admin still on a default password → refuse.
        assert!(bootstrap_admin(&pool, &cfg("0.0.0.0:8080")).await.is_err());
        // Same DB on a loopback bind is tolerated (local-only exposure).
        assert!(bootstrap_admin(&pool, &cfg("127.0.0.1:8080")).await.is_ok());
    }

    #[tokio::test]
    async fn every_pooled_connection_waits_long_for_the_write_lock() {
        let dir = std::env::temp_dir().join(format!("shardx-busy-{}", std::process::id()));
        let path = |p: &str| dir.join(p).to_string_lossy().into_owned();
        let cfg = Config {
            data_dir: path(""),
            db_path: path("server.db"),
            blob_dir: path("blobs"),
            ..cfg("127.0.0.1:8080")
        };
        let pool = open_pool(&cfg).await.unwrap();
        let mut conns = Vec::new();
        for _ in 0..3 {
            conns.push(pool.acquire().await.unwrap());
        }
        for conn in &mut conns {
            let ms: i64 = sqlx::query_scalar("PRAGMA busy_timeout")
                .fetch_one(&mut **conn)
                .await
                .unwrap();
            assert!(ms >= 30_000, "busy_timeout is {ms} ms");
        }
        drop(conns);
        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn the_database_runs_a_synced_rollback_journal_and_survives_an_unclosed_pool() {
        let dir = std::env::temp_dir().join(format!("shardx-journal-{}", std::process::id()));
        let path = |p: &str| dir.join(p).to_string_lossy().into_owned();
        let cfg = Config {
            data_dir: path(""),
            db_path: path("server.db"),
            blob_dir: path("blobs"),
            ..cfg("127.0.0.1:8080")
        };
        let pool = open_pool(&cfg).await.unwrap();
        let mut conn = pool.acquire().await.unwrap();
        let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        let sync: i64 = sqlx::query_scalar("PRAGMA synchronous")
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        assert_eq!(
            (mode.as_str(), sync),
            ("delete", 2),
            "rollback journal, FULL"
        );
        sqlx::query("CREATE TABLE t (v INTEGER NOT NULL)")
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("INSERT INTO t VALUES (9223372036854775807)")
            .execute(&mut *conn)
            .await
            .unwrap();
        // The process dies here: no close, no orderly shutdown.
        std::mem::forget(conn);
        std::mem::forget(pool);

        let reopened = open_pool(&cfg).await.unwrap();
        let v: i64 = sqlx::query_scalar("SELECT v FROM t")
            .fetch_one(&reopened)
            .await
            .unwrap();
        assert_eq!(v, i64::MAX, "a returned commit survives");
        let check: String = sqlx::query_scalar("PRAGMA integrity_check")
            .fetch_one(&reopened)
            .await
            .unwrap();
        assert_eq!(check, "ok");
        for sidecar in ["server.db-journal", "server.db-wal"] {
            assert!(!dir.join(sidecar).exists(), "{sidecar} left behind");
        }
        reopened.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn storage_that_cannot_be_resolved_is_refused() {
        let dir = std::env::temp_dir().join(format!("shardx-storage-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = |p: &str| dir.join(p).to_string_lossy().into_owned();
        let cfg = Config {
            data_dir: path(""),
            db_path: path("server.db"),
            blob_dir: path("missing-blobs"),
            ..cfg("127.0.0.1:8080")
        };
        let err = refuse_network_storage(&cfg).unwrap_err().to_string();
        assert!(err.contains("the blob directory"), "{err}");
        std::fs::create_dir(dir.join("missing-blobs")).unwrap();
        refuse_network_storage(&cfg).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// G2-50: storage on an SMB share fails closed before SQLite opens it. CI
    /// names a share it created in `SHARDX_TEST_SMB_DIR`; elsewhere the
    /// loopback administrative share of the temporary directory is tried.
    #[cfg(windows)]
    #[test]
    fn storage_on_an_smb_share_is_refused() {
        let share = match std::env::var_os("SHARDX_TEST_SMB_DIR") {
            Some(dir) => std::path::PathBuf::from(dir),
            None => {
                let temp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
                let local = temp.to_string_lossy().into_owned();
                let (drive, tail) = local.trim_start_matches(r"\\?\").split_once(":\\").unwrap();
                std::path::PathBuf::from(format!(r"\\localhost\{drive}$\{tail}"))
            }
        };
        if !share.exists() {
            assert!(
                std::env::var_os("SHARDX_TEST_SMB_DIR").is_none(),
                "SHARDX_TEST_SMB_DIR {share:?} is not reachable"
            );
            eprintln!("SKIPPED storage_on_an_smb_share_is_refused: no reachable SMB share");
            return;
        }
        let dir = share.to_string_lossy().into_owned();
        let cfg = Config {
            data_dir: dir.clone(),
            db_path: share.join("server.db").to_string_lossy().into_owned(),
            blob_dir: dir,
            ..cfg("127.0.0.1:8080")
        };
        let err = refuse_network_storage(&cfg).unwrap_err().to_string();
        assert!(err.contains("network share"), "{err}");
    }

    // ---- G2-50 process-kill harness (ADR 0002 Q-30: a kill at injected
    // points, no power pull). The child is this test binary running an
    // ignored test; at `SHARDX_CRASH_POINT` it prints a marker and waits for
    // the parent to kill it.

    fn crash_cfg(dir: &std::path::Path) -> Config {
        let path = |p: &str| dir.join(p).to_string_lossy().into_owned();
        Config {
            data_dir: path(""),
            db_path: path("server.db"),
            blob_dir: path("blobs"),
            ..cfg("127.0.0.1:8080")
        }
    }

    fn pause_if(point: &str) {
        if std::env::var("SHARDX_CRASH_POINT").as_deref() == Ok(point) {
            use std::io::Write;
            println!("SHARDX-CRASH-AT {point}");
            let _ = std::io::stdout().flush();
            loop {
                std::thread::sleep(std::time::Duration::from_secs(60));
            }
        }
    }

    /// Runs the ignored test `test` against `dir`, kills it once a stdout line
    /// contains `marker`, and says whether one did.
    fn kill_child(test: &str, point: &str, dir: &std::path::Path, marker: &str) -> bool {
        use std::io::BufRead;
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                test,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("SHARDX_CRASH_POINT", point)
            .env("SHARDX_CRASH_DIR", dir)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let seen = std::io::BufReader::new(child.stdout.take().unwrap())
            .lines()
            .map_while(Result::ok)
            .any(|line| line.contains(marker));
        let _ = child.kill();
        child.wait().unwrap();
        seen
    }

    async fn seeded(dir: &std::path::Path) {
        let pool = open_pool(&crash_cfg(dir)).await.unwrap();
        sqlx::query("CREATE TABLE g2_harness (k INTEGER PRIMARY KEY, v TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO g2_harness VALUES (1, 'old')")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
    }

    async fn reopened(dir: &std::path::Path) -> (Vec<(i64, String)>, String) {
        let pool = open_pool(&crash_cfg(dir)).await.unwrap();
        let rows = sqlx::query_as("SELECT k, v FROM g2_harness ORDER BY k")
            .fetch_all(&pool)
            .await
            .unwrap();
        let check = sqlx::query_scalar("PRAGMA integrity_check")
            .fetch_one(&pool)
            .await
            .unwrap();
        pool.close().await;
        (rows, check)
    }

    #[tokio::test]
    #[ignore = "child process of the crash harness"]
    async fn child_writes_one_transaction() {
        let Some(dir) = std::env::var_os("SHARDX_CRASH_DIR") else {
            return;
        };
        let pool = open_pool(&crash_cfg(std::path::Path::new(&dir)))
            .await
            .unwrap();
        let mut conn = pool.acquire().await.unwrap();
        // A tiny page cache makes the transaction spill pages into the
        // database file before COMMIT, behind a synced (hot) journal.
        sqlx::query("PRAGMA cache_size = 2")
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *conn)
            .await
            .unwrap();
        pause_if("begun");
        sqlx::query("UPDATE g2_harness SET v = 'new' WHERE k = 1")
            .execute(&mut *conn)
            .await
            .unwrap();
        pause_if("updated");
        sqlx::query("INSERT INTO g2_harness VALUES (2, 'new')")
            .execute(&mut *conn)
            .await
            .unwrap();
        pause_if("inserted");
        sqlx::query(
            "WITH RECURSIVE n(i) AS (SELECT 3 UNION ALL SELECT i + 1 FROM n WHERE i < 400)
             INSERT INTO g2_harness SELECT i, hex(randomblob(2000)) FROM n",
        )
        .execute(&mut *conn)
        .await
        .unwrap();
        pause_if("spilled");
        sqlx::query("COMMIT").execute(&mut *conn).await.unwrap();
        pause_if("committed");
    }

    /// Killed before COMMIT returns, the transaction is wholly gone once the
    /// reopen rolls back the hot journal; killed after, wholly there.
    #[tokio::test]
    async fn a_killed_transaction_reopens_old_or_new_never_half() {
        for (point, committed) in [
            ("begun", false),
            ("updated", false),
            ("inserted", false),
            ("spilled", false),
            ("committed", true),
        ] {
            let dir =
                std::env::temp_dir().join(format!("shardx-crash-{point}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            seeded(&dir).await;
            let marker = format!("SHARDX-CRASH-AT {point}");
            let test = "db::tests::child_writes_one_transaction";
            assert!(kill_child(test, point, &dir, &marker), "{point}");
            let journal = dir.join("server.db-journal");
            if point == "inserted" {
                assert!(journal.exists(), "the kill left no journal");
            }
            if point == "spilled" {
                // SQLite's journal magic, written once the journal is synced:
                // the database file already holds uncommitted pages.
                let head = std::fs::read(&journal).unwrap();
                let magic = [0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7];
                assert_eq!(head.get(..8), Some(&magic[..]), "the journal is not hot");
            }
            let (rows, check) = reopened(&dir).await;
            if committed {
                assert_eq!(rows.len(), 400, "{point}");
                assert_eq!(rows[..2], [(1, "new".into()), (2, "new".into())], "{point}");
            } else {
                assert_eq!(rows, [(1, "old".to_string())], "{point}");
            }
            assert_eq!(check, "ok", "{point}");
            // A journal whose header was never synced is not hot: SQLite
            // leaves it until the next write, which must still go through.
            let pool = open_pool(&crash_cfg(&dir)).await.unwrap();
            sqlx::query("INSERT INTO g2_harness VALUES (1000, 'after')")
                .execute(&pool)
                .await
                .unwrap();
            pool.close().await;
            assert!(!journal.exists(), "{point}: journal left after a write");
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[tokio::test]
    #[ignore = "child process of the crash harness"]
    async fn child_commits_in_a_loop() {
        let Some(dir) = std::env::var_os("SHARDX_CRASH_DIR") else {
            return;
        };
        let pool = open_pool(&crash_cfg(std::path::Path::new(&dir)))
            .await
            .unwrap();
        for k in 2_i64..i64::MAX {
            sqlx::query("INSERT INTO g2_harness VALUES (?, 'loop')")
                .bind(k)
                .execute(&pool)
                .await
                .unwrap();
            println!("COMMITTED {k}");
        }
    }

    /// Killed in a run of commits, every commit that returned is there and
    /// the rows have no gap.
    #[tokio::test]
    async fn a_kill_between_commits_keeps_every_returned_commit() {
        for target in [3_i64, 17, 60] {
            let dir = std::env::temp_dir()
                .join(format!("shardx-crash-loop-{target}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            seeded(&dir).await;
            let test = "db::tests::child_commits_in_a_loop";
            assert!(kill_child(test, "-", &dir, &format!("COMMITTED {target}")));
            let (rows, check) = reopened(&dir).await;
            let keys: Vec<i64> = rows.into_iter().map(|(k, _)| k).collect();
            let last = *keys.last().unwrap();
            assert!(last >= target, "returned commit {target} lost: last {last}");
            assert_eq!(keys, (1..=last).collect::<Vec<_>>(), "a gap or a torn row");
            assert_eq!(check, "ok");
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// A pooled writer queues behind the one holding the write lock instead
    /// of failing (busy handling, plan L102), and goes through once it is
    /// released.
    #[tokio::test]
    async fn a_second_writer_waits_for_the_write_lock() {
        let dir = std::env::temp_dir().join(format!("shardx-crash-busy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        seeded(&dir).await;
        let pool = open_pool(&crash_cfg(&dir)).await.unwrap();
        let mut holder = pool.acquire().await.unwrap();
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *holder)
            .await
            .unwrap();
        let started = std::time::Instant::now();
        let second = tokio::spawn({
            let pool = pool.clone();
            async move {
                sqlx::query("INSERT INTO g2_harness VALUES (2, 'second')")
                    .execute(&pool)
                    .await
                    .map(|_| started.elapsed())
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        assert!(!second.is_finished(), "the second writer did not wait");
        sqlx::query("COMMIT").execute(&mut *holder).await.unwrap();
        let waited = second.await.unwrap().unwrap();
        assert!(
            waited >= std::time::Duration::from_millis(350),
            "{waited:?}"
        );
        drop(holder);
        pool.close().await;
        let (rows, _) = reopened(&dir).await;
        assert_eq!(rows.len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn exposed_bind_accepts_strong_admin() {
        let pool = mem_pool().await;
        seed_admin(&pool, "a-strong-unique-password").await;
        // A changed-to-strong admin passes even on an exposed bind.
        assert!(bootstrap_admin(&pool, &cfg("0.0.0.0:8080")).await.is_ok());
    }
}
