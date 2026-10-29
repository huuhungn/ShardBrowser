//! Best-effort audit trail. Every security-relevant mutation (auth, user/ACL
//! management, env/folder/proxy CRUD, lock lifecycle, snapshot access) lands
//! here; failures never break the operation itself. While the DB is read-only
//! (a restore in progress or K2) a failed write is logged and counted instead
//! of dropped silently (ADR 0002 WI-AUDIT-RO).

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use axum::extract::{Query, State};
use axum::Json;
use sqlx::{SqliteConnection, SqlitePool};

use crate::auth::AuthUser;
use crate::error::AppError;
use crate::models::{AuditEntry, AuditQuery};
use crate::state::AppState;
use crate::util;

pub async fn log(
    db: &SqlitePool,
    actor: Option<&str>,
    action: &str,
    env_id: Option<&str>,
    detail: &str,
) {
    let written = sqlx::query(
        "INSERT INTO audit_log (actor, action, env_id, detail, at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(actor)
    .bind(action)
    .bind(env_id)
    .bind(detail)
    .bind(util::now_rfc3339())
    .execute(db)
    .await;
    if let Err(e) = written {
        // Off the async worker (an fsync); awaited, so the count is in the file
        // before the caller goes on.
        let counted = tokio::task::spawn_blocking(count_read_only_failure)
            .await
            .ok()
            .flatten();
        if let Some(failures) = counted {
            tracing::error!(
                action,
                actor = actor.unwrap_or("-"),
                failures,
                error = %e,
                "audit write failed while the database is read-only"
            );
        }
    }
}

/// The failed audit writes of the restore episodes a read-only server has
/// counted (a restore in progress, or K2's incident). `restore status` is a
/// separate process, so the counts are mirrored in this file in the data
/// directory (outside the read-only DB), one `<episode> <count>` per line. A
/// read-only restart in the same episode continues its count. An episode's key
/// can change while the restore runs (the manifest appears), and a non-zero
/// count is never dropped for that: the old key's line stays until `restore
/// clear-audit-count` acknowledges it. `restore commit` and `restore abort`
/// print their own episode and clear only that line.
const FAILURES_FILE: &str = "audit-ro-failures";

struct ReadOnlyFailures {
    file: PathBuf,
    episode: String,
    count: u64,
    /// The non-zero counts of other episodes, written back with every update.
    kept: Vec<(String, u64)>,
}

impl ReadOnlyFailures {
    fn entries(&self) -> Vec<(String, u64)> {
        let mut all = self.kept.clone();
        all.push((self.episode.clone(), self.count));
        all
    }
}

/// `None` outside read-only mode, where a failed write stays swallowed.
static READ_ONLY_FAILURES: Mutex<Option<ReadOnlyFailures>> = Mutex::new(None);

fn failures() -> MutexGuard<'static, Option<ReadOnlyFailures>> {
    READ_ONLY_FAILURES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// What the count file holds.
enum Counts {
    Absent,
    /// Something that is not a list of `<episode> <count>` lines.
    Unreadable,
    Entries(Vec<(String, u64)>),
}

/// Reads the count file. A link, a reparse point or a directory at its name
/// is refused by name: the count is never written through one.
fn read_counts(file: &Path) -> anyhow::Result<Counts> {
    use anyhow::Context;
    match std::fs::symlink_metadata(file) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Counts::Absent),
        Err(e) => return Err(e).with_context(|| format!("checking {}", file.display())),
        Ok(m) if crate::identity::is_link(&m) => anyhow::bail!(
            "{} is a link or reparse point; remove it, the audit failure count is never \
             written through one",
            file.display()
        ),
        Ok(m) if !m.is_file() => anyhow::bail!(
            "{} is not a regular file; remove it, the audit failure count needs that name",
            file.display()
        ),
        Ok(_) => {}
    }
    Ok(std::fs::read_to_string(file)
        .ok()
        .and_then(|text| parse_counts(&text))
        .map_or(Counts::Unreadable, Counts::Entries))
}

fn parse_counts(text: &str) -> Option<Vec<(String, u64)>> {
    let entries = text
        .lines()
        .map(|line| {
            let (episode, count) = line.split_once(' ')?;
            Some((episode.to_string(), count.parse().ok()?))
        })
        .collect::<Option<Vec<_>>>()?;
    (!entries.is_empty()).then_some(entries)
}

/// Replaces the count file atomically: a temp file, fsync, rename, fsync of
/// the directory, so a crash leaves the old counts or the new ones, never a
/// torn file.
fn write_counts(file: &Path, entries: &[(String, u64)]) -> anyhow::Result<()> {
    use anyhow::Context;
    use std::io::Write;
    let tmp = file.with_extension("tmp");
    match std::fs::remove_file(&tmp) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            return Err(e).with_context(|| format!("removing {}", tmp.display()))
        }
        _ => {}
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .with_context(|| format!("writing {}", tmp.display()))?;
    for (episode, count) in entries {
        writeln!(f, "{episode} {count}")?;
    }
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, file).with_context(|| format!("installing {}", file.display()))?;
    if let Some(dir) = file.parent() {
        crate::identity::sync_dir(dir).with_context(|| format!("fsync of {}", dir.display()))?;
    }
    Ok(())
}

/// Opens the count for `episode` when the server starts read-only, continuing
/// the count of the same episode and starting another at zero, next to the
/// non-zero counts of the episodes before it. `None` is a normal start: no
/// count is kept and earlier ones are left for `restore status`, `restore
/// commit`, `restore abort` or `restore clear-audit-count` to report.
pub fn init_read_only_count(data_dir: &str, episode: Option<&str>) -> anyhow::Result<()> {
    let file = Path::new(data_dir).join(FAILURES_FILE);
    let mut state = failures();
    let Some(episode) = episode else {
        *state = None;
        return Ok(());
    };
    let before = match read_counts(&file)? {
        Counts::Entries(entries) => entries,
        Counts::Absent => Vec::new(),
        Counts::Unreadable => {
            tracing::warn!(
                "{} is not a count file; counting again from zero",
                file.display()
            );
            Vec::new()
        }
    };
    let count = before
        .iter()
        .find_map(|(e, c)| (e == episode).then_some(*c))
        .unwrap_or(0);
    let kept: Vec<_> = before
        .into_iter()
        .filter(|(e, c)| e != episode && *c > 0)
        .collect();
    let new = ReadOnlyFailures {
        file,
        episode: episode.to_string(),
        count,
        kept,
    };
    write_counts(&new.file, &new.entries())?;
    *state = Some(new);
    Ok(())
}

/// Count one failed write; `None` outside read-only mode.
fn count_read_only_failure() -> Option<u64> {
    let mut state = failures();
    let state = state.as_mut()?;
    state.count += 1;
    if let Err(e) = write_counts(&state.file, &state.entries()) {
        tracing::error!(error = %e, "cannot record the failed audit write count");
    }
    Some(state.count)
}

/// The count of `episode` as `restore status` prints it: the number, or
/// `unreadable` when the file cannot be read, which never fails the command.
pub fn read_only_failures(data_dir: &str, episode: &str) -> String {
    match read_counts(&Path::new(data_dir).join(FAILURES_FILE)) {
        Ok(Counts::Absent) => "0".into(),
        Ok(Counts::Entries(entries)) => entries
            .iter()
            .find_map(|(e, c)| (e == episode).then(|| c.to_string()))
            .unwrap_or_else(|| "0".into()),
        Ok(Counts::Unreadable) | Err(_) => "unreadable".into(),
    }
}

/// The counts kept for episodes other than `except`, as `restore status`
/// prints them, in every class: `<episode> <count>`. An unreadable file shows
/// as `unreadable` unless `except` already reports it.
pub fn kept_failures(data_dir: &str, except: Option<&str>) -> Vec<String> {
    match read_counts(&Path::new(data_dir).join(FAILURES_FILE)) {
        Ok(Counts::Entries(entries)) => entries
            .into_iter()
            .filter(|(e, c)| Some(e.as_str()) != except && *c > 0)
            .map(|(e, c)| format!("{e} {c}"))
            .collect(),
        Ok(Counts::Unreadable) | Err(_) if except.is_none() => vec!["unreadable".into()],
        _ => Vec::new(),
    }
}

/// Removes `episode`'s line from the count file (the file itself when it was
/// the last), returning its count. The other episodes' lines stay.
pub fn clear_episode(data_dir: &str, episode: &str) -> anyhow::Result<Option<u64>> {
    let file = Path::new(data_dir).join(FAILURES_FILE);
    let entries = match read_counts(&file)? {
        Counts::Absent => return Ok(None),
        Counts::Unreadable => {
            anyhow::bail!("{} is not a count file; remove it by hand", file.display())
        }
        Counts::Entries(entries) => entries,
    };
    let cleared = entries
        .iter()
        .find_map(|(e, c)| (e == episode).then_some(*c));
    let rest: Vec<_> = entries.into_iter().filter(|(e, _)| e != episode).collect();
    if rest.is_empty() {
        std::fs::remove_file(&file)
            .map_err(|e| anyhow::anyhow!("cannot remove {}: {e}", file.display()))?;
    } else if cleared.is_some() {
        write_counts(&file, &rest)?;
    }
    Ok(cleared)
}

/// Clears `episode` when its restore ends. A name that is not a plain file is
/// left alone and reported, since the restore itself has finished.
pub fn clear_read_only_count(data_dir: &str, episode: &str) {
    if let Err(e) = clear_episode(data_dir, episode) {
        eprintln!("warning: {e:#}");
    }
}

/// A structured v2 audit row for an offline operator command, inside the
/// command's own transaction: if it fails, the command's writes roll back.
/// ADR 0001 D3: an offline action has no live account or device.
pub async fn insert_offline(
    conn: &mut SqliteConnection,
    tenant_id: &[u8],
    action: &str,
    target_type: &str,
    target_id: &[u8],
    request_id: &[u8; 16],
) -> anyhow::Result<()> {
    use anyhow::Context;
    sqlx::query(
        "INSERT INTO v2_audit_events \
         (tenant_id, id, actor_account_id, actor_device_id, action, target_type, target_id, \
          outcome, reason_code, request_id, created_at) \
         VALUES (?, ?, NULL, NULL, ?, ?, ?, 'success', 'offline_operator_cli', ?, ?)",
    )
    .bind(tenant_id)
    .bind(uuid::Uuid::new_v4().into_bytes().as_slice())
    .bind(action)
    .bind(target_type)
    .bind(target_id)
    .bind(request_id.as_slice())
    .bind(util::now_rfc3339())
    .execute(conn)
    .await
    .context("inserting the audit event")?;
    Ok(())
}

/// Admin: newest-first audit entries, optionally filtered by env/action.
pub async fn list(
    State(app): State<AppState>,
    user: AuthUser,
    Query(q): Query<AuditQuery>,
) -> Result<Json<Vec<AuditEntry>>, AppError> {
    user.require_admin()?;
    let limit = q.limit.unwrap_or(200).clamp(1, 1000);
    let rows = sqlx::query_as::<_, AuditEntry>(
        "SELECT * FROM audit_log \
         WHERE (?1 IS NULL OR env_id = ?1) AND (?2 IS NULL OR action = ?2) \
         ORDER BY id DESC LIMIT ?3",
    )
    .bind(&q.env_id)
    .bind(&q.action)
    .bind(limit)
    .fetch_all(&app.db)
    .await?;
    Ok(Json(rows))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// The counter is one process-wide state, so these tests take turns.
    static TURN: Mutex<()> = Mutex::new(());

    struct Fixture {
        _turn: MutexGuard<'static, ()>,
        dir: PathBuf,
        data_dir: String,
        pool: SqlitePool,
    }

    impl Fixture {
        /// A data directory and a pool with no `audit_log` table, so every
        /// insert fails.
        async fn new(name: &str) -> Self {
            let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
            let turn = TURN
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let dir =
                std::env::temp_dir().join(format!("shardx-audit-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self {
                _turn: turn,
                data_dir: dir.to_string_lossy().into_owned(),
                dir,
                pool,
            }
        }

        async fn fail(&self, n: usize) {
            for _ in 0..n {
                log(&self.pool, Some("u1"), "login_failed", None, "x").await;
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            *failures() = None;
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// WI-AUDIT-RO: a failed audit write is logged with its action and actor
    /// and counted, and the count is readable by `restore status`. A normal
    /// start counts nothing and leaves an earlier count to be reported.
    #[tokio::test]
    async fn a_failed_read_only_audit_write_is_logged_and_counted() {
        let f = Fixture::new("count").await;
        let captured = Captured::default();
        let sink = captured.clone();
        let _guard = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_writer(move || sink.clone())
                .with_ansi(false)
                .finish(),
        );

        // Outside read-only mode a failed write stays silent and uncounted.
        init_read_only_count(&f.data_dir, None).unwrap();
        f.fail(1).await;
        assert!(captured.0.lock().unwrap().is_empty());
        assert_eq!(read_only_failures(&f.data_dir, "e1"), "0");

        init_read_only_count(&f.data_dir, Some("e1")).unwrap();
        assert_eq!(read_only_failures(&f.data_dir, "e1"), "0");
        log(&f.pool, Some("u1"), "login_failed", None, "x").await;
        log(&f.pool, None, "env.create", None, "y").await;
        assert_eq!(read_only_failures(&f.data_dir, "e1"), "2");
        let logged = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        assert_eq!(logged.matches("ERROR").count(), 2, "{logged}");
        assert!(
            logged.contains("login_failed") && logged.contains("u1"),
            "{logged}"
        );
        assert!(logged.contains("env.create"), "{logged}");

        // A normal start keeps the count for `restore commit` to report.
        init_read_only_count(&f.data_dir, None).unwrap();
        assert_eq!(read_only_failures(&f.data_dir, "e1"), "2");
        clear_read_only_count(&f.data_dir, "e1");
        assert_eq!(read_only_failures(&f.data_dir, "e1"), "0");
        assert!(!f.dir.join(FAILURES_FILE).exists());
    }

    /// L1: the count is cumulative over a restore episode, whatever restarts
    /// the server goes through, and another episode starts from zero.
    #[tokio::test]
    async fn the_count_continues_across_read_only_restarts_of_one_episode() {
        let f = Fixture::new("episode").await;
        init_read_only_count(&f.data_dir, Some("txn-a")).unwrap();
        f.fail(3).await;
        init_read_only_count(&f.data_dir, Some("txn-a")).unwrap();
        assert_eq!(read_only_failures(&f.data_dir, "txn-a"), "3");
        f.fail(2).await;
        assert_eq!(read_only_failures(&f.data_dir, "txn-a"), "5");
        // A normal start in between does not end the episode.
        init_read_only_count(&f.data_dir, None).unwrap();
        init_read_only_count(&f.data_dir, Some("txn-a")).unwrap();
        assert_eq!(read_only_failures(&f.data_dir, "txn-a"), "5");
        // Another episode never inherits it, and does not report it.
        assert_eq!(read_only_failures(&f.data_dir, "record-b"), "0");
        init_read_only_count(&f.data_dir, Some("record-b")).unwrap();
        assert_eq!(read_only_failures(&f.data_dir, "record-b"), "0");
        f.fail(1).await;
        assert_eq!(read_only_failures(&f.data_dir, "record-b"), "1");
    }

    /// N2: when an episode's key changes mid-restore, the old key's non-zero
    /// count is kept next to the new one, listed in every class, and cleared
    /// only by name; a zero count is not worth keeping.
    #[tokio::test]
    async fn a_changed_episode_key_keeps_the_old_count_until_it_is_cleared_by_name() {
        let f = Fixture::new("switch").await;
        let file = f.dir.join(FAILURES_FILE);
        init_read_only_count(&f.data_dir, Some("zero")).unwrap();
        init_read_only_count(&f.data_dir, Some("record-a")).unwrap();
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "record-a 0
"
        );
        f.fail(2).await;
        init_read_only_count(&f.data_dir, Some("txn-b")).unwrap();
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "record-a 2
txn-b 0
"
        );
        f.fail(1).await;
        assert_eq!(read_only_failures(&f.data_dir, "txn-b"), "1");
        assert_eq!(read_only_failures(&f.data_dir, "record-a"), "2");
        assert_eq!(kept_failures(&f.data_dir, Some("txn-b")), ["record-a 2"]);
        // A class with no episode of its own (K3) lists both.
        assert_eq!(kept_failures(&f.data_dir, None), ["record-a 2", "txn-b 1"]);
        // A restart on the new key keeps the old line.
        init_read_only_count(&f.data_dir, Some("txn-b")).unwrap();
        f.fail(1).await;
        assert_eq!(kept_failures(&f.data_dir, Some("txn-b")), ["record-a 2"]);
        assert_eq!(read_only_failures(&f.data_dir, "txn-b"), "2");

        // The restore's own end clears its own line only.
        clear_read_only_count(&f.data_dir, "txn-b");
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "record-a 2
"
        );
        assert_eq!(clear_episode(&f.data_dir, "txn-b").unwrap(), None);
        assert_eq!(clear_episode(&f.data_dir, "record-a").unwrap(), Some(2));
        assert!(!file.exists());
        assert_eq!(clear_episode(&f.data_dir, "record-a").unwrap(), None);

        // An unreadable file is not guessed at.
        std::fs::write(&file, "junk").unwrap();
        assert!(clear_episode(&f.data_dir, "e1").is_err());
        assert_eq!(kept_failures(&f.data_dir, None), ["unreadable"]);
        assert!(kept_failures(&f.data_dir, Some("e1")).is_empty());
    }

    /// L2: the count is replaced atomically, and a file that is not a count
    /// is reported as unreadable instead of failing the command.
    #[tokio::test]
    async fn the_count_is_written_atomically_and_an_unreadable_one_is_reported() {
        let f = Fixture::new("atomic").await;
        init_read_only_count(&f.data_dir, Some("e1")).unwrap();
        f.fail(2).await;
        assert!(!f.dir.join("audit-ro-failures.tmp").exists());
        let file = f.dir.join(FAILURES_FILE);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "e1 2\n");

        for torn in ["", "e1", "e1 x", "e1 "] {
            std::fs::write(&file, torn).unwrap();
            assert_eq!(
                read_only_failures(&f.data_dir, "e1"),
                "unreadable",
                "{torn:?}"
            );
        }
        // A server that finds one starts the episode again from zero.
        init_read_only_count(&f.data_dir, Some("e1")).unwrap();
        assert_eq!(read_only_failures(&f.data_dir, "e1"), "0");
        // A leftover temp file from a crash does not block the next write.
        std::fs::write(f.dir.join("audit-ro-failures.tmp"), "junk").unwrap();
        f.fail(1).await;
        assert_eq!(read_only_failures(&f.data_dir, "e1"), "1");
    }

    /// L4: a directory or a link at the count's name is refused by name, never
    /// written through, and a normal start does not touch it.
    #[tokio::test]
    async fn a_directory_or_link_at_the_count_path_is_refused_by_name() {
        let f = Fixture::new("squat").await;
        let file = f.dir.join(FAILURES_FILE);
        std::fs::create_dir(&file).unwrap();
        let e = init_read_only_count(&f.data_dir, Some("e1")).unwrap_err();
        assert!(e.to_string().contains("not a regular file"), "{e:#}");
        assert_eq!(read_only_failures(&f.data_dir, "e1"), "unreadable");
        init_read_only_count(&f.data_dir, None).unwrap();
        assert!(file.is_dir());
        // `restore commit` and `abort` leave it and go on.
        clear_read_only_count(&f.data_dir, "e1");
        assert!(file.is_dir());
        std::fs::remove_dir(&file).unwrap();

        // A link at the name (a junction on Windows, which needs no privilege,
        // a symbolic link elsewhere): its target is never written through.
        let target = f.dir.join("elsewhere");
        std::fs::create_dir(&target).unwrap();
        #[cfg(windows)]
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&file)
            .arg(&target)
            .output()
            .unwrap()
            .status
            .success();
        #[cfg(unix)]
        let made = std::os::unix::fs::symlink(&target, &file).is_ok();
        assert!(made, "the test could not make a link");
        let e = init_read_only_count(&f.data_dir, Some("e1")).unwrap_err();
        assert!(e.to_string().contains("link or reparse point"), "{e:#}");
        assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0);
        assert_eq!(read_only_failures(&f.data_dir, "e1"), "unreadable");
        clear_read_only_count(&f.data_dir, "e1");
        assert!(std::fs::symlink_metadata(&file).is_ok());
    }
}
