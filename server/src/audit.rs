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
        if let Some(failures) = count_read_only_failure() {
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

/// The failed audit writes since the server opened read-only. `restore
/// status` is a separate process, so the count is mirrored in this file in
/// the data directory (outside the read-only DB).
const FAILURES_FILE: &str = "audit-ro-failures";

struct ReadOnlyFailures {
    file: PathBuf,
    count: u64,
}

/// `None` outside read-only mode, where a failed write stays swallowed.
static READ_ONLY_FAILURES: Mutex<Option<ReadOnlyFailures>> = Mutex::new(None);

fn failures() -> MutexGuard<'static, Option<ReadOnlyFailures>> {
    READ_ONLY_FAILURES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Start the count at zero when the server opens read-only; any other start
/// removes a count a previous read-only run left behind.
pub fn init_read_only_count(data_dir: &str, read_only: bool) -> std::io::Result<()> {
    let file = Path::new(data_dir).join(FAILURES_FILE);
    let mut state = failures();
    if read_only {
        std::fs::write(&file, "0")?;
        *state = Some(ReadOnlyFailures { file, count: 0 });
    } else {
        *state = None;
        match std::fs::remove_file(&file) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
    }
    Ok(())
}

/// Count one failed write; `None` outside read-only mode.
fn count_read_only_failure() -> Option<u64> {
    let mut state = failures();
    let state = state.as_mut()?;
    state.count += 1;
    if let Err(e) = std::fs::write(&state.file, state.count.to_string()) {
        tracing::error!(error = %e, "cannot record the failed audit write count");
    }
    Some(state.count)
}

/// The count a read-only server left in `data_dir`; zero if none ran.
pub fn read_only_failures(data_dir: &str) -> anyhow::Result<u64> {
    use anyhow::Context;
    let file = Path::new(data_dir).join(FAILURES_FILE);
    match std::fs::read_to_string(&file) {
        Ok(text) => text
            .trim()
            .parse()
            .with_context(|| format!("{} is not a count", file.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(e).with_context(|| format!("reading {}", file.display())),
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

    /// WI-AUDIT-RO: a failed audit write is logged with its action and actor
    /// and counted, the count is readable by `restore status`, and a start
    /// outside read-only mode discards it.
    #[tokio::test]
    async fn a_failed_read_only_audit_write_is_logged_and_counted() {
        let dir = std::env::temp_dir().join(format!("shardx-audit-ro-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let data_dir = dir.to_string_lossy().into_owned();
        // No `audit_log` table, so every insert fails.
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        let captured = Captured::default();
        let sink = captured.clone();
        let _guard = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_writer(move || sink.clone())
                .with_ansi(false)
                .finish(),
        );

        // Outside read-only mode a failed write stays silent and uncounted.
        init_read_only_count(&data_dir, false).unwrap();
        log(&pool, Some("u1"), "login_failed", None, "x").await;
        assert!(captured.0.lock().unwrap().is_empty());
        assert_eq!(read_only_failures(&data_dir).unwrap(), 0);

        init_read_only_count(&data_dir, true).unwrap();
        assert_eq!(read_only_failures(&data_dir).unwrap(), 0);
        log(&pool, Some("u1"), "login_failed", None, "x").await;
        log(&pool, None, "env.create", None, "y").await;
        assert_eq!(read_only_failures(&data_dir).unwrap(), 2);
        let logged = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        assert_eq!(logged.matches("ERROR").count(), 2, "{logged}");
        assert!(
            logged.contains("login_failed") && logged.contains("u1"),
            "{logged}"
        );
        assert!(logged.contains("env.create"), "{logged}");

        init_read_only_count(&data_dir, false).unwrap();
        assert_eq!(read_only_failures(&data_dir).unwrap(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
