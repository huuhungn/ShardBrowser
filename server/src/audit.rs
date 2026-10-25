//! Best-effort audit trail. Every security-relevant mutation (auth, user/ACL
//! management, env/folder/proxy CRUD, lock lifecycle, snapshot access) lands
//! here; failures are swallowed so auditing never breaks the operation itself.

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
    let _ = sqlx::query(
        "INSERT INTO audit_log (actor, action, env_id, detail, at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(actor)
    .bind(action)
    .bind(env_id)
    .bind(detail)
    .bind(util::now_rfc3339())
    .execute(db)
    .await;
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
