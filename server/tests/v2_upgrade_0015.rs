//! Migration 0015: `v2_idempotency` and the R3 shape of a `DEVICE_APPROVE` row.
use std::borrow::Cow;

use shardx_team_server::{run_migrations, run_migrations_with};
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;

async fn through(version: i64) -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let mut migrator = sqlx::migrate!("./migrations");
    migrator.migrations = Cow::Owned(
        migrator
            .iter()
            .filter(|m| m.version <= version)
            .cloned()
            .collect(),
    );
    run_migrations_with(&pool, &migrator).await.unwrap();
    pool
}

async fn exec(pool: &SqlitePool, sql: &str) -> Result<(), String> {
    sqlx::query(sql)
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

const T: &str = "x'01010101010101010101010101010101'";
const A: &str = "x'02020202020202020202020202020202'";
const D: &str = "x'03030303030303030303030303030303'";
const R: &str = "x'04040404040404040404040404040404'";
const I: &str = "x'05050505050505050505050505050505'";

/// An approval row the idempotency row can name.
fn approval() -> String {
    format!(
        "INSERT INTO v2_device_approvals VALUES ({T}, {R}, 'shardx.auth.device-approval.v2', 2, \
         {A}, {D}, randomblob(32), randomblob(32), 'tenant', {T}, 'team.device', 1, 1, 2, {I}, 0, \
         x'aa', randomblob(32), 1, 1, randomblob(64), randomblob(32), randomblob(32), x'bb', \
         randomblob(32), NULL, 't')"
    )
}

/// A `DEVICE_APPROVE` row; `extra` replaces the four R3 columns.
fn approve_row(kind: &str, scope: &str, r3: &str) -> String {
    format!(
        "INSERT INTO v2_idempotency VALUES ({I}, {T}, {D}, '{scope}', {R}, '{kind}', \
         randomblob(32), x'bb', randomblob(32), 'succeeded', 'DeviceApprovalReceiptV2', x'cc', \
         randomblob(32), 9, {r3})"
    )
}

#[tokio::test]
async fn a_device_approve_row_carries_its_four_columns_and_never_changes() {
    let pool = through(14).await;
    for sql in [
        format!("INSERT INTO v2_tenants VALUES ({T}, 'acme', 'active', NULL, 't')"),
        format!("INSERT INTO v2_accounts VALUES ({A}, {T}, 'owner', 'x', NULL, 0, 'active', 't')"),
        format!(
            "INSERT INTO v2_devices VALUES ({D}, {T}, {A}, x'aa', randomblob(32), randomblob(32), \
             1, randomblob(32), randomblob(32), 1, 'pending', NULL, 't')"
        ),
    ] {
        exec(&pool, &sql).await.unwrap();
    }
    run_migrations(&pool).await.unwrap();
    let r3 = format!("'shardx.auth.device-approval.v2', 0, {A}, {D}");

    // The approval must exist first: the replay ID is its reservation.
    let e = exec(
        &pool,
        &approve_row("DEVICE_APPROVE", "tenant.device-approve.v2", &r3),
    )
    .await
    .unwrap_err();
    assert!(e.contains("FOREIGN KEY"), "{e}");
    exec(&pool, &approval()).await.unwrap();

    // Another scope, a missing R3 column, or R3 columns on another kind.
    for sql in [
        approve_row("DEVICE_APPROVE", "other.scope", &r3),
        approve_row(
            "DEVICE_APPROVE",
            "tenant.device-approve.v2",
            &format!("'shardx.auth.device-approval.v2', 0, {A}, NULL"),
        ),
        approve_row("COMMIT", "tenant.device-approve.v2", &r3),
        // NULL slips through a plain comparison; the CHECK names it.
        approve_row("DEVICE_APPROVE", "tenant.device-approve.v2", &r3).replace(
            "'DeviceApprovalReceiptV2', x'cc'",
            "'DeviceApprovalReceiptV2', NULL",
        ),
        approve_row("DEVICE_APPROVE", "tenant.device-approve.v2", &r3)
            .replace("'DeviceApprovalReceiptV2', x'cc'", "NULL, x'cc'"),
    ] {
        let e = exec(&pool, &sql).await.unwrap_err();
        assert!(e.contains("CHECK constraint failed"), "{e}");
    }
    exec(
        &pool,
        &approve_row("DEVICE_APPROVE", "tenant.device-approve.v2", &r3),
    )
    .await
    .unwrap();

    for (sql, why) in [
        (
            "UPDATE v2_idempotency SET exact_response_bytes = x'dd'".to_string(),
            "never changes",
        ),
        (
            "DELETE FROM v2_device_approvals".to_string(),
            "never deleted",
        ),
        (
            "UPDATE v2_device_approvals SET not_after_ms = 3".to_string(),
            "never changes",
        ),
    ] {
        let e = exec(&pool, &sql).await.unwrap_err();
        assert!(e.contains(why), "{e}");
    }
    exec(&pool, "UPDATE v2_device_approvals SET revoked_at = 't'")
        .await
        .unwrap();
    let e = exec(&pool, "UPDATE v2_device_approvals SET revoked_at = 'u'")
        .await
        .unwrap_err();
    assert!(e.contains("stays revoked"), "{e}");
}

#[tokio::test]
async fn a_session_class_only_moves_from_pending_setup_to_root_setup() {
    let pool = through(15).await;
    exec(&pool, "PRAGMA foreign_keys = OFF").await.unwrap();
    let session = |id: u8, class: &str| {
        let id = format!("{id:02x}").repeat(16);
        format!(
            "INSERT INTO v2_sessions (id, tenant_id, account_id, device_id, server_instance_id, \
             restore_epoch, signing_key_id, hpke_key_id, account_token_version, class, \
             pre_device_session_id, device_session_challenge_id, pop_at_ms, access_token_hash, \
             access_expires_at_ms, refresh_token_hash, refresh_expires_at_ms, \
             absolute_expires_at_ms) VALUES (x'{id}', {T}, {A}, {D}, {I}, 0, randomblob(32), \
             randomblob(32), 0, '{class}', randomblob(16), randomblob(16), 1, randomblob(32), 2, \
             randomblob(32), 2, 2)"
        )
    };
    exec(&pool, &session(0x11, "pending_setup")).await.unwrap();
    exec(&pool, &session(0x12, "root_setup")).await.unwrap();
    exec(
        &pool,
        "UPDATE v2_sessions SET class = 'root_setup' WHERE class = 'pending_setup'",
    )
    .await
    .unwrap();
    for to in ["pending_setup", "ordinary"] {
        let e = exec(&pool, &format!("UPDATE v2_sessions SET class = '{to}'"))
            .await
            .unwrap_err();
        assert!(e.contains("only moves"), "{e}");
    }
}
