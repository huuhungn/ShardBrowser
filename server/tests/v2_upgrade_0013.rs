//! Migration 0013: pre-device tickets, device-session challenges and the
//! rebuilt `v2_sessions` (ADR 0001 R2).
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

/// A tenant, its account and a pending device, in the 0012 schema.
async fn seed(pool: &SqlitePool) {
    for sql in [
        "INSERT INTO v2_tenants VALUES (x'01010101010101010101010101010101', 'acme', 'active', NULL, 't')",
        "INSERT INTO v2_accounts VALUES (x'02020202020202020202020202020202', \
         x'01010101010101010101010101010101', 'owner', 'x', NULL, 0, 'active', 't')",
        "INSERT INTO v2_devices VALUES (x'03030303030303030303030303030303', \
         x'01010101010101010101010101010101', x'02020202020202020202020202020202', x'aa', \
         zeroblob(32), zeroblob(32), 1, randomblob(32), zeroblob(32), 1, 'pending', NULL, 't')",
    ] {
        exec(pool, sql).await.unwrap();
    }
}

const OLD_SESSION: &str = "INSERT INTO v2_sessions VALUES (x'04040404040404040404040404040404', \
     x'01010101010101010101010101010101', x'02020202020202020202020202020202', \
     x'03030303030303030303030303030303', zeroblob(32), '2099', ";

#[tokio::test]
async fn a_live_old_session_stops_the_migration() {
    let pool = through(12).await;
    seed(&pool).await;
    exec(&pool, &format!("{OLD_SESSION}NULL)")).await.unwrap();
    let error = run_migrations(&pool).await.unwrap_err().to_string();
    assert!(error.contains("m0013_live_v2_session_found"), "{error}");
    let left: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM sqlite_master WHERE name = 'v2_pre_device_sessions'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(left, 0, "nothing of 0013 remains");
}

#[tokio::test]
async fn revoked_old_sessions_are_dropped() {
    let pool = through(12).await;
    seed(&pool).await;
    exec(&pool, &format!("{OLD_SESSION}'t')")).await.unwrap();
    run_migrations(&pool).await.unwrap();
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM v2_sessions")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 0);
    assert!(sqlx::query("PRAGMA foreign_key_check")
        .fetch_all(&pool)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn settled_rows_and_bindings_never_change() {
    let pool = through(13).await;
    seed(&pool).await;
    for sql in [
        "INSERT INTO v2_pre_device_sessions (id, token_hash, server_instance_id, restore_epoch, \
         tenant_id, account_id, account_token_version, created_at_ms, expires_at_ms) VALUES \
         (x'05050505050505050505050505050505', randomblob(32), zeroblob(16), 0, \
          x'01010101010101010101010101010101', x'02020202020202020202020202020202', 0, 1, 600001)",
        "INSERT INTO v2_device_session_challenges (id, pre_device_session_id, tenant_id, \
         account_id, device_id, binding_bytes, secret_hash, created_at_ms, expires_at_ms) VALUES \
         (x'06060606060606060606060606060606', x'05050505050505050505050505050505', \
          x'01010101010101010101010101010101', x'02020202020202020202020202020202', \
          x'03030303030303030303030303030303', x'aa', zeroblob(32), 1, 120001)",
    ] {
        exec(&pool, sql).await.unwrap();
    }
    let refused = [
        // A ticket lives at most ten minutes, a challenge two.
        (
            "UPDATE v2_pre_device_sessions SET expires_at_ms = 700000",
            "binding never changes",
        ),
        (
            "UPDATE v2_device_session_challenges SET binding_bytes = x'bb'",
            "binding never changes",
        ),
    ];
    for (sql, why) in refused {
        let e = exec(&pool, sql).await.unwrap_err();
        assert!(e.contains(why), "{sql}: {e}");
    }
    exec(
        &pool,
        "UPDATE v2_device_session_challenges SET consumed_at_ms = 2",
    )
    .await
    .unwrap();
    exec(
        &pool,
        "UPDATE v2_pre_device_sessions SET consumed_at_ms = 2",
    )
    .await
    .unwrap();
    for sql in [
        "UPDATE v2_device_session_challenges SET consumed_at_ms = NULL",
        "UPDATE v2_pre_device_sessions SET revoked_at_ms = 3, consumed_at_ms = NULL",
    ] {
        let e = exec(&pool, sql).await.unwrap_err();
        assert!(e.contains("never changes"), "{sql}: {e}");
    }

    exec(
        &pool,
        "INSERT INTO v2_sessions (id, tenant_id, account_id, device_id, server_instance_id, \
         restore_epoch, signing_key_id, hpke_key_id, account_token_version, class, \
         pre_device_session_id, device_session_challenge_id, pop_at_ms, access_token_hash, \
         access_expires_at_ms, refresh_token_hash, refresh_expires_at_ms, absolute_expires_at_ms) \
         VALUES (x'07070707070707070707070707070707', x'01010101010101010101010101010101', \
         x'02020202020202020202020202020202', x'03030303030303030303030303030303', zeroblob(16), \
         0, zeroblob(32), randomblob(32), 0, 'pending_setup', x'05050505050505050505050505050505', \
         x'06060606060606060606060606060606', 2, randomblob(32), 300002, randomblob(32), \
         1800002, 1800002)",
    )
    .await
    .unwrap();
    for (sql, why) in [
        (
            "UPDATE v2_sessions SET device_id = x'08'",
            "binding never changes",
        ),
        (
            "UPDATE v2_sessions SET absolute_expires_at_ms = 1800003",
            "binding never changes",
        ),
        // No expiry may pass the absolute bound (the 30-minute setup bound
        // has its own case below).
        (
            "UPDATE v2_sessions SET refresh_expires_at_ms = 1800003",
            "CHECK constraint failed",
        ),
        (
            "UPDATE v2_sessions SET class = 'admin'",
            "CHECK constraint failed",
        ),
    ] {
        let e = exec(&pool, sql).await.unwrap_err();
        assert!(e.contains(why), "{sql}: {e}");
    }
    exec(&pool, "UPDATE v2_sessions SET revoked_at_ms = 3")
        .await
        .unwrap();
    let e = exec(&pool, "UPDATE v2_sessions SET revoked_at_ms = NULL")
        .await
        .unwrap_err();
    assert!(e.contains("revoked v2 session never changes"), "{e}");

    // A setup session ends within 30 minutes of its proof; other classes may not.
    exec(
        &pool,
        "INSERT INTO v2_device_session_challenges (id, pre_device_session_id, tenant_id, \
         account_id, device_id, binding_bytes, secret_hash, created_at_ms, expires_at_ms) VALUES \
         (x'0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a', x'05050505050505050505050505050505', \
          x'01010101010101010101010101010101', x'02020202020202020202020202020202', \
          x'03030303030303030303030303030303', x'aa', zeroblob(32), 1, 120001)",
    )
    .await
    .unwrap();
    let long = |class: &str| {
        format!(
            "INSERT INTO v2_sessions (id, tenant_id, account_id, device_id, server_instance_id, \
             restore_epoch, signing_key_id, hpke_key_id, account_token_version, class, \
             pre_device_session_id, device_session_challenge_id, pop_at_ms, access_token_hash, \
             access_expires_at_ms, refresh_token_hash, refresh_expires_at_ms, \
             absolute_expires_at_ms) VALUES (x'09090909090909090909090909090909', \
             x'01010101010101010101010101010101', x'02020202020202020202020202020202', \
             x'03030303030303030303030303030303', zeroblob(16), 0, zeroblob(32), randomblob(32), \
             0, '{class}', x'05050505050505050505050505050505', \
             x'0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a', 2, randomblob(32), 300002, randomblob(32), \
             1800003, 1800003)"
        )
    };
    let e = exec(&pool, &long("pending_setup")).await.unwrap_err();
    assert!(e.contains("CHECK constraint failed"), "{e}");
    exec(&pool, &long("ordinary")).await.unwrap();
}
