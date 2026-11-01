//! Migration 0014: enrollment challenges move onto the pre-device ticket.
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

#[tokio::test]
async fn old_challenges_are_dropped_and_new_ones_stay_settled() {
    let pool = through(13).await;
    for sql in [
        "INSERT INTO v2_tenants VALUES (x'01010101010101010101010101010101', 'acme', 'active', NULL, 't')",
        "INSERT INTO v2_accounts VALUES (x'02020202020202020202020202020202', \
         x'01010101010101010101010101010101', 'owner', 'x', NULL, 0, 'active', 't')",
        // An in-flight enrollment of the old shape: nonce hash and key commitment.
        "INSERT INTO v2_enrollment_challenges VALUES (x'03030303030303030303030303030303', \
         x'01010101010101010101010101010101', zeroblob(16), 0, zeroblob(32), zeroblob(32), \
         '2099', NULL)",
    ] {
        exec(&pool, sql).await.unwrap();
    }
    run_migrations(&pool).await.unwrap();
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM v2_enrollment_challenges")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        rows, 0,
        "an old challenge binds nothing the new proof covers"
    );

    for sql in [
        "INSERT INTO v2_pre_device_sessions (id, token_hash, server_instance_id, restore_epoch, \
         tenant_id, account_id, account_token_version, created_at_ms, expires_at_ms) VALUES \
         (x'04040404040404040404040404040404', randomblob(32), zeroblob(16), 0, \
          x'01010101010101010101010101010101', x'02020202020202020202020202020202', 0, 1, 600001)",
        "INSERT INTO v2_enrollment_challenges (id, pre_device_session_id, tenant_id, account_id, \
         binding_bytes, created_at_ms, expires_at_ms) VALUES \
         (x'05050505050505050505050505050505', x'04040404040404040404040404040404', \
          x'01010101010101010101010101010101', x'02020202020202020202020202020202', x'aa', 1, 120001)",
    ] {
        exec(&pool, sql).await.unwrap();
    }
    // Two minutes at most, and the binding is fixed.
    let e = exec(
        &pool,
        "INSERT INTO v2_enrollment_challenges (id, pre_device_session_id, tenant_id, account_id, \
         binding_bytes, created_at_ms, expires_at_ms) VALUES \
         (x'06060606060606060606060606060606', x'04040404040404040404040404040404', \
          x'01010101010101010101010101010101', x'02020202020202020202020202020202', x'aa', 1, 120002)",
    )
    .await
    .unwrap_err();
    assert!(e.contains("CHECK constraint failed"), "{e}");
    let e = exec(
        &pool,
        "UPDATE v2_enrollment_challenges SET binding_bytes = x'bb'",
    )
    .await
    .unwrap_err();
    assert!(e.contains("binding never changes"), "{e}");
    exec(
        &pool,
        "UPDATE v2_enrollment_challenges SET consumed_at_ms = 2",
    )
    .await
    .unwrap();
    let e = exec(
        &pool,
        "UPDATE v2_enrollment_challenges SET consumed_at_ms = NULL",
    )
    .await
    .unwrap_err();
    assert!(
        e.contains("settled enrollment challenge never changes"),
        "{e}"
    );
}
