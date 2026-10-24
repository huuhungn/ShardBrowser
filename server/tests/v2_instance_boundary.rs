//! Migration 0011: key generations bound to the server instance, and each
//! tenant's active root pointer reconciled with its root rows (ADR 0001 Q3).
use std::borrow::Cow;
use std::collections::BTreeMap;

use shardx_team_server::{run_migrations, run_migrations_with};
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;

const INSTANCE: u8 = 0x11;
const TENANT: u8 = 1;
const FLEET: u8 = 0x40;
const ROOT_KEY: u8 = 0x20;
const FKEK: u8 = 0x41;

fn b(n: u8) -> Vec<u8> {
    vec![n; 16]
}

fn k(n: u8) -> Vec<u8> {
    vec![n; 32]
}

/// A database migrated through 0010, the schema 0011 upgrades.
async fn before_0011() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let mut migrator = sqlx::migrate!("./migrations");
    migrator.migrations = Cow::Owned(
        migrator
            .iter()
            .filter(|m| m.version <= 10)
            .cloned()
            .collect(),
    );
    run_migrations_with(&pool, &migrator).await.unwrap();
    pool
}

async fn exec(pool: &SqlitePool, sql: &str) {
    sqlx::query(sql).execute(pool).await.unwrap();
}

async fn mirror(pool: &SqlitePool, instance: u8) {
    sqlx::query("INSERT INTO v2_server_state VALUES (1, ?, 0, ?, 't')")
        .bind(b(instance))
        .bind(k(0x12))
        .execute(pool)
        .await
        .unwrap();
}

async fn tenant(pool: &SqlitePool, id: u8, pointer: i64) {
    sqlx::query("INSERT INTO v2_tenants VALUES (?, ?, 'active', ?, 't')")
        .bind(b(id))
        .bind(format!("tenant-{id}"))
        .bind(pointer)
        .execute(pool)
        .await
        .unwrap();
}

/// Pre-0011 shape: no instance column.
async fn root_generation(pool: &SqlitePool, tenant: u8, generation: i64, state: &str) {
    sqlx::query(
        "INSERT INTO v2_root_key_generations (tenant_id, generation, root_key_id, state, created_at) \
         VALUES (?, ?, ?, ?, 't')",
    )
    .bind(b(tenant))
    .bind(generation)
    .bind(k(ROOT_KEY + generation as u8))
    .bind(state)
    .execute(pool)
    .await
    .unwrap();
}

async fn account_and_device(pool: &SqlitePool) {
    sqlx::query(
        "INSERT INTO v2_accounts (id, tenant_id, username, pw_hash, status, created_at) \
         VALUES (?, ?, 'owner', 'hash', 'active', 't')",
    )
    .bind(b(2))
    .bind(b(TENANT))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO v2_devices (id, tenant_id, account_id, label_ciphertext, signing_key_id, \
            signing_public_key, signing_suite, hpke_key_id, hpke_public_key, hpke_suite, status, \
            created_at) \
         VALUES (?, ?, ?, x'00', ?, ?, 1, ?, ?, 1, 'active', 't')",
    )
    .bind(b(3))
    .bind(b(TENANT))
    .bind(b(2))
    .bind(k(4))
    .bind(k(5))
    .bind(k(6))
    .bind(k(7))
    .execute(pool)
    .await
    .unwrap();
}

async fn root_grant(pool: &SqlitePool, instance: u8, generation: i64, key: Vec<u8>) {
    sqlx::query(
        "INSERT INTO v2_tenant_root_key_grants \
         (tenant_id, replay_id, payload_domain, grant_variant, root_key_id, root_generation, \
          grant_capability, subject_account_id, subject_device_id, subject_signing_key_id, \
          recipient_hpke_key_id, subject_device_approval_replay_id, hpke_suite_id, hpke_mode_id, \
          hpke_kem_id, hpke_kdf_id, hpke_aead_id, hpke_info_bytes, hpke_encapped_key_bytes, \
          hpke_wrapped_trk_bytes, server_instance_id, restore_epoch, signature_bytes, \
          issuer_signing_key_id, signed_container_hash, exact_signed_container_bytes, \
          exact_signed_container_bytes_sha256, created_at) \
         VALUES (?, ?, 'domain', 'FirstRootSelfGrant', ?, ?, 'root.custody', ?, ?, ?, ?, ?, \
                 1, 0, 32, 1, 3, x'aa', x'bb', x'cc', ?, 0, ?, ?, ?, x'dd', ?, 't')",
    )
    .bind(b(TENANT))
    .bind(b(0x30))
    .bind(key)
    .bind(generation)
    .bind(b(2))
    .bind(b(3))
    .bind(k(4))
    .bind(k(6))
    .bind(b(0x31))
    .bind(b(instance))
    .bind(vec![0x32u8; 64])
    .bind(k(4))
    .bind(k(0x33))
    .bind(k(0x34))
    .execute(pool)
    .await
    .unwrap();
}

async fn fleet_generation(pool: &SqlitePool, root_generation: i64) {
    sqlx::query("INSERT INTO v2_fleets VALUES (?, ?, 'fleet', 'active', 't')")
        .bind(b(FLEET))
        .bind(b(TENANT))
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO v2_fleet_key_generations \
         (tenant_id, fleet_id, generation, fkek_key_id, root_generation, state, created_at) \
         VALUES (?, ?, 1, ?, ?, 'ACTIVE', 't')",
    )
    .bind(b(TENANT))
    .bind(b(FLEET))
    .bind(k(FKEK))
    .bind(root_generation)
    .execute(pool)
    .await
    .unwrap();
}

async fn fleet_grant(pool: &SqlitePool, instance: u8) {
    sqlx::query(
        "INSERT INTO v2_fleet_key_grants \
         (tenant_id, replay_id, payload_domain, grant_variant, fleet_id, fkek_key_id, \
          fleet_generation, grant_capability, server_instance_id, restore_epoch, issued_at_ms, \
          not_before_ms, not_after_ms, signature_bytes, issuer_signing_key_id, \
          signed_container_hash, exact_signed_container_bytes, \
          exact_signed_container_bytes_sha256, created_at) \
         VALUES (?, ?, 'domain', 'FirstFleetSelfGrant', ?, ?, 1, 'fleet', ?, 0, 1, 2, 3, ?, ?, \
                 ?, x'ee', ?, 't')",
    )
    .bind(b(TENANT))
    .bind(b(0x50))
    .bind(b(FLEET))
    .bind(k(FKEK))
    .bind(b(instance))
    .bind(vec![0x51u8; 64])
    .bind(k(0x52))
    .bind(k(0x53))
    .bind(k(0x54))
    .execute(pool)
    .await
    .unwrap();
}

/// A tenant with an activated root, its self-grant, and a fleet key on it.
async fn consistent(pool: &SqlitePool) {
    mirror(pool, INSTANCE).await;
    tenant(pool, TENANT, 0).await;
    account_and_device(pool).await;
    root_generation(pool, TENANT, 0, "ACTIVE").await;
    root_grant(pool, INSTANCE, 0, k(ROOT_KEY)).await;
    fleet_generation(pool, 0).await;
    fleet_grant(pool, INSTANCE).await;
}

type Snapshot = BTreeMap<String, Vec<String>>;

/// Every user table as quoted rows over `columns` (or all current columns).
async fn snapshot(pool: &SqlitePool, columns: Option<&BTreeMap<String, Vec<String>>>) -> Snapshot {
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' \
         AND name != '_sqlx_migrations' ORDER BY name",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    let mut out = BTreeMap::new();
    for name in names {
        let cols = match columns {
            Some(c) => c[&name].clone(),
            None => sqlx::query_scalar(&format!(
                "SELECT name FROM pragma_table_info('{name}') ORDER BY cid"
            ))
            .fetch_all(pool)
            .await
            .unwrap(),
        };
        let quoted: Vec<String> = cols.iter().map(|c| format!("quote({c})")).collect();
        let rows: Vec<String> = sqlx::query_scalar(&format!(
            "SELECT {} FROM {name} ORDER BY {}",
            quoted.join(" || ',' || "),
            cols.join(", ")
        ))
        .fetch_all(pool)
        .await
        .unwrap();
        out.insert(name, rows);
    }
    out
}

async fn columns(pool: &SqlitePool) -> BTreeMap<String, Vec<String>> {
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' \
         AND name != '_sqlx_migrations'",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    let mut out = BTreeMap::new();
    for name in names {
        let cols: Vec<String> = sqlx::query_scalar(&format!(
            "SELECT name FROM pragma_table_info('{name}') ORDER BY cid"
        ))
        .fetch_all(pool)
        .await
        .unwrap();
        out.insert(name, cols);
    }
    out
}

async fn fk_clean(pool: &SqlitePool) {
    let on: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(on, 1);
    assert!(sqlx::query("PRAGMA foreign_key_check")
        .fetch_all(pool)
        .await
        .unwrap()
        .is_empty());
}

async fn applied(pool: &SqlitePool) -> i64 {
    sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn pointer(pool: &SqlitePool, id: u8) -> Option<i64> {
    sqlx::query_scalar("SELECT active_root_generation FROM v2_tenants WHERE id = ?")
        .bind(b(id))
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Run 0011 expecting it to refuse with `constraint`, leaving data as it was.
async fn refuses(pool: &SqlitePool, constraint: &str) {
    let before = snapshot(pool, None).await;
    let error = run_migrations(pool).await.unwrap_err().to_string();
    assert!(error.contains(constraint), "{error}");
    assert_eq!(applied(pool).await, 10);
    assert_eq!(snapshot(pool, None).await, before);
}

#[tokio::test]
async fn upgrade_binds_generations_to_the_mirror_instance_and_preserves_every_row() {
    let pool = before_0011().await;
    consistent(&pool).await;
    let cols = columns(&pool).await;
    let before = snapshot(&pool, Some(&cols)).await;

    run_migrations(&pool).await.unwrap();

    assert_eq!(snapshot(&pool, Some(&cols)).await, before);
    for table in ["v2_root_key_generations", "v2_fleet_key_generations"] {
        let instances: Vec<Vec<u8>> =
            sqlx::query_scalar(&format!("SELECT server_instance_id FROM {table}"))
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(instances, vec![b(INSTANCE)], "{table}");
    }
    assert_eq!(pointer(&pool, TENANT).await, Some(0));
    fk_clean(&pool).await;
}

#[tokio::test]
async fn empty_and_preparing_only_setups_become_null() {
    let pool = before_0011().await;
    mirror(&pool, INSTANCE).await;
    tenant(&pool, 1, 7).await;
    root_generation(&pool, 1, 0, "PREPARING").await;
    tenant(&pool, 2, 3).await;

    run_migrations(&pool).await.unwrap();

    assert_eq!(pointer(&pool, 1).await, None);
    assert_eq!(pointer(&pool, 2).await, None);
    let state: String = sqlx::query_scalar("SELECT state FROM v2_root_key_generations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        state, "PREPARING",
        "nothing is activated to finish the migration"
    );
    fk_clean(&pool).await;
}

#[tokio::test]
async fn a_pointer_that_disagrees_with_the_active_row_stops_the_migration() {
    let pool = before_0011().await;
    mirror(&pool, INSTANCE).await;
    tenant(&pool, TENANT, 2).await;
    root_generation(&pool, TENANT, 1, "ACTIVE").await;
    refuses(&pool, "m0011_root_pointer_disagrees_with_root_rows").await;
}

#[tokio::test]
async fn a_retired_root_without_an_active_one_stops_the_migration() {
    let pool = before_0011().await;
    mirror(&pool, INSTANCE).await;
    tenant(&pool, TENANT, 0).await;
    root_generation(&pool, TENANT, 0, "RETIRED").await;
    refuses(&pool, "m0011_root_pointer_disagrees_with_root_rows").await;
}

#[tokio::test]
async fn generations_without_a_server_identity_stop_the_migration() {
    let pool = before_0011().await;
    tenant(&pool, TENANT, 0).await;
    root_generation(&pool, TENANT, 0, "ACTIVE").await;
    refuses(&pool, "m0011_generations_need_server_identity").await;
}

#[tokio::test]
async fn a_grant_from_another_instance_stops_the_migration() {
    let pool = before_0011().await;
    mirror(&pool, INSTANCE).await;
    tenant(&pool, TENANT, 0).await;
    account_and_device(&pool).await;
    root_generation(&pool, TENANT, 0, "ACTIVE").await;
    root_grant(&pool, 0x99, 0, k(ROOT_KEY)).await;
    refuses(&pool, "m0011_foreign_key_violation").await;
}

#[tokio::test]
async fn a_grant_wrapping_another_key_than_its_generation_stops_the_migration() {
    let pool = before_0011().await;
    mirror(&pool, INSTANCE).await;
    tenant(&pool, TENANT, 0).await;
    account_and_device(&pool).await;
    root_generation(&pool, TENANT, 0, "ACTIVE").await;
    root_grant(&pool, INSTANCE, 0, k(0x77)).await;
    refuses(&pool, "m0011_foreign_key_violation").await;
}

#[tokio::test]
async fn a_fleet_grant_from_another_instance_stops_the_migration() {
    let pool = before_0011().await;
    mirror(&pool, INSTANCE).await;
    tenant(&pool, TENANT, 0).await;
    root_generation(&pool, TENANT, 0, "ACTIVE").await;
    fleet_generation(&pool, 0).await;
    fleet_grant(&pool, 0x99).await;
    refuses(&pool, "m0011_foreign_key_violation").await;
}

#[tokio::test]
async fn a_fleet_key_on_an_unactivated_root_stops_the_migration() {
    let pool = before_0011().await;
    mirror(&pool, INSTANCE).await;
    tenant(&pool, TENANT, 0).await;
    root_generation(&pool, TENANT, 0, "PREPARING").await;
    fleet_generation(&pool, 0).await;
    refuses(&pool, "m0011_fleet_generation_needs_an_activated_root").await;
}

#[tokio::test]
async fn the_raw_migrator_refuses_with_foreign_keys_on() {
    let pool = before_0011().await;
    consistent(&pool).await;
    let before = snapshot(&pool, None).await;
    let error = sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("m0011_requires_foreign_keys_off"), "{error}");
    assert_eq!(snapshot(&pool, None).await, before);
    run_migrations(&pool).await.unwrap();
    fk_clean(&pool).await;
}

/// After the upgrade the boundary holds for new rows too: a grant or a fleet
/// generation cannot name another instance's root generation.
#[tokio::test]
async fn new_rows_cannot_cross_the_instance_boundary() {
    let pool = before_0011().await;
    run_migrations(&pool).await.unwrap();
    exec(&pool, "PRAGMA foreign_keys = ON").await;
    mirror(&pool, INSTANCE).await;
    tenant(&pool, TENANT, 0).await;
    account_and_device(&pool).await;
    sqlx::query(
        "INSERT INTO v2_root_key_generations \
         (server_instance_id, tenant_id, generation, root_key_id, state, created_at) \
         VALUES (?, ?, 0, ?, 'ACTIVE', 't')",
    )
    .bind(b(INSTANCE))
    .bind(b(TENANT))
    .bind(k(ROOT_KEY))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO v2_fleets VALUES (?, ?, 'fleet', 'active', 't')")
        .bind(b(FLEET))
        .bind(b(TENANT))
        .execute(&pool)
        .await
        .unwrap();

    let grant = sqlx::query(
        "INSERT INTO v2_tenant_root_key_grants \
         (tenant_id, replay_id, payload_domain, grant_variant, root_key_id, root_generation, \
          grant_capability, subject_account_id, subject_device_id, subject_signing_key_id, \
          recipient_hpke_key_id, subject_device_approval_replay_id, hpke_suite_id, hpke_mode_id, \
          hpke_kem_id, hpke_kdf_id, hpke_aead_id, hpke_info_bytes, hpke_encapped_key_bytes, \
          hpke_wrapped_trk_bytes, server_instance_id, restore_epoch, signature_bytes, \
          issuer_signing_key_id, signed_container_hash, exact_signed_container_bytes, \
          exact_signed_container_bytes_sha256, created_at) \
         VALUES (?, ?, 'domain', 'FirstRootSelfGrant', ?, 0, 'root.custody', ?, ?, ?, ?, ?, \
                 1, 0, 32, 1, 3, x'aa', x'bb', x'cc', ?, 0, ?, ?, ?, x'dd', ?, 't')",
    )
    .bind(b(TENANT))
    .bind(b(0x30))
    .bind(k(ROOT_KEY))
    .bind(b(2))
    .bind(b(3))
    .bind(k(4))
    .bind(k(6))
    .bind(b(0x31))
    .bind(b(0x99))
    .bind(vec![0x32u8; 64])
    .bind(k(4))
    .bind(k(0x33))
    .bind(k(0x34))
    .execute(&pool)
    .await
    .unwrap_err();
    assert_eq!(
        grant.as_database_error().unwrap().code().as_deref(),
        Some("787")
    );

    let fleet = sqlx::query(
        "INSERT INTO v2_fleet_key_generations \
         (server_instance_id, tenant_id, fleet_id, generation, fkek_key_id, root_generation, \
          state, created_at) \
         VALUES (?, ?, ?, 1, ?, 0, 'PREPARING', 't')",
    )
    .bind(b(0x99))
    .bind(b(TENANT))
    .bind(b(FLEET))
    .bind(k(FKEK))
    .execute(&pool)
    .await
    .unwrap_err();
    assert_eq!(
        fleet.as_database_error().unwrap().code().as_deref(),
        Some("787")
    );
}
