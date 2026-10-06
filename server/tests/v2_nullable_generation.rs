//! Regression tests for the schema-only 0009 upgrade.
use shardx_team_server::run_migrations_fk_safe;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{Row, SqlitePool};
use std::borrow::Cow;

async fn before_0009() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let mut migrator = sqlx::migrate!("./migrations");
    migrator.migrations = Cow::Owned(migrator.iter().filter(|m| m.version < 9).cloned().collect());
    migrator.run(&pool).await.unwrap();
    pool
}

async fn fk_on(pool: &SqlitePool) {
    assert_eq!(
        sqlx::query_scalar::<_, i64>("PRAGMA foreign_keys")
            .fetch_one(pool)
            .await
            .unwrap(),
        1
    );
    assert!(sqlx::query("PRAGMA foreign_key_check")
        .fetch_all(pool)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn upgrade_accepts_null_without_a_numeric_default() {
    let pool = before_0009().await;
    run_migrations_fk_safe(&pool).await.unwrap();
    sqlx::query("INSERT INTO v2_tenants (id, slug, status, created_at) VALUES (?, 'fresh', 'active', 'now')")
        .bind(vec![1u8; 16]).execute(&pool).await.unwrap();
    let generation: Option<i64> =
        sqlx::query_scalar("SELECT active_root_generation FROM v2_tenants")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(generation, None);
    let info = sqlx::query("SELECT \"notnull\", dflt_value FROM pragma_table_info('v2_tenants') WHERE name = 'active_root_generation'")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(info.get::<i64, _>("notnull"), 0);
    assert_eq!(info.get::<Option<String>, _>("dflt_value"), None);
    for generation in [0, 1, i64::MAX] {
        sqlx::query("UPDATE v2_tenants SET active_root_generation = ?")
            .bind(generation)
            .execute(&pool)
            .await
            .unwrap();
    }
    let error = sqlx::query("UPDATE v2_tenants SET active_root_generation = -1")
        .execute(&pool)
        .await
        .unwrap_err();
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("275")
    );
    fk_on(&pool).await;
}

#[tokio::test]
async fn raw_migrator_refuses_fk_on_without_changing_data() {
    let pool = before_0009().await;
    sqlx::query("INSERT INTO v2_tenants VALUES (?, 'old', 'active', 7, 'now')")
        .bind(vec![1u8; 16])
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO v2_accounts (id, tenant_id, username, pw_hash, status, created_at) VALUES (?, ?, 'owner', 'hash', 'active', 'now')")
        .bind(vec![2u8; 16]).bind(vec![1u8; 16]).execute(&pool).await.unwrap();
    let error = sqlx::migrate!("./migrations").run(&pool).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("m0009_requires_foreign_keys_off"),
        "{error}"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM v2_accounts")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT active_root_generation FROM v2_tenants")
            .fetch_one(&pool)
            .await
            .unwrap(),
        7
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT max(version) FROM _sqlx_migrations")
            .fetch_one(&pool)
            .await
            .unwrap(),
        8
    );
    fk_on(&pool).await;
    run_migrations_fk_safe(&pool).await.unwrap();
    fk_on(&pool).await;
}

fn b(n: u8) -> Vec<u8> {
    vec![n; 16]
}

fn k(n: u8) -> Vec<u8> {
    vec![n; 32]
}

async fn snapshot(pool: &SqlitePool) -> std::collections::BTreeMap<String, Vec<String>> {
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name != '_sqlx_migrations' ORDER BY name",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    let mut out = std::collections::BTreeMap::new();
    for name in names {
        let columns: Vec<String> = sqlx::query_scalar(&format!(
            "SELECT name FROM pragma_table_info('{name}') ORDER BY cid"
        ))
        .fetch_all(pool)
        .await
        .unwrap();
        let quoted: Vec<String> = columns
            .iter()
            .map(|column| format!("quote({column})"))
            .collect();
        let rows: Vec<String> = sqlx::query_scalar(&format!(
            "SELECT {} FROM {name} ORDER BY rowid",
            quoted.join(" || ',' || ")
        ))
        .fetch_all(pool)
        .await
        .unwrap();
        out.insert(name, rows);
    }
    out
}

#[tokio::test]
async fn upgrade_preserves_every_existing_row() {
    let pool = before_0009().await;
    seed_populated(&pool).await;
    let before = snapshot(&pool).await;

    run_migrations_fk_safe(&pool).await.unwrap();

    let after = snapshot(&pool).await;
    assert_eq!(before.len(), after.len());
    for (table, rows) in &before {
        assert_eq!(after.get(table).unwrap(), rows, "{table}");
    }
    assert!(before.values().any(|rows| !rows.is_empty()));
    fk_on(&pool).await;
}

async fn seed_populated(pool: &SqlitePool) {
    sqlx::query("INSERT INTO v2_tenants VALUES (?, 'kept', 'active', 7, 't0')")
        .bind(b(1))
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO v2_accounts (id, tenant_id, username, pw_hash, legacy_user_id, token_version, status, created_at) \
         VALUES (?, ?, 'owner', 'hash', 'legacy', 3, 'active', 't1')",
    )
    .bind(b(2))
    .bind(b(1))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO v2_tenant_memberships VALUES (?, ?, 'owner', 'active', 't2')")
        .bind(b(1))
        .bind(b(2))
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO v2_devices VALUES (?, ?, ?, x'aa', ?, ?, 1, ?, ?, 2, 'active', 'seen', 't3')",
    )
    .bind(b(3))
    .bind(b(1))
    .bind(b(2))
    .bind(k(4))
    .bind(k(5))
    .bind(k(6))
    .bind(k(7))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO v2_sessions VALUES (?, ?, ?, ?, ?, 'exp', NULL)")
        .bind(b(8))
        .bind(b(1))
        .bind(b(2))
        .bind(b(3))
        .bind(k(9))
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO v2_enrollment_challenges VALUES (?, ?, ?, 4, ?, ?, 'exp', NULL)")
        .bind(b(10))
        .bind(b(1))
        .bind(b(11))
        .bind(k(12))
        .bind(k(13))
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO v2_device_approvals \
         (tenant_id, replay_id, payload_domain, payload_version, subject_account_id, subject_device_id, \
          subject_signing_key_id, subject_hpke_key_id, approval_scope_kind, approval_scope_id, approved_use, \
          issued_at_ms, not_before_ms, not_after_ms, server_instance_id, restore_epoch, \
          canonical_payload_bytes, payload_sha256, signature_suite_id, signature_version, signature_bytes, \
          issuer_signing_key_id, signed_container_hash, exact_signed_container_bytes, \
          exact_signed_container_bytes_sha256, created_at) \
         VALUES (?, ?, 'domain', 1, ?, ?, ?, ?, 'fleet', ?, 'sync', 1, 2, 3, ?, 4, x'bb', ?, 5, 6, ?, ?, ?, x'cc', ?, 't4')",
    )
    .bind(b(1))
    .bind(b(14))
    .bind(b(2))
    .bind(b(3))
    .bind(k(15))
    .bind(k(16))
    .bind(b(17))
    .bind(b(18))
    .bind(k(19))
    .bind(vec![20u8; 64])
    .bind(k(21))
    .bind(k(22))
    .bind(k(23))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO v2_capability_grants \
         (tenant_id, replay_id, payload_domain, payload_version, subject_account_id, subject_device_id, \
          capability, scope_kind, scope_id, issued_at_ms, not_before_ms, not_after_ms, server_instance_id, \
          restore_epoch, canonical_payload_bytes, payload_sha256, signature_bytes, issuer_signing_key_id, \
          signed_container_hash, exact_signed_container_bytes, exact_signed_container_bytes_sha256, created_at) \
         VALUES (?, ?, 'domain', 1, ?, ?, 'cap', 'tenant', ?, 1, 2, 3, ?, 4, x'dd', ?, ?, ?, ?, x'ee', ?, 't5')",
    )
    .bind(b(1))
    .bind(b(24))
    .bind(b(2))
    .bind(b(3))
    .bind(b(25))
    .bind(b(26))
    .bind(k(27))
    .bind(vec![28u8; 64])
    .bind(k(29))
    .bind(k(30))
    .bind(k(31))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO v2_tenant_issuers VALUES (?, ?, ?, 't6', NULL)")
        .bind(b(1))
        .bind(k(28))
        .bind(k(29))
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO v2_root_key_generations VALUES (?, 0, ?, 'PREPARING', 't7', NULL, NULL)",
    )
    .bind(b(1))
    .bind(k(30))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO v2_tenant_root_key_grants \
         (tenant_id, replay_id, payload_domain, grant_variant, root_key_id, root_generation, grant_capability, \
          subject_account_id, subject_device_id, subject_signing_key_id, recipient_hpke_key_id, \
          subject_device_approval_replay_id, hpke_suite_id, hpke_mode_id, hpke_kem_id, hpke_kdf_id, hpke_aead_id, \
          hpke_info_bytes, hpke_encapped_key_bytes, hpke_wrapped_trk_bytes, server_instance_id, restore_epoch, \
          signature_bytes, issuer_signing_key_id, signed_container_hash, exact_signed_container_bytes, \
          exact_signed_container_bytes_sha256, created_at) \
         VALUES (?, ?, 'domain', 'FirstRootSelfGrant', ?, 0, 'root', ?, ?, ?, ?, ?, 1, 2, 3, 4, 5, x'aa', x'bb', x'cc', ?, 6, ?, ?, ?, x'ee', ?, 't8')",
    )
    .bind(b(1))
    .bind(b(31))
    .bind(k(32))
    .bind(b(2))
    .bind(b(3))
    .bind(k(33))
    .bind(k(34))
    .bind(b(14))
    .bind(b(35))
    .bind(vec![36u8; 64])
    .bind(k(37))
    .bind(k(38))
    .bind(k(39))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO v2_fleets VALUES (?, ?, 'fleet', 'active', 't9')")
        .bind(b(36))
        .bind(b(1))
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO v2_profiles VALUES (?, ?, ?, 'profile', 2, 'active', 't10', 't10')")
        .bind(b(37))
        .bind(b(1))
        .bind(b(36))
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO v2_leases VALUES (?, ?, ?, ?, ?, 5, 2, ?, 1, 'acq', 'exp', NULL)")
        .bind(b(38))
        .bind(b(1))
        .bind(b(37))
        .bind(b(2))
        .bind(b(3))
        .bind(b(39))
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO v2_snapshot_manifests \
         (tenant_id, profile_id, version, snapshot_id, fleet_id, base_version, key_generation, restore_epoch, \
          server_instance_id, fencing_token, intent_hash, container_sha256, container_size, blob_path, \
          author_account_id, author_device_id, signature_bytes, issuer_signing_key_id, signed_container_hash, \
          exact_signed_container_bytes, exact_signed_container_bytes_sha256, created_at) \
         VALUES (?, ?, 1, ?, ?, 0, 2, 3, ?, 5, ?, ?, 9, 'blob', ?, ?, ?, ?, ?, x'ee', ?, 't11')",
    )
    .bind(b(1))
    .bind(b(37))
    .bind(b(40))
    .bind(b(36))
    .bind(b(41))
    .bind(k(42))
    .bind(k(43))
    .bind(b(2))
    .bind(b(3))
    .bind(vec![44u8; 64])
    .bind(k(45))
    .bind(k(46))
    .bind(k(47))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO v2_upload_sessions \
         (id, tenant_id, profile_id, lease_id, server_instance_id, restore_epoch, fencing_token, \
          target_version, intent_hash, declared_size, staging_path, status, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, 1, 5, 2, ?, 100, 'stage', 'open', 't12', 't12')",
    )
    .bind(b(48))
    .bind(b(1))
    .bind(b(37))
    .bind(b(38))
    .bind(b(49))
    .bind(k(50))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO v2_operations \
         (tenant_id, idempotency_key, server_instance_id, restore_epoch, account_id, device_id, \
          operation_kind, request_sha256, status, created_at) \
         VALUES (?, ?, ?, 1, ?, ?, 'kind', ?, 'in_flight', 't13')",
    )
    .bind(b(1))
    .bind(b(51))
    .bind(b(52))
    .bind(b(2))
    .bind(b(3))
    .bind(k(53))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO v2_replay_ledger VALUES (?, 'domain', ?, 'v2_device_approvals', ?, ?, 1, 2, 't14')",
    )
    .bind(b(1))
    .bind(b(51))
    .bind(k(52))
    .bind(k(53))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO v2_fleet_key_generations VALUES (?, ?, 0, ?, 0, 'PREPARING', 't15', NULL, NULL)",
    )
    .bind(b(1))
    .bind(b(36))
    .bind(k(54))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO v2_fleet_key_grants \
         (tenant_id, replay_id, payload_domain, grant_variant, fleet_id, fkek_key_id, fleet_generation, \
          grant_capability, server_instance_id, restore_epoch, issued_at_ms, not_before_ms, not_after_ms, \
          signature_bytes, issuer_signing_key_id, signed_container_hash, exact_signed_container_bytes, \
          exact_signed_container_bytes_sha256, created_at) \
         VALUES (?, ?, 'domain', 'FirstFleetSelfGrant', ?, ?, 0, 'fleet', ?, 1, 2, 3, 4, ?, ?, ?, x'22', ?, 't16')",
    )
    .bind(b(1))
    .bind(b(55))
    .bind(b(36))
    .bind(k(54))
    .bind(b(56))
    .bind(vec![57u8; 64])
    .bind(k(58))
    .bind(k(59))
    .bind(k(60))
    .execute(pool)
    .await
    .unwrap();
}
