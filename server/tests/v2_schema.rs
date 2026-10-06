//! Structural guarantees of the v2 control-plane schema.
//!
//! These assert the database rejects things, which is the part that actually
//! protects a tenant: application code can forget a WHERE clause, but a
//! composite foreign key cannot be forgotten. Each test drives real SQLite
//! through the real migrations and checks the extended result code, so a
//! constraint being silently dropped or weakened fails here.

use sqlx::sqlite::{SqlitePoolOptions, SqliteRow};
use sqlx::{Row, SqlitePool};

/// SQLite extended result codes. Asserting the exact code proves *which*
/// constraint fired — a generic "it errored" would still pass if a CHECK were
/// replaced by an unrelated failure.
const SQLITE_CONSTRAINT_CHECK: &str = "275";
const SQLITE_CONSTRAINT_UNIQUE: &str = "2067";
const SQLITE_CONSTRAINT_FOREIGNKEY: &str = "787";
const SQLITE_CONSTRAINT_PRIMARYKEY: &str = "1555";

async fn pool() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    // Foreign keys are off by default in SQLite and the composite-FK isolation
    // guarantee depends entirely on them being on.
    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&pool)
        .await
        .unwrap();
    shardx_team_server::run_migrations_fk_safe(&pool)
        .await
        .unwrap();
    pool
}

fn id(byte: u8) -> Vec<u8> {
    vec![byte; 16]
}

fn key32(byte: u8) -> Vec<u8> {
    vec![byte; 32]
}

fn err_code(e: sqlx::Error) -> String {
    match e {
        sqlx::Error::Database(db) => db.code().map(|c| c.to_string()).unwrap_or_default(),
        other => panic!("expected a database error, got {other:?}"),
    }
}

async fn seed_tenant(pool: &SqlitePool, tenant: u8) {
    sqlx::query(
        "INSERT INTO v2_tenants (id, slug, status, active_root_generation, created_at)
         VALUES (?, ?, 'active', 1, '2026-09-02T00:00:00+00:00')",
    )
    .bind(id(tenant))
    .bind(format!("tenant-{tenant}"))
    .execute(pool)
    .await
    .unwrap();
}

async fn seed_account(pool: &SqlitePool, tenant: u8, account: u8) {
    sqlx::query(
        "INSERT INTO v2_accounts (id, tenant_id, username, pw_hash, token_version, status, created_at)
         VALUES (?, ?, ?, 'x', 0, 'active', '2026-09-02T00:00:00+00:00')",
    )
    .bind(id(account))
    .bind(id(tenant))
    .bind(format!("user-{account}"))
    .execute(pool)
    .await
    .unwrap();
}

async fn seed_fleet(pool: &SqlitePool, tenant: u8, fleet: u8) {
    sqlx::query(
        "INSERT INTO v2_fleets (id, tenant_id, name, status, created_at)
         VALUES (?, ?, ?, 'active', '2026-09-02T00:00:00+00:00')",
    )
    .bind(id(fleet))
    .bind(id(tenant))
    .bind(format!("fleet-{fleet}"))
    .execute(pool)
    .await
    .unwrap();
}

async fn seed_profile(pool: &SqlitePool, tenant: u8, fleet: u8, profile: u8) {
    sqlx::query(
        "INSERT INTO v2_profiles (id, tenant_id, fleet_id, name, current_version, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, 0, 'active', '2026-09-02T00:00:00+00:00', '2026-09-02T00:00:00+00:00')",
    )
    .bind(id(profile))
    .bind(id(tenant))
    .bind(id(fleet))
    .bind(format!("profile-{profile}"))
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn v1_tables_survive_the_v2_migration() {
    // The v2 migration is additive; an existing deployment must keep working.
    let pool = pool().await;
    let rows: Vec<SqliteRow> =
        sqlx::query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .fetch_all(&pool)
            .await
            .unwrap();
    let names: Vec<String> = rows.iter().map(|r| r.get::<String, _>("name")).collect();

    for v1 in [
        "users",
        "folders",
        "proxies",
        "environments",
        "acl",
        "locks",
        "snapshots",
        "audit_log",
    ] {
        assert!(names.contains(&v1.to_string()), "v1 table {v1} was dropped");
    }
    for v2 in [
        "v2_tenants",
        "v2_accounts",
        "v2_devices",
        "v2_profiles",
        "v2_leases",
        "v2_snapshot_manifests",
        "v2_operations",
        "v2_tenant_root_key_grants",
    ] {
        assert!(names.contains(&v2.to_string()), "v2 table {v2} missing");
    }
}

#[tokio::test]
async fn a_profile_cannot_reference_a_fleet_in_another_tenant() {
    // The core isolation property. Tenant A's profile must not be able to
    // attach itself to tenant B's fleet, even with a hand-written INSERT.
    let pool = pool().await;
    seed_tenant(&pool, 1).await;
    seed_tenant(&pool, 2).await;
    seed_fleet(&pool, 2, 20).await; // fleet belongs to tenant 2

    let err = sqlx::query(
        "INSERT INTO v2_profiles (id, tenant_id, fleet_id, name, current_version, status, created_at, updated_at)
         VALUES (?, ?, ?, 'x', 0, 'active', '2026-09-02T00:00:00+00:00', '2026-09-02T00:00:00+00:00')",
    )
    .bind(id(30))
    .bind(id(1)) // tenant 1
    .bind(id(20)) // fleet from tenant 2
    .execute(&pool)
    .await
    .unwrap_err();

    assert_eq!(err_code(err), SQLITE_CONSTRAINT_FOREIGNKEY);
}

#[tokio::test]
async fn a_device_cannot_reference_an_account_in_another_tenant() {
    let pool = pool().await;
    seed_tenant(&pool, 1).await;
    seed_tenant(&pool, 2).await;
    seed_account(&pool, 2, 20).await;

    let err = sqlx::query(
        "INSERT INTO v2_devices (id, tenant_id, account_id, label_ciphertext, signing_key_id,
            signing_public_key, signing_suite, hpke_key_id, hpke_public_key, hpke_suite,
            status, created_at)
         VALUES (?, ?, ?, X'00', ?, ?, 1, ?, ?, 1, 'active', '2026-09-02T00:00:00+00:00')",
    )
    .bind(id(30))
    .bind(id(1))
    .bind(id(20)) // account from tenant 2
    .bind(key32(1))
    .bind(key32(2))
    .bind(key32(3))
    .bind(key32(4))
    .execute(&pool)
    .await
    .unwrap_err();

    assert_eq!(err_code(err), SQLITE_CONSTRAINT_FOREIGNKEY);
}

#[tokio::test]
async fn a_manifest_cannot_reference_a_profile_in_another_tenant() {
    let pool = pool().await;
    seed_tenant(&pool, 1).await;
    seed_tenant(&pool, 2).await;
    seed_fleet(&pool, 2, 20).await;
    seed_profile(&pool, 2, 20, 30).await;

    let err = sqlx::query(
        "INSERT INTO v2_snapshot_manifests (tenant_id, profile_id, version, snapshot_id, fleet_id,
            base_version, key_generation, restore_epoch, server_instance_id, fencing_token,
            intent_hash, container_sha256, container_size, blob_path, author_account_id,
            author_device_id, signature_bytes, issuer_signing_key_id, signed_container_hash,
            exact_signed_container_bytes, exact_signed_container_bytes_sha256, created_at)
         VALUES (?, ?, 1, ?, ?, 0, 1, 1, ?, 1, ?, ?, 10, 'b', ?, ?, ?, ?, ?, X'00', ?,
                 '2026-09-02T00:00:00+00:00')",
    )
    .bind(id(1)) // tenant 1
    .bind(id(30)) // profile from tenant 2
    .bind(id(40))
    .bind(id(20))
    .bind(id(50))
    .bind(key32(1))
    .bind(key32(2))
    .bind(id(60))
    .bind(id(70))
    .bind(vec![0u8; 64])
    .bind(key32(3))
    .bind(key32(4))
    .bind(key32(5))
    .execute(&pool)
    .await
    .unwrap_err();

    assert_eq!(err_code(err), SQLITE_CONSTRAINT_FOREIGNKEY);
}

#[tokio::test]
async fn only_one_live_lease_per_profile() {
    // A double checkout must be impossible at the storage layer, not merely
    // unlikely at the application layer.
    let pool = pool().await;
    seed_tenant(&pool, 1).await;
    seed_fleet(&pool, 1, 10).await;
    seed_profile(&pool, 1, 10, 20).await;

    let insert_lease = |lease: u8, token: i64| {
        sqlx::query(
            "INSERT INTO v2_leases (id, tenant_id, profile_id, holder_account_id, holder_device_id,
                fencing_token, base_version, server_instance_id, restore_epoch, acquired_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, 0, ?, 1, '2026-09-02T00:00:00+00:00', '2026-09-02T01:00:00+00:00')",
        )
        .bind(id(lease))
        .bind(id(1))
        .bind(id(20))
        .bind(id(30))
        .bind(id(40))
        .bind(token)
        .bind(id(50))
    };

    insert_lease(60, 1).execute(&pool).await.unwrap();
    let err = insert_lease(61, 2).execute(&pool).await.unwrap_err();
    assert_eq!(err_code(err), SQLITE_CONSTRAINT_UNIQUE);

    // Releasing the first lease frees the profile for a new holder.
    sqlx::query("UPDATE v2_leases SET released_at = '2026-09-02T02:00:00+00:00' WHERE id = ?")
        .bind(id(60))
        .execute(&pool)
        .await
        .unwrap();
    insert_lease(61, 2).execute(&pool).await.unwrap();
}

#[tokio::test]
async fn a_manifest_version_is_committed_only_once() {
    let pool = pool().await;
    seed_tenant(&pool, 1).await;
    seed_fleet(&pool, 1, 10).await;
    seed_profile(&pool, 1, 10, 20).await;

    let insert = |container: u8| {
        sqlx::query(
            "INSERT INTO v2_snapshot_manifests (tenant_id, profile_id, version, snapshot_id, fleet_id,
                base_version, key_generation, restore_epoch, server_instance_id, fencing_token,
                intent_hash, container_sha256, container_size, blob_path, author_account_id,
                author_device_id, signature_bytes, issuer_signing_key_id, signed_container_hash,
                exact_signed_container_bytes, exact_signed_container_bytes_sha256, created_at)
             VALUES (?, ?, 1, ?, ?, 0, 1, 1, ?, 1, ?, ?, 10, 'b', ?, ?, ?, ?, ?, X'00', ?,
                     '2026-09-02T00:00:00+00:00')",
        )
        .bind(id(1))
        .bind(id(20))
        .bind(id(40))
        .bind(id(10))
        .bind(id(50))
        .bind(key32(1))
        .bind(key32(container))
        .bind(id(60))
        .bind(id(70))
        .bind(vec![0u8; 64])
        .bind(key32(3))
        .bind(key32(4))
        .bind(key32(5))
    };

    insert(2).execute(&pool).await.unwrap();
    // A second commit at the same version — even with different content — is
    // rejected, so history cannot be rewritten.
    let err = insert(9).execute(&pool).await.unwrap_err();
    assert_eq!(err_code(err), SQLITE_CONSTRAINT_PRIMARYKEY);
}

#[tokio::test]
async fn wire_integers_above_i64_max_are_rejected() {
    // Plan 5.6: CBOR unsigned range exceeds SQLite's signed INTEGER. Binding a
    // value above i64::MAX must fail loudly rather than wrap or coerce.
    let pool = pool().await;
    seed_tenant(&pool, 1).await;

    // i64::MAX is the documented upper bound and must be accepted.
    sqlx::query("UPDATE v2_tenants SET active_root_generation = ? WHERE id = ?")
        .bind(i64::MAX)
        .bind(id(1))
        .execute(&pool)
        .await
        .unwrap();

    // Negative values are outside the unsigned wire domain.
    let err = sqlx::query("UPDATE v2_tenants SET active_root_generation = ? WHERE id = ?")
        .bind(-1i64)
        .bind(id(1))
        .execute(&pool)
        .await
        .unwrap_err();
    assert_eq!(err_code(err), SQLITE_CONSTRAINT_CHECK);
}

#[tokio::test]
async fn fixed_width_key_material_is_length_checked() {
    // A 31-byte "32-byte" key id would otherwise be stored happily and only
    // fail much later, during verification.
    let pool = pool().await;
    seed_tenant(&pool, 1).await;
    seed_account(&pool, 1, 10).await;

    let err = sqlx::query(
        "INSERT INTO v2_devices (id, tenant_id, account_id, label_ciphertext, signing_key_id,
            signing_public_key, signing_suite, hpke_key_id, hpke_public_key, hpke_suite,
            status, created_at)
         VALUES (?, ?, ?, X'00', ?, ?, 1, ?, ?, 1, 'active', '2026-09-02T00:00:00+00:00')",
    )
    .bind(id(20))
    .bind(id(1))
    .bind(id(10))
    .bind(vec![0u8; 31]) // one byte short
    .bind(key32(2))
    .bind(key32(3))
    .bind(key32(4))
    .execute(&pool)
    .await
    .unwrap_err();

    assert_eq!(err_code(err), SQLITE_CONSTRAINT_CHECK);
}

#[tokio::test]
async fn status_and_role_columns_reject_unknown_values() {
    let pool = pool().await;
    seed_tenant(&pool, 1).await;

    let err = sqlx::query(
        "INSERT INTO v2_accounts (id, tenant_id, username, pw_hash, token_version, status, created_at)
         VALUES (?, ?, 'u', 'x', 0, 'superuser', '2026-09-02T00:00:00+00:00')",
    )
    .bind(id(10))
    .bind(id(1))
    .execute(&pool)
    .await
    .unwrap_err();
    assert_eq!(err_code(err), SQLITE_CONSTRAINT_CHECK);

    seed_account(&pool, 1, 10).await;
    let err = sqlx::query(
        "INSERT INTO v2_tenant_memberships (tenant_id, account_id, role, status, created_at)
         VALUES (?, ?, 'root', 'active', '2026-09-02T00:00:00+00:00')",
    )
    .bind(id(1))
    .bind(id(10))
    .execute(&pool)
    .await
    .unwrap_err();
    assert_eq!(err_code(err), SQLITE_CONSTRAINT_CHECK);
}

#[tokio::test]
async fn idempotency_keys_are_scoped_to_instance_and_epoch() {
    // Plan V5.1: after a restore the epoch advances, so a replayed pre-restore
    // request must not collide with — and be served the response of — a
    // post-restore operation.
    let pool = pool().await;
    seed_tenant(&pool, 1).await;

    let insert = |instance: u8, epoch: i64| {
        sqlx::query(
            "INSERT INTO v2_operations (tenant_id, idempotency_key, server_instance_id,
                restore_epoch, account_id, device_id, operation_kind, request_sha256, status,
                created_at)
             VALUES (?, ?, ?, ?, ?, ?, 'commit', ?, 'succeeded', '2026-09-02T00:00:00+00:00')",
        )
        .bind(id(1))
        .bind(id(50)) // same idempotency key throughout
        .bind(id(instance))
        .bind(epoch)
        .bind(id(30))
        .bind(id(40))
        .bind(key32(1))
    };

    insert(10, 1).execute(&pool).await.unwrap();
    // Same key, later epoch: a distinct operation, not a replay.
    insert(10, 2).execute(&pool).await.unwrap();
    // Same key, different instance: also distinct.
    insert(11, 1).execute(&pool).await.unwrap();
    // Exact same (key, instance, epoch): a real replay, rejected.
    let err = insert(10, 1).execute(&pool).await.unwrap_err();
    assert_eq!(err_code(err), SQLITE_CONSTRAINT_PRIMARYKEY);
}

#[tokio::test]
async fn a_grant_cannot_name_a_device_from_another_tenant() {
    let pool = pool().await;
    seed_tenant(&pool, 1).await;
    seed_tenant(&pool, 2).await;
    seed_account(&pool, 2, 20).await;
    sqlx::query(
        "INSERT INTO v2_devices (id, tenant_id, account_id, label_ciphertext, signing_key_id,
            signing_public_key, signing_suite, hpke_key_id, hpke_public_key, hpke_suite,
            status, created_at)
         VALUES (?, ?, ?, X'00', ?, ?, 1, ?, ?, 1, 'active', '2026-09-02T00:00:00+00:00')",
    )
    .bind(id(30))
    .bind(id(2))
    .bind(id(20))
    .bind(key32(1))
    .bind(key32(2))
    .bind(key32(3))
    .bind(key32(4))
    .execute(&pool)
    .await
    .unwrap();

    // Tenant 1 tries to issue a root-key grant to tenant 2's device.
    let err = sqlx::query(
        "INSERT INTO v2_tenant_root_key_grants (tenant_id, replay_id, payload_domain,
            grant_variant, root_key_id, root_generation, grant_capability, subject_account_id,
            subject_device_id, subject_signing_key_id, recipient_hpke_key_id,
            subject_device_approval_replay_id, hpke_suite_id, hpke_mode_id, hpke_kem_id,
            hpke_kdf_id, hpke_aead_id, hpke_info_bytes, hpke_encapped_key_bytes,
            hpke_wrapped_trk_bytes, server_instance_id, restore_epoch, signature_bytes,
            issuer_signing_key_id, signed_container_hash, exact_signed_container_bytes,
            exact_signed_container_bytes_sha256, created_at)
         VALUES (?, ?, 'shardx.authorization.tenant-root-key-grant.v2', 'CustodianIssued', ?, 1,
                 'root.custody', ?, ?, ?, ?, ?, 1, 0, 32, 1, 3, X'00', X'00', X'00', ?, 1, ?, ?, ?,
                 X'00', ?, '2026-09-02T00:00:00+00:00')",
    )
    .bind(id(1)) // tenant 1
    .bind(id(60))
    .bind(key32(5))
    .bind(id(20))
    .bind(id(30)) // device belongs to tenant 2
    .bind(key32(1))
    .bind(key32(4))
    .bind(id(70))
    .bind(id(80))
    .bind(vec![0u8; 64])
    .bind(key32(6))
    .bind(key32(7))
    .bind(key32(8))
    .execute(&pool)
    .await
    .unwrap_err();

    assert_eq!(err_code(err), SQLITE_CONSTRAINT_FOREIGNKEY);
}

#[tokio::test]
async fn deleting_a_tenant_removes_its_rows_and_leaves_others_intact() {
    let pool = pool().await;
    seed_tenant(&pool, 1).await;
    seed_tenant(&pool, 2).await;
    for t in [1u8, 2u8] {
        seed_fleet(&pool, t, t * 10).await;
        seed_profile(&pool, t, t * 10, t * 10 + 1).await;
    }

    sqlx::query("DELETE FROM v2_tenants WHERE id = ?")
        .bind(id(1))
        .execute(&pool)
        .await
        .unwrap();

    let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM v2_profiles WHERE tenant_id = ?")
        .bind(id(1))
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(remaining, 0, "tenant 1's profiles should cascade away");

    let survivor: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM v2_profiles WHERE tenant_id = ?")
        .bind(id(2))
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(survivor, 1, "tenant 2 must be untouched");
}

#[tokio::test]
async fn server_state_mirror_holds_at_most_one_row() {
    // It mirrors a single external identity record; a second row would make
    // "which epoch are we on" ambiguous.
    let pool = pool().await;
    let insert = |epoch: i64| {
        sqlx::query(
            "INSERT INTO v2_server_state (singleton, server_instance_id, restore_epoch,
                external_record_sha256, updated_at)
             VALUES (1, ?, ?, ?, '2026-09-02T00:00:00+00:00')",
        )
        .bind(id(10))
        .bind(epoch)
        .bind(key32(1))
    };

    insert(1).execute(&pool).await.unwrap();
    let err = insert(2).execute(&pool).await.unwrap_err();
    assert_eq!(err_code(err), SQLITE_CONSTRAINT_PRIMARYKEY);
}
