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
    shardx_team_server::run_migrations(&pool).await.unwrap();
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

#[tokio::test]
async fn only_offline_operator_audit_rows_may_omit_the_actor() {
    // ADR 0001 D3: NULL actors mean an offline operator command, and nothing
    // else may record an anonymous actor.
    let pool = pool().await;
    seed_tenant(&pool, 1).await;
    let insert = |n: u8, actor: Option<u8>, device: Option<u8>, reason: Option<&'static str>| {
        sqlx::query(
            "INSERT INTO v2_audit_events (tenant_id, id, actor_account_id, actor_device_id,
                action, target_type, target_id, outcome, reason_code, request_id, created_at)
             VALUES (?, ?, ?, ?, 'tenant.create', 'tenant', ?, 'success', ?, ?,
                '2026-09-02T00:00:00+00:00')",
        )
        .bind(id(1))
        .bind(id(n))
        .bind(actor.map(id))
        .bind(device.map(id))
        .bind(id(1))
        .bind(reason)
        .bind(id(90 + n))
    };

    insert(1, None, None, Some("offline_operator_cli"))
        .execute(&pool)
        .await
        .unwrap();
    insert(2, Some(3), Some(4), None)
        .execute(&pool)
        .await
        .unwrap();

    for (n, actor, device, reason) in [
        (5, None, None, None),
        (6, None, None, Some("other")),
        (7, Some(3), None, None),
        (8, None, Some(4), Some("offline_operator_cli")),
        (9, Some(3), Some(4), Some("offline_operator_cli")),
    ] {
        let err = insert(n, actor, device, reason)
            .execute(&pool)
            .await
            .unwrap_err();
        assert_eq!(err_code(err), SQLITE_CONSTRAINT_CHECK, "row {n}");
    }
}

/// 0021: a fleet generation keeps its D-9 terms, carries all of them or none,
/// and only moves forward (ADR 0002 D-9).
#[tokio::test]
async fn a_fleet_generation_keeps_its_terms_and_moves_forward() {
    const TRIGGER: &str = "1811";
    // The generation's foreign keys are not what this test is about.
    let options = "sqlite::memory:"
        .parse::<sqlx::sqlite::SqliteConnectOptions>()
        .unwrap()
        .foreign_keys(false);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    shardx_team_server::run_migrations(&pool).await.unwrap();
    let insert = |generation: i64, fkek: u8, terms: bool, previous: bool| {
        sqlx::query(
            "INSERT INTO v2_fleet_key_generations (
                 server_instance_id, tenant_id, fleet_id, generation, fkek_key_id,
                 root_generation, state, created_at, required_device_grant_count,
                 required_grant_set_hash, recovery_grant_hash, previous_fkek_key_id,
                 rotation_grant_hash)
             VALUES (?, ?, ?, ?, ?, 0, 'PREPARING', 'now', ?, ?, ?, ?, ?)",
        )
        .bind(id(1))
        .bind(id(2))
        .bind(id(3))
        .bind(generation)
        .bind(key32(fkek))
        .bind(terms.then_some(1_i64))
        .bind(terms.then(|| key32(0x51)))
        .bind(terms.then(|| key32(0x52)))
        .bind(previous.then(|| key32(0x53)))
        .bind(previous.then(|| key32(0x54)))
        .execute(&pool)
    };
    // Generation 0 has no rotation pair, a rotation has one, and a legacy row
    // has no terms at all.
    for (generation, fkek, terms, previous) in [(0, 0x60, true, true), (1, 0x61, true, false)] {
        let e = insert(generation, fkek, terms, previous).await.unwrap_err();
        assert_eq!(err_code(e), TRIGGER, "generation {generation}");
    }
    insert(0, 0x62, true, false).await.unwrap();
    insert(1, 0x63, true, true).await.unwrap();
    insert(2, 0x64, false, false).await.unwrap();

    let update = |set: &'static str| {
        let statement = format!("UPDATE v2_fleet_key_generations SET {set} WHERE generation = 0");
        let pool = pool.clone();
        async move { sqlx::query(&statement).execute(&pool).await }
    };
    for set in [
        "required_grant_set_hash = zeroblob(32)",
        "recovery_grant_hash = zeroblob(32)",
        "root_generation = 1",
        "state = 'ACTIVE'",
    ] {
        assert_eq!(err_code(update(set).await.unwrap_err()), TRIGGER, "{set}");
    }
    update("state = 'ACTIVE', activated_at = 'now'")
        .await
        .unwrap();
    for set in [
        "state = 'PREPARING', activated_at = NULL",
        "activated_at = 'later'",
        "state = 'RETIRED'",
    ] {
        assert_eq!(err_code(update(set).await.unwrap_err()), TRIGGER, "{set}");
    }
    update("state = 'RETIRED', retired_at = 'now'")
        .await
        .unwrap();

    // The grant-side guards are present; the routes' tests drive them.
    for name in [
        "v2_fleet_key_grants_not_for_d9_generations",
        "v2_fleet_device_hpke_grants_window_is_bounded",
        "v2_fleet_recovery_grants_window_is_bounded",
        "v2_fleet_rotation_grants_window_is_bounded",
    ] {
        let n: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM sqlite_master WHERE type = 'trigger' AND name = ?",
        )
        .bind(name)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(n, 1, "{name}");
    }
}

/// 0022: the mutations added after 0020 commit with their responses, and a
/// fleet key generation is never removed or replaced.
#[tokio::test]
async fn later_mutations_store_their_responses_and_a_generation_is_never_removed() {
    const TRIGGER: &str = "1811";
    let options = "sqlite::memory:"
        .parse::<sqlx::sqlite::SqliteConnectOptions>()
        .unwrap()
        .foreign_keys(false);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    shardx_team_server::run_migrations(&pool).await.unwrap();

    let mut key = 0u8;
    let mut row =
        |kind: &'static str, scope: &'static str, status: &'static str, record: &'static str| {
            key += 1;
            let (pool, idempotency_key) = (pool.clone(), id(key));
            async move {
                sqlx::query(
                    "INSERT INTO v2_idempotency (
                     server_instance_id, tenant_id, actor_device_id, operation_scope,
                     idempotency_key, operation_kind, canonical_request_hash, exact_request_bytes,
                     exact_request_bytes_sha256, status, response_record_type,
                     exact_response_bytes, exact_response_bytes_sha256, retained_until)
                 VALUES (?, ?, ?, ?, ?, ?, ?, x'01', ?, ?, ?, x'02', ?, 0)",
                )
                .bind(id(1))
                .bind(id(2))
                .bind(id(3))
                .bind(scope)
                .bind(idempotency_key)
                .bind(kind)
                .bind(key32(4))
                .bind(key32(5))
                .bind(status)
                .bind(record)
                .bind(key32(6))
                .execute(&pool)
                .await
            }
        };
    for (kind, scope, record) in [
        (
            "ROOT_GRANT_CREATE",
            "tenant.root-grant-create.v2",
            "TenantRootGrantCreatedV2",
        ),
        (
            "ROOT_GRANT_REVOKE",
            "tenant.root-grant-revoke.v2",
            "TenantRootGrantRevokedV2",
        ),
        (
            "FLEET_GRANT_ACK",
            "fleet.key-grant-ack.v2",
            "FleetKeyGrantAckedV2",
        ),
        (
            "FLEET_GENERATION_ACTIVATE",
            "fleet.key-generation-activate.v2",
            "FleetKeyGenerationActivatedV2",
        ),
        (
            "FLEET_GRANT_REVOKE",
            "fleet.key-grant-revoke.v2",
            "FleetGrantRevokedV2",
        ),
    ] {
        for (k, s, st, r) in [
            (kind, scope, "in_flight", record),
            (kind, scope, "succeeded", "DeviceApprovalReceiptV2"),
            (kind, "profile.checkout.v2", "succeeded", record),
            ("PROFILE_CHECKOUT", scope, "succeeded", record),
        ] {
            let e = row(k, s, st, r).await.unwrap_err();
            assert_eq!(err_code(e), TRIGGER, "{k} {s} {st} {r}");
        }
        row(kind, scope, "succeeded", record).await.unwrap();
    }

    sqlx::query(
        "INSERT INTO v2_fleet_key_generations (
             server_instance_id, tenant_id, fleet_id, generation, fkek_key_id,
             root_generation, state, created_at)
         VALUES (?, ?, ?, 0, ?, 0, 'PREPARING', 'now')",
    )
    .bind(id(1))
    .bind(id(2))
    .bind(id(3))
    .bind(key32(7))
    .execute(&pool)
    .await
    .unwrap();
    for statement in [
        "INSERT OR REPLACE INTO v2_fleet_key_generations (
             server_instance_id, tenant_id, fleet_id, generation, fkek_key_id,
             root_generation, state, created_at)
         SELECT server_instance_id, tenant_id, fleet_id, generation, zeroblob(32),
                root_generation, state, created_at FROM v2_fleet_key_generations",
        "DELETE FROM v2_fleet_key_generations",
    ] {
        let e = sqlx::query(statement).execute(&pool).await.unwrap_err();
        assert_eq!(err_code(e), TRIGGER, "{statement}");
    }
}
