//! Migration 0012: device states, bootstrap guards and first-device
//! confirmations (ADR 0001 D1, R1, R4).
use std::borrow::Cow;

use shardx_team_server::{run_migrations, run_migrations_with};
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;

const INSTANCE: u8 = 0x11;
const APPROVAL_DOMAIN: &str = "shardx.auth.device-approval.v2";

fn b(n: u8) -> Vec<u8> {
    vec![n; 16]
}

fn k(n: u8) -> Vec<u8> {
    vec![n; 32]
}

/// A bound value: bytes bind as BLOB and text as TEXT, so CHECKs compare the
/// way the server's own queries do.
#[derive(Clone)]
enum A {
    B(Vec<u8>),
    T(&'static str),
}

fn ab(n: u8) -> A {
    A::B(b(n))
}

fn ak(n: u8) -> A {
    A::B(k(n))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|x| format!("{x:02x}")).collect()
}

async fn memory() -> SqlitePool {
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap()
}

/// A database migrated through 0011, the schema 0012 upgrades.
async fn before_0012() -> SqlitePool {
    let pool = memory().await;
    let mut migrator = sqlx::migrate!("./migrations");
    migrator.migrations = Cow::Owned(
        migrator
            .iter()
            .filter(|m| m.version <= 11)
            .cloned()
            .collect(),
    );
    run_migrations_with(&pool, &migrator).await.unwrap();
    pool
}

async fn migrated() -> SqlitePool {
    let pool = memory().await;
    run_migrations(&pool).await.unwrap();
    pool
}

async fn exec(pool: &SqlitePool, sql: &str, args: &[A]) -> Result<(), String> {
    let mut q = sqlx::query(sql);
    for a in args {
        q = match a.clone() {
            A::B(v) => q.bind(v),
            A::T(t) => q.bind(t),
        };
    }
    q.execute(pool).await.map(|_| ()).map_err(|e| e.to_string())
}

async fn ok(pool: &SqlitePool, sql: &str, args: &[A]) {
    exec(pool, sql, args).await.unwrap();
}

async fn refused(pool: &SqlitePool, sql: &str, args: &[A], why: &str) {
    let error = exec(pool, sql, args).await.unwrap_err();
    assert!(error.contains(why), "{why}: {error}");
}

async fn mirror(pool: &SqlitePool) {
    ok(
        pool,
        "INSERT INTO v2_server_state VALUES (1, ?, 0, ?, 't')",
        &[ab(INSTANCE), ak(0x12)],
    )
    .await;
}

/// A tenant with its owner account; `cli` adds the offline `tenant.create`
/// audit row that proves `tenant create` made it.
async fn tenant(pool: &SqlitePool, id: u8, cli: bool) {
    ok(
        pool,
        &format!("INSERT INTO v2_tenants VALUES (?, 'tenant-{id}', 'active', NULL, 't')"),
        &[ab(id)],
    )
    .await;
    ok(
        pool,
        "INSERT INTO v2_accounts VALUES (?, ?, 'owner', 'x', NULL, 0, 'active', 't')",
        &[ab(id + 0x80), ab(id)],
    )
    .await;
    if cli {
        ok(
            pool,
            "INSERT INTO v2_audit_events VALUES (?, ?, NULL, NULL, 'tenant.create', 'tenant', ?, \
             'success', 'offline_operator_cli', ?, 't')",
            &[ab(id), ab(id + 0x40), ab(id), ab(id + 0x41)],
        )
        .await;
    }
}

/// Signing ID `k(id)`, signing key `k(id+1)`, HPKE ID `k(id+2)`, HPKE key `k(id+3)`.
async fn device(pool: &SqlitePool, tenant: u8, id: u8, status: &'static str) {
    ok(
        pool,
        "INSERT INTO v2_devices VALUES (?, ?, ?, x'aa', ?, ?, 1, ?, ?, 1, ?, NULL, 't')",
        &[
            ab(id),
            ab(tenant),
            ab(tenant + 0x80),
            ak(id),
            ak(id + 1),
            ak(id + 2),
            ak(id + 3),
            A::T(status),
        ],
    )
    .await;
}

async fn applied(pool: &SqlitePool) -> i64 {
    sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
        .fetch_one(pool)
        .await
        .unwrap()
}

type Guard = (Vec<u8>, Vec<u8>, String, Option<String>);

async fn guards(pool: &SqlitePool) -> Vec<Guard> {
    sqlx::query_as(
        "SELECT server_instance_id, tenant_id, state, recovery_reason \
         FROM v2_bootstrap_guards ORDER BY tenant_id",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn fk_clean(pool: &SqlitePool) {
    assert!(sqlx::query("PRAGMA foreign_key_check")
        .fetch_all(pool)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn upgrade_quarantines_legacy_active_devices_and_seeds_guards() {
    let pool = before_0012().await;
    mirror(&pool).await;
    tenant(&pool, 1, true).await; // fresh from `tenant create`
    tenant(&pool, 2, true).await; // made by the CLI, but holds devices now
    device(&pool, 2, 0x20, "active").await;
    device(&pool, 2, 0x30, "revoked").await;
    tenant(&pool, 3, false).await; // no provenance
                                   // A child row of the legacy device: kept, but its session is revoked (R4).
    ok(
        &pool,
        "INSERT INTO v2_sessions VALUES (?, ?, ?, ?, ?, '2099', NULL)",
        &[ab(0x21), ab(2), ab(0x82), ab(0x20), ak(0x23)],
    )
    .await;
    let carried = "SELECT quote(id) || quote(tenant_id) || quote(account_id) || \
                   quote(label_ciphertext) || quote(signing_key_id) || quote(signing_public_key) || \
                   quote(signing_suite) || quote(hpke_key_id) || quote(hpke_public_key) || \
                   quote(hpke_suite) || quote(last_seen_at) || quote(created_at) \
                   FROM v2_devices ORDER BY id";
    let before: Vec<String> = sqlx::query_scalar(carried).fetch_all(&pool).await.unwrap();

    run_migrations(&pool).await.unwrap();

    // Every column but status is carried over unchanged.
    let after: Vec<String> = sqlx::query_scalar(carried).fetch_all(&pool).await.unwrap();
    assert_eq!(after, before);
    let states: Vec<(Vec<u8>, String)> =
        sqlx::query_as("SELECT id, status FROM v2_devices ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        states,
        vec![(b(0x20), "quarantined".into()), (b(0x30), "revoked".into())]
    );
    type Quarantine = (Vec<u8>, String, String, Vec<u8>, Vec<u8>);
    let quarantine: Vec<Quarantine> = sqlx::query_as(
        "SELECT device_id, reason, prior_status, stored_signing_key_id, stored_hpke_key_id \
         FROM v2_device_quarantine",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        quarantine,
        vec![(
            b(0x20),
            "legacy_unproven_active".into(),
            "active".into(),
            k(0x20),
            k(0x22)
        )]
    );
    let session: (Vec<u8>, bool) =
        sqlx::query_as("SELECT device_id, revoked_at IS NOT NULL FROM v2_sessions")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(session, (b(0x20), true));
    let index: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM sqlite_master \
         WHERE type = 'index' AND name = 'v2_devices_by_account'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(index, 1, "the rebuild keeps the 0004 index");

    let legacy = |t| {
        (
            b(INSTANCE),
            b(t),
            "recovery_required".to_string(),
            Some("legacy_tenant".to_string()),
        )
    };
    assert_eq!(
        guards(&pool).await,
        vec![
            (b(INSTANCE), b(1), "unused".into(), None),
            legacy(2),
            legacy(3)
        ]
    );
    fk_clean(&pool).await;
}

#[tokio::test]
async fn without_an_identity_mirror_no_guard_is_seeded() {
    let pool = before_0012().await;
    tenant(&pool, 1, true).await;
    run_migrations(&pool).await.unwrap();
    // The startup integrity pass creates it later, as recovery_required.
    assert!(guards(&pool).await.is_empty());
}

#[tokio::test]
async fn a_stored_approval_stops_the_migration() {
    let pool = before_0012().await;
    mirror(&pool).await;
    tenant(&pool, 1, true).await;
    ok(
        &pool,
        "INSERT INTO v2_device_approvals VALUES (?, ?, 'd', 2, ?, ?, ?, ?, 'tenant', ?, \
         'team.device', 1, 1, 2, ?, 0, x'aa', ?, 1, 1, ?, ?, ?, x'bb', ?, NULL, 't')",
        &[
            ab(1),
            ab(2),
            ab(3),
            ab(4),
            ak(5),
            ak(6),
            ab(1),
            ab(INSTANCE),
            ak(7),
            A::B(vec![8; 64]),
            ak(9),
            ak(10),
            ak(11),
        ],
    )
    .await;
    let error = run_migrations(&pool).await.unwrap_err().to_string();
    assert!(
        error.contains("m0012_device_approvals_must_be_empty"),
        "{error}"
    );
    assert_eq!(applied(&pool).await, 11);
    let leftovers: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM sqlite_master \
         WHERE name IN ('v2_device_quarantine', 'v2_bootstrap_guards')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(leftovers, 0, "nothing of 0012 remains");
}

#[tokio::test]
async fn a_guard_only_moves_forward_and_is_never_deleted() {
    let pool = migrated().await;
    tenant(&pool, 1, false).await;
    let set = "UPDATE v2_bootstrap_guards SET state = ? WHERE tenant_id = ?";
    let not_allowed = "bootstrap guard transition not allowed";
    ok(
        &pool,
        "INSERT INTO v2_bootstrap_guards VALUES (?, ?, 'unused', NULL, 't')",
        &[ab(INSTANCE), ab(1)],
    )
    .await;
    // Closing needs a reservation first (R1 table).
    refused(&pool, set, &[A::T("closed"), ab(1)], not_allowed).await;
    // REPLACE would skip the delete and transition triggers.
    refused(
        &pool,
        "INSERT OR REPLACE INTO v2_bootstrap_guards VALUES (?, ?, 'unused', NULL, 't')",
        &[ab(INSTANCE), ab(1)],
        "inserted once",
    )
    .await;
    ok(&pool, set, &[A::T("reserved"), ab(1)]).await;
    for back in ["unused", "reserved"] {
        refused(&pool, set, &[A::T(back), ab(1)], not_allowed).await;
    }
    ok(&pool, set, &[A::T("consumed"), ab(1)]).await;
    refused(&pool, set, &[A::T("unused"), ab(1)], not_allowed).await;
    // Recovery always names its reason.
    refused(
        &pool,
        set,
        &[A::T("recovery_required"), ab(1)],
        "CHECK constraint failed",
    )
    .await;
    refused(
        &pool,
        "DELETE FROM v2_bootstrap_guards",
        &[],
        "a bootstrap guard is never deleted",
    )
    .await;
    // A guard is born unused or in recovery, and recovery is kept as found.
    tenant(&pool, 2, false).await;
    refused(
        &pool,
        "INSERT INTO v2_bootstrap_guards VALUES (?, ?, 'consumed', NULL, 't')",
        &[ab(INSTANCE), ab(2)],
        "inserted once",
    )
    .await;
    ok(
        &pool,
        "INSERT INTO v2_bootstrap_guards VALUES (?, ?, 'recovery_required', 'legacy_tenant', 't')",
        &[ab(INSTANCE), ab(2)],
    )
    .await;
    refused(
        &pool,
        "UPDATE v2_bootstrap_guards SET recovery_reason = 'missing_guard' WHERE tenant_id = ?",
        &[ab(2)],
        "kept as found",
    )
    .await;
    refused(
        &pool,
        "UPDATE v2_bootstrap_guards SET tenant_id = ? WHERE tenant_id = ?",
        &[ab(2), ab(1)],
        "cannot move to another instance or tenant",
    )
    .await;
}

async fn confirmation(pool: &SqlitePool, tenant: u8, device: u8) {
    ok(
        pool,
        "INSERT INTO v2_first_device_confirmations \
         (server_instance_id, tenant_id, confirmation_id, account_id, device_id, request_id, \
          restore_epoch, confirmed_at_ms, signing_key_id, hpke_key_id, signing_public_key, \
          hpke_public_key, signing_suite, hpke_suite, state) \
         VALUES (?, ?, ?, ?, ?, ?, 0, 1, ?, ?, ?, ?, 1, 1, 'pending')",
        &[
            ab(INSTANCE),
            ab(tenant),
            ab(tenant + 0x60),
            ab(tenant + 0x80),
            ab(device),
            ab(tenant + 0x61),
            ak(device),
            ak(device + 2),
            ak(device + 1),
            ak(device + 3),
        ],
    )
    .await;
}

async fn approval(pool: &SqlitePool, tenant: u8, device: u8, replay: u8) {
    ok(
        pool,
        "INSERT INTO v2_device_approvals VALUES (?, ?, ?, 2, ?, ?, ?, ?, 'tenant', ?, \
         'team.device', 1, 1, 2, ?, 0, x'aa', ?, 1, 1, ?, ?, ?, x'bb', ?, NULL, 't')",
        &[
            ab(tenant),
            ab(replay),
            A::T(APPROVAL_DOMAIN),
            ab(tenant + 0x80),
            ab(device),
            ak(device),
            ak(device + 2),
            ab(tenant),
            ab(INSTANCE),
            ak(0x70),
            A::B(vec![0x71; 64]),
            ak(device),
            ak(0x72),
            ak(0x73),
        ],
    )
    .await;
}

#[tokio::test]
async fn a_confirmation_is_consumed_once_with_its_full_link() {
    let pool = migrated().await;
    tenant(&pool, 1, false).await;
    device(&pool, 1, 0x20, "pending").await;
    confirmation(&pool, 1, 0x20).await;
    let consume = |replay: u8| {
        format!(
            "UPDATE v2_first_device_confirmations SET state = 'consumed', consumed_at_ms = 2, \
             approval_payload_domain = '{APPROVAL_DOMAIN}', approval_replay_id = x'{}', \
             approval_payload_sha256 = zeroblob(32), \
             approval_signed_container_hash = zeroblob(32), approval_outer_sha256 = zeroblob(32)",
            hex(&b(replay))
        )
    };

    // Born pending, and never replaced.
    refused(
        &pool,
        "INSERT OR REPLACE INTO v2_first_device_confirmations \
         SELECT * FROM v2_first_device_confirmations",
        &[],
        "inserted once",
    )
    .await;
    // The subject never changes, even while pending.
    refused(
        &pool,
        "UPDATE v2_first_device_confirmations SET account_id = ?",
        &[ab(9)],
        "subject never changes",
    )
    .await;
    // Half a link is refused, and so is a link to no approval.
    refused(
        &pool,
        "UPDATE v2_first_device_confirmations SET state = 'consumed', consumed_at_ms = 2",
        &[],
        "CHECK constraint failed",
    )
    .await;
    refused(&pool, &consume(0x50), &[], "FOREIGN KEY constraint failed").await;

    approval(&pool, 1, 0x20, 0x50).await;
    ok(&pool, &consume(0x50), &[]).await;

    // Once consumed nothing moves: not the state, not the link.
    refused(
        &pool,
        "UPDATE v2_first_device_confirmations SET state = 'invalidated', terminal_at_ms = 3, \
         terminal_reason = 'device_revoked', consumed_at_ms = NULL",
        &[],
        "settled first-device confirmation never changes",
    )
    .await;
    refused(
        &pool,
        "UPDATE v2_first_device_confirmations SET approval_outer_sha256 = ?",
        &[ak(1)],
        "settled first-device confirmation never changes",
    )
    .await;
    refused(
        &pool,
        "DELETE FROM v2_device_approvals",
        &[],
        "FOREIGN KEY constraint failed",
    )
    .await;
    refused(
        &pool,
        "DELETE FROM v2_first_device_confirmations",
        &[],
        "never deleted",
    )
    .await;
}

#[tokio::test]
async fn a_cancellation_names_the_operator() {
    let pool = migrated().await;
    tenant(&pool, 1, false).await;
    device(&pool, 1, 0x20, "pending").await;
    confirmation(&pool, 1, 0x20).await;
    let end = "UPDATE v2_first_device_confirmations SET state = ?, terminal_at_ms = 3, \
               terminal_reason = ?";
    let check = "CHECK constraint failed";
    refused(
        &pool,
        end,
        &[A::T("cancelled"), A::T("device_revoked")],
        check,
    )
    .await;
    refused(
        &pool,
        end,
        &[A::T("invalidated"), A::T("operator_cancelled")],
        check,
    )
    .await;
    ok(&pool, end, &[A::T("cancelled"), A::T("operator_cancelled")]).await;
}

#[tokio::test]
async fn a_quarantined_device_can_only_be_revoked() {
    let pool = migrated().await;
    tenant(&pool, 1, false).await;
    device(&pool, 1, 0x20, "quarantined").await;
    ok(
        &pool,
        "INSERT INTO v2_device_quarantine VALUES (?, ?, 'key_id_mismatch', 'pending', ?, ?, 't')",
        &[ab(1), ab(0x20), ak(0x20), ak(0x22)],
    )
    .await;
    refused(
        &pool,
        "INSERT OR REPLACE INTO v2_device_quarantine \
         VALUES (?, ?, 'invalid_key_encoding', 'pending', ?, ?, 't')",
        &[ab(1), ab(0x20), ak(0x20), ak(0x22)],
        "permanent",
    )
    .await;
    let back = "UPDATE v2_devices SET status = ?";
    for status in ["active", "pending"] {
        refused(&pool, back, &[A::T(status)], "can only be revoked").await;
    }
    // The record, not the status, holds it: revoking first is no way back.
    ok(&pool, "UPDATE v2_devices SET status = 'revoked'", &[]).await;
    for status in ["active", "pending"] {
        refused(&pool, back, &[A::T(status)], "can only be revoked").await;
    }
}

#[tokio::test]
async fn approval_rows_carry_the_contract_values() {
    let pool = migrated().await;
    tenant(&pool, 1, false).await;
    device(&pool, 1, 0x20, "pending").await;
    approval(&pool, 1, 0x20, 0x50).await;
    for (column, value) in [
        ("approved_use", "'team.admin'"),
        ("approval_scope_kind", "'profile'"),
        ("payload_version", "3"),
        ("subject_hpke_key_id", "subject_signing_key_id"),
        ("not_after_ms", "not_before_ms"),
    ] {
        refused(
            &pool,
            &format!("UPDATE v2_device_approvals SET {column} = {value}"),
            &[],
            "CHECK constraint failed",
        )
        .await;
    }
}
