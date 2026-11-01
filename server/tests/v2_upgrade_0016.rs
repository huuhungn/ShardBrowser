//! Migration 0016: spike root grants archived read-only, the exact plan 7.2
//! root grant table, and the custodian terms of a root generation.
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

/// The SQLite extended result code of a refused statement, or `None`.
async fn refused(pool: &SqlitePool, sql: &str) -> Option<String> {
    match sqlx::query(sql).execute(pool).await {
        Ok(_) => None,
        Err(e) => Some(e.as_database_error().unwrap().code().unwrap().into_owned()),
    }
}

async fn exec(pool: &SqlitePool, sql: &str) {
    sqlx::query(sql).execute(pool).await.unwrap();
}

async fn count(pool: &SqlitePool, sql: &str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(pool).await.unwrap()
}

const I: &str = "x'11111111111111111111111111111111'";
const OTHER_I: &str = "x'99999999999999999999999999999999'";
// The tenant with spike history, and a fresh one.
const T1: &str = "x'01010101010101010101010101010101'";
const T2: &str = "x'02020202020202020202020202020202'";
const A1: &str = "x'03030303030303030303030303030303'";
const D1: &str = "x'04040404040404040404040404040404'";
const A2: &str = "x'05050505050505050505050505050505'";
const D2: &str = "x'06060606060606060606060606060606'";
const R2: &str = "x'07070707070707070707070707070707'";
const OLD_KEY: &str = "x'2020202020202020202020202020202020202020202020202020202020202020'";
const ROOT: &str = "x'2121212121212121212121212121212121212121212121212121212121212121'";
const SIGN: &str = "x'4444444444444444444444444444444444444444444444444444444444444444'";
const HPKE: &str = "x'4545454545454545454545454545454545454545454545454545454545454545'";

const CHECK: Option<&str> = Some("275");
const FOREIGN_KEY: Option<&str> = Some("787");
const NOT_NULL: Option<&str> = Some("1299");
const TRIGGER: Option<&str> = Some("1811");

type Overrides = Vec<(&'static str, &'static str)>;

/// An honest first self-grant of `ROOT` to `D2`; each `(column, value)`
/// replaces one default.
fn grant(over: &[(&str, &str)]) -> String {
    let mut cols: Vec<(&str, String)> = [
        ("server_instance_id", I),
        ("tenant_id", T2),
        ("replay_id", "x'61616161616161616161616161616161'"),
        (
            "container_domain",
            "'shardx.authorization.signed-container.v2'",
        ),
        ("container_version", "2"),
        ("payload_domain", "'shardx.keys.tenant-root-key-grant.v2'"),
        ("payload_version", "2"),
        ("grant_variant", "'FirstRootSelfGrant'"),
        ("root_key_id", ROOT),
        ("root_generation", "0"),
        ("grant_capability", "'root.custody'"),
        ("subject_account_id", A2),
        ("subject_device_id", D2),
        ("subject_signing_key_id", SIGN),
        (
            "subject_device_approval_payload_domain",
            "'shardx.auth.device-approval.v2'",
        ),
        ("subject_device_approval_replay_id", R2),
        ("recipient_hpke_key_id", HPKE),
        ("hpke_suite_id", "1"),
        ("hpke_mode_id", "0"),
        ("hpke_kem_id", "32"),
        ("hpke_kdf_id", "1"),
        ("hpke_aead_id", "3"),
        ("hpke_info_bytes", "x'aa'"),
        ("hpke_encapped_key_bytes", "zeroblob(32)"),
        ("hpke_wrapped_trk_bytes", "zeroblob(48)"),
        ("previous_root_key_id", "NULL"),
        ("previous_root_generation", "NULL"),
        ("issued_at_ms", "1"),
        ("not_before_ms", "1"),
        ("not_after_ms", "2"),
        ("restore_epoch", "0"),
        ("canonical_payload_bytes", "x'bb'"),
        ("payload_sha256", "zeroblob(32)"),
        ("signature_suite_id", "1"),
        ("signature_version", "1"),
        ("issuer_signing_key_id", SIGN),
        ("signature_bytes", "zeroblob(64)"),
        ("signed_container_hash", "zeroblob(32)"),
        ("exact_signed_container_bytes", "x'cc'"),
        ("exact_signed_container_bytes_sha256", "zeroblob(32)"),
        ("created_at", "'t'"),
    ]
    .into_iter()
    .map(|(c, v)| (c, v.to_string()))
    .collect();
    for (col, value) in over {
        let slot = cols.iter_mut().find(|(c, _)| c == col).expect(col);
        slot.1 = value.to_string();
    }
    let names: Vec<&str> = cols.iter().map(|(c, _)| *c).collect();
    let values: Vec<&str> = cols.iter().map(|(_, v)| v.as_str()).collect();
    format!(
        "INSERT INTO v2_tenant_root_key_grants ({}) VALUES ({})",
        names.join(", "),
        values.join(", ")
    )
}

fn account_and_device(tenant: &str, account: &str, device: &str) -> [String; 2] {
    [
        format!(
            "INSERT INTO v2_accounts (id, tenant_id, username, pw_hash, status, created_at) \
             VALUES ({account}, {tenant}, 'owner', 'hash', 'active', 't')"
        ),
        format!(
            "INSERT INTO v2_devices (id, tenant_id, account_id, label_ciphertext, signing_key_id, \
               signing_public_key, signing_suite, hpke_key_id, hpke_public_key, hpke_suite, \
               status, created_at) \
             VALUES ({device}, {tenant}, {account}, x'00', {SIGN}, randomblob(32), 1, {HPKE}, \
                     randomblob(32), 1, 'active', 't')"
        ),
    ]
}

/// A database at 0015 with spike history on `T1`, migrated to the latest.
async fn upgraded() -> SqlitePool {
    let pool = through(15).await;
    exec(&pool, "PRAGMA foreign_keys = ON").await;
    let mut setup = vec![
        format!("INSERT INTO v2_server_state VALUES (1, {I}, 0, randomblob(32), 't')"),
        format!("INSERT INTO v2_tenants VALUES ({T1}, 'one', 'active', 0, 't')"),
        format!("INSERT INTO v2_tenants VALUES ({T2}, 'two', 'active', NULL, 't')"),
        format!(
            "INSERT INTO v2_root_key_generations \
             (server_instance_id, tenant_id, generation, root_key_id, state, created_at) \
             VALUES ({I}, {T1}, 0, {OLD_KEY}, 'ACTIVE', 't')"
        ),
    ];
    setup.extend(account_and_device(T1, A1, D1));
    setup.extend(account_and_device(T2, A2, D2));
    setup.push(format!(
        "INSERT INTO v2_tenant_root_key_grants \
         (tenant_id, replay_id, payload_domain, grant_variant, root_key_id, root_generation, \
          grant_capability, subject_account_id, subject_device_id, subject_signing_key_id, \
          recipient_hpke_key_id, subject_device_approval_replay_id, hpke_suite_id, hpke_mode_id, \
          hpke_kem_id, hpke_kdf_id, hpke_aead_id, hpke_info_bytes, hpke_encapped_key_bytes, \
          hpke_wrapped_trk_bytes, server_instance_id, restore_epoch, signature_bytes, \
          issuer_signing_key_id, signed_container_hash, exact_signed_container_bytes, \
          exact_signed_container_bytes_sha256, created_at) \
         VALUES ({T1}, x'30303030303030303030303030303030', 'domain', 'FirstRootSelfGrant', \
                 {OLD_KEY}, 0, 'root.custody', {A1}, {D1}, {SIGN}, {HPKE}, \
                 x'31313131313131313131313131313131', 1, 0, 32, 1, 3, x'aa', x'bb', x'cc', {I}, \
                 0, randomblob(64), {SIGN}, randomblob(32), x'dd', randomblob(32), 't')"
    ));
    for sql in &setup {
        exec(&pool, sql).await;
    }
    run_migrations(&pool).await.unwrap();
    pool
}

#[tokio::test]
async fn spike_root_grants_stay_as_they_were_and_read_only() {
    let pool = upgraded().await;
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM v2_legacy_tenant_root_key_grants"
        )
        .await,
        1
    );
    assert_eq!(
        count(&pool, "SELECT count(*) FROM v2_tenant_root_key_grants").await,
        0
    );
    assert_eq!(
        refused(
            &pool,
            "UPDATE v2_legacy_tenant_root_key_grants SET revoked_at = 'now'"
        )
        .await
        .as_deref(),
        TRIGGER
    );
    assert_eq!(
        refused(
            &pool,
            "INSERT INTO v2_legacy_tenant_root_key_grants SELECT * FROM v2_legacy_tenant_root_key_grants"
        )
        .await
        .as_deref(),
        TRIGGER
    );

    // The spike generation keeps its NULL terms; a new one must name them,
    // and they never change.
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM v2_root_key_generations WHERE required_custodian_grant_count IS NULL"
        )
        .await,
        1
    );
    let generation = |terms: &str| {
        format!(
            "INSERT INTO v2_root_key_generations \
             (server_instance_id, tenant_id, generation, root_key_id, state, created_at, \
              required_custodian_grant_count, required_custodian_grant_set_hash, \
              recovery_bundle_sha256) \
             VALUES ({I}, {T2}, 0, {ROOT}, 'PREPARING', 't', {terms})"
        )
    };
    for terms in [
        "NULL, zeroblob(32), zeroblob(32)",
        "1, NULL, zeroblob(32)",
        "1, zeroblob(32), NULL",
    ] {
        assert_eq!(
            refused(&pool, &generation(terms)).await.as_deref(),
            TRIGGER,
            "{terms}"
        );
    }
    for terms in [
        "0, zeroblob(32), zeroblob(32)",
        "1, zeroblob(31), zeroblob(32)",
    ] {
        assert_eq!(
            refused(&pool, &generation(terms)).await.as_deref(),
            CHECK,
            "{terms}"
        );
    }
    exec(&pool, &generation("1, zeroblob(32), zeroblob(32)")).await;
    assert_eq!(
        refused(
            &pool,
            &generation("2, zeroblob(32), zeroblob(32)").replacen("INSERT", "INSERT OR REPLACE", 1)
        )
        .await
        .as_deref(),
        TRIGGER
    );
    for set in [
        "required_custodian_grant_count = 2",
        "required_custodian_grant_set_hash = randomblob(32)",
        "recovery_bundle_sha256 = randomblob(32)",
        "root_key_id = randomblob(32)",
    ] {
        assert_eq!(
            refused(
                &pool,
                &format!("UPDATE v2_root_key_generations SET {set} WHERE tenant_id = {T2}")
            )
            .await
            .as_deref(),
            TRIGGER,
            "{set}"
        );
    }
}

#[tokio::test]
async fn a_root_grant_row_is_exactly_the_plan_shape_and_is_history() {
    let pool = upgraded().await;
    for sql in [
        format!(
            "INSERT INTO v2_root_key_generations \
             (server_instance_id, tenant_id, generation, root_key_id, state, created_at, \
              required_custodian_grant_count, required_custodian_grant_set_hash, \
              recovery_bundle_sha256) \
             VALUES ({I}, {T2}, 0, {ROOT}, 'PREPARING', 't', 1, zeroblob(32), zeroblob(32))"
        ),
        format!(
            "INSERT INTO v2_device_approvals VALUES ({T2}, {R2}, \
             'shardx.auth.device-approval.v2', 2, {A2}, {D2}, {SIGN}, {HPKE}, 'tenant', {T2}, \
             'team.device', 1, 1, 2, {I}, 0, x'aa', randomblob(32), 1, 1, randomblob(64), \
             {SIGN}, randomblob(32), x'bb', randomblob(32), NULL, 't')"
        ),
    ] {
        exec(&pool, &sql).await;
    }

    let rotation = "'RotationGrant'";
    let other_key = "x'5050505050505050505050505050505050505050505050505050505050505050'";
    let cases: Vec<(Option<&str>, Overrides)> = vec![
        // Links: another tenant's device, another instance, no approval.
        (FOREIGN_KEY, vec![("subject_device_id", D1)]),
        (FOREIGN_KEY, vec![("subject_account_id", A1)]),
        (FOREIGN_KEY, vec![("server_instance_id", OTHER_I)]),
        (
            FOREIGN_KEY,
            vec![(
                "subject_device_approval_replay_id",
                "x'77777777777777777777777777777777'",
            )],
        ),
        (FOREIGN_KEY, vec![("root_key_id", other_key)]),
        // Constants and types.
        (CHECK, vec![("payload_domain", "'shardx.keys.other.v2'")]),
        (CHECK, vec![("grant_capability", "'root.read'")]),
        (CHECK, vec![("hpke_kem_id", "16")]),
        (CHECK, vec![("hpke_wrapped_trk_bytes", "zeroblob(32)")]),
        (CHECK, vec![("grant_variant", "'CustodianIssued'")]),
        (NOT_NULL, vec![("hpke_info_bytes", "NULL")]),
        (NOT_NULL, vec![("exact_signed_container_bytes", "NULL")]),
        // The previous pair exists iff rotation, each half on its own.
        (CHECK, vec![("grant_variant", rotation)]),
        (
            CHECK,
            vec![
                ("grant_variant", rotation),
                ("root_generation", "1"),
                ("previous_root_generation", "0"),
            ],
        ),
        (
            CHECK,
            vec![
                ("grant_variant", rotation),
                ("root_generation", "1"),
                ("previous_root_key_id", other_key),
            ],
        ),
        (CHECK, vec![("previous_root_key_id", other_key)]),
        (CHECK, vec![("previous_root_generation", "0")]),
        (
            CHECK,
            vec![
                ("previous_root_key_id", other_key),
                ("previous_root_generation", "0"),
            ],
        ),
        (
            CHECK,
            vec![
                ("grant_variant", "'ExistingRootGrant'"),
                ("previous_root_key_id", other_key),
                ("previous_root_generation", "0"),
            ],
        ),
        // A rotation is previous + 1 under another key.
        (
            CHECK,
            vec![
                ("grant_variant", rotation),
                ("previous_root_key_id", other_key),
                ("previous_root_generation", "0"),
            ],
        ),
        (
            CHECK,
            vec![
                ("grant_variant", rotation),
                ("root_generation", "1"),
                ("previous_root_key_id", ROOT),
                ("previous_root_generation", "0"),
            ],
        ),
        // A self-grant is generation 0. CHECKs run before foreign keys, so
        // the missing generation 1 cannot be what refuses these.
        (CHECK, vec![("root_generation", "1")]),
        // The self-grant signs itself; keys and window.
        (
            CHECK,
            vec![(
                "issuer_signing_key_id",
                "x'4646464646464646464646464646464646464646464646464646464646464646'",
            )],
        ),
        (CHECK, vec![("recipient_hpke_key_id", SIGN)]),
        (CHECK, vec![("not_before_ms", "2")]),
        (CHECK, vec![("issued_at_ms", "2")]),
    ];
    for (i, (want, over)) in cases.into_iter().enumerate() {
        assert_eq!(
            refused(&pool, &grant(&over)).await.as_deref(),
            want,
            "case {i}: {over:?}"
        );
    }
    exec(&pool, &grant(&[])).await;

    // One self-grant per tenant, ever, and REPLACE cannot swap it out
    // through the primary key or the one-self-grant index.
    let second = grant(&[("replay_id", "x'62626262626262626262626262626262'")]);
    for sql in [
        second.clone(),
        second.replacen("INSERT", "INSERT OR REPLACE", 1),
        grant(&[]).replacen("INSERT", "INSERT OR REPLACE", 1),
    ] {
        assert_eq!(refused(&pool, &sql).await.as_deref(), TRIGGER, "{sql}");
    }
    assert_eq!(
        count(&pool, "SELECT count(*) FROM v2_tenant_root_key_grants").await,
        1
    );
    assert_eq!(
        refused(&pool, "DELETE FROM v2_tenant_root_key_grants")
            .await
            .as_deref(),
        TRIGGER
    );
    for set in [
        "root_key_id = randomblob(32)",
        "exact_signed_container_bytes = x'dd'",
        "subject_device_approval_replay_id = randomblob(16)",
        "created_at = 'u'",
    ] {
        assert_eq!(
            refused(
                &pool,
                &format!("UPDATE v2_tenant_root_key_grants SET {set}")
            )
            .await
            .as_deref(),
            TRIGGER,
            "{set}"
        );
    }
    // Acknowledged once and revoked once.
    for mark in ["acked_at", "revoked_at"] {
        exec(
            &pool,
            &format!("UPDATE v2_tenant_root_key_grants SET {mark} = 'first'"),
        )
        .await;
        for again in ["'second'", "NULL"] {
            assert_eq!(
                refused(
                    &pool,
                    &format!("UPDATE v2_tenant_root_key_grants SET {mark} = {again}")
                )
                .await
                .as_deref(),
                TRIGGER,
                "{mark} = {again}"
            );
        }
    }
}

#[tokio::test]
async fn a_stored_idempotent_response_of_any_kind_never_changes() {
    let pool = upgraded().await;
    let row = |scope: &str, status: &str, record_type: &str, response: &str| {
        format!(
            "INSERT INTO v2_idempotency VALUES ({I}, {T2}, {D2}, '{scope}', \
             x'0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d', 'ROOT_GENERATION_CREATE', randomblob(32), \
             x'bb', randomblob(32), '{status}', {record_type}, {response}, 9, NULL, NULL, \
             NULL, NULL, NULL)"
        )
    };
    let scope = "tenant.root-generation-create.v2";
    let record = "'TenantRootGenerationCreatedV2'";
    let response = "x'cc', randomblob(32)";
    // A root create row is the committed response, every column of it.
    for (i, sql) in [
        row(scope, "in_flight", record, response),
        row(scope, "succeeded", "NULL", response),
        row(scope, "succeeded", "'DeviceApprovalReceiptV2'", response),
        row(scope, "succeeded", record, "NULL, randomblob(32)"),
        row(scope, "succeeded", record, "x'cc', NULL"),
        row("tenant.root-grant-create.v2", "succeeded", record, response),
    ]
    .iter()
    .enumerate()
    {
        assert_eq!(refused(&pool, sql).await.as_deref(), TRIGGER, "case {i}");
    }
    let complete = row(scope, "succeeded", record, response);
    exec(&pool, &complete).await;
    assert_eq!(
        refused(&pool, &complete.replacen("INSERT", "INSERT OR REPLACE", 1))
            .await
            .as_deref(),
        TRIGGER
    );
    for set in [
        "exact_response_bytes = x'dd'",
        "retained_until = 10",
        "status = 'pending'",
    ] {
        assert_eq!(
            refused(&pool, &format!("UPDATE v2_idempotency SET {set}"))
                .await
                .as_deref(),
            TRIGGER,
            "{set}"
        );
    }
}
