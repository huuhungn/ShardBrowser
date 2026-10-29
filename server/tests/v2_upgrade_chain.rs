//! Upgrades of a populated database (plan 12, L2078-L2081): from 0017 on,
//! each migration keeps every row before it, leaves no broken reference and
//! enforces its guard on the upgraded rows. A database built by v0.1.28 from
//! its own migration SQL upgrades through every migration to the fresh schema.
use std::borrow::Cow;

use shardx_team_server::{run_migrations, run_migrations_with};
use sqlx::migrate::{Migration, MigrationType, Migrator};
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;

async fn empty() -> SqlitePool {
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap()
}

/// Applies every embedded migration up to `version` not yet applied.
async fn migrate_to(pool: &SqlitePool, version: i64) {
    let mut migrator = sqlx::migrate!("./migrations");
    migrator.migrations = Cow::Owned(
        migrator
            .iter()
            .filter(|m| m.version <= version)
            .cloned()
            .collect(),
    );
    run_migrations_with(pool, &migrator).await.unwrap();
}

/// Runs `sql` with foreign keys enforced, as the server does.
async fn exec(pool: &SqlitePool, sql: &str) -> Result<(), String> {
    let mut conn = pool.acquire().await.unwrap();
    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&mut *conn)
        .await
        .unwrap();
    sqlx::raw_sql(sql)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

async fn tables(pool: &SqlitePool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT name FROM sqlite_master
          WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name <> '_sqlx_migrations'
          ORDER BY name",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn columns(pool: &SqlitePool, table: &str) -> Vec<String> {
    sqlx::query_scalar("SELECT name FROM pragma_table_info(?) ORDER BY cid")
        .bind(table)
        .fetch_all(pool)
        .await
        .unwrap()
}

/// Every row of `table`, each as its quoted `cols`, sorted.
async fn rows(pool: &SqlitePool, table: &str, cols: &[String]) -> Vec<String> {
    let quoted: Vec<String> = cols.iter().map(|c| format!("quote(\"{c}\")")).collect();
    sqlx::query_scalar(&format!(
        "SELECT {} FROM \"{table}\" ORDER BY 1",
        quoted.join(" || '|' || ")
    ))
    .fetch_all(pool)
    .await
    .unwrap()
}

/// Each table with its columns and rows.
type Contents = Vec<(String, Vec<String>, Vec<String>)>;

async fn contents(pool: &SqlitePool) -> Contents {
    let mut all = Vec::new();
    for table in tables(pool).await {
        let cols = columns(pool, &table).await;
        let data = rows(pool, &table, &cols).await;
        all.push((table, cols, data));
    }
    all
}

/// Every row of `before` is still there, under the table's new name if
/// `renamed` names one, with the columns it had.
async fn assert_kept(pool: &SqlitePool, before: &Contents, renamed: &[(&str, &str)]) {
    for (table, cols, data) in before {
        let now = renamed
            .iter()
            .find(|(from, _)| from == table)
            .map_or(table.as_str(), |(_, to)| to);
        assert_eq!(&rows(pool, now, cols).await, data, "{table}");
    }
}

/// No broken reference and no corrupt page.
async fn assert_sound(pool: &SqlitePool) {
    let broken: Vec<(String,)> = sqlx::query_as("SELECT \"table\" FROM pragma_foreign_key_check")
        .fetch_all(pool)
        .await
        .unwrap();
    assert!(broken.is_empty(), "{broken:?}");
    let integrity: String = sqlx::query_scalar("PRAGMA integrity_check")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(integrity, "ok");
}

const I: &str = "x'11111111111111111111111111111111'";
const T: &str = "x'01010101010101010101010101010101'";
const A: &str = "x'02020202020202020202020202020202'";
const D2: &str = "x'0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d'";
const P: &str = "x'06060606060606060606060606060606'";
const UPLOAD: &str = "x'81818181818181818181818181818181'";
const SIGN2: &str = "x'4646464646464646464646464646464646464646464646464646464646464646'";
const HPKE2: &str = "x'4747474747474747474747474747474747474747474747474747474747474747'";

/// A tenant as 0016 leaves it: an owner, a live and a revoked device, the D1
/// approval and its ledger row, an ACTIVE root generation with its
/// acknowledged self-grant, a capability grant, a fleet with an ACTIVE key
/// generation, and a profile.
const WORLD_0016: &str = "
INSERT INTO users (id, username, pw_hash, role, created_at) VALUES ('u1', 'admin', 'h', 'admin', 't');
INSERT INTO v2_server_state VALUES (1, x'11111111111111111111111111111111', 0, zeroblob(32), 't');
INSERT INTO v2_tenants VALUES (x'01010101010101010101010101010101', 'acme', 'active', 0, 't');
INSERT INTO v2_accounts VALUES (x'02020202020202020202020202020202', x'01010101010101010101010101010101', 'owner', 'h', 'u1', 0, 'active', 't');
INSERT INTO v2_tenant_memberships VALUES (x'01010101010101010101010101010101', x'02020202020202020202020202020202', 'owner', 'active', 't');
INSERT INTO v2_devices VALUES (x'03030303030303030303030303030303', x'01010101010101010101010101010101', x'02020202020202020202020202020202', x'aa', x'4444444444444444444444444444444444444444444444444444444444444444', zeroblob(32), 1, x'4545454545454545454545454545454545454545454545454545454545454545', zeroblob(32), 1, 'active', NULL, 't');
INSERT INTO v2_devices VALUES (x'0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d', x'01010101010101010101010101010101', x'02020202020202020202020202020202', x'aa', x'4646464646464646464646464646464646464646464646464646464646464646', zeroblob(32), 1, x'4747474747474747474747474747474747474747474747474747474747474747', zeroblob(32), 1, 'revoked', NULL, 't');
INSERT INTO v2_device_approvals VALUES (x'01010101010101010101010101010101', x'04040404040404040404040404040404', 'shardx.auth.device-approval.v2', 2, x'02020202020202020202020202020202', x'03030303030303030303030303030303', x'4444444444444444444444444444444444444444444444444444444444444444', x'4545454545454545454545454545454545454545454545454545454545454545', 'tenant', x'01010101010101010101010101010101', 'team.device', 1, 1, 2, x'11111111111111111111111111111111', 0, x'aa', zeroblob(32), 1, 1, zeroblob(64), x'4444444444444444444444444444444444444444444444444444444444444444', zeroblob(32), x'bb', zeroblob(32), NULL, 't');
INSERT INTO v2_idempotency VALUES (x'11111111111111111111111111111111', x'01010101010101010101010101010101', x'03030303030303030303030303030303', 'tenant.device-approve.v2', x'04040404040404040404040404040404', 'DEVICE_APPROVE', zeroblob(32), x'bb', zeroblob(32), 'succeeded', 'DeviceApprovalReceiptV2', x'cc', zeroblob(32), 9, 'shardx.auth.device-approval.v2', 0, x'02020202020202020202020202020202', x'03030303030303030303030303030303');
INSERT INTO v2_root_key_generations (server_instance_id, tenant_id, generation, root_key_id, state, created_at, required_custodian_grant_count, required_custodian_grant_set_hash, recovery_bundle_sha256) VALUES (x'11111111111111111111111111111111', x'01010101010101010101010101010101', 0, x'2121212121212121212121212121212121212121212121212121212121212121', 'PREPARING', 't', 1, zeroblob(32), zeroblob(32));
INSERT INTO v2_tenant_root_key_grants (server_instance_id, tenant_id, replay_id, container_domain, container_version, payload_domain, payload_version, grant_variant, root_key_id, root_generation, grant_capability, subject_account_id, subject_device_id, subject_signing_key_id, subject_device_approval_payload_domain, subject_device_approval_replay_id, recipient_hpke_key_id, hpke_suite_id, hpke_mode_id, hpke_kem_id, hpke_kdf_id, hpke_aead_id, hpke_info_bytes, hpke_encapped_key_bytes, hpke_wrapped_trk_bytes, issued_at_ms, not_before_ms, not_after_ms, restore_epoch, canonical_payload_bytes, payload_sha256, signature_suite_id, signature_version, issuer_signing_key_id, signature_bytes, signed_container_hash, exact_signed_container_bytes, exact_signed_container_bytes_sha256, created_at) VALUES (x'11111111111111111111111111111111', x'01010101010101010101010101010101', x'61616161616161616161616161616161', 'shardx.authorization.signed-container.v2', 2, 'shardx.keys.tenant-root-key-grant.v2', 2, 'FirstRootSelfGrant', x'2121212121212121212121212121212121212121212121212121212121212121', 0, 'root.custody', x'02020202020202020202020202020202', x'03030303030303030303030303030303', x'4444444444444444444444444444444444444444444444444444444444444444', 'shardx.auth.device-approval.v2', x'04040404040404040404040404040404', x'4545454545454545454545454545454545454545454545454545454545454545', 1, 0, 32, 1, 3, x'aa', zeroblob(32), zeroblob(48), 1, 1, 2, 0, x'bb', zeroblob(32), 1, 1, x'4444444444444444444444444444444444444444444444444444444444444444', zeroblob(64), zeroblob(32), x'cc', zeroblob(32), 't');
UPDATE v2_tenant_root_key_grants SET acked_at = 't';
UPDATE v2_root_key_generations SET state = 'ACTIVE', activated_at = 't';
INSERT INTO v2_capability_grants VALUES (x'01010101010101010101010101010101', x'71717171717171717171717171717171', 'shardx.auth.tenant-capability-grant.v2', 2, x'02020202020202020202020202020202', x'03030303030303030303030303030303', 'fleet.manage', 'tenant', x'01010101010101010101010101010101', 1, 1, 2, x'11111111111111111111111111111111', 0, x'aa', zeroblob(32), zeroblob(64), x'4444444444444444444444444444444444444444444444444444444444444444', zeroblob(32), x'bb', zeroblob(32), NULL, 't');
INSERT INTO v2_fleets VALUES (x'05050505050505050505050505050505', x'01010101010101010101010101010101', 'fleet', 'active', 't');
INSERT INTO v2_fleet_key_generations (server_instance_id, tenant_id, fleet_id, generation, fkek_key_id, root_generation, state, created_at, activated_at) VALUES (x'11111111111111111111111111111111', x'01010101010101010101010101010101', x'05050505050505050505050505050505', 0, x'2222222222222222222222222222222222222222222222222222222222222222', 0, 'ACTIVE', 't', 't');
INSERT INTO v2_profiles VALUES (x'06060606060606060606060606060606', x'01010101010101010101010101010101', x'05050505050505050505050505050505', 'profile', 3, 'active', 't', 't');
";

/// An OPEN upload of the profile under the ACTIVE fleet key generation
/// `generation`, as `upload`.
fn upload(upload: &str, snapshot: u8, generation: u8) -> String {
    let id = |b: u8| format!("x'{}'", format!("{b:02x}").repeat(16));
    format!(
        "INSERT INTO v2_uploads (server_instance_id, tenant_id, upload_id, fleet_id, profile_id,
           snapshot_id, manifest_replay_id, lease_id, fencing_token, base_version, restore_epoch,
           operation_scope, idempotency_key, canonical_request_hash, intent_hash, preamble_sha256,
           dek_slot_sha256, fkek_key_id, key_generation, expected_ciphertext_size,
           expected_ciphertext_sha256, committed_offset, staging_path, state, expires_at_ms,
           created_at_ms)
         VALUES ({I}, {T}, {upload}, x'05050505050505050505050505050505', {P}, {}, {}, {}, 1, 3, 0,
           'profile.create-upload.v2', {}, zeroblob(32), zeroblob(32), zeroblob(32), zeroblob(32),
           x'2222222222222222222222222222222222222222222222222222222222222222', {generation}, 10,
           zeroblob(32), 4, 'staging/x', 'OPEN', 9, 1)",
        id(snapshot),
        id(snapshot + 1),
        id(snapshot + 2),
        id(snapshot + 3),
    )
}

/// The populated database just before `version`. Tables a migration
/// creates get their rows right after it.
async fn world_before(version: i64) -> SqlitePool {
    let pool = empty().await;
    migrate_to(&pool, 16).await;
    exec(&pool, WORLD_0016).await.unwrap();
    for v in 17..version {
        migrate_to(&pool, v).await;
        if v == 26 {
            exec(&pool, &upload(UPLOAD, 0x82, 0)).await.unwrap();
        }
    }
    assert_sound(&pool).await;
    pool
}

/// What `version` must refuse on the upgraded rows: the statements that set
/// it up, the statement refused and the refusal it names.
fn guard(version: i64) -> (String, String, &'static str) {
    let none = String::new();
    match version {
        17 => (
            none,
            "UPDATE v2_root_key_generations SET state = 'PREPARING'".into(),
            "a root generation only moves forward",
        ),
        18 => (
            none,
            "UPDATE v2_legacy_capability_grants SET revoked_at = 't'".into(),
            "legacy capability grants are read-only",
        ),
        19 => (
            none,
            format!(
                "INSERT INTO v2_grant_quarantine VALUES ('unknown_kind', {I}, {T}, \
                 x'04040404040404040404040404040404', 'container_mismatch', 't')"
            ),
            "CHECK constraint failed",
        ),
        20 => (
            none,
            "UPDATE v2_fleet_key_generations SET required_device_grant_count = 0".into(),
            "CHECK constraint failed",
        ),
        21 => (
            none,
            "UPDATE v2_fleet_key_generations SET state = 'PREPARING'".into(),
            "a fleet generation only moves forward",
        ),
        22 => (
            none,
            "DELETE FROM v2_fleet_key_generations".into(),
            "a fleet key generation is never deleted",
        ),
        23 => (
            format!(
                "INSERT INTO v2_device_revocations VALUES ({I}, {T}, \
                 x'0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e', 'shardx.authz.device-revocation.v2', 2, \
                 {A}, {D2}, {SIGN2}, {HPKE2}, 'lost', \
                 x'4444444444444444444444444444444444444444444444444444444444444444', 1, 1, 2, \
                 0, x'aa', zeroblob(32), 1, 1, zeroblob(64), zeroblob(32), x'bb', zeroblob(32), 1)"
            ),
            "UPDATE v2_devices SET status = 'active' WHERE status = 'revoked'".into(),
            "a device with a revocation stays revoked",
        ),
        24 => (
            none,
            format!(
                "INSERT INTO v2_restore_epoch_transition_proofs VALUES ({I}, {T}, 0, 1, {P}, \
                 zeroblob(32), zeroblob(32), 0, 1, x'aa', zeroblob(32), x'bb', zeroblob(32), 't')"
            ),
            "FOREIGN KEY constraint failed",
        ),
        25 => (
            none,
            "UPDATE v2_profiles SET last_fencing_token = -1".into(),
            "a profile fence never moves back",
        ),
        // An upload under a key generation the fleet never had.
        26 => (
            none,
            upload("x'91919191919191919191919191919191'", 0x92, 7),
            "FOREIGN KEY constraint failed",
        ),
        27 => (
            format!(
                "INSERT INTO v2_upload_quarantine VALUES ({I}, {T}, {UPLOAD}, 'OPEN', \
                 'staging_invalid', 0, 1)"
            ),
            "DELETE FROM v2_upload_quarantine".into(),
            "an upload quarantine is never removed",
        ),
        _ => unreachable!("no guard for {version}"),
    }
}

/// Migrates the populated database across `version` alone and checks it.
async fn upgrade(version: i64) -> SqlitePool {
    let pool = world_before(version).await;
    let before = contents(&pool).await;
    migrate_to(&pool, version).await;
    // 0018 keeps the spike capability grants under their legacy name.
    let renamed: &[(&str, &str)] = match version {
        18 => &[("v2_capability_grants", "v2_legacy_capability_grants")],
        _ => &[],
    };
    assert_kept(&pool, &before, renamed).await;
    assert_sound(&pool).await;
    let (setup, refused, why) = guard(version);
    if !setup.is_empty() {
        exec(&pool, &setup).await.unwrap();
    }
    let e = exec(&pool, &refused).await.unwrap_err();
    assert!(e.contains(why), "{version}: {e}");
    pool
}

#[tokio::test]
async fn m0017_root_generations_only_move_forward_on_upgraded_rows() {
    upgrade(17).await;
}

#[tokio::test]
async fn m0018_spike_capability_grants_become_read_only_legacy_rows() {
    let pool = upgrade(18).await;
    assert_eq!(
        rows(&pool, "v2_capability_grants", &["replay_id".into()]).await,
        Vec::<String>::new()
    );
}

#[tokio::test]
async fn m0019_the_grant_quarantine_names_only_known_kinds() {
    upgrade(19).await;
}

#[tokio::test]
async fn m0020_the_rebuilt_ledger_keeps_its_rows_and_generations_gain_bounded_terms() {
    let pool = upgrade(20).await;
    // The spike generation has no terms: its new columns stay NULL.
    assert_eq!(
        rows(
            &pool,
            "v2_fleet_key_generations",
            &[
                "required_device_grant_count".into(),
                "rotation_grant_hash".into()
            ]
        )
        .await,
        ["NULL|NULL"]
    );
}

#[tokio::test]
async fn m0021_fleet_generations_only_move_forward_on_upgraded_rows() {
    upgrade(21).await;
}

#[tokio::test]
async fn m0022_upgraded_fleet_generations_are_never_deleted() {
    upgrade(22).await;
}

#[tokio::test]
async fn m0023_an_upgraded_device_with_a_revocation_stays_revoked() {
    upgrade(23).await;
}

#[tokio::test]
async fn m0024_a_restore_proof_needs_its_transition() {
    upgrade(24).await;
}

#[tokio::test]
async fn m0025_upgraded_profiles_start_at_fence_zero_and_never_move_back() {
    let pool = upgrade(25).await;
    assert_eq!(
        rows(
            &pool,
            "v2_profiles",
            &[
                "last_fencing_token".into(),
                "label_ciphertext".into(),
                "current_key_generation".into()
            ]
        )
        .await,
        ["0|NULL|NULL"]
    );
}

#[tokio::test]
async fn m0026_an_upload_names_a_key_generation_of_its_fleet() {
    let pool = upgrade(26).await;
    // An honest upload is accepted next to the upgraded rows.
    exec(&pool, &upload(UPLOAD, 0x82, 0)).await.unwrap();
    assert_sound(&pool).await;
}

#[tokio::test]
async fn m0027_upgraded_uploads_keep_their_terms_and_quarantines_are_kept() {
    let pool = upgrade(27).await;
    assert_eq!(
        rows(
            &pool,
            "v2_uploads",
            &[
                "state".into(),
                "exact_finalize_request_bytes".into(),
                "finalize_actor_device_id".into()
            ]
        )
        .await,
        ["'OPEN'|NULL|NULL"]
    );
}

// ------------------------------------------------- the v0.1.28 database ---

/// The server migrations v0.1.28 shipped, from its tag (`git show
/// v0.1.28:server/migrations/<file>`), run the way that build ran them.
fn v0_1_28() -> Migrator {
    let shipped = [
        (1, "init", include_str!("fixtures/v0.1.28/0001_init.sql")),
        (
            2,
            "lock token and token version",
            include_str!("fixtures/v0.1.28/0002_lock_token_and_token_version.sql"),
        ),
        (
            3,
            "clear empty lock tokens",
            include_str!("fixtures/v0.1.28/0003_clear_empty_lock_tokens.sql"),
        ),
    ];
    let migrations = shipped
        .into_iter()
        .map(|(version, description, sql)| {
            // The tag holds LF bytes; a CRLF checkout of the fixture is not
            // what v0.1.28 checksummed.
            Migration::new(
                version,
                Cow::Borrowed(description),
                MigrationType::Simple,
                Cow::Owned(sql.replace("\r\n", "\n")),
                false,
            )
        })
        .collect::<Vec<_>>();
    Migrator {
        migrations: Cow::Owned(migrations),
        ..Migrator::DEFAULT
    }
}

/// What a v0.1.28 team server holds: users, a folder, a proxy, an
/// environment with its lock, snapshot and ACL entry, and its audit trail.
const V0_1_28_ROWS: &str = "
INSERT INTO users (id, username, pw_hash, role, created_at, token_version) VALUES ('u1', 'admin', 'h1', 'admin', 't', 2);
INSERT INTO users (id, username, pw_hash, role, created_at) VALUES ('u2', 'member', 'h2', 'member', 't');
INSERT INTO folders VALUES ('f1', 'team', NULL, 't');
INSERT INTO proxies VALUES ('p1', 'office', 'socks5', '10.0.0.1', 1080, 'user', 'pass', 't');
INSERT INTO environments VALUES ('e1', 'shop', 'f1', '{\"os\":\"Windows\"}', 'p1', 'Windows', 2, 'notes', 'u1', 'u2', 't', 't');
INSERT INTO acl VALUES ('u2', 'e1', 'env', 'edit');
INSERT INTO locks VALUES ('e1', 'u2', 'client', 't', 't', 'token');
INSERT INTO snapshots VALUES ('e1', 1, 'blobs/e1/1', 'aa', 10, 'u1', 't');
INSERT INTO snapshots VALUES ('e1', 2, 'blobs/e1/2', 'bb', 20, 'u2', 't');
INSERT INTO audit_log (actor, action, env_id, detail, at) VALUES ('u1', 'env.create', 'e1', NULL, 't');
";

async fn schema(pool: &SqlitePool) -> Vec<(String, String, Option<String>)> {
    sqlx::query_as(
        "SELECT type, name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'
          ORDER BY type, name",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn a_v0_1_28_database_upgrades_through_every_migration_to_the_fresh_schema() {
    let pool = empty().await;
    let shipped = v0_1_28();
    shipped.run(&pool).await.unwrap();
    exec(&pool, V0_1_28_ROWS).await.unwrap();
    let before = contents(&pool).await;
    let applied: Vec<(i64, Vec<u8>)> =
        sqlx::query_as("SELECT version, checksum FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&pool)
            .await
            .unwrap();

    run_migrations(&pool).await.unwrap();

    // Every v1 row is kept, the database is sound, and the v0.1.28 history
    // is not rewritten.
    assert_kept(&pool, &before, &[]).await;
    assert_sound(&pool).await;
    let history: Vec<(i64, Vec<u8>, bool)> =
        sqlx::query_as("SELECT version, checksum, success FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&pool)
            .await
            .unwrap();
    let embedded = sqlx::migrate!("./migrations");
    assert_eq!(history.len(), embedded.iter().count());
    assert!(history.iter().all(|(_, _, ok)| *ok));
    for (version, checksum) in &applied {
        assert!(
            history.contains(&(*version, checksum.clone(), true)),
            "{version}"
        );
    }
    // The upgraded schema is exactly the one a fresh database gets.
    let fresh = empty().await;
    run_migrations(&fresh).await.unwrap();
    assert_eq!(schema(&pool).await, schema(&fresh).await);
    // v1 constraints still hold.
    let e = exec(
        &pool,
        "INSERT INTO users (id, username, pw_hash, created_at) VALUES ('u3', 'admin', 'h', 't')",
    )
    .await
    .unwrap_err();
    assert!(
        e.contains("UNIQUE constraint failed: users.username"),
        "{e}"
    );
    let e = exec(
        &pool,
        "INSERT INTO acl VALUES ('nobody', 'e1', 'env', 'use')",
    )
    .await
    .unwrap_err();
    assert!(e.contains("FOREIGN KEY constraint failed"), "{e}");
}
