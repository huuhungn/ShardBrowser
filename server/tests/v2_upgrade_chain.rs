//! Upgrades of a populated database (plan 12, L2078-L2081): from 0017 on,
//! each migration keeps every row before it, leaves no broken reference and
//! enforces its guard on the upgraded rows. A database built by v0.1.28 from
//! its own migration SQL upgrades through every migration to the fresh schema.
use std::borrow::Cow;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use shardx_team_server::{run_migrations, run_migrations_with};
use sqlx::migrate::{Migration, MigrationType, Migrator};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{SqliteConnection, SqlitePool};

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

/// A ledger row of `kind` in `status`; a succeeded one with its response.
fn ledger(kind: &str, status: &str) -> String {
    let response = if status == "succeeded" {
        "'CreateUploadResponseV2', x'01', zeroblob(32)"
    } else {
        "NULL, NULL, NULL"
    };
    format!(
        "INSERT INTO v2_idempotency (server_instance_id, tenant_id, actor_device_id,
           operation_scope, idempotency_key, operation_kind, canonical_request_hash,
           exact_request_bytes, exact_request_bytes_sha256, status, response_record_type,
           exact_response_bytes, exact_response_bytes_sha256, retained_until)
         VALUES ({I}, {T}, {D2}, '{scope}', x'{key}', '{kind}', zeroblob(32), x'aa',
           zeroblob(32), '{status}', {response}, 0)",
        scope = if kind == "CREATE_UPLOAD" {
            "profile.create-upload.v2"
        } else {
            "profile.local-unbind.v2"
        },
        key = format!("{:02x}", kind.len()).repeat(16),
    )
}

/// The root self-grant's quarantine, recorded as `kind`.
fn quarantined(kind: &str) -> String {
    format!(
        "INSERT INTO v2_grant_quarantine VALUES ('{kind}', {I}, {T},          x'61616161616161616161616161616161', 'container_mismatch', 't')"
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
        if v == 19 {
            exec(&pool, &quarantined("root_grant")).await.unwrap();
        }
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
        // The rebuilt quarantine takes fleet grants and is still kept.
        28 => (
            quarantined("fleet_rotation_grant"),
            "DELETE FROM v2_grant_quarantine".into(),
            "a grant quarantine is never removed",
        ),
        // The rebuilt quarantine takes device approvals and is still kept.
        29 => (
            quarantined("device_approval"),
            "DELETE FROM v2_grant_quarantine".into(),
            "a grant quarantine is never removed",
        ),
        // An integer column of an upgraded table refuses an in-range REAL.
        30 => (
            none,
            "UPDATE v2_profiles SET last_fencing_token = 1.5".into(),
            "an integer column holds only integers",
        ),
        // Only a commit, upload or publish row is ever superseded.
        31 => (
            ledger("LOCAL_UNBIND", "in_flight"),
            "UPDATE v2_idempotency SET superseded_by_restore_epoch = 1
              WHERE operation_kind = 'LOCAL_UNBIND'"
                .into(),
            "a ledger row is superseded once, by the next restore epoch",
        ),
        // The rebuilt quarantine takes device revocations and is still kept.
        32 => (
            quarantined("device_revocation"),
            "DELETE FROM v2_grant_quarantine".into(),
            "a grant quarantine is never removed",
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

#[tokio::test]
async fn m0028_the_rebuilt_grant_quarantine_keeps_its_rows_and_takes_fleet_grants() {
    let pool = upgrade(28).await;
    for kind in ["capability_grant", "unknown_kind"] {
        let e = exec(&pool, &quarantined(kind)).await;
        assert_eq!(kind == "unknown_kind", e.is_err(), "{kind}: {e:?}");
    }
    let e = exec(&pool, &quarantined("root_grant")).await.unwrap_err();
    assert!(e.contains("a grant is quarantined once"), "{e}");
}

#[tokio::test]
async fn m0029_the_rebuilt_grant_quarantine_keeps_its_rows_and_takes_device_approvals() {
    let pool = upgrade(29).await;
    for kind in ["fleet_rotation_grant", "unknown_kind"] {
        let e = exec(&pool, &quarantined(kind)).await;
        assert_eq!(kind == "unknown_kind", e.is_err(), "{kind}: {e:?}");
    }
    let e = exec(&pool, &quarantined("root_grant")).await.unwrap_err();
    assert!(e.contains("a grant is quarantined once"), "{e}");
}

#[tokio::test]
async fn m0030_upgraded_integer_columns_refuse_values_that_are_no_integers() {
    let pool = upgrade(30).await;
    for statement in [
        "UPDATE v2_accounts SET token_version = '0.5'",
        "UPDATE v2_uploads SET expires_at_ms = 9.5",
    ] {
        let e = exec(&pool, statement).await.unwrap_err();
        assert!(e.contains("an integer column holds only integers"), "{e}");
    }
    // An integer, also as text that INTEGER affinity makes one, is stored.
    exec(&pool, "UPDATE v2_profiles SET last_fencing_token = '4'")
        .await
        .unwrap();
}

#[tokio::test]
async fn m0031_upgraded_ledger_rows_are_superseded_once_and_only_by_the_next_epoch() {
    let pool = upgrade(31).await;
    assert_eq!(
        rows(
            &pool,
            "v2_idempotency",
            &["superseded_by_restore_epoch".into()]
        )
        .await,
        ["NULL", "NULL"],
        "the upgraded rows are not superseded"
    );
    exec(&pool, &ledger("CREATE_UPLOAD", "succeeded"))
        .await
        .unwrap();
    let mark = |epoch: u8| {
        format!(
            "UPDATE v2_idempotency SET superseded_by_restore_epoch = {epoch}
              WHERE operation_kind = 'CREATE_UPLOAD'"
        )
    };
    let once = "a ledger row is superseded once, by the next restore epoch";
    // The server is at epoch 0: only 1 is the next epoch.
    assert!(exec(&pool, &mark(2)).await.unwrap_err().contains(once));
    exec(&pool, &mark(1)).await.unwrap();
    assert!(exec(&pool, &mark(1)).await.unwrap_err().contains(once));
    let e = exec(
        &pool,
        "UPDATE v2_idempotency SET retained_until = 1 WHERE operation_kind = 'CREATE_UPLOAD'",
    )
    .await
    .unwrap_err();
    assert!(
        e.contains("a stored idempotent response never changes"),
        "{e}"
    );
    let e = exec(
        &pool,
        "UPDATE v2_idempotency SET superseded_by_restore_epoch = 1, retained_until = 1
          WHERE operation_kind = 'CREATE_UPLOAD'",
    )
    .await
    .unwrap_err();
    assert!(e.contains("never changes") || e.contains(once), "{e}");
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

// ------------------------------------------ file-backed shape probes ---
//
// Plan 12.1 (L2080-L2222): the `_assert` SQL runs as written against real
// files, on a fresh database and on an upgraded one, after a close and a
// reopen, and the four transaction fixtures run on top.

/// The plan's `_assert` block, from its `CREATE TEMP TABLE` to the last
/// PRAGMA (plan file lines 2087-2198), with CRLF turned into LF and nothing
/// else changed.
const PLAN_ASSERT: &str = include_str!("fixtures/plan_assert.sql");

/// SQLITE_CONSTRAINT_FOREIGNKEY and SQLITE_CONSTRAINT_UNIQUE.
const FK: &str = "787";
const UNIQUE: &str = "2067";

/// A directory of its own under the temp dir, removed on drop.
struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("shardx-shape-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Dir(dir)
    }

    fn db(&self) -> PathBuf {
        self.0.join("team.db")
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The file opened the way the server opens it: foreign keys on, a rollback
/// journal, full syncs. One connection, so a TEMP table outlives its statement.
async fn open_file(path: &Path) -> SqlitePool {
    let opts = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Delete)
        .synchronous(SqliteSynchronous::Full);
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .unwrap()
}

/// Closes the database and opens the file again.
async fn reopen(pool: SqlitePool, path: &Path) -> SqlitePool {
    pool.close().await;
    open_file(path).await
}

fn sha256(path: &Path) -> Vec<u8> {
    Sha256::digest(std::fs::read(path).unwrap()).to_vec()
}

/// Runs the plan's script statement by statement, so a failed `_assert`
/// insert names the statement, then checks what its two PRAGMAs report.
async fn assert_plan_shapes(pool: &SqlitePool, what: &str) {
    let script = PLAN_ASSERT.replace("\r\n", "\n");
    let mut conn = pool.acquire().await.unwrap();
    sqlx::query("DROP TABLE IF EXISTS temp._assert")
        .execute(&mut *conn)
        .await
        .unwrap();
    let mut pragmas = Vec::new();
    for stmt in script.split(";\n").map(str::trim).filter(|s| !s.is_empty()) {
        if stmt.starts_with("PRAGMA ") {
            let rows: Vec<String> = sqlx::query_scalar(stmt)
                .fetch_all(&mut *conn)
                .await
                .unwrap();
            pragmas.push((stmt, rows));
        } else if let Err(e) = sqlx::query(stmt).execute(&mut *conn).await {
            panic!("{what}: the plan's assertion failed: {e}\n{stmt}");
        }
    }
    let checked: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM temp._assert")
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    assert_eq!(
        checked as usize,
        script.matches("INSERT INTO _assert").count()
    );
    assert_eq!(
        pragmas,
        [
            ("PRAGMA integrity_check", vec!["ok".to_string()]),
            ("PRAGMA foreign_key_check", Vec::new())
        ],
        "{what}"
    );
}

/// The candidate keys that the plan's foreign keys and its duplicate
/// refusals rest on; the plan's script checks only the fleet generation key.
async fn assert_unique_keys(pool: &SqlitePool, what: &str) {
    let keys: [(&str, &str); 5] = [
        (
            "v2_uploads",
            "server_instance_id,tenant_id,profile_id,snapshot_id",
        ),
        (
            "v2_uploads",
            "server_instance_id,tenant_id,profile_id,manifest_replay_id",
        ),
        (
            "v2_uploads",
            "server_instance_id,tenant_id,upload_id,fleet_id,snapshot_id,manifest_replay_id",
        ),
        (
            "v2_snapshots",
            "server_instance_id,tenant_id,profile_id,snapshot_id",
        ),
        (
            "v2_snapshots",
            "server_instance_id,tenant_id,profile_id,manifest_replay_id",
        ),
    ];
    for (table, columns) in keys {
        let found: bool = sqlx::query_scalar(
            "SELECT EXISTS (
               SELECT 1 FROM pragma_index_list(?1) AS il
                WHERE il.\"unique\" = 1
                  AND (SELECT group_concat(name) FROM
                         (SELECT name FROM pragma_index_info(il.name) ORDER BY seqno)) = ?2)",
        )
        .bind(table)
        .bind(columns)
        .fetch_one(pool)
        .await
        .unwrap();
        assert!(found, "{what}: {table} has no UNIQUE ({columns})");
    }
}

fn id(b: u8) -> String {
    format!("x'{}'", format!("{b:02x}").repeat(16))
}

fn key(b: u8) -> String {
    format!("x'{}'", format!("{b:02x}").repeat(32))
}

const DEVICE: &str = "x'03030303030303030303030303030303'";
const FLEET: &str = "x'05050505050505050505050505050505'";

/// Where a child row lives: a tenant, its fleet and profile, and the FKEK
/// that fleet's generation 0 holds.
struct Scope {
    tenant: String,
    fleet: String,
    profile: String,
    fkek: String,
}

fn scope_one() -> Scope {
    Scope {
        tenant: T.into(),
        fleet: FLEET.into(),
        profile: P.into(),
        fkek: key(0x22),
    }
}

fn scope_two() -> Scope {
    Scope {
        tenant: id(0x0a),
        fleet: id(0x0c),
        profile: id(0x0e),
        fkek: key(0x24),
    }
}

/// A row as its column and SQL value pairs.
type Row = Vec<(&'static str, String)>;

fn row<const N: usize>(pairs: [(&'static str, &str); N]) -> Row {
    pairs.iter().map(|(c, v)| (*c, v.to_string())).collect()
}

/// An INSERT of `row` with the values named in `over` replaced.
fn insert(table: &str, row: &Row, over: &[(&str, &str)]) -> String {
    for (column, _) in over {
        assert!(row.iter().any(|(c, _)| c == column), "{table}.{column}");
    }
    let value = |column: &str, v: &String| {
        over.iter()
            .find(|(c, _)| *c == column)
            .map_or(v.clone(), |(_, o)| o.to_string())
    };
    let columns: Vec<&str> = row.iter().map(|(c, _)| *c).collect();
    let values: Vec<String> = row.iter().map(|(c, v)| value(c, v)).collect();
    format!(
        "INSERT INTO {table} ({}) VALUES ({})",
        columns.join(", "),
        values.join(", ")
    )
}

/// An OPEN upload under generation 0 of the scope's fleet. Its snapshot,
/// replay, lease and idempotency ids are `snap` to `snap + 3`.
fn upload_row(s: &Scope, upload: u8, snap: u8) -> Row {
    let (up, sn, rp, ls, ik) = (
        id(upload),
        id(snap),
        id(snap + 1),
        id(snap + 2),
        id(snap + 3),
    );
    row([
        ("server_instance_id", I),
        ("tenant_id", &s.tenant),
        ("upload_id", &up),
        ("fleet_id", &s.fleet),
        ("profile_id", &s.profile),
        ("snapshot_id", &sn),
        ("manifest_replay_id", &rp),
        ("lease_id", &ls),
        ("fencing_token", "1"),
        ("base_version", "3"),
        ("restore_epoch", "0"),
        ("operation_scope", "'profile.create-upload.v2'"),
        ("idempotency_key", &ik),
        ("canonical_request_hash", "zeroblob(32)"),
        ("intent_hash", "zeroblob(32)"),
        ("preamble_sha256", "zeroblob(32)"),
        ("dek_slot_sha256", "zeroblob(32)"),
        ("fkek_key_id", &s.fkek),
        ("key_generation", "0"),
        ("expected_ciphertext_size", "10"),
        ("expected_ciphertext_sha256", "zeroblob(32)"),
        ("committed_offset", "4"),
        ("staging_path", "'staging/x'"),
        ("state", "'OPEN'"),
        ("expires_at_ms", "9"),
        ("created_at_ms", "1"),
    ])
}

/// The snapshot `version` of the upload `upload_row(s, upload, snap)`. The
/// committed pair holds version 1.
fn snapshot_row(s: &Scope, upload: u8, snap: u8, version: u8) -> Row {
    let (up, sn, rp) = (id(upload), id(snap), id(snap + 1));
    let previous = if version == 1 { "NULL" } else { "zeroblob(32)" };
    let version = version.to_string();
    row([
        ("server_instance_id", I),
        ("tenant_id", &s.tenant),
        ("fleet_id", &s.fleet),
        ("profile_id", &s.profile),
        ("version", &version),
        ("snapshot_id", &sn),
        ("manifest_replay_id", &rp),
        ("upload_id", &up),
        ("fkek_key_id", &s.fkek),
        ("key_generation", "0"),
        ("envelope_version", "2"),
        ("intent_hash", "zeroblob(32)"),
        ("preamble_sha256", "zeroblob(32)"),
        ("dek_slot_sha256", "zeroblob(32)"),
        ("immutable_blob_path", "'blobs/x'"),
        ("ciphertext_sha256", "zeroblob(32)"),
        ("ciphertext_size", "10"),
        ("signed_manifest_container_bytes", "x'aa'"),
        ("signed_manifest_container_hash", "zeroblob(32)"),
        ("signed_manifest_container_bytes_sha256", "zeroblob(32)"),
        ("previous_head_hash", previous),
        ("head_hash", "zeroblob(32)"),
        ("signing_key_id", "zeroblob(32)"),
        ("signature_suite_id", "1"),
        ("signature_version", "1"),
        ("signature_bytes", "zeroblob(64)"),
        ("restore_epoch", "0"),
        ("created_by_device", "zeroblob(16)"),
        ("created_at_ms", "1"),
    ])
}

/// The columns every fleet grant table shares.
fn grant_common(replay: &str, fkek: &str, generation: &str) -> Row {
    row([
        ("server_instance_id", I),
        ("tenant_id", T),
        ("replay_id", replay),
        ("fleet_id", FLEET),
        ("fkek_key_id", fkek),
        ("generation", generation),
        ("issued_at_ms", "1"),
        ("not_before_ms", "1"),
        ("not_after_ms", "3"),
        ("restore_epoch", "0"),
        ("canonical_payload_bytes", "x'aa'"),
        ("payload_sha256", "zeroblob(32)"),
        ("signature_suite_id", "1"),
        ("signature_version", "1"),
        ("signature_bytes", "zeroblob(64)"),
        ("issuer_signing_key_id", "zeroblob(32)"),
        ("signed_container_hash", "zeroblob(32)"),
        ("exact_signed_container_bytes", "x'aa'"),
        ("exact_signed_container_bytes_sha256", "zeroblob(32)"),
        ("created_at", "'t'"),
    ])
}

/// A device grant for generation 0.
fn device_grant_row(replay: u8) -> Row {
    let mut r = grant_common(&id(replay), &key(0x22), "0");
    r.extend(row([
        (
            "payload_domain",
            "'shardx.keys.fleet-key-grant.device-hpke.v2'",
        ),
        ("payload_version", "2"),
        ("grant_variant", "'DeviceHpkeGrant'"),
        ("grant_capability", "'fleet.key.receive'"),
        ("subject_account_id", A),
        ("subject_device_id", DEVICE),
        ("subject_signing_key_id", &key(0x44)),
        ("recipient_hpke_key_id", &key(0x45)),
        ("hpke_suite_id", "1"),
        ("hpke_info_bytes", "x'aa'"),
        ("hpke_encapped_key_bytes", "zeroblob(32)"),
        ("hpke_wrapped_fleet_key_bytes", "zeroblob(48)"),
    ]));
    r
}

/// A recovery grant for generation 0, wrapped to root generation 0.
fn recovery_grant_row(replay: u8) -> Row {
    let mut r = grant_common(&id(replay), &key(0x22), "0");
    r.extend(row([
        (
            "payload_domain",
            "'shardx.keys.fleet-key-grant.recovery.v2'",
        ),
        ("payload_version", "2"),
        ("grant_variant", "'RecoveryGrant'"),
        ("grant_capability", "'fleet.key.recover'"),
        ("recipient_root_key_id", &key(0x21)),
        ("recipient_root_generation", "0"),
        ("root_wrap_suite_id", "1"),
        ("root_wrap_nonce_bytes", "zeroblob(12)"),
        ("root_wrap_context_bytes", "x'aa'"),
        ("wrapped_fleet_key_bytes", "zeroblob(48)"),
    ]));
    r
}

/// A rotation grant to the PREPARING generation `generation` (1 or 2), whose
/// FKEK is `key(0x32 + generation)`.
fn rotation_grant_row(replay: u8, generation: u8) -> Row {
    let previous = if generation == 1 {
        key(0x22)
    } else {
        key(0x31 + generation)
    };
    let (fkek, generation, before) = (
        key(0x32 + generation),
        generation.to_string(),
        (generation - 1).to_string(),
    );
    let mut r = grant_common(&id(replay), &fkek, &generation);
    r.extend(row([
        (
            "payload_domain",
            "'shardx.keys.fleet-key-grant.rotation.v2'",
        ),
        ("payload_version", "2"),
        ("grant_variant", "'RotationGrant'"),
        ("grant_capability", "'key.rotate'"),
        ("previous_fkek_key_id", &previous),
        ("previous_generation", &before),
        ("required_device_grant_count", "1"),
        ("required_device_grant_set_hash", "zeroblob(32)"),
        ("recovery_grant_signed_container_hash", "zeroblob(32)"),
        ("activation_not_before_ms", "2"),
    ]));
    r
}

/// The rows the fixtures stand on, in today's schema: a tenant with an owner,
/// a device, root generation 0, a fleet with its ACTIVE generation 0, and a
/// profile. They carry the ids WORLD_0016 uses.
fn base_final() -> String {
    let (root, fkek) = (key(0x21), key(0x22));
    let (sign, hpke) = (key(0x44), key(0x45));
    format!(
        "
INSERT INTO v2_server_state VALUES (1, {I}, 0, zeroblob(32), 't');
INSERT INTO v2_tenants VALUES ({T}, 'acme', 'active', 0, 't');
INSERT INTO v2_accounts VALUES ({A}, {T}, 'owner', 'h', NULL, 0, 'active', 't');
INSERT INTO v2_devices VALUES ({DEVICE}, {T}, {A}, x'aa', {sign}, zeroblob(32), 1, {hpke}, zeroblob(32), 1, 'active', NULL, 't');
INSERT INTO v2_root_key_generations (server_instance_id, tenant_id, generation, root_key_id, state, created_at, required_custodian_grant_count, required_custodian_grant_set_hash, recovery_bundle_sha256) VALUES ({I}, {T}, 0, {root}, 'PREPARING', 't', 1, zeroblob(32), zeroblob(32));
INSERT INTO v2_fleets VALUES ({FLEET}, {T}, 'fleet', 'active', 't');
INSERT INTO v2_fleet_key_generations (server_instance_id, tenant_id, fleet_id, generation, fkek_key_id, root_generation, state, created_at, activated_at) VALUES ({I}, {T}, {FLEET}, 0, {fkek}, 0, 'ACTIVE', 't', 't');
INSERT INTO v2_profiles (id, tenant_id, fleet_id, name, current_version, status, created_at, updated_at) VALUES ({P}, {T}, {FLEET}, 'profile', 3, 'active', 't', 't');
"
    )
}

/// What the fixtures add to every variant: the PREPARING generations 1 and 2
/// the rotation grants need, and a second tenant with a fleet of its own.
fn fixture_extras() -> String {
    let (k0, k1, k2) = (key(0x22), key(0x33), key(0x34));
    let s = scope_two();
    let (t2, a2, f2, p2) = (&s.tenant, id(0x0b), &s.fleet, &s.profile);
    let (root2, fkek2) = (key(0x23), &s.fkek);
    format!(
        "
INSERT INTO v2_fleet_key_generations (server_instance_id, tenant_id, fleet_id, generation, fkek_key_id, root_generation, state, created_at, required_device_grant_count, required_grant_set_hash, recovery_grant_hash, previous_fkek_key_id, rotation_grant_hash) VALUES ({I}, {T}, {FLEET}, 1, {k1}, 0, 'PREPARING', 't', 1, zeroblob(32), zeroblob(32), {k0}, zeroblob(32));
INSERT INTO v2_fleet_key_generations (server_instance_id, tenant_id, fleet_id, generation, fkek_key_id, root_generation, state, created_at, required_device_grant_count, required_grant_set_hash, recovery_grant_hash, previous_fkek_key_id, rotation_grant_hash) VALUES ({I}, {T}, {FLEET}, 2, {k2}, 0, 'PREPARING', 't', 1, zeroblob(32), zeroblob(32), {k1}, zeroblob(32));
INSERT INTO v2_tenants VALUES ({t2}, 'beta', 'active', 0, 't');
INSERT INTO v2_accounts VALUES ({a2}, {t2}, 'owner2', 'h', NULL, 0, 'active', 't');
INSERT INTO v2_root_key_generations (server_instance_id, tenant_id, generation, root_key_id, state, created_at, required_custodian_grant_count, required_custodian_grant_set_hash, recovery_bundle_sha256) VALUES ({I}, {t2}, 0, {root2}, 'PREPARING', 't', 1, zeroblob(32), zeroblob(32));
INSERT INTO v2_fleets VALUES ({f2}, {t2}, 'fleet2', 'active', 't');
INSERT INTO v2_fleet_key_generations (server_instance_id, tenant_id, fleet_id, generation, fkek_key_id, root_generation, state, created_at, activated_at) VALUES ({I}, {t2}, {f2}, 0, {fkek2}, 0, 'ACTIVE', 't', 't');
INSERT INTO v2_profiles (id, tenant_id, fleet_id, name, current_version, status, created_at, updated_at) VALUES ({p2}, {t2}, {f2}, 'profile2', 3, 'active', 't', 't');
"
    )
}

/// Rows that stay in the database: an upload with its snapshot in each
/// tenant under the same opaque ids (fixture 2, "allowed"), and one grant of
/// each kind.
fn committed_rows() -> String {
    let mut sql = String::new();
    for s in [scope_one(), scope_two()] {
        sql += &insert("v2_uploads", &upload_row(&s, 0x81, 0x84), &[]);
        sql += ";\n";
        sql += &insert("v2_snapshots", &snapshot_row(&s, 0x81, 0x84, 1), &[]);
        sql += ";\n";
    }
    for r in [
        insert("v2_fleet_device_hpke_grants", &device_grant_row(0xa1), &[]),
        insert("v2_fleet_recovery_grants", &recovery_grant_row(0xa2), &[]),
        insert(
            "v2_fleet_rotation_grants",
            &rotation_grant_row(0xa3, 2),
            &[],
        ),
    ] {
        sql += &r;
        sql += ";\n";
    }
    sql
}

/// The extended result code `sql` fails with, or None if it succeeds.
async fn code(conn: &mut SqliteConnection, sql: &str) -> Option<String> {
    match sqlx::query(sql).execute(conn).await {
        Ok(_) => None,
        Err(sqlx::Error::Database(e)) => Some(e.code().unwrap().into_owned()),
        Err(e) => panic!("{e}: {sql}"),
    }
}

/// `setup`, which must succeed, and then `stmt`, in a transaction that is
/// rolled back; the code `stmt` fails with, or None.
async fn rolled_back(conn: &mut SqliteConnection, setup: &[String], stmt: &str) -> Option<String> {
    sqlx::query("BEGIN").execute(&mut *conn).await.unwrap();
    for s in setup {
        assert_eq!(code(conn, s).await, None, "{s}");
    }
    let result = code(conn, stmt).await;
    sqlx::query("ROLLBACK").execute(&mut *conn).await.unwrap();
    result
}

/// A value that names no parent, for the tuple component `column`.
fn wrong(column: &str) -> String {
    match column {
        "server_instance_id" => id(0x99),
        "tenant_id" => scope_two().tenant,
        "fleet_id" => scope_two().fleet,
        "generation" | "key_generation" => "7".into(),
        "fkek_key_id" => key(0x55),
        "upload_id" => id(0x9a),
        "snapshot_id" => id(0x9b),
        "manifest_replay_id" => id(0x9c),
        _ => panic!("{column}"),
    }
}

/// Fixtures 1 to 3 of the plan (L2201-L2209), as results of SQLite's own
/// codes. Everything they write is rolled back.
async fn run_fixtures(pool: &SqlitePool, what: &str) {
    let mut conn = pool.acquire().await.unwrap();
    let conn = &mut *conn;
    let one = scope_one();

    // 1. An upload and a snapshot that agree on the whole key pass; one
    // component changed in the snapshot is a foreign key violation.
    let upload = insert("v2_uploads", &upload_row(&one, 0x91, 0x94), &[]);
    let snapshot = snapshot_row(&one, 0x91, 0x94, 2);
    let r = rolled_back(
        conn,
        std::slice::from_ref(&upload),
        &insert("v2_snapshots", &snapshot, &[]),
    )
    .await;
    assert_eq!(r, None, "{what}: fixture 1");
    for column in [
        "server_instance_id",
        "tenant_id",
        "upload_id",
        "fleet_id",
        "snapshot_id",
        "manifest_replay_id",
        "key_generation",
        "fkek_key_id",
    ] {
        let sql = insert("v2_snapshots", &snapshot, &[(column, &wrong(column))]);
        let r = rolled_back(conn, std::slice::from_ref(&upload), &sql).await;
        assert_eq!(
            r.as_deref(),
            Some(FK),
            "{what}: fixture 1, snapshot {column}"
        );
    }

    // 2. The ids committed by committed_rows() are taken under their profile,
    // by an upload and by a snapshot.
    let sql = insert("v2_uploads", &upload_row(&one, 0x92, 0x84), &[]);
    let r = rolled_back(conn, &[], &sql).await;
    assert_eq!(r.as_deref(), Some(UNIQUE), "{what}: fixture 2, snapshot id");
    let sql = insert(
        "v2_uploads",
        &upload_row(&one, 0x92, 0x95),
        &[("manifest_replay_id", &id(0x85))],
    );
    let r = rolled_back(conn, &[], &sql).await;
    assert_eq!(r.as_deref(), Some(UNIQUE), "{what}: fixture 2, replay id");
    let again = insert("v2_snapshots", &snapshot_row(&one, 0x81, 0x84, 2), &[]);
    let r = rolled_back(conn, &[], &again).await;
    assert_eq!(
        r.as_deref(),
        Some(UNIQUE),
        "{what}: fixture 2, second snapshot"
    );

    // 3. Every child of a fleet generation passes on its exact key, and
    // fails on any one component changed.
    let components = [
        "server_instance_id",
        "tenant_id",
        "fleet_id",
        "generation",
        "fkek_key_id",
    ];
    let grants = [
        ("v2_fleet_device_hpke_grants", device_grant_row(0xb1)),
        ("v2_fleet_recovery_grants", recovery_grant_row(0xb2)),
        ("v2_fleet_rotation_grants", rotation_grant_row(0xb3, 1)),
    ];
    for (table, grant) in &grants {
        let r = rolled_back(conn, &[], &insert(table, grant, &[])).await;
        assert_eq!(r, None, "{what}: fixture 3, {table}");
        for column in components {
            let mut over = vec![(column, wrong(column))];
            if *table == "v2_fleet_rotation_grants" && column == "generation" {
                // Keeps generation = previous_generation + 1, so only the
                // foreign key can refuse the row.
                over.push(("previous_generation", "6".into()));
            }
            let over: Vec<(&str, &str)> = over.iter().map(|(c, v)| (*c, v.as_str())).collect();
            let r = rolled_back(conn, &[], &insert(table, grant, &over)).await;
            assert_eq!(
                r.as_deref(),
                Some(FK),
                "{what}: fixture 3, {table}.{column}"
            );
        }
    }
    let upload = upload_row(&one, 0x96, 0x99);
    let r = rolled_back(conn, &[], &insert("v2_uploads", &upload, &[])).await;
    assert_eq!(r, None, "{what}: fixture 3, v2_uploads");
    for column in [
        "server_instance_id",
        "tenant_id",
        "fleet_id",
        "key_generation",
        "fkek_key_id",
    ] {
        let sql = insert("v2_uploads", &upload, &[(column, &wrong(column))]);
        let r = rolled_back(conn, &[], &sql).await;
        assert_eq!(
            r.as_deref(),
            Some(FK),
            "{what}: fixture 3, v2_uploads.{column}"
        );
    }
    // The snapshot table's own five-column key; its upload key is fixture 1.
    let upload = insert("v2_uploads", &upload_row(&one, 0x97, 0x9d), &[]);
    let snapshot = snapshot_row(&one, 0x97, 0x9d, 2);
    for column in [
        "server_instance_id",
        "tenant_id",
        "fleet_id",
        "key_generation",
        "fkek_key_id",
    ] {
        let sql = insert("v2_snapshots", &snapshot, &[(column, &wrong(column))]);
        let r = rolled_back(conn, std::slice::from_ref(&upload), &sql).await;
        assert_eq!(
            r.as_deref(),
            Some(FK),
            "{what}: fixture 3, v2_snapshots.{column}"
        );
    }
}

/// Adds the fixtures' rows to a migrated database that holds the base rows,
/// runs fixtures 1 to 3, then closes and reopens it (fixture 4) and checks
/// the plan's script, the candidate keys and the fixtures again.
async fn fixtures_on(pool: SqlitePool, path: &Path, what: &str) {
    exec(&pool, &fixture_extras()).await.unwrap();
    exec(&pool, &committed_rows()).await.unwrap();
    run_fixtures(&pool, what).await;
    let pool = reopen(pool, path).await;
    assert_plan_shapes(&pool, what).await;
    assert_unique_keys(&pool, what).await;
    assert_sound(&pool).await;
    run_fixtures(&pool, what).await;
    assert_sound(&pool).await;
}

#[tokio::test]
async fn the_plan_assertions_hold_on_a_reopened_fresh_file() {
    let dir = Dir::new("fresh");
    let pool = open_file(&dir.db()).await;
    run_migrations(&pool).await.unwrap();
    let pool = reopen(pool, &dir.db()).await;
    assert_plan_shapes(&pool, "fresh").await;
    assert_unique_keys(&pool, "fresh").await;
    assert_sound(&pool).await;
}

#[tokio::test]
async fn the_plan_assertions_hold_on_a_reopened_v0_1_28_file_and_its_backup_restores() {
    let dir = Dir::new("v0128");
    let (db, backup) = (dir.db(), dir.0.join("pre-migration.db"));
    let pool = open_file(&db).await;
    v0_1_28().run(&pool).await.unwrap();
    exec(&pool, V0_1_28_ROWS).await.unwrap();
    pool.close().await;
    std::fs::copy(&db, &backup).unwrap();
    let pre_migration = sha256(&backup);

    let pool = open_file(&db).await;
    run_migrations(&pool).await.unwrap();
    let pool = reopen(pool, &db).await;
    assert_plan_shapes(&pool, "upgraded").await;
    assert_unique_keys(&pool, "upgraded").await;
    assert_sound(&pool).await;
    pool.close().await;

    // The copy taken before the upgrade is untouched and is the old database:
    // restoring it brings back exactly the v0.1.28 file, which upgrades again.
    assert_ne!(sha256(&db), pre_migration);
    assert_eq!(sha256(&backup), pre_migration);
    std::fs::copy(&backup, &db).unwrap();
    assert_eq!(sha256(&db), pre_migration);
    let pool = open_file(&db).await;
    let v2: Vec<String> = tables(&pool)
        .await
        .into_iter()
        .filter(|t| t.starts_with("v2_"))
        .collect();
    assert!(v2.is_empty(), "{v2:?}");
    run_migrations(&pool).await.unwrap();
    let pool = reopen(pool, &db).await;
    assert_plan_shapes(&pool, "restored and upgraded again").await;
}

#[tokio::test]
async fn fixtures_1_to_4_hold_on_a_fresh_file() {
    let dir = Dir::new("fx-fresh");
    let pool = open_file(&dir.db()).await;
    run_migrations(&pool).await.unwrap();
    exec(&pool, &base_final()).await.unwrap();
    fixtures_on(pool, &dir.db(), "fresh").await;
}

#[tokio::test]
async fn fixtures_1_to_4_hold_on_a_v0_1_28_file_after_its_upgrade() {
    let dir = Dir::new("fx-v0128");
    let pool = open_file(&dir.db()).await;
    v0_1_28().run(&pool).await.unwrap();
    exec(&pool, V0_1_28_ROWS).await.unwrap();
    let pool = reopen(pool, &dir.db()).await;
    run_migrations(&pool).await.unwrap();
    exec(&pool, &base_final()).await.unwrap();
    fixtures_on(pool, &dir.db(), "v0.1.28 upgraded").await;
}

#[tokio::test]
async fn fixtures_1_to_4_hold_on_a_populated_0016_file_after_its_upgrade() {
    let dir = Dir::new("fx-0016");
    let pool = open_file(&dir.db()).await;
    migrate_to(&pool, 16).await;
    exec(&pool, WORLD_0016).await.unwrap();
    let pool = reopen(pool, &dir.db()).await;
    run_migrations(&pool).await.unwrap();
    fixtures_on(pool, &dir.db(), "0016 world upgraded").await;
}

#[tokio::test]
async fn m0032_the_rebuilt_grant_quarantine_keeps_its_rows_and_takes_device_revocations() {
    let pool = upgrade(32).await;
    for kind in ["device_approval", "unknown_kind"] {
        let e = exec(&pool, &quarantined(kind)).await;
        assert_eq!(kind == "unknown_kind", e.is_err(), "{kind}: {e:?}");
    }
    let e = exec(&pool, &quarantined("root_grant")).await.unwrap_err();
    assert!(e.contains("a grant is quarantined once"), "{e}");
}
