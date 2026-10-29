//! Restore-epoch filesystem harness (plan 12.4 L2246-L2267, G2-52..G2-60;
//! ADR 0002 D-1). These drive the real binary: `restore export-heads`,
//! `prepare`, `commit`, `abort` and `status`, and the server's startup
//! classification. A debug build exits at the write point named by
//! `SHARDX_TEST_CRASH_AT`, leaving the files as a killed process would; each
//! crash point must then classify as exactly one row of the plan's table and
//! resume, or abort, to a consistent state. Supported filesystem: local NTFS
//! (owner decision 2026-10-29); evidence is process exit, not power loss.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::Duration;

use serde_json::{json, Value};
use shardx_team_server::restore_manifest::{self as rm, MANIFEST_FILE};
use shared::canonical::{self as c, sha256};
use shared::keys::signing_key_id;
use shared::restore_epoch::{
    build_signed_transition, mapping_root, RestoreEpochInclusionProofV2, RestoreEpochLeafV2,
    RestoreEpochTransitionV2, RestoreReason, SignedRestoreEpochTransitionV2,
};
use shared::signing::Ed25519SigningKey;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;

const RECORD: &str = "identity-record-v2.bin";
const TENANT: [u8; 16] = [0x41; 16];
const ACCOUNT: [u8; 16] = [0x51; 16];
const DEVICE: [u8; 16] = [0x6c; 16];
/// Signs P2's snapshots, so revoking it touches no transition.
const SIGNER2: u8 = 0x7d;
const FLEET: [u8; 16] = [0xf5; 16];
const FKEK: [u8; 32] = [0xfe; 32];
const P1: [u8; 16] = [0xd1; 16];
const P2: [u8; 16] = [0xd2; 16];

struct Dirs {
    base: PathBuf,
    data: PathBuf,
    identity: PathBuf,
    backup: PathBuf,
}

impl Dirs {
    fn db(&self) -> PathBuf {
        self.data.join("shardx.db")
    }
}

fn dirs(tag: &str) -> Dirs {
    let base = std::env::temp_dir().join(format!("shardx-restore-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let d = Dirs {
        data: base.join("data"),
        identity: base.join("identity"),
        backup: base.join("backup.db"),
        base,
    };
    std::fs::create_dir_all(&d.identity).unwrap();
    std::fs::create_dir_all(d.base.join("objects")).unwrap();
    d
}

fn bin(d: &Dirs) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_shardx-team-server"));
    c.env_remove("SHARDX_TEST_CRASH_AT")
        .env("SHARDX_DATA_DIR", &d.data)
        .env("SHARDX_IDENTITY_DIR", &d.identity)
        .stdin(Stdio::null());
    c
}

fn run(d: &Dirs, crash: Option<&str>, args: &[&str]) -> Output {
    let mut c = bin(d);
    if let Some(point) = crash {
        c.env("SHARDX_TEST_CRASH_AT", point);
    }
    c.args(args).output().unwrap()
}

fn cli(d: &Dirs, args: &[&str]) -> Output {
    run(d, None, args)
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn ok(o: Output) -> Output {
    assert!(o.status.success(), "{}", text(&o));
    o
}

fn refused(o: Output, needle: &str) {
    assert!(!o.status.success(), "{}", text(&o));
    assert!(text(&o).contains(needle), "{needle:?} not in {}", text(&o));
}

fn field(o: &Output, key: &str) -> String {
    String::from_utf8_lossy(&o.stdout)
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{key}=")).map(str::to_string))
        .unwrap_or_else(|| panic!("no {key} in {}", text(o)))
}

/// `restore status`: the class and the plan row.
fn class(d: &Dirs) -> (String, String) {
    let o = ok(cli(d, &["restore", "status"]));
    (field(&o, "class"), field(&o, "row"))
}

fn assert_class(d: &Dirs, class_: &str, row: &str) {
    assert_eq!(class(d), (class_.to_string(), row.to_string()));
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn file_sha(p: &Path) -> [u8; 32] {
    sha256(&std::fs::read(p).unwrap())
}

async fn pool(d: &Dirs) -> SqlitePool {
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&format!(
            "sqlite://{}?mode=rw",
            d.db().to_string_lossy().replace('\\', "/")
        ))
        .await
        .unwrap()
}

async fn exec(d: &Dirs, sql: &str) {
    let p = pool(d).await;
    sqlx::query(sql).execute(&p).await.unwrap();
    p.close().await;
}

async fn scalar(d: &Dirs, sql: &str) -> i64 {
    let p = pool(d).await;
    let v = sqlx::query_scalar(sql).fetch_one(&p).await.unwrap();
    p.close().await;
    v
}

fn device_key() -> Ed25519SigningKey {
    Ed25519SigningKey::from_bytes(&[0x6c; 32])
}

fn signer_key(profile: [u8; 16]) -> Ed25519SigningKey {
    Ed25519SigningKey::from_bytes(&[if profile == P2 { SIGNER2 } else { 0x6c }; 32])
}

fn head(tag: u8) -> [u8; 32] {
    sha256(&[b'h', tag])
}

/// `identity init`; returns the server instance ID.
fn initialised(d: &Dirs) -> [u8; 16] {
    let o = ok(cli(d, &["identity", "init"]));
    unhex(&field(&o, "server_instance_id")).try_into().unwrap()
}

/// One tenant with a live device, a fleet on generation 0, and two
/// published profiles without heads yet.
async fn control_plane(d: &Dirs, instance: &[u8; 16]) {
    let p = pool(d).await;
    let spk = device_key().verifying_key().to_bytes();
    sqlx::query(
        "INSERT INTO v2_tenants (id, slug, status, created_at) VALUES (?, 't', 'active', 't')",
    )
    .bind(TENANT.as_slice())
    .execute(&p)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO v2_accounts (id, tenant_id, username, pw_hash, status, created_at)
       VALUES (?, ?, 'owner', 'x', 'active', 't')",
    )
    .bind(ACCOUNT.as_slice())
    .bind(TENANT.as_slice())
    .execute(&p)
    .await
    .unwrap();
    let spk2 = signer_key(P2).verifying_key().to_bytes();
    for (id, key, hpke) in [(DEVICE, spk, 0x33u8), ([SIGNER2; 16], spk2, 0x35)] {
        sqlx::query(
            "INSERT INTO v2_devices VALUES (?, ?, ?, x'aa', ?, ?, 1, ?, ?, 1, 'active', NULL, 't')",
        )
        .bind(id.as_slice())
        .bind(TENANT.as_slice())
        .bind(ACCOUNT.as_slice())
        .bind(signing_key_id(&key).as_slice())
        .bind(key.as_slice())
        .bind([hpke; 32].as_slice())
        .bind([hpke + 1; 32].as_slice())
        .execute(&p)
        .await
        .unwrap();
    }
    sqlx::query("INSERT INTO v2_root_key_generations (server_instance_id, tenant_id, generation, root_key_id,
         state, created_at, activated_at, required_custodian_grant_count,
         required_custodian_grant_set_hash, recovery_bundle_sha256)
       VALUES (?, ?, 0, ?, 'ACTIVE', 't', 't', 1, ?, ?)")
    .bind(instance.as_slice())
    .bind(TENANT.as_slice())
    .bind([0x7c; 32].as_slice())
    .bind([1u8; 32].as_slice())
    .bind([2u8; 32].as_slice())
    .execute(&p)
    .await
    .unwrap();
    sqlx::query("INSERT INTO v2_fleets VALUES (?, ?, 'fleet', 'active', 't')")
        .bind(FLEET.as_slice())
        .bind(TENANT.as_slice())
        .execute(&p)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO v2_fleet_key_generations (server_instance_id, tenant_id, fleet_id, generation,
         fkek_key_id, root_generation, state, created_at, activated_at)
       VALUES (?, ?, ?, 0, ?, 0, 'ACTIVE', 't', 't')",
    )
    .bind(instance.as_slice())
    .bind(TENANT.as_slice())
    .bind(FLEET.as_slice())
    .bind(FKEK.as_slice())
    .execute(&p)
    .await
    .unwrap();
    for (id, name) in [(P1, "p1"), (P2, "p2")] {
        sqlx::query(
            "INSERT INTO v2_profiles (id, tenant_id, fleet_id, name, current_version, status,
             created_at, updated_at, last_fencing_token, current_key_generation)
           VALUES (?, ?, ?, ?, 0, 'active', 't', 't', 0, 0)",
        )
        .bind(id.as_slice())
        .bind(TENANT.as_slice())
        .bind(FLEET.as_slice())
        .bind(name)
        .execute(&p)
        .await
        .unwrap();
    }
    p.close().await;
}

/// A committed version of `profile`: its object, COMMITTED upload, snapshot
/// and head. `tag` makes every ID of the commit unique.
async fn commit_version(d: &Dirs, instance: &[u8; 16], profile: [u8; 16], version: i64, tag: u8) {
    let object = d
        .base
        .join("objects")
        .join(format!("{}-{version}.bin", hex(&profile)));
    let body = vec![tag; 64];
    std::fs::write(&object, &body).unwrap();
    let object = object.to_string_lossy().into_owned();
    let spk = signer_key(profile).verifying_key().to_bytes();
    let (upload, snapshot, replay) = ([tag; 16], [tag ^ 0x80; 16], [tag ^ 0x40; 16]);
    let previous = (version > 1).then(|| head(tag - 2).to_vec());
    let p = pool(d).await;
    sqlx::query(
        "INSERT INTO v2_uploads (server_instance_id, tenant_id, upload_id, fleet_id, profile_id,
           snapshot_id, manifest_replay_id, lease_id, fencing_token, base_version, restore_epoch,
           operation_scope, idempotency_key, canonical_request_hash, intent_hash, preamble_sha256,
           dek_slot_sha256, fkek_key_id, key_generation, expected_ciphertext_size,
           expected_ciphertext_sha256, committed_offset, staging_path, immutable_path, state,
           signed_manifest_container_bytes, signed_manifest_container_hash,
           signed_manifest_container_bytes_sha256, exact_commit_request_bytes,
           exact_commit_request_bytes_sha256, exact_finalize_response_bytes,
           exact_commit_receipt_binding_bytes, commit_receipt_binding_bytes_sha256,
           expires_at_ms, created_at_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'profile.create-upload.v2', ?, ?, ?, ?, ?, ?, 0,
                 64, ?, 64, 'staging', ?, 'COMMITTED', x'aa', ?, ?, ?, ?, x'cc', x'dd', ?, 0, 0)",
    )
    .bind(instance.as_slice())
    .bind(TENANT.as_slice())
    .bind(upload.as_slice())
    .bind(FLEET.as_slice())
    .bind(profile.as_slice())
    .bind(snapshot.as_slice())
    .bind(replay.as_slice())
    .bind(upload.as_slice())
    .bind(version)
    .bind(version - 1)
    .bind(upload.as_slice())
    .bind([1u8; 32].as_slice())
    .bind([2u8; 32].as_slice())
    .bind([3u8; 32].as_slice())
    .bind([4u8; 32].as_slice())
    .bind(FKEK.as_slice())
    .bind(sha256(&body).as_slice())
    .bind(&object)
    .bind([5u8; 32].as_slice())
    .bind([6u8; 32].as_slice())
    .bind([tag, 0xbb].as_slice())
    .bind([7u8; 32].as_slice())
    .bind([8u8; 32].as_slice())
    .execute(&p)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO v2_snapshots VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 2, ?, ?, ?, ?, ?, 64,
           x'aa', ?, ?, ?, ?, ?, 1, 1, ?, 0, ?, 0)",
    )
    .bind(instance.as_slice())
    .bind(TENANT.as_slice())
    .bind(FLEET.as_slice())
    .bind(profile.as_slice())
    .bind(version)
    .bind(snapshot.as_slice())
    .bind(replay.as_slice())
    .bind(upload.as_slice())
    .bind(FKEK.as_slice())
    .bind([2u8; 32].as_slice())
    .bind([3u8; 32].as_slice())
    .bind([4u8; 32].as_slice())
    .bind(&object)
    .bind(sha256(&body).as_slice())
    .bind([5u8; 32].as_slice())
    .bind([6u8; 32].as_slice())
    .bind(previous)
    .bind(head(tag).as_slice())
    .bind(signing_key_id(&spk).as_slice())
    .bind([0u8; 64].as_slice())
    .bind(if profile == P2 { [SIGNER2; 16] } else { DEVICE }.as_slice())
    .execute(&p)
    .await
    .unwrap();
    sqlx::query("UPDATE v2_profiles SET current_version = ? WHERE id = ?")
        .bind(version)
        .bind(profile.as_slice())
        .execute(&p)
        .await
        .unwrap();
    p.close().await;
}

/// The leaves of `export-heads`' request for `TENANT`, and the txn it drew.
fn exported(d: &Dirs) -> (String, Vec<RestoreEpochLeafV2>) {
    let out = d.base.join("requests");
    let backup = d.backup.to_string_lossy().into_owned();
    let o = ok(cli(
        d,
        &[
            "restore",
            "export-heads",
            "--backup",
            &backup,
            "--out",
            &out.to_string_lossy(),
        ],
    ));
    let txn = field(&o, "restore_txn_id");
    let path = out.join(format!("request-{}.cbor", hex(&TENANT)));
    let Ok(bytes) = std::fs::read(path) else {
        assert_eq!(field(&o, "tenants"), "0");
        return (txn, Vec::new());
    };
    let Ok(c::Value::Map(fields)) = c::decode(&bytes) else {
        panic!("a request is a map");
    };
    let leaves = fields
        .into_iter()
        .find(|(k, _)| k == "leaves")
        .map(|(_, v)| v)
        .unwrap();
    let c::Value::Array(items) = leaves else {
        panic!("leaves is an array");
    };
    let leaves = items
        .into_iter()
        .map(|v| match v {
            c::Value::Bytes(b) => RestoreEpochLeafV2::parse(&b).unwrap(),
            _ => panic!("a leaf is bytes"),
        })
        .collect();
    (txn, leaves)
}

/// The custodian's transition over `leaves`, filed the way the route files
/// it (plan 8.1 L1131): the exact signed bytes and one proof per leaf.
async fn file_transition(d: &Dirs, instance: &[u8; 16], leaves: &[RestoreEpochLeafV2]) {
    let spk = device_key().verifying_key().to_bytes();
    let t = RestoreEpochTransitionV2 {
        transition_replay_id: [0x31; 16],
        server_instance_id: *instance,
        tenant_id: TENANT,
        previous_epoch: 0,
        new_epoch: 1,
        mapping_count: leaves.len() as u64,
        profile_head_mapping_root: mapping_root(&TENANT, leaves).unwrap(),
        reason_code: RestoreReason::VerifiedBackupRollback,
        approver_account_id: ACCOUNT,
        approver_device_id: DEVICE,
        approver_signing_key_id: signing_key_id(&spk),
        issued_at_ms: 1,
        nonce: [0x32; 16],
    };
    let signed = build_signed_transition(&device_key(), &t);
    let container = SignedRestoreEpochTransitionV2::parse(&signed).unwrap();
    let p = pool(d).await;
    sqlx::query(
        "INSERT INTO v2_restore_epoch_transitions VALUES (?, ?, 0, 1, ?,
           'PROFILE_HEAD_SET_MERKLE_V2', ?, ?, 'verified_backup_rollback', ?, ?, ?, 1, ?, ?, ?,
           1, 1, ?, ?, ?, ?, 't')",
    )
    .bind(instance.as_slice())
    .bind(TENANT.as_slice())
    .bind(t.transition_replay_id.as_slice())
    .bind(leaves.len() as i64)
    .bind(t.profile_head_mapping_root.as_slice())
    .bind(ACCOUNT.as_slice())
    .bind(DEVICE.as_slice())
    .bind(t.approver_signing_key_id.as_slice())
    .bind(t.nonce.as_slice())
    .bind(container.canonical_transition_payload_bytes())
    .bind(container.transition_payload_sha256().as_slice())
    .bind(container.signature_bytes())
    .bind(container.signed_transition_container_hash().as_slice())
    .bind(signed.as_slice())
    .bind(container.exact_signed_transition_bytes_sha256().as_slice())
    .execute(&p)
    .await
    .unwrap();
    for (i, leaf) in leaves.iter().enumerate() {
        let proof = RestoreEpochInclusionProofV2::build(&t, leaves, i)
            .unwrap()
            .encode();
        sqlx::query(
            "INSERT INTO v2_restore_epoch_transition_proofs VALUES (?, ?, 0, 1, ?, ?, ?, ?, ?, ?,
               ?, ?, ?, 't')",
        )
        .bind(instance.as_slice())
        .bind(TENANT.as_slice())
        .bind(leaf.profile_id.as_slice())
        .bind(leaf.previous_signed_head_hash.as_slice())
        .bind(leaf.new_signed_head_hash.as_slice())
        .bind(i as i64)
        .bind(leaves.len() as i64)
        .bind(leaf.encode())
        .bind(leaf.hash().as_slice())
        .bind(proof.as_slice())
        .bind(c::domain_hash(c::L_RESTORE_EPOCH_PROOF, &proof).as_slice())
        .execute(&p)
        .await
        .unwrap();
    }
    p.close().await;
}

/// A live DB at `E = 0` whose profile P1 advanced past the backup (v2 live,
/// v1 in the backup) while P2 did not, with the custodian's transition over
/// both leaves staged. Returns the txn `export-heads` drew.
async fn covered(d: &Dirs) -> String {
    let instance = initialised(d);
    control_plane(d, &instance).await;
    commit_version(d, &instance, P1, 1, 1).await;
    commit_version(d, &instance, P2, 1, 2).await;
    std::fs::copy(d.db(), &d.backup).unwrap();
    commit_version(d, &instance, P1, 2, 3).await;
    let (txn, leaves) = exported(d);
    assert_eq!(
        leaves,
        vec![
            RestoreEpochLeafV2 {
                tenant_id: TENANT,
                profile_id: P1,
                previous_signed_head_hash: head(3),
                new_signed_head_hash: head(1),
            },
            RestoreEpochLeafV2 {
                tenant_id: TENANT,
                profile_id: P2,
                previous_signed_head_hash: head(2),
                new_signed_head_hash: head(2),
            },
        ],
        "a leaf for every profile with a head in both DBs, live head first"
    );
    file_transition(d, &instance, &leaves).await;
    txn
}

/// A live DB at `E = 0` with no profile, so the set is empty (D-1 allows an
/// empty index). Returns the txn.
fn empty(d: &Dirs) -> String {
    initialised(d);
    std::fs::copy(d.db(), &d.backup).unwrap();
    exported(d).0
}

fn prepare(d: &Dirs, crash: Option<&str>, txn: &str) -> Output {
    let backup = d.backup.to_string_lossy().into_owned();
    run(
        d,
        crash,
        &["restore", "prepare", "--backup", &backup, "--txn", txn],
    )
}

fn epoch_of_record(d: &Dirs) -> u64 {
    shardx_team_server::identity_record::parse(&std::fs::read(d.identity.join(RECORD)).unwrap())
        .unwrap()
        .restore_epoch
}

/// The state every completed restore of `covered` must reach: record and
/// mirror at `E+1`, P1 back at v1, the bundle retired, the live DB archived.
async fn assert_restored(d: &Dirs, txn: &str, archived: bool) {
    assert_class(d, "K3", "L2259");
    let show = ok(cli(d, &["identity", "show"]));
    assert_eq!(field(&show, "status"), "OK");
    assert_eq!(field(&show, "restore_epoch"), "1");
    assert_eq!(epoch_of_record(d), 1);
    assert_eq!(
        scalar(d, "SELECT current_version FROM v2_profiles WHERE id = x'd1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1'").await,
        1
    );
    assert_eq!(scalar(d, "SELECT count(*) FROM v2_snapshots").await, 2);
    assert_eq!(scalar(d, "SELECT count(*) FROM v2_uploads").await, 2);
    assert_eq!(
        scalar(
            d,
            "SELECT count(*) FROM v2_audit_events WHERE action = 'tenant.restore_epoch_transition'"
        )
        .await,
        1
    );
    // The prepare audit rode in the candidate (one per prepare run), the
    // commit audit in step 5.
    assert_eq!(
        scalar(
            d,
            "SELECT count(*) FROM audit_log WHERE action = 'server.restore_commit'"
        )
        .await,
        1
    );
    assert!(
        scalar(
            d,
            "SELECT count(*) FROM audit_log WHERE action = 'server.restore_prepare'"
        )
        .await
            >= 1
    );
    assert!(!d.identity.join(MANIFEST_FILE).exists());
    assert!(!d.identity.join(format!("restore-{txn}")).exists());
    assert!(!d.data.join(format!("restore-candidate-{txn}.db")).exists());
    // `abort --orphans` removes the archive with the other K3 strays (D-1).
    assert_eq!(
        d.data.join(format!("pre-restore-{txn}.db")).exists(),
        archived
    );
}

// ------------------------------------------------------------------ G2-52 ---

/// Plan L2267 and the D-1 crash-point table: a crash at every write, rename
/// and fsync point maps to exactly one row, and resuming from that row (or
/// aborting while the authority is still `E`) ends in the same restored
/// state. Prepare crashes leave `E` in force (K3, L2259); `abort --orphans`
/// clears them and a second prepare completes.
#[tokio::test]
async fn g2_52_every_crash_point_maps_to_one_row_and_resumes_to_the_restored_state() {
    let prepare_points = [
        ("prepare.2a.tmp", "K3", "L2259"),
        ("prepare.2a", "K3", "L2259"),
        ("prepare.2b.artifact.tmp", "K3", "L2259"),
        ("prepare.2b", "K3", "L2259"),
        ("prepare.2c.tmp", "K3", "L2259"),
        // A killed process leaves the rename in place: the K7 branch of
        // "K3 or K7" (the K3 branch is the .tmp point above).
        ("prepare.2c.replaced", "K7", "L2260"),
    ];
    let commit_points = [
        ("commit.3.tmp", "K7", "L2260"),
        ("commit.3.replaced", "K8", "L2261"),
        ("commit.3.synced", "K8", "L2261"),
        ("commit.4.i", "K8", "L2261"),
        ("commit.4.ii", "K8", "L2261"),
        ("commit.4.iii", "K8", "L2261"),
        ("commit.4.v", "K9", "L2262"),
        ("commit.4.vi", "K9", "L2262"),
        ("commit.5.tx", "K9", "L2262"),
        ("commit.5.committed", "K10", "L2265"),
        ("commit.6.tmp", "K10", "L2265"),
        ("commit.6.replaced", "K11", "L2265"),
        ("commit.7.artifact", "K11", "L2265"),
        ("commit.7.manifest", "K3", "L2259"),
    ];
    for (i, (point, class_, row)) in prepare_points.iter().chain(&commit_points).enumerate() {
        let d = dirs(&format!("sweep{i}"));
        let txn = covered(&d).await;
        // An empty -wal sidecar, so step 4 (ii) has a sidecar to move.
        std::fs::write(d.data.join("shardx.db-wal"), b"").unwrap();
        let is_prepare = point.starts_with("prepare.");
        if is_prepare {
            let o = prepare(&d, Some(point), &txn);
            assert_eq!(o.status.code(), Some(86), "{point}: {}", text(&o));
        } else {
            ok(prepare(&d, None, &txn));
            let o = run(&d, Some(point), &["restore", "commit"]);
            assert_eq!(o.status.code(), Some(86), "{point}: {}", text(&o));
        }
        assert_eq!(class(&d), (class_.to_string(), row.to_string()), "{point}");
        // The authority never moves back, whatever the crash point.
        let commit_point = !is_prepare && *point != "commit.3.tmp";
        assert_eq!(epoch_of_record(&d), u64::from(commit_point), "{point}");
        if *point == "commit.5.tx" {
            assert!(d.data.join("shardx.db-journal").exists(), "a hot journal");
        }
        match *class_ {
            "K3" if is_prepare => {
                refused(prepare(&d, None, &txn), "leftovers of an earlier restore");
                ok(cli(&d, &["restore", "abort", "--orphans"]));
                ok(prepare(&d, None, &txn));
                ok(cli(&d, &["restore", "commit"]));
            }
            "K3" => {
                assert!(d.data.join(format!("pre-restore-{txn}.db")).exists());
                ok(cli(&d, &["restore", "abort", "--orphans"]));
            }
            _ => {
                ok(cli(&d, &["restore", "commit"]));
            }
        }
        assert_restored(&d, &txn, *point != "commit.7.manifest").await;
        let _ = std::fs::remove_dir_all(&d.base);
    }
}

// -------------------------------------------------------------- server ---

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn(d: &Dirs, port: u16) -> Server {
    let mut c = bin(d);
    c.env("SHARDX_BIND", format!("127.0.0.1:{port}"))
        .env("SHARDX_TOKEN_SECRET", "restore-epoch-harness")
        .env("SHARDX_ADMIN_USER", "admin")
        .env("SHARDX_ADMIN_PASS", "secret")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    Server(c.spawn().unwrap())
}

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap()
}

async fn ready(c: &reqwest::Client, port: u16) -> String {
    for _ in 0..100 {
        if let Ok(r) = c
            .get(format!("http://127.0.0.1:{port}/health"))
            .send()
            .await
        {
            if r.status().is_success() {
                let v: Value = c
                    .post(format!("http://127.0.0.1:{port}/auth/login"))
                    .json(&json!({ "username": "admin", "password": "secret" }))
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                return v["token"].as_str().unwrap().to_string();
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("server did not start on port {port}");
}

/// A v2 write, the identity read and a v1 write: their statuses and the v2
/// reason code.
async fn probe(port: u16) -> (u16, String, u16, bool) {
    let c = http();
    let token = ready(&c, port).await;
    let write = c
        .post(format!("http://127.0.0.1:{port}/v2/operations"))
        .bearer_auth(&token)
        .json(&json!({ "tenant_id": "00", "idempotency_key": "00", "operation_kind": "x", "payload_hex": "" }))
        .send()
        .await
        .unwrap();
    let status = write.status().as_u16();
    let body: Value = write.json().await.unwrap_or(Value::Null);
    let read = c
        .get(format!("http://127.0.0.1:{port}/v2/server-identity"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16();
    let v1 = c
        .post(format!("http://127.0.0.1:{port}/folders"))
        .bearer_auth(&token)
        .json(&json!({ "name": "probe" }))
        .send()
        .await
        .unwrap()
        .status()
        .is_success();
    (
        status,
        body["code"].as_str().unwrap_or_default().to_string(),
        read,
        v1,
    )
}

/// The server during a restore: v2 refused, v1 logins work, and nothing at
/// all is written to the DB (it is opened read-only, D-1 round-4 B7).
async fn assert_server_read_only(d: &Dirs, port: u16) {
    let before = file_sha(&d.db());
    {
        let _s = spawn(d, port);
        let (status, code, read, v1) = probe(port).await;
        assert_eq!((status, read), (423, 423));
        assert_eq!(code, "EPOCH_RECONCILIATION_REQUIRED");
        assert!(!v1, "a v1 write must fail on the read-only DB");
    }
    assert_eq!(file_sha(&d.db()), before, "the server changed the DB");
}

/// The server at `K3`: v2 writes reach their handlers.
async fn assert_server_normal(d: &Dirs, port: u16) {
    let _s = spawn(d, port);
    let (status, _, read, v1) = probe(port).await;
    assert_eq!(
        (status, read),
        (400, 200),
        "the handler, not the gate, answers"
    );
    assert!(v1);
}

// ------------------------------------------------------------------ G2-54 ---

/// L2259: external record = mirror and no preparation manifest is normal
/// operation; any manifest, even a terminal one, keeps the server out of it,
/// and a record the mirror does not attest still fails closed.
#[tokio::test]
async fn l2259_g2_54_a_record_equal_to_its_mirror_without_a_manifest_opens_normally() {
    let d = dirs("l2259");
    initialised(&d);
    assert_class(&d, "K3", "L2259");
    assert_server_normal(&d, 28411).await;

    // Any manifest at all is not "no preparation".
    std::fs::write(d.identity.join(MANIFEST_FILE), b"junk").unwrap();
    assert_class(&d, "K5a", "L2260");
    let show = cli(&d, &["identity", "show"]);
    assert_eq!(field(&show, "status"), "EPOCH_RECONCILIATION_REQUIRED");
    assert_server_read_only(&d, 28411).await;
    std::fs::remove_file(d.identity.join(MANIFEST_FILE)).unwrap();

    // The same epoch with other record bytes is never K3: D-1 classes it K4
    // (operator recovery), and the authority check reports it behind the DB.
    let good = std::fs::read(d.identity.join(RECORD)).unwrap();
    let original = shardx_team_server::identity_record::parse(&good).unwrap();
    let other = shardx_team_server::identity_record::IdentityRecordV2::genesis(
        original.server_instance_id,
        7,
    )
    .encode()
    .unwrap();
    std::fs::write(d.identity.join(RECORD), other).unwrap();
    assert_class(&d, "K4", "L2263");
    let show = cli(&d, &["identity", "show"]);
    assert_eq!(field(&show, "status"), "EPOCH_AUTHORITY_BEHIND_DB");
    std::fs::write(d.identity.join(RECORD), &good).unwrap();
    assert_class(&d, "K3", "L2259");
    let _ = std::fs::remove_dir_all(&d.base);
}

// ------------------------------------------------------------------ G2-55 ---

/// L2260: a durable preparation with the authority still at `E` keeps every
/// write off; it either commits (re-verifying the live DB hash) or aborts
/// with an audit, and the record never moves.
#[tokio::test]
async fn l2260_g2_55_a_durable_preparation_at_e_keeps_writes_off_until_commit_or_abort() {
    let d = dirs("l2260");
    let txn = empty(&d);
    // Bootstrap the admin at E, so the read-only server can log in.
    assert_server_normal(&d, 28412).await;
    ok(prepare(&d, None, &txn));
    assert_class(&d, "K7", "L2260");
    let record = std::fs::read(d.identity.join(RECORD)).unwrap();
    assert_server_read_only(&d, 28412).await;
    refused(cli(&d, &["restore", "commit", "--retire"]), "only for K5b");
    refused(cli(&d, &["restore", "abort", "--orphans"]), "only for K3");
    refused(prepare(&d, None, &txn), "not K3");

    // An unparsable manifest before the commit point can only be aborted.
    let manifest = std::fs::read(d.identity.join(MANIFEST_FILE)).unwrap();
    let mut broken = manifest.clone();
    broken[20] ^= 1;
    std::fs::write(d.identity.join(MANIFEST_FILE), &broken).unwrap();
    assert_class(&d, "K5a", "L2260");
    refused(cli(&d, &["restore", "commit"]), "not allowed in K5a");
    std::fs::write(d.identity.join(MANIFEST_FILE), &manifest).unwrap();

    // A live DB that changed after prepare refuses the commit (step 3).
    exec(
        &d,
        "INSERT INTO folders (id, name, created_at) VALUES ('f', 'late', 't')",
    )
    .await;
    refused(
        cli(&d, &["restore", "commit"]),
        "live DB changed after prepare",
    );
    assert_class(&d, "K7", "L2260");
    assert_eq!(std::fs::read(d.identity.join(RECORD)).unwrap(), record);

    // Audited abort: everything of the restore goes, the record stays at E.
    ok(cli(&d, &["restore", "abort"]));
    assert_class(&d, "K3", "L2259");
    assert_eq!(std::fs::read(d.identity.join(RECORD)).unwrap(), record);
    assert!(!d.identity.join(MANIFEST_FILE).exists());
    assert!(!d.identity.join(format!("restore-{txn}")).exists());
    assert!(!d.data.join(format!("restore-candidate-{txn}.db")).exists());
    assert_eq!(
        scalar(
            &d,
            "SELECT count(*) FROM audit_log WHERE action = 'server.restore_abort'"
        )
        .await,
        1
    );
    refused(cli(&d, &["restore", "abort"]), "only for K5a and K7");

    // Prepared again, the commit resumes step 3 and reaches E+1.
    ok(prepare(&d, None, &txn));
    ok(cli(&d, &["restore", "commit"]));
    assert_class(&d, "K3", "L2259");
    assert_eq!(epoch_of_record(&d), 1);
    assert_server_normal(&d, 28412).await;
    let _ = std::fs::remove_dir_all(&d.base);
}

// ------------------------------------------------------------------ G2-56 ---

/// L2261: record `E+1` with the live DB still mirroring `E`. Only the exact
/// prepared candidate is installed; the old DB is never opened for writes
/// and is archived byte for byte as it was at prepare.
#[tokio::test]
async fn l2261_g2_56_an_authority_ahead_of_the_live_mirror_resumes_only_the_install() {
    let d = dirs("l2261");
    let txn = empty(&d);
    assert_server_normal(&d, 28413).await;
    ok(prepare(&d, None, &txn));
    let live = file_sha(&d.db());
    let o = run(&d, Some("commit.3.synced"), &["restore", "commit"]);
    assert_eq!(o.status.code(), Some(86));
    assert_class(&d, "K8", "L2261");
    assert_server_read_only(&d, 28413).await;
    assert_eq!(file_sha(&d.db()), live, "the old DB is untouched");

    // After step 4 (iii) nothing is at the DB path: the server refuses to
    // start rather than create one.
    let d2 = dirs("l2261b");
    let txn2 = empty(&d2);
    ok(prepare(&d2, None, &txn2));
    let o = run(&d2, Some("commit.4.iii"), &["restore", "commit"]);
    assert_eq!(o.status.code(), Some(86));
    assert_class(&d2, "K8", "L2261");
    let mut s = spawn(&d2, 28414);
    let mut exited = None;
    for _ in 0..100 {
        if let Some(status) = s.0.try_wait().unwrap() {
            exited = Some(status);
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        exited.is_some_and(|e| !e.success()),
        "the server must not start"
    );
    assert!(!d2.db().exists(), "and must not create a DB");
    ok(cli(&d2, &["restore", "commit"]));
    assert_class(&d2, "K3", "L2259");

    ok(cli(&d, &["restore", "commit"]));
    assert_class(&d, "K3", "L2259");
    assert_eq!(
        file_sha(&d.data.join(format!("pre-restore-{txn}.db"))),
        live
    );
    let _ = std::fs::remove_dir_all(&d.base);
    let _ = std::fs::remove_dir_all(&d2.base);
}

// ------------------------------------------------------------------ G2-57 ---

/// L2262: record `E+1` with the installed DB's mirror behind. The candidate
/// hash, the artifacts and the head coverage are verified before the mirror
/// is rebuilt in one transaction; a crash inside that transaction rolls back
/// to the exact candidate (the K9 dependency, under the DELETE journal
/// policy of G2-50), and anything else fails closed.
#[tokio::test]
async fn l2262_g2_57_an_installed_db_behind_the_record_is_verified_then_rebuilt() {
    // A crash inside the step-5 transaction.
    let d = dirs("l2262");
    let txn = covered(&d).await;
    ok(prepare(&d, None, &txn));
    assert_eq!(
        run(&d, Some("commit.5.tx"), &["restore", "commit"])
            .status
            .code(),
        Some(86)
    );
    assert!(d.data.join("shardx.db-journal").exists());
    assert_class(&d, "K9", "L2262");
    ok(cli(&d, &["restore", "commit"]));
    assert_restored(&d, &txn, true).await;
    let _ = std::fs::remove_dir_all(&d.base);

    // An installed DB that is not the candidate: K12, record kept at E+1.
    let d = dirs("l2262b");
    let txn = covered(&d).await;
    let candidate = unhex(&field(&ok(prepare(&d, None, &txn)), "candidate_db_sha256"));
    assert_eq!(
        run(&d, Some("commit.4.vi"), &["restore", "commit"])
            .status
            .code(),
        Some(86)
    );
    assert_eq!(
        file_sha(&d.db()).to_vec(),
        candidate,
        "the installed DB is the candidate"
    );
    exec(
        &d,
        "INSERT INTO folders (id, name, created_at) VALUES ('f', 'tamper', 't')",
    )
    .await;
    assert_class(&d, "K9", "L2262");
    refused(
        cli(&d, &["restore", "commit"]),
        "K12: the installed DB is not the prepared candidate",
    );
    assert_class(&d, "K9", "L2262");
    assert_eq!(epoch_of_record(&d), 1, "never lowered");
    let _ = std::fs::remove_dir_all(&d.base);

    // A proof artifact missing after the install: coverage cannot be proven.
    let d = dirs("l2262c");
    let txn = covered(&d).await;
    ok(prepare(&d, None, &txn));
    assert_eq!(
        run(&d, Some("commit.4.vi"), &["restore", "commit"])
            .status
            .code(),
        Some(86)
    );
    let dir = d.identity.join(format!("restore-{txn}"));
    let proof = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| RestoreEpochInclusionProofV2::parse(&std::fs::read(p).unwrap()).is_ok())
        .unwrap();
    std::fs::remove_file(proof).unwrap();
    refused(
        cli(&d, &["restore", "commit"]),
        "installed proofs are not its artifacts",
    );
    assert_class(&d, "K9", "L2262");
    assert_eq!(
        scalar(&d, "SELECT restore_epoch FROM v2_server_state").await,
        0
    );
    let _ = std::fs::remove_dir_all(&d.base);

    // After the step-5 commit (K10) the readback re-proves the coverage: a
    // head the leaves do not name stops the retirement.
    let d = dirs("l2262d");
    let txn = covered(&d).await;
    ok(prepare(&d, None, &txn));
    let o = run(&d, Some("commit.5.committed"), &["restore", "commit"]);
    assert_eq!(o.status.code(), Some(86));
    exec(
        &d,
        "UPDATE v2_profiles SET current_version = 0 WHERE name = 'p2'",
    )
    .await;
    refused(
        cli(&d, &["restore", "commit"]),
        "do not cover exactly the installed heads",
    );
    assert_class(&d, "K10", "L2265");
    let _ = std::fs::remove_dir_all(&d.base);
}

// ------------------------------------------------------------------ G2-58 ---

/// L2263: an external record ahead of the DB without exact recovery evidence
/// (missing or corrupt manifest, uncovered or unsigned leaves) fails closed
/// for operator recovery; nothing rebuilds or lowers the authority.
#[tokio::test]
async fn l2263_g2_58_an_authority_ahead_without_exact_evidence_fails_closed() {
    let d = dirs("l2263");
    let txn = covered(&d).await;
    ok(prepare(&d, None, &txn));
    assert_eq!(
        run(&d, Some("commit.3.synced"), &["restore", "commit"])
            .status
            .code(),
        Some(86)
    );
    let manifest = std::fs::read(d.identity.join(MANIFEST_FILE)).unwrap();

    // No manifest: K4.
    std::fs::remove_file(d.identity.join(MANIFEST_FILE)).unwrap();
    assert_class(&d, "K4", "L2263");
    let show = cli(&d, &["identity", "show"]);
    assert_eq!(field(&show, "status"), "EPOCH_RECONCILIATION_REQUIRED");
    refused(cli(&d, &["restore", "commit"]), "not allowed in K4");
    refused(cli(&d, &["restore", "abort"]), "only for K5a and K7");

    // A corrupt manifest after the commit point: K6, and neither resume nor
    // abort.
    let mut broken = manifest.clone();
    broken[150] ^= 1;
    std::fs::write(d.identity.join(MANIFEST_FILE), &broken).unwrap();
    assert_class(&d, "K6", "L2263");
    refused(cli(&d, &["restore", "commit"]), "not allowed in K6");
    refused(cli(&d, &["restore", "abort"]), "only for K5a and K7");
    assert_eq!(epoch_of_record(&d), 1, "never lowered");

    // The exact manifest restored, the restore completes.
    std::fs::write(d.identity.join(MANIFEST_FILE), &manifest).unwrap();
    ok(cli(&d, &["restore", "commit"]));
    assert_restored(&d, &txn, true).await;
    let _ = std::fs::remove_dir_all(&d.base);

    // Uncovered: no transition staged for a tenant that needs one.
    let d = dirs("l2263b");
    let instance = initialised(&d);
    control_plane(&d, &instance).await;
    commit_version(&d, &instance, P1, 1, 1).await;
    std::fs::copy(d.db(), &d.backup).unwrap();
    let (txn, leaves) = exported(&d);
    refused(prepare(&d, None, &txn), "do not cover exactly the tenants");
    assert_class(&d, "K3", "L2259");
    assert!(!d.identity.join(MANIFEST_FILE).exists());

    // A transition over other leaves than the restore's.
    let mut wrong = leaves.clone();
    wrong[0].new_signed_head_hash = [0x99; 32];
    file_transition(&d, &instance, &wrong).await;
    refused(prepare(&d, None, &txn), "does not sign the computed leaves");
    assert_class(&d, "K3", "L2259");
    assert!(!d.identity.join(MANIFEST_FILE).exists());
    let _ = std::fs::remove_dir_all(&d.base);
}

// ------------------------------------------------------------------ G2-60 ---

/// L2265: `E+1` reconciled into the mirror. A preparation that is PREPARED
/// or TERMINAL there is retired (artifacts, then manifest, then directory),
/// a corrupt one only by `--retire` (K5b), and the next start is normal.
#[tokio::test]
async fn l2265_g2_60_a_reconciled_epoch_retires_its_bundle_and_the_next_start_is_normal() {
    let d = dirs("l2265");
    let txn = empty(&d);
    assert_server_normal(&d, 28415).await;
    ok(prepare(&d, None, &txn));
    assert_eq!(
        run(&d, Some("commit.6.replaced"), &["restore", "commit"])
            .status
            .code(),
        Some(86)
    );
    assert_class(&d, "K11", "L2265");
    let state = std::fs::read(d.identity.join(MANIFEST_FILE)).unwrap();
    assert_eq!(rm::parse(&state).unwrap().state, rm::State::Terminal);
    assert_server_read_only(&d, 28415).await;
    ok(cli(&d, &["restore", "commit"]));
    assert_class(&d, "K3", "L2259");
    assert!(!d.identity.join(MANIFEST_FILE).exists());
    assert!(!d.identity.join(format!("restore-{txn}")).exists());
    assert_eq!(
        field(&ok(cli(&d, &["identity", "show"])), "restore_epoch"),
        "1"
    );
    assert_server_normal(&d, 28415).await;
    let _ = std::fs::remove_dir_all(&d.base);

    // K5b: committed in step 5, then the manifest became unparsable.
    let d = dirs("l2265b");
    let txn = empty(&d);
    ok(prepare(&d, None, &txn));
    assert_eq!(
        run(&d, Some("commit.5.committed"), &["restore", "commit"])
            .status
            .code(),
        Some(86)
    );
    assert_class(&d, "K10", "L2265");
    std::fs::write(d.identity.join(MANIFEST_FILE), b"torn").unwrap();
    assert_class(&d, "K5b", "L2265");
    refused(cli(&d, &["restore", "commit"]), "not allowed in K5b");
    refused(cli(&d, &["restore", "abort"]), "only for K5a and K7");
    ok(cli(&d, &["restore", "commit", "--retire"]));
    assert_class(&d, "K3", "L2259");
    assert!(!d.identity.join(format!("restore-{txn}")).exists());
    assert_eq!(
        scalar(
            &d,
            "SELECT count(*) FROM audit_log WHERE action = 'server.restore_retire'"
        )
        .await,
        1
    );
    let _ = std::fs::remove_dir_all(&d.base);
}

// ------------------------------------------------------- D-1 refusals ---

async fn assert_refused_cleanly(d: &Dirs, txn: &str, needle: &str) {
    refused(prepare(d, None, txn), needle);
    assert_class(d, "K3", "L2259");
    assert!(!d.identity.join(MANIFEST_FILE).exists());
    assert!(
        !d.data
            .join(format!("restore-candidate-{txn}.db.tmp"))
            .exists(),
        "a refused prepare leaves no candidate"
    );
    assert!(!d.identity.join(format!("restore-{txn}")).exists());
}

async fn on_backup(d: &Dirs, sql: &str) {
    let url = format!(
        "sqlite://{}?mode=rw",
        d.backup.to_string_lossy().replace('\\', "/")
    );
    let p = SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    sqlx::query(sql).execute(&p).await.unwrap();
    p.close().await;
}

/// The COMMIT ledger row of the request `request`, as the route stores it.
fn ledger(key: u8, request: [u8; 2]) -> String {
    format!(
        "INSERT INTO v2_idempotency (server_instance_id, tenant_id, actor_device_id,
           operation_scope, idempotency_key, operation_kind, canonical_request_hash,
           exact_request_bytes, exact_request_bytes_sha256, status, response_record_type,
           exact_response_bytes, exact_response_bytes_sha256, retained_until)
         SELECT server_instance_id, x'{t}', x'{dv}', 'profile.commit.v2', x'{k}', 'COMMIT',
           x'{h}', x'{r}', x'{h}', 'succeeded', 'CommitReceiptBindingV2', x'01', x'{h}', 0
           FROM v2_server_state",
        t = hex(&TENANT),
        dv = hex(&DEVICE),
        k = hex(&[key; 16]),
        h = hex(&[9; 32]),
        r = hex(&request),
    )
}

/// D-1 restore scope, strict where D-1 drops (no `--drop-unreferenced`):
/// prepare refuses a merge it cannot prove, before anything is durable.
#[tokio::test]
async fn d1_prepare_refuses_every_merge_it_cannot_prove_and_leaves_nothing() {
    let d = dirs("refusals");
    let txn = covered(&d).await;
    refused(prepare(&d, None, &"0".repeat(32)), "--txn must not be zero");

    // The backup's schema differs.
    on_backup(&d, "CREATE TABLE extra (a)").await;
    assert_refused_cleanly(&d, &txn, "the backup's schema differs").await;
    on_backup(&d, "DROP TABLE extra").await;

    // A kept snapshot's object is not in the live store byte for byte.
    let object = d.base.join("objects").join(format!("{}-1.bin", hex(&P2)));
    let body = std::fs::read(&object).unwrap();
    // Same size, other bytes: only the hash tells.
    std::fs::write(&object, vec![0xee; body.len()]).unwrap();
    assert_refused_cleanly(&d, &txn, "is missing or differs").await;
    std::fs::write(&object, &body).unwrap();

    // A kept snapshot's signer is revoked in live.
    let set = |id: u8, status: &str| {
        format!(
            "UPDATE v2_devices SET status = '{status}' WHERE id = x'{}'",
            hex(&[id; 16])
        )
    };
    exec(&d, &set(SIGNER2, "revoked")).await;
    assert_refused_cleanly(&d, &txn, "revoked or unknown in the live DB").await;
    exec(&d, &set(SIGNER2, "active")).await;

    // The transition's signer is no longer a live device.
    exec(&d, &set(0x6c, "revoked")).await;
    assert_refused_cleanly(&d, &txn, "transition signer is not a live device").await;
    exec(&d, &set(0x6c, "active")).await;

    // A profile in only one DB, and a head in only one.
    exec(
        &d,
        "INSERT INTO v2_profiles (id, tenant_id, fleet_id, name, current_version, status,
           created_at, updated_at)
         SELECT x'd3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3', tenant_id, fleet_id, 'p3', 0, 'active',
           't', 't' FROM v2_profiles WHERE name = 'p1'",
    )
    .await;
    assert_refused_cleanly(&d, &txn, "hold different profiles").await;
    exec(&d, "DELETE FROM v2_profiles WHERE name = 'p3'").await;
    exec(
        &d,
        "UPDATE v2_profiles SET current_version = 0 WHERE name = 'p2'",
    )
    .await;
    assert_refused_cleanly(&d, &txn, "has a head in only one").await;
    exec(
        &d,
        "UPDATE v2_profiles SET current_version = 1 WHERE name = 'p2'",
    )
    .await;

    // A ledgered commit the restore keeps is fine; one it rolls back refuses
    // (D-1 would mark it superseded; that column does not exist yet).
    exec(&d, &ledger(0xa1, [1, 0xbb])).await;
    ok(prepare(&d, None, &txn));
    ok(cli(&d, &["restore", "abort"]));
    exec(&d, &ledger(0xa3, [3, 0xbb])).await;
    assert_refused_cleanly(&d, &txn, "ledgered upload or commit result").await;
    exec(
        &d,
        "DELETE FROM v2_idempotency WHERE idempotency_key = x'a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3'",
    )
    .await;

    // With every refusal undone, the same restore goes through.
    ok(prepare(&d, None, &txn));
    ok(cli(&d, &["restore", "commit"]));
    assert_restored(&d, &txn, true).await;
    let _ = std::fs::remove_dir_all(&d.base);
}
