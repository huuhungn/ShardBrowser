//! Restore-epoch filesystem harness (plan 12.4 L2246-L2267, G2-52..G2-60;
//! ADR 0002 D-1). These drive the real binary: `restore export-heads`,
//! `prepare`, `commit`, `abort` and `status`, and the server's startup
//! classification. A debug build exits at the write point named by
//! `SHARDX_TEST_CRASH_AT`, leaving the files as a killed process would; each
//! crash point must then classify as exactly one row of the plan's table and
//! resume, or abort, to a consistent state. Supported filesystem: local NTFS
//! (owner decision 2026-10-29); evidence is process exit, not power loss.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::Duration;

use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
use serde_json::{json, Value};
use shardx_team_server::restore_manifest::{self as rm, MANIFEST_FILE};
use shared::authz_record::{
    build_record, ApprovalScopeKind, AuthorizationRecord, Capability, CapabilityScopeKind,
    CommonFields, DeviceApprovalV2, GrantSubject, Payload, RootGrantVariant,
    TenantCapabilityGrantV2, TenantRootKeyGrantV2, DOMAIN_DEVICE_APPROVAL,
    DOMAIN_TENANT_CAPABILITY_GRANT, DOMAIN_TENANT_ROOT_KEY_GRANT,
};
use shared::canonical::{self as c, sha256};
use shared::envelope::{build_dek_slot, IntentIds, IntentNumbers, SlotIds};
use shared::envelope_v2::{build_intent_v2, seal, MAX_OBJECT_SIZE, MIN_FRAME_PLAINTEXT_SIZE};
use shared::grants::derive_keypair;
use shared::keys::{hpke_key_id, signing_key_id};
use shared::mutation::{
    root_custodian_grant_set_hash, EmbeddedSelfGrant, IdempotentMutationRequestV2,
    IdempotentStoredResponseV2, OperationKind, RootGenerationMode, RootGenerationTarget,
    RootGrantRef, TenantRootGenerationActivateV2, TenantRootGenerationCreateV2,
    TenantRootGrantAckV2,
};
use shared::profile_lease::{
    CreateUploadV2, LeaseOrigin, LeaseRef, ProfileCheckoutV2, ProfileLeaseV2,
    ProfilePublishCreateV2, ProfileRef, UploadCreatedV2, RECORD_TYPE_UPLOAD_CREATED,
};
use shared::restore_epoch::{
    build_signed_transition, mapping_root, RestoreEpochInclusionProofV2, RestoreEpochLeafV2,
    RestoreEpochTransitionV2, RestoreReason,
};
use shared::session_binding::{self as sb, DeviceSessionBindingV2};
use shared::signing::Ed25519SigningKey;
use shared::snapshot_v2::{
    CommitReceiptBindingV2, CommitRequestV2, FinalizeUploadV2, SignedSnapshotManifestV2,
    SnapshotManifestV2,
};
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;
use zeroize::Zeroizing;

const RECORD: &str = "identity-record-v2.bin";
const TENANT: [u8; 16] = [0x41; 16];
const ACCOUNT: [u8; 16] = [0x51; 16];
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

/// `identity init`; returns the server instance ID.
fn initialised(d: &Dirs) -> [u8; 16] {
    let o = ok(cli(d, &["identity", "init"]));
    unhex(&field(&o, "server_instance_id")).try_into().unwrap()
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

// ------------------------------------------------------------- the world ---

const PASSWORD: &str = "correct horse battery staple";
const DAY_MS: u64 = 86_400_000;
const TRK: [u8; 32] = [0x7c; 32];
const APPROVAL_REPLAY: [u8; 16] = [0x71; 16];
const SELF_GRANT_REPLAY: [u8; 16] = [0x81; 16];
/// The FKEK itself: the server only ever sees its key ID, `FKEK`.
const FKEK_SECRET: [u8; 32] = [0x3e; 32];
const DEK: [u8; 32] = [0x2d; 32];
const PLAINTEXT_LEN: usize = 4096;

struct Device {
    id: [u8; 16],
    sk: Ed25519SigningKey,
    hpke_sk: Zeroizing<Vec<u8>>,
    hpke_pk: Vec<u8>,
    signing_key_id: [u8; 32],
    hpke_key_id: [u8; 32],
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn code(body: &[u8]) -> Value {
    serde_json::from_slice(body).unwrap_or(Value::Null)
}

/// The server on `port`, once it answers.
async fn up(d: &Dirs, port: u16) -> Server {
    let s = spawn(d, port);
    ready(&http(), port).await;
    s
}

/// A CBOR POST of `body` to `path`.
async fn call(port: u16, path: &str, bearer: &str, body: &[u8]) -> (u16, Vec<u8>) {
    let r = http()
        .post(format!("http://127.0.0.1:{port}{path}"))
        .header("content-type", "application/cbor")
        .body(body.to_vec())
        .bearer_auth(bearer)
        .send()
        .await
        .unwrap();
    (r.status().as_u16(), r.bytes().await.unwrap().to_vec())
}

async fn created(port: u16, path: &str, bearer: &str, body: &[u8]) -> Vec<u8> {
    let (status, out) = call(port, path, bearer, body).await;
    assert!(
        (200..300).contains(&status),
        "{path}: {status} {}",
        String::from_utf8_lossy(&out)
    );
    out
}

async fn post_json(port: u16, path: &str, bearer: Option<&str>, body: Value) -> Value {
    let mut req = http()
        .post(format!("http://127.0.0.1:{port}{path}"))
        .json(&body);
    if let Some(t) = bearer {
        req = req.bearer_auth(t);
    }
    let r = req.send().await.unwrap();
    assert_eq!(r.status().as_u16(), 201, "{path}");
    r.json().await.unwrap()
}

/// A device of the owner, stored the way enrollment stores it.
async fn device(d: &Dirs, seed: u8, status: &str) -> Device {
    let sk = Ed25519SigningKey::from_bytes(&[seed; 32]);
    let spk = sk.verifying_key().to_bytes();
    let (hpke_sk, hpk) = derive_keypair(&[seed.wrapping_add(1); 32]);
    let p = pool(d).await;
    sqlx::query("INSERT INTO v2_devices VALUES (?, ?, ?, x'aa', ?, ?, 1, ?, ?, 1, ?, NULL, 't')")
        .bind([seed; 16].as_slice())
        .bind(TENANT.as_slice())
        .bind(ACCOUNT.as_slice())
        .bind(signing_key_id(&spk).as_slice())
        .bind(spk.as_slice())
        .bind(hpke_key_id(&hpk).as_slice())
        .bind(hpk.as_slice())
        .bind(status)
        .execute(&p)
        .await
        .unwrap();
    p.close().await;
    Device {
        id: [seed; 16],
        sk,
        hpke_sk,
        signing_key_id: signing_key_id(&spk),
        hpke_key_id: hpke_key_id(&hpk),
        hpke_pk: hpk,
    }
}

/// Login, challenge and proof; returns the access token.
async fn session(port: u16, dev: &Device) -> String {
    let ticket = post_json(
        port,
        "/v2/auth/login",
        None,
        json!({ "tenant": "t", "username": "owner", "password": PASSWORD }),
    )
    .await;
    let ticket = ticket["ticket"].as_str();
    let ch = post_json(
        port,
        "/v2/auth/device-session-challenges",
        ticket,
        json!({ "device_id": hex(&dev.id) }),
    )
    .await;
    let binding = unhex(ch["binding"].as_str().unwrap());
    DeviceSessionBindingV2::parse(&binding).unwrap();
    let secret = sb::open_pop_secret(
        &dev.hpke_sk,
        &binding,
        &unhex(ch["encapsulated_key"].as_str().unwrap()),
        &unhex(ch["ciphertext"].as_str().unwrap()),
    )
    .unwrap();
    let s = post_json(
        port,
        "/v2/auth/device-session-proofs",
        ticket,
        json!({
            "challenge_id": ch["challenge_id"],
            "secret": hex(&*secret),
            "signature": hex(&sb::sign_pop(&dev.sk, &binding, &secret)),
        }),
    )
    .await;
    s["access_token"].as_str().unwrap().to_string()
}

fn common(replay: [u8; 16], instance: [u8; 16]) -> CommonFields {
    let start = now_ms() - 60_000;
    CommonFields {
        replay_id: replay,
        tenant_id: TENANT,
        issued_at_ms: start,
        not_before_ms: start,
        not_after_ms: start + 30 * DAY_MS,
        server_instance_id: instance,
        restore_epoch: 0,
    }
}

/// The exact outer request of `kind` under idempotency key `key` at `E = 0`.
fn outer(kind: OperationKind, key: u8, payload: Vec<u8>, instance: [u8; 16]) -> Vec<u8> {
    outer_nonce(kind, key, payload, instance, [0x92; 16])
}

fn outer_nonce(
    kind: OperationKind,
    key: u8,
    payload: Vec<u8>,
    instance: [u8; 16],
    nonce: [u8; 16],
) -> Vec<u8> {
    IdempotentMutationRequestV2 {
        operation_kind: kind,
        idempotency_key: [key; 16],
        canonical_payload_bytes: payload,
        client_request_nonce: nonce,
        server_instance_id: instance,
        restore_epoch: 0,
    }
    .encode()
}

/// The tenant, its owner and the unused bootstrap guard, as `tenant
/// create` leaves them.
async fn tenant(d: &Dirs, instance: [u8; 16]) {
    let hash = argon2::Argon2::default()
        .hash_password(PASSWORD.as_bytes(), &SaltString::generate(&mut OsRng))
        .unwrap()
        .to_string();
    let p = pool(d).await;
    for (sql, binds) in [
        (
            "INSERT INTO v2_tenants VALUES (?, 't', 'active', NULL, 't')",
            vec![TENANT.to_vec()],
        ),
        (
            "INSERT INTO v2_bootstrap_guards VALUES (?, ?, 'unused', NULL, 't')",
            vec![instance.to_vec(), TENANT.to_vec()],
        ),
        (
            "INSERT INTO v2_tenant_memberships VALUES (?, ?, 'owner', 'active', 't')",
            vec![TENANT.to_vec(), ACCOUNT.to_vec()],
        ),
    ] {
        let mut q = sqlx::query(sql);
        for b in binds {
            q = q.bind(b);
        }
        q.execute(&p).await.unwrap();
        if sql.contains("v2_bootstrap_guards") {
            sqlx::query(
                "INSERT INTO v2_accounts VALUES (?, ?, 'owner', ?, NULL, 0, 'active', 't')",
            )
            .bind(ACCOUNT.as_slice())
            .bind(TENANT.as_slice())
            .bind(&hash)
            .execute(&p)
            .await
            .unwrap();
        }
    }
    p.close().await;
}

/// The fleet on its ACTIVE generation 0 under the ACTIVE root.
async fn fleet(d: &Dirs, instance: [u8; 16]) {
    let p = pool(d).await;
    for (sql, binds) in [
        (
            "INSERT INTO v2_fleets (id, tenant_id, name, status, created_at)
             VALUES (?, ?, 'fleet', 'active', 't')",
            vec![FLEET.to_vec(), TENANT.to_vec()],
        ),
        (
            "INSERT INTO v2_fleet_key_generations
                 (server_instance_id, tenant_id, fleet_id, generation, fkek_key_id,
                  root_generation, state, created_at, activated_at)
             VALUES (?, ?, ?, 0, ?, 0, 'ACTIVE', 't', 't')",
            vec![
                instance.to_vec(),
                TENANT.to_vec(),
                FLEET.to_vec(),
                FKEK.to_vec(),
            ],
        ),
    ] {
        let mut q = sqlx::query(sql);
        for b in binds {
            q = q.bind(b);
        }
        q.execute(&p).await.unwrap();
    }
    p.close().await;
}

/// The offline D1 confirmation of the pending first device, typed the way
/// the operator types it.
fn confirm(d: &Dirs, dev: &Device) {
    let mut c = bin(d);
    let mut child = c
        .args([
            "tenant",
            "confirm-first-device",
            "--tenant",
            "t",
            "--device",
            &hex(&dev.id),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let input = format!("{}\n{}\n", hex(&dev.signing_key_id), hex(&dev.hpke_key_id));
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    ok(child.wait_with_output().unwrap());
}

/// D1's approval, the root bootstrap, its acknowledgement and activation:
/// the confirmed device becomes the tenant's ACTIVE root custodian.
async fn bootstrap_root(port: u16, dev: &Device, access: &str, instance: [u8; 16]) {
    let approval = DeviceApprovalV2 {
        common: common(APPROVAL_REPLAY, instance),
        subject_account_id: ACCOUNT,
        subject_device_id: dev.id,
        subject_signing_key_id: dev.signing_key_id,
        subject_hpke_key_id: dev.hpke_key_id,
        approval_scope_kind: ApprovalScopeKind::Tenant,
        approval_scope_id: TENANT,
    };
    let rec = build_record(&dev.sk, DOMAIN_DEVICE_APPROVAL, &approval.encode());
    let path = format!("/v2/devices/{}/approve", hex(&dev.id));
    created(port, &path, access, &rec).await;

    let mut g = TenantRootKeyGrantV2 {
        common: common(SELF_GRANT_REPLAY, instance),
        variant: RootGrantVariant::FirstRootSelfGrant,
        root_key_id: shared::keys::root_key_id(&TRK),
        root_generation: 0,
        subject_account_id: ACCOUNT,
        subject_device_id: dev.id,
        subject_signing_key_id: dev.signing_key_id,
        recipient_hpke_key_id: dev.hpke_key_id,
        subject_device_approval_replay_id: APPROVAL_REPLAY,
        hpke_encapped_key_bytes: [0; 32],
        hpke_wrapped_trk_bytes: [0; 48],
    };
    let sealed = shared::grants::seal_trk(&dev.hpke_pk, &g.scope(), &TRK).unwrap();
    g.hpke_encapped_key_bytes = sealed.encapped_key_bytes.try_into().unwrap();
    g.hpke_wrapped_trk_bytes = sealed.ciphertext_bytes.try_into().unwrap();
    let container = build_record(&dev.sk, DOMAIN_TENANT_ROOT_KEY_GRANT, &g.encode());
    let record = AuthorizationRecord::parse(&container)
        .unwrap()
        .verify_signature(dev.sk.verifying_key().as_bytes())
        .unwrap();
    let hash = *record.record().signed_container_hash();
    let target = RootGenerationTarget {
        tenant_id: TENANT,
        server_instance_id: instance,
        restore_epoch: 0,
        root_key_id: shared::keys::root_key_id(&TRK),
        root_generation: 0,
        required_custodian_grant_count: 1,
        required_custodian_grant_set_hash: root_custodian_grant_set_hash(&[hash]).unwrap(),
        recovery_bundle_sha256: [0x5a; 32],
    };
    let create = TenantRootGenerationCreateV2 {
        target: target.clone(),
        mode: RootGenerationMode::Bootstrap(EmbeddedSelfGrant {
            container_bytes: container.clone(),
            signed_container_hash: hash,
        }),
    };
    let root = format!("/v2/tenants/{}/root-key-generations", hex(&TENANT));
    let request = outer(
        OperationKind::RootGenerationCreate,
        0x91,
        create.encode(),
        instance,
    );
    created(port, &root, access, &request).await;

    let Payload::TenantRootKeyGrant(g) = record.payload() else {
        panic!("a root grant")
    };
    let grant = RootGrantRef {
        tenant_id: g.common.tenant_id,
        server_instance_id: g.common.server_instance_id,
        restore_epoch: g.common.restore_epoch,
        root_generation: g.root_generation,
        root_key_id: g.root_key_id,
        replay_id: g.common.replay_id,
        signed_container_hash: hash,
        exact_signed_container_bytes_sha256: *record.record().exact_signed_container_bytes_sha256(),
    };
    let ack = TenantRootGrantAckV2 { grant }.encode();
    created(
        port,
        &format!("{root}/0/grants/{}/ack", hex(&SELF_GRANT_REPLAY)),
        access,
        &outer(OperationKind::RootGrantAck, 0xb1, ack, instance),
    )
    .await;
    let activate = TenantRootGenerationActivateV2 {
        target,
        previous: None,
    }
    .encode();
    created(
        port,
        &format!("{root}/0/activate"),
        access,
        &outer(
            OperationKind::RootGenerationActivate,
            0xb3,
            activate,
            instance,
        ),
    )
    .await;
}

/// A second device of the owner under a copy of `from`'s tenant approval.
async fn peer(d: &Dirs, from: &Device, seed: u8) -> Device {
    let to = device(d, seed, "active").await;
    let p = pool(d).await;
    sqlx::query(
        "INSERT INTO v2_device_approvals (
           tenant_id, replay_id, payload_domain, payload_version, subject_account_id,
           subject_device_id, subject_signing_key_id, subject_hpke_key_id,
           approval_scope_kind, approval_scope_id, approved_use, issued_at_ms,
           not_before_ms, not_after_ms, server_instance_id, restore_epoch,
           canonical_payload_bytes, payload_sha256, signature_suite_id, signature_version,
           signature_bytes, issuer_signing_key_id, signed_container_hash,
           exact_signed_container_bytes, exact_signed_container_bytes_sha256, created_at)
         SELECT tenant_id, ?, payload_domain, payload_version, subject_account_id,
           ?, ?, ?, approval_scope_kind, approval_scope_id, approved_use, issued_at_ms,
           not_before_ms, not_after_ms, server_instance_id, restore_epoch,
           canonical_payload_bytes, payload_sha256, signature_suite_id, signature_version,
           signature_bytes, issuer_signing_key_id, signed_container_hash,
           exact_signed_container_bytes, exact_signed_container_bytes_sha256, created_at
           FROM v2_device_approvals WHERE subject_device_id = ?",
    )
    .bind([seed; 16].as_slice())
    .bind(to.id.as_slice())
    .bind(to.signing_key_id.as_slice())
    .bind(to.hpke_key_id.as_slice())
    .bind(from.id.as_slice())
    .execute(&p)
    .await
    .unwrap();
    p.close().await;
    to
}

/// The custodian grants `subject` publish, checkout and commit.
async fn may_commit(
    port: u16,
    custodian: (&Device, &str),
    subject: &Device,
    replay: u8,
    instance: [u8; 16],
) {
    use CapabilityScopeKind as K;
    for (i, (capability, scope)) in [
        (Capability::ProfilePublish, (K::Tenant, TENANT)),
        (Capability::ProfileCheckout, (K::Fleet, FLEET)),
        (Capability::ProfileCommit, (K::Fleet, FLEET)),
    ]
    .into_iter()
    .enumerate()
    {
        let g = TenantCapabilityGrantV2 {
            common: common([replay + i as u8; 16], instance),
            subject: GrantSubject::Device {
                account_id: ACCOUNT,
                device_id: subject.id,
                signing_key_id: subject.signing_key_id,
                hpke_key_id: subject.hpke_key_id,
            },
            scope_kind: scope.0,
            scope_id: scope.1,
            capability,
        };
        let rec = build_record(&custodian.0.sk, DOMAIN_TENANT_CAPABILITY_GRANT, &g.encode());
        created(port, "/v2/capability-grants", custodian.1, &rec).await;
    }
}

fn pref(profile: [u8; 16]) -> ProfileRef {
    ProfileRef {
        tenant_id: TENANT,
        fleet_id: FLEET,
        profile_id: profile,
    }
}

fn publish_request(key: u8, profile: [u8; 16], instance: [u8; 16]) -> Vec<u8> {
    let payload = ProfilePublishCreateV2 {
        profile: pref(profile),
        label_ciphertext: vec![0x33; 24],
        requested_lease_ttl_seconds: 300,
        fkek_key_id: FKEK,
        key_generation: 0,
    };
    outer(
        OperationKind::ProfilePublishCreate,
        key,
        payload.encode(),
        instance,
    )
}

fn lease_of(origin: LeaseOrigin, body: &[u8]) -> LeaseRef {
    let stored = IdempotentStoredResponseV2::parse(body).unwrap();
    ProfileLeaseV2::parse(origin, &stored.canonical_response_payload_bytes)
        .unwrap()
        .lease
}

struct Snap {
    object: Vec<u8>,
    terms: CreateUploadV2,
    manifest: SnapshotManifestV2,
}

/// What a client seals and signs for one snapshot of `profile` under `lease`.
fn snap(
    profile: [u8; 16],
    lease: LeaseRef,
    signer: &Device,
    tag: u8,
    prev: Option<[u8; 32]>,
    instance: [u8; 16],
) -> Snap {
    let p = pref(profile);
    let snapshot_id = [tag; 16];
    let manifest_replay_id = [tag ^ 0xff; 16];
    let slot = build_dek_slot(
        &FKEK_SECRET,
        &DEK,
        &[tag; shared::keys::WRAP_NONCE_LEN],
        &SlotIds {
            tenant_id: &p.tenant_id,
            fleet_id: &p.fleet_id,
            profile_id: &p.profile_id,
            snapshot_id: &snapshot_id,
            fkek_key_id: &FKEK,
            envelope_context_nonce: &[tag; 16],
        },
        0,
    )
    .unwrap();
    let created_at_ms = now_ms();
    let intent = build_intent_v2(
        &IntentIds {
            snapshot_id,
            tenant_id: p.tenant_id,
            fleet_id: p.fleet_id,
            profile_id: p.profile_id,
            lease_id: lease.lease_id,
            manifest_replay_id,
            server_instance_id: instance,
            fkek_key_id: FKEK,
            intended_signer_signing_key_id: signer.signing_key_id,
        },
        &IntentNumbers {
            target_version: lease.base_version + 1,
            base_version: lease.base_version,
            fencing_token: lease.fencing_token,
            key_generation: 0,
            restore_epoch: 0,
            frame_plaintext_size: MIN_FRAME_PLAINTEXT_SIZE,
            max_plaintext_size: MAX_OBJECT_SIZE,
            max_ciphertext_size: MAX_OBJECT_SIZE,
            created_at_ms,
        },
        &[tag; 20],
        prev.as_ref(),
        &slot,
    )
    .unwrap();
    let plaintext = vec![tag; PLAINTEXT_LEN];
    let mut object = Vec::new();
    let d = seal(
        &mut std::io::Cursor::new(plaintext),
        &mut object,
        &DEK,
        &intent,
        &slot,
    )
    .unwrap();
    let manifest = SnapshotManifestV2 {
        snapshot_id,
        tenant_id: p.tenant_id,
        fleet_id: p.fleet_id,
        profile_id: p.profile_id,
        lease_id: lease.lease_id,
        target_version: lease.base_version + 1,
        base_version: lease.base_version,
        fencing_token: lease.fencing_token,
        key_generation: 0,
        fkek_key_id: FKEK,
        preamble_sha256: d.preamble_sha256,
        intent_hash: intent.intent_hash,
        dek_slot_sha256: slot.dek_slot_sha256,
        ciphertext_sha256: d.ciphertext_sha256,
        ciphertext_size: d.ciphertext_size,
        previous_signed_head_hash: prev,
        signer_signing_key_id: signer.signing_key_id,
        server_instance_id: instance,
        restore_epoch: 0,
        manifest_replay_id,
        created_at_ms,
    };
    let terms = CreateUploadV2 {
        profile: p,
        snapshot_id,
        manifest_replay_id,
        lease,
        intent_hash: intent.intent_hash,
        preamble_sha256: d.preamble_sha256,
        dek_slot_sha256: slot.dek_slot_sha256,
        fkek_key_id: FKEK,
        key_generation: 0,
        expected_ciphertext_size: d.ciphertext_size,
        expected_ciphertext_sha256: d.ciphertext_sha256,
    };
    Snap {
        object,
        terms,
        manifest,
    }
}

fn uploads_path(profile: [u8; 16]) -> String {
    format!("/v2/profiles/{}/uploads", hex(&profile))
}

fn upload_path(upload: &[u8; 16], action: &str) -> String {
    format!("/v2/uploads/{}/{action}", hex(upload))
}

/// One snapshot through the real routes: create-upload under `key`, the
/// object in one chunk, finalize under `key + 1`, then the commit.
struct Committed {
    upload: [u8; 16],
    create: Vec<u8>,
    finalize: Vec<u8>,
    commit: CommitRequestV2,
    receipt: Vec<u8>,
}

async fn commit_through_routes(
    port: u16,
    access: &str,
    key: u8,
    s: &Snap,
    signer: &Device,
    instance: [u8; 16],
) -> Committed {
    let create = outer(OperationKind::CreateUpload, key, s.terms.encode(), instance);
    let body = created(
        port,
        &uploads_path(s.terms.profile.profile_id),
        access,
        &create,
    )
    .await;
    let stored = IdempotentStoredResponseV2::parse(&body).unwrap();
    assert_eq!(stored.response_record_type, RECORD_TYPE_UPLOAD_CREATED);
    let upload = UploadCreatedV2::parse(&stored.canonical_response_payload_bytes)
        .unwrap()
        .upload_id;
    let r = http()
        .patch(format!(
            "http://127.0.0.1:{port}/v2/uploads/{}",
            hex(&upload)
        ))
        .header("upload-offset", "0")
        .header("upload-chunk-sha256", hex(&sha256(&s.object)))
        .body(s.object.clone())
        .bearer_auth(access)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let signed = SignedSnapshotManifestV2::sign(&signer.sk, &s.manifest).unwrap();
    let commit = CommitRequestV2::build(&signed, upload, [key ^ 0x80; 16], [key ^ 0x40; 16]);
    let finalize = outer(
        OperationKind::FinalizeUpload,
        key + 1,
        FinalizeUploadV2::new(commit.clone()).encode(),
        instance,
    );
    created(port, &upload_path(&upload, "finalize"), access, &finalize).await;
    let receipt = created(
        port,
        &upload_path(&upload, "commit"),
        access,
        commit.exact_bytes(),
    )
    .await;
    CommitReceiptBindingV2::parse(&receipt)
        .unwrap()
        .check_binds(&commit)
        .unwrap();
    Committed {
        upload,
        create,
        finalize,
        commit,
        receipt,
    }
}

fn filing(signed: &[u8], proofs: &[Vec<u8>]) -> Vec<u8> {
    let proofs = c::Value::Array(proofs.iter().map(|p| c::b(p)).collect());
    c::encode(&c::m(vec![
        ("domain", c::t("shardx.restore-epoch.transition-filing.v2")),
        ("version", c::u(2)),
        ("exact_signed_transition_bytes", c::b(signed)),
        ("canonical_inclusion_proofs", proofs),
    ]))
}

/// The custodian's `E -> E+1` transition over `leaves` with one proof per
/// leaf, filed through the route (plan 8.1 L1131): its status.
async fn file_transition(
    port: u16,
    w: &World,
    access: &str,
    leaves: &[RestoreEpochLeafV2],
    tag: u8,
) -> u16 {
    let t = RestoreEpochTransitionV2 {
        transition_replay_id: [tag; 16],
        server_instance_id: w.instance,
        tenant_id: TENANT,
        previous_epoch: 0,
        new_epoch: 1,
        mapping_count: leaves.len() as u64,
        profile_head_mapping_root: mapping_root(&TENANT, leaves).unwrap(),
        reason_code: RestoreReason::VerifiedBackupRollback,
        approver_account_id: ACCOUNT,
        approver_device_id: w.dev.id,
        approver_signing_key_id: w.dev.signing_key_id,
        issued_at_ms: now_ms(),
        nonce: [tag ^ 0xff; 16],
    };
    let signed = build_signed_transition(&w.dev.sk, &t);
    let proofs: Vec<Vec<u8>> = (0..leaves.len())
        .map(|i| {
            RestoreEpochInclusionProofV2::build(&t, leaves, i)
                .unwrap()
                .encode()
        })
        .collect();
    let path = "/v2/recovery/restore-epoch-transitions";
    call(port, path, access, &filing(&signed, &proofs)).await.0
}

/// A live DB at `E = 0` built through the real routes: P1 and P2 published
/// and committed at v1 (P2 by a second device), the backup taken, then P1
/// committed at v2. The custodian's transition over both leaves is filed
/// unless `file` is false. The world is kept, so [`reset`] can bring it
/// back at the same paths.
struct World {
    instance: [u8; 16],
    txn: String,
    leaves: Vec<RestoreEpochLeafV2>,
    dev: Device,
    publish_p1: Vec<u8>,
    publish_p1_response: Vec<u8>,
    kept: Committed,
    rolled_back: Committed,
}

async fn world(d: &Dirs, port: u16, file: bool) -> World {
    let instance = initialised(d);
    tenant(d, instance).await;
    let dev = device(d, 0x6c, "pending").await;
    confirm(d, &dev);
    let server = up(d, port).await;
    let access = session(port, &dev).await;
    bootstrap_root(port, &dev, &access, instance).await;
    fleet(d, instance).await;
    let other = peer(d, &dev, SIGNER2).await;
    let other_access = session(port, &other).await;
    may_commit(port, (&dev, &access), &dev, 0xa1, instance).await;
    may_commit(port, (&dev, &access), &other, 0xa4, instance).await;

    let publish_p1 = publish_request(0x01, P1, instance);
    let fleet = format!("/v2/fleets/{}/profiles", hex(&FLEET));
    let publish_p1_response = created(port, &fleet, &access, &publish_p1).await;
    let p2 = created(
        port,
        &fleet,
        &other_access,
        &publish_request(0x02, P2, instance),
    )
    .await;
    let s1 = snap(
        P1,
        lease_of(LeaseOrigin::PublishCreate, &publish_p1_response),
        &dev,
        0x11,
        None,
        instance,
    );
    let kept = commit_through_routes(port, &access, 0x03, &s1, &dev, instance).await;
    let s2 = snap(
        P2,
        lease_of(LeaseOrigin::PublishCreate, &p2),
        &other,
        0x12,
        None,
        instance,
    );
    let p2_commit = commit_through_routes(port, &other_access, 0x06, &s2, &other, instance).await;
    drop(server);
    std::fs::copy(d.db(), &d.backup).unwrap();

    let server = up(d, port).await;
    let head1 = kept.commit.manifest().head_hash();
    let checkout = ProfileCheckoutV2 {
        profile: pref(P1),
        observed_version: 1,
        observed_signed_head_hash: Some(head1),
        requested_lease_ttl_seconds: 300,
    };
    let path = format!("/v2/profiles/{}/checkout", hex(&P1));
    let body = created(
        port,
        &path,
        &access,
        &outer(
            OperationKind::ProfileCheckout,
            0x09,
            checkout.encode(),
            instance,
        ),
    )
    .await;
    let s3 = snap(
        P1,
        lease_of(LeaseOrigin::Checkout, &body),
        &dev,
        0x13,
        Some(head1),
        instance,
    );
    let rolled_back = commit_through_routes(port, &access, 0x0a, &s3, &dev, instance).await;
    drop(server);

    let (txn, leaves) = exported(d);
    let head = |c: &Committed| c.commit.manifest().head_hash();
    assert_eq!(
        leaves,
        vec![
            RestoreEpochLeafV2 {
                tenant_id: TENANT,
                profile_id: P1,
                previous_signed_head_hash: head(&rolled_back),
                new_signed_head_hash: head1,
            },
            RestoreEpochLeafV2 {
                tenant_id: TENANT,
                profile_id: P2,
                previous_signed_head_hash: head(&p2_commit),
                new_signed_head_hash: head(&p2_commit),
            },
        ],
        "a leaf for every profile with a head in both DBs, live head first"
    );
    let w = World {
        instance,
        txn,
        leaves,
        dev,
        publish_p1,
        publish_p1_response,
        kept,
        rolled_back,
    };
    if file {
        let _server = up(d, port).await;
        let access = session(port, &w.dev).await;
        assert_eq!(
            file_transition(port, &w, &access, &w.leaves, 0x31).await,
            201
        );
    }
    save_template(d);
    w
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let target = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_tree(&e.path(), &target);
        } else {
            std::fs::copy(e.path(), target).unwrap();
        }
    }
}

fn template(d: &Dirs) -> PathBuf {
    d.base.with_extension("template")
}

fn save_template(d: &Dirs) {
    let _ = std::fs::remove_dir_all(template(d));
    copy_tree(&d.base, &template(d));
}

/// The world exactly as [`world`] left it, at the same paths (the DB
/// stores absolute object paths).
fn reset(d: &Dirs) {
    std::fs::remove_dir_all(&d.base).unwrap();
    copy_tree(&template(d), &d.base);
}

fn done(d: &Dirs) {
    let _ = std::fs::remove_dir_all(&d.base);
    let _ = std::fs::remove_dir_all(template(d));
}

/// The object a kept snapshot names in the live store.
fn object_of(d: &Dirs, profile: [u8; 16], snapshot: u8) -> PathBuf {
    d.data
        .join("blobs")
        .join(hex(&TENANT))
        .join("objects")
        .join(hex(&profile))
        .join(format!("{}.bin", hex(&[snapshot; 16])))
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

/// The state every completed restore of [`world`] must reach: record and
/// mirror at `E+1`, P1 back at v1, the bundle retired, the live DB archived,
/// and exactly the three ledger rows of P1's v2 marked superseded (D-1).
async fn assert_restored(d: &Dirs, txn: &str) {
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
    // One from the route that filed the transition, one from step 5.
    assert_eq!(
        scalar(
            d,
            "SELECT count(*) FROM v2_audit_events WHERE action = 'tenant.restore_epoch_transition'"
        )
        .await,
        2
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
    // `abort --orphans` keeps the archive unless told --delete-archives.
    assert!(d.data.join(format!("pre-restore-{txn}.db")).exists());
    assert_eq!(superseded(d).await, "COMMIT,CREATE_UPLOAD,FINALIZE_UPLOAD");
    assert_eq!(
        scalar(d, "SELECT count(*) FROM v2_idempotency").await,
        scalar(
            d,
            "SELECT count(*) FROM v2_idempotency WHERE superseded_by_restore_epoch IS NULL"
        )
        .await
            + 3,
        "every ledger row is kept"
    );
}

/// The kinds of the ledger rows superseded by epoch 1, in order.
async fn superseded(d: &Dirs) -> String {
    let p = pool(d).await;
    let kinds: Vec<String> = sqlx::query_scalar(
        "SELECT operation_kind FROM v2_idempotency WHERE superseded_by_restore_epoch = 1
          ORDER BY operation_kind",
    )
    .fetch_all(&p)
    .await
    .unwrap();
    p.close().await;
    kinds.join(",")
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
    let d = dirs("sweep");
    let w = world(&d, 28421, true).await;
    let txn = w.txn.as_str();
    for (i, (point, class_, row)) in prepare_points.iter().chain(&commit_points).enumerate() {
        if i > 0 {
            reset(&d);
        }
        // An empty -wal sidecar, so step 4 (ii) has a sidecar to move.
        std::fs::write(d.data.join("shardx.db-wal"), b"").unwrap();
        let is_prepare = point.starts_with("prepare.");
        if is_prepare {
            let o = prepare(&d, Some(point), txn);
            assert_eq!(o.status.code(), Some(86), "{point}: {}", text(&o));
        } else {
            ok(prepare(&d, None, txn));
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
                refused(prepare(&d, None, txn), "leftovers of an earlier restore");
                ok(cli(&d, &["restore", "abort", "--orphans"]));
                ok(prepare(&d, None, txn));
                ok(cli(&d, &["restore", "commit"]));
            }
            "K3" => {
                ok(cli(&d, &["restore", "abort", "--orphans"]));
            }
            _ => {
                ok(cli(&d, &["restore", "commit"]));
            }
        }
        assert_restored(&d, txn).await;
    }
    // The archive, the only copy of the pre-restore live DB, goes only on
    // request.
    let archive = d.data.join(format!("pre-restore-{txn}.db"));
    ok(cli(&d, &["restore", "abort", "--orphans"]));
    assert!(archive.exists());
    ok(cli(
        &d,
        &["restore", "abort", "--orphans", "--delete-archives"],
    ));
    assert!(!archive.exists());
    assert_class(&d, "K3", "L2259");
    done(&d);
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
    assert_server_read_only_with(d, port, "EPOCH_RECONCILIATION_REQUIRED").await;
}

async fn assert_server_read_only_with(d: &Dirs, port: u16, want: &str) {
    let before = file_sha(&d.db());
    {
        let _s = spawn(d, port);
        let (status, code, read, v1) = probe(port).await;
        assert_eq!((status, read), (423, 423));
        assert_eq!(code, want);
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

/// The server exits without creating a DB at the DB path.
async fn assert_refuses_to_start(d: &Dirs, port: u16) {
    let mut s = spawn(d, port);
    let mut exited = None;
    for _ in 0..100 {
        if let Some(status) = s.0.try_wait().unwrap() {
            exited = Some(status);
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(exited.is_some_and(|e| !e.success()), "the server started");
    assert!(!d.db().exists(), "the server created a DB");
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
    // Without the manifest (K4) or the record (K1) the files of the restore
    // are still there: the server refuses to start rather than create a DB.
    let manifest = std::fs::read(d2.identity.join(MANIFEST_FILE)).unwrap();
    let record = std::fs::read(d2.identity.join(RECORD)).unwrap();
    std::fs::remove_file(d2.identity.join(MANIFEST_FILE)).unwrap();
    assert_class(&d2, "K4", "L2263");
    assert_refuses_to_start(&d2, 28414).await;
    std::fs::remove_file(d2.identity.join(RECORD)).unwrap();
    assert_class(&d2, "K1", "L2258");
    assert_refuses_to_start(&d2, 28414).await;
    std::fs::write(d2.identity.join(RECORD), record).unwrap();
    std::fs::write(d2.identity.join(MANIFEST_FILE), manifest).unwrap();
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
    let w = world(&d, 28422, true).await;
    let txn = w.txn.as_str();
    ok(prepare(&d, None, txn));
    assert_eq!(
        run(&d, Some("commit.5.tx"), &["restore", "commit"])
            .status
            .code(),
        Some(86)
    );
    assert!(d.data.join("shardx.db-journal").exists());
    assert_class(&d, "K9", "L2262");
    ok(cli(&d, &["restore", "commit"]));
    assert_restored(&d, txn).await;
    reset(&d);

    // An installed DB that is not the candidate: K12, record kept at E+1.
    let candidate = unhex(&field(&ok(prepare(&d, None, txn)), "candidate_db_sha256"));
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
    reset(&d);

    // A proof artifact missing after the install: coverage cannot be proven.
    ok(prepare(&d, None, txn));
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
    reset(&d);

    // After the step-5 commit (K10) the readback re-proves the coverage: a
    // head the leaves do not name stops the retirement.
    ok(prepare(&d, None, txn));
    let o = run(&d, Some("commit.5.committed"), &["restore", "commit"]);
    assert_eq!(o.status.code(), Some(86));
    exec(
        &d,
        "UPDATE v2_profiles SET current_version = 0 WHERE id = x'd2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2'",
    )
    .await;
    refused(
        cli(&d, &["restore", "commit"]),
        "do not cover exactly the installed heads",
    );
    assert_class(&d, "K10", "L2265");
    done(&d);
}

// ------------------------------------------------------------------ G2-58 ---

/// L2263: an external record ahead of the DB without exact recovery evidence
/// (missing or corrupt manifest, uncovered or unsigned leaves) fails closed
/// for operator recovery; nothing rebuilds or lowers the authority.
#[tokio::test]
async fn l2263_g2_58_an_authority_ahead_without_exact_evidence_fails_closed() {
    let d = dirs("l2263");
    let w = world(&d, 28423, true).await;
    let txn = w.txn.as_str();
    ok(prepare(&d, None, txn));
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
    assert_restored(&d, txn).await;
    done(&d);
}

/// D-1 and ADR 0002 L561 at prepare: every covered tenant needs exactly one
/// staged transition over the computed leaves, signed by a device that is
/// still an ACTIVE root custodian at `E`. A filing no restore can use cannot
/// be replaced, so it blocks every restore at `E` until the operator
/// withdraws it offline, with an audit, and never while one is prepared.
#[tokio::test]
async fn l2263_g2_58_only_a_live_custodian_transition_over_the_computed_leaves_prepares() {
    let d = dirs("l2263b");
    let w = world(&d, 28424, false).await;
    let txn = w.txn.as_str();
    refused(prepare(&d, None, txn), "do not cover exactly the tenants");
    assert_class(&d, "K3", "L2259");
    assert!(!d.identity.join(MANIFEST_FILE).exists());

    // A custodian files a transition over other leaves than the restore's;
    // the route cannot tell, and refuses the right one after it.
    let mut wrong = w.leaves.clone();
    wrong[0].new_signed_head_hash = [0x99; 32];
    {
        let _s = up(&d, 28424).await;
        let access = session(28424, &w.dev).await;
        assert_eq!(file_transition(28424, &w, &access, &wrong, 0x41).await, 201);
        assert_eq!(
            file_transition(28424, &w, &access, &w.leaves, 0x42).await,
            409
        );
    }
    assert_refused_cleanly(&d, txn, "does not sign the computed leaves").await;
    let tenant = hex(&TENANT);
    let withdraw = [
        "restore",
        "withdraw-transitions",
        "--tenant",
        tenant.as_str(),
    ];
    let audits =
        "SELECT count(*) FROM audit_log WHERE action = 'server.restore_withdraw_transitions'";
    ok(cli(&d, &withdraw));
    assert_eq!(scalar(&d, audits).await, 1);
    assert_eq!(
        scalar(
            &d,
            "SELECT count(*) FROM v2_restore_epoch_transition_proofs"
        )
        .await,
        0
    );
    refused(cli(&d, &withdraw), "has no staged transition at E");
    {
        let _s = up(&d, 28424).await;
        let access = session(28424, &w.dev).await;
        assert_eq!(
            file_transition(28424, &w, &access, &w.leaves, 0x43).await,
            201
        );
    }
    ok(prepare(&d, None, txn));
    // A prepared restore has bound its set.
    refused(cli(&d, &withdraw), "only for K3, not K7");
    ok(cli(&d, &["restore", "abort"]));
    assert_eq!(scalar(&d, audits).await, 1);

    // The custodian demoted after filing: prepare checks custody at E, not
    // only that the signer is a live device.
    exec(&d, "UPDATE v2_tenant_root_key_grants SET revoked_at = 't'").await;
    assert_refused_cleanly(&d, txn, "is not an ACTIVE root custodian at E").await;
    done(&d);
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
    let at_e = std::fs::read(d.identity.join(RECORD)).unwrap();
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

    // K2 (C-3, ADR 0002 L520): a record behind the mirror is the L2264
    // incident; the DB opens read-only, so v1 writes are frozen too.
    let record = std::fs::read(d.identity.join(RECORD)).unwrap();
    std::fs::write(d.identity.join(RECORD), &at_e).unwrap();
    assert_class(&d, "K2", "L2264");
    assert_server_read_only_with(&d, 28415, "EPOCH_AUTHORITY_BEHIND_DB").await;
    std::fs::write(d.identity.join(RECORD), record).unwrap();
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

/// D-1 restore scope, strict where D-1 drops (no `--drop-unreferenced`):
/// prepare refuses a merge it cannot prove, before anything is durable.
#[tokio::test]
async fn d1_prepare_refuses_every_merge_it_cannot_prove_and_leaves_nothing() {
    let d = dirs("refusals");
    let w = world(&d, 28425, true).await;
    let txn = w.txn.as_str();
    refused(prepare(&d, None, &"0".repeat(32)), "--txn must not be zero");

    // The backup's schema differs.
    on_backup(&d, "CREATE TABLE extra (a)").await;
    assert_refused_cleanly(&d, txn, "the backup's schema differs").await;
    on_backup(&d, "DROP TABLE extra").await;

    // A kept snapshot's object is not in the live store byte for byte.
    let object = object_of(&d, P2, 0x12);
    let body = std::fs::read(&object).unwrap();
    // Same size, other bytes: only the hash tells.
    std::fs::write(&object, vec![0xee; body.len()]).unwrap();
    assert_refused_cleanly(&d, txn, "is missing or differs").await;
    std::fs::write(&object, &body).unwrap();

    // A kept snapshot's signer is revoked in live.
    let set = |id: u8, status: &str| {
        format!(
            "UPDATE v2_devices SET status = '{status}' WHERE id = x'{}'",
            hex(&[id; 16])
        )
    };
    exec(&d, &set(SIGNER2, "revoked")).await;
    assert_refused_cleanly(&d, txn, "revoked or unknown in the live DB").await;
    exec(&d, &set(SIGNER2, "active")).await;

    // The transition's signer is no longer a live device.
    exec(&d, &set(0x6c, "revoked")).await;
    assert_refused_cleanly(&d, txn, "transition signer is not a live device").await;
    exec(&d, &set(0x6c, "active")).await;

    // A profile in only one DB, and a head in only one.
    exec(
        &d,
        "INSERT INTO v2_profiles (id, tenant_id, fleet_id, name, current_version, status,
           created_at, updated_at)
         SELECT x'd3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3', tenant_id, fleet_id, 'p3', 0, 'active',
           't', 't' FROM v2_profiles WHERE id = x'd2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2'",
    )
    .await;
    assert_refused_cleanly(&d, txn, "hold different profiles").await;
    exec(
        &d,
        "DELETE FROM v2_profiles WHERE id = x'd3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3'",
    )
    .await;
    exec(
        &d,
        "UPDATE v2_profiles SET current_version = 0 WHERE id = x'd2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2'",
    )
    .await;
    assert_refused_cleanly(&d, txn, "has a head in only one").await;
    exec(
        &d,
        "UPDATE v2_profiles SET current_version = 1 WHERE id = x'd2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2'",
    )
    .await;

    // With every refusal undone, the same restore goes through.
    ok(prepare(&d, None, txn));
    ok(cli(&d, &["restore", "commit"]));
    assert_restored(&d, txn).await;
    done(&d);
}

/// ADR 0002 L377-L389: after a restore that rolled P1's v2 back, the ledger
/// keeps every key. The superseded commit answers `BASE_VERSION_MISMATCH`
/// with the epoch, its upload's create and finalize `RESOURCE_NOT_FOUND`,
/// another request under a used key still `IDEMPOTENCY_MISMATCH` first, and
/// what the restore kept replays its stored bytes.
#[tokio::test]
async fn d1_replays_of_rolled_back_results_answer_as_superseded_and_kept_ones_replay() {
    let d = dirs("replays");
    let w = world(&d, 28426, true).await;
    ok(prepare(&d, None, &w.txn));
    ok(cli(&d, &["restore", "commit"]));
    assert_restored(&d, &w.txn).await;

    let port = 28426;
    let _s = up(&d, port).await;
    let access = session(port, &w.dev).await;
    let r = &w.rolled_back;
    let commit = upload_path(&r.upload, "commit");
    let (status, body) = call(port, &commit, &access, r.commit.exact_bytes()).await;
    assert_eq!(status, 409);
    let body = code(&body);
    assert_eq!(body["code"], "BASE_VERSION_MISMATCH");
    assert_eq!(body["superseded_by_restore_epoch"], 1);
    let other = CommitRequestV2::build(
        r.commit.manifest(),
        r.upload,
        *r.commit.idempotency_key(),
        [0x5e; 16],
    );
    let (status, body) = call(port, &commit, &access, other.exact_bytes()).await;
    assert_eq!(
        (status, code(&body)["code"].clone()),
        (409, json!("IDEMPOTENCY_MISMATCH"))
    );

    for (path, request) in [
        (uploads_path(P1), &r.create),
        (upload_path(&r.upload, "finalize"), &r.finalize),
    ] {
        let (status, body) = call(port, &path, &access, request).await;
        assert_eq!(
            (status, code(&body)["code"].clone()),
            (404, json!("RESOURCE_NOT_FOUND")),
            "{path}"
        );
    }
    let mut other = IdempotentMutationRequestV2::parse(&r.create).unwrap();
    other.client_request_nonce = [0x5f; 16];
    let (status, body) = call(port, &uploads_path(P1), &access, &other.encode()).await;
    assert_eq!(
        (status, code(&body)["code"].clone()),
        (409, json!("IDEMPOTENCY_MISMATCH"))
    );

    // Kept results are never superseded: the exact stored bytes.
    let k = &w.kept;
    assert_eq!(
        call(
            port,
            &upload_path(&k.upload, "commit"),
            &access,
            k.commit.exact_bytes()
        )
        .await,
        (201, k.receipt.clone())
    );
    let fleet = format!("/v2/fleets/{}/profiles", hex(&FLEET));
    assert_eq!(
        call(port, &fleet, &access, &w.publish_p1).await,
        (201, w.publish_p1_response.clone())
    );
    drop(_s);
    done(&d);
}
