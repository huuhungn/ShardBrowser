//! Profile publish, checkout, renew, release and force-expire over HTTP
//! (plan 8.1 L1137-L1143, 5.6.5 L948/L949/L952/L962-L970; G2-21, G2-22,
//! G2-25).
//!
//! The server, device and custody helpers are the minimal ones copied from
//! `v2_auth.rs`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
use serde_json::{json, Value};
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;
use zeroize::Zeroizing;

use shardx_team_server::identity_record::{external_record_sha256, IdentityRecordV2};
use shared::authz_record::{
    build_record, ApprovalScopeKind, AuthorizationRecord, Capability, CapabilityScopeKind,
    CommonFields, DeviceApprovalV2, GrantSubject, Payload, RootGrantVariant,
    TenantCapabilityGrantV2, TenantRootKeyGrantV2, DOMAIN_DEVICE_APPROVAL,
    DOMAIN_TENANT_CAPABILITY_GRANT, DOMAIN_TENANT_ROOT_KEY_GRANT,
};
use shared::grants::derive_keypair;
use shared::keys::{hpke_key_id, signing_key_id};
use shared::mutation::{
    root_custodian_grant_set_hash, EmbeddedSelfGrant, IdempotentMutationRequestV2,
    IdempotentStoredResponseV2, OperationKind, RootGenerationMode, RootGenerationTarget,
    RootGrantRef, TenantRootGenerationActivateV2, TenantRootGenerationCreateV2,
    TenantRootGrantAckV2,
};
use shared::profile_lease::{
    LeaseOrigin, LeaseRef, LeaseReleasedV2, LeaseRenewV2, LeaseRenewedV2, ProfileCheckoutV2,
    ProfileLeaseV2, ProfilePublishCreateV2, ProfileRef, ReleaseLeaseV2, ReleaseReason,
    RECORD_TYPE_CHECKED_OUT, RECORD_TYPE_LEASE_RELEASED, RECORD_TYPE_PUBLISH_CREATED,
};
use shared::session_binding::{self as sb, DeviceSessionBindingV2};
use shared::signing::Ed25519SigningKey;

const INSTANCE: [u8; 16] = [7; 16];
const TENANT: [u8; 16] = [0x41; 16];
const OWNER: [u8; 16] = [0x51; 16];
const PASSWORD: &str = "correct horse battery staple";
const DAY_MS: u64 = 86_400_000;
const TRK: [u8; 32] = [0x7c; 32];
const APPROVAL_REPLAY: u8 = 0x71;
const SELF_GRANT_REPLAY: [u8; 16] = [0x81; 16];
const FLEET: [u8; 16] = [0xf5; 16];
const ARCHIVED: [u8; 16] = [0xf6; 16];
const FKEK: [u8; 32] = [0xe0; 32];
const P1: [u8; 16] = [0xc1; 16];
const P2: [u8; 16] = [0xc2; 16];
const P3: [u8; 16] = [0xc3; 16];
const P4: [u8; 16] = [0xc4; 16];
const P5: [u8; 16] = [0xc5; 16];

struct Server {
    child: Child,
    port: u16,
    data: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap()
}

async fn db(data: &Path) -> SqlitePool {
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&format!(
            "sqlite://{}/shardx.db?mode=rwc",
            data.to_string_lossy().replace('\\', "/")
        ))
        .await
        .unwrap()
}

fn launch(data: &Path, port: u16) -> Child {
    Command::new(env!("CARGO_BIN_EXE_shardx-team-server"))
        .env("SHARDX_BIND", format!("127.0.0.1:{port}"))
        .env("SHARDX_DATA_DIR", data)
        .env("SHARDX_IDENTITY_DIR", data.with_extension("identity"))
        .env("SHARDX_TOKEN_SECRET", "v2-auth-secret")
        .env("SHARDX_ADMIN_USER", "admin")
        .env("SHARDX_ADMIN_PASS", "secret")
        .spawn()
        .expect("spawn server binary")
}

async fn wait_health(port: u16) {
    for _ in 0..75 {
        if let Ok(r) = client()
            .get(format!("http://127.0.0.1:{port}/health"))
            .send()
            .await
        {
            if r.status().is_success() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("server did not become healthy on port {port}");
}

/// A verified identity, one tenant with its owner account, and a server.
async fn start(tag: &str, port: u16) -> Server {
    let data = std::env::temp_dir().join(format!("shardx-v2-profiles-{tag}"));
    let identity = data.with_extension("identity");
    let _ = std::fs::remove_dir_all(&data);
    let _ = std::fs::remove_dir_all(&identity);
    std::fs::create_dir_all(&data).unwrap();
    std::fs::create_dir_all(&identity).unwrap();
    let record = IdentityRecordV2::genesis(INSTANCE, 1_790_985_600_000)
        .encode()
        .unwrap();
    std::fs::write(identity.join("identity-record-v2.bin"), record).unwrap();

    let pool = db(&data).await;
    shardx_team_server::run_migrations(&pool).await.unwrap();
    sqlx::query("INSERT INTO v2_server_state VALUES (1, ?, 0, ?, 't')")
        .bind(INSTANCE.as_slice())
        .bind(external_record_sha256(&record).as_slice())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO v2_tenants VALUES (?, 'acme', 'active', NULL, 't')")
        .bind(TENANT.as_slice())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO v2_bootstrap_guards VALUES (?, ?, 'unused', NULL, 't')")
        .bind(INSTANCE.as_slice())
        .bind(TENANT.as_slice())
        .execute(&pool)
        .await
        .unwrap();
    let hash = argon2::Argon2::default()
        .hash_password(PASSWORD.as_bytes(), &SaltString::generate(&mut OsRng))
        .unwrap()
        .to_string();
    sqlx::query("INSERT INTO v2_accounts VALUES (?, ?, 'owner', ?, NULL, 0, 'active', 't')")
        .bind(OWNER.as_slice())
        .bind(TENANT.as_slice())
        .bind(&hash)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO v2_tenant_memberships VALUES (?, ?, 'owner', 'active', 't')")
        .bind(TENANT.as_slice())
        .bind(OWNER.as_slice())
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    let child = launch(&data, port);
    wait_health(port).await;
    Server { child, port, data }
}

impl Server {
    async fn post(&self, path: &str, bearer: Option<&str>, body: Value) -> (u16, Value) {
        let mut req = client()
            .post(format!("http://127.0.0.1:{}{path}", self.port))
            .json(&body);
        if let Some(t) = bearer {
            req = req.bearer_auth(t);
        }
        let r = req.send().await.unwrap();
        let status = r.status().as_u16();
        (status, r.json().await.unwrap_or(Value::Null))
    }

    /// Stops the server, runs one offline operator command with `stdin`, and
    /// starts the server again.
    async fn offline(&mut self, args: &[&str], stdin: &str) -> std::process::Output {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let mut cli = Command::new(env!("CARGO_BIN_EXE_shardx-team-server"))
            .args(args)
            .env("SHARDX_DATA_DIR", &self.data)
            .env("SHARDX_IDENTITY_DIR", self.data.with_extension("identity"))
            .env("SHARDX_TOKEN_SECRET", "v2-auth-secret")
            .env("SHARDX_ADMIN_USER", "admin")
            .env("SHARDX_ADMIN_PASS", "secret")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn the operator command");
        cli.stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        let out = cli.wait_with_output().unwrap();
        self.child = launch(&self.data, self.port);
        wait_health(self.port).await;
        out
    }

    /// The offline D1 confirmation, typed the way the operator types it.
    async fn confirm(&mut self, dev: &Device) {
        let out = self
            .offline(
                &[
                    "tenant",
                    "confirm-first-device",
                    "--tenant",
                    "acme",
                    "--device",
                    &hex(&dev.id),
                ],
                &format!("{}\n{}\n", hex(&dev.signing_key_id), hex(&dev.hpke_key_id)),
            )
            .await;
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// A CBOR POST of `body` to `path`.
    async fn call(&self, path: &str, bearer: &str, body: &[u8]) -> (u16, Vec<u8>) {
        let r = client()
            .post(format!("http://127.0.0.1:{}{path}", self.port))
            .header("content-type", "application/cbor")
            .body(body.to_vec())
            .bearer_auth(bearer)
            .send()
            .await
            .unwrap();
        let status = r.status().as_u16();
        (status, r.bytes().await.unwrap().to_vec())
    }

    async fn try_sql(&self, statement: &str, binds: &[&[u8]]) -> bool {
        let pool = db(&self.data).await;
        let mut q = sqlx::query(statement);
        for b in binds {
            q = q.bind(b.to_vec());
        }
        let ok = q.execute(&pool).await.is_ok();
        pool.close().await;
        ok
    }

    async fn sql(&self, statement: &str, binds: &[&[u8]]) {
        assert!(self.try_sql(statement, binds).await, "{statement}");
    }

    async fn count(&self, query: &str) -> i64 {
        let pool = db(&self.data).await;
        let n = sqlx::query_scalar(query).fetch_one(&pool).await.unwrap();
        pool.close().await;
        n
    }

    async fn login(&self) -> Value {
        let (status, body) = self
            .post(
                "/v2/auth/login",
                None,
                json!({ "tenant": "acme", "username": "owner", "password": PASSWORD }),
            )
            .await;
        assert_eq!(status, 201, "{body}");
        body
    }
}

struct Device {
    id: [u8; 16],
    sk: Ed25519SigningKey,
    hpke_sk: Zeroizing<Vec<u8>>,
    hpke_pk: Vec<u8>,
    signing_key_id: [u8; 32],
    hpke_key_id: [u8; 32],
}

/// A device enrolled for the owner, stored the way enrollment stores it.
async fn device(server: &Server, seed: u8, status: &str) -> Device {
    let sk = Ed25519SigningKey::from_bytes(&[seed; 32]);
    let spk = sk.verifying_key().to_bytes();
    let (hpke_sk, hpk) = derive_keypair(&[seed.wrapping_add(1); 32]);
    let id = [seed; 16];
    let pool = db(&server.data).await;
    sqlx::query("INSERT INTO v2_devices VALUES (?, ?, ?, x'aa', ?, ?, 1, ?, ?, 1, ?, NULL, 't')")
        .bind(id.as_slice())
        .bind(TENANT.as_slice())
        .bind(OWNER.as_slice())
        .bind(signing_key_id(&spk).as_slice())
        .bind(spk.as_slice())
        .bind(hpke_key_id(&hpk).as_slice())
        .bind(hpk.as_slice())
        .bind(status)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    Device {
        id,
        sk,
        hpke_sk,
        signing_key_id: signing_key_id(&spk),
        hpke_key_id: hpke_key_id(&hpk),
        hpke_pk: hpk,
    }
}

/// Login, challenge and proof; returns the access token.
async fn session(server: &Server, dev: &Device) -> String {
    let ticket = server.login().await;
    let (status, ch) = server
        .post(
            "/v2/auth/device-session-challenges",
            ticket["ticket"].as_str(),
            json!({ "device_id": hex(&dev.id) }),
        )
        .await;
    assert_eq!(status, 201, "{ch}");
    let binding = unhex(ch["binding"].as_str().unwrap());
    DeviceSessionBindingV2::parse(&binding).unwrap();
    let secret = sb::open_pop_secret(
        &dev.hpke_sk,
        &binding,
        &unhex(ch["encapsulated_key"].as_str().unwrap()),
        &unhex(ch["ciphertext"].as_str().unwrap()),
    )
    .unwrap();
    let (status, s) = server
        .post(
            "/v2/auth/device-session-proofs",
            ticket["ticket"].as_str(),
            json!({
                "challenge_id": ch["challenge_id"],
                "secret": hex(&*secret),
                "signature": hex(&sb::sign_pop(&dev.sk, &binding, &secret)),
            }),
        )
        .await;
    assert_eq!(status, 201, "{s}");
    s["access_token"].as_str().unwrap().to_string()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn code(body: &[u8]) -> String {
    serde_json::from_slice::<Value>(body).unwrap_or(Value::Null)["code"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

fn common(replay: [u8; 16], days: u64) -> CommonFields {
    let start = now_ms() - 60_000;
    CommonFields {
        replay_id: replay,
        tenant_id: TENANT,
        issued_at_ms: start,
        not_before_ms: start,
        not_after_ms: start + days * DAY_MS,
        server_instance_id: INSTANCE,
        restore_epoch: 0,
    }
}

/// The exact outer request of `kind` under idempotency key `key`.
fn outer(kind: OperationKind, key: u8, payload: Vec<u8>) -> Vec<u8> {
    outer_with(kind, key, payload, [0x92; 16], INSTANCE, 0)
}

fn outer_with(
    kind: OperationKind,
    key: u8,
    payload: Vec<u8>,
    nonce: [u8; 16],
    instance: [u8; 16],
    epoch: u64,
) -> Vec<u8> {
    IdempotentMutationRequestV2 {
        operation_kind: kind,
        idempotency_key: [key; 16],
        canonical_payload_bytes: payload,
        client_request_nonce: nonce,
        server_instance_id: instance,
        restore_epoch: epoch,
    }
    .encode()
}

/// D1, the root bootstrap, its acknowledgement and activation: the device is
/// the tenant's ACTIVE root custodian. Returns it and its access token.
async fn custodian(server: &mut Server, seed: u8) -> (Device, String) {
    let dev = device(server, seed, "pending").await;
    server.confirm(&dev).await;
    let access = session(server, &dev).await;
    let start = now_ms() - 60_000;
    let approval = DeviceApprovalV2 {
        common: common([APPROVAL_REPLAY; 16], 30),
        subject_account_id: OWNER,
        subject_device_id: dev.id,
        subject_signing_key_id: dev.signing_key_id,
        subject_hpke_key_id: dev.hpke_key_id,
        approval_scope_kind: ApprovalScopeKind::Tenant,
        approval_scope_id: TENANT,
    };
    let rec = build_record(&dev.sk, DOMAIN_DEVICE_APPROVAL, &approval.encode());
    let path = format!("/v2/devices/{}/approve", hex(&dev.id));
    assert_eq!(server.call(&path, &access, &rec).await.0, 201);

    let mut g = TenantRootKeyGrantV2 {
        common: CommonFields {
            replay_id: SELF_GRANT_REPLAY,
            tenant_id: TENANT,
            issued_at_ms: start,
            not_before_ms: start,
            not_after_ms: start + 30 * DAY_MS,
            server_instance_id: INSTANCE,
            restore_epoch: 0,
        },
        variant: RootGrantVariant::FirstRootSelfGrant,
        root_key_id: shared::keys::root_key_id(&TRK),
        root_generation: 0,
        subject_account_id: OWNER,
        subject_device_id: dev.id,
        subject_signing_key_id: dev.signing_key_id,
        recipient_hpke_key_id: dev.hpke_key_id,
        subject_device_approval_replay_id: [APPROVAL_REPLAY; 16],
        hpke_encapped_key_bytes: [0; 32],
        hpke_wrapped_trk_bytes: [0; 48],
    };
    let sealed = shared::grants::seal_trk(&dev.hpke_pk, &g.scope(), &TRK).unwrap();
    g.hpke_encapped_key_bytes = sealed.encapped_key_bytes.try_into().unwrap();
    g.hpke_wrapped_trk_bytes = sealed.ciphertext_bytes.try_into().unwrap();
    let container = build_record(&dev.sk, DOMAIN_TENANT_ROOT_KEY_GRANT, &g.encode());
    let hash = *AuthorizationRecord::parse(&container)
        .unwrap()
        .signed_container_hash();
    let target = RootGenerationTarget {
        tenant_id: TENANT,
        server_instance_id: INSTANCE,
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
    let request = outer(OperationKind::RootGenerationCreate, 0x91, create.encode());
    let root = format!("/v2/tenants/{}/root-key-generations", hex(&TENANT));
    assert_eq!(server.call(&root, &access, &request).await.0, 201);

    let v = AuthorizationRecord::parse(&container)
        .unwrap()
        .verify_signature(dev.sk.verifying_key().as_bytes())
        .unwrap();
    let Payload::TenantRootKeyGrant(g) = v.payload() else {
        panic!("a root grant")
    };
    let grant = RootGrantRef {
        tenant_id: g.common.tenant_id,
        server_instance_id: g.common.server_instance_id,
        restore_epoch: g.common.restore_epoch,
        root_generation: g.root_generation,
        root_key_id: g.root_key_id,
        replay_id: g.common.replay_id,
        signed_container_hash: *v.record().signed_container_hash(),
        exact_signed_container_bytes_sha256: *v.record().exact_signed_container_bytes_sha256(),
    };
    let ack = outer(
        OperationKind::RootGrantAck,
        0xb1,
        TenantRootGrantAckV2 { grant }.encode(),
    );
    let ack_path = format!("{root}/0/grants/{}/ack", hex(&SELF_GRANT_REPLAY));
    assert_eq!(server.call(&ack_path, &access, &ack).await.0, 201);
    let activate = outer(
        OperationKind::RootGenerationActivate,
        0xb3,
        TenantRootGenerationActivateV2 {
            target,
            previous: None,
        }
        .encode(),
    );
    assert_eq!(
        server
            .call(&format!("{root}/0/activate"), &access, &activate)
            .await
            .0,
        201
    );
    (dev, access)
}

/// A second device of the owner approved tenant-wide by `from`, and its
/// access token.
async fn peer(server: &Server, from: &Device, seed: u8) -> (Device, String) {
    peer_in(server, from, seed, (ApprovalScopeKind::Tenant, TENANT)).await
}

/// [`peer`] under the approval scope `(kind, id)`: a signed approval filed
/// straight into the table.
async fn peer_in(
    server: &Server,
    from: &Device,
    seed: u8,
    scope: (ApprovalScopeKind, [u8; 16]),
) -> (Device, String) {
    let to = device(server, seed, "active").await;
    let replay = seed;
    let approval = DeviceApprovalV2 {
        common: common([replay; 16], 30),
        subject_account_id: OWNER,
        subject_device_id: to.id,
        subject_signing_key_id: to.signing_key_id,
        subject_hpke_key_id: to.hpke_key_id,
        approval_scope_kind: scope.0,
        approval_scope_id: scope.1,
    };
    let c = &approval.common;
    let exact = build_record(&from.sk, DOMAIN_DEVICE_APPROVAL, &approval.encode());
    let r = AuthorizationRecord::parse(&exact).unwrap();
    server
        .sql(
            &format!(
                "INSERT INTO v2_device_approvals (
                 tenant_id, replay_id, payload_domain, payload_version, subject_account_id,
                 subject_device_id, subject_signing_key_id, subject_hpke_key_id,
                 approval_scope_kind, approval_scope_id, approved_use, issued_at_ms,
                 not_before_ms, not_after_ms, server_instance_id, restore_epoch,
                 canonical_payload_bytes, payload_sha256, signature_suite_id, signature_version,
                 signature_bytes, issuer_signing_key_id, signed_container_hash,
                 exact_signed_container_bytes, exact_signed_container_bytes_sha256, created_at)
             VALUES (?, ?, '{DOMAIN_DEVICE_APPROVAL}', 2, ?, ?, ?, ?, '{}', ?, 'team.device',
                     {}, {}, {}, ?, 0, ?, ?, 1, 1, ?, ?, ?, ?, ?, 't')",
                scope.0.as_str(),
                c.issued_at_ms,
                c.not_before_ms,
                c.not_after_ms
            ),
            &[
                &TENANT,
                &[replay; 16],
                &OWNER,
                &to.id,
                &to.signing_key_id,
                &to.hpke_key_id,
                &scope.1,
                &INSTANCE,
                r.canonical_payload_bytes(),
                r.payload_sha256(),
                r.signature_bytes(),
                r.issuer_signing_key_id(),
                r.signed_container_hash(),
                r.exact_signed_container_bytes(),
                r.exact_signed_container_bytes_sha256(),
            ],
        )
        .await;
    let access = session(server, &to).await;
    (to, access)
}

/// Files `capability` for `subject` (a device, or the owner account when
/// `None`) over `scope`, signed by the custodian.
async fn grant(
    server: &Server,
    custodian: (&Device, &str),
    subject: Option<&Device>,
    replay: u8,
    capability: Capability,
    scope: (CapabilityScopeKind, [u8; 16]),
) {
    let subject = match subject {
        Some(d) => GrantSubject::Device {
            account_id: OWNER,
            device_id: d.id,
            signing_key_id: d.signing_key_id,
            hpke_key_id: d.hpke_key_id,
        },
        None => GrantSubject::Account { account_id: OWNER },
    };
    let g = TenantCapabilityGrantV2 {
        common: common([replay; 16], 30),
        subject,
        scope_kind: scope.0,
        scope_id: scope.1,
        capability,
    };
    let rec = build_record(&custodian.0.sk, DOMAIN_TENANT_CAPABILITY_GRANT, &g.encode());
    let (status, body) = server
        .call("/v2/capability-grants", custodian.1, &rec)
        .await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
}

/// `FLEET` active with ACTIVE generation 0 under `FKEK`, and `ARCHIVED`
/// archived with its own ACTIVE generation.
async fn fleets(server: &Server) {
    for (fleet, name, status, fkek) in [
        (FLEET, "f", "active", FKEK),
        (ARCHIVED, "a", "archived", [0xe9; 32]),
    ] {
        server
            .sql(
                &format!(
                    "INSERT INTO v2_fleets (id, tenant_id, name, status, created_at)
                     VALUES (?, ?, '{name}', '{status}', 't')"
                ),
                &[&fleet, &TENANT],
            )
            .await;
        server
            .sql(
                "INSERT INTO v2_fleet_key_generations
                     (server_instance_id, tenant_id, fleet_id, generation, fkek_key_id,
                      root_generation, state, created_at, activated_at)
                 VALUES (?, ?, ?, 0, ?, 0, 'ACTIVE', 't', 't')",
                &[&INSTANCE, &TENANT, &fleet, &fkek],
            )
            .await;
    }
}

/// A v1 token for the legacy JSON fleet routes, whose account maps to the
/// owner through `legacy_user_id`.
async fn legacy_token(server: &Server) -> String {
    server
        .sql(
            "UPDATE v2_accounts SET legacy_user_id = (SELECT id FROM users WHERE username = 'admin')
              WHERE id = ?",
            &[&OWNER],
        )
        .await;
    let (status, body) = server
        .post(
            "/auth/login",
            None,
            json!({ "username": "admin", "password": "secret" }),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    body["token"].as_str().unwrap().to_string()
}

/// The exact `DEVICE_REVOKE` request of `subject`, signed by `issuer`.
fn revoke_request(issuer: &Device, subject: &Device, key: u8) -> Vec<u8> {
    use shared::authz_record::{
        DeviceRevocationReason, DeviceRevocationV2, DOMAIN_DEVICE_REVOCATION,
    };
    let r = DeviceRevocationV2 {
        common: common([key; 16], 30),
        subject_account_id: OWNER,
        subject_device_id: subject.id,
        subject_signing_key_id: subject.signing_key_id,
        subject_hpke_key_id: subject.hpke_key_id,
        reason_code: DeviceRevocationReason::Compromised,
    };
    let container = build_record(&issuer.sk, DOMAIN_DEVICE_REVOCATION, &r.encode());
    let request = shared::mutation::DeviceRevokeRequestV2 {
        signed_container_hash: *AuthorizationRecord::parse(&container)
            .unwrap()
            .signed_container_hash(),
        exact_signed_revocation_container_bytes: container,
    };
    outer(OperationKind::DeviceRevoke, key, request.encode())
}

fn pref(profile: [u8; 16]) -> ProfileRef {
    ProfileRef {
        tenant_id: TENANT,
        fleet_id: FLEET,
        profile_id: profile,
    }
}

fn publish_payload(p: ProfileRef) -> ProfilePublishCreateV2 {
    ProfilePublishCreateV2 {
        profile: p,
        label_ciphertext: vec![0x33; 24],
        requested_lease_ttl_seconds: 300,
        fkek_key_id: FKEK,
        key_generation: 0,
    }
}

fn publish(key: u8, p: ProfileRef) -> Vec<u8> {
    outer(
        OperationKind::ProfilePublishCreate,
        key,
        publish_payload(p).encode(),
    )
}

fn checkout(key: u8, p: ProfileRef, observed_version: u64) -> Vec<u8> {
    let payload = ProfileCheckoutV2 {
        profile: p,
        observed_version,
        observed_signed_head_hash: (observed_version != 0).then_some([0x44; 32]),
        requested_lease_ttl_seconds: 300,
    };
    outer(OperationKind::ProfileCheckout, key, payload.encode())
}

fn release(key: u8, p: ProfileRef, lease: LeaseRef) -> Vec<u8> {
    let payload = ReleaseLeaseV2 {
        profile: p,
        lease,
        reason_code: ReleaseReason::UserRelease,
    };
    outer(OperationKind::ReleaseLease, key, payload.encode())
}

fn renew(p: ProfileRef, lease: LeaseRef, ttl: u32) -> Vec<u8> {
    LeaseRenewV2 {
        profile: p,
        lease,
        requested_lease_ttl_seconds: ttl,
    }
    .encode()
}

fn publish_path(fleet: [u8; 16]) -> String {
    format!("/v2/fleets/{}/profiles", hex(&fleet))
}

fn checkout_path(profile: [u8; 16]) -> String {
    format!("/v2/profiles/{}/checkout", hex(&profile))
}

fn lease_path(profile: [u8; 16], lease: &[u8; 16], action: &str) -> String {
    format!(
        "/v2/profiles/{}/leases/{}/{action}",
        hex(&profile),
        hex(lease)
    )
}

/// The lease a stored publish or checkout response grants.
fn granted(origin: LeaseOrigin, body: &[u8]) -> ProfileLeaseV2 {
    let stored = IdempotentStoredResponseV2::parse(body).unwrap();
    assert_eq!(stored.response_record_type, origin.record_type());
    ProfileLeaseV2::parse(origin, &stored.canonical_response_payload_bytes).unwrap()
}

async fn expect(server: &Server, path: &str, bearer: &str, body: &[u8], want: (u16, &str)) {
    let (status, got) = server.call(path, bearer, body).await;
    assert_eq!(
        (status, code(&got).as_str()),
        want,
        "{path}: {}",
        String::from_utf8_lossy(&got)
    );
}

#[tokio::test]
async fn one_lease_and_one_fence_per_grant_and_every_retry_gets_the_stored_bytes() {
    let mut server = start("happy", 28261).await;
    let (dev, access) = custodian(&mut server, 0x6c).await;
    fleets(&server).await;
    let c = (&dev, access.as_str());
    use CapabilityScopeKind as K;
    grant(
        &server,
        c,
        Some(&dev),
        0xa1,
        Capability::ProfilePublish,
        (K::Tenant, TENANT),
    )
    .await;
    grant(
        &server,
        c,
        Some(&dev),
        0xa2,
        Capability::ProfileCheckout,
        (K::Fleet, FLEET),
    )
    .await;
    grant(
        &server,
        c,
        Some(&dev),
        0xa3,
        Capability::LeaseForceExpire,
        (K::Tenant, TENANT),
    )
    .await;
    let p = pref(P1);

    // Publish: the version-0 profile, fence 1 and its lease, at once.
    let before = now_ms();
    let req = publish(0x01, p);
    let (status, body) = server.call(&publish_path(FLEET), &access, &req).await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    let first = granted(LeaseOrigin::PublishCreate, &body);
    assert_eq!(first.profile, p);
    assert_eq!(
        (first.lease.fencing_token, first.lease.base_version),
        (1, 0)
    );
    assert_eq!((first.fkek_key_id, first.key_generation), (FKEK, 0));
    assert_eq!(first.current_signed_head_hash, None);
    assert_eq!(
        (first.server_instance_id, first.restore_epoch),
        (INSTANCE, 0)
    );
    assert!(first.expires_at_ms >= before + 300_000 && first.expires_at_ms <= now_ms() + 300_000);
    let state = [
        "SELECT count(*) FROM v2_profiles WHERE label_ciphertext IS NOT NULL
            AND last_fencing_token = 1 AND current_key_generation = 0 AND current_version = 0",
        "SELECT count(*) FROM v2_profile_leases WHERE fencing_token = 1",
        "SELECT count(*) FROM v2_audit_events WHERE action = 'profile.publish_create'",
        "SELECT count(*) FROM v2_idempotency WHERE operation_kind = 'PROFILE_PUBLISH_CREATE'",
    ];
    for q in state {
        assert_eq!(server.count(q).await, 1, "{q}");
    }
    // The exact retry gets the same bytes and creates nothing.
    assert_eq!(
        server.call(&publish_path(FLEET), &access, &req).await,
        (201, body.clone())
    );
    for q in state {
        assert_eq!(server.count(q).await, 1, "{q}");
    }
    // The same key with other bytes is refused.
    let other = outer_with(
        OperationKind::ProfilePublishCreate,
        0x01,
        publish_payload(p).encode(),
        [0x93; 16],
        INSTANCE,
        0,
    );
    expect(
        &server,
        &publish_path(FLEET),
        &access,
        &other,
        (409, "IDEMPOTENCY_MISMATCH"),
    )
    .await;

    // One current lease: even its holder cannot check out again.
    let held = checkout_path(P1);
    expect(
        &server,
        &held,
        &access,
        &checkout(0x02, p, 0),
        (409, "LEASE_HELD"),
    )
    .await;

    // Renew moves only the expiry, and only for the exact lease.
    let renew_path = lease_path(P1, &first.lease.lease_id, "renew");
    let (status, body) = server
        .call(&renew_path, &access, &renew(p, first.lease, 900))
        .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let renewed = LeaseRenewedV2::parse(&body).unwrap();
    assert_eq!((renewed.profile, renewed.lease), (p, first.lease));
    assert!(renewed.expires_at_ms > first.expires_at_ms);
    assert_eq!(
        server
            .count(&format!(
                "SELECT count(*) FROM v2_profile_leases WHERE expires_at_ms = {}",
                renewed.expires_at_ms
            ))
            .await,
        1
    );
    let stale = LeaseRef {
        fencing_token: 2,
        ..first.lease
    };
    expect(
        &server,
        &renew_path,
        &access,
        &renew(p, stale, 60),
        (409, "FENCE_STALE"),
    )
    .await;

    // Release: a stale fence is refused; the exact lease is deleted, and the
    // retry after the delete gets the stored bytes.
    let release_path = lease_path(P1, &first.lease.lease_id, "release");
    expect(
        &server,
        &release_path,
        &access,
        &release(0x03, p, stale),
        (409, "FENCE_STALE"),
    )
    .await;
    let req = release(0x04, p, first.lease);
    let (status, body) = server.call(&release_path, &access, &req).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let stored = IdempotentStoredResponseV2::parse(&body).unwrap();
    assert_eq!(stored.response_record_type, RECORD_TYPE_LEASE_RELEASED);
    let released = LeaseReleasedV2::parse(&stored.canonical_response_payload_bytes).unwrap();
    assert_eq!((released.profile, released.lease), (p, first.lease));
    assert_eq!(
        server.count("SELECT count(*) FROM v2_profile_leases").await,
        0
    );
    assert_eq!(
        server.call(&release_path, &access, &req).await,
        (200, body.clone())
    );
    assert_eq!(
        server
            .count("SELECT count(*) FROM v2_audit_events WHERE action = 'profile.release_lease'")
            .await,
        1
    );

    // A second device checks out under a profile-scoped grant: fence 2.
    let (other, other_access) = peer(&server, &dev, 0x7d).await;
    grant(
        &server,
        c,
        Some(&other),
        0xa4,
        Capability::ProfileCheckout,
        (K::Profile, P1),
    )
    .await;
    let theirs = checkout(0x05, p, 0);
    let (status, their_body) = server.call(&held, &other_access, &theirs).await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&their_body));
    let second = granted(LeaseOrigin::Checkout, &their_body);
    assert_eq!(
        (second.lease.fencing_token, second.lease.base_version),
        (2, 0)
    );
    assert_eq!((second.fkek_key_id, second.key_generation), (FKEK, 0));
    assert_eq!(second.current_signed_head_hash, None);
    // Held by another device: no checkout, release or renew by this one.
    expect(
        &server,
        &held,
        &access,
        &checkout(0x06, p, 0),
        (409, "LEASE_HELD"),
    )
    .await;
    let their_release = lease_path(P1, &second.lease.lease_id, "release");
    let their_renew = lease_path(P1, &second.lease.lease_id, "renew");
    expect(
        &server,
        &their_release,
        &access,
        &release(0x07, p, second.lease),
        (403, ""),
    )
    .await;
    expect(
        &server,
        &their_renew,
        &access,
        &renew(p, second.lease, 60),
        (403, ""),
    )
    .await;

    // Once it expired: the retry still returns the same bytes and no fence,
    // renew is refused, and a new checkout replaces the row with fence 3.
    server
        .sql("UPDATE v2_profile_leases SET expires_at_ms = 1", &[])
        .await;
    assert_eq!(
        server.call(&held, &other_access, &theirs).await,
        (201, their_body.clone())
    );
    expect(
        &server,
        &their_renew,
        &other_access,
        &renew(p, second.lease, 60),
        (409, "LEASE_EXPIRED"),
    )
    .await;
    let (status, body) = server.call(&held, &access, &checkout(0x08, p, 0)).await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    let third = granted(LeaseOrigin::Checkout, &body);
    assert_eq!(third.lease.fencing_token, 3);
    expect(
        &server,
        &their_renew,
        &other_access,
        &renew(p, second.lease, 60),
        (409, "LEASE_EXPIRED"),
    )
    .await;
    assert_eq!(
        server.call(&held, &other_access, &theirs).await,
        (201, their_body)
    );
    for (q, want) in [
        (
            "SELECT count(*) FROM v2_profiles WHERE last_fencing_token = 3",
            1,
        ),
        (
            "SELECT count(*) FROM v2_profile_leases WHERE fencing_token = 3",
            1,
        ),
        ("SELECT count(*) FROM v2_profile_leases", 1),
        (
            "SELECT count(*) FROM v2_audit_events WHERE action = 'profile.checkout'",
            2,
        ),
    ] {
        assert_eq!(server.count(q).await, want, "{q}");
    }
    // The replaced lease is gone for its holder.
    expect(
        &server,
        &their_release,
        &other_access,
        &release(0x09, p, second.lease),
        (409, "LEASE_EXPIRED"),
    )
    .await;

    // Force-expire needs `lease.force_expire`, deletes the row, and audits.
    let force = lease_path(P1, &third.lease.lease_id, "force-expire");
    // Only the named lease: a stale lease ID expires nothing.
    let stale_force = lease_path(P1, &second.lease.lease_id, "force-expire");
    expect(&server, &stale_force, &access, b"", (409, "LEASE_EXPIRED")).await;
    expect(&server, &force, &other_access, b"", (403, "")).await;
    let (status, body) = server.call(&force, &access, b"").await;
    assert_eq!(status, 204, "{}", String::from_utf8_lossy(&body));
    assert_eq!(
        server.count("SELECT count(*) FROM v2_profile_leases").await,
        0
    );
    assert_eq!(
        server
            .count("SELECT count(*) FROM v2_audit_events WHERE action = 'lease.force_expire'")
            .await,
        1
    );
    expect(&server, &force, &access, b"", (409, "LEASE_EXPIRED")).await;
    let third_renew = lease_path(P1, &third.lease.lease_id, "renew");
    expect(
        &server,
        &third_renew,
        &access,
        &renew(p, third.lease, 60),
        (409, "LEASE_EXPIRED"),
    )
    .await;
    let missing = lease_path(P5, &third.lease.lease_id, "force-expire");
    expect(&server, &missing, &access, b"", (404, "RESOURCE_NOT_FOUND")).await;

    // Revoking a device ends its current lease in the same transaction (C-1).
    let (status, body) = server
        .call(&held, &other_access, &checkout(0x0a, p, 0))
        .await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    grant(
        &server,
        c,
        Some(&dev),
        0xa8,
        Capability::DeviceRevoke,
        (K::Tenant, TENANT),
    )
    .await;
    let revoke = format!("/v2/devices/{}/revoke", hex(&other.id));
    let (status, body) = server
        .call(&revoke, &access, &revoke_request(&dev, &other, 0x90))
        .await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    assert_eq!(
        server.count("SELECT count(*) FROM v2_profile_leases").await,
        0
    );
    assert_eq!(
        server.call(&held, &access, &checkout(0x0b, p, 0)).await.0,
        201
    );
}

#[tokio::test]
async fn every_refusal_has_its_status_and_code() {
    let mut server = start("refusals", 28262).await;
    let (dev, access) = custodian(&mut server, 0x6c).await;
    fleets(&server).await;
    let c = (&dev, access.as_str());
    use CapabilityScopeKind as K;
    grant(
        &server,
        c,
        Some(&dev),
        0xa1,
        Capability::ProfilePublish,
        (K::Tenant, TENANT),
    )
    .await;
    grant(
        &server,
        c,
        Some(&dev),
        0xa2,
        Capability::ProfileCheckout,
        (K::Tenant, TENANT),
    )
    .await;
    let (peer_dev, other) = peer(&server, &dev, 0x7d).await;
    let pub_path = publish_path(FLEET);
    let p = pref(P1);

    // Who: a ticket, a device without the capability, another tenant.
    let ticket = server.login().await["ticket"].as_str().unwrap().to_string();
    expect(&server, &pub_path, &ticket, &publish(0x10, p), (403, "")).await;
    expect(&server, &pub_path, &other, &publish(0x10, p), (403, "")).await;
    let foreign = ProfileRef {
        tenant_id: [0x42; 16],
        ..p
    };
    expect(
        &server,
        &pub_path,
        &access,
        &publish(0x10, foreign),
        (403, ""),
    )
    .await;
    // The request: another fleet than the path, instance or epoch.
    expect(
        &server,
        &publish_path(ARCHIVED),
        &access,
        &publish(0x10, p),
        (422, "AUTH_CLAIM_COLUMN_MISMATCH"),
    )
    .await;
    let payload = publish_payload(p).encode();
    let kind = OperationKind::ProfilePublishCreate;
    let wrong_instance = outer_with(kind, 0x10, payload.clone(), [0x92; 16], [8; 16], 0);
    expect(&server, &pub_path, &access, &wrong_instance, (403, "")).await;
    let wrong_epoch = outer_with(kind, 0x10, payload, [0x92; 16], INSTANCE, 1);
    expect(
        &server,
        &pub_path,
        &access,
        &wrong_epoch,
        (409, "STALE_CONTEXT"),
    )
    .await;
    // Live state: an archived fleet, another key generation.
    let archived = ProfileRef {
        fleet_id: ARCHIVED,
        ..p
    };
    expect(
        &server,
        &publish_path(ARCHIVED),
        &access,
        &publish(0x10, archived),
        (404, "RESOURCE_NOT_FOUND"),
    )
    .await;
    for (fkek, generation) in [([0xee; 32], 0), (FKEK, 1)] {
        let mut wrong = publish_payload(p);
        (wrong.fkek_key_id, wrong.key_generation) = (fkek, generation);
        let req = outer(kind, 0x10, wrong.encode());
        expect(
            &server,
            &pub_path,
            &access,
            &req,
            (409, "FLEET_GENERATION_NOT_ACTIVE"),
        )
        .await;
    }
    // Nothing above was stored: the key still publishes once.
    let (status, body) = server.call(&pub_path, &access, &publish(0x10, p)).await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    let lease = granted(LeaseOrigin::PublishCreate, &body).lease;
    expect(
        &server,
        &pub_path,
        &access,
        &publish(0x11, p),
        (409, "PROFILE_EXISTS"),
    )
    .await;

    // Release and renew: the path, the tenant, a lease that is not current.
    let rel = lease_path(P1, &lease.lease_id, "release");
    let ren = lease_path(P1, &lease.lease_id, "renew");
    let other_lease = LeaseRef {
        lease_id: [0x99; 16],
        ..lease
    };
    expect(
        &server,
        &rel,
        &access,
        &release(0x12, p, other_lease),
        (422, "AUTH_CLAIM_COLUMN_MISMATCH"),
    )
    .await;
    expect(
        &server,
        &ren,
        &access,
        &renew(p, other_lease, 60),
        (422, "AUTH_CLAIM_COLUMN_MISMATCH"),
    )
    .await;
    expect(
        &server,
        &rel,
        &access,
        &release(0x12, foreign, lease),
        (403, ""),
    )
    .await;
    expect(
        &server,
        &ren,
        &access,
        &renew(foreign, lease, 60),
        (403, ""),
    )
    .await;
    // The legacy JSON routes refuse a published profile (PROFILE_PUBLISHED),
    // and the schema refuses their rows under any race.
    let v1 = legacy_token(&server).await;
    let (t, pr) = (hex(&TENANT), hex(&P1));
    for (path, body) in [
        (
            "/v2/fleet/leases",
            json!({
                "tenant_id": t, "profile_id": pr, "lease_id": hex(&[0x61; 16]),
                "account_id": hex(&OWNER), "device_id": hex(&dev.id), "ttl_seconds": 60,
            }),
        ),
        (
            "/v2/fleet/uploads",
            json!({
                "tenant_id": t, "profile_id": pr, "session_id": hex(&[0x62; 16]),
                "lease_id": hex(&[0x61; 16]), "fencing_token": 1, "target_version": 1,
                "intent_hash": hex(&[0x63; 32]), "declared_size": 4,
            }),
        ),
        (
            "/v2/fleet/uploads/commit",
            json!({
                "tenant_id": t, "profile_id": pr, "session_id": hex(&[0x62; 16]),
                "manifest_hex": "00", "snapshot_id": hex(&[0x64; 16]), "fleet_id": hex(&FLEET),
                "base_version": 0, "key_generation": 0, "container_sha256": hex(&[0x65; 32]),
                "author_account_id": hex(&OWNER), "author_device_id": hex(&dev.id),
            }),
        ),
    ] {
        let (status, got) = server.post(path, Some(&v1), body).await;
        assert_eq!(
            (status, got["code"].as_str()),
            (409, Some("PROFILE_PUBLISHED")),
            "{path}: {got}"
        );
    }
    assert!(
        !server
            .try_sql(
                "INSERT INTO v2_leases
                     (id, tenant_id, profile_id, holder_account_id, holder_device_id, fencing_token,
                      base_version, server_instance_id, restore_epoch, acquired_at, expires_at)
                 VALUES (?, ?, ?, ?, ?, 9, 0, ?, 0, 't', 't')",
                &[&[0x61; 16], &TENANT, &P1, &OWNER, &dev.id, &INSTANCE],
            )
            .await
    );
    assert!(
        !server
            .try_sql(
                "INSERT INTO v2_upload_sessions
                     (id, tenant_id, profile_id, lease_id, server_instance_id, restore_epoch,
                      fencing_token, target_version, intent_hash, declared_size, received_size,
                      staging_path, status, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, 0, 1, 1, ?, 4, 0, 's', 'open', 't', 't')",
                &[
                    &[0x62; 16],
                    &TENANT,
                    &P1,
                    &[0x61; 16],
                    &INSTANCE,
                    &[0x63; 32]
                ],
            )
            .await
    );

    let gone = lease_path(P1, &other_lease.lease_id, "release");
    expect(
        &server,
        &gone,
        &access,
        &release(0x12, p, other_lease),
        (409, "LEASE_EXPIRED"),
    )
    .await;
    let rel2 = lease_path(P2, &lease.lease_id, "release");
    let ren2 = lease_path(P2, &lease.lease_id, "renew");
    expect(
        &server,
        &rel2,
        &access,
        &release(0x12, p, lease),
        (422, "AUTH_CLAIM_COLUMN_MISMATCH"),
    )
    .await;
    expect(
        &server,
        &ren2,
        &access,
        &renew(p, lease, 60),
        (422, "AUTH_CLAIM_COLUMN_MISMATCH"),
    )
    .await;
    expect(
        &server,
        &rel,
        &access,
        &release(0x12, archived, lease),
        (409, "LEASE_EXPIRED"),
    )
    .await;
    assert_eq!(
        server.call(&rel, &access, &release(0x12, p, lease)).await.0,
        200
    );

    // Checkout: the path, the capability, the tenant, the profile state.
    let co = checkout_path(P1);
    expect(
        &server,
        &checkout_path(P2),
        &access,
        &checkout(0x13, p, 0),
        (422, "AUTH_CLAIM_COLUMN_MISMATCH"),
    )
    .await;
    expect(&server, &co, &other, &checkout(0x13, p, 0), (403, "")).await;
    expect(
        &server,
        &co,
        &access,
        &checkout(0x13, foreign, 0),
        (403, ""),
    )
    .await;
    expect(
        &server,
        &co,
        &access,
        &checkout(0x13, archived, 0),
        (404, "RESOURCE_NOT_FOUND"),
    )
    .await;
    expect(
        &server,
        &co,
        &access,
        &checkout(0x13, p, 1),
        (409, "BASE_VERSION_MISMATCH"),
    )
    .await;
    let id = hex(&P1);
    for (break_it, fix_it, want) in [
        (
            format!("UPDATE v2_profiles SET current_version = 1 WHERE id = x'{id}'"),
            format!("UPDATE v2_profiles SET current_version = 0 WHERE id = x'{id}'"),
            (409, "BASE_VERSION_MISMATCH"),
        ),
        (
            format!("UPDATE v2_profiles SET status = 'archived' WHERE id = x'{id}'"),
            format!("UPDATE v2_profiles SET status = 'active' WHERE id = x'{id}'"),
            (404, "RESOURCE_NOT_FOUND"),
        ),
        (
            format!(
                "UPDATE v2_fleets SET status = 'archived' WHERE id = x'{}'",
                hex(&FLEET)
            ),
            format!(
                "UPDATE v2_fleets SET status = 'active' WHERE id = x'{}'",
                hex(&FLEET)
            ),
            (404, "RESOURCE_NOT_FOUND"),
        ),
    ] {
        server.sql(&break_it, &[]).await;
        let observed = if want.1 == "BASE_VERSION_MISMATCH" {
            1
        } else {
            0
        };
        expect(&server, &co, &access, &checkout(0x13, p, observed), want).await;
        server.sql(&fix_it, &[]).await;
    }
    // A legacy profile (no label ciphertext) is not served here.
    server
        .sql(
            "INSERT INTO v2_profiles (id, tenant_id, fleet_id, name, status, created_at, updated_at)
             VALUES (?, ?, ?, 'legacy', 'active', 't', 't')",
            &[&P2, &TENANT, &FLEET],
        )
        .await;
    expect(
        &server,
        &checkout_path(P2),
        &access,
        &checkout(0x13, pref(P2), 0),
        (404, "RESOURCE_NOT_FOUND"),
    )
    .await;

    // An account-scoped grant is server RBAC (D-2); a row that left its
    // container refuses the whole check.
    grant(
        &server,
        c,
        None,
        0xa4,
        Capability::ProfilePublish,
        (K::Tenant, TENANT),
    )
    .await;
    let (status, body) = server
        .call(&pub_path, &other, &publish(0x14, pref(P3)))
        .await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    // A grant for another fleet or profile does not cover this one.
    let other_fleet = [0xf7; 16];
    server
        .sql(
            "INSERT INTO v2_fleets (id, tenant_id, name, status, created_at)
             VALUES (?, ?, 'o', 'active', 't')",
            &[&other_fleet, &TENANT],
        )
        .await;
    grant(
        &server,
        c,
        Some(&peer_dev),
        0xa5,
        Capability::ProfileCheckout,
        (K::Fleet, other_fleet),
    )
    .await;
    grant(
        &server,
        c,
        Some(&peer_dev),
        0xa6,
        Capability::ProfileCheckout,
        (K::Profile, P3),
    )
    .await;
    expect(&server, &co, &other, &checkout(0x13, p, 0), (403, "")).await;
    // An attacker with DB write could edit a row; the check still refuses.
    server
        .sql("DROP TRIGGER v2_capability_grants_record_is_fixed", &[])
        .await;
    server
        .sql(
            "UPDATE v2_capability_grants SET issued_at_ms = issued_at_ms - 1
              WHERE subject_kind = 'account'",
            &[],
        )
        .await;
    expect(
        &server,
        &pub_path,
        &other,
        &publish(0x15, pref(P5)),
        (422, "AUTH_CLAIM_COLUMN_MISMATCH"),
    )
    .await;
    server
        .sql(
            "UPDATE v2_capability_grants SET issued_at_ms = issued_at_ms + 1
              WHERE subject_kind = 'account'",
            &[],
        )
        .await;

    // A fleet-scoped approval admits a device to that fleet only (Q-22).
    let (_, fleet_b) = peer_in(&server, &dev, 0x7e, (ApprovalScopeKind::Fleet, other_fleet)).await;
    expect(
        &server,
        &pub_path,
        &fleet_b,
        &publish(0x20, pref([0xc7; 16])),
        (403, ""),
    )
    .await;
    // Nor do approvals of it for this fleet that are revoked or outside
    // their window.
    let here = format!("x'{}'", hex(&FLEET));
    for (replay, window, revoked) in [
        (0xe1u8, "issued_at_ms, not_before_ms, not_after_ms", "'t'"),
        (0xe2, "0, 0, 1", "NULL"),
        (0xe3, "issued_at_ms, not_after_ms, not_after_ms + 1", "NULL"),
    ] {
        server
            .sql(
                &format!(
                    "INSERT INTO v2_device_approvals (
                         tenant_id, replay_id, payload_domain, payload_version, subject_account_id,
                         subject_device_id, subject_signing_key_id, subject_hpke_key_id,
                         approval_scope_kind, approval_scope_id, approved_use, issued_at_ms,
                         not_before_ms, not_after_ms, server_instance_id, restore_epoch,
                         canonical_payload_bytes, payload_sha256, signature_suite_id,
                         signature_version, signature_bytes, issuer_signing_key_id,
                         signed_container_hash, exact_signed_container_bytes,
                         exact_signed_container_bytes_sha256, created_at, revoked_at)
                     SELECT tenant_id, ?, payload_domain, payload_version, subject_account_id,
                            subject_device_id, subject_signing_key_id, subject_hpke_key_id,
                            'fleet', {here}, approved_use, {window},
                            server_instance_id, restore_epoch, canonical_payload_bytes,
                            payload_sha256, signature_suite_id, signature_version,
                            signature_bytes, issuer_signing_key_id, signed_container_hash,
                            exact_signed_container_bytes, exact_signed_container_bytes_sha256,
                            created_at, {revoked}
                       FROM v2_device_approvals WHERE replay_id = ?"
                ),
                &[&[replay; 16], &[0x7e; 16]],
            )
            .await;
    }
    expect(
        &server,
        &pub_path,
        &fleet_b,
        &publish(0x20, pref([0xc7; 16])),
        (403, ""),
    )
    .await;
    let (_, fleet_a) = peer_in(&server, &dev, 0x7f, (ApprovalScopeKind::Fleet, FLEET)).await;
    let (status, body) = server
        .call(&pub_path, &fleet_a, &publish(0x21, pref([0xc8; 16])))
        .await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    // A candidate approval row that left its container refuses the request
    // and is quarantined; from then on it is no approval.
    for statement in [
        "CREATE TABLE twin AS SELECT * FROM v2_device_approvals
          WHERE replay_id = x'71717171717171717171717171717171'",
        "UPDATE twin SET replay_id = x'eaeaeaeaeaeaeaeaeaeaeaeaeaeaeaea'",
        "INSERT INTO v2_device_approvals SELECT * FROM twin",
    ] {
        server.sql(statement, &[]).await;
    }
    expect(
        &server,
        &pub_path,
        &access,
        &publish(0x23, pref([0xc9; 16])),
        (422, "AUTH_CLAIM_COLUMN_MISMATCH"),
    )
    .await;

    // Its row's name is the hex ID, which a legacy profile may hold already.
    let p6 = [0xc6; 16];
    server
        .sql(
            &format!(
                "INSERT INTO v2_profiles (id, tenant_id, fleet_id, name, status, created_at, updated_at)
                 VALUES (?, ?, ?, '{}', 'active', 't', 't')",
                hex(&p6)
            ),
            &[&[0xd6; 16], &TENANT, &FLEET],
        )
        .await;
    expect(
        &server,
        &pub_path,
        &access,
        &publish(0x22, pref(p6)),
        (409, "PROFILE_EXISTS"),
    )
    .await;

    // A revoked or expired grant counts for nothing: renew needs the live
    // checkout capability.
    let (status, body) = server
        .call(&pub_path, &access, &publish(0x16, pref(P4)))
        .await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    let held = granted(LeaseOrigin::PublishCreate, &body).lease;
    let ren4 = lease_path(P4, &held.lease_id, "renew");
    server
        .sql(
            "UPDATE v2_profiles SET status = 'archived' WHERE id = ?",
            &[&P4],
        )
        .await;
    expect(
        &server,
        &ren4,
        &access,
        &renew(pref(P4), held, 60),
        (404, "RESOURCE_NOT_FOUND"),
    )
    .await;
    server
        .sql(
            "UPDATE v2_profiles SET status = 'active' WHERE id = ?",
            &[&P4],
        )
        .await;
    assert_eq!(
        server
            .call(&ren4, &access, &renew(pref(P4), held, 60))
            .await
            .0,
        200
    );
    server
        .sql(
            "UPDATE v2_capability_grants SET revoked_at = 't' WHERE capability = 'profile.checkout'",
            &[],
        )
        .await;
    expect(
        &server,
        &ren4,
        &access,
        &renew(pref(P4), held, 60),
        (403, ""),
    )
    .await;
    expect(&server, &co, &access, &checkout(0x17, p, 0), (403, "")).await;
    grant(
        &server,
        c,
        Some(&dev),
        0xa7,
        Capability::ProfileCheckout,
        (K::Tenant, TENANT),
    )
    .await;
    // Outside its window a grant is not selected (403); a selected row would
    // no longer match its container (422).
    for window in [
        "not_before_ms = issued_at_ms + 3600000000, not_after_ms = issued_at_ms + 3600000001",
        "not_after_ms = issued_at_ms + 1",
    ] {
        server
            .sql(&format!("UPDATE v2_capability_grants SET {window} WHERE revoked_at IS NULL AND capability = 'profile.checkout'"), &[])
            .await;
        expect(&server, &co, &access, &checkout(0x17, p, 0), (403, "")).await;
        server
            .sql(
                "UPDATE v2_capability_grants SET not_before_ms = issued_at_ms,
                        not_after_ms = issued_at_ms + 2592000000
                  WHERE revoked_at IS NULL AND capability = 'profile.checkout'",
                &[],
            )
            .await;
    }
    assert_eq!(
        server.call(&co, &access, &checkout(0x17, p, 0)).await.0,
        201
    );
    server
        .sql("DELETE FROM v2_profile_leases WHERE profile_id = ?", &[&P1])
        .await;

    // L1098: the fence fails closed at i64::MAX, and never moves back.
    server
        .sql(
            "UPDATE v2_profiles SET last_fencing_token = 9223372036854775807 WHERE id = ?",
            &[&P1],
        )
        .await;
    expect(
        &server,
        &co,
        &access,
        &checkout(0x18, p, 0),
        (422, "WIRE_INTEGER_OUT_OF_RANGE"),
    )
    .await;
    assert!(
        !server
            .try_sql(
                "UPDATE v2_profiles SET last_fencing_token = 1 WHERE id = ?",
                &[&P1]
            )
            .await
    );
    assert!(
        !server
            .try_sql(
                "UPDATE v2_profiles SET last_fencing_token = last_fencing_token WHERE id = ?",
                &[&P4]
            )
            .await
    );
    // A lease holds its profile's newest fence and keeps its terms.
    assert!(
        !server
            .try_sql(
                "INSERT INTO v2_profile_leases VALUES (?, ?, ?, ?, ?, 1, 0, 0, 1, ?)",
                &[&TENANT, &P1, &[0x98; 16], &OWNER, &dev.id, &[0x18; 16]],
            )
            .await
    );
    assert!(
        !server
            .try_sql(
                "UPDATE v2_profile_leases SET fencing_token = 9 WHERE profile_id = ?",
                &[&P4]
            )
            .await
    );

    // The three kinds are stored with their responses.
    for (kind, scope) in [
        ("PROFILE_PUBLISH_CREATE", "profile.publish-create.v2"),
        ("PROFILE_CHECKOUT", "profile.checkout.v2"),
        ("RELEASE_LEASE", "profile.release-lease.v2"),
    ] {
        let statement = format!(
            "INSERT INTO v2_idempotency
                 (server_instance_id, tenant_id, actor_device_id, operation_scope, idempotency_key,
                  operation_kind, canonical_request_hash, exact_request_bytes,
                  exact_request_bytes_sha256, status, retained_until)
             VALUES (?, ?, ?, '{scope}', ?, '{kind}', zeroblob(32), x'01', zeroblob(32),
                     'in_flight', 0)"
        );
        assert!(
            !server
                .try_sql(&statement, &[&INSTANCE, &TENANT, &dev.id, &[0x5f; 16]])
                .await,
            "{kind}"
        );
    }

    // No ACTIVE generation: no checkout.
    server
        .sql(
            "UPDATE v2_fleet_key_generations SET state = 'RETIRED', retired_at = 't'
              WHERE fleet_id = ?",
            &[&FLEET],
        )
        .await;
    server.sql("DELETE FROM v2_profile_leases", &[]).await;
    expect(
        &server,
        &checkout_path(P4),
        &access,
        &checkout(0x19, pref(P4), 0),
        (409, "FLEET_GENERATION_NOT_ACTIVE"),
    )
    .await;
}

/// Rewrites the stored response of `key` to an honest-looking one naming
/// `payload`, with every hash recomputed.
async fn forge(
    server: &Server,
    kind: OperationKind,
    key: u8,
    request: &[u8],
    record_type: &str,
    payload: Vec<u8>,
) {
    let outer = IdempotentMutationRequestV2::parse(request).unwrap();
    let forged = IdempotentStoredResponseV2 {
        operation_kind: kind,
        idempotency_key: [key; 16],
        exact_request_hash: outer.canonical_request_hash(),
        response_record_type: record_type.into(),
        canonical_response_payload_bytes: payload,
        server_instance_id: INSTANCE,
        restore_epoch: 0,
        committed_at_ms: now_ms(),
        receipt_id: [0x55; 16],
    }
    .encode();
    server
        .sql(
            "UPDATE v2_idempotency SET exact_response_bytes = ?, exact_response_bytes_sha256 = ?
              WHERE idempotency_key = ?",
            &[&forged, &shared::canonical::sha256(&forged), &[key; 16]],
        )
        .await;
}

#[tokio::test]
async fn a_stored_response_naming_another_profile_or_lease_is_never_replayed() {
    let mut server = start("forged", 28263).await;
    let (dev, access) = custodian(&mut server, 0x6c).await;
    fleets(&server).await;
    let c = (&dev, access.as_str());
    use CapabilityScopeKind as K;
    grant(
        &server,
        c,
        Some(&dev),
        0xa1,
        Capability::ProfilePublish,
        (K::Tenant, TENANT),
    )
    .await;
    grant(
        &server,
        c,
        Some(&dev),
        0xa2,
        Capability::ProfileCheckout,
        (K::Tenant, TENANT),
    )
    .await;
    let p = pref(P1);
    let pub_req = publish(0x01, p);
    let (status, body) = server.call(&publish_path(FLEET), &access, &pub_req).await;
    assert_eq!(status, 201);
    let first = granted(LeaseOrigin::PublishCreate, &body);
    let rel_req = release(0x02, p, first.lease);
    let rel = lease_path(P1, &first.lease.lease_id, "release");
    let (status, rel_body) = server.call(&rel, &access, &rel_req).await;
    assert_eq!(status, 200);
    let co_req = checkout(0x03, p, 0);
    let (status, co_body) = server.call(&checkout_path(P1), &access, &co_req).await;
    assert_eq!(status, 201);

    let mismatch = (422, "MUTATION_RESPONSE_MISMATCH");
    // Stands in for an attacker with DB write.
    server
        .sql("DROP TRIGGER v2_idempotency_succeeded_is_fixed", &[])
        .await;
    let elsewhere = ProfileLeaseV2 {
        profile: pref(P2),
        ..first.clone()
    };
    forge(
        &server,
        OperationKind::ProfilePublishCreate,
        0x01,
        &pub_req,
        RECORD_TYPE_PUBLISH_CREATED,
        elsewhere.encode(LeaseOrigin::PublishCreate),
    )
    .await;
    expect(&server, &publish_path(FLEET), &access, &pub_req, mismatch).await;

    let co = granted(LeaseOrigin::Checkout, &co_body);
    forge(
        &server,
        OperationKind::ProfileCheckout,
        0x03,
        &co_req,
        RECORD_TYPE_CHECKED_OUT,
        ProfileLeaseV2 {
            profile: pref(P2),
            ..co
        }
        .encode(LeaseOrigin::Checkout),
    )
    .await;
    expect(&server, &checkout_path(P1), &access, &co_req, mismatch).await;

    let released = LeaseReleasedV2::parse(
        &IdempotentStoredResponseV2::parse(&rel_body)
            .unwrap()
            .canonical_response_payload_bytes,
    )
    .unwrap();
    for wrong in [
        LeaseReleasedV2 {
            profile: pref(P2),
            ..released.clone()
        },
        LeaseReleasedV2 {
            lease: LeaseRef {
                fencing_token: 9,
                ..released.lease
            },
            ..released.clone()
        },
    ] {
        forge(
            &server,
            OperationKind::ReleaseLease,
            0x02,
            &rel_req,
            RECORD_TYPE_LEASE_RELEASED,
            wrong.encode(),
        )
        .await;
        expect(&server, &rel, &access, &rel_req, mismatch).await;
    }
}

// ------------------------------------------------- uploads and commits ---
//
// CREATE_UPLOAD, chunks, FINALIZE_UPLOAD and COMMIT (plan 8.1 L1145-L1176,
// 5.6.2, 5.6.5 L950/L951; G2-23, G2-24).

use shared::canonical::sha256;
use shared::envelope::{build_dek_slot, IntentIds, IntentNumbers, SlotIds};
use shared::envelope_v2::{build_intent_v2, seal, MAX_OBJECT_SIZE, MIN_FRAME_PLAINTEXT_SIZE};
use shared::profile_lease::{
    CreateUploadV2, UploadCreatedV2, UploadFinalizedV2, RECORD_TYPE_UPLOAD_CREATED,
    RECORD_TYPE_UPLOAD_FINALIZED,
};
use shared::snapshot_v2::{
    CommitReceiptBindingV2, CommitRequestV2, FinalizeUploadV2, LeaseReleaseOutcome,
    SignedSnapshotManifestV2, SnapshotManifestV2,
};

/// The FKEK itself: the server only ever sees its key ID, `FKEK`.
const FKEK_SECRET: [u8; 32] = [0x3e; 32];
const DEK: [u8; 32] = [0x2d; 32];
/// Three 64 KiB frames, the last one short.
const PLAINTEXT_LEN: usize = 150_000;
const CHUNK: usize = 65_536;

/// What a client seals and signs for one snapshot of `p` under `lease`.
#[derive(Clone)]
struct Snap {
    object: Vec<u8>,
    terms: CreateUploadV2,
    manifest: SnapshotManifestV2,
}

fn snap(p: ProfileRef, lease: LeaseRef, signer: &Device, tag: u8, prev: Option<[u8; 32]>) -> Snap {
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
            server_instance_id: INSTANCE,
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
    let plaintext: Vec<u8> = (0..PLAINTEXT_LEN)
        .map(|i| (i * 7 + usize::from(tag)) as u8)
        .collect();
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
        server_instance_id: INSTANCE,
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

impl Snap {
    /// The same snapshot over other bytes: terms and manifest name them.
    fn with_object(mut self, object: Vec<u8>) -> Self {
        let (size, sha) = (object.len() as u64, sha256(&object));
        self.terms.expected_ciphertext_size = size;
        self.terms.expected_ciphertext_sha256 = sha;
        self.manifest.ciphertext_size = size;
        self.manifest.ciphertext_sha256 = sha;
        self.object = object;
        self
    }
}

fn commit_request(
    m: &SnapshotManifestV2,
    signer: &Device,
    upload: [u8; 16],
    key: u8,
    nonce: u8,
) -> CommitRequestV2 {
    let signed = SignedSnapshotManifestV2::sign(&signer.sk, m).unwrap();
    CommitRequestV2::build(&signed, upload, [key; 16], [nonce; 16])
}

fn upload_req(key: u8, terms: &CreateUploadV2) -> Vec<u8> {
    outer(OperationKind::CreateUpload, key, terms.encode())
}

fn finalize_req(key: u8, c: &CommitRequestV2) -> Vec<u8> {
    outer(
        OperationKind::FinalizeUpload,
        key,
        FinalizeUploadV2::new(c.clone()).encode(),
    )
}

fn uploads_path(profile: [u8; 16]) -> String {
    format!("/v2/profiles/{}/uploads", hex(&profile))
}

fn upload_path(upload: &[u8; 16], action: &str) -> String {
    format!("/v2/uploads/{}/{action}", hex(upload))
}

fn snapshot_path(profile: [u8; 16], version: u64) -> String {
    format!("/v2/profiles/{}/snapshots/{version}", hex(&profile))
}

fn checkout_at(key: u8, p: ProfileRef, version: u64, head: Option<[u8; 32]>) -> Vec<u8> {
    let payload = ProfileCheckoutV2 {
        profile: p,
        observed_version: version,
        observed_signed_head_hash: head,
        requested_lease_ttl_seconds: 300,
    };
    outer(OperationKind::ProfileCheckout, key, payload.encode())
}

fn created(body: &[u8]) -> UploadCreatedV2 {
    let stored = IdempotentStoredResponseV2::parse(body).unwrap();
    assert_eq!(stored.response_record_type, RECORD_TYPE_UPLOAD_CREATED);
    UploadCreatedV2::parse(&stored.canonical_response_payload_bytes).unwrap()
}

impl Server {
    fn staging_file(&self, upload: &[u8; 16]) -> PathBuf {
        self.data
            .join("blobs")
            .join(hex(&TENANT))
            .join("staging")
            .join(format!("{}.part", hex(upload)))
    }

    fn object_file(&self, profile: [u8; 16], snapshot: &[u8; 16]) -> PathBuf {
        self.data
            .join("blobs")
            .join(hex(&TENANT))
            .join("objects")
            .join(hex(&profile))
            .join(format!("{}.bin", hex(snapshot)))
    }

    /// One chunk at `offset`, under its own digest unless `digest` is given:
    /// the status, the code and the returned offset.
    async fn chunk(
        &self,
        upload: &[u8; 16],
        bearer: &str,
        offset: usize,
        bytes: &[u8],
        digest: Option<[u8; 32]>,
    ) -> (u16, String, Option<u64>) {
        let r = client()
            .patch(format!(
                "http://127.0.0.1:{}/v2/uploads/{}",
                self.port,
                hex(upload)
            ))
            .header("upload-offset", offset.to_string())
            .header(
                "upload-chunk-sha256",
                hex(&digest.unwrap_or_else(|| sha256(bytes))),
            )
            .body(bytes.to_vec())
            .bearer_auth(bearer)
            .send()
            .await
            .unwrap();
        let status = r.status().as_u16();
        let offset = r
            .headers()
            .get("upload-offset")
            .map(|h| h.to_str().unwrap().parse().unwrap());
        (status, code(&r.bytes().await.unwrap()), offset)
    }

    async fn patch(
        &self,
        upload: &[u8; 16],
        bearer: &str,
        offset: usize,
        bytes: &[u8],
    ) -> (u16, String, Option<u64>) {
        self.chunk(upload, bearer, offset, bytes, None).await
    }

    /// `HEAD`: the status, and the offset and state it reports.
    async fn head(&self, upload: &[u8; 16], bearer: &str) -> (u16, Option<(u64, String)>) {
        let r = client()
            .head(format!(
                "http://127.0.0.1:{}/v2/uploads/{}",
                self.port,
                hex(upload)
            ))
            .bearer_auth(bearer)
            .send()
            .await
            .unwrap();
        let h = r.headers();
        let state = h
            .get("upload-offset")
            .zip(h.get("upload-state"))
            .map(|(o, s)| {
                (
                    o.to_str().unwrap().parse().unwrap(),
                    s.to_str().unwrap().to_string(),
                )
            });
        (r.status().as_u16(), state)
    }

    async fn get(
        &self,
        path: &str,
        bearer: &str,
        range: Option<&str>,
    ) -> (u16, reqwest::header::HeaderMap, Vec<u8>) {
        let mut req = client()
            .get(format!("http://127.0.0.1:{}{path}", self.port))
            .bearer_auth(bearer);
        if let Some(r) = range {
            req = req.header("range", r);
        }
        let r = req.send().await.unwrap();
        let (status, headers) = (r.status().as_u16(), r.headers().clone());
        (status, headers, r.bytes().await.unwrap().to_vec())
    }

    /// Creates the upload of `s` and sends all of `object` from `from`.
    async fn uploaded(&self, bearer: &str, key: u8, s: &Snap) -> [u8; 16] {
        let path = uploads_path(s.terms.profile.profile_id);
        let (status, body) = self.call(&path, bearer, &upload_req(key, &s.terms)).await;
        assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
        let id = created(&body).upload_id;
        self.send(&id, bearer, &s.object, 0).await;
        id
    }

    async fn send(&self, upload: &[u8; 16], bearer: &str, object: &[u8], from: usize) {
        for at in (from..object.len()).step_by(CHUNK) {
            let end = (at + CHUNK).min(object.len());
            let got = self.patch(upload, bearer, at, &object[at..end]).await;
            assert_eq!(got, (200, String::new(), Some(end as u64)), "chunk at {at}");
        }
    }
}

/// A refusal whose code is `code` and whose message names `field` first.
async fn expect_field(
    server: &Server,
    path: &str,
    bearer: &str,
    body: &[u8],
    code_want: &str,
    field: &str,
) {
    let (status, got) = server.call(path, bearer, body).await;
    let error = serde_json::from_slice::<Value>(&got).unwrap_or(Value::Null)["error"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert_eq!(
        (status, code(&got).as_str()),
        (422, code_want),
        "{field}: {error}"
    );
    assert!(error.starts_with(field), "{field}: {error}");
}

#[tokio::test]
async fn an_upload_commits_once_and_the_next_checkout_starts_at_its_head() {
    let mut server = start("commit", 28264).await;
    let (dev, access) = custodian(&mut server, 0x6c).await;
    fleets(&server).await;
    let c = (&dev, access.as_str());
    use CapabilityScopeKind as K;
    for (replay, capability, scope) in [
        (0xa1, Capability::ProfilePublish, (K::Tenant, TENANT)),
        (0xa2, Capability::ProfileCheckout, (K::Fleet, FLEET)),
        (0xa3, Capability::ProfileCommit, (K::Fleet, FLEET)),
    ] {
        grant(&server, c, Some(&dev), replay, capability, scope).await;
    }
    let p = pref(P1);
    let (status, body) = server
        .call(&publish_path(FLEET), &access, &publish(0x01, p))
        .await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    let first = granted(LeaseOrigin::PublishCreate, &body);

    // Create-upload binds the terms; its retry returns the same upload.
    let s1 = snap(p, first.lease, &dev, 0x11, None);
    let req = upload_req(0x02, &s1.terms);
    let (status, body) = server.call(&uploads_path(P1), &access, &req).await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    let up = created(&body);
    assert_eq!(up.terms, s1.terms);
    assert_eq!((up.server_instance_id, up.restore_epoch), (INSTANCE, 0));
    assert!(up.expires_at_ms > now_ms());
    assert_eq!(
        server.call(&uploads_path(P1), &access, &req).await,
        (201, body.clone())
    );
    let id = up.upload_id;
    for q in [
        "SELECT count(*) FROM v2_uploads WHERE state = 'OPEN' AND committed_offset = 0",
        "SELECT count(*) FROM v2_audit_events WHERE action = 'profile.create_upload'",
        "SELECT count(*) FROM v2_idempotency WHERE operation_kind = 'CREATE_UPLOAD'",
    ] {
        assert_eq!(server.count(q).await, 1, "{q}");
    }

    // Chunks land at the exact offset under their digest; an old offset is
    // a duplicate only with the same bytes.
    let o = &s1.object;
    let n = o.len();
    let at = |end: usize| (200, String::new(), Some(end as u64));
    assert_eq!(server.patch(&id, &access, 0, &o[..CHUNK]).await, at(CHUNK));
    assert_eq!(server.patch(&id, &access, 0, &o[..CHUNK]).await, at(CHUNK));
    let mismatch = |got: (u16, String, Option<u64>)| (got.0, got.1);
    let offset = (409, "UPLOAD_OFFSET_MISMATCH".to_string());
    assert_eq!(
        mismatch(server.patch(&id, &access, 0, &o[1..=CHUNK]).await),
        offset
    );
    assert_eq!(
        mismatch(server.patch(&id, &access, 2 * CHUNK, &o[2 * CHUNK..]).await),
        offset
    );
    assert_eq!(
        mismatch(
            server
                .chunk(&id, &access, CHUNK, &o[CHUNK..2 * CHUNK], Some([1; 32]))
                .await
        ),
        (422, "CIPHERTEXT_HASH_MISMATCH".to_string())
    );
    assert_eq!(
        mismatch(
            server
                .patch(&id, &access, CHUNK, &[&o[CHUNK..], &[0][..]].concat())
                .await
        ),
        (413, "SNAPSHOT_TOO_LARGE".to_string())
    );
    assert_eq!(
        server.head(&id, &access).await,
        (200, Some((CHUNK as u64, "OPEN".to_string())))
    );
    // A write that crashed before its offset committed left a tail; resume
    // drops it.
    let staging = server.staging_file(&id);
    let mut tail = std::fs::OpenOptions::new()
        .append(true)
        .open(&staging)
        .unwrap();
    tail.write_all(&vec![0x5c; n]).unwrap();
    drop(tail);
    // A chunk at the wrong offset is refused before it touches the file.
    let len = std::fs::metadata(&staging).unwrap().len();
    assert_eq!(
        mismatch(server.patch(&id, &access, 2 * CHUNK, &o[2 * CHUNK..]).await),
        offset
    );
    assert_eq!(std::fs::metadata(&staging).unwrap().len(), len);
    server.send(&id, &access, o, CHUNK).await;
    assert_eq!(
        server.count("SELECT count(*) FROM v2_upload_chunks").await,
        n.div_ceil(CHUNK) as i64
    );

    // Finalize: READY under the exact manifest and request, the object
    // immutable; its retry is the same READY receipt.
    let c1 = commit_request(&s1.manifest, &dev, id, 0x31, 0x41);
    let fin = finalize_req(0x03, &c1);
    let (status, body) = server
        .call(&upload_path(&id, "finalize"), &access, &fin)
        .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let stored = IdempotentStoredResponseV2::parse(&body).unwrap();
    assert_eq!(stored.response_record_type, RECORD_TYPE_UPLOAD_FINALIZED);
    let ready = UploadFinalizedV2::parse(&stored.canonical_response_payload_bytes).unwrap();
    assert_eq!(
        (ready.upload_id, ready.snapshot_id, ready.manifest_replay_id),
        (id, s1.terms.snapshot_id, s1.terms.manifest_replay_id)
    );
    assert_eq!(
        (ready.ciphertext_size, ready.ciphertext_sha256),
        (n as u64, sha256(o))
    );
    assert_eq!(
        server
            .call(&upload_path(&id, "finalize"), &access, &fin)
            .await,
        (200, body)
    );
    let object = server.object_file(P1, &s1.terms.snapshot_id);
    assert_eq!(std::fs::read(&object).unwrap(), *o);
    assert!(!staging.exists());
    assert_eq!(
        server.head(&id, &access).await,
        (200, Some((n as u64, "READY".to_string())))
    );
    assert_eq!(
        server
            .count("SELECT count(*) FROM v2_profiles WHERE current_version = 0")
            .await,
        1
    );

    // Commit: version 1, its signed head, the lease gone, all at once.
    let commit = upload_path(&id, "commit");
    let (status, receipt) = server.call(&commit, &access, c1.exact_bytes()).await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&receipt));
    let bound = CommitReceiptBindingV2::parse(&receipt).unwrap();
    bound.check_binds(&c1).unwrap();
    assert_eq!(
        (bound.resulting_version, bound.lease_release_outcome),
        (1, LeaseReleaseOutcome::Released)
    );
    for q in [
        "SELECT count(*) FROM v2_profiles WHERE current_version = 1",
        "SELECT count(*) FROM v2_snapshots WHERE version = 1 AND previous_head_hash IS NULL",
        "SELECT count(*) FROM v2_uploads WHERE state = 'COMMITTED'",
        "SELECT count(*) FROM v2_audit_events WHERE action = 'profile.commit'",
        "SELECT count(*) FROM v2_idempotency WHERE operation_kind = 'COMMIT'",
    ] {
        assert_eq!(server.count(q).await, 1, "{q}");
    }
    assert_eq!(
        server.count("SELECT count(*) FROM v2_profile_leases").await,
        0
    );
    // The retry after the lease is gone gets the same bytes; the same key
    // with another request is refused.
    assert_eq!(
        server.call(&commit, &access, c1.exact_bytes()).await,
        (201, receipt.clone())
    );
    let other = commit_request(&s1.manifest, &dev, id, 0x31, 0x42);
    expect(
        &server,
        &commit,
        &access,
        other.exact_bytes(),
        (409, "IDEMPOTENCY_MISMATCH"),
    )
    .await;
    expect(
        &server,
        &upload_path(&[0x66; 16], "commit"),
        &access,
        c1.exact_bytes(),
        (422, "AUTH_CLAIM_COLUMN_MISMATCH"),
    )
    .await;

    // Readback: the object whole or ranged, and the exact manifest.
    let (status, headers, bytes) = server.get(&snapshot_path(P1, 1), &access, None).await;
    assert_eq!((status, bytes == *o), (200, true));
    assert_eq!(headers["etag"], format!("\"{}\"", hex(&sha256(o))).as_str());
    assert_eq!(headers["shardx-key-generation"], "0");
    let (status, headers, bytes) = server
        .get(&snapshot_path(P1, 1), &access, Some("bytes=10-19"))
        .await;
    assert_eq!((status, bytes.as_slice()), (206, &o[10..20]));
    assert_eq!(
        headers["content-range"],
        format!("bytes 10-19/{n}").as_str()
    );
    let manifest_path = format!("{}/manifest", snapshot_path(P1, 1));
    let (status, _, manifest) = server.get(&manifest_path, &access, None).await;
    assert_eq!(
        (status, manifest.as_slice()),
        (200, c1.manifest().exact_bytes())
    );
    assert_eq!(
        server.get(&snapshot_path(P1, 2), &access, None).await.0,
        404
    );
    let head1 = c1.manifest().head_hash();

    // Checkout of version 1 names its stored head.
    let co = checkout_path(P1);
    let stale = (409, "BASE_VERSION_MISMATCH");
    expect(
        &server,
        &co,
        &access,
        &checkout_at(0x04, p, 1, Some([0x44; 32])),
        stale,
    )
    .await;
    expect(&server, &co, &access, &checkout(0x05, p, 0), stale).await;
    let (status, body) = server
        .call(&co, &access, &checkout_at(0x06, p, 1, Some(head1)))
        .await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    let second = granted(LeaseOrigin::Checkout, &body);
    assert_eq!(
        (second.lease.base_version, second.lease.fencing_token),
        (1, 2)
    );
    assert_eq!(second.current_signed_head_hash, Some(head1));

    // Version 2 chains from the stored head, or does not commit.
    let forked = snap(p, second.lease, &dev, 0x12, Some([0x45; 32]));
    let fid = server.uploaded(&access, 0x07, &forked).await;
    let fc = commit_request(&forked.manifest, &dev, fid, 0x32, 0x43);
    let (status, body) = server
        .call(
            &upload_path(&fid, "finalize"),
            &access,
            &finalize_req(0x08, &fc),
        )
        .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    expect(
        &server,
        &upload_path(&fid, "commit"),
        &access,
        fc.exact_bytes(),
        stale,
    )
    .await;
    let s2 = snap(p, second.lease, &dev, 0x13, Some(head1));
    let id2 = server.uploaded(&access, 0x09, &s2).await;
    // A finalize whose promote fails stays FINALIZING, its response stored
    // and its upload not yet committable. Its retry, after a crash past the
    // rename, finishes it with the same bytes.
    let object2 = server.object_file(P1, &s2.terms.snapshot_id);
    std::fs::create_dir_all(&object2).unwrap();
    let c2 = commit_request(&s2.manifest, &dev, id2, 0x33, 0x44);
    let fin2 = finalize_req(0x0a, &c2);
    let fin2_path = upload_path(&id2, "finalize");
    assert_eq!(server.call(&fin2_path, &access, &fin2).await.0, 500);
    assert_eq!(
        server.head(&id2, &access).await,
        (
            200,
            Some((s2.object.len() as u64, "FINALIZING".to_string()))
        )
    );
    assert_eq!(
        server.abort(&id2, &access).await,
        (409, "UPLOAD_STATE_CONFLICT".to_string())
    );
    // Only the finalize that stored it resumes it, and only under a live
    // lease.
    expect(
        &server,
        &fin2_path,
        &access,
        &finalize_req(0x0b, &c2),
        (409, "UPLOAD_OFFSET_MISMATCH"),
    )
    .await;
    let lease =
        |at: u64| format!("UPDATE v2_profile_leases SET expires_at_ms = {at} WHERE profile_id = ?");
    server.sql(&lease(1), &[&P1]).await;
    expect(&server, &fin2_path, &access, &fin2, (409, "LEASE_EXPIRED")).await;
    server.sql(&lease(now_ms() + 300_000), &[&P1]).await;
    expect(
        &server,
        &upload_path(&id2, "commit"),
        &access,
        c2.exact_bytes(),
        (409, "UPLOAD_STATE_CONFLICT"),
    )
    .await;
    std::fs::remove_dir(&object2).unwrap();
    std::fs::rename(server.staging_file(&id2), &object2).unwrap();
    let (status, body) = server.call(&fin2_path, &access, &fin2).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(server.call(&fin2_path, &access, &fin2).await, (200, body));
    let (status, receipt2) = server
        .call(&upload_path(&id2, "commit"), &access, c2.exact_bytes())
        .await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&receipt2));
    assert_eq!(
        CommitReceiptBindingV2::parse(&receipt2)
            .unwrap()
            .resulting_version,
        2
    );
    assert_eq!(
        server
            .count("SELECT count(*) FROM v2_snapshots WHERE version = 2 AND previous_head_hash IS NOT NULL")
            .await,
        1
    );

    // A stored receipt that does not bind its request is never replayed,
    // nor one whose snapshot a restore rolled back (ADR 0002 D-1).
    server
        .sql("DROP TRIGGER v2_idempotency_succeeded_is_fixed", &[])
        .await;
    let forged = CommitReceiptBindingV2 {
        snapshot_id: [0x77; 16],
        ..bound.clone()
    }
    .encode();
    let set_receipt = "UPDATE v2_idempotency SET exact_response_bytes = ?
                        WHERE idempotency_key = ? AND operation_kind = 'COMMIT'";
    server.sql(set_receipt, &[&forged, &[0x31; 16]]).await;
    expect(
        &server,
        &commit,
        &access,
        c1.exact_bytes(),
        (422, "RECEIPT_MISMATCH"),
    )
    .await;
    server.sql(set_receipt, &[&receipt, &[0x31; 16]]).await;
    assert_eq!(server.call(&commit, &access, c1.exact_bytes()).await.0, 201);
    server
        .sql("DELETE FROM v2_snapshots WHERE version = 1", &[])
        .await;
    expect(&server, &commit, &access, c1.exact_bytes(), stale).await;
}

#[tokio::test]
async fn every_upload_refusal_has_its_status_and_code() {
    let mut server = start("upload-refusals", 28265).await;
    let (dev, access) = custodian(&mut server, 0x6c).await;
    fleets(&server).await;
    let c = (&dev, access.as_str());
    use CapabilityScopeKind as K;
    for (replay, capability, scope) in [
        (0xa1, Capability::ProfilePublish, (K::Tenant, TENANT)),
        (0xa2, Capability::ProfileCheckout, (K::Tenant, TENANT)),
        (0xa3, Capability::ProfileCommit, (K::Fleet, FLEET)),
    ] {
        grant(&server, c, Some(&dev), replay, capability, scope).await;
    }
    // The peer holds `profile.commit` only through its account, which no
    // manifest signer may use (ADR 0002 D-2).
    let (other, other_access) = peer(&server, &dev, 0x7d).await;
    grant(
        &server,
        c,
        Some(&other),
        0xa4,
        Capability::ProfileCheckout,
        (K::Tenant, TENANT),
    )
    .await;
    grant(
        &server,
        c,
        None,
        0xa5,
        Capability::ProfileCommit,
        (K::Tenant, TENANT),
    )
    .await;
    let mut leases = Vec::new();
    for (key, profile) in [(0x01, P1), (0x02, P2), (0x03, P3), (0x04, P4)] {
        let (status, body) = server
            .call(&publish_path(FLEET), &access, &publish(key, pref(profile)))
            .await;
        assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
        leases.push(granted(LeaseOrigin::PublishCreate, &body).lease);
    }
    let (l1, l2, l3, l4) = (leases[0], leases[1], leases[2], leases[3]);
    let p1 = pref(P1);
    let up1 = uploads_path(P1);
    let s = snap(p1, l1, &dev, 0x11, None);
    let forbidden = (403, "");
    let gone = (404, "RESOURCE_NOT_FOUND");
    let expired = (409, "LEASE_EXPIRED");
    let no_key = (409, "FLEET_GENERATION_NOT_ACTIVE");
    let offset = (409, "UPLOAD_OFFSET_MISMATCH");
    let quarantined = (422, "UPLOAD_QUARANTINED");

    // CREATE_UPLOAD: path, tenant and epoch.
    let column = (422, "AUTH_CLAIM_COLUMN_MISMATCH");
    expect(
        &server,
        &uploads_path(P2),
        &access,
        &upload_req(0x10, &s.terms),
        column,
    )
    .await;
    let mut t = s.terms.clone();
    t.profile.tenant_id = [0x99; 16];
    expect(&server, &up1, &access, &upload_req(0x10, &t), forbidden).await;
    let epoch = outer_with(
        OperationKind::CreateUpload,
        0x10,
        s.terms.encode(),
        [0x92; 16],
        INSTANCE,
        1,
    );
    expect(&server, &up1, &access, &epoch, (409, "STALE_CONTEXT")).await;

    // The caller's own live lease with its exact fence, and a device-scoped
    // `profile.commit`.
    let release_path = lease_path(P3, &l3.lease_id, "release");
    assert_eq!(
        server
            .call(&release_path, &access, &release(0x05, pref(P3), l3))
            .await
            .0,
        200
    );
    let (status, body) = server
        .call(
            &checkout_path(P3),
            &other_access,
            &checkout(0x06, pref(P3), 0),
        )
        .await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    let l3o = granted(LeaseOrigin::Checkout, &body).lease;
    let theirs = snap(pref(P3), l3o, &other, 0x13, None);
    expect(
        &server,
        &uploads_path(P3),
        &other_access,
        &upload_req(0x11, &theirs.terms),
        forbidden,
    )
    .await;
    let not_mine = snap(pref(P3), l3o, &dev, 0x13, None);
    expect(
        &server,
        &uploads_path(P3),
        &access,
        &upload_req(0x12, &not_mine.terms),
        forbidden,
    )
    .await;
    let stale = snap(
        p1,
        LeaseRef {
            fencing_token: 9,
            ..l1
        },
        &dev,
        0x11,
        None,
    );
    expect(
        &server,
        &up1,
        &access,
        &upload_req(0x13, &stale.terms),
        (409, "FENCE_STALE"),
    )
    .await;
    // A lease ID that is not the profile's current lease.
    let replaced = LeaseRef {
        lease_id: [9; 16],
        ..l1
    };
    let replaced = snap(p1, replaced, &dev, 0x11, None);
    expect(
        &server,
        &up1,
        &access,
        &upload_req(0x13, &replaced.terms),
        expired,
    )
    .await;
    let release_path = lease_path(P2, &l2.lease_id, "release");
    assert_eq!(
        server
            .call(&release_path, &access, &release(0x07, pref(P2), l2))
            .await
            .0,
        200
    );
    let released = snap(pref(P2), l2, &dev, 0x12, None);
    expect(
        &server,
        &uploads_path(P2),
        &access,
        &upload_req(0x14, &released.terms),
        expired,
    )
    .await;
    server
        .sql(
            "UPDATE v2_profile_leases SET expires_at_ms = 1 WHERE profile_id = ?",
            &[&P4],
        )
        .await;
    let lapsed = snap(pref(P4), l4, &dev, 0x14, None);
    expect(
        &server,
        &uploads_path(P4),
        &access,
        &upload_req(0x15, &lapsed.terms),
        expired,
    )
    .await;

    // The fleet's ACTIVE generation and key; an active published profile of
    // the named fleet.
    let mut t = s.terms.clone();
    t.key_generation = 1;
    expect(&server, &up1, &access, &upload_req(0x16, &t), no_key).await;
    let mut t = s.terms.clone();
    t.fkek_key_id = [0xe9; 32];
    expect(&server, &up1, &access, &upload_req(0x16, &t), no_key).await;
    let mut t = s.terms.clone();
    // Another fleet is judged by its own grants first.
    t.profile.fleet_id = ARCHIVED;
    expect(&server, &up1, &access, &upload_req(0x16, &t), forbidden).await;
    let unpublished = snap(pref(P5), l1, &dev, 0x15, None);
    expect(
        &server,
        &uploads_path(P5),
        &access,
        &upload_req(0x16, &unpublished.terms),
        gone,
    )
    .await;

    // One snapshot ID and one manifest replay ID per upload.
    let (status, body) = server
        .call(&up1, &access, &upload_req(0x17, &s.terms))
        .await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    let u1 = created(&body).upload_id;
    let replayed = (422, "SNAPSHOT_REPLAY_MISMATCH");
    let mut t = s.terms.clone();
    t.manifest_replay_id = [0x55; 16];
    expect(&server, &up1, &access, &upload_req(0x18, &t), replayed).await;
    let mut t = s.terms.clone();
    t.snapshot_id = [0x56; 16];
    expect(&server, &up1, &access, &upload_req(0x18, &t), replayed).await;
    // One open upload per lease.
    let second = snap(p1, l1, &dev, 0x28, None);
    expect(
        &server,
        &up1,
        &access,
        &upload_req(0x0e, &second.terms),
        (429, "UPLOAD_CAPACITY"),
    )
    .await;
    // Another lease has its own slot.
    let (status, body) = server
        .call(&checkout_path(P2), &access, &checkout(0x08, pref(P2), 0))
        .await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    let l2b = granted(LeaseOrigin::Checkout, &body).lease;
    let own = snap(pref(P2), l2b, &dev, 0x29, None);
    let (status, body) = server
        .call(&uploads_path(P2), &access, &upload_req(0x0d, &own.terms))
        .await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));

    // PATCH and HEAD: only the lease holder.
    let o = &s.object;
    let n = o.len();
    let short = |got: (u16, String, Option<u64>)| (got.0, got.1);
    assert_eq!(
        short(server.patch(&u1, &other_access, 0, &o[..CHUNK]).await),
        (403, String::new())
    );
    assert_eq!(server.head(&u1, &other_access).await, (403, None));
    assert_eq!(server.head(&[0x66; 16], &access).await, (404, None));
    assert_eq!(
        server.patch(&u1, &access, 0, &o[..CHUNK]).await,
        (200, String::new(), Some(CHUNK as u64))
    );

    // FINALIZE_UPLOAD: the whole object, the path, the tenant, the signer
    // and every binding.
    let fin = upload_path(&u1, "finalize");
    let c1 = commit_request(&s.manifest, &dev, u1, 0x30, 0x40);
    expect(&server, &fin, &access, &finalize_req(0x20, &c1), offset).await;
    server.send(&u1, &access, o, CHUNK).await;
    let elsewhere = upload_path(&[0x66; 16], "finalize");
    expect(
        &server,
        &elsewhere,
        &access,
        &finalize_req(0x20, &c1),
        column,
    )
    .await;
    let mut m = s.manifest.clone();
    m.tenant_id = [0x99; 16];
    let foreign = commit_request(&m, &dev, u1, 0x30, 0x40);
    expect(
        &server,
        &fin,
        &access,
        &finalize_req(0x20, &foreign),
        forbidden,
    )
    .await;
    let mut m = s.manifest.clone();
    m.signer_signing_key_id = other.signing_key_id;
    let by_other = commit_request(&m, &other, u1, 0x30, 0x40);
    expect(
        &server,
        &fin,
        &access,
        &finalize_req(0x20, &by_other),
        (422, "KEY_SUBSTITUTION_DETECTED"),
    )
    .await;
    type Edit = fn(&mut SnapshotManifestV2);
    let edits: [(&str, Edit); 16] = [
        ("profile_id", |m| m.profile_id = P2),
        ("fleet_id", |m| m.fleet_id = ARCHIVED),
        ("snapshot_id", |m| m.snapshot_id = [1; 16]),
        ("manifest_replay_id", |m| m.manifest_replay_id = [1; 16]),
        ("lease_id", |m| m.lease_id = [1; 16]),
        ("fencing_token", |m| m.fencing_token = 9),
        ("base_version", |m| {
            m.base_version = 1;
            m.target_version = 2;
            m.previous_signed_head_hash = Some([1; 32]);
        }),
        ("intent_hash", |m| m.intent_hash = [1; 32]),
        ("preamble_sha256", |m| m.preamble_sha256 = [1; 32]),
        ("dek_slot_sha256", |m| m.dek_slot_sha256 = [1; 32]),
        ("fkek_key_id", |m| m.fkek_key_id = [1; 32]),
        ("key_generation", |m| m.key_generation = 1),
        ("ciphertext_size", |m| m.ciphertext_size -= 1),
        ("ciphertext_sha256", |m| m.ciphertext_sha256 = [1; 32]),
        ("server_instance_id", |m| m.server_instance_id = [1; 16]),
        ("restore_epoch", |m| m.restore_epoch = 1),
    ];
    for (field, edit) in edits {
        let mut m = s.manifest.clone();
        edit(&mut m);
        let r = commit_request(&m, &dev, u1, 0x30, 0x40);
        expect_field(
            &server,
            &fin,
            &access,
            &finalize_req(0x20, &r),
            "MANIFEST_REPLAY_MISMATCH",
            field,
        )
        .await;
    }
    let revoke = "UPDATE v2_capability_grants SET revoked_at = 't' WHERE replay_id = ?";
    server.sql(revoke, &[&[0xa3; 16]]).await;
    expect(&server, &fin, &access, &finalize_req(0x20, &c1), forbidden).await;
    grant(
        &server,
        c,
        Some(&dev),
        0xa6,
        Capability::ProfileCommit,
        (K::Profile, P1),
    )
    .await;
    // Two finalizes at once: one is READY, the other is told to HEAD.
    let (f1, f2) = (finalize_req(0x21, &c1), finalize_req(0x26, &c1));
    let (a, b) = tokio::join!(
        server.call(&fin, &access, &f1),
        server.call(&fin, &access, &f2)
    );
    let mut got = [(a.0, code(&a.1)), (b.0, code(&b.1))];
    got.sort();
    assert_eq!(
        got,
        [(200, String::new()), (409, "UPLOAD_OFFSET_MISMATCH".into())]
    );
    // READY takes no more chunks and no second finalize.
    assert_eq!(
        short(server.patch(&u1, &access, 0, &o[..CHUNK]).await),
        (409, "UPLOAD_OFFSET_MISMATCH".into())
    );
    expect(&server, &fin, &access, &finalize_req(0x22, &c1), offset).await;

    // Objects that do not match their terms are quarantined, with evidence.
    let flipped = {
        let mut f = snap(p1, l1, &dev, 0x21, None);
        let terms = f.terms.clone();
        let manifest = f.manifest.clone();
        let mut bytes = f.object.clone();
        bytes[n / 2] ^= 1;
        f = f.with_object(bytes);
        f.terms = terms;
        f.manifest = manifest;
        f
    };
    let trailing = {
        let f = snap(p1, l1, &dev, 0x22, None);
        let bytes = [&f.object[..], &[0][..]].concat();
        f.with_object(bytes)
    };
    let mut misnamed = snap(p1, l1, &dev, 0x23, None);
    misnamed.terms.manifest_replay_id = [0x5a; 16];
    misnamed.manifest.manifest_replay_id = [0x5a; 16];
    // A refused finalize keeps its key: its retry is told the quarantine.
    for (key, f, want, fin_key) in [
        (0x19, &flipped, (422, "CIPHERTEXT_HASH_MISMATCH"), 0x23),
        (0x1a, &trailing, quarantined, 0x27),
        (0x1b, &misnamed, quarantined, 0x28),
    ] {
        let id = server.uploaded(&access, key, f).await;
        let r = commit_request(&f.manifest, &dev, id, 0x34, 0x40);
        let path = upload_path(&id, "finalize");
        expect(&server, &path, &access, &finalize_req(fin_key, &r), want).await;
        expect(
            &server,
            &path,
            &access,
            &finalize_req(fin_key, &r),
            quarantined,
        )
        .await;
        assert_eq!(server.head(&id, &access).await.1.unwrap().1, "QUARANTINED");
        let commit = upload_path(&id, "commit");
        expect(&server, &commit, &access, r.exact_bytes(), quarantined).await;
        assert_eq!(
            server.abort(&id, &access).await,
            (422, "UPLOAD_QUARANTINED".to_string())
        );
    }
    assert_eq!(
        server
            .count("SELECT count(*) FROM v2_audit_events WHERE action = 'upload.quarantine'")
            .await,
        3
    );
    // A staging file shorter than the offset, or missing, cannot resume.
    let truncated = snap(p1, l1, &dev, 0x24, None);
    let (status, body) = server
        .call(&up1, &access, &upload_req(0x1c, &truncated.terms))
        .await;
    assert_eq!(status, 201);
    let tid = created(&body).upload_id;
    assert_eq!(
        server
            .patch(&tid, &access, 0, &truncated.object[..CHUNK])
            .await
            .0,
        200
    );
    std::fs::OpenOptions::new()
        .write(true)
        .open(server.staging_file(&tid))
        .unwrap()
        .set_len(10)
        .unwrap();
    let next = &truncated.object[CHUNK..2 * CHUNK];
    assert_eq!(
        short(server.patch(&tid, &access, CHUNK, next).await),
        (422, "UPLOAD_QUARANTINED".into())
    );
    assert_eq!(
        short(server.patch(&tid, &access, CHUNK, next).await),
        (422, "UPLOAD_QUARANTINED".into())
    );
    let missing = snap(p1, l1, &dev, 0x25, None);
    let (status, body) = server
        .call(&up1, &access, &upload_req(0x1d, &missing.terms))
        .await;
    assert_eq!(status, 201);
    let mid = created(&body).upload_id;
    // At offset 0 a missing file is an empty one (L1193); past it, gone.
    std::fs::remove_file(server.staging_file(&mid)).unwrap();
    assert_eq!(
        short(
            server
                .patch(&mid, &access, 0, &missing.object[..CHUNK])
                .await
        ),
        (200, String::new())
    );
    std::fs::remove_file(server.staging_file(&mid)).unwrap();
    assert_eq!(
        short(
            server
                .patch(&mid, &access, CHUNK, &missing.object[CHUNK..2 * CHUNK])
                .await
        ),
        (422, "UPLOAD_QUARANTINED".into())
    );
    assert!(!server.staging_file(&mid).exists());

    // An upload past its expiry is gone (stands in for a day passing).
    server
        .sql("DROP TRIGGER v2_uploads_terms_are_fixed", &[])
        .await;
    let late = snap(p1, l1, &dev, 0x26, None);
    let lid = server.uploaded(&access, 0x1e, &late).await;
    let lapse = "UPDATE v2_uploads SET expires_at_ms = 1 WHERE upload_id = ?";
    server.sql(lapse, &[&lid]).await;
    // Complete, for a finalize after the lease lapsed. Its create aborts the
    // expired upload and deletes its staging file, but keeps the evidence of
    // a quarantine.
    let unleased = snap(p1, l1, &dev, 0x27, None);
    let nid = server.uploaded(&access, 0x1f, &unleased).await;
    assert!(!server.staging_file(&lid).exists());
    assert!(server.staging_file(&tid).exists());
    assert_eq!(
        server
            .count("SELECT count(*) FROM v2_uploads WHERE state = 'ABORTED'")
            .await,
        1
    );
    assert_eq!(
        short(server.patch(&lid, &access, 0, &late.object[..CHUNK]).await),
        (404, "RESOURCE_NOT_FOUND".into())
    );
    let lr = commit_request(&late.manifest, &dev, lid, 0x35, 0x40);
    expect(
        &server,
        &upload_path(&lid, "finalize"),
        &access,
        &finalize_req(0x24, &lr),
        gone,
    )
    .await;

    // COMMIT: the exact finalized request, `profile.commit`, the base and
    // head, the ACTIVE generation and the live lease.
    let commit = upload_path(&u1, "commit");
    server.sql(lapse, &[&u1]).await;
    expect(&server, &commit, &access, c1.exact_bytes(), gone).await;
    server
        .sql(
            "UPDATE v2_uploads SET expires_at_ms = created_at_ms + 86400000 WHERE upload_id = ?",
            &[&u1],
        )
        .await;
    let renonced = commit_request(&s.manifest, &dev, u1, 0x30, 0x4f);
    expect_field(
        &server,
        &commit,
        &access,
        renonced.exact_bytes(),
        "MANIFEST_REPLAY_MISMATCH",
        "exact_commit_request_bytes",
    )
    .await;
    server.sql(revoke, &[&[0xa6; 16]]).await;
    expect(&server, &commit, &access, c1.exact_bytes(), forbidden).await;
    grant(
        &server,
        c,
        Some(&dev),
        0xa7,
        Capability::ProfileCommit,
        (K::Tenant, TENANT),
    )
    .await;
    let version = |n: u8| format!("UPDATE v2_profiles SET current_version = {n} WHERE id = ?");
    server.sql(&version(5), &[&P1]).await;
    expect(
        &server,
        &commit,
        &access,
        c1.exact_bytes(),
        (409, "BASE_VERSION_MISMATCH"),
    )
    .await;
    server.sql(&version(0), &[&P1]).await;
    server
        .sql(
            "UPDATE v2_fleet_key_generations SET state = 'RETIRED', retired_at = 't'
              WHERE fleet_id = ? AND generation = 0",
            &[&FLEET],
        )
        .await;
    server
        .sql(
            "INSERT INTO v2_fleet_key_generations
                 (server_instance_id, tenant_id, fleet_id, generation, fkek_key_id,
                  root_generation, state, created_at, activated_at)
             VALUES (?, ?, ?, 1, ?, 0, 'ACTIVE', 't', 't')",
            &[&INSTANCE, &TENANT, &FLEET, &[0xe1; 32]],
        )
        .await;
    expect(&server, &commit, &access, c1.exact_bytes(), no_key).await;
    server
        .sql(
            "UPDATE v2_profile_leases SET expires_at_ms = 1 WHERE profile_id = ?",
            &[&P1],
        )
        .await;
    expect(&server, &commit, &access, c1.exact_bytes(), expired).await;
    let nr = commit_request(&unleased.manifest, &dev, nid, 0x36, 0x40);
    let nfin = upload_path(&nid, "finalize");
    expect(&server, &nfin, &access, &finalize_req(0x25, &nr), expired).await;

    // ADR 0002 D-1: an upload from before a restore is gone, and so are the
    // stored responses that name it.
    server
        .sql(
            "UPDATE v2_uploads SET restore_epoch = 1 WHERE upload_id = ?",
            &[&u1],
        )
        .await;
    // Whichever of the two finalizes won is a stored response.
    expect(&server, &fin, &access, &f1, gone).await;
    expect(&server, &fin, &access, &f2, gone).await;
    expect(&server, &commit, &access, c1.exact_bytes(), gone).await;
    expect(&server, &up1, &access, &upload_req(0x17, &s.terms), gone).await;
    assert_eq!(server.head(&u1, &access).await, (404, None));
}

impl Server {
    /// Stops the server and starts it on the same data: the upload
    /// reconciler runs before it serves (plan L1216).
    async fn restart(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.child = launch(&self.data, self.port);
        wait_health(self.port).await;
    }

    /// `DELETE /v2/uploads/{upload_id}`: the status and the code.
    async fn abort(&self, upload: &[u8; 16], bearer: &str) -> (u16, String) {
        let r = client()
            .delete(format!(
                "http://127.0.0.1:{}/v2/uploads/{}",
                self.port,
                hex(upload)
            ))
            .bearer_auth(bearer)
            .send()
            .await
            .unwrap();
        (r.status().as_u16(), code(&r.bytes().await.unwrap()))
    }
}

#[tokio::test]
async fn a_restart_reconciles_uploads_and_an_abort_frees_the_lease_slot() {
    let mut server = start("reconcile", 28266).await;
    let (dev, access) = custodian(&mut server, 0x6c).await;
    fleets(&server).await;
    let c = (&dev, access.as_str());
    use CapabilityScopeKind as K;
    for (replay, capability, scope) in [
        (0xa1, Capability::ProfilePublish, (K::Tenant, TENANT)),
        (0xa2, Capability::ProfileCheckout, (K::Fleet, FLEET)),
        (0xa3, Capability::ProfileCommit, (K::Fleet, FLEET)),
    ] {
        grant(&server, c, Some(&dev), replay, capability, scope).await;
    }
    let p = pref(P1);
    let (status, body) = server
        .call(&publish_path(FLEET), &access, &publish(0x01, p))
        .await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    let first = granted(LeaseOrigin::PublishCreate, &body);

    // A finalize that crashed past its rename: FINALIZING, the object in
    // place, the staging file gone. The restart makes it READY (L1199).
    let s1 = snap(p, first.lease, &dev, 0x11, None);
    let id = server.uploaded(&access, 0x02, &s1).await;
    let object = server.object_file(P1, &s1.terms.snapshot_id);
    std::fs::create_dir_all(&object).unwrap();
    let c1 = commit_request(&s1.manifest, &dev, id, 0x31, 0x41);
    let fin = finalize_req(0x03, &c1);
    let fin_path = upload_path(&id, "finalize");
    assert_eq!(server.call(&fin_path, &access, &fin).await.0, 500);
    std::fs::remove_dir(&object).unwrap();
    std::fs::rename(server.staging_file(&id), &object).unwrap();
    server.restart().await;
    let n = s1.object.len() as u64;
    assert_eq!(
        server.head(&id, &access).await,
        (200, Some((n, "READY".to_string())))
    );
    let (status, body) = server.call(&fin_path, &access, &fin).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let (status, receipt) = server
        .call(&upload_path(&id, "commit"), &access, c1.exact_bytes())
        .await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&receipt));
    let head1 = c1.manifest().head_hash();

    // Abort: the lease holder's, idempotent, and it frees the lease's one
    // upload slot.
    let (status, body) = server
        .call(
            &checkout_path(P1),
            &access,
            &checkout_at(0x04, p, 1, Some(head1)),
        )
        .await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    let second = granted(LeaseOrigin::Checkout, &body);
    let s2 = snap(p, second.lease, &dev, 0x12, Some(head1));
    let (status, body) = server
        .call(&uploads_path(P1), &access, &upload_req(0x05, &s2.terms))
        .await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    let id2 = created(&body).upload_id;
    assert_eq!(
        server.patch(&id2, &access, 0, &s2.object[..CHUNK]).await.0,
        200
    );
    let s3 = snap(p, second.lease, &dev, 0x13, Some(head1));
    let third = upload_req(0x06, &s3.terms);
    expect(
        &server,
        &uploads_path(P1),
        &access,
        &third,
        (429, "UPLOAD_CAPACITY"),
    )
    .await;
    assert_eq!(server.abort(&id2, &access).await, (204, String::new()));
    assert_eq!(server.abort(&id2, &access).await, (204, String::new()));
    assert!(!server.staging_file(&id2).exists());
    assert_eq!(
        server.head(&id2, &access).await,
        (200, Some((CHUNK as u64, "ABORTED".to_string())))
    );
    assert_eq!(
        server
            .patch(&id2, &access, CHUNK, &s2.object[CHUNK..2 * CHUNK])
            .await
            .1,
        "UPLOAD_OFFSET_MISMATCH"
    );
    assert_eq!(
        server.abort(&id, &access).await,
        (409, "UPLOAD_STATE_CONFLICT".to_string())
    );
    assert_eq!(
        server.abort(&[0x66; 16], &access).await,
        (404, "RESOURCE_NOT_FOUND".to_string())
    );
    let (status, body) = server.call(&uploads_path(P1), &access, &third).await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    assert_eq!(
        server
            .count("SELECT count(*) FROM v2_audit_events WHERE action = 'upload.abort'")
            .await,
        1
    );

    // A READY upload aborts too, by the lease holder with `profile.commit`
    // only, and never commits after; its object stays (L1176).
    let id3 = created(&body).upload_id;
    server.send(&id3, &access, &s3.object, 0).await;
    let c3 = commit_request(&s3.manifest, &dev, id3, 0x32, 0x42);
    let (status, body) = server
        .call(
            &upload_path(&id3, "finalize"),
            &access,
            &finalize_req(0x07, &c3),
        )
        .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let lease =
        |at: u64| format!("UPDATE v2_profile_leases SET expires_at_ms = {at} WHERE profile_id = ?");
    server.sql(&lease(1), &[&P1]).await;
    assert_eq!(
        server.abort(&id3, &access).await,
        (409, "LEASE_EXPIRED".to_string())
    );
    server.sql(&lease(now_ms() + 300_000), &[&P1]).await;
    let revoke = "UPDATE v2_capability_grants SET revoked_at = 't' WHERE replay_id = ?";
    server.sql(revoke, &[&[0xa3; 16]]).await;
    assert_eq!(server.abort(&id3, &access).await.0, 403);
    grant(
        &server,
        c,
        Some(&dev),
        0xa4,
        Capability::ProfileCommit,
        (K::Fleet, FLEET),
    )
    .await;
    assert_eq!(server.abort(&id3, &access).await, (204, String::new()));
    expect(
        &server,
        &upload_path(&id3, "commit"),
        &access,
        c3.exact_bytes(),
        (409, "UPLOAD_STATE_CONFLICT"),
    )
    .await;
    let object3 = server.object_file(P1, &s3.terms.snapshot_id);
    assert!(object3.exists());

    // L1210: a corrupt committed object is a security incident: its snapshot
    // is no longer served nor its receipt replayed. The aborted object is
    // not GC's.
    let mut corrupt = std::fs::read(&object).unwrap();
    corrupt[0] ^= 1;
    std::fs::write(&object, corrupt).unwrap();
    server.restart().await;
    expect_get(&server, &snapshot_path(P1, 1), &access).await;
    expect(
        &server,
        &upload_path(&id, "commit"),
        &access,
        c1.exact_bytes(),
        (422, "UPLOAD_QUARANTINED"),
    )
    .await;
    expect(
        &server,
        &fin_path,
        &access,
        &fin,
        (422, "UPLOAD_QUARANTINED"),
    )
    .await;
    assert_eq!(
        server
            .count(
                "SELECT count(*) FROM v2_upload_quarantine
                  WHERE reason = 'object_invalid' AND security_incident = 1
                    AND from_state = 'COMMITTED'"
            )
            .await,
        1
    );
    assert_eq!(server.head(&id3, &access).await.1.unwrap().1, "ABORTED");
    assert!(object3.exists());
}

/// A snapshot readback refused as quarantined.
async fn expect_get(server: &Server, path: &str, bearer: &str) {
    let (status, _, body) = server.get(path, bearer, None).await;
    assert_eq!((status, code(&body).as_str()), (422, "UPLOAD_QUARANTINED"));
}

// ------------------------------------------------------------ fleet list ---

use shared::fleet_profiles::{FleetProfileHeadV2, FleetProfilePageV2, MAX_FLEET_PROFILE_PAGE};

fn list_path(fleet: [u8; 16], query: &str) -> String {
    format!("/v2/fleets/{}/profiles{query}", hex(&fleet))
}

/// One page of `fleet`'s list, which must be served.
async fn page(server: &Server, bearer: &str, fleet: [u8; 16], query: &str) -> FleetProfilePageV2 {
    let (status, headers, body) = server.get(&list_path(fleet, query), bearer, None).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(headers["content-type"], "application/cbor");
    FleetProfilePageV2::parse(&body).unwrap()
}

async fn list_refused(server: &Server, bearer: &str, fleet: [u8; 16], want: (u16, &str)) {
    let (status, _, body) = server.get(&list_path(fleet, ""), bearer, None).await;
    assert_eq!((status, code(&body).as_str()), want, "{}", hex(&fleet));
}

/// The ID `[tag, i >> 8, i, 0..]`.
fn row_id(tag: u8, i: u16) -> [u8; 16] {
    let mut id = [0u8; 16];
    id[..3].copy_from_slice(&[tag, (i >> 8) as u8, i as u8]);
    id
}

/// Inserts `n` published, active version-0 profiles of `fleet` in `tenant`,
/// with the IDs [`row_id`] of `tag`.
async fn published_rows(server: &Server, tenant: [u8; 16], fleet: [u8; 16], tag: u8, n: u16) {
    let rows = (0..n)
        .map(|i| {
            let id = hex(&row_id(tag, i));
            format!(
                "(x'{id}', x'{}', x'{}', '{id}', 0, 'active', 't', 't', x'5a', 0, 0)",
                hex(&tenant),
                hex(&fleet)
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    server
        .sql(
            &format!(
                "INSERT INTO v2_profiles
                     (id, tenant_id, fleet_id, name, current_version, status, created_at,
                      updated_at, label_ciphertext, last_fencing_token, current_key_generation)
                 VALUES {rows}"
            ),
            &[],
        )
        .await;
}

fn ids(p: &FleetProfilePageV2) -> Vec<[u8; 16]> {
    p.profiles.iter().map(|h| h.profile_id).collect()
}

/// Another tenant, `foreign`, with an active fleet `fleet`.
async fn foreign_fleet(server: &Server, foreign: [u8; 16], fleet: [u8; 16]) {
    server
        .sql(
            "INSERT INTO v2_tenants VALUES (?, 'other', 'active', NULL, 't')",
            &[&foreign],
        )
        .await;
    server
        .sql(
            "INSERT INTO v2_fleets (id, tenant_id, name, status, created_at)
             VALUES (?, ?, 'f', 'active', 't')",
            &[&fleet, &foreign],
        )
        .await;
}

#[tokio::test]
async fn the_fleet_list_shows_each_published_head_in_bounded_pages_without_a_lease() {
    let mut server = start("list", 28281).await;
    let (dev, access) = custodian(&mut server, 0x6c).await;
    fleets(&server).await;
    let c = (&dev, access.as_str());
    use CapabilityScopeKind as K;
    for (replay, capability, scope) in [
        (0xa1, Capability::ProfilePublish, (K::Tenant, TENANT)),
        (0xa2, Capability::ProfileCheckout, (K::Fleet, FLEET)),
        (0xa3, Capability::ProfileCommit, (K::Fleet, FLEET)),
    ] {
        grant(&server, c, Some(&dev), replay, capability, scope).await;
    }

    // An empty fleet is one empty last page naming this instance and fleet.
    assert_eq!(
        page(&server, &access, FLEET, "").await,
        FleetProfilePageV2 {
            server_instance_id: INSTANCE,
            restore_epoch: 0,
            tenant_id: TENANT,
            fleet_id: FLEET,
            profiles: vec![],
            next_after: None,
        }
    );

    // Two published profiles at version 0, in ID order whatever the publish
    // order, each with its exact label ciphertext and no head.
    let (status, body) = server
        .call(&publish_path(FLEET), &access, &publish(0x02, pref(P2)))
        .await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    let (status, body) = server
        .call(&publish_path(FLEET), &access, &publish(0x01, pref(P1)))
        .await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    let first = granted(LeaseOrigin::PublishCreate, &body);
    let at_zero = |id| FleetProfileHeadV2 {
        profile_id: id,
        current_version: 0,
        current_signed_head_hash: None,
        key_generation: 0,
        label_ciphertext: vec![0x33; 24],
    };
    assert_eq!(
        page(&server, &access, FLEET, "").await.profiles,
        vec![at_zero(P1), at_zero(P2)]
    );

    // Not listed: a legacy profile, an archived one, one of another fleet,
    // and one of another tenant's fleet under the same fleet ID.
    server
        .sql(
            "INSERT INTO v2_profiles (id, tenant_id, fleet_id, name, status, created_at, updated_at)
             VALUES (?, ?, ?, 'legacy', 'active', 't', 't')",
            &[&P3, &TENANT, &FLEET],
        )
        .await;
    published_rows(&server, TENANT, FLEET, 0xc4, 1).await;
    server
        .sql(
            "UPDATE v2_profiles SET status = 'archived' WHERE id = ?",
            &[&row_id(0xc4, 0)],
        )
        .await;
    let other_fleet = [0xf7; 16];
    server
        .sql(
            "INSERT INTO v2_fleets (id, tenant_id, name, status, created_at)
             VALUES (?, ?, 'o', 'active', 't')",
            &[&other_fleet, &TENANT],
        )
        .await;
    published_rows(&server, TENANT, other_fleet, 0xc5, 1).await;
    let foreign = [0x42; 16];
    foreign_fleet(&server, foreign, FLEET).await;
    published_rows(&server, foreign, FLEET, 0xc6, 1).await;
    assert_eq!(ids(&page(&server, &access, FLEET, "").await), vec![P1, P2]);
    assert_eq!(ids(&page(&server, &access, FLEET, "?").await), vec![P1, P2]);

    // Listing took no lease, fence, stored response or audit row.
    let state = "SELECT (SELECT count(*) FROM v2_profile_leases) * 1000000
                      + (SELECT sum(last_fencing_token) FROM v2_profiles) * 10000
                      + (SELECT count(*) FROM v2_idempotency) * 100
                      + (SELECT count(*) FROM v2_audit_events)";
    let before = server.count(state).await;
    page(&server, &access, FLEET, "").await;
    assert_eq!(server.count(state).await, before);

    // After a commit, P1 shows version 1 and the head that commit stored,
    // under the profile's key generation.
    let s1 = snap(pref(P1), first.lease, &dev, 0x11, None);
    let id = server.uploaded(&access, 0x03, &s1).await;
    let c1 = commit_request(&s1.manifest, &dev, id, 0x31, 0x41);
    let (status, body) = server
        .call(
            &upload_path(&id, "finalize"),
            &access,
            &finalize_req(0x04, &c1),
        )
        .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let (status, body) = server
        .call(&upload_path(&id, "commit"), &access, c1.exact_bytes())
        .await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    server
        .sql(
            "UPDATE v2_profiles SET current_key_generation = 7 WHERE id = ?",
            &[&P1],
        )
        .await;
    // A head of the same profile ID and version under another tenant or
    // another instance is not P1's (profile IDs are per tenant).
    server
        .sql(
            &format!(
                "PRAGMA foreign_keys = OFF;
                 CREATE TEMP TABLE stray AS SELECT * FROM v2_snapshots WHERE profile_id = x'{p1}';
                 UPDATE stray SET tenant_id = x'{foreign}', head_hash = randomblob(32);
                 INSERT INTO v2_snapshots SELECT * FROM stray;
                 UPDATE stray SET tenant_id = x'{tenant}', server_instance_id = x'{instance}',
                                  head_hash = randomblob(32);
                 INSERT INTO v2_snapshots SELECT * FROM stray;",
                p1 = hex(&P1),
                foreign = hex(&foreign),
                tenant = hex(&TENANT),
                instance = hex(&[0x09; 16]),
            ),
            &[],
        )
        .await;
    assert_eq!(
        server
            .count(&format!(
                "SELECT count(*) FROM v2_snapshots WHERE profile_id = x'{}'",
                hex(&P1)
            ))
            .await,
        3
    );
    let head1 = FleetProfileHeadV2 {
        profile_id: P1,
        current_version: 1,
        current_signed_head_hash: Some(c1.manifest().head_hash()),
        key_generation: 7,
        label_ciphertext: vec![0x33; 24],
    };
    assert_eq!(
        page(&server, &access, FLEET, "").await.profiles,
        vec![head1.clone(), at_zero(P2)]
    );
    // That head is the one a checkout must observe.
    let (status, body) = server
        .call(
            &checkout_path(P1),
            &access,
            &checkout_at(0x05, pref(P1), 1, head1.current_signed_head_hash),
        )
        .await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    // A version without its stored head fails closed rather than list it
    // without one.
    server
        .sql(
            "UPDATE v2_profiles SET current_version = 2 WHERE id = ?",
            &[&P1],
        )
        .await;
    list_refused(&server, &access, FLEET, (422, "AUTH_CLAIM_COLUMN_MISMATCH")).await;
    server
        .sql(
            "UPDATE v2_profiles SET current_version = 1 WHERE id = ?",
            &[&P1],
        )
        .await;

    // `after` starts past that ID.
    let after_p1 = format!("?after={}", hex(&P1));
    assert_eq!(
        ids(&page(&server, &access, FLEET, &after_p1).await),
        vec![P2]
    );
    let after_p2 = format!("?after={}", hex(&P2));
    assert_eq!(
        page(&server, &access, FLEET, &after_p2).await.profiles,
        vec![]
    );

    // A full last page names no next page; one more profile moves the last
    // to a second page, and the pages together are every ID in order.
    published_rows(
        &server,
        TENANT,
        FLEET,
        0xd0,
        MAX_FLEET_PROFILE_PAGE as u16 - 2,
    )
    .await;
    let full = page(&server, &access, FLEET, "").await;
    assert_eq!(
        (full.profiles.len(), full.next_after),
        (MAX_FLEET_PROFILE_PAGE, None)
    );
    published_rows(&server, TENANT, FLEET, 0xd1, 1).await;
    let one = page(&server, &access, FLEET, "").await;
    let last = one.profiles.last().unwrap().profile_id;
    assert_eq!(one.next_after, Some(last));
    assert_eq!(ids(&one), ids(&full));
    let two = page(&server, &access, FLEET, &format!("?after={}", hex(&last))).await;
    assert_eq!((ids(&two), two.next_after), (vec![row_id(0xd1, 0)], None));

    // The query takes one `after` ID and nothing else.
    for q in [
        "?after=zz".to_string(),
        format!("?after={}0", hex(&P1)),
        format!("?after={}&after={}", hex(&P1), hex(&P2)),
        format!("?cursor={}", hex(&P1)),
        "?after=".to_string(),
    ] {
        let (status, _, _) = server.get(&list_path(FLEET, &q), &access, None).await;
        assert_eq!(status, 400, "{q}");
    }
}

#[tokio::test]
async fn the_fleet_list_needs_fleet_wide_checkout_and_hides_other_fleets() {
    let mut server = start("list-refusals", 28282).await;
    let (dev, access) = custodian(&mut server, 0x6c).await;
    fleets(&server).await;
    let c = (&dev, access.as_str());
    use CapabilityScopeKind as K;
    for (replay, capability, scope) in [
        (0xa1, Capability::ProfilePublish, (K::Tenant, TENANT)),
        (0xa2, Capability::ProfileCheckout, (K::Tenant, TENANT)),
    ] {
        grant(&server, c, Some(&dev), replay, capability, scope).await;
    }
    let (status, body) = server
        .call(&publish_path(FLEET), &access, &publish(0x01, pref(P1)))
        .await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    assert_eq!(ids(&page(&server, &access, FLEET, "").await), vec![P1]);

    // An unknown, an archived and another tenant's fleet are the same
    // not-found, even to a tenant-wide holder.
    let foreign = [0xf8; 16];
    foreign_fleet(&server, [0x42; 16], foreign).await;
    published_rows(&server, [0x42; 16], foreign, 0xc6, 1).await;
    published_rows(&server, TENANT, ARCHIVED, 0xc7, 1).await;
    for fleet in [[0x99; 16], ARCHIVED, foreign] {
        list_refused(&server, &access, fleet, (404, "RESOURCE_NOT_FOUND")).await;
    }
    let (status, _, _) = server.get("/v2/fleets/zz/profiles", &access, None).await;
    assert_eq!(status, 400);

    // No session, or only a password ticket.
    let r = client()
        .get(format!(
            "http://127.0.0.1:{}{}",
            server.port,
            list_path(FLEET, "")
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401);
    let ticket = server.login().await;
    let (status, _, _) = server
        .get(
            &list_path(FLEET, ""),
            ticket["ticket"].as_str().unwrap(),
            None,
        )
        .await;
    assert_eq!(status, 403);

    // A device without a fleet-wide checkout grant, whatever else it holds.
    let (bare, bare_access) = peer(&server, &dev, 0x7d).await;
    list_refused(&server, &bare_access, FLEET, (403, "")).await;
    let other_fleet = [0xf7; 16];
    server
        .sql(
            "INSERT INTO v2_fleets (id, tenant_id, name, status, created_at)
             VALUES (?, ?, 'o', 'active', 't')",
            &[&other_fleet, &TENANT],
        )
        .await;
    for (replay, capability, scope) in [
        (0xb1, Capability::ProfileCheckout, (K::Profile, P1)),
        (0xb2, Capability::ProfilePublish, (K::Fleet, FLEET)),
        (0xb3, Capability::ProfileCommit, (K::Fleet, FLEET)),
        (0xb4, Capability::ProfileCheckout, (K::Fleet, other_fleet)),
    ] {
        grant(&server, c, Some(&bare), replay, capability, scope).await;
        list_refused(&server, &bare_access, FLEET, (403, "")).await;
    }
    grant(
        &server,
        c,
        Some(&bare),
        0xb5,
        Capability::ProfileCheckout,
        (K::Fleet, FLEET),
    )
    .await;
    assert_eq!(ids(&page(&server, &bare_access, FLEET, "").await), vec![P1]);

    // A fleet-scoped approval lists that fleet only (Q-22).
    let (fleet_b, fleet_b_access) =
        peer_in(&server, &dev, 0x7e, (ApprovalScopeKind::Fleet, other_fleet)).await;
    grant(
        &server,
        c,
        Some(&fleet_b),
        0xb6,
        Capability::ProfileCheckout,
        (K::Tenant, TENANT),
    )
    .await;
    list_refused(&server, &fleet_b_access, FLEET, (403, "")).await;
    let (fleet_a, fleet_a_access) =
        peer_in(&server, &dev, 0x7f, (ApprovalScopeKind::Fleet, FLEET)).await;
    grant(
        &server,
        c,
        Some(&fleet_a),
        0xb7,
        Capability::ProfileCheckout,
        (K::Tenant, TENANT),
    )
    .await;
    assert_eq!(
        ids(&page(&server, &fleet_a_access, FLEET, "").await),
        vec![P1]
    );

    // An account-scoped grant is server RBAC and counts (D-2).
    let (_, plain_access) = peer(&server, &dev, 0x80).await;
    list_refused(&server, &plain_access, FLEET, (403, "")).await;
    grant(
        &server,
        c,
        None,
        0xb8,
        Capability::ProfileCheckout,
        (K::Fleet, FLEET),
    )
    .await;
    assert_eq!(
        ids(&page(&server, &plain_access, FLEET, "").await),
        vec![P1]
    );
}
