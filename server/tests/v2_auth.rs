//! ADR 0001 R2 over HTTP: login issues an account-only ticket, and only both
//! proofs of possession turn it into a session bound to one device.
//!
//! These drive the real binary, so they cover the wiring as well as the
//! checks: that each route reads the right token type, that a refusal is a
//! non-2xx response, and that the rows behind a session say what the
//! response says.

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
use shared::approval_receipt::DeviceApprovalReceiptV2;
use shared::authz_record::{
    build_record, ApprovalScopeKind, AuthorizationRecord, Capability, CapabilityScopeKind,
    CommonFields, DeviceApprovalV2, GrantSubject, Payload, RootGrantVariant,
    TenantCapabilityGrantV2, TenantRootKeyGrantV2, DOMAIN_DEVICE_APPROVAL,
    DOMAIN_TENANT_CAPABILITY_GRANT, DOMAIN_TENANT_ROOT_KEY_GRANT,
};
use shared::canonical::sha256;
use shared::grants::derive_keypair;
use shared::keys::{hpke_key_id, signing_key_id};
use shared::mutation::{
    root_custodian_grant_set_hash, EmbeddedSelfGrant, IdempotentMutationRequestV2,
    IdempotentStoredResponseV2, OperationKind, PreviousRoot, RootGenerationMode,
    RootGenerationState, RootGenerationTarget, RootGrantRef, RootGrantState,
    TenantRootGenerationActivateV2, TenantRootGenerationActivatedV2, TenantRootGenerationCreateV2,
    TenantRootGenerationCreatedV2, TenantRootGrantAckV2, TenantRootGrantAckedV2,
    TenantRootGrantDescriptorV2,
};
use shared::session_binding::{self as sb, DeviceSessionBindingV2};
use shared::signing::Ed25519SigningKey;
use shared::trust_chain::{Binding, Evidence, Scope, TrustChain};
use shared::trust_evidence::TenantTrustEvidencePageV2;

const INSTANCE: [u8; 16] = [7; 16];
const TENANT: [u8; 16] = [0x41; 16];
const OWNER: [u8; 16] = [0x51; 16];
const OTHER: [u8; 16] = [0x52; 16];
const PASSWORD: &str = "correct horse battery staple";

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
        // Lets a test spread requests over source addresses; without the
        // header the peer address is used, as before.
        .env("SHARDX_TRUST_PROXY", "1")
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

/// A verified identity, one tenant with two member accounts, and a server.
async fn start(tag: &str, port: u16) -> Server {
    let data = std::env::temp_dir().join(format!("shardx-v2-auth-{tag}"));
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
    for (account, name, role) in [(OWNER, "owner", "owner"), (OTHER, "other", "member")] {
        sqlx::query("INSERT INTO v2_accounts VALUES (?, ?, ?, ?, NULL, 0, 'active', 't')")
            .bind(account.as_slice())
            .bind(TENANT.as_slice())
            .bind(name)
            .bind(&hash)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO v2_tenant_memberships VALUES (?, ?, ?, 'active', 't')")
            .bind(TENANT.as_slice())
            .bind(account.as_slice())
            .bind(role)
            .execute(&pool)
            .await
            .unwrap();
    }
    pool.close().await;

    let child = launch(&data, port);
    wait_health(port).await;
    Server { child, port, data }
}

impl Server {
    async fn restart(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.child = launch(&self.data, self.port);
        wait_health(self.port).await;
    }

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

    async fn post_from(&self, ip: &str, path: &str, body: Value) -> (u16, Value) {
        let r = client()
            .post(format!("http://127.0.0.1:{}{path}", self.port))
            .header("x-forwarded-for", ip)
            .json(&body)
            .send()
            .await
            .unwrap();
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
    async fn confirm(&mut self, dev: &Device) -> [u8; 16] {
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
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "{stdout} {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let id = stdout
            .lines()
            .find_map(|l| l.strip_prefix("confirmation_id="))
            .expect("the CLI prints the confirmation ID");
        unhex(id).try_into().unwrap()
    }

    /// Posts exact CBOR; returns the status, content type and body bytes.
    async fn approve(
        &self,
        device: &[u8; 16],
        bearer: &str,
        body: &[u8],
    ) -> (u16, String, Vec<u8>) {
        let r = client()
            .post(format!(
                "http://127.0.0.1:{}/v2/devices/{}/approve",
                self.port,
                hex(device)
            ))
            .bearer_auth(bearer)
            .header("content-type", "application/cbor")
            .body(body.to_vec())
            .send()
            .await
            .unwrap();
        let status = r.status().as_u16();
        let ct = r
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        (status, ct, r.bytes().await.unwrap().to_vec())
    }

    /// Posts an exact root generation create to `tenant`'s path.
    async fn root(&self, tenant: &[u8; 16], bearer: &str, body: &[u8]) -> (u16, Vec<u8>) {
        let r = client()
            .post(format!(
                "http://127.0.0.1:{}/v2/tenants/{}/root-key-generations",
                self.port,
                hex(tenant)
            ))
            .bearer_auth(bearer)
            .header("content-type", "application/cbor")
            .body(body.to_vec())
            .send()
            .await
            .unwrap();
        let status = r.status().as_u16();
        (status, r.bytes().await.unwrap().to_vec())
    }

    /// A GET, or a CBOR POST of `body`, to `path`.
    async fn call(&self, path: &str, bearer: &str, body: Option<&[u8]>) -> (u16, Vec<u8>) {
        let url = format!("http://127.0.0.1:{}{path}", self.port);
        let r = match body {
            None => client().get(url),
            Some(b) => client()
                .post(url)
                .header("content-type", "application/cbor")
                .body(b.to_vec()),
        }
        .bearer_auth(bearer)
        .send()
        .await
        .unwrap();
        let status = r.status().as_u16();
        (status, r.bytes().await.unwrap().to_vec())
    }

    async fn me(&self, bearer: &str) -> (u16, Value) {
        let r = client()
            .get(format!("http://127.0.0.1:{}/v2/me", self.port))
            .bearer_auth(bearer)
            .send()
            .await
            .unwrap();
        let status = r.status().as_u16();
        (status, r.json().await.unwrap_or(Value::Null))
    }

    async fn sql(&self, statement: &str, binds: &[&[u8]]) {
        let pool = db(&self.data).await;
        let mut q = sqlx::query(statement);
        for b in binds {
            q = q.bind(b.to_vec());
        }
        q.execute(&pool).await.unwrap();
        pool.close().await;
    }

    async fn count(&self, query: &str) -> i64 {
        let pool = db(&self.data).await;
        let n = sqlx::query_scalar(query).fetch_one(&pool).await.unwrap();
        pool.close().await;
        n
    }

    async fn login(&self, username: &str) -> Value {
        let (status, body) = self
            .post(
                "/v2/auth/login",
                None,
                json!({ "tenant": "acme", "username": username, "password": PASSWORD }),
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

/// A device enrolled for `account`, stored the way enrollment stores it.
async fn device(server: &Server, account: [u8; 16], seed: u8, status: &str) -> Device {
    let sk = Ed25519SigningKey::from_bytes(&[seed; 32]);
    let spk = sk.verifying_key().to_bytes();
    let (hpke_sk, hpk) = derive_keypair(&[seed.wrapping_add(1); 32]);
    let id = [seed; 16];
    let pool = db(&server.data).await;
    sqlx::query("INSERT INTO v2_devices VALUES (?, ?, ?, x'aa', ?, ?, 1, ?, ?, 1, ?, NULL, 't')")
        .bind(id.as_slice())
        .bind(TENANT.as_slice())
        .bind(account.as_slice())
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

/// The client half of a challenge: check the binding, open the secret, sign.
fn answer(ticket: &Value, challenge: &Value, dev: &Device) -> Value {
    answer_at(ticket, challenge, dev, 0)
}

/// [`answer`] to a server at `epoch`.
fn answer_at(ticket: &Value, challenge: &Value, dev: &Device, epoch: u64) -> Value {
    let binding = unhex(challenge["binding"].as_str().unwrap());
    let parsed = DeviceSessionBindingV2::parse(&binding).unwrap();
    assert_eq!(parsed.device_id, dev.id);
    assert_eq!(parsed.fields.server_instance_id, INSTANCE);
    assert_eq!(parsed.fields.restore_epoch, epoch);
    assert_eq!(
        hex(&parsed.fields.pre_device_session_id),
        ticket["ticket_id"].as_str().unwrap()
    );
    let secret = sb::open_pop_secret(
        &dev.hpke_sk,
        &binding,
        &unhex(challenge["encapsulated_key"].as_str().unwrap()),
        &unhex(challenge["ciphertext"].as_str().unwrap()),
    )
    .unwrap();
    json!({
        "challenge_id": challenge["challenge_id"],
        "secret": hex(&*secret),
        "signature": hex(&sb::sign_pop(&dev.sk, &binding, &secret)),
    })
}

async fn challenge(server: &Server, ticket: &Value, dev: &Device) -> (u16, Value) {
    server
        .post(
            "/v2/auth/device-session-challenges",
            ticket["ticket"].as_str(),
            json!({ "device_id": hex(&dev.id) }),
        )
        .await
}

/// Login, challenge and proof; returns the proof response.
async fn session(server: &Server, dev: &Device) -> Value {
    session_at(server, dev, 0).await
}

/// [`session`] on a server at `epoch`.
async fn session_at(server: &Server, dev: &Device, epoch: u64) -> Value {
    let ticket = server.login("owner").await;
    let (status, ch) = challenge(server, &ticket, dev).await;
    assert_eq!(status, 201, "{ch}");
    let (status, s) = server
        .post(
            "/v2/auth/device-session-proofs",
            ticket["ticket"].as_str(),
            answer_at(&ticket, &ch, dev, epoch),
        )
        .await;
    assert_eq!(status, 201, "{s}");
    s
}

#[tokio::test]
async fn a_ticket_becomes_a_device_session_only_through_both_proofs() {
    let server = start("journey", 28171).await;
    let dev = device(&server, OWNER, 0x21, "pending").await;

    let ticket = server.login("owner").await;
    let t = ticket["ticket"].as_str().unwrap();
    assert!(t.starts_with("v2t."));
    // The ticket names the account and lists its devices, nothing more.
    let (status, me) = server.me(t).await;
    assert_eq!(status, 200);
    assert_eq!(me["kind"], "pre_device");
    assert_eq!(me["account_id"], hex(&OWNER));
    assert_eq!(me["devices"][0]["device_id"], hex(&dev.id));
    assert_eq!(me["devices"][0]["status"], "pending");
    assert_eq!(
        server.count("SELECT count(*) FROM v2_sessions").await,
        0,
        "login creates no session"
    );

    let (status, ch) = challenge(&server, &ticket, &dev).await;
    assert_eq!(status, 201, "{ch}");
    let proof = answer(&ticket, &ch, &dev);
    let (status, s) = server
        .post("/v2/auth/device-session-proofs", Some(t), proof.clone())
        .await;
    assert_eq!(status, 201, "{s}");
    assert_eq!(s["class"], "pending_setup");
    assert_eq!(s["device_id"], hex(&dev.id));
    let access = s["access_token"].as_str().unwrap();
    let (status, me) = server.me(access).await;
    assert_eq!(status, 200);
    assert_eq!(me["kind"], "session");
    assert_eq!(me["device_id"], hex(&dev.id));
    assert_eq!(
        me["signing_key_id"],
        hex(&signing_key_id(&dev.sk.verifying_key().to_bytes()))
    );

    // The proof consumed the ticket and the challenge: neither works again.
    assert_eq!(server.me(t).await.0, 401);
    let (status, _) = server
        .post("/v2/auth/device-session-proofs", Some(t), proof)
        .await;
    assert_eq!(status, 401);
    // Only hashes are stored, and the audit row names the device.
    let raw = unhex(&access["v2a.".len()..]);
    let stored = server
        .count(&format!(
            "SELECT count(*) FROM v2_sessions WHERE access_token_hash = x'{}'",
            hex(&shared::canonical::sha256(&raw))
        ))
        .await;
    assert_eq!(stored, 1);
    assert_eq!(
        server
            .count(&format!(
                "SELECT count(*) FROM v2_audit_events WHERE action = 'auth.device_session' \
                 AND actor_device_id = x'{}' AND actor_account_id = x'{}'",
                hex(&dev.id),
                hex(&OWNER)
            ))
            .await,
        1
    );
}

#[tokio::test]
async fn a_ticket_authorizes_nothing_but_its_own_proofs() {
    let server = start("ticket-only", 28172).await;
    let dev = device(&server, OWNER, 0x22, "pending").await;
    let ticket = server.login("owner").await;
    let t = ticket["ticket"].as_str();

    // A ticket is a principal, but a grant and custody need a device session.
    let (status, _) = server.post("/v2/capability-grants", t, json!({})).await;
    assert_eq!(status, 403);
    let (status, _) = server
        .post(
            &format!("/v2/tenants/{}/root-key-generations", hex(&TENANT)),
            t,
            json!({}),
        )
        .await;
    assert_eq!(status, 403);
    let (status, _) = server
        .post("/v2/auth/refresh", None, json!({ "refresh_token": t }))
        .await;
    assert_eq!(status, 401);
    // A session cannot open challenges in a ticket's place.
    let s = session(&server, &dev).await;
    let (status, _) = server
        .post(
            "/v2/auth/device-session-challenges",
            s["access_token"].as_str(),
            json!({ "device_id": hex(&dev.id) }),
        )
        .await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn only_the_accounts_own_pending_device_gets_a_challenge() {
    let server = start("devices", 28173).await;
    let other = device(&server, OTHER, 0x23, "pending").await;
    let active = device(&server, OWNER, 0x24, "active").await;
    let quarantined = device(&server, OWNER, 0x25, "quarantined").await;
    let ticket = server.login("owner").await;

    // Another account's device and a guessed ID look the same.
    assert_eq!(challenge(&server, &ticket, &other).await.0, 404);
    let guessed = Device {
        id: [0x99; 16],
        ..device(&server, OWNER, 0x26, "pending").await
    };
    assert_eq!(challenge(&server, &ticket, &guessed).await.0, 404);
    assert_eq!(challenge(&server, &ticket, &active).await.0, 409);
    assert_eq!(challenge(&server, &ticket, &quarantined).await.0, 409);
    assert_eq!(
        server
            .count("SELECT count(*) FROM v2_device_session_challenges")
            .await,
        0
    );
}

#[tokio::test]
async fn a_signing_only_proof_burns_the_challenge() {
    let server = start("signing-only", 28174).await;
    let dev = device(&server, OWNER, 0x27, "pending").await;
    let ticket = server.login("owner").await;
    let t = ticket["ticket"].as_str();
    let (_, ch) = challenge(&server, &ticket, &dev).await;
    let binding = unhex(ch["binding"].as_str().unwrap());

    // Without the HPKE key the client cannot know the secret; a valid
    // signature over a guessed one proves only the signing key.
    let guess = [0x5a; 32];
    let (status, _) = server
        .post(
            "/v2/auth/device-session-proofs",
            t,
            json!({
                "challenge_id": ch["challenge_id"],
                "secret": hex(&guess),
                "signature": hex(&sb::sign_pop(&dev.sk, &binding, &guess)),
            }),
        )
        .await;
    assert_eq!(status, 401);
    // The challenge is spent even for the right answer now.
    let (status, _) = server
        .post(
            "/v2/auth/device-session-proofs",
            t,
            answer(&ticket, &ch, &dev),
        )
        .await;
    assert_eq!(status, 401);

    // A signature by another key over the right secret fails the same way.
    let (_, ch) = challenge(&server, &ticket, &dev).await;
    let mut wrong = answer(&ticket, &ch, &dev);
    let impostor = Ed25519SigningKey::from_bytes(&[0x77; 32]);
    let secret = unhex(wrong["secret"].as_str().unwrap());
    wrong["signature"] = json!(hex(&sb::sign_pop(
        &impostor,
        &unhex(ch["binding"].as_str().unwrap()),
        &secret.try_into().unwrap()
    )));
    assert_eq!(
        server
            .post("/v2/auth/device-session-proofs", t, wrong)
            .await
            .0,
        401
    );

    // A fresh challenge still works: nothing was promoted on the way.
    assert_eq!(server.count("SELECT count(*) FROM v2_sessions").await, 0);
    let (_, ch) = challenge(&server, &ticket, &dev).await;
    let (status, _) = server
        .post(
            "/v2/auth/device-session-proofs",
            t,
            answer(&ticket, &ch, &dev),
        )
        .await;
    assert_eq!(status, 201);
}

#[tokio::test]
async fn a_proof_belongs_to_its_own_ticket() {
    let server = start("other-ticket", 28175).await;
    let dev = device(&server, OWNER, 0x28, "pending").await;
    let first = server.login("owner").await;
    let second = server.login("owner").await;
    let (_, ch) = challenge(&server, &first, &dev).await;
    // The same account's second ticket cannot redeem the first's challenge.
    let (status, _) = server
        .post(
            "/v2/auth/device-session-proofs",
            second["ticket"].as_str(),
            answer(&first, &ch, &dev),
        )
        .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn live_state_ends_tickets_and_sessions() {
    let server = start("live", 28176).await;
    let dev = device(&server, OWNER, 0x29, "pending").await;
    let s = session(&server, &dev).await;
    let access = s["access_token"].as_str().unwrap();
    let ticket = server.login("owner").await;
    let t = ticket["ticket"].as_str().unwrap();
    assert_eq!(server.me(access).await.0, 200);

    // A password change (token version) ends both at once.
    server
        .sql(
            "UPDATE v2_accounts SET token_version = 1 WHERE id = ?",
            &[&OWNER],
        )
        .await;
    assert_eq!(server.me(access).await.0, 401);
    assert_eq!(server.me(t).await.0, 401);
    server
        .sql(
            "UPDATE v2_accounts SET token_version = 0 WHERE id = ?",
            &[&OWNER],
        )
        .await;
    assert_eq!(server.me(access).await.0, 200);

    // So do a disabled account, a suspended tenant and a revoked membership,
    // for the ticket as for the session; and a device that left pending.
    for (set, reset) in [
        (
            "UPDATE v2_accounts SET status = 'disabled' WHERE id = ?",
            "UPDATE v2_accounts SET status = 'active' WHERE id = ?",
        ),
        (
            "UPDATE v2_tenants SET status = 'suspended' WHERE id = (SELECT tenant_id FROM v2_accounts WHERE id = ?)",
            "UPDATE v2_tenants SET status = 'active' WHERE id = (SELECT tenant_id FROM v2_accounts WHERE id = ?)",
        ),
        (
            "UPDATE v2_tenant_memberships SET status = 'revoked' WHERE account_id = ?",
            "UPDATE v2_tenant_memberships SET status = 'active' WHERE account_id = ?",
        ),
    ] {
        assert_eq!(server.me(t).await.0, 200, "control before {set}");
        server.sql(set, &[&OWNER]).await;
        assert_eq!(server.me(access).await.0, 401, "{set}");
        assert_eq!(server.me(t).await.0, 401, "{set}");
        server.sql(reset, &[&OWNER]).await;
        assert_eq!(server.me(access).await.0, 200, "{reset}");
    }
    server
        .sql(
            "UPDATE v2_devices SET status = 'revoked' WHERE id = ?",
            &[&dev.id],
        )
        .await;
    assert_eq!(server.me(access).await.0, 401);
    let (status, _) = server
        .post(
            "/v2/auth/refresh",
            None,
            json!({ "refresh_token": s["refresh_token"] }),
        )
        .await;
    assert_eq!(status, 401);
    assert_eq!(
        server
            .count("SELECT count(*) FROM v2_sessions WHERE revoked_at_ms IS NOT NULL")
            .await,
        1,
        "a failed refresh revokes the session"
    );

    // A ticket is pinned to the instance and epoch it was issued under. The
    // control ticket is the same row under the current pair, so only the pin
    // differs.
    assert_eq!(
        server
            .me(&forge_ticket(&server, INSTANCE, 0, 0x31).await)
            .await
            .0,
        200
    );
    assert_eq!(
        server
            .me(&forge_ticket(&server, INSTANCE, 1, 0x33).await)
            .await
            .0,
        401
    );
    assert_eq!(
        server
            .me(&forge_ticket(&server, [8; 16], 0, 0x35).await)
            .await
            .0,
        401
    );
}

#[tokio::test]
async fn refresh_rotates_once_and_respects_expiry() {
    let server = start("refresh", 28177).await;
    let dev = device(&server, OWNER, 0x2a, "pending").await;
    let s = session(&server, &dev).await;
    let refresh = s["refresh_token"].clone();

    let (status, r) = server
        .post(
            "/v2/auth/refresh",
            None,
            json!({ "refresh_token": refresh }),
        )
        .await;
    assert_eq!(status, 200, "{r}");
    assert_ne!(r["access_token"], s["access_token"]);
    assert_eq!(r["absolute_expires_at_ms"], s["absolute_expires_at_ms"]);
    // The old access token is dead; the new one works.
    assert_eq!(server.me(s["access_token"].as_str().unwrap()).await.0, 401);
    assert_eq!(server.me(r["access_token"].as_str().unwrap()).await.0, 200);
    // A second rotation, then the first token again: any replaced token means
    // two holders, however many rotations ago, and both lose the session.
    let (status, r) = server
        .post(
            "/v2/auth/refresh",
            None,
            json!({ "refresh_token": r["refresh_token"] }),
        )
        .await;
    assert_eq!(status, 200, "{r}");
    let access = r["access_token"].as_str().unwrap();
    assert_eq!(server.me(access).await.0, 200);
    let (status, _) = server
        .post(
            "/v2/auth/refresh",
            None,
            json!({ "refresh_token": refresh }),
        )
        .await;
    assert_eq!(status, 401);
    assert_eq!(server.me(access).await.0, 401);
    let (status, _) = server
        .post(
            "/v2/auth/refresh",
            None,
            json!({ "refresh_token": r["refresh_token"] }),
        )
        .await;
    assert_eq!(status, 401);
    assert_eq!(
        server
            .count(&format!(
                "SELECT count(*) FROM v2_audit_events WHERE action = 'auth.refresh_reuse' \
                 AND actor_device_id = x'{}'",
                hex(&dev.id)
            ))
            .await,
        1
    );
    // The revoked session's spent tokens went with it.
    assert_eq!(
        server
            .count("SELECT count(*) FROM v2_spent_refresh_tokens")
            .await,
        0
    );

    // On a new session: the binding cannot be rewritten to stretch it, an
    // expired access token is refused, and an expired refresh ends it.
    let s = session(&server, &dev).await;
    let access = s["access_token"].as_str().unwrap();
    let pool = db(&server.data).await;
    let error = sqlx::query(
        "UPDATE v2_sessions SET absolute_expires_at_ms = absolute_expires_at_ms + 1
          WHERE revoked_at_ms IS NULL",
    )
    .execute(&pool)
    .await
    .unwrap_err()
    .to_string();
    pool.close().await;
    assert!(error.contains("binding never changes"), "{error}");
    server
        .sql(
            "UPDATE v2_sessions SET access_expires_at_ms = 1 WHERE revoked_at_ms IS NULL",
            &[],
        )
        .await;
    assert_eq!(server.me(access).await.0, 401);
    server
        .sql(
            "UPDATE v2_sessions SET refresh_expires_at_ms = 1 WHERE revoked_at_ms IS NULL",
            &[],
        )
        .await;
    let (status, _) = server
        .post(
            "/v2/auth/refresh",
            None,
            json!({ "refresh_token": s["refresh_token"] }),
        )
        .await;
    assert_eq!(status, 401);
    assert_eq!(
        server
            .count("SELECT count(*) FROM v2_sessions WHERE revoked_at_ms IS NULL")
            .await,
        0,
        "an expired refresh revokes the session"
    );
}

#[tokio::test]
async fn logout_ends_the_ticket_its_challenges_or_the_session() {
    let server = start("logout", 28178).await;
    let dev = device(&server, OWNER, 0x2b, "pending").await;
    let ticket = server.login("owner").await;
    let t = ticket["ticket"].as_str();
    let (_, ch) = challenge(&server, &ticket, &dev).await;
    assert_eq!(server.post("/v2/auth/logout", t, json!({})).await.0, 204);
    assert_eq!(server.me(t.unwrap()).await.0, 401);
    assert_eq!(
        server
            .count(
                "SELECT count(*) FROM v2_device_session_challenges WHERE revoked_at_ms IS NOT NULL"
            )
            .await,
        1
    );
    let _ = ch;

    let s = session(&server, &dev).await;
    let access = s["access_token"].as_str();
    assert_eq!(
        server.post("/v2/auth/logout", access, json!({})).await.0,
        204
    );
    assert_eq!(server.me(access.unwrap()).await.0, 401);
    let (status, _) = server
        .post(
            "/v2/auth/refresh",
            None,
            json!({ "refresh_token": s["refresh_token"] }),
        )
        .await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn login_failures_are_throttled_and_say_nothing() {
    let server = start("throttle", 28179).await;
    let wrong = |user: &str| json!({ "tenant": "acme", "username": user, "password": "nope" });
    // Unknown user and wrong password are the same 401.
    assert_eq!(
        server.post("/v2/auth/login", None, wrong("ghost")).await.0,
        401
    );
    for _ in 0..4 {
        assert_eq!(
            server.post("/v2/auth/login", None, wrong("owner")).await.0,
            401
        );
    }
    assert_eq!(
        server.post("/v2/auth/login", None, wrong("owner")).await.0,
        429
    );
    let (status, _) = server
        .post(
            "/v2/auth/login",
            None,
            json!({ "tenant": "acme", "username": "owner", "password": PASSWORD }),
        )
        .await;
    assert_eq!(status, 429, "the source stays locked out");
    assert_eq!(
        server
            .count("SELECT count(*) FROM v2_pre_device_sessions")
            .await,
        0
    );
}

#[tokio::test]
async fn every_way_of_naming_the_tenant_shares_one_account_throttle() {
    let server = start("throttle-forms", 28189).await;
    let lower = hex(&TENANT);
    let upper = lower.to_ascii_uppercase();
    let forms = [
        json!({ "tenant": "acme" }),
        json!({ "tenant_id": lower }),
        json!({ "tenant_id": upper }),
    ];
    let with = |form: &Value, password: &str| {
        let mut body = form.clone();
        body["username"] = json!("owner");
        body["password"] = json!(password);
        body
    };
    // Fifteen failures, a fresh source address each, so only the account key
    // counts them; split over three spellings, no single one reaches the limit.
    for i in 0..15 {
        let (status, _) = server
            .post_from(
                &format!("10.0.0.{i}"),
                "/v2/auth/login",
                with(&forms[i % 3], "nope"),
            )
            .await;
        assert_eq!(status, 401);
    }
    for (i, form) in forms.iter().enumerate() {
        let (status, _) = server
            .post_from(
                &format!("10.0.1.{i}"),
                "/v2/auth/login",
                with(form, PASSWORD),
            )
            .await;
        assert_eq!(status, 429, "form {i} must share the account's lockout");
    }
}

#[tokio::test]
async fn after_a_restart_a_new_login_reaches_the_same_device() {
    let mut server = start("restart", 28180).await;
    let dev = device(&server, OWNER, 0x2c, "pending").await;
    let first = session(&server, &dev).await;
    server.restart().await;
    // No re-enrollment and no account-only shortcut: a new ticket and new
    // proofs bind a second session to the same device.
    let second = session(&server, &dev).await;
    assert_eq!(second["device_id"], first["device_id"]);
    assert_ne!(second["session_id"], first["session_id"]);
    assert_eq!(server.count("SELECT count(*) FROM v2_devices").await, 1);
}

#[tokio::test]
async fn a_device_that_changed_since_its_challenge_gets_no_session() {
    let server = start("changed", 28181).await;
    let dev = device(&server, OWNER, 0x3c, "pending").await;
    let ticket = server.login("owner").await;
    let t = ticket["ticket"].as_str();
    // Five challenges per ticket; a sixth needs a new login.
    let mut open = Vec::new();
    for _ in 0..5 {
        let (status, ch) = challenge(&server, &ticket, &dev).await;
        assert_eq!(status, 201, "{ch}");
        open.push(ch);
    }
    assert_eq!(challenge(&server, &ticket, &dev).await.0, 409);

    // The proof rechecks the device it binds; a revoked one gets nothing.
    server
        .sql(
            "UPDATE v2_devices SET status = 'revoked' WHERE id = ?",
            &[&dev.id],
        )
        .await;
    let (status, _) = server
        .post(
            "/v2/auth/device-session-proofs",
            t,
            answer(&ticket, &open[0], &dev),
        )
        .await;
    assert_eq!(status, 409);
    assert_eq!(server.count("SELECT count(*) FROM v2_sessions").await, 0);
    assert_eq!(
        server
            .count(
                "SELECT count(*) FROM v2_device_session_challenges \
                 WHERE revoked_at_ms IS NOT NULL"
            )
            .await,
        1
    );
}

/// A live ticket for the owner under `instance` and `epoch`; returns its token.
async fn forge_ticket(server: &Server, instance: [u8; 16], epoch: i64, tag: u8) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let raw = [tag; 32];
    let pool = db(&server.data).await;
    sqlx::query(
        "INSERT INTO v2_pre_device_sessions
             (id, token_hash, server_instance_id, restore_epoch, tenant_id, account_id,
              account_token_version, created_at_ms, expires_at_ms)
         VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)",
    )
    .bind([tag; 16].as_slice())
    .bind(shared::canonical::sha256(&raw).as_slice())
    .bind(instance.as_slice())
    .bind(epoch)
    .bind(TENANT.as_slice())
    .bind(OWNER.as_slice())
    .bind(now)
    .bind(now + 600_000)
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;
    format!("v2t.{}", hex(&raw))
}

/// A session row for `dev`, written as the proof would but under `epoch`;
/// returns its access token.
async fn forge_session(
    server: &Server,
    dev: &Device,
    hpk: &[u8; 32],
    epoch: i64,
    tag: u8,
) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let raw = [tag; 32];
    let ticket = [tag; 16];
    let ch = [tag.wrapping_add(1); 16];
    let pool = db(&server.data).await;
    sqlx::query(
        "INSERT INTO v2_pre_device_sessions
             (id, token_hash, server_instance_id, restore_epoch, tenant_id, account_id,
              account_token_version, created_at_ms, expires_at_ms, consumed_at_ms)
         VALUES (?, randomblob(32), ?, ?, ?, ?, 0, 1, 600000, 2)",
    )
    .bind(ticket.as_slice())
    .bind(INSTANCE.as_slice())
    .bind(epoch)
    .bind(TENANT.as_slice())
    .bind(OWNER.as_slice())
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO v2_device_session_challenges
             (id, pre_device_session_id, tenant_id, account_id, device_id, binding_bytes,
              secret_hash, created_at_ms, expires_at_ms, consumed_at_ms)
         VALUES (?, ?, ?, ?, ?, x'aa', zeroblob(32), 1, 120000, 2)",
    )
    .bind(ch.as_slice())
    .bind(ticket.as_slice())
    .bind(TENANT.as_slice())
    .bind(OWNER.as_slice())
    .bind(dev.id.as_slice())
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO v2_sessions
             (id, tenant_id, account_id, device_id, server_instance_id, restore_epoch,
              signing_key_id, hpke_key_id, account_token_version, class,
              pre_device_session_id, device_session_challenge_id, pop_at_ms,
              access_token_hash, access_expires_at_ms, refresh_token_hash,
              refresh_expires_at_ms, absolute_expires_at_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 'pending_setup', ?, ?, ?, ?, ?, randomblob(32), ?, ?)",
    )
    .bind(ticket.as_slice())
    .bind(TENANT.as_slice())
    .bind(OWNER.as_slice())
    .bind(dev.id.as_slice())
    .bind(INSTANCE.as_slice())
    .bind(epoch)
    .bind(signing_key_id(&dev.sk.verifying_key().to_bytes()).as_slice())
    .bind(hpke_key_id(hpk).as_slice())
    .bind(ticket.as_slice())
    .bind(ch.as_slice())
    .bind(now)
    .bind(shared::canonical::sha256(&raw).as_slice())
    .bind(now + 300_000)
    .bind(now + 1_800_000)
    .bind(now + 1_800_000)
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;
    format!("v2a.{}", hex(&raw))
}

#[tokio::test]
async fn a_session_from_another_epoch_is_refused() {
    let server = start("epoch", 28182).await;
    let dev = device(&server, OWNER, 0x3e, "pending").await;
    let (_, hpk) = derive_keypair(&[0x3f; 32]);
    let hpk: [u8; 32] = hpk.as_slice().try_into().unwrap();
    // The same row under the current epoch works, so only the epoch differs.
    let current = forge_session(&server, &dev, &hpk, 0, 0x60).await;
    assert_eq!(server.me(&current).await.0, 200);
    let stale = forge_session(&server, &dev, &hpk, 1, 0x70).await;
    assert_eq!(server.me(&stale).await.0, 401);
}

#[tokio::test]
async fn an_account_holds_a_bounded_number_of_tickets() {
    let server = start("tickets", 28183).await;
    // Tickets from another epoch can never be used, so they take no slot.
    for tag in 0x80..0x8a {
        forge_ticket(&server, INSTANCE, 1, tag).await;
    }
    let first = server.login("owner").await;
    for _ in 1..10 {
        server.login("owner").await;
    }
    let (status, _) = server
        .post(
            "/v2/auth/login",
            None,
            json!({ "tenant": "acme", "username": "owner", "password": PASSWORD }),
        )
        .await;
    assert_eq!(status, 429);
    // Another account of the tenant is unaffected, and a ticket given back
    // frees its slot.
    server.login("other").await;
    let (status, _) = server
        .post("/v2/auth/logout", first["ticket"].as_str(), json!({}))
        .await;
    assert_eq!(status, 204);
    server.login("owner").await;
    assert_eq!(
        server
            .post(
                "/v2/auth/login",
                None,
                json!({ "tenant": "acme", "username": "owner", "password": PASSWORD }),
            )
            .await
            .0,
        429
    );
    // A password change (token version) kills the old tickets, so they free
    // their slots.
    server
        .sql(
            "UPDATE v2_accounts SET token_version = 1 WHERE id = ?",
            &[&OWNER],
        )
        .await;
    server.login("owner").await;
}

#[tokio::test]
async fn a_ticket_issues_five_challenges_in_its_life() {
    let server = start("burn", 28187).await;
    let dev = device(&server, OWNER, 0x3b, "pending").await;
    let ticket = server.login("owner").await;
    // Burning a challenge with a wrong answer does not give its slot back.
    for _ in 0..5 {
        let (status, ch) = challenge(&server, &ticket, &dev).await;
        assert_eq!(status, 201, "{ch}");
        let mut wrong = answer(&ticket, &ch, &dev);
        wrong["secret"] = json!(hex(&[0u8; 32]));
        let (status, _) = server
            .post(
                "/v2/auth/device-session-proofs",
                ticket["ticket"].as_str(),
                wrong,
            )
            .await;
        assert_eq!(status, 401);
    }
    assert_eq!(challenge(&server, &ticket, &dev).await.0, 409);
    // A new login starts a new budget.
    let fresh = server.login("owner").await;
    assert_eq!(challenge(&server, &fresh, &dev).await.0, 201);
}

#[tokio::test]
async fn concurrent_challenges_stop_at_the_cap() {
    let server = start("race", 28184).await;
    let dev = device(&server, OWNER, 0x3a, "pending").await;
    let ticket = server.login("owner").await;
    let t = ticket["ticket"].as_str().unwrap().to_string();
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..20 {
        let url = format!(
            "http://127.0.0.1:{}/v2/auth/device-session-challenges",
            server.port
        );
        let (t, body) = (t.clone(), json!({ "device_id": hex(&dev.id) }));
        tasks.spawn(async move {
            client()
                .post(url)
                .bearer_auth(t)
                .json(&body)
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        });
    }
    let mut created = 0;
    while let Some(status) = tasks.join_next().await {
        match status.unwrap() {
            201 => created += 1,
            409 => {}
            other => panic!("unexpected status {other}"),
        }
    }
    assert_eq!(created, 5);
    assert_eq!(
        server
            .count("SELECT count(*) FROM v2_device_session_challenges")
            .await,
        5
    );
}

#[tokio::test]
async fn a_session_rotates_a_bounded_number_of_times() {
    let server = start("rotations", 28188).await;
    let dev = device(&server, OWNER, 0x3d, "pending").await;
    let mut s = session(&server, &dev).await;
    for _ in 0..64 {
        let (status, r) = server
            .post(
                "/v2/auth/refresh",
                None,
                json!({ "refresh_token": s["refresh_token"] }),
            )
            .await;
        assert_eq!(status, 200, "{r}");
        s = r;
    }
    let (status, _) = server
        .post(
            "/v2/auth/refresh",
            None,
            json!({ "refresh_token": s["refresh_token"] }),
        )
        .await;
    assert_eq!(status, 401);
    assert_eq!(server.me(s["access_token"].as_str().unwrap()).await.0, 401);
    // The revoked session takes its spent tokens with it.
    assert_eq!(
        server
            .count("SELECT count(*) FROM v2_spent_refresh_tokens")
            .await,
        0
    );
}

#[tokio::test]
async fn a_ticket_enrolls_a_device_and_then_proves_it_into_a_session() {
    let server = start("enroll", 28185).await;
    // The Launcher names the tenant by ID; naming it twice is refused.
    let (status, _) = server
        .post(
            "/v2/auth/login",
            None,
            json!({ "tenant": "acme", "tenant_id": hex(&TENANT), "username": "owner", "password": PASSWORD }),
        )
        .await;
    assert_eq!(status, 400);
    let (status, ticket) = server
        .post(
            "/v2/auth/login",
            None,
            json!({ "tenant_id": hex(&TENANT), "username": "owner", "password": PASSWORD }),
        )
        .await;
    assert_eq!(status, 201, "{ticket}");
    let t = ticket["ticket"].as_str();

    let sk = Ed25519SigningKey::from_bytes(&[0x4b; 32]);
    let spk = sk.verifying_key().to_bytes();
    let (hpke_sk, hpk) = derive_keypair(&[0x4c; 32]);
    let keys = json!({ "signing_public_key": hex(&spk), "hpke_public_key": hex(&hpk) });
    let (status, ch) = server
        .post("/v2/devices/enrollment-challenges", t, keys.clone())
        .await;
    assert_eq!(status, 201, "{ch}");
    let binding = unhex(ch["binding"].as_str().unwrap());
    let parsed = sb::EnrollmentBindingV2::parse(&binding).unwrap();
    assert_eq!(parsed.fields.account_id, OWNER);
    assert_eq!(
        hex(&parsed.fields.pre_device_session_id),
        ticket["ticket_id"].as_str().unwrap()
    );
    let (status, enrolled) = server
        .post(
            "/v2/devices/enrollment-proofs",
            t,
            json!({
                "challenge_id": ch["challenge_id"],
                "signature": hex(&sb::sign_enrollment(&sk, &binding)),
                "label_ciphertext": hex(b"label"),
            }),
        )
        .await;
    assert_eq!(status, 201, "{enrolled}");
    assert_eq!(enrolled["status"], "pending");
    // The same keys cannot be enrolled twice.
    let (status, _) = server
        .post("/v2/devices/enrollment-challenges", t, keys)
        .await;
    assert_eq!(status, 409);

    // Enrollment left the ticket usable: it lists the device and proves it.
    let (_, me) = server.me(t.unwrap()).await;
    assert_eq!(me["devices"][0]["device_id"], enrolled["device_id"]);
    let dev = Device {
        id: unhex(enrolled["device_id"].as_str().unwrap())
            .try_into()
            .unwrap(),
        sk,
        hpke_sk,
        signing_key_id: signing_key_id(&spk),
        hpke_key_id: hpke_key_id(&hpk),
        hpke_pk: hpk,
    };
    let (status, ch) = challenge(&server, &ticket, &dev).await;
    assert_eq!(status, 201, "{ch}");
    let (status, s) = server
        .post(
            "/v2/auth/device-session-proofs",
            t,
            answer(&ticket, &ch, &dev),
        )
        .await;
    assert_eq!(status, 201, "{s}");
    assert_eq!(s["device_id"], enrolled["device_id"]);

    // A session is not a ticket: it cannot enroll another device.
    let (status, _) = server
        .post(
            "/v2/devices/enrollment-challenges",
            s["access_token"].as_str(),
            json!({ "signing_public_key": hex(&[0x11; 32]), "hpke_public_key": hex(&[0x12; 32]) }),
        )
        .await;
    assert_eq!(status, 403);

    // Logout ends a ticket's open enrollment challenges too.
    let other = server.login("owner").await;
    let sk2 = Ed25519SigningKey::from_bytes(&[0x4d; 32]);
    let (_, hpk2) = derive_keypair(&[0x4e; 32]);
    let (status, _) = server
        .post(
            "/v2/devices/enrollment-challenges",
            other["ticket"].as_str(),
            json!({ "signing_public_key": hex(&sk2.verifying_key().to_bytes()), "hpke_public_key": hex(&hpk2) }),
        )
        .await;
    assert_eq!(status, 201);
    assert_eq!(
        server
            .post("/v2/auth/logout", other["ticket"].as_str(), json!({}))
            .await
            .0,
        204
    );
    assert_eq!(
        server
            .count(
                "SELECT count(*) FROM v2_enrollment_challenges \
                 WHERE consumed_at_ms IS NULL AND revoked_at_ms IS NULL"
            )
            .await,
        0
    );
}

#[tokio::test]
async fn a_wrong_enrollment_signature_burns_the_challenge() {
    let server = start("enroll-wrong", 28186).await;
    let ticket = server.login("owner").await;
    let t = ticket["ticket"].as_str();
    let sk = Ed25519SigningKey::from_bytes(&[0x4f; 32]);
    let (_, hpk) = derive_keypair(&[0x50; 32]);
    let (_, ch) = server
        .post(
            "/v2/devices/enrollment-challenges",
            t,
            json!({ "signing_public_key": hex(&sk.verifying_key().to_bytes()), "hpke_public_key": hex(&hpk) }),
        )
        .await;
    let binding = unhex(ch["binding"].as_str().unwrap());
    let prove = |signer: &Ed25519SigningKey| {
        json!({
            "challenge_id": ch["challenge_id"],
            "signature": hex(&sb::sign_enrollment(signer, &binding)),
            "label_ciphertext": "",
        })
    };
    let impostor = Ed25519SigningKey::from_bytes(&[0x51; 32]);
    let (status, _) = server
        .post("/v2/devices/enrollment-proofs", t, prove(&impostor))
        .await;
    assert_eq!(status, 401);
    let (status, _) = server
        .post("/v2/devices/enrollment-proofs", t, prove(&sk))
        .await;
    assert_eq!(status, 401, "the challenge is spent");
    assert_eq!(server.count("SELECT count(*) FROM v2_devices").await, 0);
    // Another ticket of the same account cannot redeem it either.
    let second = server.login("owner").await;
    let (status, _) = server
        .post(
            "/v2/devices/enrollment-proofs",
            second["ticket"].as_str(),
            prove(&sk),
        )
        .await;
    assert_eq!(status, 404);

    // Enrollment challenges spend the ticket's lifetime budget too.
    for seed in 0x52..0x56u8 {
        let (_, hpk) = derive_keypair(&[seed; 32]);
        let (status, _) = server
            .post(
                "/v2/devices/enrollment-challenges",
                t,
                json!({ "signing_public_key": hex(&Ed25519SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes()), "hpke_public_key": hex(&hpk) }),
            )
            .await;
        assert_eq!(status, 201);
    }
    let (_, hpk) = derive_keypair(&[0x56; 32]);
    let (status, _) = server
        .post(
            "/v2/devices/enrollment-challenges",
            t,
            json!({ "signing_public_key": hex(&Ed25519SigningKey::from_bytes(&[0x56; 32]).verifying_key().to_bytes()), "hpke_public_key": hex(&hpk) }),
        )
        .await;
    assert_eq!(status, 409);
}

// ------------------------------------------------------------ D1 approval ---

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

const DAY_MS: u64 = 86_400_000;

/// A D1 self-approval of `dev`, signed by `signer`.
fn approval(
    dev: &Device,
    signer: &Ed25519SigningKey,
    replay: u8,
    epoch: u64,
    days: u64,
) -> Vec<u8> {
    let start = now_ms() - 60_000;
    approval_window(dev, signer, replay, epoch, start, start + days * DAY_MS)
}

/// The same approval with an explicit validity window.
fn approval_window(
    dev: &Device,
    signer: &Ed25519SigningKey,
    replay: u8,
    epoch: u64,
    not_before_ms: u64,
    not_after_ms: u64,
) -> Vec<u8> {
    let payload = DeviceApprovalV2 {
        common: CommonFields {
            replay_id: [replay; 16],
            tenant_id: TENANT,
            issued_at_ms: not_before_ms,
            not_before_ms,
            not_after_ms,
            server_instance_id: INSTANCE,
            restore_epoch: epoch,
        },
        subject_account_id: OWNER,
        subject_device_id: dev.id,
        subject_signing_key_id: dev.signing_key_id,
        subject_hpke_key_id: dev.hpke_key_id,
        approval_scope_kind: ApprovalScopeKind::Tenant,
        approval_scope_id: TENANT,
    }
    .encode();
    build_record(signer, DOMAIN_DEVICE_APPROVAL, &payload)
}

fn code(body: &[u8]) -> String {
    serde_json::from_slice::<Value>(body).unwrap_or(Value::Null)["code"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

#[tokio::test]
async fn the_first_device_approves_itself_once_and_a_retry_gets_the_same_receipt() {
    let mut server = start("d1", 28190).await;
    let dev = device(&server, OWNER, 0x61, "pending").await;
    let confirmation_id = server.confirm(&dev).await;
    // A second pending device of the same owner, with a live setup session.
    let bystander = device(&server, OWNER, 0x68, "pending").await;
    let bystander_session = session(&server, &bystander).await;
    let other_session = session(&server, &dev).await;
    let s = session(&server, &dev).await;
    let access = s["access_token"].as_str().unwrap();

    let rec = approval(&dev, &dev.sk, 0x71, 0, 30);
    let (status, ct, receipt) = server.approve(&dev.id, access, &rec).await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&receipt));
    assert_eq!(ct, "application/cbor");
    let r = DeviceApprovalReceiptV2::parse(&receipt).unwrap();
    assert_eq!(
        (r.server_instance_id, r.restore_epoch, r.tenant_id),
        (INSTANCE, 0, TENANT)
    );
    assert_eq!((r.actor_account_id, r.actor_device_id), (OWNER, dev.id));
    assert_eq!(
        (r.subject_device_id, r.approval_replay_id),
        (dev.id, [0x71; 16])
    );
    assert_eq!(r.approval_outer_sha256, sha256(&rec));
    assert_eq!(r.confirmation_id, Some(confirmation_id));

    // Every transition happened, once.
    for (query, want) in [
        ("SELECT count(*) FROM v2_devices WHERE status = 'active'", 1),
        ("SELECT count(*) FROM v2_device_approvals", 1),
        ("SELECT count(*) FROM v2_idempotency WHERE operation_kind = 'DEVICE_APPROVE'", 1),
        ("SELECT count(*) FROM v2_bootstrap_guards WHERE state = 'consumed'", 1),
        (
            "SELECT count(*) FROM v2_first_device_confirmations \
              WHERE state = 'consumed' AND approval_replay_id = x'71717171717171717171717171717171'",
            1,
        ),
        ("SELECT count(*) FROM v2_audit_events WHERE action = 'device.approve'", 1),
    ] {
        assert_eq!(server.count(query).await, want, "{query}");
    }
    let (status, me) = server.me(access).await;
    assert_eq!((status, me["class"].as_str()), (200, Some("root_setup")));
    // The device's other setup session is not promoted; it simply ends.
    let (status, _) = server
        .me(other_session["access_token"].as_str().unwrap())
        .await;
    assert_eq!(status, 401);

    // A lost response: the same bytes get the same receipt, and nothing more.
    let (status, _, again) = server.approve(&dev.id, access, &rec).await;
    assert_eq!((status, &again), (201, &receipt));
    assert_eq!(
        server
            .count("SELECT count(*) FROM v2_audit_events WHERE action = 'device.approve'")
            .await,
        1
    );
    // Other bytes under that replay ID, and any new D1 approval, are refused.
    let changed = approval(&dev, &dev.sk, 0x71, 0, 31);
    let (status, _, body) = server.approve(&dev.id, access, &changed).await;
    assert_eq!(
        (status, code(&body).as_str()),
        (409, "IDEMPOTENCY_MISMATCH")
    );
    // The replay ID is reserved for its first actor: another device gets a
    // conflict, not the receipt.
    let (status, _, body) = server
        .approve(
            &dev.id,
            bystander_session["access_token"].as_str().unwrap(),
            &rec,
        )
        .await;
    assert_eq!(
        (status, code(&body).as_str()),
        (409, "IDEMPOTENCY_MISMATCH")
    );
    let (status, _, body) = server.approve(&bystander.id, access, &rec).await;
    assert_eq!(
        (status, code(&body).as_str()),
        (409, "IDEMPOTENCY_MISMATCH")
    );
    // After D1 a second self-approval is an ordinary renewal (ADR 0002 D-2),
    // which needs `device.approve`; the device holds none yet.
    let second = approval(&dev, &dev.sk, 0x72, 0, 30);
    assert_eq!(server.approve(&dev.id, access, &second).await.0, 403);

    // After a restart the device proves itself again into root_setup, and the
    // new session, same actor and keys, still gets the stored receipt.
    server.restart().await;
    let s2 = session(&server, &dev).await;
    assert_eq!(s2["class"], "root_setup");
    assert_ne!(s2["session_id"], s["session_id"]);
    let access2 = s2["access_token"].as_str().unwrap();
    let (status, _, again) = server.approve(&dev.id, access2, &rec).await;
    assert_eq!((status, &again), (201, &receipt));
    // The receipt goes only to the tenant's sole owner, checked at each retry.
    server
        .sql(
            "UPDATE v2_tenant_memberships SET role = 'member' WHERE account_id = ?",
            &[&OWNER],
        )
        .await;
    assert_eq!(server.approve(&dev.id, access2, &rec).await.0, 403);
    server
        .sql(
            "UPDATE v2_tenant_memberships SET role = 'owner' WHERE account_id = ?",
            &[&OWNER],
        )
        .await;

    // Revoking the approval ends root_setup at once, and no new session
    // starts on it: not from a fresh challenge, and not from one opened
    // while the approval was still live.
    let early = server.login("owner").await;
    let (status, open) = challenge(&server, &early, &dev).await;
    assert_eq!(status, 201, "{open}");
    server
        .sql("UPDATE v2_device_approvals SET revoked_at = 't'", &[])
        .await;
    assert_eq!(server.me(access2).await.0, 401);
    let (status, _) = server
        .post(
            "/v2/auth/device-session-proofs",
            early["ticket"].as_str(),
            answer(&early, &open, &dev),
        )
        .await;
    assert_eq!(status, 409);
    let ticket = server.login("owner").await;
    assert_eq!(challenge(&server, &ticket, &dev).await.0, 409);
}

#[tokio::test]
async fn a_closed_or_recovering_guard_never_approves() {
    // An inconsistency found while the confirmation is still pending.
    let mut server = start("d1-recovery", 28194).await;
    let dev = device(&server, OWNER, 0x6a, "pending").await;
    server.confirm(&dev).await;
    server
        .sql(
            "UPDATE v2_bootstrap_guards SET state = 'recovery_required', \
             recovery_reason = 'integrity_failure'",
            &[],
        )
        .await;
    let s = session(&server, &dev).await;
    let access = s["access_token"].as_str().unwrap();
    let rec = approval(&dev, &dev.sk, 0x7b, 0, 30);
    assert_eq!(server.approve(&dev.id, access, &rec).await.0, 403);
    assert_eq!(
        server
            .count("SELECT count(*) FROM v2_device_approvals")
            .await,
        0
    );
    drop(server);

    // The operator cancelled the attempt: closed for good, not just refused.
    let mut server = start("d1-cancelled", 28195).await;
    let dev = device(&server, OWNER, 0x6b, "pending").await;
    server.confirm(&dev).await;
    let out = server
        .offline(&["tenant", "cancel-first-device", "--tenant", "acme"], "")
        .await;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = session(&server, &dev).await;
    let (status, _, body) = server
        .approve(
            &dev.id,
            s["access_token"].as_str().unwrap(),
            &approval(&dev, &dev.sk, 0x7c, 0, 30),
        )
        .await;
    assert_eq!(
        (status, code(&body).as_str()),
        (409, "FIRST_DEVICE_ALREADY_CLOSED")
    );
    assert_eq!(
        server
            .count("SELECT count(*) FROM v2_device_approvals")
            .await,
        0
    );
}

#[tokio::test]
async fn an_approval_needs_the_confirmation_the_session_and_the_exact_subject() {
    let mut server = start("d1-refusals", 28191).await;
    let dev = device(&server, OWNER, 0x63, "pending").await;
    let s = session(&server, &dev).await;
    let access = s["access_token"].as_str().unwrap();
    let good = approval(&dev, &dev.sk, 0x73, 0, 30);

    // No offline confirmation yet.
    assert_eq!(server.approve(&dev.id, access, &good).await.0, 403);
    // A ticket proves only the password.
    let ticket = server.login("owner").await;
    assert_eq!(
        server
            .approve(&dev.id, ticket["ticket"].as_str().unwrap(), &good)
            .await
            .0,
        403
    );

    server.confirm(&dev).await;
    // JSON is not the exact signed record.
    let (status, _) = server
        .post(
            &format!("/v2/devices/{}/approve", hex(&dev.id)),
            Some(access),
            json!({ "record_hex": hex(&good) }),
        )
        .await;
    assert_eq!(status, 400);
    // The path must name the approval's subject.
    assert_eq!(server.approve(&[0x99; 16], access, &good).await.0, 400);
    // Another epoch is stale, not a new approval.
    let (status, _, body) = server
        .approve(&dev.id, access, &approval(&dev, &dev.sk, 0x74, 1, 30))
        .await;
    assert_eq!((status, code(&body).as_str()), (409, "STALE_CONTEXT"));
    // One flipped byte breaks the container.
    let mut tampered = good.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let (status, _, body) = server.approve(&dev.id, access, &tampered).await;
    assert_eq!(status, 422);
    assert!(!code(&body).is_empty());
    // A key that is not a device here, and a device that is not the subject.
    let stranger = Ed25519SigningKey::from_bytes(&[0x64; 32]);
    let (status, _, body) = server
        .approve(&dev.id, access, &approval(&dev, &stranger, 0x75, 0, 30))
        .await;
    assert_eq!(
        (status, code(&body).as_str()),
        (422, "KEY_SUBSTITUTION_DETECTED")
    );
    let other = device(&server, OTHER, 0x65, "pending").await;
    assert_eq!(
        server
            .approve(&dev.id, access, &approval(&dev, &other.sk, 0x76, 0, 30))
            .await
            .0,
        403
    );
    // A window longer than the 730-day policy, one not yet open, one over.
    let now = now_ms();
    for rec in [
        approval(&dev, &dev.sk, 0x77, 0, 731),
        approval_window(&dev, &dev.sk, 0x7d, 0, now + 600_000, now + 30 * DAY_MS),
        approval_window(&dev, &dev.sk, 0x7e, 0, now - 2 * DAY_MS, now - DAY_MS),
    ] {
        assert_eq!(server.approve(&dev.id, access, &rec).await.0, 403);
    }
    // A second owner, added after the confirmation, ends the sole-owner case.
    server
        .sql(
            "UPDATE v2_tenant_memberships SET role = 'owner' WHERE account_id = ?",
            &[&OTHER],
        )
        .await;
    assert_eq!(server.approve(&dev.id, access, &good).await.0, 403);
    server
        .sql(
            "UPDATE v2_tenant_memberships SET role = 'member' WHERE account_id = ?",
            &[&OTHER],
        )
        .await;

    // The confirmation names `dev`; another pending device of the owner cannot
    // use it, even approving itself on its own session.
    let dev2 = device(&server, OWNER, 0x69, "pending").await;
    let s2 = session(&server, &dev2).await;
    assert_eq!(
        server
            .approve(
                &dev2.id,
                s2["access_token"].as_str().unwrap(),
                &approval(&dev2, &dev2.sk, 0x7a, 0, 30),
            )
            .await
            .0,
        403
    );

    // A well-formed, correctly signed record of another kind is not an approval.
    let start = now_ms() - 60_000;
    let grant = TenantCapabilityGrantV2 {
        common: CommonFields {
            replay_id: [0x7f; 16],
            tenant_id: TENANT,
            issued_at_ms: start,
            not_before_ms: start,
            not_after_ms: start + 30 * DAY_MS,
            server_instance_id: INSTANCE,
            restore_epoch: 0,
        },
        subject: GrantSubject::Device {
            account_id: OWNER,
            device_id: dev.id,
            signing_key_id: dev.signing_key_id,
            hpke_key_id: dev.hpke_key_id,
        },
        scope_kind: CapabilityScopeKind::Tenant,
        scope_id: TENANT,
        capability: Capability::DeviceApprove,
    }
    .encode();
    let (status, _, body) = server
        .approve(
            &dev.id,
            access,
            &build_record(&dev.sk, DOMAIN_TENANT_CAPABILITY_GRANT, &grant),
        )
        .await;
    assert_eq!(
        (status, code(&body).as_str()),
        (422, "AUTH_CLAIM_COLUMN_MISMATCH")
    );

    // None of that wrote anything; the real approval still goes through.
    for query in [
        "SELECT count(*) FROM v2_device_approvals",
        "SELECT count(*) FROM v2_idempotency",
        "SELECT count(*) FROM v2_devices WHERE status = 'active'",
        "SELECT count(*) FROM v2_bootstrap_guards WHERE state <> 'reserved'",
    ] {
        assert_eq!(server.count(query).await, 0, "{query}");
    }
    assert_eq!(server.approve(&dev.id, access, &good).await.0, 201);
}

#[tokio::test]
async fn concurrent_identical_approvals_commit_once() {
    let mut server = start("d1-race", 28192).await;
    let dev = device(&server, OWNER, 0x66, "pending").await;
    server.confirm(&dev).await;
    let s = session(&server, &dev).await;
    let access = s["access_token"].as_str().unwrap();
    let rec = approval(&dev, &dev.sk, 0x78, 0, 30);
    let (a, b) = tokio::join!(
        server.approve(&dev.id, access, &rec),
        server.approve(&dev.id, access, &rec)
    );
    assert_eq!((a.0, b.0), (201, 201));
    assert_eq!(a.2, b.2, "one commit, one receipt");
    assert_eq!(server.count("SELECT count(*) FROM v2_idempotency").await, 1);
    assert_eq!(
        server
            .count("SELECT count(*) FROM v2_audit_events WHERE action = 'device.approve'")
            .await,
        1
    );
}

#[tokio::test]
async fn a_stored_receipt_that_disagrees_closes_the_approval_path() {
    let mut server = start("d1-integrity", 28193).await;
    let dev = device(&server, OWNER, 0x67, "pending").await;
    server.confirm(&dev).await;
    let s = session(&server, &dev).await;
    let access = s["access_token"].as_str().unwrap();
    let rec = approval(&dev, &dev.sk, 0x79, 0, 30);
    assert_eq!(server.approve(&dev.id, access, &rec).await.0, 201);

    let (_, _, stored) = server.approve(&dev.id, access, &rec).await;
    // Behind the trigger's back, store a receipt that parses, whose hash
    // matches, and that names another request.
    let mut forged = DeviceApprovalReceiptV2::parse(&stored).unwrap();
    forged.request_hash[0] ^= 1;
    let forged = forged.encode();
    for trigger in [
        "v2_idempotency_device_approve_is_fixed",
        "v2_idempotency_succeeded_is_fixed",
    ] {
        server.sql(&format!("DROP TRIGGER {trigger}"), &[]).await;
    }
    server
        .sql(
            "UPDATE v2_idempotency SET exact_response_bytes = ?, exact_response_bytes_sha256 = ?",
            &[&forged, &sha256(&forged)],
        )
        .await;
    let (status, _, body) = server.approve(&dev.id, access, &rec).await;
    assert_eq!(
        (status, code(&body).as_str()),
        (422, "MUTATION_RESPONSE_MISMATCH")
    );
    assert_eq!(
        server
            .count("SELECT count(*) FROM v2_bootstrap_guards WHERE state = 'recovery_required'")
            .await,
        1
    );
    // root_setup needs a consumed guard, so the session ends with it.
    assert_eq!(server.me(access).await.0, 401);
}

// ------------------------------------------------------ S6 root bootstrap ---

const TRK: [u8; 32] = [0x7c; 32];
const APPROVAL_REPLAY: u8 = 0x71;

/// D1 for a fresh pending device of the owner; returns it and its
/// `root_setup` access token.
async fn approved(server: &mut Server, seed: u8) -> (Device, String) {
    let dev = device(server, OWNER, seed, "pending").await;
    server.confirm(&dev).await;
    let s = session(server, &dev).await;
    let access = s["access_token"].as_str().unwrap().to_string();
    let rec = approval(&dev, &dev.sk, APPROVAL_REPLAY, 0, 30);
    assert_eq!(server.approve(&dev.id, &access, &rec).await.0, 201);
    (dev, access)
}

/// An honest first self-grant of `trk` to `dev`, sealed to its HPKE key.
fn self_grant(
    dev: &Device,
    trk: &[u8; 32],
    edit: impl FnOnce(&mut TenantRootKeyGrantV2),
) -> Vec<u8> {
    let start = now_ms() - 60_000;
    let mut g = TenantRootKeyGrantV2 {
        common: CommonFields {
            replay_id: [0x81; 16],
            tenant_id: TENANT,
            issued_at_ms: start,
            not_before_ms: start,
            not_after_ms: start + 30 * DAY_MS,
            server_instance_id: INSTANCE,
            restore_epoch: 0,
        },
        variant: RootGrantVariant::FirstRootSelfGrant,
        root_key_id: shared::keys::root_key_id(trk),
        root_generation: 0,
        subject_account_id: OWNER,
        subject_device_id: dev.id,
        subject_signing_key_id: dev.signing_key_id,
        recipient_hpke_key_id: dev.hpke_key_id,
        subject_device_approval_replay_id: [APPROVAL_REPLAY; 16],
        hpke_encapped_key_bytes: [0; 32],
        hpke_wrapped_trk_bytes: [0; 48],
    };
    let sealed = shared::grants::seal_trk(&dev.hpke_pk, &g.scope(), trk).unwrap();
    g.hpke_encapped_key_bytes = sealed.encapped_key_bytes.try_into().unwrap();
    g.hpke_wrapped_trk_bytes = sealed.ciphertext_bytes.try_into().unwrap();
    edit(&mut g);
    build_record(&dev.sk, DOMAIN_TENANT_ROOT_KEY_GRANT, &g.encode())
}

/// The bootstrap create naming `container`, with `edit` applied.
fn bootstrap_create(
    trk: &[u8; 32],
    container: Vec<u8>,
    edit: impl FnOnce(&mut TenantRootGenerationCreateV2),
) -> TenantRootGenerationCreateV2 {
    let hash = *AuthorizationRecord::parse(&container)
        .unwrap()
        .signed_container_hash();
    let mut create = TenantRootGenerationCreateV2 {
        target: RootGenerationTarget {
            tenant_id: TENANT,
            server_instance_id: INSTANCE,
            restore_epoch: 0,
            root_key_id: shared::keys::root_key_id(trk),
            root_generation: 0,
            required_custodian_grant_count: 1,
            required_custodian_grant_set_hash: root_custodian_grant_set_hash(&[hash]).unwrap(),
            recovery_bundle_sha256: [0x5a; 32],
        },
        mode: RootGenerationMode::Bootstrap(EmbeddedSelfGrant {
            container_bytes: container,
            signed_container_hash: hash,
        }),
    };
    edit(&mut create);
    create
}

/// The exact outer request under idempotency key `key`.
fn root_request(key: u8, create: &TenantRootGenerationCreateV2) -> Vec<u8> {
    IdempotentMutationRequestV2 {
        operation_kind: OperationKind::RootGenerationCreate,
        idempotency_key: [key; 16],
        canonical_payload_bytes: create.encode(),
        client_request_nonce: [0x92; 16],
        server_instance_id: INSTANCE,
        restore_epoch: 0,
    }
    .encode()
}

fn code_of(body: &[u8]) -> String {
    code(body)
}

#[tokio::test]
async fn the_first_device_bootstraps_the_root_once_and_a_retry_gets_the_same_response() {
    let mut server = start("s6", 28196).await;
    let (dev, access) = approved(&mut server, 0x61).await;
    let create = bootstrap_create(&TRK, self_grant(&dev, &TRK, |_| {}), |_| {});
    let req = root_request(0x91, &create);

    let (status, stored) = server.root(&TENANT, &access, &req).await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&stored));
    let response = IdempotentStoredResponseV2::parse(&stored).unwrap();
    assert_eq!(response.operation_kind, OperationKind::RootGenerationCreate);
    assert_eq!(
        response.exact_request_hash,
        IdempotentMutationRequestV2::parse(&req)
            .unwrap()
            .canonical_request_hash()
    );
    let created =
        TenantRootGenerationCreatedV2::parse(&response.canonical_response_payload_bytes).unwrap();
    assert_eq!(created.target, create.target);
    let RootGenerationMode::Bootstrap(identity) = &created.mode else {
        panic!("a bootstrap response names its self-grant")
    };
    assert_eq!(identity.replay_id, [0x81; 16]);

    for (query, want) in [
        (
            "SELECT count(*) FROM v2_root_key_generations
              WHERE generation = 0 AND state = 'PREPARING' AND required_custodian_grant_count = 1",
            1,
        ),
        (
            "SELECT count(*) FROM v2_tenant_root_key_grants
              WHERE grant_variant = 'FirstRootSelfGrant' AND acked_at IS NULL",
            1,
        ),
        (
            "SELECT count(*) FROM v2_idempotency WHERE operation_kind = 'ROOT_GENERATION_CREATE'",
            1,
        ),
        (
            "SELECT count(*) FROM v2_audit_events WHERE action = 'root.bootstrap'",
            1,
        ),
    ] {
        assert_eq!(server.count(query).await, want, "{query}");
    }

    // The filed grant is the exact signed container, and it opens on the
    // device to the TRK its key ID names.
    let pool = db(&server.data).await;
    let exact: Vec<u8> =
        sqlx::query_scalar("SELECT exact_signed_container_bytes FROM v2_tenant_root_key_grants")
            .fetch_one(&pool)
            .await
            .unwrap();
    pool.close().await;
    let EmbeddedSelfGrant {
        container_bytes, ..
    } = match &create.mode {
        RootGenerationMode::Bootstrap(g) => g.clone(),
        RootGenerationMode::Rotation { .. } => unreachable!(),
    };
    assert_eq!(exact, container_bytes);
    let verified = AuthorizationRecord::parse(&exact)
        .unwrap()
        .verify_signature(dev.sk.verifying_key().as_bytes())
        .unwrap();
    let Payload::TenantRootKeyGrant(g) = verified.payload() else {
        panic!("a root grant")
    };
    assert_eq!(*g.open_trk(&dev.hpke_sk).unwrap(), TRK);

    // A lost response: the same bytes get the same response, and nothing more.
    let (status, again) = server.root(&TENANT, &access, &req).await;
    assert_eq!((status, &again), (201, &stored));
    assert_eq!(
        server
            .count("SELECT count(*) FROM v2_audit_events WHERE action = 'root.bootstrap'")
            .await,
        1
    );
    // Other bytes under the key are a mismatch; a new bootstrap is refused.
    let other_nonce = IdempotentMutationRequestV2 {
        client_request_nonce: [0x93; 16],
        ..IdempotentMutationRequestV2::parse(&req).unwrap()
    }
    .encode();
    let (status, body) = server.root(&TENANT, &access, &other_nonce).await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (409, "IDEMPOTENCY_MISMATCH")
    );
    let trk2 = [0x7d; 32];
    let second = bootstrap_create(
        &trk2,
        self_grant(&dev, &trk2, |g| g.common.replay_id = [0x82; 16]),
        |_| {},
    );
    let (status, body) = server
        .root(&TENANT, &access, &root_request(0x94, &second))
        .await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (409, "ROOT_BOOTSTRAP_ALREADY_EXISTS")
    );
    // The stored response cannot be rewritten in place.
    let pool = db(&server.data).await;
    let rewrite = sqlx::query("UPDATE v2_idempotency SET retained_until = 0")
        .execute(&pool)
        .await;
    pool.close().await;
    assert!(rewrite.is_err());
}

#[tokio::test]
async fn a_bootstrap_needs_d1_the_setup_session_and_an_exact_self_grant() {
    let mut server = start("s6-refusals", 28197).await;
    // Before D1 the device's session is pending_setup.
    let early = device(&server, OWNER, 0x62, "pending").await;
    let s = session(&server, &early).await;
    let pending = s["access_token"].as_str().unwrap().to_string();
    let honest = |dev: &Device| bootstrap_create(&TRK, self_grant(dev, &TRK, |_| {}), |_| {});
    assert_eq!(
        server
            .root(&TENANT, &pending, &root_request(0xa0, &honest(&early)))
            .await
            .0,
        403
    );

    server
        .sql("DELETE FROM v2_devices WHERE id = ?", &[&early.id])
        .await;
    let (dev, access) = approved(&mut server, 0x63).await;
    let other = device(&server, OWNER, 0x64, "pending").await;
    let refused = |status: u16, code: &'static str| (status, code.to_string());
    let cases: Vec<((u16, String), TenantRootGenerationCreateV2)> = vec![
        // The self-grant names another approval, recipient or key.
        (
            refused(422, "AUTH_CLAIM_COLUMN_MISMATCH"),
            bootstrap_create(
                &TRK,
                self_grant(&dev, &TRK, |g| {
                    g.subject_device_approval_replay_id = [0x77; 16]
                }),
                |_| {},
            ),
        ),
        (
            refused(422, "AUTH_CLAIM_COLUMN_MISMATCH"),
            bootstrap_create(
                &TRK,
                self_grant(&dev, &TRK, |g| g.recipient_hpke_key_id = other.hpke_key_id),
                |_| {},
            ),
        ),
        // Signed by this device, but naming another subject or context.
        (
            refused(422, "AUTH_CLAIM_COLUMN_MISMATCH"),
            bootstrap_create(
                &TRK,
                self_grant(&dev, &TRK, |g| g.subject_device_id = other.id),
                |_| {},
            ),
        ),
        (
            refused(422, "AUTH_CLAIM_COLUMN_MISMATCH"),
            bootstrap_create(
                &TRK,
                self_grant(&dev, &TRK, |g| g.subject_account_id = OTHER),
                |_| {},
            ),
        ),
        (
            refused(422, "AUTH_CLAIM_COLUMN_MISMATCH"),
            bootstrap_create(
                &TRK,
                self_grant(&dev, &TRK, |g| g.common.tenant_id = [0x42; 16]),
                |_| {},
            ),
        ),
        (
            refused(422, "AUTH_CLAIM_COLUMN_MISMATCH"),
            bootstrap_create(
                &TRK,
                self_grant(&dev, &TRK, |g| g.common.server_instance_id = [0x43; 16]),
                |_| {},
            ),
        ),
        (
            refused(422, "AUTH_CLAIM_COLUMN_MISMATCH"),
            bootstrap_create(
                &TRK,
                self_grant(&dev, &TRK, |g| g.common.restore_epoch = 1),
                |_| {},
            ),
        ),
        (
            refused(422, "AUTH_CLAIM_COLUMN_MISMATCH"),
            bootstrap_create(&TRK, self_grant(&dev, &TRK, |_| {}), |c| {
                c.target.root_key_id = [0x33; 32]
            }),
        ),
        // The custodian set is the self-grant alone; the codec refuses it.
        (
            refused(422, "NON_CANONICAL_RECORD"),
            bootstrap_create(&TRK, self_grant(&dev, &TRK, |_| {}), |c| {
                c.target.required_custodian_grant_count = 2
            }),
        ),
        (
            refused(422, "NON_CANONICAL_RECORD"),
            bootstrap_create(&TRK, self_grant(&dev, &TRK, |_| {}), |c| {
                c.target.required_custodian_grant_set_hash = [0x34; 32]
            }),
        ),
        // The request names another container hash than the bytes have, with
        // a custodian set consistent with that claim.
        (
            refused(422, "AUTH_CLAIM_COLUMN_MISMATCH"),
            bootstrap_create(&TRK, self_grant(&dev, &TRK, |_| {}), |c| {
                if let RootGenerationMode::Bootstrap(g) = &mut c.mode {
                    g.signed_container_hash = [0x35; 32];
                }
                c.target.required_custodian_grant_set_hash =
                    root_custodian_grant_set_hash(&[[0x35; 32]]).unwrap();
            }),
        ),
        // Another device's honest self-grant is not this session's.
        (
            refused(422, "KEY_SUBSTITUTION_DETECTED"),
            bootstrap_create(&TRK, self_grant(&other, &TRK, |_| {}), |_| {}),
        ),
        // A grant that is not yet valid, or valid for more than 730 days.
        (
            refused(403, ""),
            bootstrap_create(
                &TRK,
                self_grant(&dev, &TRK, |g| {
                    g.common.issued_at_ms = now_ms() + 3_600_000;
                    g.common.not_before_ms = now_ms() + 3_600_000;
                }),
                |_| {},
            ),
        ),
        (
            refused(403, ""),
            bootstrap_create(
                &TRK,
                self_grant(&dev, &TRK, |g| {
                    g.common.not_after_ms = g.common.not_before_ms + 731 * DAY_MS;
                }),
                |_| {},
            ),
        ),
        // A grant whose window has closed.
        (
            refused(403, ""),
            bootstrap_create(
                &TRK,
                self_grant(&dev, &TRK, |g| {
                    g.common.issued_at_ms = 1;
                    g.common.not_before_ms = 1;
                    g.common.not_after_ms = 2;
                }),
                |_| {},
            ),
        ),
        // Rotation needs an ACTIVE root.
        (
            refused(403, ""),
            bootstrap_create(&TRK, self_grant(&dev, &TRK, |_| {}), |c| {
                c.target.root_generation = 1;
                c.mode = RootGenerationMode::Rotation {
                    previous_root_key_id: [0x36; 32],
                    previous_root_generation: 0,
                };
            }),
        ),
    ];
    for (i, (want, create)) in cases.into_iter().enumerate() {
        let (status, body) = server
            .root(&TENANT, &access, &root_request(0xb0 + i as u8, &create))
            .await;
        assert_eq!((status, code_of(&body)), want, "case {i}");
    }

    // Another tenant named by both the path and the target is still not the
    // session's tenant.
    let elsewhere = bootstrap_create(&TRK, self_grant(&dev, &TRK, |_| {}), |c| {
        c.target.tenant_id = [0x42; 16]
    });
    assert_eq!(
        server
            .root(&[0x42; 16], &access, &root_request(0xbf, &elsewhere))
            .await
            .0,
        403
    );

    // Context: another epoch, another tenant's path, another operation.
    let good = honest(&dev);
    let stale = IdempotentMutationRequestV2 {
        restore_epoch: 1,
        ..IdempotentMutationRequestV2::parse(&root_request(0xc0, &good)).unwrap()
    }
    .encode();
    let (status, body) = server.root(&TENANT, &access, &stale).await;
    assert_eq!((status, code_of(&body).as_str()), (409, "STALE_CONTEXT"));
    let (status, body) = server
        .root(&[0x42; 16], &access, &root_request(0xc1, &good))
        .await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (422, "AUTH_CLAIM_COLUMN_MISMATCH")
    );
    let grant_kind = IdempotentMutationRequestV2 {
        operation_kind: OperationKind::RootGrantCreate,
        ..IdempotentMutationRequestV2::parse(&root_request(0xc2, &good)).unwrap()
    }
    .encode();
    let (status, body) = server.root(&TENANT, &access, &grant_kind).await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (422, "AUTH_CLAIM_COLUMN_MISMATCH")
    );
    // Only the tenant's sole owner bootstraps.
    server
        .sql(
            "UPDATE v2_tenant_memberships SET role = 'owner' WHERE account_id = ?",
            &[&OTHER],
        )
        .await;
    assert_eq!(
        server
            .root(&TENANT, &access, &root_request(0xc3, &good))
            .await
            .0,
        403
    );
    server
        .sql(
            "UPDATE v2_tenant_memberships SET role = 'member' WHERE account_id = ?",
            &[&OTHER],
        )
        .await;

    // Nothing was written by any refusal, and the honest request still works.
    for table in [
        "v2_root_key_generations",
        "v2_tenant_root_key_grants",
        "v2_audit_events WHERE action = 'root.bootstrap'",
    ] {
        assert_eq!(
            server.count(&format!("SELECT count(*) FROM {table}")).await,
            0,
            "{table}"
        );
    }
    assert_eq!(
        server
            .root(&TENANT, &access, &root_request(0xc4, &good))
            .await
            .0,
        201
    );
}

#[tokio::test]
async fn concurrent_identical_bootstraps_commit_once_and_a_bad_ledger_is_refused() {
    let mut server = start("s6-race", 28198).await;
    let (dev, access) = approved(&mut server, 0x65).await;
    let req = root_request(
        0x95,
        &bootstrap_create(&TRK, self_grant(&dev, &TRK, |_| {}), |_| {}),
    );
    let (a, b) = tokio::join!(
        server.root(&TENANT, &access, &req),
        server.root(&TENANT, &access, &req)
    );
    assert_eq!((a.0, b.0), (201, 201));
    assert_eq!(a.1, b.1, "one commit, one response");
    assert_eq!(
        server
            .count("SELECT count(*) FROM v2_root_key_generations")
            .await,
        1
    );

    // Behind the trigger's back, store a response that parses and hashes
    // consistently but names another request.
    let mut forged = IdempotentStoredResponseV2::parse(&a.1).unwrap();
    forged.exact_request_hash[0] ^= 1;
    let forged = forged.encode();
    server
        .sql("DROP TRIGGER v2_idempotency_succeeded_is_fixed", &[])
        .await;
    server
        .sql(
            "UPDATE v2_idempotency SET exact_response_bytes = ?, exact_response_bytes_sha256 = ?
              WHERE operation_kind = 'ROOT_GENERATION_CREATE'",
            &[&forged, &sha256(&forged)],
        )
        .await;
    let (status, body) = server.root(&TENANT, &access, &req).await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (422, "MUTATION_RESPONSE_MISMATCH")
    );
}

#[tokio::test]
async fn a_bootstrap_needs_a_first_self_grant_and_a_consumed_guard() {
    let mut server = start("s6-state", 28199).await;
    let (dev, access) = approved(&mut server, 0x66).await;
    let request = |key: u8, edit: fn(&mut TenantRootKeyGrantV2)| {
        root_request(
            key,
            &bootstrap_create(&TRK, self_grant(&dev, &TRK, edit), |_| {}),
        )
    };

    // A grant of an existing root, signed by the subject, at generation 0.
    let (status, body) = server
        .root(
            &TENANT,
            &access,
            &request(0xd0, |g| g.variant = RootGrantVariant::ExistingRootGrant),
        )
        .await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (422, "AUTH_CLAIM_COLUMN_MISMATCH")
    );

    // A guard that moved to recovery after D1 ends the setup session.
    server
        .sql(
            "UPDATE v2_bootstrap_guards
                SET state = 'recovery_required', recovery_reason = 'integrity_failure'",
            &[],
        )
        .await;
    assert_eq!(
        server
            .root(&TENANT, &access, &request(0xd2, |_| {}))
            .await
            .0,
        401
    );
    for table in ["v2_root_key_generations", "v2_tenant_root_key_grants"] {
        assert_eq!(
            server.count(&format!("SELECT count(*) FROM {table}")).await,
            0,
            "{table}"
        );
    }
}

#[tokio::test]
async fn two_bootstraps_under_different_keys_commit_once_and_a_custodian_closes_it() {
    let mut server = start("s6-race-keys", 28200).await;
    let (dev, access) = approved(&mut server, 0x67).await;

    // An active `root.custody` capability is root history (rule 1). Only a
    // spike row can hold one: the exact table refuses it, and the spike table
    // is read-only behind its triggers.
    for trigger in ["no_insert", "no_update"] {
        server
            .sql(
                &format!("DROP TRIGGER v2_legacy_capability_grants_{trigger}"),
                &[],
            )
            .await;
    }
    server
        .sql(
            "INSERT INTO v2_legacy_capability_grants VALUES (?, randomblob(16), 'domain', 2, ?, ?, \
             'root.custody', 'tenant', ?, 1, 1, 2, ?, 0, x'aa', randomblob(32), \
             randomblob(64), randomblob(32), randomblob(32), x'bb', randomblob(32), NULL, 't')",
            &[&TENANT, &OWNER, &dev.id, &TENANT, &INSTANCE],
        )
        .await;
    let create = bootstrap_create(&TRK, self_grant(&dev, &TRK, |_| {}), |_| {});
    let (status, body) = server
        .root(&TENANT, &access, &root_request(0xe0, &create))
        .await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (409, "ROOT_BOOTSTRAP_ALREADY_EXISTS")
    );
    server
        .sql(
            "UPDATE v2_legacy_capability_grants SET revoked_at = 'now'",
            &[],
        )
        .await;

    let (first, second) = (root_request(0xe1, &create), root_request(0xe2, &create));
    let (a, b) = tokio::join!(
        server.root(&TENANT, &access, &first),
        server.root(&TENANT, &access, &second)
    );
    let mut statuses = [a.0, b.0];
    statuses.sort();
    assert_eq!(statuses, [201, 409]);
    let refused = if a.0 == 409 { &a.1 } else { &b.1 };
    assert_eq!(code_of(refused), "ROOT_BOOTSTRAP_ALREADY_EXISTS");
    for table in [
        "v2_root_key_generations",
        "v2_tenant_root_key_grants",
        "v2_idempotency WHERE operation_kind = 'ROOT_GENERATION_CREATE'",
    ] {
        assert_eq!(
            server.count(&format!("SELECT count(*) FROM {table}")).await,
            1,
            "{table}"
        );
    }

    // Behind the trigger's back, an unfinished row under a third key that
    // holds these exact request bytes: only a succeeded row replays.
    let third = root_request(0xe3, &create);
    let hash = IdempotentMutationRequestV2::parse(&third)
        .unwrap()
        .canonical_request_hash();
    server
        .sql(
            "DROP TRIGGER v2_idempotency_root_generation_create_is_complete",
            &[],
        )
        .await;
    server
        .sql(
            "INSERT INTO v2_idempotency
             SELECT server_instance_id, tenant_id, actor_device_id, operation_scope, ?,
                    operation_kind, ?, ?, ?, 'in_flight', response_record_type,
                    exact_response_bytes, exact_response_bytes_sha256, retained_until,
                    approval_payload_domain, restore_epoch, actor_account_id, subject_device_id
               FROM v2_idempotency WHERE operation_kind = 'ROOT_GENERATION_CREATE'",
            &[&[0xe3; 16], &hash, &third, &sha256(&third)],
        )
        .await;
    let (status, body) = server.root(&TENANT, &access, &third).await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (409, "IDEMPOTENCY_MISMATCH")
    );
}

// --------------------------------------------- S6 readback, ack, activate ---

const SELF_GRANT_REPLAY: [u8; 16] = [0x81; 16];

/// The exact ref naming `container`, a grant `dev` signed.
fn grant_ref(dev: &Device, container: &[u8]) -> RootGrantRef {
    let v = AuthorizationRecord::parse(container)
        .unwrap()
        .verify_signature(dev.sk.verifying_key().as_bytes())
        .unwrap();
    let Payload::TenantRootKeyGrant(g) = v.payload() else {
        panic!("a root grant")
    };
    RootGrantRef {
        tenant_id: g.common.tenant_id,
        server_instance_id: g.common.server_instance_id,
        restore_epoch: g.common.restore_epoch,
        root_generation: g.root_generation,
        root_key_id: g.root_key_id,
        replay_id: g.common.replay_id,
        signed_container_hash: *v.record().signed_container_hash(),
        exact_signed_container_bytes_sha256: *v.record().exact_signed_container_bytes_sha256(),
    }
}

/// The exact outer request of `kind` under idempotency key `key`.
fn lifecycle_request(kind: OperationKind, key: u8, payload: Vec<u8>) -> Vec<u8> {
    IdempotentMutationRequestV2 {
        operation_kind: kind,
        idempotency_key: [key; 16],
        canonical_payload_bytes: payload,
        client_request_nonce: [0x92; 16],
        server_instance_id: INSTANCE,
        restore_epoch: 0,
    }
    .encode()
}

fn grant_path(generation: &str, replay: &[u8; 16]) -> String {
    format!(
        "/v2/tenants/{}/root-key-generations/{generation}/grants/{}",
        hex(&TENANT),
        hex(replay)
    )
}

fn activate_path(generation: &str) -> String {
    format!(
        "/v2/tenants/{}/root-key-generations/{generation}/activate",
        hex(&TENANT)
    )
}

fn ack_request(key: u8, grant: RootGrantRef) -> Vec<u8> {
    lifecycle_request(
        OperationKind::RootGrantAck,
        key,
        TenantRootGrantAckV2 { grant }.encode(),
    )
}

fn activate_request(key: u8, target: RootGenerationTarget) -> Vec<u8> {
    lifecycle_request(
        OperationKind::RootGenerationActivate,
        key,
        TenantRootGenerationActivateV2 {
            target,
            previous: None,
        }
        .encode(),
    )
}

/// D1 and the S6 bootstrap; returns the device, its access token, the filed
/// self-grant and the create request's terms.
async fn bootstrapped(
    server: &mut Server,
    seed: u8,
) -> (Device, String, Vec<u8>, RootGenerationTarget) {
    let (dev, access, container, target, _) = bootstrapped_by(server, seed).await;
    (dev, access, container, target)
}

/// [`bootstrapped`], also returning the exact create request.
async fn bootstrapped_by(
    server: &mut Server,
    seed: u8,
) -> (Device, String, Vec<u8>, RootGenerationTarget, Vec<u8>) {
    let (dev, access) = approved(server, seed).await;
    let container = self_grant(&dev, &TRK, |_| {});
    let create = bootstrap_create(&TRK, container.clone(), |_| {});
    let request = root_request(0x91, &create);
    let (status, body) = server.root(&TENANT, &access, &request).await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    (dev, access, container, create.target, request)
}

async fn read_self_grant(
    server: &Server,
    dev: &Device,
    access: &str,
) -> TenantRootGrantDescriptorV2 {
    let (status, body) = server
        .call(&grant_path("0", &SELF_GRANT_REPLAY), access, None)
        .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    TenantRootGrantDescriptorV2::parse(&body, dev.sk.verifying_key().as_bytes()).unwrap()
}

#[tokio::test]
async fn the_first_device_reads_back_acknowledges_and_activates_generation_zero() {
    let mut server = start("s6-activate", 28201).await;
    let (dev, access, container, target) = bootstrapped(&mut server, 0x63).await;
    let read = || read_self_grant(&server, &dev, &access);

    // The readback is the exact container, and it opens to the TRK.
    let d = read().await;
    assert_eq!(
        (d.grant_state(), d.generation_state()),
        (RootGrantState::PendingAck, RootGenerationState::Preparing)
    );
    assert_eq!(
        d.record().record().exact_signed_container_bytes(),
        container
    );
    let Payload::TenantRootKeyGrant(g) = d.record().payload() else {
        panic!("a root grant")
    };
    assert_eq!(*g.open_trk(&dev.hpke_sk).unwrap(), TRK);

    // Nothing activates before the self-grant is acknowledged.
    let (status, body) = server
        .call(
            &activate_path("0"),
            &access,
            Some(&activate_request(0xb0, target.clone())),
        )
        .await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (409, "ROOT_GENERATION_MISMATCH")
    );

    // The acknowledgement, once; a lost response gets the same bytes back.
    let ack = ack_request(0xb1, grant_ref(&dev, &container));
    let ack_path = format!("{}/ack", grant_path("0", &SELF_GRANT_REPLAY));
    let (status, stored) = server.call(&ack_path, &access, Some(&ack)).await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&stored));
    let response = IdempotentStoredResponseV2::parse(&stored).unwrap();
    let acked = TenantRootGrantAckedV2::parse(&response.canonical_response_payload_bytes).unwrap();
    assert_eq!(acked.grant, grant_ref(&dev, &container));
    assert_eq!(
        server.call(&ack_path, &access, Some(&ack)).await,
        (201, stored)
    );
    let (status, body) = server
        .call(
            &ack_path,
            &access,
            Some(&ack_request(0xb2, grant_ref(&dev, &container))),
        )
        .await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (409, "ROOT_GENERATION_MISMATCH")
    );
    assert_eq!(read().await.grant_state(), RootGrantState::Acknowledged);

    // Activation flips the generation and the tenant's pointer, once.
    let activate = activate_request(0xb3, target.clone());
    let (status, stored) = server
        .call(&activate_path("0"), &access, Some(&activate))
        .await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&stored));
    let response = IdempotentStoredResponseV2::parse(&stored).unwrap();
    let activated =
        TenantRootGenerationActivatedV2::parse(&response.canonical_response_payload_bytes).unwrap();
    assert_eq!(
        (activated.target, activated.previous),
        (target.clone(), None)
    );
    assert_eq!(
        server
            .call(&activate_path("0"), &access, Some(&activate))
            .await,
        (201, stored.clone())
    );
    let (status, body) = server
        .call(
            &activate_path("0"),
            &access,
            Some(&activate_request(0xb4, target)),
        )
        .await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (409, "ROOT_GENERATION_MISMATCH")
    );
    assert_eq!(read().await.generation_state(), RootGenerationState::Active);
    for (query, want) in [
        (
            "SELECT count(*) FROM v2_root_key_generations
              WHERE generation = 0 AND state = 'ACTIVE' AND activated_at IS NOT NULL",
            1,
        ),
        (
            "SELECT count(*) FROM v2_tenants WHERE active_root_generation = 0",
            1,
        ),
        (
            "SELECT count(*) FROM v2_tenant_root_key_grants WHERE acked_at IS NOT NULL",
            1,
        ),
        (
            "SELECT count(*) FROM v2_audit_events WHERE action = 'root.grant_ack'",
            1,
        ),
        (
            "SELECT count(*) FROM v2_audit_events WHERE action = 'root.activate'",
            1,
        ),
    ] {
        assert_eq!(server.count(query).await, want, "{query}");
    }

    // An ACTIVE generation never goes back, nor rewrites when it became so,
    // and each mutation commits with its response.
    let pool = db(&server.data).await;
    let mut statements = vec![
        (
            "UPDATE v2_root_key_generations SET state = 'PREPARING'".to_string(),
            "only moves forward",
        ),
        (
            "UPDATE v2_root_key_generations SET activated_at = 'later'".to_string(),
            "only moves forward",
        ),
        (
            "UPDATE v2_root_key_generations SET retired_at = 'now'".to_string(),
            "only moves forward",
        ),
    ];
    for kind in ["ROOT_GRANT_ACK", "ROOT_GENERATION_ACTIVATE"] {
        statements.push((
            format!(
                "INSERT INTO v2_idempotency
                 SELECT server_instance_id, tenant_id, actor_device_id, operation_scope,
                        x'{}', operation_kind, canonical_request_hash, exact_request_bytes,
                        exact_request_bytes_sha256, 'in_flight', NULL, NULL, NULL,
                        retained_until, approval_payload_domain, restore_epoch,
                        actor_account_id, subject_device_id
                   FROM v2_idempotency WHERE operation_kind = '{kind}'",
                "ee".repeat(16)
            ),
            "stored with its response",
        ));
    }
    for (statement, why) in statements {
        let err = sqlx::query(&statement).execute(&pool).await.unwrap_err();
        assert!(err.to_string().contains(why), "{statement}: {err}");
    }
    pool.close().await;

    // A stored activation stands after the generation moved on, but not once
    // its row no longer says it was ever activated.
    server
        .sql(
            "UPDATE v2_root_key_generations SET state = 'RETIRED', retired_at = 'now'",
            &[],
        )
        .await;
    assert_eq!(
        server
            .call(&activate_path("0"), &access, Some(&activate))
            .await,
        (201, stored)
    );
    server
        .sql(
            "DROP TRIGGER v2_root_key_generations_state_moves_forward",
            &[],
        )
        .await;
    server
        .sql(
            "UPDATE v2_root_key_generations SET activated_at = NULL",
            &[],
        )
        .await;
    let (status, body) = server
        .call(&activate_path("0"), &access, Some(&activate))
        .await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (422, "MUTATION_RESPONSE_MISMATCH")
    );
}

#[tokio::test]
async fn readback_ack_and_activate_refuse_anything_but_the_exact_stored_grant() {
    let mut server = start("s6-lifecycle-refusals", 28202).await;
    let (dev, access, container, target) = bootstrapped(&mut server, 0x64).await;
    let honest = grant_ref(&dev, &container);
    let ack_path = format!("{}/ack", grant_path("0", &SELF_GRANT_REPLAY));
    let refused = |status: u16, body: &[u8]| (status, code_of(body));

    // One spelling per path; no such grant; another tenant's path.
    for path in [
        grant_path("00", &SELF_GRANT_REPLAY),
        grant_path("+0", &SELF_GRANT_REPLAY),
    ] {
        assert_eq!(server.call(&path, &access, None).await.0, 400, "{path}");
    }
    let (status, body) = server
        .call(&grant_path("0", &[0x99; 16]), &access, None)
        .await;
    assert_eq!(refused(status, &body), (404, "RESOURCE_NOT_FOUND".into()));
    let elsewhere = format!(
        "/v2/tenants/{}/root-key-generations/0/grants/{}",
        hex(&[0x42; 16]),
        hex(&SELF_GRANT_REPLAY)
    );
    let (status, body) = server.call(&elsewhere, &access, None).await;
    assert_eq!(refused(status, &body), (404, "RESOURCE_NOT_FOUND".into()));

    // Only the self-grant's subject, on its setup session, reads or acts on it.
    let other = device(&server, OWNER, 0x65, "pending").await;
    let stranger = session(&server, &other).await["access_token"]
        .as_str()
        .unwrap()
        .to_string();
    // To a stranger the grant does not exist; it may not act on it either.
    for (path, body, want) in [
        (grant_path("0", &SELF_GRANT_REPLAY), None, 404),
        (
            ack_path.clone(),
            Some(ack_request(0xbf, honest.clone())),
            403,
        ),
        (
            activate_path("0"),
            Some(activate_request(0xbe, target.clone())),
            403,
        ),
    ] {
        assert_eq!(
            server.call(&path, &stranger, body.as_deref()).await.0,
            want,
            "{path}"
        );
    }

    // An acknowledgement names exactly the grant on its path.
    for (name, edit, want) in [
        (
            "another replay",
            (|r: &mut RootGrantRef| r.replay_id = [0x99; 16]) as fn(&mut RootGrantRef),
            (422, "AUTH_CLAIM_COLUMN_MISMATCH"),
        ),
        (
            "another container",
            |r: &mut RootGrantRef| r.signed_container_hash = [0x99; 32],
            (422, "AUTH_CLAIM_COLUMN_MISMATCH"),
        ),
        (
            "another root key",
            |r: &mut RootGrantRef| r.root_key_id = [0x99; 32],
            (422, "AUTH_CLAIM_COLUMN_MISMATCH"),
        ),
        (
            // A ref carries its grant's issuance epoch, not the server's (Q-1).
            "another epoch",
            |r: &mut RootGrantRef| r.restore_epoch = 1,
            (422, "AUTH_CLAIM_COLUMN_MISMATCH"),
        ),
    ] {
        let mut r = honest.clone();
        edit(&mut r);
        let (status, body) = server
            .call(&ack_path, &access, Some(&ack_request(0xc0, r)))
            .await;
        assert_eq!(
            (status, code_of(&body).as_str()),
            want,
            "{name} {}",
            String::from_utf8_lossy(&body)
        );
    }
    let mut r = honest.clone();
    r.server_instance_id = [0x99; 16];
    assert_eq!(
        server
            .call(&ack_path, &access, Some(&ack_request(0xc1, r)))
            .await
            .0,
        403
    );
    // The body must be the operation its path names.
    let (status, body) = server
        .call(
            &ack_path,
            &access,
            Some(&activate_request(0xc2, target.clone())),
        )
        .await;
    assert_eq!(
        refused(status, &body),
        (422, "AUTH_CLAIM_COLUMN_MISMATCH".into())
    );

    // An activation restates the generation's terms, and only generation 0
    // activates for now.
    let mut other = target.clone();
    other.recovery_bundle_sha256 = [0x99; 32];
    let (status, body) = server
        .call(
            &activate_path("0"),
            &access,
            Some(&activate_request(0xc3, other)),
        )
        .await;
    assert_eq!(
        refused(status, &body),
        (422, "AUTH_CLAIM_COLUMN_MISMATCH".into())
    );
    let mut later = target.clone();
    later.root_generation = 1;
    later.root_key_id = [0x98; 32];
    let rotation = lifecycle_request(
        OperationKind::RootGenerationActivate,
        0xc4,
        TenantRootGenerationActivateV2 {
            target: later,
            previous: Some(PreviousRoot {
                root_key_id: target.root_key_id,
                root_generation: 0,
            }),
        }
        .encode(),
    );
    assert_eq!(
        server
            .call(&activate_path("1"), &access, Some(&rotation))
            .await
            .0,
        403
    );

    // A revoked grant is neither acknowledged nor counted.
    let (status, _) = server
        .call(&ack_path, &access, Some(&ack_request(0xc5, honest.clone())))
        .await;
    assert_eq!(status, 201);
    server
        .sql(
            "UPDATE v2_tenant_root_key_grants SET revoked_at = 'now'",
            &[],
        )
        .await;
    let (status, body) = server
        .call(
            &activate_path("0"),
            &access,
            Some(&activate_request(0xc6, target.clone())),
        )
        .await;
    assert_eq!(
        refused(status, &body),
        (409, "ROOT_GENERATION_MISMATCH".into())
    );
    assert_eq!(
        TenantRootGrantDescriptorV2::parse(
            &server
                .call(&grant_path("0", &SELF_GRANT_REPLAY), &access, None)
                .await
                .1,
            dev.sk.verifying_key().as_bytes()
        )
        .unwrap()
        .grant_state(),
        RootGrantState::Revoked
    );
    server
        .sql(
            "DROP TRIGGER v2_tenant_root_key_grants_marks_are_final",
            &[],
        )
        .await;
    server
        .sql("UPDATE v2_tenant_root_key_grants SET acked_at = NULL", &[])
        .await;
    let (status, body) = server
        .call(&ack_path, &access, Some(&ack_request(0xc5, honest.clone())))
        .await;
    assert_eq!(
        refused(status, &body),
        (422, "MUTATION_RESPONSE_MISMATCH".into())
    );
    let (status, body) = server
        .call(&ack_path, &access, Some(&ack_request(0xc8, honest.clone())))
        .await;
    assert_eq!(
        refused(status, &body),
        (409, "ROOT_GENERATION_MISMATCH".into())
    );

    // A row that no longer matches its signed container is never served, and
    // the grant is quarantined for good, even once the row is put back.
    server
        .sql(
            "DROP TRIGGER v2_tenant_root_key_grants_record_is_fixed",
            &[],
        )
        .await;
    let info: Vec<u8> = sqlx::query_scalar("SELECT hpke_info_bytes FROM v2_tenant_root_key_grants")
        .fetch_one(&db(&server.data).await)
        .await
        .unwrap();
    server
        .sql(
            "UPDATE v2_tenant_root_key_grants SET hpke_info_bytes = x'00'",
            &[],
        )
        .await;
    let (status, body) = server
        .call(&grant_path("0", &SELF_GRANT_REPLAY), &access, None)
        .await;
    assert_eq!(
        refused(status, &body),
        (422, "AUTH_CLAIM_COLUMN_MISMATCH".into())
    );
    assert_eq!(
        server
            .count(
                "SELECT count(*) FROM v2_grant_quarantine
                  WHERE kind = 'root_grant' AND reason = 'container_mismatch'"
            )
            .await,
        1
    );
    server
        .sql(
            "UPDATE v2_tenant_root_key_grants SET hpke_info_bytes = ?",
            &[&info],
        )
        .await;
    let (status, body) = server
        .call(&grant_path("0", &SELF_GRANT_REPLAY), &access, None)
        .await;
    assert_eq!(
        refused(status, &body),
        (422, "AUTH_CLAIM_COLUMN_MISMATCH".into())
    );
    // A stranger is not told that the row is broken, or that it exists.
    assert_eq!(
        server
            .call(&grant_path("0", &SELF_GRANT_REPLAY), &stranger, None)
            .await
            .0,
        404
    );
    let (status, body) = server
        .call(&ack_path, &access, Some(&ack_request(0xc7, honest)))
        .await;
    assert_eq!(
        refused(status, &body),
        (422, "AUTH_CLAIM_COLUMN_MISMATCH".into())
    );

    // The PREPARING generation carries exactly the times of the states it
    // reached: none yet, and each state needs its own.
    let pool = db(&server.data).await;
    for statement in [
        "UPDATE v2_root_key_generations SET state = 'ACTIVE'",
        "UPDATE v2_root_key_generations SET activated_at = 'now'",
        "UPDATE v2_root_key_generations SET state = 'RETIRED'",
    ] {
        let err = sqlx::query(statement).execute(&pool).await.unwrap_err();
        assert!(
            err.to_string().contains("only moves forward"),
            "{statement}: {err}"
        );
    }
    pool.close().await;
}

#[tokio::test]
async fn an_expired_self_grant_is_neither_counted_nor_acknowledged() {
    let mut server = start("s6-expired", 28203).await;
    let (dev, access) = approved(&mut server, 0x66).await;
    let until = now_ms() + 15_000;
    let container = self_grant(&dev, &TRK, |g| g.common.not_after_ms = until);
    let create = bootstrap_create(&TRK, container.clone(), |_| {});
    let (status, body) = server
        .root(&TENANT, &access, &root_request(0x91, &create))
        .await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    let ack_path = format!("{}/ack", grant_path("0", &SELF_GRANT_REPLAY));
    let ack = |key| ack_request(key, grant_ref(&dev, &container));
    assert_eq!(
        server.call(&ack_path, &access, Some(&ack(0xd0))).await.0,
        201
    );
    tokio::time::sleep(Duration::from_millis(until.saturating_sub(now_ms()) + 200)).await;
    // Past its window the acknowledged self-grant holds no custody ...
    let (status, body) = server
        .call(
            &activate_path("0"),
            &access,
            Some(&activate_request(0xd1, create.target.clone())),
        )
        .await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (409, "ROOT_GENERATION_MISMATCH")
    );
    // ... and, had it not been acknowledged, could not be.
    server
        .sql(
            "DROP TRIGGER v2_tenant_root_key_grants_marks_are_final",
            &[],
        )
        .await;
    server
        .sql("UPDATE v2_tenant_root_key_grants SET acked_at = NULL", &[])
        .await;
    assert_eq!(
        server.call(&ack_path, &access, Some(&ack(0xd2))).await.0,
        403
    );
}

#[tokio::test]
async fn a_row_holding_another_rows_container_is_not_that_grant() {
    let mut server = start("s6-borrowed", 28204).await;
    let (_dev, access, _container, target) = bootstrapped(&mut server, 0x67).await;
    // Behind the triggers' back, a second row under another replay ID that
    // holds the self-grant's exact container and claims an acknowledgement.
    let pool = db(&server.data).await;
    let columns: Vec<String> =
        sqlx::query_scalar("SELECT name FROM pragma_table_info('v2_tenant_root_key_grants')")
            .fetch_all(&pool)
            .await
            .unwrap();
    let values: Vec<String> = columns
        .iter()
        .map(|c| match c.as_str() {
            "replay_id" => format!("x'{}'", "99".repeat(16)),
            "grant_variant" => "'ExistingRootGrant'".into(),
            "acked_at" => "'now'".into(),
            _ => c.clone(),
        })
        .collect();
    sqlx::query(&format!(
        "INSERT INTO v2_tenant_root_key_grants ({}) SELECT {} FROM v2_tenant_root_key_grants",
        columns.join(", "),
        values.join(", ")
    ))
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;

    // It is not read back as the grant it copied, nor counted for activation.
    let (status, body) = server
        .call(&grant_path("0", &[0x99; 16]), &access, None)
        .await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (422, "AUTH_CLAIM_COLUMN_MISMATCH")
    );
    let (status, body) = server
        .call(
            &activate_path("0"),
            &access,
            Some(&activate_request(0xd3, target)),
        )
        .await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (422, "AUTH_CLAIM_COLUMN_MISMATCH")
    );
}

// --------------------------------------------- D2 capability grant filing ---

/// D1, the S6 bootstrap, the ack and the activation: `dev` is the ACTIVE
/// root custodian.
/// Returns the device, its access token and the exact bootstrap request.
async fn custodian(server: &mut Server, seed: u8) -> (Device, String, Vec<u8>) {
    let (dev, access, container, target, request) = bootstrapped_by(server, seed).await;
    let ack_path = format!("{}/ack", grant_path("0", &SELF_GRANT_REPLAY));
    let ack = ack_request(0xb1, grant_ref(&dev, &container));
    assert_eq!(server.call(&ack_path, &access, Some(&ack)).await.0, 201);
    let activate = activate_request(0xb3, target.clone());
    assert_eq!(
        server
            .call(&activate_path("0"), &access, Some(&activate))
            .await
            .0,
        201
    );
    (dev, access, request)
}

/// `capability` for `dev` itself, tenant-wide, signed by `signer`.
fn capability_grant(
    dev: &Device,
    signer: &Ed25519SigningKey,
    edit: impl FnOnce(&mut TenantCapabilityGrantV2),
) -> Vec<u8> {
    let start = now_ms() - 60_000;
    let mut g = TenantCapabilityGrantV2 {
        common: CommonFields {
            replay_id: [0xa1; 16],
            tenant_id: TENANT,
            issued_at_ms: start,
            not_before_ms: start,
            not_after_ms: start + 30 * DAY_MS,
            server_instance_id: INSTANCE,
            restore_epoch: 0,
        },
        subject: GrantSubject::Device {
            account_id: OWNER,
            device_id: dev.id,
            signing_key_id: dev.signing_key_id,
            hpke_key_id: dev.hpke_key_id,
        },
        scope_kind: CapabilityScopeKind::Tenant,
        scope_id: TENANT,
        capability: Capability::DeviceApprove,
    };
    edit(&mut g);
    build_record(signer, DOMAIN_TENANT_CAPABILITY_GRANT, &g.encode())
}

const GRANTS: &str = "/v2/capability-grants";

#[tokio::test]
async fn the_active_custodian_files_capability_grants_once() {
    let mut server = start("d2-file", 28205).await;
    let (dev, access, container, target) = bootstrapped(&mut server, 0x68).await;
    let own = capability_grant(&dev, &dev.sk, |_| {});

    // Before activation the device is no custodian (ADR 0001 D2).
    assert_eq!(server.call(GRANTS, &access, Some(&own)).await.0, 403);
    let ack_path = format!("{}/ack", grant_path("0", &SELF_GRANT_REPLAY));
    let ack = ack_request(0xb1, grant_ref(&dev, &container));
    assert_eq!(server.call(&ack_path, &access, Some(&ack)).await.0, 201);
    assert_eq!(server.call(GRANTS, &access, Some(&own)).await.0, 403);
    let activate = activate_request(0xb3, target);
    assert_eq!(
        server
            .call(&activate_path("0"), &access, Some(&activate))
            .await
            .0,
        201
    );

    // Now it signs its own operating capability, filed whole, once.
    let (status, body) = server.call(GRANTS, &access, Some(&own)).await;
    assert_eq!(
        (status, &body),
        (201, &own),
        "{}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(
        server.call(GRANTS, &access, Some(&own)).await,
        (201, own.clone())
    );
    for (query, want) in [
        (
            "SELECT count(*) FROM v2_capability_grants
              WHERE subject_kind = 'device' AND capability = 'device.approve'
                AND scope_kind = 'tenant' AND revoked_at IS NULL",
            1,
        ),
        (
            "SELECT count(*) FROM v2_audit_events WHERE action = 'capability.grant'",
            1,
        ),
    ] {
        assert_eq!(server.count(query).await, want, "{query}");
    }
    let exact: i64 = server
        .count(&format!(
            "SELECT count(*) FROM v2_capability_grants WHERE exact_signed_container_bytes = x'{}'",
            hex(&own)
        ))
        .await;
    assert_eq!(exact, 1);

    // Other bytes under the same replay ID are another request.
    let other = capability_grant(&dev, &dev.sk, |g| g.capability = Capability::DeviceRevoke);
    let (status, body) = server.call(GRANTS, &access, Some(&other)).await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (409, "IDEMPOTENCY_MISMATCH")
    );

    // An account-scoped grant carries no device columns.
    let account = capability_grant(&dev, &dev.sk, |g| {
        g.common.replay_id = [0xa2; 16];
        g.subject = GrantSubject::Account { account_id: OWNER };
        g.capability = Capability::TenantManage;
    });
    assert_eq!(server.call(GRANTS, &access, Some(&account)).await.0, 201);
    assert_eq!(
        server
            .count(
                "SELECT count(*) FROM v2_capability_grants WHERE subject_kind = 'account'
                   AND subject_device_id IS NULL AND subject_signing_key_id IS NULL
                   AND subject_hpke_key_id IS NULL"
            )
            .await,
        1
    );

    // A fleet scope must name a fleet of the tenant.
    let fleet = capability_grant(&dev, &dev.sk, |g| {
        g.common.replay_id = [0xa3; 16];
        g.scope_kind = CapabilityScopeKind::Fleet;
        g.scope_id = [0xf1; 16];
        g.capability = Capability::FleetManage;
    });
    let (status, body) = server.call(GRANTS, &access, Some(&fleet)).await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (404, "RESOURCE_NOT_FOUND")
    );
    server
        .sql(
            "INSERT INTO v2_fleets (id, tenant_id, name, status, created_at)
             VALUES (?, ?, 'f', 'active', 'now')",
            &[&[0xf1; 16], &TENANT],
        )
        .await;
    assert_eq!(server.call(GRANTS, &access, Some(&fleet)).await.0, 201);

    // D-6: exactly 365 days is the longest life.
    let longest = capability_grant(&dev, &dev.sk, |g| {
        g.common.replay_id = [0xa4; 16];
        g.common.not_after_ms = g.common.not_before_ms + 365 * DAY_MS;
    });
    assert_eq!(server.call(GRANTS, &access, Some(&longest)).await.0, 201);

    // A filed grant never changes, and a row that drifted from its container
    // does not answer a retry.
    let pool = db(&server.data).await;
    for statement in [
        "UPDATE v2_capability_grants SET capability = 'device.revoke'",
        "DELETE FROM v2_capability_grants",
    ] {
        assert!(
            sqlx::query(statement).execute(&pool).await.is_err(),
            "{statement}"
        );
    }
    pool.close().await;
    server
        .sql("DROP TRIGGER v2_capability_grants_record_is_fixed", &[])
        .await;
    // The same bytes again find the drift and quarantine the grant for good.
    for (shift, quarantined) in [("- 1", 1), ("+ 1", 1)] {
        server
            .sql(
                &format!(
                    "UPDATE v2_capability_grants SET not_after_ms = not_after_ms {shift}
                      WHERE replay_id = ?"
                ),
                &[&[0xa1; 16]],
            )
            .await;
        let (status, body) = server.call(GRANTS, &access, Some(&own)).await;
        assert_eq!(
            (status, code_of(&body).as_str()),
            (422, "AUTH_CLAIM_COLUMN_MISMATCH")
        );
        assert_eq!(
            server
                .count("SELECT count(*) FROM v2_grant_quarantine WHERE kind = 'capability_grant'")
                .await,
            quarantined
        );
    }
    // Once quarantined, the replay ID answers nothing else either.
    let (status, body) = server.call(GRANTS, &access, Some(&other)).await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (422, "AUTH_CLAIM_COLUMN_MISMATCH")
    );
}

#[tokio::test]
async fn only_a_live_custodian_files_an_issuable_grant_for_a_live_subject() {
    let mut server = start("d2-refusals", 28206).await;
    let (dev, access, _) = custodian(&mut server, 0x69).await;
    let stranger = Ed25519SigningKey::from_bytes(&[0x5e; 32]);

    type Edit = fn(&mut TenantCapabilityGrantV2);
    let cases: [(&str, Edit, u16, &str); 9] = [
        (
            "root.custody",
            |g| g.capability = Capability::RootCustody,
            403,
            "",
        ),
        (
            "not yet valid",
            |g| {
                g.common.issued_at_ms = now_ms() + 600_000;
                g.common.not_before_ms = now_ms() + 600_000;
                g.common.not_after_ms = now_ms() + DAY_MS;
            },
            403,
            "",
        ),
        (
            "over 365 days",
            |g| g.common.not_after_ms = g.common.not_before_ms + 366 * DAY_MS,
            403,
            "",
        ),
        (
            "another epoch",
            |g| g.common.restore_epoch = 1,
            409,
            "STALE_CONTEXT",
        ),
        (
            "another instance",
            |g| g.common.server_instance_id = [0x99; 16],
            403,
            "",
        ),
        (
            "another tenant",
            |g| {
                g.common.tenant_id = [0x42; 16];
                g.scope_id = [0x42; 16];
            },
            403,
            "",
        ),
        (
            "subject under other keys",
            |g| {
                if let GrantSubject::Device { hpke_key_id, .. } = &mut g.subject {
                    *hpke_key_id = [0x99; 32];
                }
            },
            422,
            "AUTH_CLAIM_COLUMN_MISMATCH",
        ),
        (
            "unknown subject account",
            |g| {
                g.subject = GrantSubject::Account {
                    account_id: [0x99; 16],
                }
            },
            422,
            "AUTH_CLAIM_COLUMN_MISMATCH",
        ),
        (
            "unknown profile",
            |g| {
                g.scope_kind = CapabilityScopeKind::Profile;
                g.scope_id = [0x99; 16];
                g.capability = Capability::ProfileCommit;
            },
            404,
            "RESOURCE_NOT_FOUND",
        ),
    ];
    for (i, (name, edit, status, code)) in cases.into_iter().enumerate() {
        let rec = capability_grant(&dev, &dev.sk, |g| {
            g.common.replay_id = [0xc0 + i as u8; 16];
            edit(g);
        });
        let (got, body) = server.call(GRANTS, &access, Some(&rec)).await;
        assert_eq!(got, status, "{name}: {}", String::from_utf8_lossy(&body));
        if !code.is_empty() {
            assert_eq!(code_of(&body), code, "{name}");
        }
    }

    // The codec refuses values that never appear in a capability grant.
    let receive = capability_grant(&dev, &dev.sk, |g| {
        g.common.replay_id = [0xd0; 16];
        g.capability = Capability::FleetKeyReceive;
    });
    let (status, body) = server.call(GRANTS, &access, Some(&receive)).await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (422, "NON_CANONICAL_RECORD")
    );
    // Another record kind is not a capability grant.
    let approval = approval(&dev, &dev.sk, 0xd1, 0, 30);
    assert_eq!(server.call(GRANTS, &access, Some(&approval)).await.0, 422);
    // The issuer is the presenting device and no other key.
    let foreign = capability_grant(&dev, &stranger, |g| g.common.replay_id = [0xd2; 16]);
    assert_eq!(server.call(GRANTS, &access, Some(&foreign)).await.0, 403);

    // An account that is no longer active is no subject.
    server
        .sql(
            "UPDATE v2_accounts SET status = 'disabled' WHERE id = ?",
            &[&OTHER],
        )
        .await;
    let disabled = capability_grant(&dev, &dev.sk, |g| {
        g.common.replay_id = [0xd7; 16];
        g.subject = GrantSubject::Account { account_id: OTHER };
        g.capability = Capability::TenantManage;
    });
    let (status, body) = server.call(GRANTS, &access, Some(&disabled)).await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (422, "AUTH_CLAIM_COLUMN_MISMATCH")
    );

    // The spike table is read-only, and a replay ID one of its rows holds is
    // spent.
    let spike_row = format!(
        "INSERT INTO v2_legacy_capability_grants VALUES (?, ?, '{DOMAIN_TENANT_CAPABILITY_GRANT}', \
         2, ?, ?, 'device.approve', 'tenant', ?, 1, 1, 2, ?, 0, x'aa', randomblob(32), \
         randomblob(64), randomblob(32), randomblob(32), x'bb', randomblob(32), NULL, 't')"
    );
    let binds: [&[u8]; 6] = [&TENANT, &[0xd6; 16], &OWNER, &dev.id, &TENANT, &INSTANCE];
    let pool = db(&server.data).await;
    let refused = binds
        .iter()
        .fold(sqlx::query(&spike_row), |q, b| q.bind(*b))
        .execute(&pool)
        .await;
    assert!(refused.is_err(), "the spike table took a row");
    pool.close().await;
    for trigger in ["no_insert", "no_update"] {
        server
            .sql(
                &format!("DROP TRIGGER v2_legacy_capability_grants_{trigger}"),
                &[],
            )
            .await;
    }
    server.sql(&spike_row, &binds).await;
    let spike = capability_grant(&dev, &dev.sk, |g| g.common.replay_id = [0xd6; 16]);
    let (status, body) = server.call(GRANTS, &access, Some(&spike)).await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (409, "IDEMPOTENCY_MISMATCH")
    );

    // A device on a pending session is no custodian, even for itself.
    let other = device(&server, OWNER, 0x6a, "pending").await;
    let pending = session(&server, &other).await["access_token"]
        .as_str()
        .unwrap()
        .to_string();
    let self_issued = capability_grant(&other, &other.sk, |g| g.common.replay_id = [0xd3; 16]);
    assert_eq!(
        server.call(GRANTS, &pending, Some(&self_issued)).await.0,
        403
    );

    // Custody ends with a revoked custody grant or a retired generation.
    let honest =
        |replay: u8| capability_grant(&dev, &dev.sk, |g| g.common.replay_id = [replay; 16]);
    assert_eq!(
        server.call(GRANTS, &access, Some(&honest(0xd4))).await.0,
        201
    );
    server
        .sql(
            "UPDATE v2_root_key_generations SET state = 'RETIRED', retired_at = 'now'",
            &[],
        )
        .await;
    assert_eq!(
        server.call(GRANTS, &access, Some(&honest(0xd5))).await.0,
        403
    );
    assert_eq!(
        server
            .count("SELECT count(*) FROM v2_capability_grants")
            .await,
        1
    );
}

#[tokio::test]
async fn only_an_acknowledged_unrevoked_custody_grant_issues() {
    let mut server = start("d2-revoked", 28207).await;
    let (dev, access, _) = custodian(&mut server, 0x6b).await;
    let grant = |replay: u8| capability_grant(&dev, &dev.sk, |g| g.common.replay_id = [replay; 16]);

    // An acknowledgement lost behind the trigger's back ends custody, and
    // restoring it brings custody back.
    server
        .sql(
            "DROP TRIGGER v2_tenant_root_key_grants_marks_are_final",
            &[],
        )
        .await;
    let acked: String = sqlx::query_scalar("SELECT acked_at FROM v2_tenant_root_key_grants")
        .fetch_one(&db(&server.data).await)
        .await
        .unwrap();
    server
        .sql("UPDATE v2_tenant_root_key_grants SET acked_at = NULL", &[])
        .await;
    assert_eq!(
        server.call(GRANTS, &access, Some(&grant(0xe1))).await.0,
        403
    );
    server
        .sql(
            &format!("UPDATE v2_tenant_root_key_grants SET acked_at = '{acked}'"),
            &[],
        )
        .await;
    let filed = grant(0xe2);
    assert_eq!(server.call(GRANTS, &access, Some(&filed)).await.0, 201);

    server
        .sql(
            "UPDATE v2_tenant_root_key_grants SET revoked_at = 'now'",
            &[],
        )
        .await;
    assert_eq!(
        server.call(GRANTS, &access, Some(&grant(0xe3))).await.0,
        403
    );
    // A lost response still gets its stored answer, but a device that is no
    // custodian is not told that a replay ID is spent.
    assert_eq!(
        server.call(GRANTS, &access, Some(&filed)).await,
        (201, filed.clone())
    );
    let other = capability_grant(&dev, &dev.sk, |g| {
        g.common.replay_id = [0xe2; 16];
        g.capability = Capability::DeviceRevoke;
    });
    assert_eq!(server.call(GRANTS, &access, Some(&other)).await.0, 403);
}

#[tokio::test]
async fn the_startup_pass_quarantines_grants_that_left_their_containers() {
    let mut server = start("quarantine-pass", 28208).await;
    let (dev, access, bootstrap) = custodian(&mut server, 0x6c).await;
    // The v1 collection route lists the grant, and the bootstrap replays.
    server
        .sql(
            "UPDATE v2_accounts SET legacy_user_id = (SELECT id FROM users WHERE username = 'admin')
              WHERE id = ?",
            &[&OWNER],
        )
        .await;
    let (_, login) = server
        .post(
            "/auth/login",
            None,
            json!({ "username": "admin", "password": "secret" }),
        )
        .await;
    let v1 = login["token"].as_str().unwrap().to_string();
    let collect = format!(
        "/v2/tenants/{}/devices/{}/root-key-grants",
        hex(&TENANT),
        hex(&dev.id)
    );
    let listed = |body: Vec<u8>| {
        serde_json::from_slice::<Value>(&body).unwrap()["grants"]
            .as_array()
            .unwrap()
            .len()
    };
    let (status, body) = server.call(&collect, &v1, None).await;
    assert_eq!((status, listed(body)), (200, 1));
    assert_eq!(server.root(&TENANT, &access, &bootstrap).await.0, 201);
    let filed = capability_grant(&dev, &dev.sk, |g| g.common.replay_id = [0xf2; 16]);
    assert_eq!(server.call(GRANTS, &access, Some(&filed)).await.0, 201);
    let intact = capability_grant(&dev, &dev.sk, |g| g.common.replay_id = [0xf3; 16]);
    assert_eq!(server.call(GRANTS, &access, Some(&intact)).await.0, 201);

    // Both rows drift while the server is down; no request ever sees them.
    for (trigger, statement) in [
        (
            "v2_tenant_root_key_grants_record_is_fixed",
            "UPDATE v2_tenant_root_key_grants SET hpke_info_bytes = x'00'",
        ),
        (
            "v2_capability_grants_record_is_fixed",
            "UPDATE v2_capability_grants SET capability = 'device.revoke' WHERE replay_id = x'f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2'",
        ),
    ] {
        server.sql(&format!("DROP TRIGGER {trigger}"), &[]).await;
        server.sql(statement, &[]).await;
    }
    // A row under another replay ID holding the intact grant's exact
    // container is not that grant.
    for statement in [
        "CREATE TABLE borrowed AS SELECT * FROM v2_capability_grants
          WHERE replay_id = x'f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3'",
        "UPDATE borrowed SET replay_id = x'f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5'",
        "INSERT INTO v2_capability_grants SELECT * FROM borrowed",
    ] {
        server.sql(statement, &[]).await;
    }
    server.restart().await;
    for (kind, want) in [("root_grant", 1), ("capability_grant", 2)] {
        assert_eq!(
            server
                .count(&format!(
                    "SELECT count(*) FROM v2_grant_quarantine WHERE kind = '{kind}'"
                ))
                .await,
            want,
            "{kind}"
        );
    }
    let (status, body) = server
        .call(&grant_path("0", &SELF_GRANT_REPLAY), &access, None)
        .await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (422, "AUTH_CLAIM_COLUMN_MISMATCH")
    );
    // The intact grant still answers its retry; the custodian's quarantined
    // root grant ends its custody.
    assert_eq!(
        server.call(GRANTS, &access, Some(&intact)).await,
        (201, intact.clone())
    );
    let (status, body) = server.call(GRANTS, &access, Some(&filed)).await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (422, "AUTH_CLAIM_COLUMN_MISMATCH")
    );
    let next = capability_grant(&dev, &dev.sk, |g| g.common.replay_id = [0xf4; 16]);
    assert_eq!(server.call(GRANTS, &access, Some(&next)).await.0, 422);
    // Neither is the quarantined self-grant collected, nor does its bootstrap
    // replay.
    let (status, body) = server.call(&collect, &v1, None).await;
    assert_eq!((status, listed(body)), (200, 0));
    let (status, body) = server.root(&TENANT, &access, &bootstrap).await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (422, "AUTH_CLAIM_COLUMN_MISMATCH")
    );

    // A second pass finds nothing new, and the record never changes.
    server.restart().await;
    assert_eq!(
        server
            .count("SELECT count(*) FROM v2_grant_quarantine")
            .await,
        3
    );
    let pool = db(&server.data).await;
    for statement in [
        "DELETE FROM v2_grant_quarantine",
        "UPDATE v2_grant_quarantine SET reason = 'container_mismatch'",
        "INSERT OR REPLACE INTO v2_grant_quarantine SELECT * FROM v2_grant_quarantine",
    ] {
        assert!(
            sqlx::query(statement).execute(&pool).await.is_err(),
            "{statement}"
        );
    }
    pool.close().await;
}

// ------------------------------------------------------- W3 trust evidence ---

/// Every page of the tenant's trust evidence, following the cursors.
async fn evidence(
    server: &Server,
    bearer: &str,
    signers: &[[u8; 32]],
) -> Vec<TenantTrustEvidencePageV2> {
    let mut pages = Vec::new();
    let mut cursor = String::new();
    loop {
        let mut query: Vec<String> = signers
            .iter()
            .map(|s| format!("signer={}", hex(s)))
            .collect();
        if !cursor.is_empty() {
            query.push(format!("cursor={cursor}"));
        }
        let path = format!(
            "/v2/tenants/{}/trust-evidence?{}",
            hex(&TENANT),
            query.join("&")
        );
        let (status, body) = server.call(&path, bearer, None).await;
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
        let page = TenantTrustEvidencePageV2::parse(&body).unwrap();
        assert_eq!(page.page_index as usize, pages.len());
        assert_eq!(
            (page.server_instance_id, page.tenant_id),
            (INSTANCE, TENANT)
        );
        cursor = hex(&page.next_cursor);
        pages.push(page);
        if cursor.is_empty() {
            return pages;
        }
    }
}

fn containers(pages: &[TenantTrustEvidencePageV2]) -> Vec<Vec<u8>> {
    pages.iter().flat_map(|p| p.containers.clone()).collect()
}

#[tokio::test]
async fn the_trust_evidence_is_the_full_ancestry_of_the_root_subjects() {
    let mut server = start("trust-evidence", 28209).await;
    let (dev, access, _) = custodian(&mut server, 0x6d).await;
    let own = capability_grant(&dev, &dev.sk, |g| g.common.replay_id = [0xa5; 16]);
    assert_eq!(server.call(GRANTS, &access, Some(&own)).await.0, 201);
    // A grant for another device is evidence only when its key is asked about.
    let other = device(&server, OWNER, 0x6e, "active").await;
    let theirs = capability_grant(&other, &dev.sk, |g| g.common.replay_id = [0xa6; 16]);
    assert_eq!(server.call(GRANTS, &access, Some(&theirs)).await.0, 201);

    let pages = evidence(&server, &access, &[]).await;
    assert_eq!(pages.len(), 1);
    let all = containers(&pages);
    let stored = |table: &str| format!("SELECT exact_signed_container_bytes FROM {table}");
    let pool = db(&server.data).await;
    let mut want: Vec<Vec<u8>> = Vec::new();
    for table in ["v2_tenant_root_key_grants", "v2_device_approvals"] {
        want.extend(
            sqlx::query_scalar::<_, Vec<u8>>(&stored(table))
                .fetch_all(&pool)
                .await
                .unwrap(),
        );
    }
    want.push(own.clone());
    assert_eq!(
        all, want,
        "root grants, then approvals, then capability grants"
    );
    assert!(!all.contains(&theirs));
    assert_eq!(
        pages[0].signing_public_keys,
        vec![dev.sk.verifying_key().to_bytes()]
    );
    assert!(pages[0].revocations.is_empty());

    // What the server serves verifies on its own: the bootstrap anchor is
    // the custodian, and it is one now.
    let binding = Binding {
        server_instance_id: INSTANCE,
        tenant_id: TENANT,
    };
    let chain = TrustChain::evaluate(Evidence::collect(&binding, &pages).unwrap(), None).unwrap();
    assert_eq!(chain.anchor(), &dev.signing_key_id);
    assert!(chain.custodian_now(&dev.signing_key_id, now_ms()));
    assert!(!chain.custodian_now(&other.signing_key_id, now_ms()));
    // The grant it filed for itself is held under its own custody.
    assert!(chain.capability_at(
        &dev.signing_key_id,
        Capability::DeviceApprove,
        Scope::Fleet([0x33; 16]),
        now_ms()
    ));

    // Naming the other device's key adds its grant.
    let named = containers(&evidence(&server, &access, &[other.signing_key_id]).await);
    assert_eq!(named.len(), all.len() + 1);
    assert_eq!(named.last(), Some(&theirs));

    // A revoked record is still evidence, and is reported revoked.
    server
        .sql(
            "UPDATE v2_capability_grants SET revoked_at = '2026-01-01T00:00:00+00:00'
              WHERE replay_id = ?",
            &[&[0xa5; 16]],
        )
        .await;
    let pages = evidence(&server, &access, &[]).await;
    assert_eq!(containers(&pages), all);
    assert_eq!(pages[0].revocations.len(), 1);
    assert_eq!(
        (
            pages[0].revocations[0].replay_id,
            pages[0].revocations[0].revoked_at_ms
        ),
        ([0xa5; 16], 1_767_225_600_000)
    );

    // A quarantined grant is not served, and two rows holding one container
    // serve it once.
    server
        .sql(
            "INSERT INTO v2_grant_quarantine
                 SELECT 'capability_grant', server_instance_id, tenant_id, replay_id,
                        'container_mismatch', 't'
                   FROM v2_capability_grants WHERE replay_id = ?",
            &[&[0xa5; 16]],
        )
        .await;
    for statement in [
        "CREATE TABLE twin AS SELECT * FROM v2_device_approvals LIMIT 1",
        "UPDATE twin SET replay_id = x'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'",
        "INSERT INTO v2_device_approvals SELECT * FROM twin",
    ] {
        server.sql(statement, &[]).await;
    }
    let served = containers(&evidence(&server, &access, &[]).await);
    let without: Vec<Vec<u8>> = all.iter().filter(|c| **c != own).cloned().collect();
    assert_eq!(served, without);

    // A joining device reads it too; another tenant's path and a ticket do
    // not.
    let joiner = device(&server, OWNER, 0x6f, "pending").await;
    let pending = session(&server, &joiner).await["access_token"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(containers(&evidence(&server, &pending, &[]).await), without);
    let elsewhere = format!("/v2/tenants/{}/trust-evidence", hex(&[0x42; 16]));
    assert_eq!(server.call(&elsewhere, &access, None).await.0, 404);
    let ticket = server.login("owner").await["ticket"]
        .as_str()
        .unwrap()
        .to_string();
    let path = format!("/v2/tenants/{}/trust-evidence", hex(&TENANT));
    assert_eq!(server.call(&path, &ticket, None).await.0, 403);
    for bad in ["cursor=00", "signer=00", "other=1"] {
        assert_eq!(
            server.call(&format!("{path}?{bad}"), &access, None).await.0,
            400,
            "{bad}"
        );
    }
    pool.close().await;
}

#[tokio::test]
async fn the_trust_evidence_pages_past_a_thousand_containers_and_leaves_nothing_out() {
    let mut server = start("trust-pages", 28210).await;
    let (_dev, access, _) = custodian(&mut server, 0x70).await;
    // 1100 more approvals of the root subject, each its own container.
    let pool = db(&server.data).await;
    let cols: String = sqlx::query_scalar(
        "SELECT group_concat(name, ', ') FROM pragma_table_info('v2_device_approvals')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let picked = cols
        .split(", ")
        .map(|c| match c {
            "replay_id" => "randomblob(16)",
            "exact_signed_container_bytes" => "randomblob(200)",
            other => other,
        })
        .collect::<Vec<_>>()
        .join(", ");
    sqlx::query(&format!(
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 1100)
         INSERT INTO v2_device_approvals ({cols})
         SELECT {picked} FROM n, (SELECT * FROM v2_device_approvals LIMIT 1)"
    ))
    .execute(&pool)
    .await
    .unwrap();
    // A row of another server instance is not this tenant's evidence.
    let foreign = cols
        .split(", ")
        .map(|c| match c {
            "server_instance_id" => "randomblob(16)",
            "replay_id" => "randomblob(16)",
            "exact_signed_container_bytes" => "randomblob(200)",
            other => other,
        })
        .collect::<Vec<_>>()
        .join(", ");
    sqlx::query(&format!(
        "INSERT INTO v2_device_approvals ({cols})
         SELECT {foreign} FROM (SELECT * FROM v2_device_approvals LIMIT 1)"
    ))
    .execute(&pool)
    .await
    .unwrap();
    let total: i64 = server
        .count(&format!(
            "SELECT (SELECT count(*) FROM v2_tenant_root_key_grants)
                  + (SELECT count(*) FROM v2_device_approvals WHERE server_instance_id = x'{}')",
            hex(&INSTANCE)
        ))
        .await;
    assert_eq!(
        server
            .count(&format!(
                "SELECT count(*) FROM v2_device_approvals WHERE server_instance_id <> x'{}'",
                hex(&INSTANCE)
            ))
            .await,
        1
    );
    pool.close().await;

    let pages = evidence(&server, &access, &[]).await;
    assert_eq!(pages.len(), 2);
    assert_eq!(pages[0].containers.len(), 1024);
    let all = containers(&pages);
    assert_eq!(all.len() as i64, total);
    let unique: std::collections::BTreeSet<_> = all.iter().collect();
    assert_eq!(unique.len(), all.len(), "no container twice");

    // A cursor cannot name a page past the last index.
    let forged = format!(
        "/v2/tenants/{}/trust-evidence?cursor=ffffffff000000000000000000",
        hex(&TENANT)
    );
    assert_eq!(server.call(&forged, &access, None).await.0, 400);
}

#[tokio::test]
async fn a_trust_evidence_page_stays_within_four_mebibytes() {
    let mut server = start("trust-bytes", 28211).await;
    let (_dev, access, _) = custodian(&mut server, 0x71).await;
    // 40 revoked approvals of 128 KiB each: more than one page can carry.
    let pool = db(&server.data).await;
    let cols: String = sqlx::query_scalar(
        "SELECT group_concat(name, ', ') FROM pragma_table_info('v2_device_approvals')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let picked = cols
        .split(", ")
        .map(|c| match c {
            "replay_id" => "randomblob(16)",
            "exact_signed_container_bytes" => "randomblob(131072)",
            "revoked_at" => "'2026-01-01T00:00:00+00:00'",
            other => other,
        })
        .collect::<Vec<_>>()
        .join(", ");
    sqlx::query(&format!(
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 40)
         INSERT INTO v2_device_approvals ({cols})
         SELECT {picked} FROM n, (SELECT * FROM v2_device_approvals LIMIT 1)"
    ))
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;

    let pages = evidence(&server, &access, &[]).await;
    assert!(pages.len() >= 2, "{} pages", pages.len());
    for page in &pages {
        assert!(page.encode().len() <= shared::trust_evidence::MAX_PAGE_BYTES);
    }
    assert_eq!(containers(&pages).len(), 1 + 41);
    let reported: usize = pages.iter().map(|p| p.revocations.len()).sum();
    assert_eq!(reported, 40);
}

// ------------------------------------------------ D-9 fleet create and grants ---

const FLEET: [u8; 16] = [0xf5; 16];

fn fleet_generation_path() -> String {
    format!("/v2/fleets/{}/key-generations", hex(&FLEET))
}

fn fleet_grants_path(generation: u64) -> String {
    format!("{}/{generation}/grants", fleet_generation_path())
}

fn fleet_common(replay: u8, days: u64) -> CommonFields {
    let start = now_ms() - 60_000;
    CommonFields {
        replay_id: [replay; 16],
        tenant_id: TENANT,
        issued_at_ms: start,
        not_before_ms: start,
        not_after_ms: start + days * DAY_MS,
        server_instance_id: INSTANCE,
        restore_epoch: 0,
    }
}

fn container_hash(container: &[u8]) -> [u8; 32] {
    *AuthorizationRecord::parse(container)
        .unwrap()
        .signed_container_hash()
}

/// The `FLEET_GRANT_CREATE` request filing `container` as `variant`.
fn fleet_grant_request(
    key: u8,
    generation: u64,
    fkek: [u8; 32],
    variant: shared::fleet_lifecycle::FleetGrantVariant,
    replay: u8,
    container: &[u8],
) -> Vec<u8> {
    use shared::fleet_lifecycle::{FleetGenerationRef, FleetKeyGrantCreateV2};
    // Every fixture grant's replay ID is one repeated byte.
    let replay_id = [replay; 16];
    let create = FleetKeyGrantCreateV2::new(
        FleetGenerationRef {
            tenant_id: TENANT,
            server_instance_id: INSTANCE,
            restore_epoch: 0,
            fleet_id: FLEET,
            generation,
            fkek_key_id: fkek,
        },
        variant,
        replay_id,
        container_hash(container),
        container.to_vec(),
    );
    lifecycle_request(OperationKind::FleetGrantCreate, key, create.encode())
}

#[tokio::test]
async fn a_custodian_creates_fleet_generations_and_files_their_grants() {
    use shared::authz_record::{
        DeviceHpkeGrantV2, RecoveryGrantV2, RotationGrantV2, DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE,
        DOMAIN_FLEET_KEY_GRANT_RECOVERY, DOMAIN_FLEET_KEY_GRANT_ROTATION,
    };
    use shared::fleet_lifecycle::{
        FleetGenerationRef, FleetGenerationTerms, FleetGrantVariant as V,
        FleetKeyGenerationCreateV2, FleetKeyGenerationCreatedV2, FleetRotation,
    };
    use shared::mutation::fleet_device_grant_set_hash;

    let mut server = start("d9-fleet", 28212).await;
    let (dev, access, _) = custodian(&mut server, 0x6c).await;
    server
        .sql(
            "INSERT INTO v2_fleets (id, tenant_id, name, status, created_at)
             VALUES (?, ?, 'f', 'active', 'now')",
            &[&FLEET, &TENANT],
        )
        .await;
    let (fkek0, fkek1) = ([0xe0; 32], [0xe1; 32]);
    let device_grant = |replay: u8, generation: u64, fkek: [u8; 32], days: u64| {
        let g = DeviceHpkeGrantV2 {
            common: fleet_common(replay, days),
            fleet_id: FLEET,
            fkek_key_id: fkek,
            generation,
            subject_account_id: OWNER,
            subject_device_id: dev.id,
            subject_signing_key_id: dev.signing_key_id,
            recipient_hpke_key_id: dev.hpke_key_id,
            hpke_encapped_key_bytes: vec![3; 32],
            hpke_wrapped_fleet_key_bytes: vec![4; 48],
        };
        build_record(&dev.sk, DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE, &g.encode())
    };
    let recovery_grant = |replay: u8, generation: u64, fkek: [u8; 32]| {
        let g = RecoveryGrantV2 {
            common: fleet_common(replay, 3650),
            fleet_id: FLEET,
            fkek_key_id: fkek,
            generation,
            recipient_root_key_id: shared::keys::root_key_id(&TRK),
            recipient_root_generation: 0,
            root_wrap_nonce_bytes: [5; 12],
            wrapped_fleet_key_bytes: [6; 48],
        };
        build_record(&dev.sk, DOMAIN_FLEET_KEY_GRANT_RECOVERY, &g.encode())
    };
    let gen_ref = |generation: u64, fkek: [u8; 32]| FleetGenerationRef {
        tenant_id: TENANT,
        server_instance_id: INSTANCE,
        restore_epoch: 0,
        fleet_id: FLEET,
        generation,
        fkek_key_id: fkek,
    };

    // Generation 0 names its one device grant and its recovery grant (D-4).
    let device0 = device_grant(0xd0, 0, fkek0, 365);
    let recovery0 = recovery_grant(0xd1, 0, fkek0);
    let create0 = FleetKeyGenerationCreateV2 {
        terms: FleetGenerationTerms {
            generation: gen_ref(0, fkek0),
            required_device_grant_count: 1,
            required_device_grant_set_hash: fleet_device_grant_set_hash(&[container_hash(
                &device0,
            )])
            .unwrap(),
            recovery_grant_signed_container_hash: container_hash(&recovery0),
            rotation: None,
        },
        root_generation: 0,
    };
    let request0 = lifecycle_request(OperationKind::FleetGenerationCreate, 0xc1, create0.encode());

    // A custodian without `fleet.manage` creates nothing (D-2).
    let path = fleet_generation_path();
    assert_eq!(server.call(&path, &access, Some(&request0)).await.0, 403);
    let manage = capability_grant(&dev, &dev.sk, |g| {
        g.common.replay_id = [0xa7; 16];
        g.scope_kind = CapabilityScopeKind::Fleet;
        g.scope_id = FLEET;
        g.capability = Capability::FleetManage;
    });
    assert_eq!(server.call(GRANTS, &access, Some(&manage)).await.0, 201);

    let (status, body) = server.call(&path, &access, Some(&request0)).await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    let stored = IdempotentStoredResponseV2::parse(&body).unwrap();
    let created =
        FleetKeyGenerationCreatedV2::parse(&stored.canonical_response_payload_bytes).unwrap();
    assert_eq!(created.create, create0);
    // The same bytes get the same answer; a second bootstrap is refused.
    assert_eq!(
        server.call(&path, &access, Some(&request0)).await,
        (201, body.clone())
    );
    let mut other = create0.clone();
    other.terms.generation.fkek_key_id = [0xee; 32];
    let again = lifecycle_request(OperationKind::FleetGenerationCreate, 0xc2, other.encode());
    let (status, body) = server.call(&path, &access, Some(&again)).await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (409, "FLEET_GENERATION_EXISTS")
    );

    // Grants for generation 0: the device grant and the recovery grant.
    let grants0 = fleet_grants_path(0);
    let device_request = fleet_grant_request(0xc3, 0, fkek0, V::DeviceHpke, 0xd0, &device0);
    let (status, body) = server.call(&grants0, &access, Some(&device_request)).await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    assert_eq!(
        server.call(&grants0, &access, Some(&device_request)).await,
        (201, body)
    );
    let recovery_request = fleet_grant_request(0xc4, 0, fkek0, V::Recovery, 0xd1, &recovery0);
    let (status, body) = server
        .call(&grants0, &access, Some(&recovery_request))
        .await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    // A grant signed by another key and a variant the request does not name
    // are refused.
    let stranger = Ed25519SigningKey::from_bytes(&[0x99; 32]);
    let forged = {
        let parsed = AuthorizationRecord::parse(&device_grant(0xd3, 0, fkek0, 30)).unwrap();
        build_record(
            &stranger,
            DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE,
            parsed.canonical_payload_bytes(),
        )
    };
    let forged = fleet_grant_request(0xc7, 0, fkek0, V::DeviceHpke, 0xd3, &forged);
    let (status, body) = server.call(&grants0, &access, Some(&forged)).await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (422, "KEY_SUBSTITUTION_DETECTED")
    );
    let misnamed = fleet_grant_request(
        0xc8,
        0,
        fkek0,
        V::Recovery,
        0xd4,
        &device_grant(0xd4, 0, fkek0, 30),
    );
    assert_eq!(server.call(&grants0, &access, Some(&misnamed)).await.0, 422);

    // Rotation to generation 1 needs `key.rotate` and an ACTIVE generation 0.
    // shortcut: activation is the next route; the test marks it ACTIVE.
    server
        .sql(
            "UPDATE v2_fleet_key_generations SET state = 'ACTIVE', activated_at = 'now'
              WHERE tenant_id = ? AND fleet_id = ? AND generation = 0",
            &[&TENANT, &FLEET],
        )
        .await;
    // An issuer that does not hold generation 0 hands it to nobody else (D-2).
    let peer = device(&server, OWNER, 0x7d, "active").await;
    approve_by_copy(&server, &dev, &peer, 0x7d).await;
    let to_peer = DeviceHpkeGrantV2 {
        common: fleet_common(0xdd, 30),
        fleet_id: FLEET,
        fkek_key_id: fkek0,
        generation: 0,
        subject_account_id: OWNER,
        subject_device_id: peer.id,
        subject_signing_key_id: peer.signing_key_id,
        recipient_hpke_key_id: peer.hpke_key_id,
        hpke_encapped_key_bytes: vec![3; 32],
        hpke_wrapped_fleet_key_bytes: vec![4; 48],
    };
    let to_peer = build_record(
        &dev.sk,
        DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE,
        &to_peer.encode(),
    );
    let request = fleet_grant_request(0xcf, 0, fkek0, V::DeviceHpke, 0xdd, &to_peer);
    assert_eq!(server.call(&grants0, &access, Some(&request)).await.0, 403);
    // The rotation issuer holds generation 0 (D-2): it acknowledges its grant.
    let ack0 = lifecycle_request(
        OperationKind::FleetGrantAck,
        0xcc,
        shared::fleet_lifecycle::FleetKeyGrantAckV2 {
            grant: fleet_grant_ref(0, fkek0, V::DeviceHpke, 0xd0, &device0),
        }
        .encode(),
    );
    let ack0_path = format!("{path}/0/ack");
    assert_eq!(server.call(&ack0_path, &access, Some(&ack0)).await.0, 201);
    // Holding it, the issuer still cannot reuse a spent replay ID or file a
    // device grant past 365 days.
    let reused = fleet_grant_request(0xc5, 0, fkek0, V::DeviceHpke, 0xd0, &device0);
    let (status, body) = server.call(&grants0, &access, Some(&reused)).await;
    assert_eq!((status, code_of(&body).as_str()), (409, "REPLAY_DETECTED"));
    let long = fleet_grant_request(
        0xc6,
        0,
        fkek0,
        V::DeviceHpke,
        0xd2,
        &device_grant(0xd2, 0, fkek0, 366),
    );
    assert_eq!(server.call(&grants0, &access, Some(&long)).await.0, 403);
    // A subject without a live approval gets no fleet key (D-2).
    let unapproved = device(&server, OWNER, 0x7f, "active").await;
    let to_unapproved = DeviceHpkeGrantV2 {
        common: fleet_common(0xdb, 30),
        fleet_id: FLEET,
        fkek_key_id: fkek0,
        generation: 0,
        subject_account_id: OWNER,
        subject_device_id: unapproved.id,
        subject_signing_key_id: unapproved.signing_key_id,
        recipient_hpke_key_id: unapproved.hpke_key_id,
        hpke_encapped_key_bytes: vec![3; 32],
        hpke_wrapped_fleet_key_bytes: vec![4; 48],
    };
    let to_unapproved = build_record(
        &dev.sk,
        DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE,
        &to_unapproved.encode(),
    );
    let request = fleet_grant_request(0xcd, 0, fkek0, V::DeviceHpke, 0xdb, &to_unapproved);
    let (status, body) = server.call(&grants0, &access, Some(&request)).await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (409, "SUBJECT_NOT_ELIGIBLE")
    );

    let device1 = device_grant(0xd5, 1, fkek1, 365);
    let recovery1 = recovery_grant(0xd6, 1, fkek1);
    let set1 = fleet_device_grant_set_hash(&[container_hash(&device1)]).unwrap();
    let rotation_grant = |replay: u8, count: u32| {
        let common = fleet_common(replay, 30);
        let g = RotationGrantV2 {
            activation_not_before_ms: common.not_before_ms,
            common,
            fleet_id: FLEET,
            fkek_key_id: fkek1,
            generation: 1,
            previous_fkek_key_id: fkek0,
            previous_generation: 0,
            required_device_grant_count: count,
            required_device_grant_set_hash: set1,
            recovery_grant_signed_container_hash: container_hash(&recovery1),
        };
        build_record(&dev.sk, DOMAIN_FLEET_KEY_GRANT_ROTATION, &g.encode())
    };
    let rotation1 = rotation_grant(0xd7, 1);
    let create1 = FleetKeyGenerationCreateV2 {
        terms: FleetGenerationTerms {
            generation: gen_ref(1, fkek1),
            required_device_grant_count: 1,
            required_device_grant_set_hash: set1,
            recovery_grant_signed_container_hash: container_hash(&recovery1),
            rotation: Some(FleetRotation {
                previous_generation: 0,
                previous_fkek_key_id: fkek0,
                rotation_grant_signed_container_hash: container_hash(&rotation1),
            }),
        },
        root_generation: 0,
    };
    let request1 = lifecycle_request(OperationKind::FleetGenerationCreate, 0xc9, create1.encode());
    assert_eq!(server.call(&path, &access, Some(&request1)).await.0, 403);
    let rotate = capability_grant(&dev, &dev.sk, |g| {
        g.common.replay_id = [0xa8; 16];
        g.capability = Capability::KeyRotate;
    });
    assert_eq!(server.call(GRANTS, &access, Some(&rotate)).await.0, 201);
    let (status, body) = server.call(&path, &access, Some(&request1)).await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));

    // The rotation grant must be the one the generation names.
    let grants1 = fleet_grants_path(1);
    let wrong = fleet_grant_request(0xca, 1, fkek1, V::Rotation, 0xd8, &rotation_grant(0xd8, 2));
    let (status, body) = server.call(&grants1, &access, Some(&wrong)).await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (409, "ROTATION_GRANT_MISMATCH")
    );
    let right = fleet_grant_request(0xcb, 1, fkek1, V::Rotation, 0xd7, &rotation1);
    let (status, body) = server.call(&grants1, &access, Some(&right)).await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    // An archived fleet takes no new device grant.
    server
        .sql(
            "UPDATE v2_fleets SET status = 'archived' WHERE tenant_id = ? AND id = ?",
            &[&TENANT, &FLEET],
        )
        .await;
    let late = fleet_grant_request(
        0xce,
        1,
        fkek1,
        V::DeviceHpke,
        0xdc,
        &device_grant(0xdc, 1, fkek1, 30),
    );
    let (status, body) = server.call(&grants1, &access, Some(&late)).await;
    assert_eq!((status, code_of(&body).as_str()), (409, "FLEET_ARCHIVED"));

    for (query, want) in [
        (
            "SELECT count(*) FROM v2_fleet_key_generations WHERE state = 'PREPARING'",
            1,
        ),
        (
            "SELECT count(*) FROM v2_fleet_device_hpke_grants WHERE acked_at IS NOT NULL",
            1,
        ),
        ("SELECT count(*) FROM v2_fleet_recovery_grants", 1),
        ("SELECT count(*) FROM v2_fleet_rotation_grants", 1),
        (
            "SELECT count(*) FROM v2_audit_events WHERE action = 'fleet.key_generation.create'",
            2,
        ),
        (
            "SELECT count(*) FROM v2_audit_events WHERE action = 'fleet.key_grant.create'",
            3,
        ),
        (
            "SELECT count(*) FROM v2_idempotency WHERE operation_kind = 'FLEET_GRANT_CREATE'",
            3,
        ),
    ] {
        assert_eq!(server.count(query).await, want, "{query}");
    }
}

/// Gives `to` a live approval by copying `from`'s stored one with `to`'s keys.
/// The copy's container no longer matches its columns; the fleet routes only
/// ask whether a live approval of the subject's keys exists.
async fn approve_by_copy(server: &Server, from: &Device, to: &Device, replay: u8) {
    approve_by_copy_in(server, from, to, replay, "approval_scope_kind").await;
}

/// [`approve_by_copy`] with `scope` as the approval scope kind, a column name
/// to keep the copy's or a quoted literal such as `'fleet'`.
async fn approve_by_copy_in(server: &Server, from: &Device, to: &Device, replay: u8, scope: &str) {
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
             SELECT tenant_id, ?, payload_domain, payload_version, subject_account_id,
                    ?, ?, ?, {scope}, approval_scope_id, approved_use, issued_at_ms,
                    not_before_ms, not_after_ms, server_instance_id, restore_epoch,
                    canonical_payload_bytes, payload_sha256, signature_suite_id, signature_version,
                    signature_bytes, issuer_signing_key_id, signed_container_hash,
                    exact_signed_container_bytes, exact_signed_container_bytes_sha256, created_at
               FROM v2_device_approvals WHERE subject_device_id = ?"
            ),
            &[
                &[replay; 16],
                &to.id,
                &to.signing_key_id,
                &to.hpke_key_id,
                &from.id,
            ],
        )
        .await;
}

fn fleet_grant_ref(
    generation: u64,
    fkek: [u8; 32],
    variant: shared::fleet_lifecycle::FleetGrantVariant,
    replay: u8,
    container: &[u8],
) -> shared::fleet_lifecycle::FleetGrantRef {
    use shared::fleet_lifecycle::{FleetGenerationRef, FleetKeyGrantCreateV2};
    FleetKeyGrantCreateV2::new(
        FleetGenerationRef {
            tenant_id: TENANT,
            server_instance_id: INSTANCE,
            restore_epoch: 0,
            fleet_id: FLEET,
            generation,
            fkek_key_id: fkek,
        },
        variant,
        [replay; 16],
        container_hash(container),
        container.to_vec(),
    )
    .grant
}

#[tokio::test]
async fn a_custodian_acks_activates_rotates_and_revokes_fleet_grants() {
    use shared::authz_record::{
        DeviceHpkeGrantV2, RecoveryGrantV2, RotationGrantV2, DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE,
        DOMAIN_FLEET_KEY_GRANT_RECOVERY, DOMAIN_FLEET_KEY_GRANT_ROTATION,
    };
    use shared::fleet_lifecycle::{
        FleetGenerationRef, FleetGenerationTerms, FleetGrantRevocation, FleetGrantRevokeReason,
        FleetGrantRevokeV2, FleetGrantRevokedV2, FleetGrantVariant as V,
        FleetKeyGenerationActivateV2, FleetKeyGenerationCreateV2, FleetKeyGrantAckV2,
        FleetRotation,
    };
    use shared::mutation::fleet_device_grant_set_hash;

    let mut server = start("d9-fleet-ack", 28213).await;
    let (dev, access, _) = custodian(&mut server, 0x6d).await;
    server
        .sql(
            "INSERT INTO v2_fleets (id, tenant_id, name, status, created_at)
             VALUES (?, ?, 'f', 'active', 'now')",
            &[&FLEET, &TENANT],
        )
        .await;
    for (replay, capability) in [
        (0xa7, Capability::FleetManage),
        (0xa8, Capability::KeyRotate),
    ] {
        let grant = capability_grant(&dev, &dev.sk, |g| {
            g.common.replay_id = [replay; 16];
            g.capability = capability;
        });
        assert_eq!(server.call(GRANTS, &access, Some(&grant)).await.0, 201);
    }
    let gen_ref = |generation: u64, fkek: [u8; 32]| FleetGenerationRef {
        tenant_id: TENANT,
        server_instance_id: INSTANCE,
        restore_epoch: 0,
        fleet_id: FLEET,
        generation,
        fkek_key_id: fkek,
    };
    let device_grant = |replay: u8, generation: u64, fkek: [u8; 32]| {
        let g = DeviceHpkeGrantV2 {
            common: fleet_common(replay, 365),
            fleet_id: FLEET,
            fkek_key_id: fkek,
            generation,
            subject_account_id: OWNER,
            subject_device_id: dev.id,
            subject_signing_key_id: dev.signing_key_id,
            recipient_hpke_key_id: dev.hpke_key_id,
            hpke_encapped_key_bytes: vec![3; 32],
            hpke_wrapped_fleet_key_bytes: vec![4; 48],
        };
        build_record(&dev.sk, DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE, &g.encode())
    };
    let recovery_grant = |replay: u8, generation: u64, fkek: [u8; 32]| {
        let g = RecoveryGrantV2 {
            common: fleet_common(replay, 3650),
            fleet_id: FLEET,
            fkek_key_id: fkek,
            generation,
            recipient_root_key_id: shared::keys::root_key_id(&TRK),
            recipient_root_generation: 0,
            root_wrap_nonce_bytes: [5; 12],
            wrapped_fleet_key_bytes: [6; 48],
        };
        build_record(&dev.sk, DOMAIN_FLEET_KEY_GRANT_RECOVERY, &g.encode())
    };
    let path = fleet_generation_path();
    // Files one grant under idempotency key `$key`.
    macro_rules! file {
        ($key:expr, $generation:expr, $fkek:expr, $variant:expr, $replay:expr, $c:expr) => {{
            let request = fleet_grant_request($key, $generation, $fkek, $variant, $replay, $c);
            let grants = fleet_grants_path($generation);
            assert_eq!(server.call(&grants, &access, Some(&request)).await.0, 201);
        }};
    }
    let ack = |key: u8, generation: u64, fkek: [u8; 32], variant: V, replay: u8, c: &[u8]| {
        let grant = fleet_grant_ref(generation, fkek, variant, replay, c);
        lifecycle_request(
            OperationKind::FleetGrantAck,
            key,
            FleetKeyGrantAckV2 { grant }.encode(),
        )
    };
    let activate = |key: u8, terms: FleetGenerationTerms| {
        lifecycle_request(
            OperationKind::FleetGenerationActivate,
            key,
            FleetKeyGenerationActivateV2 { terms }.encode(),
        )
    };

    // Generation 0: create, file both grants.
    let (fkek0, fkek1) = ([0xe0; 32], [0xe1; 32]);
    let (device0, recovery0) = (device_grant(0xd0, 0, fkek0), recovery_grant(0xd1, 0, fkek0));
    let terms0 = FleetGenerationTerms {
        generation: gen_ref(0, fkek0),
        required_device_grant_count: 1,
        required_device_grant_set_hash: fleet_device_grant_set_hash(&[container_hash(&device0)])
            .unwrap(),
        recovery_grant_signed_container_hash: container_hash(&recovery0),
        rotation: None,
    };
    let create0 = FleetKeyGenerationCreateV2 {
        terms: terms0,
        root_generation: 0,
    };
    let request = lifecycle_request(OperationKind::FleetGenerationCreate, 0xb0, create0.encode());
    assert_eq!(server.call(&path, &access, Some(&request)).await.0, 201);
    file!(0xb1, 0, fkek0, V::DeviceHpke, 0xd0, &device0);
    file!(0xb2, 0, fkek0, V::Recovery, 0xd1, &recovery0);

    // The launcher's v1 read reports only what this lifecycle activates.
    server
        .sql(
            "UPDATE v2_accounts SET legacy_user_id = (SELECT id FROM users WHERE username = 'admin')
              WHERE id = ?",
            &[&OWNER],
        )
        .await;
    let (_, login) = server
        .post(
            "/auth/login",
            None,
            json!({ "username": "admin", "password": "secret" }),
        )
        .await;
    let v1 = login["token"].as_str().unwrap().to_string();
    let active_path = format!(
        "/v2/tenants/{}/fleets/{}/key-generation",
        hex(&TENANT),
        hex(&FLEET)
    );
    let (status, body) = server.call(&active_path, &v1, None).await;
    assert_eq!((status, body.as_slice()), (200, b"null".as_slice()));

    // Activation waits for every required acknowledgement (D-4, D-9).
    let activate0 = activate(0xb3, terms0);
    let ack0 = format!("{path}/0/ack");
    let activate0_path = format!("{path}/0/activate");
    let (status, body) = server
        .call(&activate0_path, &access, Some(&activate0))
        .await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (409, "FLEET_GRANTS_INCOMPLETE")
    );
    let device_ack = ack(0xb4, 0, fkek0, V::DeviceHpke, 0xd0, &device0);
    let (status, body) = server.call(&ack0, &access, Some(&device_ack)).await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    // An exact retry gets the stored answer; a second ack is refused.
    assert_eq!(
        server.call(&ack0, &access, Some(&device_ack)).await,
        (201, body)
    );
    // Only the grant's subject acknowledges a device grant (D-9).
    let other = device(&server, OWNER, 0x7e, "active").await;
    approve_by_copy(&server, &dev, &other, 0x7e).await;
    let to_other = DeviceHpkeGrantV2 {
        common: fleet_common(0xd9, 365),
        fleet_id: FLEET,
        fkek_key_id: fkek0,
        generation: 0,
        subject_account_id: OWNER,
        subject_device_id: other.id,
        subject_signing_key_id: other.signing_key_id,
        recipient_hpke_key_id: other.hpke_key_id,
        hpke_encapped_key_bytes: vec![3; 32],
        hpke_wrapped_fleet_key_bytes: vec![4; 48],
    };
    let to_other = build_record(
        &dev.sk,
        DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE,
        &to_other.encode(),
    );
    file!(0xba, 0, fkek0, V::DeviceHpke, 0xd9, &to_other);
    let foreign_ack = ack(0xbb, 0, fkek0, V::DeviceHpke, 0xd9, &to_other);
    assert_eq!(server.call(&ack0, &access, Some(&foreign_ack)).await.0, 403);
    let again = ack(0xb5, 0, fkek0, V::DeviceHpke, 0xd0, &device0);
    let (status, body) = server.call(&ack0, &access, Some(&again)).await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (409, "FLEET_GRANT_NOT_PENDING")
    );
    // The recovery grant is still unacknowledged.
    let activate0b = activate(0xb6, terms0);
    let (status, body) = server
        .call(&activate0_path, &access, Some(&activate0b))
        .await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (409, "FLEET_GRANTS_INCOMPLETE")
    );
    let recovery_ack = ack(0xb7, 0, fkek0, V::Recovery, 0xd1, &recovery0);
    assert_eq!(
        server.call(&ack0, &access, Some(&recovery_ack)).await.0,
        201
    );
    // A second acknowledged device grant makes the live set differ from the
    // required one, until it is revoked (D-4 "exactly").
    let extra = device_grant(0xda, 0, fkek0);
    file!(0xbc, 0, fkek0, V::DeviceHpke, 0xda, &extra);
    let extra_ack = ack(0xbd, 0, fkek0, V::DeviceHpke, 0xda, &extra);
    assert_eq!(server.call(&ack0, &access, Some(&extra_ack)).await.0, 201);
    let (status, body) = server
        .call(&activate0_path, &access, Some(&activate(0xbe, terms0)))
        .await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (409, "FLEET_GRANTS_INCOMPLETE")
    );
    let superseded = FleetGrantRevokeV2 {
        revocation: FleetGrantRevocation {
            generation: gen_ref(0, fkek0),
            grant_variant: V::DeviceHpke,
            replay_id: [0xda; 16],
            signed_container_hash: container_hash(&extra),
            reason_code: FleetGrantRevokeReason::Superseded,
        },
    };
    let request = lifecycle_request(OperationKind::FleetGrantRevoke, 0xbf, superseded.encode());
    let extra_path = format!("{path}/0/grants/{}/revoke", hex(&[0xda; 16]));
    assert_eq!(
        server.call(&extra_path, &access, Some(&request)).await.0,
        201
    );
    // Activation restating other terms is refused.
    let mut other = terms0;
    other.required_device_grant_count = 2;
    let (status, body) = server
        .call(&activate0_path, &access, Some(&activate(0xb8, other)))
        .await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (409, "FLEET_GENERATION_MISMATCH")
    );
    let (status, body) = server
        .call(&activate0_path, &access, Some(&activate0))
        .await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    assert_eq!(
        server
            .call(&activate0_path, &access, Some(&activate0))
            .await,
        (201, body)
    );

    // Rotation to generation 1: the rotation grant must be acknowledged too.
    let (device1, recovery1) = (device_grant(0xd5, 1, fkek1), recovery_grant(0xd6, 1, fkek1));
    let set1 = fleet_device_grant_set_hash(&[container_hash(&device1)]).unwrap();
    let rotation1 = {
        let common = fleet_common(0xd7, 30);
        let g = RotationGrantV2 {
            activation_not_before_ms: common.not_before_ms,
            common,
            fleet_id: FLEET,
            fkek_key_id: fkek1,
            generation: 1,
            previous_fkek_key_id: fkek0,
            previous_generation: 0,
            required_device_grant_count: 1,
            required_device_grant_set_hash: set1,
            recovery_grant_signed_container_hash: container_hash(&recovery1),
        };
        build_record(&dev.sk, DOMAIN_FLEET_KEY_GRANT_ROTATION, &g.encode())
    };
    let terms1 = FleetGenerationTerms {
        generation: gen_ref(1, fkek1),
        required_device_grant_count: 1,
        required_device_grant_set_hash: set1,
        recovery_grant_signed_container_hash: container_hash(&recovery1),
        rotation: Some(FleetRotation {
            previous_generation: 0,
            previous_fkek_key_id: fkek0,
            rotation_grant_signed_container_hash: container_hash(&rotation1),
        }),
    };
    let create1 = FleetKeyGenerationCreateV2 {
        terms: terms1,
        root_generation: 0,
    };
    let request = lifecycle_request(OperationKind::FleetGenerationCreate, 0xc0, create1.encode());
    assert_eq!(server.call(&path, &access, Some(&request)).await.0, 201);
    file!(0xc1, 1, fkek1, V::DeviceHpke, 0xd5, &device1);
    file!(0xc2, 1, fkek1, V::Recovery, 0xd6, &recovery1);
    // The issuer renews its generation-0 grant while it holds generation 0;
    // once the old grant is revoked it no longer holds it, and files no
    // rotation grant until it acknowledges the renewal (D-2).
    let renewed = device_grant(0xde, 0, fkek0);
    file!(0xe4, 0, fkek0, V::DeviceHpke, 0xde, &renewed);
    let drop0 = FleetGrantRevokeV2 {
        revocation: FleetGrantRevocation {
            generation: gen_ref(0, fkek0),
            grant_variant: V::DeviceHpke,
            replay_id: [0xd0; 16],
            signed_container_hash: container_hash(&device0),
            reason_code: FleetGrantRevokeReason::Superseded,
        },
    };
    let request = lifecycle_request(OperationKind::FleetGrantRevoke, 0xe2, drop0.encode());
    let drop_path = format!("{path}/0/grants/{}/revoke", hex(&[0xd0; 16]));
    assert_eq!(
        server.call(&drop_path, &access, Some(&request)).await.0,
        201
    );
    let early = fleet_grant_request(0xe3, 1, fkek1, V::Rotation, 0xd7, &rotation1);
    let grants1 = fleet_grants_path(1);
    assert_eq!(server.call(&grants1, &access, Some(&early)).await.0, 403);
    let request = ack(0xe5, 0, fkek0, V::DeviceHpke, 0xde, &renewed);
    assert_eq!(server.call(&ack0, &access, Some(&request)).await.0, 201);
    file!(0xc3, 1, fkek1, V::Rotation, 0xd7, &rotation1);
    let ack1 = format!("{path}/1/ack");
    for (key, variant, replay, c) in [
        (0xc4, V::DeviceHpke, 0xd5, &device1),
        (0xc5, V::Recovery, 0xd6, &recovery1),
    ] {
        let request = ack(key, 1, fkek1, variant, replay, c);
        assert_eq!(server.call(&ack1, &access, Some(&request)).await.0, 201);
    }
    let activate1_path = format!("{path}/1/activate");
    let (status, body) = server
        .call(&activate1_path, &access, Some(&activate(0xc6, terms1)))
        .await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (409, "FLEET_GRANTS_INCOMPLETE")
    );
    let rotation_ack = ack(0xc7, 1, fkek1, V::Rotation, 0xd7, &rotation1);
    assert_eq!(
        server.call(&ack1, &access, Some(&rotation_ack)).await.0,
        201
    );
    let (status, body) = server
        .call(&activate1_path, &access, Some(&activate(0xc8, terms1)))
        .await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    let (status, body) = server.call(&active_path, &v1, None).await;
    let active: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(status, 200, "{active}");
    assert_eq!(
        (
            &active["generation"],
            &active["fkek_key_id"],
            &active["state"]
        ),
        (&json!(1), &json!(hex(&fkek1)), &json!("ACTIVE"))
    );

    // Revoking the generation-1 device grant marks it and keeps the row.
    let revocation = FleetGrantRevocation {
        generation: gen_ref(1, fkek1),
        grant_variant: V::DeviceHpke,
        replay_id: [0xd5; 16],
        signed_container_hash: container_hash(&device1),
        reason_code: FleetGrantRevokeReason::MemberRemoved,
    };
    let revoke_path = format!("{path}/1/grants/{}/revoke", hex(&[0xd5; 16]));
    let revoke = |key: u8| {
        lifecycle_request(
            OperationKind::FleetGrantRevoke,
            key,
            FleetGrantRevokeV2 { revocation }.encode(),
        )
    };
    let (status, body) = server
        .call(&revoke_path, &access, Some(&revoke(0xc9)))
        .await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    let stored = IdempotentStoredResponseV2::parse(&body).unwrap();
    let revoked = FleetGrantRevokedV2::parse(&stored.canonical_response_payload_bytes).unwrap();
    assert_eq!(
        (revoked.revocation, revoked.invalidation_count),
        (revocation, 0)
    );
    assert_eq!(
        server
            .call(&revoke_path, &access, Some(&revoke(0xc9)))
            .await,
        (201, body)
    );
    let (status, body) = server
        .call(&revoke_path, &access, Some(&revoke(0xca)))
        .await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (409, "FLEET_GRANT_REVOKED")
    );
    // A path naming another grant than the body is refused.
    let wrong_path = format!("{path}/1/grants/{}/revoke", hex(&[0xd6; 16]));
    assert_eq!(
        server
            .call(&wrong_path, &access, Some(&revoke(0xcb)))
            .await
            .0,
        422
    );

    for (query, want) in [
        (
            "SELECT count(*) FROM v2_fleet_key_generations
              WHERE generation = 0 AND state = 'RETIRED' AND retired_at IS NOT NULL",
            1,
        ),
        (
            "SELECT count(*) FROM v2_fleet_key_generations
              WHERE generation = 1 AND state = 'ACTIVE' AND activated_at IS NOT NULL",
            1,
        ),
        (
            "SELECT count(*) FROM v2_fleet_device_hpke_grants
              WHERE acked_at IS NOT NULL AND revoked_at IS NULL",
            1,
        ),
        (
            "SELECT count(*) FROM v2_fleet_device_hpke_grants WHERE revoked_at IS NOT NULL",
            3,
        ),
        (
            "SELECT count(*) FROM v2_fleet_rotation_grants WHERE acked_at IS NOT NULL",
            1,
        ),
        (
            "SELECT count(*) FROM v2_audit_events WHERE action = 'fleet.key_grant.ack'",
            7,
        ),
        (
            "SELECT count(*) FROM v2_audit_events WHERE action = 'fleet.key_generation.activate'",
            2,
        ),
        (
            "SELECT count(*) FROM v2_audit_events WHERE action = 'fleet.key_grant.revoke'",
            3,
        ),
    ] {
        assert_eq!(server.count(query).await, want, "{query}");
    }

    // The trust evidence serves every fleet grant, revoked ones included,
    // and reports the revoked ones.
    let pages = evidence(&server, &access, &[]).await;
    let served = containers(&pages);
    for filed in [&device0, &recovery0, &device1, &recovery1, &rotation1] {
        assert!(served.contains(filed));
    }
    let reported: Vec<[u8; 16]> = pages
        .iter()
        .flat_map(|p| &p.revocations)
        .filter(|r| r.payload_domain == shared::authz_record::DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE)
        .map(|r| r.replay_id)
        .collect();
    assert_eq!(reported.len(), 3, "{reported:?}");
}

// ------------------------------------------------------- ROOT_GRANT_REVOKE ---

fn root_revoke_request(
    key: u8,
    grant: RootGrantRef,
    reason: shared::mutation::RootGrantRevokeReason,
) -> Vec<u8> {
    lifecycle_request(
        OperationKind::RootGrantRevoke,
        key,
        shared::mutation::TenantRootGrantRevokeV2 {
            grant,
            reason_code: reason,
        }
        .encode(),
    )
}

#[tokio::test]
async fn a_custodian_revokes_a_root_grant_but_never_the_last_one() {
    use shared::mutation::{RootGrantRevokeReason as R, TenantRootGrantRevokedV2};

    let mut server = start("root-revoke", 28214).await;
    let (dev, access, container, target, _) = bootstrapped_by(&mut server, 0x6e).await;
    let ack_path = format!("{}/ack", grant_path("0", &SELF_GRANT_REPLAY));
    let ack = ack_request(0xb1, grant_ref(&dev, &container));
    assert_eq!(server.call(&ack_path, &access, Some(&ack)).await.0, 201);
    let activate = activate_request(0xb3, target.clone());
    assert_eq!(
        server
            .call(&activate_path("0"), &access, Some(&activate))
            .await
            .0,
        201
    );
    let revoke_path = format!("{}/revoke", grant_path("0", &SELF_GRANT_REPLAY));
    let grant = grant_ref(&dev, &container);

    // A device that is no custodian revokes nothing.
    let stranger = device(&server, OWNER, 0x7c, "pending").await;
    let stranger_access = session(&server, &stranger).await["access_token"]
        .as_str()
        .unwrap()
        .to_string();
    let request = root_revoke_request(0xbf, grant.clone(), R::CustodyRemoved);
    assert_eq!(
        server
            .call(&revoke_path, &stranger_access, Some(&request))
            .await
            .0,
        403
    );
    // The ACTIVE root's only custodian cannot be revoked.
    let request = root_revoke_request(0xc0, grant.clone(), R::CustodyRemoved);
    let (status, body) = server.call(&revoke_path, &access, Some(&request)).await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (409, "LAST_ROOT_CUSTODIAN")
    );
    // A request naming another container, or a path naming another grant,
    // is refused.
    let mut other = grant.clone();
    other.signed_container_hash = [0x55; 32];
    let request = root_revoke_request(0xc1, other, R::CustodyRemoved);
    assert_eq!(
        server.call(&revoke_path, &access, Some(&request)).await.0,
        422
    );
    let request = root_revoke_request(0xc2, grant.clone(), R::CustodyRemoved);
    let wrong = format!("{}/revoke", grant_path("0", &[0x82; 16]));
    assert_eq!(server.call(&wrong, &access, Some(&request)).await.0, 422);

    // A second custodian: approved by the first (D-2), granted the root
    // through ROOT_GRANT_CREATE, and acknowledging it on its own session.
    let peer = device(&server, OWNER, 0x7b, "pending").await;
    let duty = capability_grant(&dev, &dev.sk, |g| {
        g.common.replay_id = [0xd7; 16];
    });
    assert_eq!(server.call(GRANTS, &access, Some(&duty)).await.0, 201);
    let peer_approval = approval(&peer, &dev.sk, 0x7b, 0, 30);
    assert_eq!(
        server.approve(&peer.id, &access, &peer_approval).await.0,
        201
    );
    let existing = existing_root_grant(&dev, &peer, 0x7b, 0x91);
    let request = root_grant_create_request(0xc4, &dev, &existing);
    assert_eq!(
        server
            .call(&root_grants_path(), &access, Some(&request))
            .await
            .0,
        201
    );
    let peer_access = session(&server, &peer).await["access_token"]
        .as_str()
        .unwrap()
        .to_string();
    let peer_grant = grant_path("0", &[0x91; 16]);
    // Only its subject reads it, and acknowledges it once.
    assert_eq!(server.call(&peer_grant, &peer_access, None).await.0, 200);
    assert_eq!(
        server.call(&peer_grant, &stranger_access, None).await.0,
        404
    );
    let peer_ack = ack_request(0xd8, grant_ref(&dev, &existing));
    let ack_peer = format!("{peer_grant}/ack");
    assert_eq!(
        server.call(&ack_peer, &access, Some(&peer_ack)).await.0,
        403
    );
    let (status, body) = server.call(&ack_peer, &peer_access, Some(&peer_ack)).await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    assert_eq!(
        server.call(&ack_peer, &peer_access, Some(&peer_ack)).await,
        (201, body)
    );

    // A grant whose device is no longer active makes no custodian, so it does
    // not stand in for the last one.
    let peer_status = |status: &'static str| {
        format!(
            "UPDATE v2_devices SET status = '{status}' WHERE id = X'{}'",
            hex(&peer.id)
        )
    };
    server.sql(&peer_status("revoked"), &[]).await;
    let request = root_revoke_request(0xc5, grant.clone(), R::DeviceLost);
    let (status, body) = server.call(&revoke_path, &access, Some(&request)).await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (409, "LAST_ROOT_CUSTODIAN")
    );
    server.sql(&peer_status("active"), &[]).await;

    // A second, expired session of the subject is ended too, but not counted.
    // shortcut: a session's expiry never changes, so the test drops that guard
    // to age one.
    session(&server, &dev).await;
    server
        .sql("DROP TRIGGER v2_sessions_binding_is_fixed", &[])
        .await;
    server
        .sql(
            &format!(
                "UPDATE v2_sessions
                    SET access_expires_at_ms = 1, refresh_expires_at_ms = 1,
                        absolute_expires_at_ms = 1
                  WHERE rowid = (SELECT max(rowid) FROM v2_sessions WHERE device_id = X'{}')",
                hex(&dev.id)
            ),
            &[],
        )
        .await;

    let request = root_revoke_request(0xc3, grant.clone(), R::DeviceLost);
    let (status, body) = server.call(&revoke_path, &access, Some(&request)).await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    let stored = IdempotentStoredResponseV2::parse(&body).unwrap();
    let revoked =
        TenantRootGrantRevokedV2::parse(&stored.canonical_response_payload_bytes).unwrap();
    assert_eq!(
        (revoked.grant, revoked.reason_code),
        (grant.clone(), R::DeviceLost)
    );
    // It ended the subject's one live session; a fresh session of the same
    // device gets the stored bytes back.
    assert_eq!(revoked.sessions_invalidated_count, 1);
    assert_eq!(
        server.call(&revoke_path, &access, Some(&request)).await.0,
        401
    );
    let fresh = session(&server, &dev).await["access_token"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        server.call(&revoke_path, &fresh, Some(&request)).await,
        (201, body)
    );

    for (query, want) in [
        (
            "SELECT count(*) FROM v2_tenant_root_key_grants
              WHERE grant_variant = 'FirstRootSelfGrant' AND revoked_at IS NOT NULL",
            1,
        ),
        (
            "SELECT count(*) FROM v2_tenant_root_key_grants
              WHERE grant_variant = 'ExistingRootGrant' AND revoked_at IS NULL",
            1,
        ),
        (
            &format!(
                "SELECT count(*) FROM v2_sessions WHERE revoked_at_ms IS NULL AND device_id = X'{}'",
                hex(&dev.id)
            ),
            // Only the fresh session opened after the revocation: the
            // expired one was ended with the live one.
            1,
        ),
        (
            "SELECT count(*) FROM v2_audit_events WHERE action = 'root.grant_revoke'",
            1,
        ),
        (
            "SELECT count(*) FROM v2_idempotency WHERE operation_kind = 'ROOT_GRANT_REVOKE'",
            1,
        ),
    ] {
        assert_eq!(server.count(query).await, want, "{query}");
    }
}

// ------------------------------------------------------- ROOT_GRANT_CREATE ---

fn root_grants_path() -> String {
    format!("/v2/tenants/{}/root-key-generations/0/grants", hex(&TENANT))
}

/// An `ExistingRootGrant` of `TRK` from `issuer` to `subject`, linked to the
/// subject's approval `approval` and sealed to its HPKE key.
fn existing_root_grant(issuer: &Device, subject: &Device, approval: u8, replay: u8) -> Vec<u8> {
    let start = now_ms() - 60_000;
    let mut g = TenantRootKeyGrantV2 {
        common: CommonFields {
            replay_id: [replay; 16],
            tenant_id: TENANT,
            issued_at_ms: start,
            not_before_ms: start,
            not_after_ms: start + 30 * DAY_MS,
            server_instance_id: INSTANCE,
            restore_epoch: 0,
        },
        variant: RootGrantVariant::ExistingRootGrant,
        root_key_id: shared::keys::root_key_id(&TRK),
        root_generation: 0,
        subject_account_id: OWNER,
        subject_device_id: subject.id,
        subject_signing_key_id: subject.signing_key_id,
        recipient_hpke_key_id: subject.hpke_key_id,
        subject_device_approval_replay_id: [approval; 16],
        hpke_encapped_key_bytes: [0; 32],
        hpke_wrapped_trk_bytes: [0; 48],
    };
    let sealed = shared::grants::seal_trk(&subject.hpke_pk, &g.scope(), &TRK).unwrap();
    g.hpke_encapped_key_bytes = sealed.encapped_key_bytes.try_into().unwrap();
    g.hpke_wrapped_trk_bytes = sealed.ciphertext_bytes.try_into().unwrap();
    build_record(&issuer.sk, DOMAIN_TENANT_ROOT_KEY_GRANT, &g.encode())
}

/// The `ROOT_GRANT_CREATE` request filing `container`, signed by `signer`.
fn root_grant_create_request(key: u8, signer: &Device, container: &[u8]) -> Vec<u8> {
    lifecycle_request(
        OperationKind::RootGrantCreate,
        key,
        shared::mutation::TenantRootGrantCreateV2 {
            grant: grant_ref(signer, container),
            exact_signed_grant_container_bytes: container.to_vec(),
        }
        .encode(),
    )
}

#[tokio::test]
async fn a_custodian_files_an_existing_root_grant_only_to_a_tenant_approved_device() {
    use shared::mutation::TenantRootGrantCreatedV2;

    let mut server = start("root-existing", 28215).await;
    let (dev, access, _) = custodian(&mut server, 0x6f).await;
    let path = root_grants_path();
    let peer = device(&server, OWNER, 0x7b, "active").await;
    approve_by_copy(&server, &dev, &peer, 0x7b).await;

    let existing = existing_root_grant(&dev, &peer, 0x7b, 0x91);
    let request = root_grant_create_request(0xc0, &dev, &existing);
    let (status, body) = server.call(&path, &access, Some(&request)).await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    let stored = IdempotentStoredResponseV2::parse(&body).unwrap();
    let created =
        TenantRootGrantCreatedV2::parse(&stored.canonical_response_payload_bytes).unwrap();
    assert_eq!(
        (
            created.grant,
            created.grant_variant,
            created.subject_device_id
        ),
        (grant_ref(&dev, &existing), "ExistingRootGrant", peer.id)
    );
    // The same bytes get the same answer; the replay ID is then spent.
    assert_eq!(
        server.call(&path, &access, Some(&request)).await,
        (201, body)
    );
    let again = root_grant_create_request(0xc1, &dev, &existing);
    let (status, body) = server.call(&path, &access, Some(&again)).await;
    assert_eq!((status, code_of(&body).as_str()), (409, "REPLAY_DETECTED"));

    // Q-22: a fleet-scoped approval never carries root custody.
    let fleet_only = device(&server, OWNER, 0x7a, "active").await;
    approve_by_copy_in(&server, &dev, &fleet_only, 0x7a, "'fleet'").await;
    let grant = existing_root_grant(&dev, &fleet_only, 0x7a, 0x92);
    let request = root_grant_create_request(0xc2, &dev, &grant);
    let (status, body) = server.call(&path, &access, Some(&request)).await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (409, "SUBJECT_NOT_ELIGIBLE")
    );
    // A device without any approval, likewise.
    let unapproved = device(&server, OWNER, 0x79, "active").await;
    let grant = existing_root_grant(&dev, &unapproved, 0x79, 0x93);
    let request = root_grant_create_request(0xc3, &dev, &grant);
    let (status, body) = server.call(&path, &access, Some(&request)).await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (409, "SUBJECT_NOT_ELIGIBLE")
    );
    // A grant signed by another key than the session's.
    let forged = existing_root_grant(&peer, &peer, 0x7b, 0x94);
    let request = root_grant_create_request(0xc4, &peer, &forged);
    let (status, body) = server.call(&path, &access, Some(&request)).await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (422, "KEY_SUBSTITUTION_DETECTED")
    );
    // A device that is no custodian files nothing.
    let stranger = device(&server, OWNER, 0x78, "pending").await;
    let stranger_access = session(&server, &stranger).await["access_token"]
        .as_str()
        .unwrap()
        .to_string();
    let grant = existing_root_grant(&dev, &peer, 0x7b, 0x95);
    let request = root_grant_create_request(0xc5, &dev, &grant);
    assert_eq!(
        server.call(&path, &stranger_access, Some(&request)).await.0,
        403
    );

    for (query, want) in [
        (
            "SELECT count(*) FROM v2_tenant_root_key_grants
              WHERE grant_variant = 'ExistingRootGrant' AND acked_at IS NULL",
            1,
        ),
        (
            "SELECT count(*) FROM v2_audit_events WHERE action = 'root.grant_create'",
            1,
        ),
    ] {
        assert_eq!(server.count(query).await, want, "{query}");
    }
}

#[tokio::test]
async fn a_device_reads_back_only_its_own_fleet_grant_as_an_exact_descriptor() {
    use shared::authz_record::{DeviceHpkeGrantV2, DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE};
    use shared::fleet_lifecycle::{
        FleetGenerationRef, FleetGenerationTerms, FleetGrantVariant as V,
        FleetKeyGenerationCreateV2, FleetKeyGrantAckV2,
    };
    use shared::mutation::{
        fleet_device_grant_set_hash, FleetDeviceGrantDescriptorV2, RootGenerationState,
        RootGrantState,
    };

    let mut server = start("d9-fleet-read", 28216).await;
    let (dev, access, _) = custodian(&mut server, 0x6c).await;
    server
        .sql(
            "INSERT INTO v2_fleets (id, tenant_id, name, status, created_at)
             VALUES (?, ?, 'f', 'active', 'now')",
            &[&FLEET, &TENANT],
        )
        .await;
    let grant = capability_grant(&dev, &dev.sk, |g| {
        g.common.replay_id = [0xa7; 16];
        g.capability = Capability::FleetManage;
    });
    assert_eq!(server.call(GRANTS, &access, Some(&grant)).await.0, 201);
    let fkek = [0xe0; 32];
    let device_grant = DeviceHpkeGrantV2 {
        common: fleet_common(0xd0, 365),
        fleet_id: FLEET,
        fkek_key_id: fkek,
        generation: 0,
        subject_account_id: OWNER,
        subject_device_id: dev.id,
        subject_signing_key_id: dev.signing_key_id,
        recipient_hpke_key_id: dev.hpke_key_id,
        hpke_encapped_key_bytes: vec![3; 32],
        hpke_wrapped_fleet_key_bytes: vec![4; 48],
    };
    let container = build_record(
        &dev.sk,
        DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE,
        &device_grant.encode(),
    );
    let terms = FleetGenerationTerms {
        generation: FleetGenerationRef {
            tenant_id: TENANT,
            server_instance_id: INSTANCE,
            restore_epoch: 0,
            fleet_id: FLEET,
            generation: 0,
            fkek_key_id: fkek,
        },
        required_device_grant_count: 1,
        required_device_grant_set_hash: fleet_device_grant_set_hash(&[container_hash(&container)])
            .unwrap(),
        recovery_grant_signed_container_hash: [0x77; 32],
        rotation: None,
    };
    let create = FleetKeyGenerationCreateV2 {
        terms,
        root_generation: 0,
    };
    let request = lifecycle_request(OperationKind::FleetGenerationCreate, 0xb0, create.encode());
    assert_eq!(
        server
            .call(&fleet_generation_path(), &access, Some(&request))
            .await
            .0,
        201
    );
    let read_path = |generation: u64, device: &[u8; 16]| {
        format!("{}/{}", fleet_grants_path(generation), hex(device))
    };
    let path = read_path(0, &dev.id);
    let issuer = *dev.sk.verifying_key().as_bytes();
    let read = |status: u16, body: Vec<u8>| {
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
        let d = FleetDeviceGrantDescriptorV2::parse(&body, &issuer).unwrap();
        assert_eq!(
            d.record().record().exact_signed_container_bytes(),
            &container[..]
        );
        (d.grant_state(), d.generation_state())
    };

    // Nothing filed yet.
    assert_eq!(server.call(&path, &access, None).await.0, 404);
    let request = fleet_grant_request(0xb1, 0, fkek, V::DeviceHpke, 0xd0, &container);
    assert_eq!(
        server
            .call(&fleet_grants_path(0), &access, Some(&request))
            .await
            .0,
        201
    );
    let (status, body) = server.call(&path, &access, None).await;
    assert_eq!(
        read(status, body),
        (RootGrantState::PendingAck, RootGenerationState::Preparing)
    );
    let ack = lifecycle_request(
        OperationKind::FleetGrantAck,
        0xb2,
        FleetKeyGrantAckV2 {
            grant: fleet_grant_ref(0, fkek, V::DeviceHpke, 0xd0, &container),
        }
        .encode(),
    );
    let ack_path = format!("{}/0/ack", fleet_generation_path());
    assert_eq!(server.call(&ack_path, &access, Some(&ack)).await.0, 201);
    let (status, body) = server.call(&path, &access, None).await;
    assert_eq!(
        read(status, body),
        (RootGrantState::Acknowledged, RootGenerationState::Preparing)
    );

    // Another device's grant, and another generation, do not exist for it.
    let other = device(&server, OWNER, 0x7b, "pending").await;
    let other_access = session(&server, &other).await["access_token"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(server.call(&path, &other_access, None).await.0, 404);
    assert_eq!(
        server.call(&read_path(1, &dev.id), &access, None).await.0,
        404
    );
    assert_eq!(
        server.call(&read_path(0, &other.id), &access, None).await.0,
        404
    );

    // A row that left its container is never served.
    server
        .sql(
            "DROP TRIGGER v2_fleet_device_hpke_grants_record_is_fixed",
            &[],
        )
        .await;
    server
        .sql(
            "UPDATE v2_fleet_device_hpke_grants SET not_after_ms = not_after_ms - 1",
            &[],
        )
        .await;
    assert_eq!(server.call(&path, &access, None).await.0, 422);
}

/// The device that created a generation files its own first grant of it
/// before holding it (D-2); nobody else does, and a revoked one is not
/// replaced that way.
#[tokio::test]
async fn only_the_creator_files_its_own_grant_before_holding_the_generation() {
    use shared::authz_record::{DeviceHpkeGrantV2, DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE};
    use shared::fleet_lifecycle::{
        FleetGenerationRef, FleetGenerationTerms, FleetGrantVariant as V,
        FleetKeyGenerationCreateV2,
    };
    use shared::mutation::fleet_device_grant_set_hash;

    let mut server = start("d9-fleet-own", 28217).await;
    let (dev, access, _) = custodian(&mut server, 0x6c).await;
    server
        .sql(
            "INSERT INTO v2_fleets (id, tenant_id, name, status, created_at)
             VALUES (?, ?, 'f', 'active', 'now')",
            &[&FLEET, &TENANT],
        )
        .await;
    let grant = capability_grant(&dev, &dev.sk, |g| {
        g.common.replay_id = [0xa7; 16];
        g.capability = Capability::FleetManage;
    });
    assert_eq!(server.call(GRANTS, &access, Some(&grant)).await.0, 201);
    let fkek = [0xe0; 32];
    let own_grant = |replay: u8| {
        let g = DeviceHpkeGrantV2 {
            common: fleet_common(replay, 365),
            fleet_id: FLEET,
            fkek_key_id: fkek,
            generation: 0,
            subject_account_id: OWNER,
            subject_device_id: dev.id,
            subject_signing_key_id: dev.signing_key_id,
            recipient_hpke_key_id: dev.hpke_key_id,
            hpke_encapped_key_bytes: vec![3; 32],
            hpke_wrapped_fleet_key_bytes: vec![4; 48],
        };
        build_record(&dev.sk, DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE, &g.encode())
    };
    let (first, second) = (own_grant(0xd0), own_grant(0xd1));
    let create = FleetKeyGenerationCreateV2 {
        terms: FleetGenerationTerms {
            generation: FleetGenerationRef {
                tenant_id: TENANT,
                server_instance_id: INSTANCE,
                restore_epoch: 0,
                fleet_id: FLEET,
                generation: 0,
                fkek_key_id: fkek,
            },
            required_device_grant_count: 1,
            required_device_grant_set_hash: fleet_device_grant_set_hash(&[container_hash(&first)])
                .unwrap(),
            recovery_grant_signed_container_hash: [0x77; 32],
            rotation: None,
        },
        root_generation: 0,
    };
    let request = lifecycle_request(OperationKind::FleetGenerationCreate, 0xb0, create.encode());
    assert_eq!(
        server
            .call(&fleet_generation_path(), &access, Some(&request))
            .await
            .0,
        201
    );
    let grants = fleet_grants_path(0);
    let file = |key: u8, replay: u8, container: &[u8]| {
        fleet_grant_request(key, 0, fkek, V::DeviceHpke, replay, container)
    };
    let creator = |device: &[u8; 16]| {
        format!(
            "UPDATE v2_audit_events SET actor_device_id = X'{}'
              WHERE action = 'fleet.key_generation.create'",
            hex(device)
        )
    };

    // Another fleet.manage holder that did not create the generation.
    server.sql(&creator(&[0x55; 16]), &[]).await;
    assert_eq!(
        server
            .call(&grants, &access, Some(&file(0xb1, 0xd0, &first)))
            .await
            .0,
        403
    );
    server.sql(&creator(&dev.id), &[]).await;
    let (status, body) = server
        .call(&grants, &access, Some(&file(0xb2, 0xd0, &first)))
        .await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));

    // A second one is refused, before and after the first is revoked.
    assert_eq!(
        server
            .call(&grants, &access, Some(&file(0xb3, 0xd1, &second)))
            .await
            .0,
        403
    );
    server
        .sql(
            "UPDATE v2_fleet_device_hpke_grants SET revoked_at = 'now'",
            &[],
        )
        .await;
    assert_eq!(
        server
            .call(&grants, &access, Some(&file(0xb4, 0xd1, &second)))
            .await
            .0,
        403
    );
}

// ----------------------------------------------------------- DEVICE_REVOKE ---

fn revocation(issuer: &Ed25519SigningKey, subject: &Device, replay: u8, days: u64) -> Vec<u8> {
    revocation_issued(issuer, subject, replay, days, 60_000)
}

/// A revocation issued `ago` ms before now, its window opening then.
fn revocation_issued(
    issuer: &Ed25519SigningKey,
    subject: &Device,
    replay: u8,
    days: u64,
    ago: u64,
) -> Vec<u8> {
    use shared::authz_record::{
        DeviceRevocationReason, DeviceRevocationV2, DOMAIN_DEVICE_REVOCATION,
    };
    let start = now_ms() - ago;
    let r = DeviceRevocationV2 {
        common: CommonFields {
            replay_id: [replay; 16],
            tenant_id: TENANT,
            issued_at_ms: start,
            not_before_ms: start,
            not_after_ms: start + days * DAY_MS,
            server_instance_id: INSTANCE,
            restore_epoch: 0,
        },
        subject_account_id: OWNER,
        subject_device_id: subject.id,
        subject_signing_key_id: subject.signing_key_id,
        subject_hpke_key_id: subject.hpke_key_id,
        reason_code: DeviceRevocationReason::Compromised,
    };
    build_record(issuer, DOMAIN_DEVICE_REVOCATION, &r.encode())
}

fn revoke_request(key: u8, container: &[u8]) -> Vec<u8> {
    let request = shared::mutation::DeviceRevokeRequestV2 {
        signed_container_hash: container_hash(container),
        exact_signed_revocation_container_bytes: container.to_vec(),
    };
    lifecycle_request(OperationKind::DeviceRevoke, key, request.encode())
}

fn device_revoke_path(device: &[u8; 16]) -> String {
    format!("/v2/devices/{}/revoke", hex(device))
}

/// Q-13: a custodian holding `device.revoke` files a signed revocation; the
/// device's sessions end, its approvals and grants are revoked, and it can
/// never open a session again.
#[tokio::test]
async fn a_revoked_device_cannot_sign_in_again() {
    use shared::mutation::DeviceRevokedV2;

    let mut server = start("q13-revoke", 28218).await;
    let (dev, access, _) = custodian(&mut server, 0x6c).await;
    // A pending device can open a session; an approved one is revoked too.
    let pending = device(&server, OWNER, 0x7b, "pending").await;
    let pending_access = session(&server, &pending).await["access_token"]
        .as_str()
        .unwrap()
        .to_string();
    let approved = device(&server, OWNER, 0x7d, "active").await;
    approve_by_copy(&server, &dev, &approved, 0x7d).await;
    let path = device_revoke_path(&pending.id);
    let good = revocation(&dev.sk, &pending, 0x90, 30);

    // Without `device.revoke` nothing is revoked (Q-13 issuer rule).
    assert_eq!(
        server
            .call(&path, &access, Some(&revoke_request(0xa0, &good)))
            .await
            .0,
        403
    );
    // A fleet-scoped one covers only devices approved for that fleet alone.
    server
        .sql(
            "INSERT INTO v2_fleets (id, tenant_id, name, status, created_at)
             VALUES (?, ?, 'f', 'active', 'now')",
            &[&FLEET, &TENANT],
        )
        .await;
    let fleet_duty = capability_grant(&dev, &dev.sk, |g| {
        g.common.replay_id = [0xa7; 16];
        g.scope_kind = CapabilityScopeKind::Fleet;
        g.scope_id = FLEET;
        g.capability = Capability::DeviceRevoke;
    });
    assert_eq!(server.call(GRANTS, &access, Some(&fleet_duty)).await.0, 201);
    let approved_revoke = revocation(&dev.sk, &approved, 0x96, 30);
    for (p, request) in [
        (&path, revoke_request(0xa0, &good)),
        (
            &device_revoke_path(&approved.id),
            revoke_request(0xaf, &approved_revoke),
        ),
    ] {
        assert_eq!(server.call(p, &access, Some(&request)).await.0, 403);
    }
    let duty = capability_grant(&dev, &dev.sk, |g| {
        g.common.replay_id = [0xa8; 16];
        g.capability = Capability::DeviceRevoke;
    });
    assert_eq!(server.call(GRANTS, &access, Some(&duty)).await.0, 201);

    // Another key's signature, a window past 30 days, another device on the
    // path, and other keys for the device are refused.
    let stranger = Ed25519SigningKey::from_bytes(&[0x99; 32]);
    let forged = revocation(&stranger, &pending, 0x91, 30);
    let (status, body) = server
        .call(&path, &access, Some(&revoke_request(0xa1, &forged)))
        .await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (422, "KEY_SUBSTITUTION_DETECTED")
    );
    let long = revocation(&dev.sk, &pending, 0x92, 31);
    assert_eq!(
        server
            .call(&path, &access, Some(&revoke_request(0xa2, &long)))
            .await
            .0,
        403
    );
    // Issued long before it is filed: no client could tell custody held then.
    let stale_issue = revocation_issued(&dev.sk, &pending, 0x97, 30, 400_000);
    assert_eq!(
        server
            .call(&path, &access, Some(&revoke_request(0xab, &stale_issue)))
            .await
            .0,
        403
    );
    let other_path = device_revoke_path(&approved.id);
    assert_eq!(
        server
            .call(&other_path, &access, Some(&revoke_request(0xa3, &good)))
            .await
            .0,
        422
    );
    let mut rekeyed = device(&server, OWNER, 0x7e, "pending").await;
    rekeyed.id = pending.id;
    let wrong_keys = revocation(&dev.sk, &rekeyed, 0x93, 30);
    assert_eq!(
        server
            .call(&path, &access, Some(&revoke_request(0xa4, &wrong_keys)))
            .await
            .0,
        422
    );
    // A record naming this device with another device's keys, filed on that
    // device's path, would revoke one device and store the other.
    let mut swapped = device(&server, OWNER, 0x7f, "pending").await;
    swapped.id = pending.id;
    swapped.signing_key_id = approved.signing_key_id;
    swapped.hpke_key_id = approved.hpke_key_id;
    let swapped = revocation(&dev.sk, &swapped, 0x98, 30);
    assert_eq!(
        server
            .call(&other_path, &access, Some(&revoke_request(0xac, &swapped)))
            .await
            .0,
        422
    );
    // The last custodian cannot revoke itself (C-1: someone must rotate).
    let own = revocation(&dev.sk, &dev, 0x94, 30);
    let (status, body) = server
        .call(
            &device_revoke_path(&dev.id),
            &access,
            Some(&revoke_request(0xa5, &own)),
        )
        .await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (409, "LAST_ROOT_CUSTODIAN")
    );

    let request = revoke_request(0xa6, &good);
    let (status, body) = server.call(&path, &access, Some(&request)).await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    let stored = IdempotentStoredResponseV2::parse(&body).unwrap();
    let revoked = DeviceRevokedV2::parse(&stored.canonical_response_payload_bytes).unwrap();
    assert_eq!(
        (revoked.subject_device_id, revoked.replay_id),
        (pending.id, [0x90; 16])
    );
    assert_eq!(revoked.sessions_invalidated_count, 1);
    assert_eq!(
        server.call(&path, &access, Some(&request)).await,
        (201, body)
    );

    // The device's session is gone and it cannot open another.
    assert_eq!(
        server.call(&path, &pending_access, Some(&request)).await.0,
        401
    );
    let ticket = server.login("owner").await;
    assert_eq!(challenge(&server, &ticket, &pending).await.0, 409);
    // A spent replay ID is refused; a fresh revocation is filed again.
    let (status, body) = server
        .call(&path, &access, Some(&revoke_request(0xa7, &good)))
        .await;
    assert_eq!((status, code_of(&body).as_str()), (409, "REPLAY_DETECTED"));
    let again = revocation(&dev.sk, &pending, 0x95, 30);
    assert_eq!(
        server
            .call(&path, &access, Some(&revoke_request(0xa8, &again)))
            .await
            .0,
        201
    );

    // The approved device loses its approval and its grants with it.
    let root_grant = existing_root_grant(&dev, &approved, 0x7d, 0xc7);
    assert_eq!(
        server
            .call(
                &root_grants_path(),
                &access,
                Some(&root_grant_create_request(0xc8, &dev, &root_grant))
            )
            .await
            .0,
        201
    );
    let approve_duty = capability_grant(&approved, &dev.sk, |g| {
        g.common.replay_id = [0xaa; 16];
    });
    let (status, body) = server.call(GRANTS, &access, Some(&approve_duty)).await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    assert_eq!(
        server
            .call(
                &other_path,
                &access,
                Some(&revoke_request(0xa9, &approved_revoke))
            )
            .await
            .0,
        201
    );
    for (query, want) in [
        (
            format!(
                "SELECT count(*) FROM v2_devices WHERE status = 'revoked' AND id IN (X'{}', X'{}')",
                hex(&pending.id),
                hex(&approved.id)
            ),
            2,
        ),
        (
            format!(
                "SELECT count(*) FROM v2_device_approvals
                  WHERE subject_device_id = X'{}' AND revoked_at IS NULL",
                hex(&approved.id)
            ),
            0,
        ),
        (
            format!(
                "SELECT count(*) FROM v2_tenant_root_key_grants
                  WHERE subject_device_id = X'{}' AND revoked_at IS NULL",
                hex(&approved.id)
            ),
            0,
        ),
        (
            format!(
                "SELECT count(*) FROM v2_capability_grants
                  WHERE subject_device_id = X'{}' AND revoked_at IS NULL",
                hex(&approved.id)
            ),
            0,
        ),
        (
            format!(
                "SELECT count(*) FROM v2_sessions
                  WHERE device_id IN (X'{}', X'{}') AND revoked_at_ms IS NULL",
                hex(&pending.id),
                hex(&approved.id)
            ),
            0,
        ),
        ("SELECT count(*) FROM v2_device_revocations".to_string(), 3),
        (
            "SELECT count(*) FROM v2_audit_events WHERE action = 'device.revoke'".to_string(),
            3,
        ),
    ] {
        assert_eq!(server.count(&query).await, want, "{query}");
    }

    // The trust evidence serves every filed revocation, and reports each
    // revoked device once per page at its first filing.
    let pages = evidence(&server, &access, &[]).await;
    let served = containers(&pages);
    for filed in [&good, &again, &approved_revoke] {
        assert!(served.contains(filed));
    }
    let mut reported: Vec<[u8; 16]> = pages
        .iter()
        .flat_map(|p| p.device_revocations.iter().map(|d| d.device_id))
        .collect();
    reported.sort();
    assert_eq!(reported, vec![pending.id, approved.id]);
    assert!(pages
        .iter()
        .flat_map(|p| &p.signing_public_keys)
        .any(|k| *k == dev.sk.verifying_key().to_bytes()));

    // Without root custody the same issuer cannot revoke, even with its grant.
    server
        .sql(
            "UPDATE v2_tenant_root_key_grants SET revoked_at = 'now' WHERE subject_device_id = ?",
            &[&dev.id],
        )
        .await;
    let bystander = device(&server, OWNER, 0x7c, "pending").await;
    let late = revocation(&dev.sk, &bystander, 0x9a, 30);
    assert_eq!(
        server
            .call(
                &device_revoke_path(&bystander.id),
                &access,
                Some(&revoke_request(0xae, &late))
            )
            .await
            .0,
        403
    );

    // A revoked device never becomes usable again, and its revocation stays.
    let pool = db(&server.data).await;
    for statement in [
        format!(
            "UPDATE v2_devices SET status = 'active' WHERE id = X'{}'",
            hex(&pending.id)
        ),
        "DELETE FROM v2_device_revocations".to_string(),
        "UPDATE v2_device_revocations SET reason_code = 'lost'".to_string(),
        // REPLACE writes a fresh active row past the status trigger.
        format!(
            "INSERT OR REPLACE INTO v2_devices
             SELECT id, tenant_id, account_id, label_ciphertext, signing_key_id,
                    signing_public_key, signing_suite, hpke_key_id, hpke_public_key,
                    hpke_suite, 'active', last_seen_at, created_at
               FROM v2_devices WHERE id = X'{}'",
            hex(&pending.id)
        ),
    ] {
        assert!(
            sqlx::query(&statement).execute(&pool).await.is_err(),
            "{statement}"
        );
    }
    pool.close().await;
}

// ------------------------------------------------------ ordinary approvals ---

/// ADR 0002 D-2: after D1, a custodian holding `device.approve` approves a
/// second device, which then opens an `ordinary` session.
#[tokio::test]
async fn a_custodian_approves_a_second_device_into_an_ordinary_session() {
    let mut server = start("g201-approve", 28219).await;
    let (dev, access, _) = custodian(&mut server, 0x6d).await;
    let joiner = device(&server, OWNER, 0x5b, "pending").await;
    let setup = session(&server, &joiner).await;
    assert_eq!(setup["class"], "pending_setup");
    let setup_access = setup["access_token"].as_str().unwrap().to_string();
    let rec = approval(&joiner, &dev.sk, 0x5c, 0, 30);

    // Without `device.approve` nothing is approved.
    assert_eq!(server.approve(&joiner.id, &access, &rec).await.0, 403);
    // A fleet-scoped grant covers that fleet's approvals, not the tenant's.
    server
        .sql(
            "INSERT INTO v2_fleets (id, tenant_id, name, status, created_at)
             VALUES (?, ?, 'f', 'active', 'now')",
            &[&FLEET, &TENANT],
        )
        .await;
    let fleet_duty = capability_grant(&dev, &dev.sk, |g| {
        g.common.replay_id = [0xc1; 16];
        g.scope_kind = CapabilityScopeKind::Fleet;
        g.scope_id = FLEET;
    });
    assert_eq!(server.call(GRANTS, &access, Some(&fleet_duty)).await.0, 201);
    assert_eq!(server.approve(&joiner.id, &access, &rec).await.0, 403);
    let duty = capability_grant(&dev, &dev.sk, |g| {
        g.common.replay_id = [0xc2; 16];
    });
    assert_eq!(server.call(GRANTS, &access, Some(&duty)).await.0, 201);

    // Another key's signature, a pending session as the issuer, and a
    // window past the limit are refused.
    let forged = approval(&joiner, &joiner.sk, 0x5d, 0, 30);
    let (status, _, body) = server.approve(&joiner.id, &access, &forged).await;
    assert_eq!(
        (status, code(&body).as_str()),
        (422, "KEY_SUBSTITUTION_DETECTED")
    );
    assert_eq!(
        server.approve(&joiner.id, &setup_access, &forged).await.0,
        403
    );
    let long = approval(&joiner, &dev.sk, 0x5e, 0, 731);
    assert_eq!(server.approve(&joiner.id, &access, &long).await.0, 403);

    let (status, ct, receipt) = server.approve(&joiner.id, &access, &rec).await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&receipt));
    assert_eq!(ct, "application/cbor");
    let parsed = DeviceApprovalReceiptV2::parse(&receipt).unwrap();
    assert_eq!(
        (
            parsed.subject_device_id,
            parsed.actor_device_id,
            parsed.confirmation_id
        ),
        (joiner.id, dev.id, None)
    );
    // A retry gets the stored receipt; another actor's is a conflict.
    let (status, _, again) = server.approve(&joiner.id, &access, &rec).await;
    assert_eq!((status, &again), (201, &receipt));
    let (status, _, body) = server.approve(&joiner.id, &setup_access, &rec).await;
    assert_ne!(status, 201, "{}", String::from_utf8_lossy(&body));

    // The joiner's setup session ends with the status change; a new one is
    // ordinary, and approving it twice is refused.
    assert_eq!(server.me(&setup_access).await.0, 401);
    let ordinary = session(&server, &joiner).await;
    assert_eq!(ordinary["class"], "ordinary");
    let ordinary_access = ordinary["access_token"].as_str().unwrap().to_string();
    assert_eq!(server.me(&ordinary_access).await.0, 200);
    let twice = approval(&joiner, &dev.sk, 0x5f, 0, 30);
    assert_eq!(server.approve(&joiner.id, &access, &twice).await.0, 403);
    // The joiner is no custodian, so it cannot renew its own approval.
    let renewal = approval(&joiner, &joiner.sk, 0x60, 0, 30);
    assert_eq!(
        server
            .approve(&joiner.id, &ordinary_access, &renewal)
            .await
            .0,
        403
    );
    // A retry after the actor lost `device.approve` is refused.
    server
        .sql(
            "UPDATE v2_capability_grants SET revoked_at = 'now' WHERE replay_id = ?",
            &[&[0xc2; 16]],
        )
        .await;
    assert_eq!(server.approve(&joiner.id, &access, &rec).await.0, 403);

    // Revoking the approval ends the ordinary session at once.
    server
        .sql(
            "UPDATE v2_device_approvals SET revoked_at = 'now' WHERE subject_device_id = ?",
            &[&joiner.id],
        )
        .await;
    assert_eq!(server.me(&ordinary_access).await.0, 401);
    assert_eq!(
        server
            .count("SELECT count(*) FROM v2_audit_events WHERE action = 'device.approve'")
            .await,
        2
    );
}

/// A root grant of `trk` as `generation`, of `variant`, from `issuer` to
/// `subject`, linked to the subject's approval `approval` and sealed to its
/// HPKE key.
fn root_grant_of(
    issuer: &Device,
    subject: &Device,
    approval: u8,
    replay: u8,
    trk: &[u8; 32],
    generation: u64,
    variant: RootGrantVariant,
) -> Vec<u8> {
    let start = now_ms() - 60_000;
    let mut g = TenantRootKeyGrantV2 {
        common: CommonFields {
            replay_id: [replay; 16],
            tenant_id: TENANT,
            issued_at_ms: start,
            not_before_ms: start,
            not_after_ms: start + 30 * DAY_MS,
            server_instance_id: INSTANCE,
            restore_epoch: 0,
        },
        variant,
        root_key_id: shared::keys::root_key_id(trk),
        root_generation: generation,
        subject_account_id: OWNER,
        subject_device_id: subject.id,
        subject_signing_key_id: subject.signing_key_id,
        recipient_hpke_key_id: subject.hpke_key_id,
        subject_device_approval_replay_id: [approval; 16],
        hpke_encapped_key_bytes: [0; 32],
        hpke_wrapped_trk_bytes: [0; 48],
    };
    let sealed = shared::grants::seal_trk(&subject.hpke_pk, &g.scope(), trk).unwrap();
    g.hpke_encapped_key_bytes = sealed.encapped_key_bytes.try_into().unwrap();
    g.hpke_wrapped_trk_bytes = sealed.ciphertext_bytes.try_into().unwrap();
    build_record(&issuer.sk, DOMAIN_TENANT_ROOT_KEY_GRANT, &g.encode())
}

/// The terms of generation `generation` of `trk`, held by `members`.
fn rotation_target(trk: &[u8; 32], generation: u64, members: &[&[u8]]) -> RootGenerationTarget {
    let hashes: Vec<[u8; 32]> = members.iter().map(|m| container_hash(m)).collect();
    RootGenerationTarget {
        tenant_id: TENANT,
        server_instance_id: INSTANCE,
        restore_epoch: 0,
        root_key_id: shared::keys::root_key_id(trk),
        root_generation: generation,
        required_custodian_grant_count: hashes.len() as u32,
        required_custodian_grant_set_hash: root_custodian_grant_set_hash(&hashes).unwrap(),
        recovery_bundle_sha256: [0x5b; 32],
    }
}

fn rotation_create(key: u8, target: RootGenerationTarget, previous: PreviousRoot) -> Vec<u8> {
    root_request(
        key,
        &TenantRootGenerationCreateV2 {
            target,
            mode: RootGenerationMode::Rotation {
                previous_root_key_id: previous.root_key_id,
                previous_root_generation: previous.root_generation,
            },
        },
    )
}

fn rotation_activate(key: u8, target: RootGenerationTarget, previous: PreviousRoot) -> Vec<u8> {
    lifecycle_request(
        OperationKind::RootGenerationActivate,
        key,
        TenantRootGenerationActivateV2 {
            target,
            previous: Some(previous),
        }
        .encode(),
    )
}

#[tokio::test]
async fn a_custodian_rotates_the_root_to_a_new_custodian_set() {
    let mut server = start("root-rotate", 28220).await;
    let (a, access, _) = custodian(&mut server, 0x6e).await;
    let grants_path = |generation: u64| {
        format!(
            "/v2/tenants/{}/root-key-generations/{generation}/grants",
            hex(&TENANT)
        )
    };
    let ack_path =
        |generation: &str, replay: u8| format!("{}/ack", grant_path(generation, &[replay; 16]));
    let key_rotate = |replay: u8| {
        capability_grant(&a, &a.sk, |g| {
            g.common.replay_id = [replay; 16];
            g.capability = Capability::KeyRotate;
        })
    };

    // Only the bootstrap files a FirstRootSelfGrant.
    let second_self = self_grant(&a, &TRK, |g| g.common.replay_id = [0xea; 16]);
    let request = root_grant_create_request(0xcf, &a, &second_self);
    let (status, body) = server.call(&grants_path(0), &access, Some(&request)).await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (422, "AUTH_CLAIM_COLUMN_MISMATCH")
    );

    // B joins through A's `device.approve`, at tenant scope.
    let duty = capability_grant(&a, &a.sk, |g| g.common.replay_id = [0xc2; 16]);
    assert_eq!(server.call(GRANTS, &access, Some(&duty)).await.0, 201);
    let b = device(&server, OWNER, 0x5b, "pending").await;
    session(&server, &b).await;
    let rec = approval(&b, &a.sk, 0x5c, 0, 30);
    assert_eq!(server.approve(&b.id, &access, &rec).await.0, 201);
    let b_access = session(&server, &b).await["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    let k0 = shared::keys::root_key_id(&TRK);
    let gen0 = PreviousRoot {
        root_key_id: k0,
        root_generation: 0,
    };
    let after0 = RootGrantVariant::RotationGrant {
        previous_root_key_id: k0,
        previous_root_generation: 0,
    };
    let trk1 = [0x7d; 32];
    let grant_a = root_grant_of(&a, &a, APPROVAL_REPLAY, 0xe1, &trk1, 1, after0);
    let grant_b = root_grant_of(&a, &b, 0x5c, 0xe2, &trk1, 1, after0);
    let target = rotation_target(&trk1, 1, &[grant_a.as_slice(), grant_b.as_slice()]);
    let create = rotation_create(0xd1, target.clone(), gen0);

    // A custodian without `key.rotate` rotates nothing.
    assert_eq!(server.root(&TENANT, &access, &create).await.0, 403);
    assert_eq!(
        server
            .call(GRANTS, &access, Some(&key_rotate(0xc3)))
            .await
            .0,
        201
    );
    // A rotation follows exactly the ACTIVE root.
    let wrong_previous = PreviousRoot {
        root_key_id: [0x33; 32],
        root_generation: 0,
    };
    let wrong = rotation_create(0xd2, target.clone(), wrong_previous);
    let (status, body) = server.root(&TENANT, &access, &wrong).await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (409, "ROOT_GENERATION_MISMATCH")
    );

    let (status, created) = server.root(&TENANT, &access, &create).await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&created));
    let stored = IdempotentStoredResponseV2::parse(&created).unwrap();
    let parsed =
        TenantRootGenerationCreatedV2::parse(&stored.canonical_response_payload_bytes).unwrap();
    assert_eq!(
        (parsed.target, parsed.mode),
        (
            target.clone(),
            RootGenerationMode::Rotation {
                previous_root_key_id: k0,
                previous_root_generation: 0,
            }
        )
    );
    assert_eq!(server.root(&TENANT, &access, &create).await, (201, created));
    // One rotation is PREPARING at a time.
    let trk_other = [0x7e; 32];
    let other = rotation_create(
        0xd3,
        rotation_target(&trk_other, 1, &[grant_a.as_slice()]),
        gen0,
    );
    let (status, body) = server.root(&TENANT, &access, &other).await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (409, "ROOT_GENERATION_MISMATCH")
    );

    // Rotation grants come from a custodian of the ACTIVE root, name it
    // exactly and wrap the PREPARING key; an ExistingRootGrant cannot target
    // a PREPARING generation.
    let path1 = grants_path(1);
    let by_b = root_grant_of(&b, &b, 0x5c, 0xe3, &trk1, 1, after0);
    let request = root_grant_create_request(0xd4, &b, &by_b);
    assert_eq!(server.call(&path1, &b_access, Some(&request)).await.0, 403);
    let renamed = RootGrantVariant::RotationGrant {
        previous_root_key_id: [0x33; 32],
        previous_root_generation: 0,
    };
    let off = root_grant_of(&a, &b, 0x5c, 0xe4, &trk1, 1, renamed);
    let request = root_grant_create_request(0xd5, &a, &off);
    let (status, body) = server.call(&path1, &access, Some(&request)).await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (422, "AUTH_CLAIM_COLUMN_MISMATCH")
    );
    let other_key = root_grant_of(&a, &b, 0x5c, 0xe5, &trk_other, 1, after0);
    let request = root_grant_create_request(0xd6, &a, &other_key);
    let (status, body) = server.call(&path1, &access, Some(&request)).await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (422, "AUTH_CLAIM_COLUMN_MISMATCH")
    );
    let existing = root_grant_of(
        &a,
        &b,
        0x5c,
        0xe6,
        &trk1,
        1,
        RootGrantVariant::ExistingRootGrant,
    );
    let request = root_grant_create_request(0xd7, &a, &existing);
    assert_eq!(server.call(&path1, &access, Some(&request)).await.0, 403);
    for (key, grant) in [(0xd8, &grant_a), (0xd9, &grant_b)] {
        let request = root_grant_create_request(key, &a, grant);
        let (status, body) = server.call(&path1, &access, Some(&request)).await;
        assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    }

    // Each subject reads its own grant back and acknowledges it.
    let (status, body) = server
        .call(&grant_path("1", &[0xe2; 16]), &b_access, None)
        .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let read = TenantRootGrantDescriptorV2::parse(&body, a.sk.verifying_key().as_bytes()).unwrap();
    assert_eq!(
        (read.grant_state(), read.generation_state()),
        (RootGrantState::PendingAck, RootGenerationState::Preparing)
    );
    let ack_a = ack_request(0xda, grant_ref(&a, &grant_a));
    assert_eq!(
        server
            .call(&ack_path("1", 0xe1), &access, Some(&ack_a))
            .await
            .0,
        201
    );
    // Not before every required grant is acknowledged.
    let activate = rotation_activate(0xdb, target.clone(), gen0);
    let (status, body) = server
        .call(&activate_path("1"), &access, Some(&activate))
        .await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (409, "ROOT_GENERATION_MISMATCH")
    );
    let ack_b = ack_request(0xdc, grant_ref(&a, &grant_b));
    assert_eq!(
        server
            .call(&ack_path("1", 0xe2), &b_access, Some(&ack_b))
            .await
            .0,
        201
    );

    // B is no custodian yet; it neither activates nor issues.
    let b_activate = rotation_activate(0xdd, target.clone(), gen0);
    assert_eq!(
        server
            .call(&activate_path("1"), &b_access, Some(&b_activate))
            .await
            .0,
        403
    );
    let b_duty = capability_grant(&b, &b.sk, |g| g.common.replay_id = [0xc6; 16]);
    assert_eq!(server.call(GRANTS, &b_access, Some(&b_duty)).await.0, 403);
    // Other terms, another previous root, or no `key.rotate` are refused.
    let mut wrong_set = target.clone();
    wrong_set.required_custodian_grant_set_hash = [0x44; 32];
    let request = rotation_activate(0xde, wrong_set, gen0);
    let (status, body) = server
        .call(&activate_path("1"), &access, Some(&request))
        .await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (422, "AUTH_CLAIM_COLUMN_MISMATCH")
    );
    let request = rotation_activate(0xdf, target.clone(), wrong_previous);
    let (status, body) = server
        .call(&activate_path("1"), &access, Some(&request))
        .await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (409, "ROOT_GENERATION_MISMATCH")
    );
    server
        .sql(
            "UPDATE v2_capability_grants SET revoked_at = 'now' WHERE replay_id = ?",
            &[&[0xc3; 16]],
        )
        .await;
    assert_eq!(
        server
            .call(&activate_path("1"), &access, Some(&activate))
            .await
            .0,
        403
    );
    assert_eq!(
        server
            .call(GRANTS, &access, Some(&key_rotate(0xc4)))
            .await
            .0,
        201
    );

    let (status, activated) = server
        .call(&activate_path("1"), &access, Some(&activate))
        .await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&activated));
    let stored = IdempotentStoredResponseV2::parse(&activated).unwrap();
    let parsed =
        TenantRootGenerationActivatedV2::parse(&stored.canonical_response_payload_bytes).unwrap();
    assert_eq!(
        (parsed.target, parsed.previous),
        (target.clone(), Some(gen0))
    );
    assert_eq!(
        server
            .call(&activate_path("1"), &access, Some(&activate))
            .await,
        (201, activated)
    );
    for (query, want) in [
        (
            "SELECT count(*) FROM v2_root_key_generations
              WHERE generation = 0 AND state = 'RETIRED' AND retired_at IS NOT NULL",
            1,
        ),
        (
            "SELECT count(*) FROM v2_root_key_generations
              WHERE generation = 1 AND state = 'ACTIVE' AND activated_at IS NOT NULL",
            1,
        ),
        (
            "SELECT count(*) FROM v2_tenants WHERE active_root_generation = 1",
            1,
        ),
        (
            "SELECT count(*) FROM v2_audit_events WHERE action = 'root.rotate'",
            1,
        ),
        (
            "SELECT count(*) FROM v2_audit_events WHERE action = 'root.activate'",
            2,
        ),
    ] {
        assert_eq!(server.count(query).await, want, "{query}");
    }
    // B now holds custody of the ACTIVE root.
    assert_eq!(server.call(GRANTS, &b_access, Some(&b_duty)).await.0, 201);

    // A RotationGrant cannot target the now ACTIVE generation, and a new
    // generation cannot reuse a key an older one had.
    let late = root_grant_of(&a, &b, 0x5c, 0xe7, &trk1, 1, after0);
    let request = root_grant_create_request(0xe0, &a, &late);
    let (status, body) = server.call(&path1, &access, Some(&request)).await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (422, "AUTH_CLAIM_COLUMN_MISMATCH")
    );
    let k1 = shared::keys::root_key_id(&trk1);
    let gen1 = PreviousRoot {
        root_key_id: k1,
        root_generation: 1,
    };
    let after1 = RootGrantVariant::RotationGrant {
        previous_root_key_id: k1,
        previous_root_generation: 1,
    };
    let reused = root_grant_of(&a, &a, APPROVAL_REPLAY, 0xe8, &TRK, 2, after1);
    let request = rotation_create(0xe1, rotation_target(&TRK, 2, &[reused.as_slice()]), gen1);
    let (status, body) = server.root(&TENANT, &access, &request).await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (409, "ROOT_GENERATION_MISMATCH")
    );

    // D-5: a rotation is created while a fleet generation holds its key under
    // the ACTIVE root, but activates only once that key is rewrapped under
    // the new root.
    let trk2 = [0x7f; 32];
    let grant2 = root_grant_of(&a, &a, APPROVAL_REPLAY, 0xe9, &trk2, 2, after1);
    let target2 = rotation_target(&trk2, 2, &[grant2.as_slice()]);
    server
        .sql(
            "INSERT INTO v2_fleets (id, tenant_id, name, status, created_at)
             VALUES (?, ?, 'f', 'active', 'now')",
            &[&FLEET, &TENANT],
        )
        .await;
    server
        .sql(
            "INSERT INTO v2_fleet_key_generations
                 (server_instance_id, tenant_id, fleet_id, generation, fkek_key_id,
                  root_generation, state, created_at, activated_at)
             VALUES (?, ?, ?, 0, ?, 1, 'ACTIVE', 'now', 'now')",
            &[&INSTANCE, &TENANT, &FLEET, &[0xe0; 32]],
        )
        .await;
    let create2 = rotation_create(0xe2, target2.clone(), gen1);
    assert_eq!(server.root(&TENANT, &access, &create2).await.0, 201);
    let request = root_grant_create_request(0xe3, &a, &grant2);
    assert_eq!(
        server
            .call(&grants_path(2), &access, Some(&request))
            .await
            .0,
        201
    );
    let ack = ack_request(0xe4, grant_ref(&a, &grant2));
    assert_eq!(
        server
            .call(&ack_path("2", 0xe9), &access, Some(&ack))
            .await
            .0,
        201
    );
    let request = rotation_activate(0xe5, target2, gen1);
    let (status, body) = server
        .call(&activate_path("2"), &access, Some(&request))
        .await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (409, "ROOT_GENERATION_MISMATCH")
    );

    // Behind the trigger's back, store a create response that parses and
    // hashes consistently but names another previous root.
    let (status, created) = server.root(&TENANT, &access, &create2).await;
    assert_eq!(status, 201);
    let mut forged = IdempotentStoredResponseV2::parse(&created).unwrap();
    let mut payload =
        TenantRootGenerationCreatedV2::parse(&forged.canonical_response_payload_bytes).unwrap();
    payload.mode = RootGenerationMode::Rotation {
        previous_root_key_id: [0x33; 32],
        previous_root_generation: 1,
    };
    forged.canonical_response_payload_bytes = payload.encode();
    let forged = forged.encode();
    server
        .sql("DROP TRIGGER v2_idempotency_succeeded_is_fixed", &[])
        .await;
    server
        .sql(
            "UPDATE v2_idempotency SET exact_response_bytes = ?, exact_response_bytes_sha256 = ?
              WHERE operation_kind = 'ROOT_GENERATION_CREATE' AND idempotency_key = ?",
            &[&forged, &sha256(&forged), &[0xe2; 16]],
        )
        .await;
    let (status, body) = server.root(&TENANT, &access, &create2).await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (422, "MUTATION_RESPONSE_MISMATCH")
    );
}

// ------------------------------------------------ restore-epoch transitions ---

const TRANSITIONS: &str = "/v2/recovery/restore-epoch-transitions";
const TENANT2: [u8; 16] = [0x42; 16];

/// Moves the authority and its mirror to `epoch`, as a finished D-1 restore
/// leaves them.
/// shortcut: sessions and approvals stay bound to the epoch they were made
/// in, so no device could sign in after a restore; the fixture moves them.
async fn restored_to(server: &mut Server, epoch: u64) {
    let record = IdentityRecordV2 {
        server_instance_id: INSTANCE,
        restore_epoch: epoch,
        restore_txn_id: [0x99; 16],
        restored_db_sha256: [0x98; 32],
        transition_set_sha256: [0x97; 32],
        written_at_ms: 1_790_985_600_000,
    }
    .encode()
    .unwrap();
    let identity = server.data.with_extension("identity");
    std::fs::write(identity.join("identity-record-v2.bin"), record).unwrap();
    server
        .sql(
            &format!(
                "UPDATE v2_server_state SET restore_epoch = {epoch}, external_record_sha256 = ?"
            ),
            &[&external_record_sha256(&record)],
        )
        .await;
    for statement in [
        "DROP TRIGGER IF EXISTS v2_sessions_binding_is_fixed".to_string(),
        "DROP TRIGGER IF EXISTS v2_device_approvals_record_is_fixed".to_string(),
        format!("UPDATE v2_sessions SET restore_epoch = {epoch}"),
        format!("UPDATE v2_device_approvals SET restore_epoch = {epoch}"),
    ] {
        server.sql(&statement, &[]).await;
    }
    server.restart().await;
}

type Leaf = shared::restore_epoch::RestoreEpochLeafV2;
type Transition = shared::restore_epoch::RestoreEpochTransitionV2;

/// Three sorted leaves of `tenant`.
fn restore_leaves(tenant: [u8; 16]) -> Vec<Leaf> {
    (1..=3u8)
        .map(|i| Leaf {
            tenant_id: tenant,
            profile_id: [0xd0 + i; 16],
            previous_signed_head_hash: [0xe0 + i; 32],
            new_signed_head_hash: [0xf0 + i; 32],
        })
        .collect()
}

/// `dev`'s `0 -> 1` transition over `leaves`, with `edit` applied.
fn restore_transition(dev: &Device, leaves: &[Leaf], edit: fn(&mut Transition)) -> Transition {
    let tenant = leaves[0].tenant_id;
    let mut t = Transition {
        transition_replay_id: [0x31; 16],
        server_instance_id: INSTANCE,
        tenant_id: tenant,
        previous_epoch: 0,
        new_epoch: 1,
        mapping_count: leaves.len() as u64,
        profile_head_mapping_root: shared::restore_epoch::mapping_root(&tenant, leaves).unwrap(),
        reason_code: shared::restore_epoch::RestoreReason::OperatorRestore,
        approver_account_id: OWNER,
        approver_device_id: dev.id,
        approver_signing_key_id: dev.signing_key_id,
        issued_at_ms: now_ms(),
        nonce: [0x32; 16],
    };
    edit(&mut t);
    t
}

fn restore_proofs(t: &Transition, leaves: &[Leaf]) -> Vec<Vec<u8>> {
    (0..leaves.len())
        .map(|i| {
            shared::restore_epoch::RestoreEpochInclusionProofV2::build(t, leaves, i)
                .unwrap()
                .encode()
        })
        .collect()
}

/// The filing body: the exact signed transition and `proofs`, in order.
fn filing(signed: &[u8], proofs: &[Vec<u8>]) -> Vec<u8> {
    use shared::canonical as c;
    let proofs = c::Value::Array(proofs.iter().map(|p| c::b(p)).collect());
    c::encode(&c::m(vec![
        ("domain", c::t("shardx.restore-epoch.transition-filing.v2")),
        ("version", c::u(2)),
        ("exact_signed_transition_bytes", c::b(signed)),
        ("canonical_inclusion_proofs", proofs),
    ]))
}

/// `dev`'s filing of `edit`ed transition over `leaves` with all its proofs.
fn signed_filing(dev: &Device, leaves: &[Leaf], edit: fn(&mut Transition)) -> Vec<u8> {
    let t = restore_transition(dev, leaves, edit);
    let signed = shared::restore_epoch::build_signed_transition(&dev.sk, &t);
    filing(&signed, &restore_proofs(&t, leaves))
}

/// `signed` with one signature bit flipped and its container hash redone.
fn with_bad_signature(signed: &[u8]) -> Vec<u8> {
    use shared::canonical::{self as c, Value};
    let Value::Map(mut entries) = c::decode(signed).unwrap() else {
        panic!("a container is a map");
    };
    entries.retain(|(k, _)| k != "signed_transition_container_hash");
    for (k, v) in &mut entries {
        if let (true, Value::Bytes(b)) = (k == "signature_bytes", v) {
            b[0] ^= 1;
        }
    }
    let hash = c::domain_hash(
        c::L_RESTORE_EPOCH_TRANSITION_CONTAINER,
        &c::encode(&Value::Map(entries.clone())),
    );
    entries.push(("signed_transition_container_hash".into(), c::b(&hash)));
    c::encode(&Value::Map(entries))
}

impl Server {
    /// Posts a filing; returns the status and the error code, if any.
    async fn file(&self, bearer: &str, body: &[u8]) -> (u16, String) {
        let (status, out) = self.call(TRANSITIONS, bearer, Some(body)).await;
        (status, code_of(&out))
    }
}

#[tokio::test]
async fn a_custodian_files_a_restore_epoch_transition_once_and_the_tenant_reads_it_back() {
    use shared::restore_epoch::{build_signed_transition, RestoreEpochInclusionProofV2};
    let mut server = start("g2-restore-epoch", 28230).await;
    let (dev, access, _) = custodian(&mut server, 0x6c).await;
    let peer = device(&server, OWNER, 0x7c, "active").await;
    approve_by_copy(&server, &dev, &peer, 0x7c).await;
    let peer_access = session(&server, &peer).await["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    let leaves = restore_leaves(TENANT);
    let t = restore_transition(&dev, &leaves, |_| {});
    let signed = build_signed_transition(&dev.sk, &t);
    let proofs = restore_proofs(&t, &leaves);
    let body = filing(&signed, &proofs);
    let refused = |code: &str| (422, code.to_string());

    // Custody comes before the body is decoded: garbage is a custodian's
    // problem only.
    let garbage = vec![0xff; 1 << 20];
    assert_eq!(server.file(&peer_access, &garbage).await.0, 403);
    assert_eq!(
        server.file(&access, &garbage).await,
        refused("NON_CANONICAL_RECORD")
    );
    // Not a closed filing map.
    assert_eq!(
        server.file(&access, &signed).await,
        refused("NON_CANONICAL_RECORD")
    );
    for (domain, version) in [
        (None, 2),
        (Some("shardx.restore-epoch.transition-filing.v3"), 2),
        (Some("shardx.restore-epoch.transition-filing.v2"), 3),
    ] {
        use shared::canonical as c;
        let mut map = vec![
            ("version", c::u(version)),
            ("exact_signed_transition_bytes", c::b(&signed)),
            (
                "canonical_inclusion_proofs",
                c::Value::Array(proofs.iter().map(|p| c::b(p)).collect()),
            ),
        ];
        map.extend(domain.map(|d| ("domain", c::t(d))));
        assert_eq!(
            server.file(&access, &c::encode(&c::m(map))).await,
            refused("NON_CANONICAL_RECORD")
        );
    }
    // Exact CBOR only.
    let (status, _) = server.post(TRANSITIONS, Some(&access), json!({})).await;
    assert_eq!(status, 400);
    // Only a custodian, signing as its own session's device, for its own
    // tenant and instance.
    let by_peer = signed_filing(&peer, &leaves, |_| {});
    assert_eq!(server.file(&peer_access, &by_peer).await.0, 403);
    assert_eq!(server.file(&access, &by_peer).await.0, 403);
    let foreign_leaves = restore_leaves(TENANT2);
    let foreign = restore_transition(&dev, &foreign_leaves, |_| {});
    let foreign_body = filing(
        &build_signed_transition(&dev.sk, &foreign),
        &restore_proofs(&foreign, &foreign_leaves),
    );
    assert_eq!(server.file(&access, &foreign_body).await.0, 403);
    for edit in [
        (|t| t.server_instance_id = [8; 16]) as fn(&mut Transition),
        |t| t.approver_account_id = OTHER,
        |t| t.approver_device_id = [0x7c; 16],
    ] {
        let b = signed_filing(&dev, &leaves, edit);
        assert_eq!(server.file(&access, &b).await.0, 403);
    }
    // The epochs are `E -> E+1`, staged at the current `E`.
    for edit in [
        (|t| (t.previous_epoch, t.new_epoch) = (1, 2)) as fn(&mut Transition),
        |t| t.new_epoch = 2,
    ] {
        assert_eq!(
            server
                .file(&access, &signed_filing(&dev, &leaves, edit))
                .await,
            (409, "STALE_CONTEXT".into())
        );
    }
    // A broken signature, and proofs that are not the signed set.
    assert_eq!(
        server
            .file(&access, &filing(&with_bad_signature(&signed), &proofs))
            .await,
        refused("SIGNATURE_INVALID")
    );
    assert_eq!(
        server.file(&access, &filing(&signed, &proofs[..2])).await,
        (423, "RESTORE_EPOCH_PROOF_MISSING".into())
    );
    let mut bent = RestoreEpochInclusionProofV2::parse(&proofs[0]).unwrap();
    bent.steps[0].1 = Some([0xee; 32]);
    let bent = [bent.encode(), proofs[1].clone(), proofs[2].clone()];
    assert_eq!(
        server.file(&access, &filing(&signed, &bent)).await,
        (423, "RESTORE_EPOCH_TRANSITION_INVALID".into())
    );
    let crossed = [
        restore_proofs(&foreign, &foreign_leaves)[0].clone(),
        proofs[1].clone(),
        proofs[2].clone(),
    ];
    assert_eq!(
        server.file(&access, &filing(&signed, &crossed)).await,
        (423, "RESTORE_EPOCH_CROSS_TENANT".into())
    );
    let reordered = [proofs[1].clone(), proofs[0].clone(), proofs[2].clone()];
    assert_eq!(
        server.file(&access, &filing(&signed, &reordered)).await,
        (423, "RESTORE_EPOCH_TRANSITION_INVALID".into())
    );
    assert_eq!(
        server
            .count("SELECT count(*) FROM v2_restore_epoch_transitions")
            .await,
        0
    );

    // Filed once; the same bytes get the same answer.
    let (status, out) = server.call(TRANSITIONS, &access, Some(&body)).await;
    assert_eq!((status, &out), (201, &signed), "{}", code_of(&out));
    let (status, out) = server.call(TRANSITIONS, &access, Some(&body)).await;
    assert_eq!((status, &out), (201, &signed));
    // Staged for a restore that has not happened: not found.
    let tenant = hex(&TENANT);
    let path = format!("{TRANSITIONS}/{tenant}/0/1");
    let first_proof = format!("{path}/proofs/{}", hex(&leaves[0].profile_id));
    assert_eq!(server.call(&path, &peer_access, None).await.0, 404);
    assert_eq!(server.call(&first_proof, &peer_access, None).await.0, 404);
    // Other bytes under the same epochs, replay ID or nonce conflict; only a
    // custodian learns it.
    for edit in [
        (|t| t.nonce = [0x33; 16]) as fn(&mut Transition),
        |t| t.transition_replay_id = [0x34; 16],
        |t| (t.nonce, t.transition_replay_id) = ([0x35; 16], [0x36; 16]),
    ] {
        let b = signed_filing(&dev, &leaves, edit);
        assert_eq!(
            server.file(&access, &b).await,
            (409, "IDEMPOTENCY_MISMATCH".into())
        );
    }
    assert_eq!(
        server.file(&access, &filing(&signed, &reordered)).await,
        (409, "IDEMPOTENCY_MISMATCH".into())
    );
    assert_eq!(server.file(&peer_access, &by_peer).await.0, 403);

    // After the restore to `E+1`, any session of the tenant reads the exact
    // bytes back, and a lost response is still answered.
    restored_to(&mut server, 1).await;
    let (status, out) = server.call(TRANSITIONS, &access, Some(&body)).await;
    assert_eq!((status, &out), (201, &signed));
    assert_eq!(
        server.call(&path, &peer_access, None).await,
        (200, signed.clone())
    );
    for (leaf, proof) in leaves.iter().zip(&proofs) {
        let at = format!("{path}/proofs/{}", hex(&leaf.profile_id));
        assert_eq!(
            server.call(&at, &peer_access, None).await,
            (200, proof.clone())
        );
    }
    let other = hex(&TENANT2);
    for (missing, status) in [
        (format!("{TRANSITIONS}/{tenant}/0/2"), 404),
        (format!("{TRANSITIONS}/{other}/0/1"), 404),
        (format!("{path}/proofs/{}", hex(&[0xd9; 16])), 404),
        (
            format!("{TRANSITIONS}/{other}/0/1/proofs/{}", hex(&[0xd1; 16])),
            404,
        ),
        (format!("{TRANSITIONS}/{tenant}/00/1"), 400),
    ] {
        assert_eq!(
            server.call(&missing, &access, None).await.0,
            status,
            "{missing}"
        );
    }
    for (query, n) in [
        ("SELECT count(*) FROM v2_restore_epoch_transitions", 1),
        ("SELECT count(*) FROM v2_restore_epoch_transition_proofs", 3),
        (
            "SELECT count(*) FROM v2_audit_events WHERE action = 'tenant.restore_epoch_transition'",
            1,
        ),
    ] {
        assert_eq!(server.count(query).await, n, "{query}");
    }

    // The next step may not reuse a filed replay ID or nonce.
    for edit in [
        (|t| (t.previous_epoch, t.new_epoch, t.nonce) = (1, 2, [0x39; 16])) as fn(&mut Transition),
        |t| (t.previous_epoch, t.new_epoch, t.transition_replay_id) = (1, 2, [0x3a; 16]),
    ] {
        assert_eq!(
            server
                .file(&access, &signed_filing(&dev, &leaves, edit))
                .await,
            (409, "IDEMPOTENCY_MISMATCH".into())
        );
    }
    let next = signed_filing(&dev, &leaves, |t| {
        (
            t.previous_epoch,
            t.new_epoch,
            t.nonce,
            t.transition_replay_id,
        ) = (1, 2, [0x39; 16], [0x3a; 16])
    });
    // Once the epoch passed it, a step can no longer be staged.
    restored_to(&mut server, 2).await;
    assert_eq!(
        server.file(&access, &next).await,
        (409, "STALE_CONTEXT".into())
    );
    assert_eq!(server.call(&path, &peer_access, None).await, (200, signed));
}

/// D-5: a root rotation activates once every retained fleet generation has an
/// acknowledged RecoveryGrant under the new root, wrapped by a custodian of
/// the ACTIVE root that holds the new one; a fleet generation then activates
/// only under the root that is ACTIVE.
#[tokio::test]
async fn a_root_rotation_rewraps_every_retained_fleet_key_before_it_activates() {
    use shared::authz_record::{
        DeviceHpkeGrantV2, RecoveryGrantV2, RotationGrantV2, DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE,
        DOMAIN_FLEET_KEY_GRANT_RECOVERY, DOMAIN_FLEET_KEY_GRANT_ROTATION,
    };
    use shared::fleet_lifecycle::{
        FleetGenerationRef, FleetGenerationTerms, FleetGrantVariant as V,
        FleetKeyGenerationActivateV2, FleetKeyGenerationCreateV2, FleetKeyGrantAckV2,
        FleetRotation,
    };
    use shared::mutation::fleet_device_grant_set_hash;

    let mut server = start("d5-rewrap", 28222).await;
    let (a, access, _) = custodian(&mut server, 0x6a).await;
    server
        .sql(
            "INSERT INTO v2_fleets (id, tenant_id, name, status, created_at)
             VALUES (?, ?, 'f', 'active', 'now')",
            &[&FLEET, &TENANT],
        )
        .await;
    for (replay, capability) in [
        (0xa6, Capability::DeviceApprove),
        (0xa7, Capability::FleetManage),
        (0xa8, Capability::KeyRotate),
    ] {
        let grant = capability_grant(&a, &a.sk, |g| {
            g.common.replay_id = [replay; 16];
            g.capability = capability;
        });
        assert_eq!(server.call(GRANTS, &access, Some(&grant)).await.0, 201);
    }
    let gen_ref = |generation: u64, fkek: [u8; 32]| FleetGenerationRef {
        tenant_id: TENANT,
        server_instance_id: INSTANCE,
        restore_epoch: 0,
        fleet_id: FLEET,
        generation,
        fkek_key_id: fkek,
    };
    let device_grant = |replay: u8, generation: u64, fkek: [u8; 32]| {
        let g = DeviceHpkeGrantV2 {
            common: fleet_common(replay, 365),
            fleet_id: FLEET,
            fkek_key_id: fkek,
            generation,
            subject_account_id: OWNER,
            subject_device_id: a.id,
            subject_signing_key_id: a.signing_key_id,
            recipient_hpke_key_id: a.hpke_key_id,
            hpke_encapped_key_bytes: vec![3; 32],
            hpke_wrapped_fleet_key_bytes: vec![4; 48],
        };
        build_record(&a.sk, DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE, &g.encode())
    };
    // A wrap of generation 0's key under `root`, signed by `by`.
    let rewrap = |by: &Device, replay: u8, root: (u64, [u8; 32])| {
        let g = RecoveryGrantV2 {
            common: fleet_common(replay, 3650),
            fleet_id: FLEET,
            fkek_key_id: [0xe0; 32],
            generation: 0,
            recipient_root_key_id: root.1,
            recipient_root_generation: root.0,
            root_wrap_nonce_bytes: [5; 12],
            wrapped_fleet_key_bytes: [6; 48],
        };
        build_record(&by.sk, DOMAIN_FLEET_KEY_GRANT_RECOVERY, &g.encode())
    };
    let path = fleet_generation_path();
    macro_rules! file {
        ($who:expr, $key:expr, $generation:expr, $fkek:expr, $variant:expr, $replay:expr, $c:expr) => {{
            let request = fleet_grant_request($key, $generation, $fkek, $variant, $replay, $c);
            server
                .call(&fleet_grants_path($generation), $who, Some(&request))
                .await
                .0
        }};
    }
    macro_rules! ack {
        ($who:expr, $key:expr, $generation:expr, $fkek:expr, $variant:expr, $replay:expr, $c:expr) => {{
            let grant = fleet_grant_ref($generation, $fkek, $variant, $replay, $c);
            let request = lifecycle_request(
                OperationKind::FleetGrantAck,
                $key,
                FleetKeyGrantAckV2 { grant }.encode(),
            );
            let ack_path = format!("{path}/{}/ack", $generation);
            server.call(&ack_path, $who, Some(&request)).await.0
        }};
    }
    let activate = |key: u8, terms: FleetGenerationTerms| {
        lifecycle_request(
            OperationKind::FleetGenerationActivate,
            key,
            FleetKeyGenerationActivateV2 { terms }.encode(),
        )
    };
    let k0 = shared::keys::root_key_id(&TRK);
    let root0 = (0, k0);

    // Fleet generation 0 is ACTIVE, its key wrapped under root 0.
    let (fkek0, fkek1) = ([0xe0; 32], [0xe1; 32]);
    let (device0, recovery0) = (device_grant(0xd0, 0, fkek0), rewrap(&a, 0xd1, root0));
    let terms0 = FleetGenerationTerms {
        generation: gen_ref(0, fkek0),
        required_device_grant_count: 1,
        required_device_grant_set_hash: fleet_device_grant_set_hash(&[container_hash(&device0)])
            .unwrap(),
        recovery_grant_signed_container_hash: container_hash(&recovery0),
        rotation: None,
    };
    let create0 = FleetKeyGenerationCreateV2 {
        terms: terms0,
        root_generation: 0,
    };
    let request = lifecycle_request(OperationKind::FleetGenerationCreate, 0xb0, create0.encode());
    assert_eq!(server.call(&path, &access, Some(&request)).await.0, 201);
    assert_eq!(
        file!(&access, 0xb1, 0, fkek0, V::DeviceHpke, 0xd0, &device0),
        201
    );
    assert_eq!(
        file!(&access, 0xb2, 0, fkek0, V::Recovery, 0xd1, &recovery0),
        201
    );
    assert_eq!(
        ack!(&access, 0xb4, 0, fkek0, V::DeviceHpke, 0xd0, &device0),
        201
    );
    assert_eq!(
        ack!(&access, 0xb5, 0, fkek0, V::Recovery, 0xd1, &recovery0),
        201
    );
    let activate0_path = format!("{path}/0/activate");
    let request = activate(0xb3, terms0);
    assert_eq!(
        server
            .call(&activate0_path, &access, Some(&request))
            .await
            .0,
        201
    );

    // Fleet generation 1 is fully acknowledged but stays PREPARING, its
    // recovery grant under root 0.
    let device1 = device_grant(0xd5, 1, fkek1);
    let recovery1 = {
        let g = RecoveryGrantV2 {
            common: fleet_common(0xd6, 3650),
            fleet_id: FLEET,
            fkek_key_id: fkek1,
            generation: 1,
            recipient_root_key_id: k0,
            recipient_root_generation: 0,
            root_wrap_nonce_bytes: [5; 12],
            wrapped_fleet_key_bytes: [6; 48],
        };
        build_record(&a.sk, DOMAIN_FLEET_KEY_GRANT_RECOVERY, &g.encode())
    };
    let set1 = fleet_device_grant_set_hash(&[container_hash(&device1)]).unwrap();
    let rotation1 = {
        let common = fleet_common(0xd7, 30);
        let g = RotationGrantV2 {
            activation_not_before_ms: common.not_before_ms,
            common,
            fleet_id: FLEET,
            fkek_key_id: fkek1,
            generation: 1,
            previous_fkek_key_id: fkek0,
            previous_generation: 0,
            required_device_grant_count: 1,
            required_device_grant_set_hash: set1,
            recovery_grant_signed_container_hash: container_hash(&recovery1),
        };
        build_record(&a.sk, DOMAIN_FLEET_KEY_GRANT_ROTATION, &g.encode())
    };
    let terms1 = FleetGenerationTerms {
        generation: gen_ref(1, fkek1),
        required_device_grant_count: 1,
        required_device_grant_set_hash: set1,
        recovery_grant_signed_container_hash: container_hash(&recovery1),
        rotation: Some(FleetRotation {
            previous_generation: 0,
            previous_fkek_key_id: fkek0,
            rotation_grant_signed_container_hash: container_hash(&rotation1),
        }),
    };
    let create1 = FleetKeyGenerationCreateV2 {
        terms: terms1,
        root_generation: 0,
    };
    let request = lifecycle_request(OperationKind::FleetGenerationCreate, 0xc0, create1.encode());
    assert_eq!(server.call(&path, &access, Some(&request)).await.0, 201);
    for (key, variant, replay, c) in [
        (0xc1, V::DeviceHpke, 0xd5, &device1),
        (0xc2, V::Recovery, 0xd6, &recovery1),
        (0xc3, V::Rotation, 0xd7, &rotation1),
    ] {
        assert_eq!(file!(&access, key, 1, fkek1, variant, replay, c), 201);
    }
    for (key, variant, replay, c) in [
        (0xc4, V::DeviceHpke, 0xd5, &device1),
        (0xc5, V::Recovery, 0xd6, &recovery1),
        (0xc6, V::Rotation, 0xd7, &rotation1),
    ] {
        assert_eq!(ack!(&access, key, 1, fkek1, variant, replay, c), 201);
    }

    // B will hold root 1 only; C holds root 0 only.
    let joined = |seed: u8, approval_replay: u8| {
        let server = &server;
        let a = &a;
        let access = &access;
        async move {
            let d = device(server, OWNER, seed, "pending").await;
            session(server, &d).await;
            let rec = approval(&d, &a.sk, approval_replay, 0, 30);
            assert_eq!(server.approve(&d.id, access, &rec).await.0, 201);
            let token = session(server, &d).await["access_token"]
                .as_str()
                .unwrap()
                .to_string();
            (d, token)
        }
    };
    let (b, b_access) = joined(0x5b, 0x5c).await;
    let (c, c_access) = joined(0x5d, 0x5e).await;
    let to_c = existing_root_grant(&a, &c, 0x5e, 0x96);
    let request = root_grant_create_request(0xc8, &a, &to_c);
    assert_eq!(
        server
            .call(&root_grants_path(), &access, Some(&request))
            .await
            .0,
        201
    );
    let request = ack_request(0xc9, grant_ref(&a, &to_c));
    let c_ack = format!("{}/ack", grant_path("0", &[0x96; 16]));
    assert_eq!(server.call(&c_ack, &c_access, Some(&request)).await.0, 201);

    // The tenant's fleet keys no longer keep a rotation from being created.
    let gen0 = PreviousRoot {
        root_key_id: k0,
        root_generation: 0,
    };
    let after0 = RootGrantVariant::RotationGrant {
        previous_root_key_id: k0,
        previous_root_generation: 0,
    };
    let trk1 = [0x7d; 32];
    let k1 = shared::keys::root_key_id(&trk1);
    let root1 = (1, k1);
    let grant_a = root_grant_of(&a, &a, APPROVAL_REPLAY, 0xe1, &trk1, 1, after0);
    let grant_b = root_grant_of(&a, &b, 0x5c, 0xe2, &trk1, 1, after0);
    let target = rotation_target(&trk1, 1, &[grant_a.as_slice(), grant_b.as_slice()]);
    let create = rotation_create(0xd1, target.clone(), gen0);
    let (status, body) = server.root(&TENANT, &access, &create).await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    let grants1 = format!("/v2/tenants/{}/root-key-generations/1/grants", hex(&TENANT));
    for (key, grant) in [(0xd8, &grant_a), (0xd9, &grant_b)] {
        let request = root_grant_create_request(key, &a, grant);
        assert_eq!(server.call(&grants1, &access, Some(&request)).await.0, 201);
    }
    for (key, grant, replay, who) in [
        (0xda, &grant_a, 0xe1, &access),
        (0xdc, &grant_b, 0xe2, &b_access),
    ] {
        let request = ack_request(key, grant_ref(&a, grant));
        let ack_path = format!("{}/ack", grant_path("1", &[replay; 16]));
        assert_eq!(server.call(&ack_path, who, Some(&request)).await.0, 201);
    }

    // ACTIVE fleet generation 0 has no recovery grant under root 1 yet.
    let activate_root = rotation_activate(0xdb, target.clone(), gen0);
    let (status, body) = server
        .call(&activate_path("1"), &access, Some(&activate_root))
        .await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (409, "ROOT_GENERATION_MISMATCH")
    );

    // The rewrap names root 1 exactly and comes from a custodian of root 0
    // that holds root 1: not B (root 1 only), not C (root 0 only).
    for (who, by, key, replay, root) in [
        (&access, &a, 0xf0, 0xf1, (1, [0x33; 32])),
        (&access, &a, 0xf2, 0xf3, (0, k1)),
        (&b_access, &b, 0xf4, 0xf5, root1),
        (&c_access, &c, 0xf6, 0xf7, root1),
    ] {
        let wrap = rewrap(by, replay, root);
        assert_eq!(file!(who, key, 0, fkek0, V::Recovery, replay, &wrap), 403);
    }
    let rewrapped = rewrap(&a, 0xf9, root1);
    assert_eq!(
        file!(&access, 0xf8, 0, fkek0, V::Recovery, 0xf9, &rewrapped),
        201
    );
    // Nor does C acknowledge it.
    assert_eq!(
        ack!(&c_access, 0xe6, 0, fkek0, V::Recovery, 0xf9, &rewrapped),
        403
    );
    assert_eq!(
        ack!(&access, 0xe7, 0, fkek0, V::Recovery, 0xf9, &rewrapped),
        201
    );

    // Generation 1 is still PREPARING: its recovery grant stays under the
    // ACTIVE root, and the root waits for it.
    let early = {
        let g = RecoveryGrantV2 {
            common: fleet_common(0xfd, 3650),
            fleet_id: FLEET,
            fkek_key_id: fkek1,
            generation: 1,
            recipient_root_key_id: k1,
            recipient_root_generation: 1,
            root_wrap_nonce_bytes: [5; 12],
            wrapped_fleet_key_bytes: [6; 48],
        };
        build_record(&a.sk, DOMAIN_FLEET_KEY_GRANT_RECOVERY, &g.encode())
    };
    assert_eq!(
        file!(&access, 0xfc, 1, fkek1, V::Recovery, 0xfd, &early),
        409
    );
    let (status, body) = server
        .call(&activate_path("1"), &access, Some(&activate_root))
        .await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (409, "ROOT_GENERATION_MISMATCH")
    );
    let request = activate(0xea, terms1);
    let (status, body) = server
        .call(&format!("{path}/1/activate"), &access, Some(&request))
        .await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));

    // Generation 1 is ACTIVE now and generation 0 RETIRED: both need a
    // rewrap, and only an acknowledged one counts.
    let (status, body) = server
        .call(&activate_path("1"), &access, Some(&activate_root))
        .await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (409, "ROOT_GENERATION_MISMATCH")
    );
    let rewrapped1 = {
        let g = RecoveryGrantV2 {
            common: fleet_common(0xee, 3650),
            fleet_id: FLEET,
            fkek_key_id: fkek1,
            generation: 1,
            recipient_root_key_id: k1,
            recipient_root_generation: 1,
            root_wrap_nonce_bytes: [5; 12],
            wrapped_fleet_key_bytes: [6; 48],
        };
        build_record(&a.sk, DOMAIN_FLEET_KEY_GRANT_RECOVERY, &g.encode())
    };
    assert_eq!(
        file!(&access, 0xed, 1, fkek1, V::Recovery, 0xee, &rewrapped1),
        201
    );
    let (status, body) = server
        .call(&activate_path("1"), &access, Some(&activate_root))
        .await;
    assert_eq!(
        (status, code_of(&body).as_str()),
        (409, "ROOT_GENERATION_MISMATCH")
    );
    assert_eq!(
        ack!(&access, 0xec, 1, fkek1, V::Recovery, 0xee, &rewrapped1),
        201
    );
    let (status, body) = server
        .call(&activate_path("1"), &access, Some(&activate_root))
        .await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    for (query, want) in [
        (
            "SELECT count(*) FROM v2_root_key_generations
              WHERE generation = 0 AND state = 'RETIRED'",
            1,
        ),
        (
            "SELECT count(*) FROM v2_root_key_generations
              WHERE generation = 1 AND state = 'ACTIVE'",
            1,
        ),
    ] {
        assert_eq!(server.count(query).await, want, "{query}");
    }

    // Root 0 is RETIRED: nothing is wrapped under it any more.
    let late = rewrap(&a, 0xfb, root0);
    assert_eq!(
        file!(&access, 0xfa, 0, fkek0, V::Recovery, 0xfb, &late),
        403
}

/// Moves the identity record and its mirror to `epoch` and restarts, as a
/// finished D-1 restore leaves them. Sessions and challenges are bound to the
/// epoch they were made in, so the move ends them.
async fn restored_to(server: &mut Server, epoch: u64) {
    let record = IdentityRecordV2 {
        server_instance_id: INSTANCE,
        restore_epoch: epoch,
        restore_txn_id: [0x99; 16],
        restored_db_sha256: [0x98; 32],
        transition_set_sha256: [0x97; 32],
        written_at_ms: 1_790_985_600_000,
    }
    .encode()
    .unwrap();
    let identity = server.data.with_extension("identity");
    std::fs::write(identity.join("identity-record-v2.bin"), record).unwrap();
    server
        .sql(
            &format!(
                "UPDATE v2_server_state SET restore_epoch = {epoch}, external_record_sha256 = ?"
            ),
            &[&external_record_sha256(&record)],
        )
        .await;
    server.restart().await;
}

/// `request` as a client sends it to a server at `epoch`.
fn at_epoch(request: &[u8], epoch: u64) -> Vec<u8> {
    let mut outer = IdempotentMutationRequestV2::parse(request).unwrap();
    outer.restore_epoch = epoch;
    outer.encode()
}

#[tokio::test]
async fn approvals_and_root_grants_from_before_a_restore_still_work_after_it() {
    use shared::mutation::RootGrantRevokeReason as R;

    let mut server = start("q1-approvals", 28231).await;
    let (dev, old_access, _) = custodian(&mut server, 0x6d).await;
    let duty = capability_grant(&dev, &dev.sk, |g| {
        g.common.replay_id = [0xc2; 16];
    });
    assert_eq!(server.call(GRANTS, &old_access, Some(&duty)).await.0, 201);
    let joiner = device(&server, OWNER, 0x5b, "pending").await;
    let rec = approval(&joiner, &dev.sk, 0x5c, 0, 30);
    assert_eq!(server.approve(&joiner.id, &old_access, &rec).await.0, 201);
    let existing = existing_root_grant(&dev, &joiner, 0x5c, 0x91);
    let request = root_grant_create_request(0xc4, &dev, &existing);
    assert_eq!(
        server
            .call(&root_grants_path(), &old_access, Some(&request))
            .await
            .0,
        201
    );
    let gone = device(&server, OWNER, 0x5d, "pending").await;
    let rec = approval(&gone, &dev.sk, 0x5e, 0, 30);
    assert_eq!(server.approve(&gone.id, &old_access, &rec).await.0, 201);
    server
        .sql(
            "UPDATE v2_device_approvals SET revoked_at = 'now' WHERE subject_device_id = ?",
            &[&gone.id],
        )
        .await;

    restored_to(&mut server, 1).await;
    assert_eq!(server.me(&old_access).await.0, 401);
    // The epoch-0 D1 approval still opens a setup session, which approves a
    // device under its epoch-0 capability grant (Q-1).
    let s = session_at(&server, &dev, 1).await;
    assert_eq!(s["class"], "root_setup");
    let access = s["access_token"].as_str().unwrap().to_string();
    let late = device(&server, OWNER, 0x5f, "pending").await;
    let rec = approval(&late, &dev.sk, 0x60, 1, 30);
    let (status, _, body) = server.approve(&late.id, &access, &rec).await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    // The epoch-0 ordinary approval still opens an ordinary session.
    let s = session_at(&server, &joiner, 1).await;
    assert_eq!(s["class"], "ordinary");
    let joiner_access = s["access_token"].as_str().unwrap().to_string();
    assert_eq!(server.me(&joiner_access).await.0, 200);
    // A root grant filed at epoch 0 is acknowledged and revoked at epoch 1.
    let ack = at_epoch(&ack_request(0xd8, grant_ref(&dev, &existing)), 1);
    let ack_path = format!("{}/ack", grant_path("0", &[0x91; 16]));
    let (status, body) = server.call(&ack_path, &joiner_access, Some(&ack)).await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    let revoke = at_epoch(
        &root_revoke_request(0xc5, grant_ref(&dev, &existing), R::CustodyRemoved),
        1,
    );
    let revoke_path = format!("{}/revoke", grant_path("0", &[0x91; 16]));
    let (status, body) = server.call(&revoke_path, &access, Some(&revoke)).await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    // A revoked epoch-0 approval stays revoked.
    let ticket = server.login("owner").await;
    assert_eq!(challenge(&server, &ticket, &gone).await.0, 409);
}

#[tokio::test]
async fn fleet_grants_from_before_a_restore_are_acknowledged_and_revoked_after_it() {
    use shared::authz_record::{
        DeviceHpkeGrantV2, RecoveryGrantV2, DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE,
        DOMAIN_FLEET_KEY_GRANT_RECOVERY,
    };
    use shared::fleet_lifecycle::{
        FleetGenerationRef, FleetGenerationTerms, FleetGrantRevocation, FleetGrantRevokeReason,
        FleetGrantRevokeV2, FleetGrantVariant as V, FleetKeyGenerationCreateV2, FleetKeyGrantAckV2,
    };
    use shared::mutation::fleet_device_grant_set_hash;

    let mut server = start("q1-fleet", 28232).await;
    let (dev, old_access, _) = custodian(&mut server, 0x6d).await;
    server
        .sql(
            "INSERT INTO v2_fleets (id, tenant_id, name, status, created_at)
             VALUES (?, ?, 'f', 'active', 'now')",
            &[&FLEET, &TENANT],
        )
        .await;
    let manage = capability_grant(&dev, &dev.sk, |g| {
        g.common.replay_id = [0xa7; 16];
        g.capability = Capability::FleetManage;
    });
    assert_eq!(server.call(GRANTS, &old_access, Some(&manage)).await.0, 201);
    let fkek = [0xe0; 32];
    let device0 = build_record(
        &dev.sk,
        DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE,
        &DeviceHpkeGrantV2 {
            common: fleet_common(0xd0, 365),
            fleet_id: FLEET,
            fkek_key_id: fkek,
            generation: 0,
            subject_account_id: OWNER,
            subject_device_id: dev.id,
            subject_signing_key_id: dev.signing_key_id,
            recipient_hpke_key_id: dev.hpke_key_id,
            hpke_encapped_key_bytes: vec![3; 32],
            hpke_wrapped_fleet_key_bytes: vec![4; 48],
        }
        .encode(),
    );
    let recovery0 = build_record(
        &dev.sk,
        DOMAIN_FLEET_KEY_GRANT_RECOVERY,
        &RecoveryGrantV2 {
            common: fleet_common(0xd1, 3650),
            fleet_id: FLEET,
            fkek_key_id: fkek,
            generation: 0,
            recipient_root_key_id: shared::keys::root_key_id(&TRK),
            recipient_root_generation: 0,
            root_wrap_nonce_bytes: [5; 12],
            wrapped_fleet_key_bytes: [6; 48],
        }
        .encode(),
    );
    let generation = FleetGenerationRef {
        tenant_id: TENANT,
        server_instance_id: INSTANCE,
        restore_epoch: 0,
        fleet_id: FLEET,
        generation: 0,
        fkek_key_id: fkek,
    };
    let create = FleetKeyGenerationCreateV2 {
        terms: FleetGenerationTerms {
            generation,
            required_device_grant_count: 1,
            required_device_grant_set_hash: fleet_device_grant_set_hash(&[container_hash(
                &device0,
            )])
            .unwrap(),
            recovery_grant_signed_container_hash: container_hash(&recovery0),
            rotation: None,
        },
        root_generation: 0,
    };
    let request = lifecycle_request(OperationKind::FleetGenerationCreate, 0xb0, create.encode());
    let path = fleet_generation_path();
    assert_eq!(server.call(&path, &old_access, Some(&request)).await.0, 201);
    for (key, variant, replay, container) in [
        (0xb1, V::DeviceHpke, 0xd0, &device0),
        (0xb2, V::Recovery, 0xd1, &recovery0),
    ] {
        let request = fleet_grant_request(key, 0, fkek, variant, replay, container);
        let grants = fleet_grants_path(0);
        assert_eq!(
            server.call(&grants, &old_access, Some(&request)).await.0,
            201
        );
    }

    restored_to(&mut server, 1).await;
    let access = session_at(&server, &dev, 1).await["access_token"]
        .as_str()
        .unwrap()
        .to_string();
    let grant = fleet_grant_ref(0, fkek, V::DeviceHpke, 0xd0, &device0);
    let ack = lifecycle_request(
        OperationKind::FleetGrantAck,
        0xb4,
        FleetKeyGrantAckV2 { grant }.encode(),
    );
    let (status, body) = server
        .call(&format!("{path}/0/ack"), &access, Some(&at_epoch(&ack, 1)))
        .await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    let revoke = FleetGrantRevokeV2 {
        revocation: FleetGrantRevocation {
            generation,
            grant_variant: V::Recovery,
            replay_id: [0xd1; 16],
            signed_container_hash: container_hash(&recovery0),
            reason_code: FleetGrantRevokeReason::Superseded,
        },
    };
    let request = lifecycle_request(OperationKind::FleetGrantRevoke, 0xbf, revoke.encode());
    let revoke_path = format!("{path}/0/grants/{}/revoke", hex(&[0xd1; 16]));
    let (status, body) = server
        .call(&revoke_path, &access, Some(&at_epoch(&request, 1)))
        .await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
}

#[tokio::test]
async fn a_first_device_confirmed_before_a_restore_is_approved_or_cancelled_after_it() {
    let mut server = start("q1-confirm", 28233).await;
    let dev = device(&server, OWNER, 0x6d, "pending").await;
    server.confirm(&dev).await;
    restored_to(&mut server, 1).await;
    let s = session_at(&server, &dev, 1).await;
    assert_eq!(s["class"], "pending_setup");
    let rec = approval(&dev, &dev.sk, APPROVAL_REPLAY, 1, 30);
    let access = s["access_token"].as_str().unwrap();
    let (status, _, body) = server.approve(&dev.id, access, &rec).await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    assert_eq!(session_at(&server, &dev, 1).await["class"], "root_setup");
    drop(server);

    let mut server = start("q1-cancel", 28234).await;
    let dev = device(&server, OWNER, 0x6d, "pending").await;
    server.confirm(&dev).await;
    restored_to(&mut server, 1).await;
    let out = server
        .offline(&["tenant", "cancel-first-device", "--tenant", "acme"], "")
        .await;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        server
            .count("SELECT count(*) FROM v2_first_device_confirmations WHERE state = 'cancelled'")
            .await,
        1
    );
}
