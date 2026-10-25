//! ADR 0001 R2 over HTTP: login issues an account-only ticket, and only both
//! proofs of possession turn it into a session bound to one device.
//!
//! These drive the real binary, so they cover the wiring as well as the
//! checks: that each route reads the right token type, that a refusal is a
//! non-2xx response, and that the rows behind a session say what the
//! response says.

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;

use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
use serde_json::{json, Value};
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;
use zeroize::Zeroizing;

use shardx_team_server::identity_record::{external_record_sha256, IdentityRecordV2};
use shared::grants::derive_keypair;
use shared::keys::{hpke_key_id, signing_key_id};
use shared::session_binding::{self as sb, DeviceSessionBindingV2};
use shared::signing::Ed25519SigningKey;

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
    Device { id, sk, hpke_sk }
}

/// The client half of a challenge: check the binding, open the secret, sign.
fn answer(ticket: &Value, challenge: &Value, dev: &Device) -> Value {
    let binding = unhex(challenge["binding"].as_str().unwrap());
    let parsed = DeviceSessionBindingV2::parse(&binding).unwrap();
    assert_eq!(parsed.device_id, dev.id);
    assert_eq!(parsed.fields.server_instance_id, INSTANCE);
    assert_eq!(parsed.fields.restore_epoch, 0);
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
    let ticket = server.login("owner").await;
    let (status, ch) = challenge(server, &ticket, dev).await;
    assert_eq!(status, 201, "{ch}");
    let (status, s) = server
        .post(
            "/v2/auth/device-session-proofs",
            ticket["ticket"].as_str(),
            answer(&ticket, &ch, dev),
        )
        .await;
    assert_eq!(status, 201, "{s}");
    s
}

#[tokio::test]
async fn a_ticket_becomes_a_device_session_only_through_both_proofs() {
    let server = start("journey", 38171).await;
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
    let server = start("ticket-only", 38172).await;
    let dev = device(&server, OWNER, 0x22, "pending").await;
    let ticket = server.login("owner").await;
    let t = ticket["ticket"].as_str();

    // Not a v1 token and not a device session.
    for path in [
        "/v2/device-approvals",
        "/v2/capability-grants",
        "/v2/root-key-generations",
    ] {
        let (status, _) = server.post(path, t, json!({})).await;
        assert_eq!(status, 401, "{path}");
    }
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
    let server = start("devices", 38173).await;
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
    let server = start("signing-only", 38174).await;
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
    let server = start("other-ticket", 38175).await;
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
    let server = start("live", 38176).await;
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
    let server = start("refresh", 38177).await;
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
    let server = start("logout", 38178).await;
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
    let server = start("throttle", 38179).await;
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
async fn after_a_restart_a_new_login_reaches_the_same_device() {
    let mut server = start("restart", 38180).await;
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
    let server = start("changed", 38181).await;
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
    let server = start("epoch", 38182).await;
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
    let server = start("tickets", 38183).await;
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
}

#[tokio::test]
async fn a_ticket_issues_five_challenges_in_its_life() {
    let server = start("burn", 38187).await;
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
    let server = start("race", 38184).await;
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
    let server = start("rotations", 38188).await;
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
