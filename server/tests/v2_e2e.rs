//! End-to-end checks of the v2 control-plane endpoints.
//!
//! These drive the real server binary over HTTP. Unit tests already cover the
//! verification and replay logic in isolation; what they cannot show is that
//! the wiring in front of that logic is correct — that the route actually
//! calls the verifier, that a rejection becomes a non-2xx response, and that
//! a tenant boundary holds when the request arrives over the network rather
//! than as a direct function call.

use std::process::{Child, Command};
use std::time::Duration;

use serde_json::{json, Value};
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::Executor;

use shared::canonical as c;
use shared::signing::{build_signed_container, identity_key_id, Ed25519SigningKey};

fn base(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

struct ServerGuard(Child);
impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap()
}

async fn wait_health(c: &reqwest::Client, port: u16) {
    for _ in 0..60 {
        if let Ok(r) = c.get(format!("{}/health", base(port))).send().await {
            if r.status().is_success() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("server did not become healthy on port {port}");
}

fn spawn_server(data: &std::path::Path, port: u16) -> ServerGuard {
    let _ = std::fs::remove_dir_all(data);
    let bin = env!("CARGO_BIN_EXE_shardx-team-server");
    let child = Command::new(bin)
        .env("SHARDX_BIND", format!("127.0.0.1:{port}"))
        .env("SHARDX_DATA_DIR", data)
        .env("SHARDX_TOKEN_SECRET", "e2e-v2-secret")
        .env("SHARDX_ADMIN_USER", "admin")
        .env("SHARDX_ADMIN_PASS", "secret")
        .spawn()
        .expect("spawn server binary");
    ServerGuard(child)
}

async fn token(c: &reqwest::Client, port: u16, user: &str, pass: &str) -> String {
    let v: Value = c
        .post(format!("{}/auth/login", base(port)))
        .json(&json!({ "username": user, "password": pass }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    v["token"].as_str().unwrap().to_string()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

const INSTANCE: [u8; 16] = [7u8; 16];
const TENANT_A: [u8; 16] = [0xAAu8; 16];
const TENANT_B: [u8; 16] = [0xBBu8; 16];

/// Seed the v2 tables the endpoints read: server identity, two tenants, an
/// issuer per tenant, and a v2 account linked to the v1 admin user.
///
/// Done directly against the database because there is no provisioning API
/// yet; the point of these tests is the request path, not provisioning.
async fn seed(
    data: &std::path::Path,
    user_id: &str,
    key_a: &Ed25519SigningKey,
    key_b: &Ed25519SigningKey,
) {
    let db = data.join("shardx.db");
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&format!(
            "sqlite://{}",
            db.to_string_lossy().replace('\\', "/")
        ))
        .await
        .expect("open server db");

    pool.execute("PRAGMA foreign_keys = ON").await.unwrap();

    sqlx::query(
        "INSERT OR REPLACE INTO v2_server_state
             (singleton, server_instance_id, restore_epoch, external_record_sha256, updated_at)
         VALUES (1, ?, 0, ?, '2026-01-01T00:00:00Z')",
    )
    .bind(INSTANCE.as_slice())
    .bind([0u8; 32].as_slice())
    .execute(&pool)
    .await
    .unwrap();

    for (tid, sk) in [(TENANT_A, key_a), (TENANT_B, key_b)] {
        // The issuer is keyed by its derived identity id — the same value the
        // record carries — while `public_key` holds the raw verifying key the
        // signature is actually checked against.
        let vk = sk.verifying_key().to_bytes();
        let key_id = identity_key_id(&sk.verifying_key());
        sqlx::query(
            "INSERT INTO v2_tenants (id, slug, status, active_root_generation, created_at)
             VALUES (?, ?, 'active', 1, '2026-01-01T00:00:00Z')",
        )
        .bind(tid.as_slice())
        .bind(format!("tenant-{}", hex(&tid[..1])))
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO v2_tenant_issuers
                 (tenant_id, signing_key_id, public_key, added_at)
             VALUES (?, ?, ?, '2026-01-01T00:00:00Z')",
        )
        .bind(tid.as_slice())
        .bind(key_id.as_slice())
        .bind(vk.as_slice())
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO v2_accounts
                 (id, tenant_id, username, pw_hash, legacy_user_id, status, created_at)
             VALUES (?, ?, 'admin', 'x', ?, 'active', '2026-01-01T00:00:00Z')",
        )
        .bind([1u8; 16].as_slice())
        .bind(tid.as_slice())
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    }

    pool.close().await;
}

/// Build a signed device-approval record for a tenant.
fn approval_record(
    sk: &Ed25519SigningKey,
    tenant: [u8; 16],
    replay_id: [u8; 16],
    domain: &str,
) -> Vec<u8> {
    let fields = vec![
        ("container_domain", c::Value::Text(domain.to_string())),
        ("container_version", c::Value::Uint(1)),
        ("tenant_id", c::Value::Bytes(tenant.to_vec())),
        ("replay_id", c::Value::Bytes(replay_id.to_vec())),
        ("subject_account_id", c::Value::Bytes(vec![3u8; 16])),
        ("subject_device_id", c::Value::Bytes(vec![4u8; 16])),
        ("approved_use", c::Value::Text("profile.sync".to_string())),
        ("issued_at_ms", c::Value::Uint(0)),
        ("not_before_ms", c::Value::Uint(0)),
        // Far enough out that wall-clock time in CI cannot expire it, but
        // still a real bounded window rather than "never expires".
        ("not_after_ms", c::Value::Uint(4_102_444_800_000)),
        ("server_instance_id", c::Value::Bytes(INSTANCE.to_vec())),
        ("restore_epoch", c::Value::Uint(0)),
        (
            "issuer_signing_key_id",
            c::Value::Bytes(identity_key_id(&sk.verifying_key()).to_vec()),
        ),
    ];
    build_signed_container(sk, fields).exact_bytes
}

async fn admin_user_id(c: &reqwest::Client, port: u16, tok: &str) -> String {
    let v: Value = c
        .get(format!("{}/users", base(port)))
        .bearer_auth(tok)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    v.as_array()
        .unwrap()
        .iter()
        .find(|u| u["username"] == "admin")
        .expect("admin user")["id"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn v2_authorization_holds_over_http() {
    let port = 38111u16;
    let data = std::env::temp_dir().join(format!("shardx-e2e-v2-{}", std::process::id()));
    let _guard = spawn_server(&data, port);
    let cl = client();
    wait_health(&cl, port).await;

    let admin = token(&cl, port, "admin", "secret").await;
    let user_id = admin_user_id(&cl, port, &admin).await;

    let sk_a = Ed25519SigningKey::from_bytes(&[11u8; 32]);
    let sk_b = Ed25519SigningKey::from_bytes(&[22u8; 32]);
    seed(&data, &user_id, &sk_a, &sk_b).await;

    let present = |body: Value| {
        let cl = cl.clone();
        let admin = admin.clone();
        async move {
            cl.post(format!("{}/v2/device-approvals", base(port)))
                .bearer_auth(&admin)
                .json(&body)
                .send()
                .await
                .unwrap()
        }
    };

    // A well-formed record for tenant A is accepted.
    let rec = approval_record(
        &sk_a,
        TENANT_A,
        [1u8; 16],
        "shardx.authorization.device-approval.v2",
    );
    let r = present(json!({
        "tenant_id": hex(&TENANT_A),
        "record_hex": hex(&rec),
    }))
    .await;
    let status = r.status();
    let body = r.text().await.unwrap_or_default();
    assert_eq!(status, 201, "valid record should be accepted: {body}");

    // The same record a second time is a replay: refused, not silently re-run.
    let r = present(json!({
        "tenant_id": hex(&TENANT_A),
        "record_hex": hex(&rec),
    }))
    .await;
    assert_eq!(r.status(), 409, "replayed record must be refused");

    // Tenant isolation over HTTP: a record signed by tenant A's issuer,
    // presented against tenant B, must fail. B does not trust that key.
    let cross = approval_record(
        &sk_a,
        TENANT_B,
        [2u8; 16],
        "shardx.authorization.device-approval.v2",
    );
    let r = present(json!({
        "tenant_id": hex(&TENANT_B),
        "record_hex": hex(&cross),
    }))
    .await;
    assert!(
        !r.status().is_success(),
        "a record signed by another tenant's issuer must not verify, got {}",
        r.status()
    );

    // Tenant confusion, the case a trusted-issuer check alone cannot catch:
    // a record that binds tenant A, presented as tenant B, signed by B's own
    // issuer. The issuer IS trusted for B, the signature IS valid, and the
    // domain IS right — only the tenant binding separates the two. Without
    // it, B could replay A's authorizations under its own key.
    let confused = approval_record(
        &sk_b,
        TENANT_A,
        [7u8; 16],
        "shardx.authorization.device-approval.v2",
    );
    let r = present(json!({
        "tenant_id": hex(&TENANT_B),
        "record_hex": hex(&confused),
    }))
    .await;
    assert!(
        !r.status().is_success(),
        "a record bound to another tenant must not verify even when signed by \
         a trusted issuer of the presenting tenant, got {}",
        r.status()
    );

    // Domain confusion: a capability grant presented to the device-approval
    // endpoint must be refused even though it is correctly signed.
    let wrong_domain = approval_record(
        &sk_a,
        TENANT_A,
        [3u8; 16],
        "shardx.authorization.capability-grant.v2",
    );
    let r = present(json!({
        "tenant_id": hex(&TENANT_A),
        "record_hex": hex(&wrong_domain),
    }))
    .await;
    assert!(
        !r.status().is_success(),
        "a record from another domain must not be accepted, got {}",
        r.status()
    );

    // A single flipped byte in the signed container must not verify.
    let mut tampered = approval_record(
        &sk_a,
        TENANT_A,
        [4u8; 16],
        "shardx.authorization.device-approval.v2",
    );
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let r = present(json!({
        "tenant_id": hex(&TENANT_A),
        "record_hex": hex(&tampered),
    }))
    .await;
    assert!(
        !r.status().is_success(),
        "a tampered record must not verify, got {}",
        r.status()
    );

    // Unauthenticated requests never reach the verifier.
    let r = cl
        .post(format!("{}/v2/device-approvals", base(port)))
        .json(&json!({ "tenant_id": hex(&TENANT_A), "record_hex": hex(&rec) }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401, "v2 endpoints require a session");

    let _ = sk_b;
}

#[tokio::test]
async fn v2_operations_replay_the_stored_response() {
    let port = 38112u16;
    let data = std::env::temp_dir().join(format!("shardx-e2e-v2op-{}", std::process::id()));
    let _guard = spawn_server(&data, port);
    let cl = client();
    wait_health(&cl, port).await;

    let admin = token(&cl, port, "admin", "secret").await;
    let user_id = admin_user_id(&cl, port, &admin).await;

    let sk_a = Ed25519SigningKey::from_bytes(&[11u8; 32]);
    let sk_b = Ed25519SigningKey::from_bytes(&[22u8; 32]);
    seed(&data, &user_id, &sk_a, &sk_b).await;

    let begin = |key: &str, payload: &str| {
        let cl = cl.clone();
        let admin = admin.clone();
        let body = json!({
            "tenant_id": hex(&TENANT_A),
            "idempotency_key": key,
            "operation_kind": "profile.push",
            "payload_hex": payload,
        });
        async move {
            cl.post(format!("{}/v2/operations", base(port)))
                .bearer_auth(&admin)
                .json(&body)
                .send()
                .await
                .unwrap()
        }
    };

    let key = hex(&[9u8; 16]);

    // First claim starts the operation.
    let r = begin(&key, "aabb").await;
    assert_eq!(r.status(), 202, "first claim should start the operation");

    // Same key while in flight is a conflict, not a second execution.
    let r = begin(&key, "aabb").await;
    assert_eq!(r.status(), 409, "in-flight duplicate must conflict");

    // Record the outcome, then retry: the stored response comes back verbatim.
    let r = cl
        .post(format!("{}/v2/operations/complete", base(port)))
        .bearer_auth(&admin)
        .json(&json!({
            "tenant_id": hex(&TENANT_A),
            "idempotency_key": key,
            "status_code": 200,
            "response_hex": "cafe",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "completion should be recorded");

    let r = begin(&key, "aabb").await;
    assert_eq!(
        r.status(),
        200,
        "a completed operation replays its response"
    );
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["status"], "replayed");
    assert_eq!(
        v["response_hex"], "cafe",
        "the replayed body must be the exact stored bytes"
    );

    // Same key, different request body: refused rather than answering a
    // question the caller did not ask.
    let r = begin(&key, "ccdd").await;
    assert_eq!(
        r.status(),
        409,
        "key reuse with a different request must conflict"
    );
}

/// A client needs the deployment identity before it can sign anything the
/// server will accept, so the endpoint must report the same values the
/// verifier reads — and must not hand them to an unauthenticated caller.
#[tokio::test]
async fn server_identity_reports_the_values_records_bind_to() {
    let port = 38113u16;
    let data = std::env::temp_dir().join(format!("shardx-e2e-v2id-{}", std::process::id()));
    let _guard = spawn_server(&data, port);
    let cl = client();
    wait_health(&cl, port).await;

    let admin = token(&cl, port, "admin", "secret").await;
    let user_id = admin_user_id(&cl, port, &admin).await;
    let sk_a = Ed25519SigningKey::from_bytes(&[11u8; 32]);
    let sk_b = Ed25519SigningKey::from_bytes(&[22u8; 32]);
    seed(&data, &user_id, &sk_a, &sk_b).await;

    let url = format!("http://127.0.0.1:{port}/v2/server-identity");

    // Deployment identity is not public: it is an input to authorization.
    let anon = cl.get(&url).send().await.expect("anon request");
    assert_eq!(anon.status(), 401, "identity must require a session");

    let res = cl
        .get(&url)
        .bearer_auth(&admin)
        .send()
        .await
        .expect("identity request");
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.expect("identity json");

    assert_eq!(
        body["server_instance_id"].as_str().expect("instance id"),
        hex(&INSTANCE),
        "must match the instance the verifier checks records against",
    );
    assert_eq!(
        body["restore_epoch"].as_i64().expect("restore epoch"),
        0,
        "must match the seeded epoch",
    );
}

/// The manifest the Launcher signs must be one the server accepts.
///
/// Client and server each used to describe this record separately, which is
/// exactly the kind of split that fails only during a real sync. Both sides
/// now build it from `shared::fleet_manifest`, and this test drives that
/// builder through the real HTTP commit path to prove the two agree.
#[tokio::test]
async fn a_client_built_manifest_is_accepted_by_the_commit_endpoint() {
    let port = 38114u16;
    let data = std::env::temp_dir().join(format!("shardx-e2e-manifest-{}", std::process::id()));
    let _guard = spawn_server(&data, port);
    let cl = client();
    wait_health(&cl, port).await;

    let admin = token(&cl, port, "admin", "secret").await;
    let user_id = admin_user_id(&cl, port, &admin).await;
    let sk_a = Ed25519SigningKey::from_bytes(&[11u8; 32]);
    let sk_b = Ed25519SigningKey::from_bytes(&[22u8; 32]);
    seed(&data, &user_id, &sk_a, &sk_b).await;

    let tenant_hex = hex(&TENANT_A);
    let profile = [0x51u8; 16];
    let profile_hex = hex(&profile);

    // The identity endpoint is the only way a client learns these; a manifest
    // signed against the wrong pair is refused.
    let identity: Value = cl
        .get(format!("{}/v2/server-identity", base(port)))
        .bearer_auth(&admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let instance_hex = identity["server_instance_id"].as_str().unwrap().to_string();
    let restore_epoch = identity["restore_epoch"].as_i64().unwrap();
    assert_eq!(instance_hex, hex(&INSTANCE));

    let fleet = [0x53u8; 16];
    seed_profile(&data, &fleet, &profile).await;

    let container = b"sealed-container-bytes-opaque-to-the-server".to_vec();
    let container_sha = c::sha256(&container);
    let snapshot = [0x52u8; 16];
    let lease_id = hex(&[0x54u8; 16]);
    let session_id = hex(&[0x55u8; 16]);

    let lease_res = cl
        .post(format!("{}/v2/fleet/leases", base(port)))
        .bearer_auth(&admin)
        .json(&json!({
            "tenant_id": tenant_hex,
            "profile_id": profile_hex,
            "lease_id": lease_id,
            "account_id": hex(&[1u8; 16]),
            "device_id": hex(&[4u8; 16]),
            "ttl_seconds": 60,
        }))
        .send()
        .await
        .unwrap();
    let lease_status = lease_res.status();
    let lease_body = lease_res.text().await.unwrap();
    assert!(
        lease_status.is_success(),
        "lease ({lease_status}): {lease_body}"
    );
    let lease: Value = serde_json::from_str(&lease_body).unwrap();
    let fencing = lease["fencing_token"].as_i64().unwrap();

    let intent = c::sha256(&c::encode(&c::m(vec![
        ("profile_id", c::t(&profile_hex)),
        ("snapshot_id", c::t(&hex(&snapshot))),
        ("container_sha256", c::b(&container_sha)),
    ])));

    let open = cl
        .post(format!("{}/v2/fleet/uploads", base(port)))
        .bearer_auth(&admin)
        .json(&json!({
            "tenant_id": tenant_hex,
            "profile_id": profile_hex,
            "session_id": session_id,
            "lease_id": lease_id,
            "fencing_token": fencing,
            "target_version": 1,
            "intent_hash": hex(&intent),
            "declared_size": container.len() as i64,
        }))
        .send()
        .await
        .unwrap();
    assert!(
        open.status().is_success(),
        "open upload: {}",
        open.text().await.unwrap()
    );

    let chunk = cl
        .post(format!(
            "{}/v2/fleet/uploads/{tenant_hex}/{session_id}/chunk",
            base(port)
        ))
        .bearer_auth(&admin)
        .header("x-chunk-offset", "0")
        .header("content-type", "application/octet-stream")
        .body(container.clone())
        .send()
        .await
        .unwrap();
    assert!(
        chunk.status().is_success(),
        "chunk: {}",
        chunk.text().await.unwrap()
    );

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // Built by the same code path the Launcher uses.
    let manifest = shared::fleet_manifest::build_snapshot_manifest(
        &sk_a,
        &shared::fleet_manifest::ManifestFields {
            tenant_id: TENANT_A,
            server_instance_id: INSTANCE,
            restore_epoch: restore_epoch as u64,
            replay_id: [0x56u8; 16],
            profile_id: profile,
            snapshot_id: snapshot,
            fleet_id: fleet,
            base_version: 0,
            key_generation: 1,
            container_sha256: container_sha,
            not_before_ms: now_ms.saturating_sub(60_000),
            not_after_ms: now_ms + 300_000,
        },
    );

    let commit = cl
        .post(format!("{}/v2/fleet/uploads/commit", base(port)))
        .bearer_auth(&admin)
        .json(&json!({
            "tenant_id": tenant_hex,
            "profile_id": profile_hex,
            "session_id": session_id,
            "manifest_hex": hex(&manifest),
            "snapshot_id": hex(&snapshot),
            "fleet_id": hex(&fleet),
            "base_version": 0,
            "key_generation": 1,
            "container_sha256": hex(&container_sha),
            "author_account_id": hex(&[1u8; 16]),
            "author_device_id": hex(&[4u8; 16]),
        }))
        .send()
        .await
        .unwrap();
    let status = commit.status();
    let body = commit.text().await.unwrap();
    assert!(status.is_success(), "commit rejected ({status}): {body}");

    let published: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(published["version"].as_i64(), Some(1));
}

/// A lease targets an existing profile, so create the fleet and profile rows
/// the way tenant provisioning would.
async fn seed_profile(data: &std::path::Path, fleet: &[u8; 16], profile: &[u8; 16]) {
    let url = format!(
        "sqlite://{}/shardx.db",
        data.display().to_string().replace('\\', "/")
    );
    let pool = SqlitePoolOptions::new().connect(&url).await.unwrap();
    pool.execute("PRAGMA foreign_keys = ON").await.unwrap();

    sqlx::query(
        "INSERT INTO v2_fleets (id, tenant_id, name, status, created_at)
         VALUES (?, ?, 'fleet-1', 'active', '2026-01-01T00:00:00Z')",
    )
    .bind(fleet.as_slice())
    .bind(TENANT_A.as_slice())
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO v2_profiles
             (id, tenant_id, fleet_id, name, current_version, status, created_at, updated_at)
         VALUES (?, ?, ?, 'profile-1', 0, 'active', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
    )
    .bind(profile.as_slice())
    .bind(TENANT_A.as_slice())
    .bind(fleet.as_slice())
    .execute(&pool)
    .await
    .unwrap();

    pool.close().await;
}

/// A valid signature must not authorize different data.
///
/// The commit endpoint verifies the manifest and then reads several values
/// from the request body. If it trusts the body over the signed record, a
/// caller can attach a genuine manifest to another payload. This drives that
/// exact attack: same signed manifest, mismatched body.
#[tokio::test]
async fn a_body_that_contradicts_the_signed_manifest_is_refused() {
    let port = 38115u16;
    let data = std::env::temp_dir().join(format!("shardx-e2e-mismatch-{}", std::process::id()));
    let _guard = spawn_server(&data, port);
    let cl = client();
    wait_health(&cl, port).await;

    let admin = token(&cl, port, "admin", "secret").await;
    let user_id = admin_user_id(&cl, port, &admin).await;
    let sk_a = Ed25519SigningKey::from_bytes(&[11u8; 32]);
    let sk_b = Ed25519SigningKey::from_bytes(&[22u8; 32]);
    seed(&data, &user_id, &sk_a, &sk_b).await;

    let tenant_hex = hex(&TENANT_A);
    let profile = [0x61u8; 16];
    let profile_hex = hex(&profile);
    let fleet = [0x62u8; 16];
    seed_profile(&data, &fleet, &profile).await;

    let container = b"the-bytes-actually-staged".to_vec();
    let container_sha = c::sha256(&container);
    let snapshot = [0x63u8; 16];
    let lease_id = hex(&[0x64u8; 16]);
    let session_id = hex(&[0x65u8; 16]);

    let lease: Value = cl
        .post(format!("{}/v2/fleet/leases", base(port)))
        .bearer_auth(&admin)
        .json(&json!({
            "tenant_id": tenant_hex,
            "profile_id": profile_hex,
            "lease_id": lease_id,
            "account_id": hex(&[1u8; 16]),
            "device_id": hex(&[4u8; 16]),
            "ttl_seconds": 60,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let fencing = lease["fencing_token"].as_i64().unwrap();

    let intent = c::sha256(&c::encode(&c::m(vec![
        ("profile_id", c::t(&profile_hex)),
        ("snapshot_id", c::t(&hex(&snapshot))),
        ("container_sha256", c::b(&container_sha)),
    ])));

    cl.post(format!("{}/v2/fleet/uploads", base(port)))
        .bearer_auth(&admin)
        .json(&json!({
            "tenant_id": tenant_hex,
            "profile_id": profile_hex,
            "session_id": session_id,
            "lease_id": lease_id,
            "fencing_token": fencing,
            "target_version": 1,
            "intent_hash": hex(&intent),
            "declared_size": container.len() as i64,
        }))
        .send()
        .await
        .unwrap();

    cl.post(format!(
        "{}/v2/fleet/uploads/{tenant_hex}/{session_id}/chunk",
        base(port)
    ))
    .bearer_auth(&admin)
    .header("x-chunk-offset", "0")
    .header("content-type", "application/octet-stream")
    .body(container.clone())
    .send()
    .await
    .unwrap();

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // A manifest that is genuinely signed, but for a *different* snapshot:
    // it commits to other bytes than the ones staged in this session.
    let other_container = b"bytes-from-some-other-snapshot".to_vec();
    let manifest = shared::fleet_manifest::build_snapshot_manifest(
        &sk_a,
        &shared::fleet_manifest::ManifestFields {
            tenant_id: TENANT_A,
            server_instance_id: INSTANCE,
            restore_epoch: 0,
            replay_id: [0x66u8; 16],
            profile_id: profile,
            snapshot_id: snapshot,
            fleet_id: fleet,
            base_version: 0,
            key_generation: 1,
            container_sha256: c::sha256(&other_container),
            not_before_ms: now_ms.saturating_sub(60_000),
            not_after_ms: now_ms + 300_000,
        },
    );

    // The body describes the staged bytes, so every server-side consistency
    // check on the staged content passes. Only comparing the body against the
    // signed manifest catches this.
    let forged = cl
        .post(format!("{}/v2/fleet/uploads/commit", base(port)))
        .bearer_auth(&admin)
        .json(&json!({
            "tenant_id": tenant_hex,
            "profile_id": profile_hex,
            "session_id": session_id,
            "manifest_hex": hex(&manifest),
            "snapshot_id": hex(&snapshot),
            "fleet_id": hex(&fleet),
            "base_version": 0,
            "key_generation": 1,
            "container_sha256": hex(&container_sha),
            "author_account_id": hex(&[1u8; 16]),
            "author_device_id": hex(&[4u8; 16]),
        }))
        .send()
        .await
        .unwrap();
    let st = forged.status();
    let body = forged.text().await.unwrap();
    assert_eq!(
        st,
        reqwest::StatusCode::BAD_REQUEST,
        "a manifest signed for other bytes must not publish the staged ones: {body}"
    );
    assert!(
        body.contains("signed manifest"),
        "refusal should name the manifest mismatch, got: {body}"
    );
}

/// A member with no v2 account in a tenant must not be able to lease that
/// tenant's profiles.
///
/// The lease handler reads `account_id` from the request body. Nothing tied
/// that value to the caller, so any authenticated user could name any account
/// in any tenant and check out its profiles. The signed-record endpoints are
/// safe because a signature covers their fields; the fleet endpoints carry no
/// signature, so the tenant boundary has to be enforced by the handler.
#[tokio::test]
async fn a_member_outside_the_tenant_cannot_lease_its_profiles() {
    let port = 38117u16;
    let data = std::env::temp_dir().join(format!("shardx-e2e-crosstenant-{}", std::process::id()));
    let _guard = spawn_server(&data, port);
    let cl = client();
    wait_health(&cl, port).await;

    let admin = token(&cl, port, "admin", "secret").await;
    let user_id = admin_user_id(&cl, port, &admin).await;
    let sk_a = Ed25519SigningKey::from_bytes(&[11u8; 32]);
    let sk_b = Ed25519SigningKey::from_bytes(&[22u8; 32]);
    seed(&data, &user_id, &sk_a, &sk_b).await;

    let fleet = [0x63u8; 16];
    let profile = [0x61u8; 16];
    seed_profile(&data, &fleet, &profile).await;

    // A second, legitimate user of the deployment — but seeded into no tenant,
    // so it holds no v2 account anywhere.
    let created = cl
        .post(format!("{}/users", base(port)))
        .bearer_auth(&admin)
        .json(&json!({ "username": "outsider", "password": "outsider-pass", "role": "member" }))
        .send()
        .await
        .unwrap();
    assert!(
        created.status().is_success(),
        "could not create the outsider account: {}",
        created.status()
    );
    let outsider = token(&cl, port, "outsider", "outsider-pass").await;

    // The account id the *admin* owns in tenant A, named by someone who has no
    // account in that tenant at all.
    let res = cl
        .post(format!("{}/v2/fleet/leases", base(port)))
        .bearer_auth(&outsider)
        .json(&json!({
            "tenant_id": hex(&TENANT_A),
            "profile_id": hex(&profile),
            "lease_id": hex(&[0x64u8; 16]),
            "account_id": hex(&[1u8; 16]),
            "device_id": hex(&[0x65u8; 16]),
            "ttl_seconds": 60,
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        res.status(),
        reqwest::StatusCode::FORBIDDEN,
        "a caller with no account in the tenant leased one of its profiles"
    );
}

/// Enrollment registers a device key only when the caller proves it holds the
/// matching private key.
///
/// A registration endpoint that skipped the proof would let anyone bind a
/// public key they do not control, and every later manifest signed by the
/// real holder would be attributed to whoever registered it first.
#[tokio::test]
async fn device_enrollment_requires_proof_of_possession() {
    let port = 38118u16;
    let data = std::env::temp_dir().join(format!("shardx-e2e-enroll-{}", std::process::id()));
    let _guard = spawn_server(&data, port);
    let cl = client();
    wait_health(&cl, port).await;

    let admin = token(&cl, port, "admin", "secret").await;
    let user_id = admin_user_id(&cl, port, &admin).await;
    let sk_a = Ed25519SigningKey::from_bytes(&[11u8; 32]);
    let sk_b = Ed25519SigningKey::from_bytes(&[22u8; 32]);
    seed(&data, &user_id, &sk_a, &sk_b).await;

    let tenant_hex = hex(&TENANT_A);

    // The device key pair being enrolled. The challenge commits to it, so the
    // keys are named before the nonce is issued.
    let device_sk = Ed25519SigningKey::from_bytes(&[0x44u8; 32]);
    let device_vk = device_sk.verifying_key().to_bytes();
    let hpke_pk = [0x55u8; 32];

    // Round trip one: ask for a challenge.
    let ch: Value = cl
        .post(format!("{}/v2/devices/enrollment-challenges", base(port)))
        .bearer_auth(&admin)
        .json(&json!({
            "tenant_id": tenant_hex,
            "signing_public_key": hex(&device_vk),
            "hpke_public_key": hex(&hpke_pk),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let challenge_id = ch["challenge_id"].as_str().unwrap().to_string();
    let nonce = decode_hex_str(ch["nonce"].as_str().unwrap());
    let account_id = decode_hex_str(ch["account_id"].as_str().unwrap());

    let proof_bytes = enrollment_proof_bytes(
        &decode_hex_str(&challenge_id),
        &nonce,
        &TENANT_A,
        &account_id,
        &device_vk,
        &hpke_pk,
    );

    // A signature from the wrong key must not enroll the device.
    let wrong = shared::signing::sign_tbs(&sk_b, &proof_bytes);
    let refused = cl
        .post(format!("{}/v2/devices/enrollment-proofs", base(port)))
        .bearer_auth(&admin)
        .json(&json!({
            "tenant_id": tenant_hex,
            "challenge_id": challenge_id,
            "nonce": hex(&nonce),
            "signing_public_key": hex(&device_vk),
            "hpke_public_key": hex(&hpke_pk),
            "proof_signature": hex(&wrong),
            "label_ciphertext": hex(b"opaque"),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        refused.status().as_u16(),
        400,
        "a proof signed by another key must not enroll the device"
    );

    // The real holder succeeds.
    let sig = shared::signing::sign_tbs(&device_sk, &proof_bytes);
    let ok = cl
        .post(format!("{}/v2/devices/enrollment-proofs", base(port)))
        .bearer_auth(&admin)
        .json(&json!({
            "tenant_id": tenant_hex,
            "challenge_id": challenge_id,
            "nonce": hex(&nonce),
            "signing_public_key": hex(&device_vk),
            "hpke_public_key": hex(&hpke_pk),
            "proof_signature": hex(&sig),
            "label_ciphertext": hex(b"opaque"),
        }))
        .send()
        .await
        .unwrap();
    let ok_status = ok.status().as_u16();
    let ok_body = ok.text().await.unwrap();
    assert_eq!(ok_status, 201, "valid proof should enroll, got: {ok_body}");
    let enrolled: Value = serde_json::from_str(&ok_body).unwrap();
    let device_id = enrolled["device_id"].as_str().unwrap().to_string();
    assert_eq!(device_id.len(), 32, "device id should be a 16-byte hex id");

    // The challenge is single-use: replaying the same valid proof must fail,
    // or an intercepted proof could enroll a second device.
    let replay = cl
        .post(format!("{}/v2/devices/enrollment-proofs", base(port)))
        .bearer_auth(&admin)
        .json(&json!({
            "tenant_id": tenant_hex,
            "challenge_id": challenge_id,
            "nonce": hex(&nonce),
            "signing_public_key": hex(&device_vk),
            "hpke_public_key": hex(&hpke_pk),
            "proof_signature": hex(&sig),
            "label_ciphertext": hex(b"opaque"),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        replay.status().as_u16(),
        400,
        "a consumed challenge must not enroll a second device"
    );
}

fn decode_hex_str(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Mirror of the server's canonical proof bytes. Written independently here on
/// purpose: if the server changes its preimage, this test fails rather than
/// following it silently.
fn enrollment_proof_bytes(
    challenge_id: &[u8],
    nonce: &[u8],
    tenant_id: &[u8; 16],
    account_id: &[u8],
    signing_public_key: &[u8; 32],
    hpke_public_key: &[u8; 32],
) -> Vec<u8> {
    c::encode(&c::Value::Map(vec![
        (
            "container_domain".into(),
            c::t("shardx.authorization.device-enrollment-proof.v2"),
        ),
        ("container_version".into(), c::u(1)),
        ("challenge_id".into(), c::b(challenge_id)),
        ("nonce".into(), c::b(nonce)),
        ("tenant_id".into(), c::b(tenant_id)),
        ("account_id".into(), c::b(account_id)),
        ("signing_public_key".into(), c::b(signing_public_key)),
        ("hpke_public_key".into(), c::b(hpke_public_key)),
    ]))
}

/// Build a signed tenant-root-key-grant record.
///
/// The field set matches what the server reads out of the signed container; a
/// grant assembled from anything less would be storable but not verifiable.
#[allow(clippy::too_many_arguments)]
/// Create the tenant's first root key generation so grants have something to
/// bind to. Returns the generation number the server assigned.
async fn begin_generation(
    cl: &reqwest::Client,
    port: u16,
    admin: &str,
    tenant_hex: &str,
    root_key_id: &[u8; 32],
) -> u64 {
    let resp = cl
        .post(format!("{}/v2/root-key-generations", base(port)))
        .bearer_auth(admin)
        .json(&json!({
            "tenant_id": tenant_hex,
            "root_key_id": hex(root_key_id),
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap();
    assert_eq!(status, 200, "begin generation failed: {body}");
    let v: Value = serde_json::from_str(&body).unwrap();
    v["generation"].as_u64().expect("generation number")
}

// A grant is signed over all eight of these fields; grouping them into a
// struct here would only move the same list one level down.
#[allow(clippy::too_many_arguments)]
fn grant_record(
    sk: &Ed25519SigningKey,
    tenant: [u8; 16],
    replay_id: [u8; 16],
    scope: &shared::grants::GrantScope,
    sealed: &shared::grants::SealedGrant,
    subject_signing_key_id: [u8; 32],
    approval_replay_id: [u8; 16],
    variant: &str,
) -> Vec<u8> {
    let fields = vec![
        (
            "container_domain",
            c::Value::Text("shardx.authorization.tenant-root-key-grant.v2".to_string()),
        ),
        ("container_version", c::Value::Uint(1)),
        ("tenant_id", c::Value::Bytes(tenant.to_vec())),
        ("replay_id", c::Value::Bytes(replay_id.to_vec())),
        ("grant_variant", c::Value::Text(variant.to_string())),
        ("root_key_id", c::Value::Bytes(scope.root_key_id.to_vec())),
        ("root_generation", c::Value::Uint(scope.root_generation)),
        (
            "grant_capability",
            c::Value::Text("root-custody".to_string()),
        ),
        (
            "subject_account_id",
            c::Value::Bytes(scope.subject_account_id.to_vec()),
        ),
        (
            "subject_device_id",
            c::Value::Bytes(scope.subject_device_id.to_vec()),
        ),
        (
            "subject_signing_key_id",
            c::Value::Bytes(subject_signing_key_id.to_vec()),
        ),
        (
            "recipient_hpke_key_id",
            c::Value::Bytes(scope.recipient_hpke_key_id.to_vec()),
        ),
        (
            "subject_device_approval_replay_id",
            c::Value::Bytes(approval_replay_id.to_vec()),
        ),
        ("hpke_suite_id", c::Value::Uint(1)),
        ("hpke_mode_id", c::Value::Uint(0)),
        ("hpke_kem_id", c::Value::Uint(32)),
        ("hpke_kdf_id", c::Value::Uint(1)),
        ("hpke_aead_id", c::Value::Uint(3)),
        (
            "hpke_info_bytes",
            c::Value::Bytes(sealed.hpke_info_bytes.clone()),
        ),
        (
            "hpke_encapped_key_bytes",
            c::Value::Bytes(sealed.encapped_key_bytes.clone()),
        ),
        (
            "hpke_wrapped_trk_bytes",
            c::Value::Bytes(sealed.ciphertext_bytes.clone()),
        ),
        ("issued_at_ms", c::Value::Uint(0)),
        ("not_before_ms", c::Value::Uint(0)),
        ("not_after_ms", c::Value::Uint(4_102_444_800_000)),
        ("server_instance_id", c::Value::Bytes(INSTANCE.to_vec())),
        ("restore_epoch", c::Value::Uint(0)),
        (
            "issuer_signing_key_id",
            c::Value::Bytes(identity_key_id(&sk.verifying_key()).to_vec()),
        ),
    ];
    build_signed_container(sk, fields).exact_bytes
}

/// Enroll a device over HTTP and return its id and account id.
///
/// Enrollment rather than a direct insert, because a grant is bound to a device
/// the server considers enrolled; seeding the row directly would prove the
/// storage path works against a device state the enrollment path cannot produce.
async fn enroll(
    cl: &reqwest::Client,
    port: u16,
    tok: &str,
    tenant: &[u8; 16],
    device_sk: &Ed25519SigningKey,
    hpke_pk: &[u8; 32],
) -> (Vec<u8>, Vec<u8>) {
    let tenant_hex = hex(tenant);
    let tenant_hex = tenant_hex.as_str();
    let device_vk = device_sk.verifying_key().to_bytes();

    let ch: Value = cl
        .post(format!("{}/v2/devices/enrollment-challenges", base(port)))
        .bearer_auth(tok)
        .json(&json!({
            "tenant_id": tenant_hex,
            "signing_public_key": hex(&device_vk),
            "hpke_public_key": hex(hpke_pk),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let challenge_id = ch["challenge_id"].as_str().unwrap().to_string();
    let nonce = decode_hex_str(ch["nonce"].as_str().unwrap());
    let account_id = decode_hex_str(ch["account_id"].as_str().unwrap());

    let proof_bytes = enrollment_proof_bytes(
        &decode_hex_str(&challenge_id),
        &nonce,
        tenant,
        &account_id,
        &device_vk,
        hpke_pk,
    );
    let sig = shared::signing::sign_tbs(device_sk, &proof_bytes);

    let body = cl
        .post(format!("{}/v2/devices/enrollment-proofs", base(port)))
        .bearer_auth(tok)
        .json(&json!({
            "tenant_id": tenant_hex,
            "challenge_id": challenge_id,
            "nonce": hex(&nonce),
            "signing_public_key": hex(&device_vk),
            "hpke_public_key": hex(hpke_pk),
            "proof_signature": hex(&sig),
            "label_ciphertext": hex(b"opaque"),
        }))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    let enrolled: Value = serde_json::from_str(&body).unwrap();
    let device_id = decode_hex_str(enrolled["device_id"].as_str().expect("device_id"));
    (device_id, account_id)
}

/// A stored grant must come back sealed, and only to its own tenant.
///
/// This is the whole point of grant storage: before it existed the endpoint
/// verified a grant and dropped it, so a second device had no way to obtain the
/// tenant root key. The test seals a real key, files it, reads it back over
/// HTTP and opens it with the device private key.
#[tokio::test]
async fn a_filed_root_key_grant_comes_back_sealed_to_its_device() {
    let port = 38119u16;
    let data = std::env::temp_dir().join(format!("shardx-e2e-grant-{}", std::process::id()));
    let _guard = spawn_server(&data, port);
    let cl = client();
    wait_health(&cl, port).await;

    let admin = token(&cl, port, "admin", "secret").await;
    let user_id = admin_user_id(&cl, port, &admin).await;
    let sk_a = Ed25519SigningKey::from_bytes(&[11u8; 32]);
    let sk_b = Ed25519SigningKey::from_bytes(&[22u8; 32]);
    seed(&data, &user_id, &sk_a, &sk_b).await;

    let tenant_hex = hex(&TENANT_A);

    // The recipient device holds an HPKE key pair; only its private half can
    // open the grant.
    let (device_hpke_sk, device_hpke_pk) = shared::grants::derive_keypair(&[0x66u8; 32]);
    let device_sk = Ed25519SigningKey::from_bytes(&[0x44u8; 32]);
    let device_hpke_pk: [u8; 32] = device_hpke_pk.as_slice().try_into().expect("hpke pk");
    let (device_id, account_id) =
        enroll(&cl, port, &admin, &TENANT_A, &device_sk, &device_hpke_pk).await;

    // The tenant root key that custody is actually about. It never leaves this
    // test in plaintext, and the server never sees it.
    let trk: [u8; 32] = [0x9Au8; 32];

    // Grants bind to a generation, so the tenant must have one before it can
    // receive custody. This is the bootstrap the server now requires.
    let generation = begin_generation(
        &cl,
        port,
        &admin,
        &tenant_hex,
        &shared::keys::root_key_id(&trk),
    )
    .await;

    let scope = shared::grants::GrantScope {
        replay_id: [0x31u8; 16],
        tenant_id: TENANT_A,
        server_instance_id: INSTANCE,
        restore_epoch: 0,
        root_key_id: shared::keys::root_key_id(&trk),
        root_generation: generation,
        subject_account_id: account_id.clone().try_into().expect("account id"),
        subject_device_id: device_id.clone().try_into().expect("device id"),
        recipient_hpke_key_id: shared::keys::hpke_key_id(&device_hpke_pk),
    };

    let sealed = shared::grants::seal_trk(&device_hpke_pk, &scope, &trk).expect("seal trk");

    let record = grant_record(
        &sk_a,
        TENANT_A,
        scope.replay_id,
        &scope,
        &sealed,
        identity_key_id(&device_sk.verifying_key()),
        [0x32u8; 16],
        "FirstRootSelfGrant",
    );

    let filed = cl
        .post(format!("{}/v2/tenant-root-key-grants", base(port)))
        .bearer_auth(&admin)
        .json(&json!({
            "tenant_id": tenant_hex,
            "record_hex": hex(&record),
        }))
        .send()
        .await
        .unwrap();
    let filed_status = filed.status().as_u16();
    let filed_body = filed.text().await.unwrap();
    assert_eq!(
        filed_status, 201,
        "grant should be filed, got: {filed_body}"
    );

    // Read it back through the collection endpoint.
    let listed_resp = cl
        .get(format!(
            "{}/v2/tenants/{}/devices/{}/root-key-grants",
            base(port),
            tenant_hex,
            hex(&device_id)
        ))
        .bearer_auth(&admin)
        .send()
        .await
        .unwrap();
    let listed_status = listed_resp.status().as_u16();
    let listed_body = listed_resp.text().await.unwrap();
    assert_eq!(listed_status, 200, "listing grants failed: {listed_body}");
    let listed: Value = serde_json::from_str(&listed_body).unwrap();

    let grants = listed["grants"].as_array().expect("grants array");
    assert_eq!(grants.len(), 1, "exactly the filed grant should come back");
    let g = &grants[0];
    assert_eq!(g["grant_variant"], "FirstRootSelfGrant");
    assert_eq!(g["root_generation"], generation);

    // The payload must survive storage byte-for-byte, or the device would hold
    // a grant whose AEAD tag no longer checks out.
    let got_encapped = decode_hex_str(g["hpke_encapped_key_hex"].as_str().unwrap());
    let got_wrapped = decode_hex_str(g["hpke_wrapped_trk_hex"].as_str().unwrap());
    assert_eq!(got_encapped, sealed.encapped_key_bytes);
    assert_eq!(got_wrapped, sealed.ciphertext_bytes);

    // The real assertion: the device recovers the tenant root key from what the
    // server handed back. Comparing stored bytes alone would pass even if the
    // grant were sealed to the wrong key.
    let opened = shared::grants::open_trk(&device_hpke_sk, &scope, &got_encapped, &got_wrapped)
        .expect("device should open its own grant");
    assert_eq!(&opened[..], &trk[..], "recovered key must be the root key");

    // Someone outside the tenant must not read these grants. Same class of flaw
    // as the fleet endpoints: the path names a tenant, so authority has to come
    // from the session instead. The seeded admin belongs to both tenants, so
    // the check needs an account that belongs to neither.
    let created = cl
        .post(format!("{}/users", base(port)))
        .bearer_auth(&admin)
        .json(&json!({ "username": "outsider", "password": "outsider-pass", "role": "member" }))
        .send()
        .await
        .unwrap();
    assert!(
        created.status().is_success(),
        "could not create the outsider account: {}",
        created.status()
    );
    let outsider = token(&cl, port, "outsider", "outsider-pass").await;

    let cross = cl
        .get(format!(
            "{}/v2/tenants/{}/devices/{}/root-key-grants",
            base(port),
            tenant_hex,
            hex(&device_id)
        ))
        .bearer_auth(&outsider)
        .send()
        .await
        .unwrap();
    assert_ne!(
        cross.status().as_u16(),
        200,
        "a non-member must not read a tenant's root key grants"
    );
}

/// The replay ledger must accept root key grants, and refuse a real replay.
///
/// A regression guard for a silent failure: `record_table` once had a CHECK
/// that omitted `v2_tenant_root_key_grants`, and because the claim uses
/// `INSERT OR IGNORE`, the violation looked identical to a duplicate key. Every
/// grant was answered "authorization record already used" while nothing was
/// ever written -- so grants were both impossible to file and unprotected
/// against actual replay.
#[tokio::test]
async fn a_root_key_grant_replay_id_is_claimed_exactly_once() {
    let port = 38120u16;
    let data = std::env::temp_dir().join(format!("shardx-e2e-grantreplay-{}", std::process::id()));
    let _guard = spawn_server(&data, port);
    let cl = client();
    wait_health(&cl, port).await;

    let admin = token(&cl, port, "admin", "secret").await;
    let user_id = admin_user_id(&cl, port, &admin).await;
    let sk_a = Ed25519SigningKey::from_bytes(&[11u8; 32]);
    let sk_b = Ed25519SigningKey::from_bytes(&[22u8; 32]);
    seed(&data, &user_id, &sk_a, &sk_b).await;

    let tenant_hex = hex(&TENANT_A);
    let (_sk, device_hpke_pk) = shared::grants::derive_keypair(&[0x77u8; 32]);
    let device_hpke_pk: [u8; 32] = device_hpke_pk.as_slice().try_into().expect("hpke pk");
    let device_sk = Ed25519SigningKey::from_bytes(&[0x45u8; 32]);
    let (device_id, account_id) =
        enroll(&cl, port, &admin, &TENANT_A, &device_sk, &device_hpke_pk).await;

    let trk: [u8; 32] = [0x5Cu8; 32];

    // Grants bind to a generation, so the tenant must have one before it can
    // receive custody. This is the bootstrap the server now requires.
    let generation = begin_generation(
        &cl,
        port,
        &admin,
        &tenant_hex,
        &shared::keys::root_key_id(&trk),
    )
    .await;

    let scope = shared::grants::GrantScope {
        replay_id: [0x41u8; 16],
        tenant_id: TENANT_A,
        server_instance_id: INSTANCE,
        restore_epoch: 0,
        root_key_id: shared::keys::root_key_id(&trk),
        root_generation: generation,
        subject_account_id: account_id.try_into().expect("account id"),
        subject_device_id: device_id.try_into().expect("device id"),
        recipient_hpke_key_id: shared::keys::hpke_key_id(&device_hpke_pk),
    };
    let sealed = shared::grants::seal_trk(&device_hpke_pk, &scope, &trk).expect("seal trk");
    // A custodian grant hands the key to an additional device, which is only
    // meaningful once the generation is established. Walk the real bootstrap
    // first: file the self-grant, then activate.
    let self_scope = shared::grants::GrantScope {
        replay_id: [0x5Du8; 16],
        ..scope.clone()
    };
    let self_sealed =
        shared::grants::seal_trk(&device_hpke_pk, &self_scope, &trk).expect("seal self grant");
    let self_record = grant_record(
        &sk_a,
        TENANT_A,
        self_scope.replay_id,
        &self_scope,
        &self_sealed,
        identity_key_id(&device_sk.verifying_key()),
        [0x5Eu8; 16],
        "FirstRootSelfGrant",
    );
    let self_filed = cl
        .post(format!("{}/v2/tenant-root-key-grants", base(port)))
        .bearer_auth(&admin)
        .json(&json!({
            "tenant_id": tenant_hex,
            "record_hex": hex(&self_record),
        }))
        .send()
        .await
        .unwrap();
    let self_status = self_filed.status().as_u16();
    let self_body = self_filed.text().await.unwrap();
    assert_eq!(self_status, 201, "self-grant should file: {self_body}");

    let activated = cl
        .post(format!("{}/v2/root-key-generations/activate", base(port)))
        .bearer_auth(&admin)
        .json(&json!({ "tenant_id": tenant_hex, "generation": generation }))
        .send()
        .await
        .unwrap();
    let act_status = activated.status().as_u16();
    let act_body = activated.text().await.unwrap();
    assert_eq!(act_status, 200, "activation should succeed: {act_body}");

    let record = grant_record(
        &sk_a,
        TENANT_A,
        scope.replay_id,
        &scope,
        &sealed,
        identity_key_id(&device_sk.verifying_key()),
        [0x42u8; 16],
        "CustodianIssued",
    );

    let file_once = || async {
        let r = cl
            .post(format!("{}/v2/tenant-root-key-grants", base(port)))
            .bearer_auth(&admin)
            .json(&json!({
                "tenant_id": tenant_hex,
                "record_hex": hex(&record),
            }))
            .send()
            .await
            .unwrap();
        let status = r.status().as_u16();
        (status, r.text().await.unwrap())
    };

    let (first, first_body) = file_once().await;
    assert_eq!(first, 201, "the first filing should succeed: {first_body}");

    // The second attempt is a genuine replay and must be refused as one -- and
    // must not have stored a second copy of the grant.
    let (second, _) = file_once().await;
    assert_eq!(second, 409, "re-filing the same record must be a conflict");

    let listed: Value = cl
        .get(format!(
            "{}/v2/tenants/{}/devices/{}/root-key-grants",
            base(port),
            tenant_hex,
            hex(&scope.subject_device_id)
        ))
        .bearer_auth(&admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // The device legitimately holds two grants here: the bootstrap self-grant
    // and the custodian grant under test. Only the latter is what the replay
    // must not duplicate, so count that variant rather than the total.
    let custodian_grants = listed["grants"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|g| g["grant_variant"] == "CustodianIssued")
        .count();
    assert_eq!(
        custodian_grants, 1,
        "a refused replay must not leave a second grant behind"
    );
}

/// An unknown grant variant is refused with a clear error.
///
/// `grant_variant` is the one CHECK-constrained column fed from a signed
/// client record, so it is the place the ledger's swallowed-constraint bug
/// could recur. The rejection must name the field rather than surface as a
/// database fault or, worse, be absorbed into a misleading replay answer.
#[tokio::test]
async fn an_unknown_grant_variant_is_refused_before_it_reaches_the_database() {
    let port = 38121u16;
    let data = std::env::temp_dir().join(format!("shardx-e2e-variant-{}", std::process::id()));
    let _guard = spawn_server(&data, port);
    let cl = client();
    wait_health(&cl, port).await;

    let admin = token(&cl, port, "admin", "secret").await;
    let user_id = admin_user_id(&cl, port, &admin).await;
    let sk_a = Ed25519SigningKey::from_bytes(&[11u8; 32]);
    let sk_b = Ed25519SigningKey::from_bytes(&[22u8; 32]);
    seed(&data, &user_id, &sk_a, &sk_b).await;

    let device_sk = Ed25519SigningKey::from_bytes(&[0x77u8; 32]);
    let ikm: [u8; 32] = [0x78u8; 32];
    let (_device_hpke_sk, device_hpke_pk) = shared::grants::derive_keypair(&ikm);
    let hpke_pk32: [u8; 32] = device_hpke_pk.as_slice().try_into().unwrap();

    let (device_id, account_id) =
        enroll(&cl, port, &admin, &TENANT_A, &device_sk, &hpke_pk32).await;

    let trk: [u8; 32] = [0x79u8; 32];
    let scope = shared::grants::GrantScope {
        replay_id: [0x7Au8; 16],
        tenant_id: TENANT_A,
        server_instance_id: INSTANCE,
        restore_epoch: 0,
        root_key_id: shared::keys::root_key_id(&trk),
        root_generation: 1,
        subject_account_id: account_id.clone().try_into().expect("account id"),
        subject_device_id: device_id.clone().try_into().expect("device id"),
        recipient_hpke_key_id: shared::keys::hpke_key_id(&device_hpke_pk),
    };
    let sealed = shared::grants::seal_trk(&device_hpke_pk, &scope, &trk).expect("seal");

    // Signed by a trusted issuer, so the signature is valid and only the
    // variant is wrong. Anything less would not reach the check under test.
    let record = grant_record(
        &sk_a,
        TENANT_A,
        scope.replay_id,
        &scope,
        &sealed,
        identity_key_id(&device_sk.verifying_key()),
        [0x7Bu8; 16],
        "SomethingElse",
    );

    let res = cl
        .post(format!("{}/v2/tenant-root-key-grants", base(port)))
        .bearer_auth(&admin)
        .json(&json!({
            "tenant_id": hex(&TENANT_A),
            "record_hex": hex(&record),
        }))
        .send()
        .await
        .unwrap();

    let status = res.status().as_u16();
    let body = res.text().await.unwrap();
    assert_eq!(
        status, 400,
        "an unknown grant variant should be a client error, got: {body}"
    );
    assert!(
        body.contains("grant_variant"),
        "the error should name the offending field, got: {body}"
    );
}

/// A grant naming a generation the tenant never created must be refused.
///
/// Without this the generation number in a grant is decoration: a device could
/// collect a grant for a generation nobody established and encrypt under a key
/// no other device would ever look for.
#[tokio::test]
async fn a_grant_for_an_unknown_generation_is_refused() {
    let port = 38122u16;
    let data = std::env::temp_dir().join(format!("shardx-e2e-nogen-{}", std::process::id()));
    let _guard = spawn_server(&data, port);
    let cl = client();
    wait_health(&cl, port).await;

    let admin = token(&cl, port, "admin", "secret").await;
    let user_id = admin_user_id(&cl, port, &admin).await;
    let sk_a = Ed25519SigningKey::from_bytes(&[11u8; 32]);
    let sk_b = Ed25519SigningKey::from_bytes(&[22u8; 32]);
    seed(&data, &user_id, &sk_a, &sk_b).await;
    let tenant_hex = hex(&TENANT_A);

    let device_sk = Ed25519SigningKey::from_bytes(&[0x81u8; 32]);
    let ikm: [u8; 32] = [0x82u8; 32];
    let (_hpke_sk, device_hpke_pk) = shared::grants::derive_keypair(&ikm);
    let hpke_pk32: [u8; 32] = device_hpke_pk.as_slice().try_into().unwrap();
    let (device_id, account_id) =
        enroll(&cl, port, &admin, &TENANT_A, &device_sk, &hpke_pk32).await;

    let trk: [u8; 32] = [0x83u8; 32];

    // Deliberately no generation is created for this tenant.
    let scope = shared::grants::GrantScope {
        replay_id: [0x84u8; 16],
        tenant_id: TENANT_A,
        server_instance_id: INSTANCE,
        restore_epoch: 0,
        root_key_id: shared::keys::root_key_id(&trk),
        root_generation: 9,
        subject_account_id: account_id.clone().try_into().unwrap(),
        subject_device_id: device_id.clone().try_into().unwrap(),
        recipient_hpke_key_id: shared::keys::hpke_key_id(&device_hpke_pk),
    };
    let sealed = shared::grants::seal_trk(&device_hpke_pk, &scope, &trk).expect("seal");
    let record = grant_record(
        &sk_a,
        TENANT_A,
        scope.replay_id,
        &scope,
        &sealed,
        identity_key_id(&device_sk.verifying_key()),
        [0x85u8; 16],
        "FirstRootSelfGrant",
    );

    let res = cl
        .post(format!("{}/v2/tenant-root-key-grants", base(port)))
        .bearer_auth(&admin)
        .json(&json!({ "tenant_id": tenant_hex, "record_hex": hex(&record) }))
        .send()
        .await
        .unwrap();
    let status = res.status().as_u16();
    let body = res.text().await.unwrap();
    assert_eq!(status, 400, "unknown generation should be refused: {body}");
    assert!(
        body.contains("does not exist"),
        "the error should say the generation is unknown, got: {body}"
    );
}

/// A second FirstRootSelfGrant must be refused, with a reason that names it.
///
/// The first self-grant decides who holds a tenant's root key. If a second
/// could be filed, anyone able to sign a record could append themselves as an
/// original root holder after the fact. The body is asserted too: a bare 409
/// would also be produced by the database's unique index, and that would hide
/// whether the rule is actually being enforced in code.
#[tokio::test]
async fn a_second_first_root_self_grant_is_refused() {
    let port = 38123u16;
    let data = std::env::temp_dir().join(format!("shardx-e2e-twoself-{}", std::process::id()));
    let _guard = spawn_server(&data, port);
    let cl = client();
    wait_health(&cl, port).await;

    let admin = token(&cl, port, "admin", "secret").await;
    let user_id = admin_user_id(&cl, port, &admin).await;
    let sk_a = Ed25519SigningKey::from_bytes(&[11u8; 32]);
    let sk_b = Ed25519SigningKey::from_bytes(&[22u8; 32]);
    seed(&data, &user_id, &sk_a, &sk_b).await;
    let tenant_hex = hex(&TENANT_A);

    let device_sk = Ed25519SigningKey::from_bytes(&[0x86u8; 32]);
    let ikm: [u8; 32] = [0x87u8; 32];
    let (_hpke_sk, device_hpke_pk) = shared::grants::derive_keypair(&ikm);
    let hpke_pk32: [u8; 32] = device_hpke_pk.as_slice().try_into().unwrap();
    let (device_id, account_id) =
        enroll(&cl, port, &admin, &TENANT_A, &device_sk, &hpke_pk32).await;

    let trk: [u8; 32] = [0x88u8; 32];
    let generation = begin_generation(
        &cl,
        port,
        &admin,
        &tenant_hex,
        &shared::keys::root_key_id(&trk),
    )
    .await;

    let file_self = |replay: [u8; 16], op: [u8; 16]| {
        let scope = shared::grants::GrantScope {
            replay_id: replay,
            tenant_id: TENANT_A,
            server_instance_id: INSTANCE,
            restore_epoch: 0,
            root_key_id: shared::keys::root_key_id(&trk),
            root_generation: generation,
            subject_account_id: account_id.clone().try_into().unwrap(),
            subject_device_id: device_id.clone().try_into().unwrap(),
            recipient_hpke_key_id: shared::keys::hpke_key_id(&device_hpke_pk),
        };
        let sealed = shared::grants::seal_trk(&device_hpke_pk, &scope, &trk).expect("seal");
        let record = grant_record(
            &sk_a,
            TENANT_A,
            scope.replay_id,
            &scope,
            &sealed,
            identity_key_id(&device_sk.verifying_key()),
            op,
            "FirstRootSelfGrant",
        );
        cl.post(format!("{}/v2/tenant-root-key-grants", base(port)))
            .bearer_auth(&admin)
            .json(&json!({ "tenant_id": tenant_hex, "record_hex": hex(&record) }))
            .send()
    };

    let first = file_self([0x8Au8; 16], [0x8Bu8; 16]).await.unwrap();
    assert_eq!(first.status().as_u16(), 201, "first self-grant should file");

    // A distinct replay id, so this is refused for being a second self-grant
    // rather than for being a replay of the first.
    let second = file_self([0x8Cu8; 16], [0x8Du8; 16]).await.unwrap();
    let status = second.status().as_u16();
    let body = second.text().await.unwrap();
    assert_eq!(status, 409, "a second self-grant should conflict: {body}");
    assert!(
        body.contains("already has a first root self-grant"),
        "the refusal must come from the self-grant rule, not a bare unique \
         index violation, got: {body}"
    );
}

/// A generation cannot be activated before a grant exists for it.
///
/// Activating first would advertise a key that no device has proven it can
/// open, which is how a tenant locks itself out of its own backups.
#[tokio::test]
async fn a_generation_cannot_activate_without_a_grant() {
    let port = 38124u16;
    let data = std::env::temp_dir().join(format!("shardx-e2e-noact-{}", std::process::id()));
    let _guard = spawn_server(&data, port);
    let cl = client();
    wait_health(&cl, port).await;

    let admin = token(&cl, port, "admin", "secret").await;
    let user_id = admin_user_id(&cl, port, &admin).await;
    let sk_a = Ed25519SigningKey::from_bytes(&[11u8; 32]);
    let sk_b = Ed25519SigningKey::from_bytes(&[22u8; 32]);
    seed(&data, &user_id, &sk_a, &sk_b).await;
    let tenant_hex = hex(&TENANT_A);

    let trk: [u8; 32] = [0x8Eu8; 32];
    let generation = begin_generation(
        &cl,
        port,
        &admin,
        &tenant_hex,
        &shared::keys::root_key_id(&trk),
    )
    .await;

    let res = cl
        .post(format!("{}/v2/root-key-generations/activate", base(port)))
        .bearer_auth(&admin)
        .json(&json!({ "tenant_id": tenant_hex, "generation": generation }))
        .send()
        .await
        .unwrap();
    let status = res.status().as_u16();
    let body = res.text().await.unwrap();
    assert_eq!(
        status, 409,
        "activation without a grant should conflict: {body}"
    );
    assert!(
        body.contains("no root key grant on file"),
        "the refusal should explain what is missing, got: {body}"
    );

    // And the tenant must still report no active generation.
    let active: Value = cl
        .get(format!(
            "{}/v2/tenants/{}/root-key-generation",
            base(port),
            tenant_hex
        ))
        .bearer_auth(&admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        active["active"], false,
        "no generation should be active yet"
    );
}

/// An outsider cannot create a generation for a tenant they do not belong to.
#[tokio::test]
async fn an_outsider_cannot_begin_a_generation() {
    let port = 38125u16;
    let data = std::env::temp_dir().join(format!("shardx-e2e-genout-{}", std::process::id()));
    let _guard = spawn_server(&data, port);
    let cl = client();
    wait_health(&cl, port).await;

    let admin = token(&cl, port, "admin", "secret").await;
    let user_id = admin_user_id(&cl, port, &admin).await;
    let sk_a = Ed25519SigningKey::from_bytes(&[11u8; 32]);
    let sk_b = Ed25519SigningKey::from_bytes(&[22u8; 32]);
    seed(&data, &user_id, &sk_a, &sk_b).await;

    // The seeded admin belongs to both tenants, so proving a tenant boundary
    // needs an account that belongs to neither.
    let created = cl
        .post(format!("{}/users", base(port)))
        .bearer_auth(&admin)
        .json(&json!({ "username": "outsider", "password": "outsider-pass", "role": "member" }))
        .send()
        .await
        .unwrap();
    assert!(
        created.status().is_success(),
        "could not create the outsider account: {}",
        created.status()
    );
    let outsider = token(&cl, port, "outsider", "outsider-pass").await;

    let res = cl
        .post(format!("{}/v2/root-key-generations", base(port)))
        .bearer_auth(&outsider)
        .json(&json!({
            "tenant_id": hex(&TENANT_A),
            "root_key_id": hex(&[0x8Fu8; 32]),
        }))
        .send()
        .await
        .unwrap();
    assert!(
        matches!(res.status().as_u16(), 401 | 403 | 404),
        "an outsider must not begin a generation, got {}",
        res.status()
    );
}

/// A grant must wrap the key its generation actually commits to.
///
/// This is the constraint that makes a generation number mean something. A
/// grant that names generation N while sealing an unrelated key would give the
/// receiving device a key that decrypts nothing anyone else wrote, and the
/// mismatch would only surface later as an unopenable backup.
#[tokio::test]
async fn a_grant_wrapping_a_different_key_than_its_generation_is_refused() {
    let port = 38126u16;
    let data = std::env::temp_dir().join(format!("shardx-e2e-wrongkey-{}", std::process::id()));
    let _guard = spawn_server(&data, port);
    let cl = client();
    wait_health(&cl, port).await;

    let admin = token(&cl, port, "admin", "secret").await;
    let user_id = admin_user_id(&cl, port, &admin).await;
    let sk_a = Ed25519SigningKey::from_bytes(&[11u8; 32]);
    let sk_b = Ed25519SigningKey::from_bytes(&[22u8; 32]);
    seed(&data, &user_id, &sk_a, &sk_b).await;
    let tenant_hex = hex(&TENANT_A);

    let device_sk = Ed25519SigningKey::from_bytes(&[0x90u8; 32]);
    let ikm: [u8; 32] = [0x91u8; 32];
    let (_hpke_sk, device_hpke_pk) = shared::grants::derive_keypair(&ikm);
    let hpke_pk32: [u8; 32] = device_hpke_pk.as_slice().try_into().unwrap();
    let (device_id, account_id) =
        enroll(&cl, port, &admin, &TENANT_A, &device_sk, &hpke_pk32).await;

    // The generation commits to this key.
    let committed_trk: [u8; 32] = [0x92u8; 32];
    let generation = begin_generation(
        &cl,
        port,
        &admin,
        &tenant_hex,
        &shared::keys::root_key_id(&committed_trk),
    )
    .await;

    // The grant seals a different one, but still names that generation.
    let other_trk: [u8; 32] = [0x93u8; 32];
    let scope = shared::grants::GrantScope {
        replay_id: [0x94u8; 16],
        tenant_id: TENANT_A,
        server_instance_id: INSTANCE,
        restore_epoch: 0,
        root_key_id: shared::keys::root_key_id(&other_trk),
        root_generation: generation,
        subject_account_id: account_id.clone().try_into().unwrap(),
        subject_device_id: device_id.clone().try_into().unwrap(),
        recipient_hpke_key_id: shared::keys::hpke_key_id(&device_hpke_pk),
    };
    let sealed = shared::grants::seal_trk(&device_hpke_pk, &scope, &other_trk).expect("seal");
    let record = grant_record(
        &sk_a,
        TENANT_A,
        scope.replay_id,
        &scope,
        &sealed,
        identity_key_id(&device_sk.verifying_key()),
        [0x95u8; 16],
        "FirstRootSelfGrant",
    );

    let res = cl
        .post(format!("{}/v2/tenant-root-key-grants", base(port)))
        .bearer_auth(&admin)
        .json(&json!({ "tenant_id": tenant_hex, "record_hex": hex(&record) }))
        .send()
        .await
        .unwrap();
    let status = res.status().as_u16();
    let body = res.text().await.unwrap();
    assert_eq!(status, 400, "a mismatched root key must be refused: {body}");
    assert!(
        body.contains("does not match"),
        "the error should name the mismatch, got: {body}"
    );
}

/// Insert a fleet row the way tenant provisioning would.
async fn seed_fleet(data: &std::path::Path, fleet: &[u8; 16]) {
    let url = format!(
        "sqlite://{}/shardx.db",
        data.display().to_string().replace('\\', "/")
    );
    let pool = SqlitePoolOptions::new().connect(&url).await.unwrap();
    pool.execute("PRAGMA foreign_keys = ON").await.unwrap();
    sqlx::query(
        "INSERT INTO v2_fleets (id, tenant_id, name, status, created_at)
         VALUES (?, ?, 'fleet-1', 'active', '2026-01-01T00:00:00Z')",
    )
    .bind(fleet.as_slice())
    .bind(TENANT_A.as_slice())
    .execute(&pool)
    .await
    .unwrap();
}

/// Build a signed fleet-key-grant record.
///
/// Deliberately separate from `grant_record`: fleet grants carry a fleet id and
/// wrap the FKEK, and the two record shapes must not drift into each other.
fn fleet_grant_record(
    sk: &Ed25519SigningKey,
    scope: &shared::fleet_grants::FleetGrantScope,
    sealed: &shared::grants::SealedGrant,
    subject_signing_key_id: [u8; 32],
    variant: &str,
) -> Vec<u8> {
    fleet_grant_record_with_capability(
        sk,
        scope,
        sealed,
        subject_signing_key_id,
        variant,
        "fleet.key.receive",
    )
}

/// Same, but the caller chooses the claimed capability.
fn fleet_grant_record_with_capability(
    sk: &Ed25519SigningKey,
    scope: &shared::fleet_grants::FleetGrantScope,
    sealed: &shared::grants::SealedGrant,
    subject_signing_key_id: [u8; 32],
    variant: &str,
    capability: &str,
) -> Vec<u8> {
    let fields = vec![
        (
            "container_domain",
            c::Value::Text("shardx.authorization.fleet-key-grant.v2".to_string()),
        ),
        ("container_version", c::Value::Uint(1)),
        ("tenant_id", c::Value::Bytes(scope.tenant_id.to_vec())),
        ("replay_id", c::Value::Bytes(scope.replay_id.to_vec())),
        ("grant_variant", c::Value::Text(variant.to_string())),
        ("fleet_id", c::Value::Bytes(scope.fleet_id.to_vec())),
        ("fkek_key_id", c::Value::Bytes(scope.fkek_key_id.to_vec())),
        ("generation", c::Value::Uint(scope.generation)),
        ("grant_capability", c::Value::Text(capability.to_string())),
        (
            "subject_account_id",
            c::Value::Bytes(scope.subject_account_id.to_vec()),
        ),
        (
            "subject_device_id",
            c::Value::Bytes(scope.subject_device_id.to_vec()),
        ),
        (
            "subject_signing_key_id",
            c::Value::Bytes(subject_signing_key_id.to_vec()),
        ),
        (
            "recipient_hpke_key_id",
            c::Value::Bytes(scope.recipient_hpke_key_id.to_vec()),
        ),
        (
            "hpke_suite_id",
            c::Value::Uint(
                shared::grants::HPKE_SUITE_ID_X25519_HKDF_SHA256_CHACHA20POLY1305 as u64,
            ),
        ),
        (
            "hpke_info_bytes",
            c::Value::Bytes(sealed.hpke_info_bytes.clone()),
        ),
        (
            "hpke_encapped_key_bytes",
            c::Value::Bytes(sealed.encapped_key_bytes.clone()),
        ),
        (
            "hpke_wrapped_fkek_bytes",
            c::Value::Bytes(sealed.ciphertext_bytes.clone()),
        ),
        ("issued_at_ms", c::Value::Uint(0)),
        ("not_before_ms", c::Value::Uint(0)),
        ("not_after_ms", c::Value::Uint(4_102_444_800_000)),
        (
            "server_instance_id",
            c::Value::Bytes(scope.server_instance_id.to_vec()),
        ),
        ("restore_epoch", c::Value::Uint(scope.restore_epoch)),
        (
            "issuer_signing_key_id",
            c::Value::Bytes(identity_key_id(&sk.verifying_key()).to_vec()),
        ),
    ];
    build_signed_container(sk, fields).exact_bytes
}

/// Create a fleet's first key generation. Returns the assigned generation.
async fn begin_fleet_generation(
    cl: &reqwest::Client,
    port: u16,
    admin: &str,
    tenant_hex: &str,
    fleet_hex: &str,
    fkek_key_id: &[u8; 32],
) -> u64 {
    let resp = cl
        .post(format!("{}/v2/fleet-key-generations", base(port)))
        .bearer_auth(admin)
        .json(&json!({
            "tenant_id": tenant_hex,
            "fleet_id": fleet_hex,
            "fkek_key_id": hex(fkek_key_id),
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap();
    assert_eq!(status, 200, "begin fleet generation failed: {body}");
    let v: Value = serde_json::from_str(&body).unwrap();
    v["generation"].as_u64().expect("generation number")
}

/// Set up an admin token, seeded tenant, and one enrolled device.
async fn fleet_fixture(
    cl: &reqwest::Client,
    port: u16,
    data: &std::path::Path,
    hpke_seed: u8,
) -> (
    String,
    Vec<u8>,
    Vec<u8>,
    [u8; 32],
    Vec<u8>,
    Ed25519SigningKey,
    Ed25519SigningKey,
) {
    let admin = token(cl, port, "admin", "secret").await;
    let user_id = admin_user_id(cl, port, &admin).await;
    let sk_a = Ed25519SigningKey::from_bytes(&[11u8; 32]);
    let sk_b = Ed25519SigningKey::from_bytes(&[22u8; 32]);
    seed(data, &user_id, &sk_a, &sk_b).await;

    let (hpke_sk, hpke_pk) = shared::grants::derive_keypair(&[hpke_seed; 32]);
    let hpke_pk: [u8; 32] = hpke_pk.as_slice().try_into().expect("hpke pk");
    let device_sk = Ed25519SigningKey::from_bytes(&[0x44u8; 32]);
    let (device_id, account_id) = enroll(cl, port, &admin, &TENANT_A, &device_sk, &hpke_pk).await;

    // A fleet key anchors to an active root generation, so bootstrap one the
    // way a real tenant would: begin, file the first self grant, activate.
    let tenant_hex = hex(&TENANT_A);
    let trk: [u8; 32] = [0x7Cu8; 32];
    let root_gen = begin_generation(
        cl,
        port,
        &admin,
        &tenant_hex,
        &shared::keys::root_key_id(&trk),
    )
    .await;
    let root_scope = shared::grants::GrantScope {
        replay_id: [0x51u8; 16],
        tenant_id: TENANT_A,
        server_instance_id: INSTANCE,
        restore_epoch: 0,
        root_key_id: shared::keys::root_key_id(&trk),
        root_generation: root_gen,
        subject_account_id: account_id.clone().try_into().expect("account id"),
        subject_device_id: device_id.clone().try_into().expect("device id"),
        recipient_hpke_key_id: shared::keys::hpke_key_id(&hpke_pk),
    };
    let root_sealed = shared::grants::seal_trk(&hpke_pk, &root_scope, &trk).expect("seal trk");
    let root_record = grant_record(
        &sk_a,
        TENANT_A,
        root_scope.replay_id,
        &root_scope,
        &root_sealed,
        identity_key_id(&device_sk.verifying_key()),
        [0x32u8; 16],
        "FirstRootSelfGrant",
    );
    let filed = cl
        .post(format!("{}/v2/tenant-root-key-grants", base(port)))
        .bearer_auth(&admin)
        .json(&json!({ "tenant_id": tenant_hex, "record_hex": hex(&root_record) }))
        .send()
        .await
        .unwrap();
    assert_eq!(filed.status().as_u16(), 201, "root self grant must file");
    let activated = cl
        .post(format!("{}/v2/root-key-generations/activate", base(port)))
        .bearer_auth(&admin)
        .json(&json!({ "tenant_id": tenant_hex, "generation": root_gen }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        activated.status().as_u16(),
        200,
        "root generation must activate"
    );

    (
        admin,
        device_id,
        account_id,
        hpke_pk,
        hpke_sk.to_vec(),
        device_sk,
        sk_a,
    )
}

/// End to end: a fleet key is sealed to a device, retrieved by that device, and
/// unwrapped to the exact same bytes.
///
/// This is the property profile sync depends on. Encrypting under a key the
/// receiving device cannot reconstruct byte for byte is silent data loss.
#[tokio::test]
async fn a_fleet_key_grant_round_trips_to_its_device() {
    let port = 38131u16;
    let data = std::env::temp_dir().join(format!("shardx-e2e-fleet-rt-{}", std::process::id()));
    let _guard = spawn_server(&data, port);
    let cl = client();
    wait_health(&cl, port).await;

    let (admin, device_id, account_id, hpke_pk, hpke_sk, device_sk, sk_a) =
        fleet_fixture(&cl, port, &data, 0x66).await;
    let tenant_hex = hex(&TENANT_A);
    let fleet_id: [u8; 16] = [0xF1u8; 16];
    let fleet_hex = hex(&fleet_id);
    seed_fleet(&data, &fleet_id).await;

    // The fleet key that snapshots are encrypted under. The server never sees it.
    let fkek: [u8; 32] = [0x5Au8; 32];
    let fkek_key_id = shared::fleet_grants::fkek_key_id(&fkek);
    let generation =
        begin_fleet_generation(&cl, port, &admin, &tenant_hex, &fleet_hex, &fkek_key_id).await;

    let scope = shared::fleet_grants::FleetGrantScope {
        replay_id: [0x41u8; 16],
        tenant_id: TENANT_A,
        server_instance_id: INSTANCE,
        restore_epoch: 0,
        fleet_id,
        fkek_key_id,
        generation,
        subject_account_id: account_id.clone().try_into().expect("account id"),
        subject_device_id: device_id.clone().try_into().expect("device id"),
        recipient_hpke_key_id: shared::keys::hpke_key_id(&hpke_pk),
    };
    let sealed = shared::fleet_grants::seal_fkek(&hpke_pk, &scope, &fkek).expect("seal fkek");

    let record = fleet_grant_record(
        &sk_a,
        &scope,
        &sealed,
        identity_key_id(&device_sk.verifying_key()),
        "FirstFleetSelfGrant",
    );

    let filed = cl
        .post(format!("{}/v2/fleet-key-grants", base(port)))
        .bearer_auth(&admin)
        .json(&json!({ "tenant_id": tenant_hex, "record_hex": hex(&record) }))
        .send()
        .await
        .unwrap();
    let filed_status = filed.status().as_u16();
    let filed_body = filed.text().await.unwrap();
    assert_eq!(
        filed_status, 200,
        "filing the fleet grant failed: {filed_body}"
    );

    let listed: Value = cl
        .get(format!(
            "{}/v2/tenants/{}/devices/{}/fleet-key-grants",
            base(port),
            tenant_hex,
            hex(&device_id)
        ))
        .bearer_auth(&admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let grants = listed["grants"].as_array().expect("grants array");
    assert_eq!(grants.len(), 1, "exactly the filed grant should come back");
    let g = &grants[0];
    assert_eq!(g["grant_variant"], "FirstFleetSelfGrant");
    assert_eq!(g["fleet_generation"], generation);

    // Unwrap with exactly the info bytes the server returned.
    let retrieved = shared::grants::SealedGrant {
        hpke_info_bytes: decode_hex_str(g["hpke_info_hex"].as_str().unwrap()),
        encapped_key_bytes: decode_hex_str(g["hpke_encapped_key_hex"].as_str().unwrap()),
        ciphertext_bytes: decode_hex_str(g["hpke_wrapped_fkek_hex"].as_str().unwrap()),
    };
    let opened = shared::fleet_grants::open_fkek_with_info(&hpke_sk, &retrieved)
        .expect("the receiving device must be able to unwrap the fleet key");

    assert_eq!(
        opened.as_slice(),
        fkek.as_slice(),
        "the unwrapped fleet key must equal the original, byte for byte"
    );
}

/// A fleet generation must not activate before a self grant proves the key can
/// be unwrapped. Activating early advertises a key nothing can open.
#[tokio::test]
async fn a_fleet_generation_cannot_activate_without_a_self_grant() {
    let port = 38132u16;
    let data = std::env::temp_dir().join(format!("shardx-e2e-fleet-act-{}", std::process::id()));
    let _guard = spawn_server(&data, port);
    let cl = client();
    wait_health(&cl, port).await;

    let (admin, _device_id, _account_id, _pk, _sk, _dsk, _sk_a) =
        fleet_fixture(&cl, port, &data, 0x67).await;
    let tenant_hex = hex(&TENANT_A);
    let fleet_id: [u8; 16] = [0xF2u8; 16];
    let fleet_hex = hex(&fleet_id);
    seed_fleet(&data, &fleet_id).await;
    let fkek_key_id = shared::fleet_grants::fkek_key_id(&[0x11u8; 32]);

    let generation =
        begin_fleet_generation(&cl, port, &admin, &tenant_hex, &fleet_hex, &fkek_key_id).await;

    let resp = cl
        .post(format!("{}/v2/fleet-key-generations/activate", base(port)))
        .bearer_auth(&admin)
        .json(&json!({
            "tenant_id": tenant_hex,
            "fleet_id": fleet_hex,
            "generation": generation,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        409,
        "activation must be refused until a first self grant exists"
    );

    let active: Value = cl
        .get(format!(
            "{}/v2/tenants/{}/fleets/{}/key-generation",
            base(port),
            tenant_hex,
            fleet_hex
        ))
        .bearer_auth(&admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        active.is_null(),
        "no generation may be advertised as active yet"
    );
}

/// A grant wrapping a different key than its generation declares must be
/// refused, or a device could be handed a key that decrypts nothing.
#[tokio::test]
async fn a_fleet_grant_wrapping_a_different_key_is_refused() {
    let port = 38133u16;
    let data =
        std::env::temp_dir().join(format!("shardx-e2e-fleet-mismatch-{}", std::process::id()));
    let _guard = spawn_server(&data, port);
    let cl = client();
    wait_health(&cl, port).await;

    let (admin, device_id, account_id, hpke_pk, _sk, device_sk, sk_a) =
        fleet_fixture(&cl, port, &data, 0x68).await;
    let tenant_hex = hex(&TENANT_A);
    let fleet_id: [u8; 16] = [0xF3u8; 16];
    let fleet_hex = hex(&fleet_id);
    seed_fleet(&data, &fleet_id).await;

    // The generation declares one key.
    let declared = shared::fleet_grants::fkek_key_id(&[0x11u8; 32]);
    let generation =
        begin_fleet_generation(&cl, port, &admin, &tenant_hex, &fleet_hex, &declared).await;

    // The grant wraps another.
    let other: [u8; 32] = [0x22u8; 32];
    let scope = shared::fleet_grants::FleetGrantScope {
        replay_id: [0x42u8; 16],
        tenant_id: TENANT_A,
        server_instance_id: INSTANCE,
        restore_epoch: 0,
        fleet_id,
        fkek_key_id: shared::fleet_grants::fkek_key_id(&other),
        generation,
        subject_account_id: account_id.try_into().expect("account id"),
        subject_device_id: device_id.try_into().expect("device id"),
        recipient_hpke_key_id: shared::keys::hpke_key_id(&hpke_pk),
    };
    let sealed = shared::fleet_grants::seal_fkek(&hpke_pk, &scope, &other).expect("seal");
    let record = fleet_grant_record(
        &sk_a,
        &scope,
        &sealed,
        identity_key_id(&device_sk.verifying_key()),
        "FirstFleetSelfGrant",
    );

    let resp = cl
        .post(format!("{}/v2/fleet-key-grants", base(port)))
        .bearer_auth(&admin)
        .json(&json!({ "tenant_id": tenant_hex, "record_hex": hex(&record) }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        409,
        "a grant must not wrap a key the generation did not declare"
    );
}

/// The first fleet grant must be a self grant, exactly one may exist, and only
/// then may the generation activate.
#[tokio::test]
async fn the_first_fleet_grant_must_be_a_unique_self_grant() {
    let port = 38134u16;
    let data = std::env::temp_dir().join(format!("shardx-e2e-fleet-first-{}", std::process::id()));
    let _guard = spawn_server(&data, port);
    let cl = client();
    wait_health(&cl, port).await;

    let (admin, device_id, account_id, hpke_pk, _sk, device_sk, sk_a) =
        fleet_fixture(&cl, port, &data, 0x69).await;
    let tenant_hex = hex(&TENANT_A);
    let fleet_id: [u8; 16] = [0xF4u8; 16];
    let fleet_hex = hex(&fleet_id);
    seed_fleet(&data, &fleet_id).await;

    let fkek: [u8; 32] = [0x5Bu8; 32];
    let fkek_key_id = shared::fleet_grants::fkek_key_id(&fkek);
    let generation =
        begin_fleet_generation(&cl, port, &admin, &tenant_hex, &fleet_hex, &fkek_key_id).await;

    let mut scope = shared::fleet_grants::FleetGrantScope {
        replay_id: [0x43u8; 16],
        tenant_id: TENANT_A,
        server_instance_id: INSTANCE,
        restore_epoch: 0,
        fleet_id,
        fkek_key_id,
        generation,
        subject_account_id: account_id.try_into().expect("account id"),
        subject_device_id: device_id.try_into().expect("device id"),
        recipient_hpke_key_id: shared::keys::hpke_key_id(&hpke_pk),
    };
    let sealed = shared::fleet_grants::seal_fkek(&hpke_pk, &scope, &fkek).expect("seal");
    let subject_key_id = identity_key_id(&device_sk.verifying_key());

    // A custodian-issued grant cannot come first: nothing has proven the key is
    // recoverable yet.
    let premature = fleet_grant_record(&sk_a, &scope, &sealed, subject_key_id, "DeviceHpkeGrant");
    let resp = cl
        .post(format!("{}/v2/fleet-key-grants", base(port)))
        .bearer_auth(&admin)
        .json(&json!({ "tenant_id": tenant_hex, "record_hex": hex(&premature) }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        409,
        "the first fleet grant must be a self grant"
    );

    // The self grant is accepted.
    scope.replay_id = [0x44u8; 16];
    let sealed = shared::fleet_grants::seal_fkek(&hpke_pk, &scope, &fkek).expect("seal");
    let first = fleet_grant_record(
        &sk_a,
        &scope,
        &sealed,
        subject_key_id,
        "FirstFleetSelfGrant",
    );
    let ok = cl
        .post(format!("{}/v2/fleet-key-grants", base(port)))
        .bearer_auth(&admin)
        .json(&json!({ "tenant_id": tenant_hex, "record_hex": hex(&first) }))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status().as_u16(), 200, "the first self grant must store");

    // A second one must not.
    scope.replay_id = [0x45u8; 16];
    let sealed = shared::fleet_grants::seal_fkek(&hpke_pk, &scope, &fkek).expect("seal");
    let dup = fleet_grant_record(
        &sk_a,
        &scope,
        &sealed,
        subject_key_id,
        "FirstFleetSelfGrant",
    );
    let resp = cl
        .post(format!("{}/v2/fleet-key-grants", base(port)))
        .bearer_auth(&admin)
        .json(&json!({ "tenant_id": tenant_hex, "record_hex": hex(&dup) }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        409,
        "a second first-self-grant must be refused"
    );

    // Now activation succeeds and the fleet advertises the generation.
    let act = cl
        .post(format!("{}/v2/fleet-key-generations/activate", base(port)))
        .bearer_auth(&admin)
        .json(&json!({
            "tenant_id": tenant_hex,
            "fleet_id": fleet_hex,
            "generation": generation,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(act.status().as_u16(), 200, "activation must now succeed");

    let active: Value = cl
        .get(format!(
            "{}/v2/tenants/{}/fleets/{}/key-generation",
            base(port),
            tenant_hex,
            fleet_hex
        ))
        .bearer_auth(&admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(active["generation"].as_u64().unwrap(), generation);
    assert_eq!(active["fkek_key_id"].as_str().unwrap(), hex(&fkek_key_id));
}

/// A signed grant that claims some other capability must not be stored as fleet
/// custody. Signature validity is not authority to receive the fleet key: the
/// record has to claim `fleet.key.receive` specifically, or a device holding a
/// grant for an unrelated purpose could collect the key that opens snapshots.
#[tokio::test]
async fn a_fleet_grant_claiming_another_capability_is_refused() {
    let port = 38137u16;
    let data = std::env::temp_dir().join(format!("shardx-e2e-fleet-cap-{}", std::process::id()));
    let _guard = spawn_server(&data, port);
    let cl = client();
    wait_health(&cl, port).await;

    let (admin, device_id, account_id, hpke_pk, _sk, device_sk, sk_a) =
        fleet_fixture(&cl, port, &data, 0x6C).await;
    let tenant_hex = hex(&TENANT_A);
    let fleet_id: [u8; 16] = [0xF7u8; 16];
    let fleet_hex = hex(&fleet_id);
    seed_fleet(&data, &fleet_id).await;

    let fkek: [u8; 32] = [0x5Au8; 32];
    let key_id = shared::fleet_grants::fkek_key_id(&fkek);
    let generation =
        begin_fleet_generation(&cl, port, &admin, &tenant_hex, &fleet_hex, &key_id).await;

    let scope = shared::fleet_grants::FleetGrantScope {
        replay_id: [0x4Au8; 16],
        tenant_id: TENANT_A,
        server_instance_id: INSTANCE,
        restore_epoch: 0,
        fleet_id,
        fkek_key_id: key_id,
        generation,
        subject_account_id: account_id.try_into().expect("account id"),
        subject_device_id: device_id.try_into().expect("device id"),
        recipient_hpke_key_id: shared::keys::hpke_key_id(&hpke_pk),
    };
    let sealed = shared::fleet_grants::seal_fkek(&hpke_pk, &scope, &fkek).expect("seal");

    // Correctly signed, correctly sealed — but claims the rotation capability.
    let record = fleet_grant_record_with_capability(
        &sk_a,
        &scope,
        &sealed,
        identity_key_id(&device_sk.verifying_key()),
        "FirstFleetSelfGrant",
        "key.rotate",
    );

    let resp = cl
        .post(format!("{}/v2/fleet-key-grants", base(port)))
        .bearer_auth(&admin)
        .json(&json!({ "tenant_id": tenant_hex, "record_hex": hex(&record) }))
        .send()
        .await
        .expect("file");
    assert_eq!(
        resp.status().as_u16(),
        400,
        "a grant claiming another capability must not be stored as fleet custody"
    );
}
