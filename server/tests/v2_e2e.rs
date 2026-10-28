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

use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
use serde_json::{json, Value};
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::Executor;

use shardx_team_server::identity_record::{external_record_sha256, IdentityRecordV2};
use shared::canonical as c;
use shared::signing::{identity_key_id, Ed25519SigningKey};

// Test ports are fixed at 28xxx: below the Linux ephemeral range (32768+),
// where a parallel test's client socket could already hold them.
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

/// Start the server with a verified identity: an epoch-0 record for
/// `INSTANCE` and its mirror, provisioned before startup as `identity init`
/// would, so the records these tests sign bind to a known instance.
async fn spawn_server(data: &std::path::Path, port: u16) -> ServerGuard {
    let _ = std::fs::remove_dir_all(data);
    let identity = data.with_extension("identity");
    let _ = std::fs::remove_dir_all(&identity);
    std::fs::create_dir_all(data).unwrap();
    std::fs::create_dir_all(&identity).unwrap();

    let bytes = IdentityRecordV2::genesis(INSTANCE, 1_790_985_600_000)
        .encode()
        .unwrap();
    std::fs::write(identity.join("identity-record-v2.bin"), bytes).unwrap();
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&format!(
            "sqlite://{}/shardx.db?mode=rwc",
            data.to_string_lossy().replace('\\', "/")
        ))
        .await
        .expect("create server db");
    shardx_team_server::run_migrations(&pool).await.unwrap();
    sqlx::query(
        "INSERT INTO v2_server_state
             (singleton, server_instance_id, restore_epoch, external_record_sha256, updated_at)
         VALUES (1, ?, 0, ?, '2026-01-01T00:00:00Z')",
    )
    .bind(INSTANCE.as_slice())
    .bind(external_record_sha256(&bytes).as_slice())
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;

    let bin = env!("CARGO_BIN_EXE_shardx-team-server");
    let child = Command::new(bin)
        .env("SHARDX_BIND", format!("127.0.0.1:{port}"))
        .env("SHARDX_DATA_DIR", data)
        .env("SHARDX_IDENTITY_DIR", &identity)
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

/// Seed the v2 tables the endpoints read: two tenants, an issuer per tenant, and a v2 account linked to the v1 admin user.
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

        // The same password as the v1 admin: enrollment logs in as this v2
        // account, while the fleet routes still map the v1 user through
        // `legacy_user_id`.
        let pw_hash = argon2::Argon2::default()
            .hash_password(b"secret", &SaltString::generate(&mut OsRng))
            .unwrap()
            .to_string();
        sqlx::query(
            "INSERT INTO v2_accounts
                 (id, tenant_id, username, pw_hash, legacy_user_id, status, created_at)
             VALUES (?, ?, 'admin', ?, ?, 'active', '2026-01-01T00:00:00Z')",
        )
        .bind([1u8; 16].as_slice())
        .bind(tid.as_slice())
        .bind(&pw_hash)
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO v2_tenant_memberships VALUES (?, ?, 'owner', 'active', '2026-01-01T00:00:00Z')",
        )
        .bind(tid.as_slice())
        .bind([1u8; 16].as_slice())
        .execute(&pool)
        .await
        .unwrap();
    }

    pool.close().await;
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
async fn a_v1_token_cannot_file_a_capability_grant() {
    let port = 28111u16;
    let data = std::env::temp_dir().join(format!("shardx-e2e-v2-{}", std::process::id()));
    let _guard = spawn_server(&data, port).await;
    let cl = client();
    wait_health(&cl, port).await;
    let admin = token(&cl, port, "admin", "secret").await;

    // Filing needs the issuer's v2 device session; the custody rules
    // themselves are covered in v2_auth.rs.
    for bearer in [Some(admin.as_str()), None] {
        let mut r = cl
            .post(format!("{}/v2/capability-grants", base(port)))
            .header("content-type", "application/cbor")
            .body(vec![0xa0]);
        if let Some(b) = bearer {
            r = r.bearer_auth(b);
        }
        assert_eq!(r.send().await.unwrap().status(), 401, "{bearer:?}");
    }
}

#[tokio::test]
async fn v2_operations_replay_the_stored_response() {
    let port = 28112u16;
    let data = std::env::temp_dir().join(format!("shardx-e2e-v2op-{}", std::process::id()));
    let _guard = spawn_server(&data, port).await;
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
    let port = 28113u16;
    let data = std::env::temp_dir().join(format!("shardx-e2e-v2id-{}", std::process::id()));
    let _guard = spawn_server(&data, port).await;
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
    let port = 28114u16;
    let data = std::env::temp_dir().join(format!("shardx-e2e-manifest-{}", std::process::id()));
    let _guard = spawn_server(&data, port).await;
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

    // A body value outside the unsigned domain is a mismatch, not a value to
    // clamp: -1 must not pass as a signed 0 and fail only after the staged
    // blob has been promoted, which would strand this session.
    for (field, replay) in [("key_generation", 0x57u8), ("base_version", 0x58u8)] {
        let fields = shared::fleet_manifest::ManifestFields {
            tenant_id: TENANT_A,
            server_instance_id: INSTANCE,
            restore_epoch: restore_epoch as u64,
            replay_id: [replay; 16],
            profile_id: profile,
            snapshot_id: snapshot,
            fleet_id: fleet,
            base_version: 0,
            key_generation: 0,
            container_sha256: container_sha,
            not_before_ms: now_ms.saturating_sub(60_000),
            not_after_ms: now_ms + 300_000,
        };
        let zero = shared::fleet_manifest::build_snapshot_manifest(&sk_a, &fields);
        let mut body = json!({
            "tenant_id": tenant_hex,
            "profile_id": profile_hex,
            "session_id": session_id,
            "manifest_hex": hex(&zero),
            "snapshot_id": hex(&snapshot),
            "fleet_id": hex(&fleet),
            "base_version": 0,
            "key_generation": 0,
            "container_sha256": hex(&container_sha),
            "author_account_id": hex(&[1u8; 16]),
            "author_device_id": hex(&[4u8; 16]),
        });
        body[field] = json!(-1);
        let negative = cl
            .post(format!("{}/v2/fleet/uploads/commit", base(port)))
            .bearer_auth(&admin)
            .json(&body)
            .send()
            .await
            .unwrap();
        let st = negative.status();
        let text = negative.text().await.unwrap();
        assert_eq!(st, reqwest::StatusCode::BAD_REQUEST, "{field} -1: {text}");
        assert!(text.contains("signed manifest"), "{field} -1: {text}");
    }

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
    let port = 28115u16;
    let data = std::env::temp_dir().join(format!("shardx-e2e-mismatch-{}", std::process::id()));
    let _guard = spawn_server(&data, port).await;
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
    let port = 28117u16;
    let data = std::env::temp_dir().join(format!("shardx-e2e-crosstenant-{}", std::process::id()));
    let _guard = spawn_server(&data, port).await;
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
/// matching private key, and only under a v2 account's pre-device ticket.
///
/// A registration endpoint that skipped the proof would let anyone bind a
/// public key they do not control, and every later manifest signed by the
/// real holder would be attributed to whoever registered it first.
#[tokio::test]
async fn device_enrollment_requires_proof_of_possession() {
    let port = 28118u16;
    let data = std::env::temp_dir().join(format!("shardx-e2e-enroll-{}", std::process::id()));
    let _guard = spawn_server(&data, port).await;
    let cl = client();
    wait_health(&cl, port).await;

    let admin = token(&cl, port, "admin", "secret").await;
    let user_id = admin_user_id(&cl, port, &admin).await;
    let sk_a = Ed25519SigningKey::from_bytes(&[11u8; 32]);
    let sk_b = Ed25519SigningKey::from_bytes(&[22u8; 32]);
    seed(&data, &user_id, &sk_a, &sk_b).await;

    // The device key pair being enrolled. The binding names both keys, so
    // they are fixed before the server issues it.
    let device_sk = Ed25519SigningKey::from_bytes(&[0x44u8; 32]);
    let device_vk = device_sk.verifying_key().to_bytes();
    let (_, hpke_pk) = shared::grants::derive_keypair(&[0x55u8; 32]);
    let hpke_pk: [u8; 32] = hpke_pk.try_into().unwrap();

    // A v1 session token is not a ticket.
    let (status, _) = enrollment_challenge(&cl, port, &admin, &device_vk, &hpke_pk).await;
    assert_eq!(status, 401, "enrollment needs a pre-device ticket");

    let t = ticket(&cl, port, &TENANT_A).await;
    let (status, ch) = enrollment_challenge(&cl, port, &t, &device_vk, &hpke_pk).await;
    assert_eq!(status, 201, "{ch}");
    let binding = decode_hex_str(ch["binding"].as_str().unwrap());
    let parsed = shared::session_binding::EnrollmentBindingV2::parse(&binding).unwrap();
    assert_eq!(parsed.fields.tenant_id, TENANT_A);
    assert_eq!(parsed.fields.signing_public_key, device_vk);
    assert_eq!(parsed.fields.hpke_public_key, hpke_pk);

    // A signature from the wrong key must not enroll the device, and it
    // spends the challenge.
    let (status, _) = prove_enrollment(&cl, port, &t, &ch, &sk_b).await;
    assert_eq!(
        status, 401,
        "a proof signed by another key must not enroll the device"
    );
    let (status, _) = prove_enrollment(&cl, port, &t, &ch, &device_sk).await;
    assert_eq!(status, 401, "a refused proof burns its challenge");

    // The real holder succeeds with a fresh challenge.
    let (_, ch) = enrollment_challenge(&cl, port, &t, &device_vk, &hpke_pk).await;
    let (status, enrolled) = prove_enrollment(&cl, port, &t, &ch, &device_sk).await;
    assert_eq!(status, 201, "valid proof should enroll, got: {enrolled}");
    let device_id = enrolled["device_id"].as_str().unwrap().to_string();
    assert_eq!(device_id.len(), 32, "device id should be a 16-byte hex id");
    assert_eq!(enrolled["account_id"], hex(&[1u8; 16]));

    // Enrollment must use the same domain-separated ids as the grant codecs.
    // Successful enrollment alone did not catch HPKE keys being assigned a
    // signing-key id, which makes later recipient bindings disagree.
    let expected_signing_id = shared::keys::signing_key_id(&device_vk);
    let expected_hpke_id = shared::keys::hpke_key_id(&hpke_pk);
    assert_eq!(enrolled["signing_key_id"], hex(&expected_signing_id));
    assert_eq!(enrolled["hpke_key_id"], hex(&expected_hpke_id));
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&format!(
            "sqlite://{}/shardx.db",
            data.display().to_string().replace('\\', "/")
        ))
        .await
        .unwrap();
    let stored: (Vec<u8>, Vec<u8>, String) = sqlx::query_as(
        "SELECT signing_key_id, hpke_key_id, status FROM v2_devices \
         WHERE tenant_id = ? AND id = ?",
    )
    .bind(TENANT_A.as_slice())
    .bind(decode_hex_str(&device_id))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stored.0, expected_signing_id);
    assert_eq!(stored.1, expected_hpke_id);
    // Plan L369: proof of possession alone leaves the device pending.
    assert_eq!(stored.2, "pending");
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM v2_audit_events WHERE action = 'auth.device_enrolled' \
         AND tenant_id = ? AND actor_device_id = ?",
    )
    .bind(TENANT_A.as_slice())
    .bind(decode_hex_str(&device_id))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        audited, 1,
        "enrollment writes its audit row with the device"
    );
    pool.close().await;

    // The challenge is single-use: replaying the same valid proof must fail,
    // or an intercepted proof could enroll a second device.
    let (status, _) = prove_enrollment(&cl, port, &t, &ch, &device_sk).await;
    assert_eq!(
        status, 401,
        "a consumed challenge must not enroll a second device"
    );
    // A ticket of the other tenant cannot redeem this tenant's challenge.
    let other = ticket(&cl, port, &TENANT_B).await;
    let (_, ch) = enrollment_challenge(
        &cl,
        port,
        &t,
        &Ed25519SigningKey::from_bytes(&[0x47u8; 32])
            .verifying_key()
            .to_bytes(),
        &shared::grants::derive_keypair(&[0x57u8; 32])
            .1
            .try_into()
            .unwrap(),
    )
    .await;
    let (status, _) = prove_enrollment(
        &cl,
        port,
        &other,
        &ch,
        &Ed25519SigningKey::from_bytes(&[0x47u8; 32]),
    )
    .await;
    assert_eq!(status, 404, "a challenge belongs to its own ticket");
}

fn decode_hex_str(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// A pre-device ticket for the seeded `admin` account of `tenant`, named by
/// ID the way the Launcher names it.
async fn ticket(cl: &reqwest::Client, port: u16, tenant: &[u8; 16]) -> String {
    let res = cl
        .post(format!("{}/v2/auth/login", base(port)))
        .json(&json!({ "tenant_id": hex(tenant), "username": "admin", "password": "secret" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 201);
    let body: Value = res.json().await.unwrap();
    body["ticket"].as_str().unwrap().to_string()
}

async fn enrollment_challenge(
    cl: &reqwest::Client,
    port: u16,
    bearer: &str,
    signing_public_key: &[u8; 32],
    hpke_public_key: &[u8; 32],
) -> (u16, Value) {
    let res = cl
        .post(format!("{}/v2/devices/enrollment-challenges", base(port)))
        .bearer_auth(bearer)
        .json(&json!({
            "signing_public_key": hex(signing_public_key),
            "hpke_public_key": hex(hpke_public_key),
        }))
        .send()
        .await
        .unwrap();
    let status = res.status().as_u16();
    (status, res.json().await.unwrap_or(Value::Null))
}

/// Sign the challenge's binding with `signer` and submit it.
async fn prove_enrollment(
    cl: &reqwest::Client,
    port: u16,
    ticket: &str,
    challenge: &Value,
    signer: &Ed25519SigningKey,
) -> (u16, Value) {
    let binding = decode_hex_str(challenge["binding"].as_str().unwrap());
    let res = cl
        .post(format!("{}/v2/devices/enrollment-proofs", base(port)))
        .bearer_auth(ticket)
        .json(&json!({
            "challenge_id": challenge["challenge_id"],
            "signature": hex(&shared::session_binding::sign_enrollment(signer, &binding)),
            "label_ciphertext": hex(b"opaque"),
        }))
        .send()
        .await
        .unwrap();
    let status = res.status().as_u16();
    (status, res.json().await.unwrap_or(Value::Null))
}

#[tokio::test]
async fn duplicate_hpke_keys_are_rejected_across_enrollment_versions() {
    let port = 28138u16;
    let data = std::env::temp_dir().join(format!("shardx-e2e-hpke-upgrade-{}", std::process::id()));
    let _guard = spawn_server(&data, port).await;
    let cl = client();
    wait_health(&cl, port).await;
    let admin = token(&cl, port, "admin", "secret").await;
    let user_id = admin_user_id(&cl, port, &admin).await;
    let sk_a = Ed25519SigningKey::from_bytes(&[11u8; 32]);
    let sk_b = Ed25519SigningKey::from_bytes(&[22u8; 32]);
    seed(&data, &user_id, &sk_a, &sk_b).await;

    let original_signer = Ed25519SigningKey::from_bytes(&[0x45u8; 32]);
    let (_, hpke_pk) = shared::grants::derive_keypair(&[0x56u8; 32]);
    let hpke_pk: [u8; 32] = hpke_pk.try_into().unwrap();
    // A second challenge for the same HPKE key, issued before the first
    // enrollment lands: only the proof's own check can refuse it.
    let t = ticket(&cl, port, &TENANT_A).await;
    let racing_signer = Ed25519SigningKey::from_bytes(&[0x48u8; 32]);
    let (status, racing) = enrollment_challenge(
        &cl,
        port,
        &t,
        &racing_signer.verifying_key().to_bytes(),
        &hpke_pk,
    )
    .await;
    assert_eq!(status, 201, "{racing}");
    let (original_device, _) = enroll(&cl, port, &TENANT_A, &original_signer, &hpke_pk).await;
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&format!(
            "sqlite://{}/shardx.db",
            data.display().to_string().replace('\\', "/")
        ))
        .await
        .unwrap();
    let (status, body) = prove_enrollment(&cl, port, &t, &racing, &racing_signer).await;
    assert_eq!(status, 409, "{body}");
    let racing_id = decode_hex_str(racing["challenge_id"].as_str().unwrap());
    let revoked: Option<i64> =
        sqlx::query_scalar("SELECT revoked_at_ms FROM v2_enrollment_challenges WHERE id = ?")
            .bind(&racing_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(revoked.is_some(), "a refused proof ends its challenge");

    let replacement_signer = Ed25519SigningKey::from_bytes(&[0x46u8; 32]);
    let replacement_vk = replacement_signer.verifying_key().to_bytes();

    // Model an upgrade without rewriting existing ids in the product path.
    // Both current and historical rows must reject reusing the same HPKE key.
    for legacy in [false, true] {
        let stored_id = if legacy {
            shared::keys::signing_key_id(&hpke_pk)
        } else {
            shared::keys::hpke_key_id(&hpke_pk)
        };
        sqlx::query("UPDATE v2_devices SET hpke_key_id = ? WHERE tenant_id = ? AND id = ?")
            .bind(stored_id.as_slice())
            .bind(TENANT_A.as_slice())
            .bind(&original_device)
            .execute(&pool)
            .await
            .unwrap();
        let (status, body) = enrollment_challenge(&cl, port, &t, &replacement_vk, &hpke_pk).await;
        assert_eq!(status, 409, "duplicate HPKE key accepted (legacy={legacy})");
        assert_eq!(
            body["error"],
            "these keys are already enrolled in this tenant"
        );
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM v2_devices WHERE tenant_id = ?")
            .bind(TENANT_A.as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1, "a refused enrollment must not insert a device");
        let after: Vec<u8> =
            sqlx::query_scalar("SELECT hpke_key_id FROM v2_devices WHERE tenant_id = ? AND id = ?")
                .bind(TENANT_A.as_slice())
                .bind(&original_device)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(after, stored_id, "refusal must not rewrite historical ids");
    }
    pool.close().await;
}

/// Enroll a device over HTTP and return its id and account id.
///
/// Enrollment rather than a direct insert, because a grant is bound to a device
/// the server considers enrolled; seeding the row directly would prove the
/// storage path works against a device state the enrollment path cannot produce.
async fn enroll(
    cl: &reqwest::Client,
    port: u16,
    tenant: &[u8; 16],
    device_sk: &Ed25519SigningKey,
    hpke_pk: &[u8; 32],
) -> (Vec<u8>, Vec<u8>) {
    let t = ticket(cl, port, tenant).await;
    let device_vk = device_sk.verifying_key().to_bytes();
    let (status, ch) = enrollment_challenge(cl, port, &t, &device_vk, hpke_pk).await;
    assert_eq!(status, 201, "{ch}");
    let (status, enrolled) = prove_enrollment(cl, port, &t, &ch, device_sk).await;
    assert_eq!(status, 201, "{enrolled}");
    let device_id = decode_hex_str(enrolled["device_id"].as_str().expect("device_id"));
    let account_id = decode_hex_str(enrolled["account_id"].as_str().expect("account_id"));
    (device_id, account_id)
}

/// The legacy fleet key routes are gone (G2-03): they wrote the same
/// generations table as the D-9 lifecycle while skipping its grant filing,
/// acknowledgements and required sets.
#[tokio::test]
async fn the_legacy_fleet_key_routes_are_gone() {
    let port = 28131u16;
    let data = std::env::temp_dir().join(format!("shardx-e2e-fleet-gone-{}", std::process::id()));
    let _guard = spawn_server(&data, port).await;
    let cl = client();
    wait_health(&cl, port).await;
    let admin = token(&cl, port, "admin", "secret").await;

    let (t, d) = (hex(&TENANT_A), hex(&[0x44u8; 16]));
    for (post, path) in [
        (true, "/v2/fleet-key-grants".to_string()),
        (true, "/v2/fleet-key-generations".to_string()),
        (true, "/v2/fleet-key-generations/activate".to_string()),
        (
            false,
            format!("/v2/tenants/{t}/devices/{d}/fleet-key-grants"),
        ),
    ] {
        let url = format!("{}{path}", base(port));
        let req = if post {
            cl.post(url).json(&json!({}))
        } else {
            cl.get(url)
        };
        let status = req.bearer_auth(&admin).send().await.unwrap().status();
        assert_eq!(status.as_u16(), 404, "{path}");
    }
}
