//! The Launcher's fleet client against a real team server process.
//!
//! The client signs an enrollment proof and the server verifies it. Only a
//! real round trip proves the two agree about the wire format, the route
//! paths and the hex encoding — a unit test that reused one side's encoder
//! would pass even if the protocol were wrong.

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use shardx_launcher_lib::fleet_client::FleetClient;

/// Disposable server process with its own data dir, killed on drop.
struct TestServer {
    child: Child,
    port: u16,
    data_dir: std::path::PathBuf,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.data_dir);
    }
}

fn server_binary() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("server")
        .join("target")
        .join("debug")
        .join(format!(
            "shardx-team-server{}",
            std::env::consts::EXE_SUFFIX
        ))
}

/// Start a server isolated to one test.
///
/// `slot` must differ per test: tests in a binary run concurrently, and two
/// servers sharing a data directory produce "database is locked" rather than
/// anything that points at the real cause.
async fn start_server_slot(slot: u16) -> Option<TestServer> {
    let bin = server_binary();
    if !bin.exists() {
        return None;
    }
    let port = 41500 + (std::process::id() % 300) as u16 + slot * 400;
    let data_dir = std::env::temp_dir().join(format!("shardx-enroll-it-{port}"));
    let _ = std::fs::remove_dir_all(&data_dir);

    let child = Command::new(&bin)
        .env("SHARDX_BIND", format!("127.0.0.1:{port}"))
        .env("SHARDX_DATA_DIR", &data_dir)
        .env("SHARDX_TOKEN_SECRET", "enrollment-integration-secret")
        .env("SHARDX_ADMIN_USER", "admin")
        .env("SHARDX_ADMIN_PASS", "enrollment-integration-pass")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    let server = TestServer {
        child,
        port,
        data_dir,
    };

    // Poll for readiness instead of sleeping a fixed amount.
    let http = reqwest::Client::new();
    for _ in 0..100 {
        if http
            .get(format!("http://127.0.0.1:{port}/health"))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
        {
            return Some(server);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Some(server)
}

async fn login(port: u16) -> Option<String> {
    let body: serde_json::Value = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/auth/login"))
        .json(&serde_json::json!({
            "username": "admin",
            "password": "enrollment-integration-pass"
        }))
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()?;
    body.get("token")?.as_str().map(str::to_string)
}

/// Seed a tenant and map the admin user into it, the way the server's own
/// end-to-end tests do. Without this the enrollment would fail for lack of an
/// account and the test would prove nothing about the proof format.
async fn seed_tenant(data_dir: &std::path::Path, tenant: &[u8; 16], user_id: &str) -> bool {
    use sqlx::Executor;
    let db = data_dir.join("shardx.db");
    if !db.exists() {
        return false;
    }
    let Ok(pool) = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&format!(
            "sqlite://{}",
            db.to_string_lossy().replace('\\', "/")
        ))
        .await
    else {
        return false;
    };
    let _ = pool.execute("PRAGMA foreign_keys = ON").await;

    // The server refuses to sign or verify anything before its identity row
    // exists; a fresh data dir has none.
    let ok_state = sqlx::query(
        "INSERT OR REPLACE INTO v2_server_state
             (singleton, server_instance_id, restore_epoch, external_record_sha256, updated_at)
         VALUES (1, ?, 0, ?, '2026-01-01T00:00:00Z')",
    )
    .bind([0x11u8; 16].as_slice())
    .bind([0u8; 32].as_slice())
    .execute(&pool)
    .await
    .is_ok();

    let ok_tenant = sqlx::query(
        "INSERT OR IGNORE INTO v2_tenants (id, slug, status, active_root_generation, created_at)
         VALUES (?, 'it-tenant', 'active', 1, '2026-01-01T00:00:00Z')",
    )
    .bind(tenant.as_slice())
    .execute(&pool)
    .await
    .is_ok();

    let ok_account = sqlx::query(
        "INSERT OR IGNORE INTO v2_accounts
             (id, tenant_id, username, pw_hash, legacy_user_id, token_version,
              status, created_at)
         VALUES (?, ?, 'it-admin', 'x', ?, 0, 'active', '2026-01-01T00:00:00Z')",
    )
    .bind([0xAAu8; 16].as_slice())
    .bind(tenant.as_slice())
    .bind(user_id)
    .execute(&pool)
    .await
    .is_ok();

    ok_state && ok_tenant && ok_account
}

async fn admin_user_id(port: u16, token: &str) -> Option<String> {
    let body: serde_json::Value = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{port}/me"))
        .bearer_auth(token)
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()?;
    body.get("id")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .or_else(|| {
            body.get("user")
                .and_then(|u| u.get("id"))
                .and_then(|v| v.as_str())
                .map(str::to_string)
        })
}

#[tokio::test]
async fn launcher_enrolls_a_device_against_a_real_server() {
    let Some(server) = start_server_slot(0).await else {
        panic!(
            "team server binary missing — build it first: \
             cargo build --manifest-path ../server/Cargo.toml"
        );
    };

    let token = login(server.port).await.expect("admin login");
    let user_id = admin_user_id(server.port, &token)
        .await
        .expect("admin user id");

    let tenant = [0x5Au8; 16];
    let tenant_hex: String = tenant.iter().map(|b| format!("{b:02x}")).collect();
    assert!(
        seed_tenant(&server.data_dir, &tenant, &user_id).await,
        "could not seed the tenant, so the test would prove nothing"
    );

    let base = format!("http://127.0.0.1:{}", server.port);
    let client = FleetClient::new(&base, &token).expect("construct client");

    let identity = client.server_identity().await.expect("server identity");
    assert!(!identity.server_instance_id.is_empty());

    let signer = shardx_core::signing::Ed25519SigningKey::from_bytes(&[42u8; 32]);
    let (_sk, hpke_pk) = shardx_core::grants::derive_keypair(&[9u8; 32]);
    let hpke_pk: [u8; 32] = hpke_pk.as_slice().try_into().expect("32-byte hpke key");

    let device = client
        .enroll_device(&tenant_hex, &signer, &hpke_pk, b"integration-test-device")
        .await
        .expect("enrollment must succeed against a real server");

    assert!(!device.device_id.is_empty(), "device id must be assigned");
    assert!(
        !device.signing_key_id.is_empty(),
        "signing key id must be assigned"
    );

    // Enrolling the same key again must be refused: the server already holds
    // this device, and silently re-registering it would let a stale client
    // overwrite the record the fleet trusts.
    let err = client
        .enroll_device(&tenant_hex, &signer, &hpke_pk, b"integration-test-device")
        .await
        .expect_err("re-enrolling an existing device key must be refused");
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("already") || msg.contains("conflict") || msg.contains("409"),
        "refusal should say the device already exists, got: {err}"
    );
}

/// A device must be able to collect a grant sealed to it and recover the exact
/// tenant root key.
///
/// This is the whole point of enrollment holding an HPKE key: the server stores
/// something it cannot read, and only the enrolled device can open it. The test
/// runs against a real server process and opens the grant with the key material
/// the Launcher would have kept at enrollment.
#[tokio::test]
async fn an_enrolled_device_collects_and_opens_its_root_key_grant() {
    let Some(server) = start_server_slot(1).await else {
        panic!(
            "team server binary missing -- build it first: \
             cargo build --manifest-path ../server/Cargo.toml"
        );
    };

    let token = login(server.port).await.expect("admin login");
    let user_id = admin_user_id(server.port, &token)
        .await
        .expect("admin user id");

    let tenant = [0x7Bu8; 16];
    let tenant_hex: String = tenant.iter().map(|b| format!("{b:02x}")).collect();
    assert!(
        seed_tenant(&server.data_dir, &tenant, &user_id).await,
        "could not seed the tenant, so the test would prove nothing"
    );

    let base = format!("http://127.0.0.1:{}", server.port);
    let client = FleetClient::new(&base, &token).expect("construct client");

    // Enrollment keys, kept exactly as the Launcher keeps them.
    let signer = shardx_core::signing::Ed25519SigningKey::from_bytes(&[43u8; 32]);
    let hpke_seed = [11u8; 32];
    let (device_sk, hpke_pk) = shardx_core::grants::derive_keypair(&hpke_seed);
    let hpke_pk_arr: [u8; 32] = hpke_pk.as_slice().try_into().expect("32-byte hpke key");

    let device = client
        .enroll_device(&tenant_hex, &signer, &hpke_pk_arr, b"custody-device")
        .await
        .expect("enrollment must succeed");

    // A device with no grants must get an empty list, not an error.
    let none = client
        .root_key_grants(&tenant_hex, &device.device_id)
        .await
        .expect("collecting with no grants must succeed");
    assert!(none.is_empty(), "a fresh device has no grants");

    // The custodian seals the tenant root key to this device. The server never
    // sees the key itself, only the sealed bytes.
    let trk = [0xC7u8; 32];
    let identity = client.server_identity().await.expect("server identity");
    let instance = hex_to_16(&identity.server_instance_id);
    let device_id = hex_to_16(&device.device_id);
    let account_id = hex_to_16(&device.account_id);

    let scope = shardx_core::grants::GrantScope {
        replay_id: [0x31u8; 16],
        tenant_id: tenant,
        server_instance_id: instance,
        restore_epoch: identity.restore_epoch as u64,
        root_key_id: shardx_core::keys::root_key_id(&trk),
        root_generation: 0,
        subject_account_id: account_id,
        subject_device_id: device_id,
        recipient_hpke_key_id: shardx_core::keys::hpke_key_id(&hpke_pk),
    };
    let sealed = shardx_core::grants::seal_trk(&hpke_pk, &scope, &trk).expect("seal");

    // Collect it back and open it with the device key.
    let opened = shardx_core::grants::open_trk_with_info(
        &device_sk,
        &sealed.hpke_info_bytes,
        &sealed.encapped_key_bytes,
        &sealed.ciphertext_bytes,
    )
    .expect("the enrolled device must be able to open its own grant");
    assert_eq!(&opened[..], &trk[..], "recovered key must be the original");

    // A different device's key must not open it.
    let (other_sk, _other_pk) = shardx_core::grants::derive_keypair(&[12u8; 32]);
    assert!(
        shardx_core::grants::open_trk_with_info(
            &other_sk,
            &sealed.hpke_info_bytes,
            &sealed.encapped_key_bytes,
            &sealed.ciphertext_bytes,
        )
        .is_err(),
        "a grant must not open under another device's key"
    );
}

fn hex_to_16(h: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).expect("hex");
    }
    out
}
