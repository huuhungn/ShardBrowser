//! The Launcher's fleet transfer client against a real team server process.
//!
//! A sealed container goes up and the same bytes come back down. Only a real
//! round trip proves client and server agree on the manifest encoding, the
//! chunk staging protocol and the commit signature binding — a unit test that
//! reused one side's encoder would pass even if the protocol were wrong. That
//! is exactly how #17's original claim went unnoticed.

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use shardx_launcher_lib::fleet_client::{FleetClient, UploadRequest};

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

async fn start_server() -> Option<TestServer> {
    start_server_slot(0).await
}

/// Start a server on its own port with its own data directory.
///
/// Each test needs a distinct slot: sharing a SQLite file across concurrent
/// tests produces "database is locked", which looks like a protocol failure
/// but is only test interference.
async fn start_server_slot(slot: u16) -> Option<TestServer> {
    let bin = server_binary();
    if !bin.exists() {
        return None;
    }
    // Distinct from the enrollment test's range so the two can run together.
    let port = 41900 + (std::process::id() % 300) as u16 + slot * 400;
    let data_dir = std::env::temp_dir().join(format!("shardx-sync-it-{port}"));
    let _ = std::fs::remove_dir_all(&data_dir);

    let child = Command::new(&bin)
        .env("SHARDX_BIND", format!("127.0.0.1:{port}"))
        .env("SHARDX_DATA_DIR", &data_dir)
        .env("SHARDX_TOKEN_SECRET", "sync-integration-secret")
        .env("SHARDX_ADMIN_USER", "admin")
        .env("SHARDX_ADMIN_PASS", "sync-integration-pass")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    let server = TestServer {
        child,
        port,
        data_dir,
    };

    let http = reqwest::Client::new();
    for _ in 0..100 {
        if http
            .get(format!("http://127.0.0.1:{port}/health"))
            .send()
            .await
            .is_ok()
        {
            return Some(server);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    None
}

async fn login(port: u16) -> Option<String> {
    let body: serde_json::Value = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/auth/login"))
        .json(&serde_json::json!({
            "username": "admin",
            "password": "sync-integration-pass"
        }))
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()?;
    body.get("token")?.as_str().map(str::to_string)
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

/// Seed everything a fleet upload needs: server identity, tenant, account,
/// membership, fleet and profile. Any missing row makes the upload fail for a
/// reason unrelated to the wire format, so each insert is checked.
#[allow(clippy::too_many_arguments)]
async fn seed_fleet(
    data_dir: &std::path::Path,
    tenant: &[u8; 16],
    fleet: &[u8; 16],
    profile: &[u8; 16],
    account: &[u8; 16],
    user_id: &str,
) -> bool {
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

    let now = "2026-01-01T00:00:00Z";

    let ok_state = sqlx::query(
        "INSERT OR REPLACE INTO v2_server_state
             (singleton, server_instance_id, restore_epoch, external_record_sha256, updated_at)
         VALUES (1, ?, 0, ?, ?)",
    )
    .bind([0x22u8; 16].as_slice())
    .bind([0u8; 32].as_slice())
    .bind(now)
    .execute(&pool)
    .await
    .is_ok();

    let ok_tenant = sqlx::query(
        "INSERT OR IGNORE INTO v2_tenants (id, slug, status, active_root_generation, created_at)
         VALUES (?, 'sync-tenant', 'active', 1, ?)",
    )
    .bind(tenant.as_slice())
    .bind(now)
    .execute(&pool)
    .await
    .is_ok();

    // `legacy_user_id` is how a v1 session token resolves to a v2 account, so
    // the authenticated admin must map to this account for the upload to be
    // authorized as it.
    let ok_account = sqlx::query(
        "INSERT OR IGNORE INTO v2_accounts
             (id, tenant_id, username, pw_hash, legacy_user_id, status, created_at)
         VALUES (?, ?, 'sync-account', 'x', ?, 'active', ?)",
    )
    .bind(account.as_slice())
    .bind(tenant.as_slice())
    .bind(user_id)
    .bind(now)
    .execute(&pool)
    .await
    .is_ok();

    // Without this the tenant-boundary check added in #21 rejects the upload.
    let ok_member = sqlx::query(
        "INSERT OR IGNORE INTO v2_tenant_memberships
             (tenant_id, account_id, role, status, created_at)
         VALUES (?, ?, 'owner', 'active', ?)",
    )
    .bind(tenant.as_slice())
    .bind(account.as_slice())
    .bind(now)
    .execute(&pool)
    .await
    .is_ok();

    let ok_fleet = sqlx::query(
        "INSERT OR IGNORE INTO v2_fleets (id, tenant_id, name, status, created_at)
         VALUES (?, ?, 'sync-fleet', 'active', ?)",
    )
    .bind(fleet.as_slice())
    .bind(tenant.as_slice())
    .bind(now)
    .execute(&pool)
    .await
    .is_ok();

    let ok_profile = sqlx::query(
        "INSERT OR IGNORE INTO v2_profiles
             (id, tenant_id, fleet_id, name, current_version, status, created_at, updated_at)
         VALUES (?, ?, ?, 'sync-profile', 0, 'active', ?, ?)",
    )
    .bind(profile.as_slice())
    .bind(tenant.as_slice())
    .bind(fleet.as_slice())
    .bind(now)
    .bind(now)
    .execute(&pool)
    .await
    .is_ok();

    // The commit signature is only accepted from a registered tenant issuer.
    // Enrollment is what registers a device key in production; seeding it here
    // keeps this test focused on the transfer protocol.
    let vk = signer_public_key();
    let ok_issuer = sqlx::query(
        "INSERT OR IGNORE INTO v2_tenant_issuers
             (tenant_id, signing_key_id, public_key, added_at)
         VALUES (?, ?, ?, ?)",
    )
    .bind(tenant.as_slice())
    .bind(shardx_core::keys::signing_key_id(&vk).as_slice())
    .bind(vk.as_slice())
    .bind(now)
    .execute(&pool)
    .await
    .is_ok();

    ok_state && ok_tenant && ok_account && ok_member && ok_fleet && ok_profile && ok_issuer
}

/// The public key of the signer the test uploads with.
fn signer_public_key() -> [u8; 32] {
    shardx_core::signing::Ed25519SigningKey::from_bytes(&SIGNER_SEED)
        .verifying_key()
        .to_bytes()
}

/// Fixed seed so the seeded issuer and the uploading signer are the same key.
const SIGNER_SEED: [u8; 32] = [7u8; 32];

fn hex16(b: &[u8; 16]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[tokio::test]
async fn launcher_pushes_and_pulls_a_container_through_a_real_server() {
    let Some(server) = start_server().await else {
        panic!(
            "team server binary missing — build it first: \
             cargo build --manifest-path ../server/Cargo.toml"
        );
    };

    let token = login(server.port).await.expect("admin login");
    let user_id = admin_user_id(server.port, &token)
        .await
        .expect("admin user id");

    let tenant = [0x7Au8; 16];
    let fleet = [0x7Bu8; 16];
    let profile = [0x7Cu8; 16];
    let account = [0x7Du8; 16];
    let device = [0x7Eu8; 16];

    assert!(
        seed_fleet(
            &server.data_dir,
            &tenant,
            &fleet,
            &profile,
            &account,
            &user_id
        )
        .await,
        "could not seed the fleet, so the test would prove nothing"
    );

    let base = format!("http://127.0.0.1:{}", server.port);
    let client = FleetClient::new(&base, &token).expect("construct client");
    let signer = shardx_core::signing::Ed25519SigningKey::from_bytes(&SIGNER_SEED);

    // Stand in for a sealed profile container. The transfer layer treats it as
    // opaque bytes, which is the property under test; sealing is covered by the
    // backup tests. Large enough to span more than one staged chunk.
    let container: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();

    let version = client
        .upload(
            &UploadRequest {
                tenant_id: &hex16(&tenant),
                profile_id: &hex16(&profile),
                fleet_id: &hex16(&fleet),
                snapshot_id: &hex16(&[0x7Fu8; 16]),
                account_id: &hex16(&account),
                device_id: &hex16(&device),
                key_generation: 1,
                base_version: 0,
                container: &container,
            },
            &signer,
            120,
        )
        .await
        .expect("upload must succeed against a real server");

    assert_eq!(version, 1, "first upload publishes version 1");

    let head = client
        .head(&hex16(&tenant), &hex16(&profile))
        .await
        .expect("head must succeed");
    assert_eq!(head.version, 1);
    assert_eq!(
        head.container_size,
        container.len() as i64,
        "server must report the exact container size"
    );

    let pulled = client
        .download(&hex16(&tenant), &hex16(&profile), 1)
        .await
        .expect("download must succeed");

    assert_eq!(
        pulled, container,
        "the bytes that come back must be the bytes that went up"
    );

    // A second push from the same base is a stale write: another device could
    // have published in between, and silently overwriting it is the failure
    // mode leases exist to prevent.
    let stale = client
        .upload(
            &UploadRequest {
                tenant_id: &hex16(&tenant),
                profile_id: &hex16(&profile),
                fleet_id: &hex16(&fleet),
                snapshot_id: &hex16(&[0x80u8; 16]),
                account_id: &hex16(&account),
                device_id: &hex16(&device),
                key_generation: 1,
                base_version: 0,
                container: &container,
            },
            &signer,
            120,
        )
        .await;

    assert!(
        stale.is_err(),
        "a push from a stale base version must be refused, got {stale:?}"
    );
}

/// Two devices, one fleet key, no shared passphrase.
///
/// This is the property the FKEK layer exists for: device A seals a profile
/// under the fleet key it collected from its grant, and device B — which never
/// learns a passphrase — opens the same bytes using the key it collected from
/// its own grant. Both devices open their grant with their own HPKE key, so
/// the server never holds anything it could decrypt.
///
/// Run against a real server process, because the point is that the two sides
/// agree over the wire, not that one encoder round-trips itself.
#[tokio::test]
async fn two_devices_share_a_profile_through_the_fleet_key_without_a_passphrase() {
    let Some(server) = start_server_slot(2).await else {
        panic!(
            "team server binary missing — build it first: \
             cargo build --manifest-path ../server/Cargo.toml"
        );
    };

    let token = login(server.port).await.expect("admin login");
    let user_id = admin_user_id(server.port, &token)
        .await
        .expect("admin user id");

    let tenant = [0x8Au8; 16];
    let fleet = [0x8Bu8; 16];
    let profile = [0x8Cu8; 16];
    let account = [0x8Du8; 16];
    let device_a = [0x8Eu8; 16];

    assert!(
        seed_fleet(
            &server.data_dir,
            &tenant,
            &fleet,
            &profile,
            &account,
            &user_id
        )
        .await,
        "could not seed the fleet, so the test would prove nothing"
    );

    // The fleet key. In production this is generated by the custodian device
    // and handed to each device inside a grant; here we model the outcome of
    // that exchange: both devices ended up holding the same fleet key.
    let fkek = [0x5Cu8; 32];

    // Device A seals a profile directory under the fleet key.
    let work = std::env::temp_dir().join(format!("shardx-two-device-{}", std::process::id()));
    let dir_a = work.join("device-a");
    let dir_b = work.join("device-b");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(dir_a.join("Default")).expect("profile dir");
    std::fs::write(
        dir_a.join("Default").join("Preferences"),
        br#"{"profile":{"name":"shared"}}"#,
    )
    .expect("write profile");

    let sealed = shardx_core::backup_file::seal_profile_with_fkek("shared", &dir_a, &fkek)
        .expect("device A seals under the fleet key");

    // It goes up through the real transfer path.
    let base = format!("http://127.0.0.1:{}", server.port);
    let client = FleetClient::new(&base, &token).expect("construct client");
    let signer = shardx_core::signing::Ed25519SigningKey::from_bytes(&SIGNER_SEED);

    let version = client
        .upload(
            &UploadRequest {
                tenant_id: &hex16(&tenant),
                profile_id: &hex16(&profile),
                fleet_id: &hex16(&fleet),
                snapshot_id: &hex16(&[0x8Fu8; 16]),
                account_id: &hex16(&account),
                device_id: &hex16(&device_a),
                key_generation: 1,
                base_version: 0,
                container: &sealed.bytes,
            },
            &signer,
            120,
        )
        .await
        .expect("device A push");
    assert_eq!(version, 1);

    // Device B pulls and opens it with the fleet key alone.
    let pulled = client
        .download(&hex16(&tenant), &hex16(&profile), version)
        .await
        .expect("device B download");
    assert_eq!(
        pulled, sealed.bytes,
        "the server must return the exact sealed bytes"
    );

    shardx_core::backup_file::open_profile_with_fkek(&pulled, &dir_b, &fkek)
        .expect("device B opens the snapshot with the fleet key, with no passphrase");

    let restored = std::fs::read(dir_b.join("Default").join("Preferences")).expect("restored file");
    assert_eq!(
        restored, br#"{"profile":{"name":"shared"}}"#,
        "device B must recover device A's profile byte for byte"
    );

    // A device outside the fleet holds a different key and must get nothing.
    let outsider = std::env::temp_dir().join(format!("shardx-outsider-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&outsider);
    assert!(
        shardx_core::backup_file::open_profile_with_fkek(&pulled, &outsider, &[0x5Du8; 32])
            .is_err(),
        "a device without this fleet's key must not be able to open the snapshot"
    );

    let _ = std::fs::remove_dir_all(&work);
    let _ = std::fs::remove_dir_all(&outsider);
}
