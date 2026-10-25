//! The external identity record is the v2 epoch authority (ADR 0001 S1-S3,
//! Option A). These drive the real binary: the offline `identity` and
//! `tenant create` commands, the data directory lock, and the startup check
//! that keeps v2 writes off unless the record and its database mirror agree.

use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::time::Duration;

use serde_json::{json, Value};
use shardx_team_server::identity_record::{self, IdentityRecordV2};
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;

const RECORD: &str = "identity-record-v2.bin";

struct Dirs {
    data: PathBuf,
    identity: PathBuf,
}

fn dirs(tag: &str) -> Dirs {
    let base = std::env::temp_dir().join(format!("shardx-idauth-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let d = Dirs {
        data: base.join("data"),
        identity: base.join("identity"),
    };
    std::fs::create_dir_all(&d.identity).unwrap();
    d
}

fn bin() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_shardx-team-server"));
    c.env_remove("SHARDX_IDENTITY_DIR").stdin(Stdio::null());
    c
}

fn cli(d: &Dirs, args: &[&str]) -> Output {
    bin()
        .args(args)
        .env("SHARDX_DATA_DIR", &d.data)
        .env("SHARDX_IDENTITY_DIR", &d.identity)
        .output()
        .unwrap()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn field(o: &Output, key: &str) -> String {
    stdout(o)
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{key}=")).map(str::to_string))
        .unwrap_or_else(|| panic!("no {key} in {}", stdout(o)))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

async fn db(d: &Dirs) -> SqlitePool {
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&format!(
            "sqlite://{}/shardx.db?mode=rwc",
            d.data.to_string_lossy().replace('\\', "/")
        ))
        .await
        .unwrap()
}

/// A migrated database with nothing in it, as a fresh install would have.
async fn migrated(d: &Dirs) -> SqlitePool {
    std::fs::create_dir_all(&d.data).unwrap();
    let pool = db(d).await;
    shardx_team_server::run_migrations(&pool).await.unwrap();
    pool
}

async fn count(pool: &SqlitePool, table: &str) -> i64 {
    sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
        .fetch_one(pool)
        .await
        .unwrap()
}

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn(d: &Dirs, port: u16, with_identity: bool) -> Server {
    let mut c = bin();
    c.env("SHARDX_BIND", format!("127.0.0.1:{port}"))
        .env("SHARDX_DATA_DIR", &d.data)
        .env("SHARDX_TOKEN_SECRET", "identity-authority-test")
        .env("SHARDX_ADMIN_USER", "admin")
        .env("SHARDX_ADMIN_PASS", "secret");
    if with_identity {
        c.env("SHARDX_IDENTITY_DIR", &d.identity);
    }
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
    for _ in 0..60 {
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

/// Status and reason code of a v2 write and of the identity read.
async fn v2_state(c: &reqwest::Client, port: u16, token: &str) -> (u16, Value, u16, Value) {
    let write = c
        .post(format!("http://127.0.0.1:{port}/v2/root-key-generations"))
        .bearer_auth(token)
        .json(&json!({ "tenant_id": "00", "root_key_id": "00" }))
        .send()
        .await
        .unwrap();
    let write_status = write.status().as_u16();
    let write_body: Value = write.json().await.unwrap_or(Value::Null);
    let read = c
        .get(format!("http://127.0.0.1:{port}/v2/server-identity"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    let read_status = read.status().as_u16();
    let read_body: Value = read.json().await.unwrap_or(Value::Null);
    (write_status, write_body, read_status, read_body)
}

#[test]
fn a_non_utf8_argument_is_a_usage_error() {
    #[cfg(unix)]
    let arg = {
        use std::os::unix::ffi::OsStrExt;
        std::ffi::OsStr::from_bytes(b"\xff").to_os_string()
    };
    #[cfg(windows)]
    let arg = {
        use std::os::windows::ffi::OsStringExt;
        std::ffi::OsString::from_wide(&[0xD800])
    };
    let out = bin().arg("identity").arg(arg).output().unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(stderr(&out).contains("usage:"));
}

/// A symlinked record could point into the data directory's rollback scope,
/// so it is refused even when the file it names is a valid record.
#[test]
fn a_symlinked_record_is_refused() {
    let d = dirs("symlink");
    assert!(cli(&d, &["identity", "init"]).status.success());
    let record = d.identity.join(RECORD);
    let target = d.data.join("moved-record.bin");
    std::fs::rename(&record, &target).unwrap();

    // Any non-regular entry is refused the same way; a directory needs no
    // privilege to create, so this part runs everywhere.
    std::fs::create_dir(&record).unwrap();
    let out = cli(&d, &["identity", "show"]);
    assert_eq!(field(&out, "status"), "EPOCH_AUTHORITY_CORRUPT");
    assert!(field(&out, "reason").contains("not a regular file"));
    std::fs::remove_dir(&record).unwrap();

    #[cfg(unix)]
    let linked = std::os::unix::fs::symlink(&target, &record);
    #[cfg(windows)]
    let linked = std::os::windows::fs::symlink_file(&target, &record);
    if let Err(e) = linked {
        // Windows needs Developer Mode or a privilege to create symlinks.
        eprintln!("skipping: cannot create a symlink here: {e}");
        return;
    }
    let out = cli(&d, &["identity", "show"]);
    assert_eq!(field(&out, "status"), "EPOCH_AUTHORITY_CORRUPT");
    assert!(
        field(&out, "reason").contains("not a regular file"),
        "{}",
        stdout(&out)
    );

    // The same bytes as a regular file verify.
    std::fs::remove_file(&record).unwrap();
    std::fs::rename(&target, &record).unwrap();
    assert_eq!(field(&cli(&d, &["identity", "show"]), "status"), "OK");
}

#[test]
fn unknown_commands_print_usage_and_fail() {
    for args in [
        &["identity"][..],
        &["identity", "repair"],
        &["serve"],
        &[
            "tenant",
            "create",
            "--slug",
            "a",
            "--owner-username",
            "b",
            "--password",
            "x",
        ],
    ] {
        let out = bin().args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(stderr(&out).contains("usage:"), "{args:?}");
    }
}

#[test]
fn init_writes_the_record_then_the_mirror_and_show_verifies_both() {
    let d = dirs("init");
    let out = cli(&d, &["identity", "init"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let instance = field(&out, "server_instance_id");
    let sha = field(&out, "external_record_sha256");
    assert_eq!(field(&out, "restore_epoch"), "0");

    let bytes = std::fs::read(d.identity.join(RECORD)).unwrap();
    let record = identity_record::parse(&bytes).unwrap();
    assert_eq!(hex(&record.server_instance_id), instance);
    assert_eq!(record.restore_epoch, 0);
    assert_eq!(
        hex(&identity_record::external_record_sha256(
            &bytes.as_slice().try_into().unwrap()
        )),
        sha
    );
    assert!(!d.identity.join(format!("{RECORD}.tmp")).exists());

    let show = cli(&d, &["identity", "show"]);
    assert!(show.status.success(), "{}", stdout(&show));
    assert_eq!(field(&show, "status"), "OK");
    assert_eq!(field(&show, "server_instance_id"), instance);
    assert_eq!(field(&show, "external_record_sha256"), sha);

    // A second init refuses and leaves the first record alone.
    let again = cli(&d, &["identity", "init"]);
    assert!(!again.status.success());
    assert!(
        stderr(&again).contains("already exists"),
        "{}",
        stderr(&again)
    );
    assert_eq!(std::fs::read(d.identity.join(RECORD)).unwrap(), bytes);
}

#[tokio::test]
async fn init_refuses_existing_state_and_writes_nothing() {
    // A leftover record or temp file.
    for (i, name) in [RECORD.to_string(), format!("{RECORD}.tmp")]
        .iter()
        .enumerate()
    {
        let d = dirs(&format!("leftover{i}"));
        std::fs::write(d.identity.join(name), b"leftover").unwrap();
        let out = cli(&d, &["identity", "init"]);
        assert!(!out.status.success(), "{name}");
        assert!(stderr(&out).contains("already exists"), "{}", stderr(&out));
        assert_eq!(
            std::fs::read(d.identity.join(name)).unwrap(),
            b"leftover".to_vec()
        );
        assert_eq!(std::fs::read_dir(&d.identity).unwrap().count(), 1);
        assert!(!d.data.join("shardx.db").exists(), "{name}");
    }

    // A mirror row or a tenant row already in the database.
    for (tag, sql) in [
        (
            "mirror",
            "INSERT INTO v2_server_state VALUES (1, x'0102030405060708090a0b0c0d0e0f10', 0, \
             x'0000000000000000000000000000000000000000000000000000000000000000', 'now')",
        ),
        (
            "tenant",
            "INSERT INTO v2_tenants (id, slug, status, created_at) \
             VALUES (x'0102030405060708090a0b0c0d0e0f10', 'acme', 'active', 'now')",
        ),
    ] {
        let d = dirs(&format!("row-{tag}"));
        let pool = migrated(&d).await;
        sqlx::query(sql).execute(&pool).await.unwrap();
        pool.close().await;
        let out = cli(&d, &["identity", "init"]);
        assert!(!out.status.success(), "{tag}");
        assert!(
            stderr(&out).contains("already has a row"),
            "{}",
            stderr(&out)
        );
        assert_eq!(std::fs::read_dir(&d.identity).unwrap().count(), 0, "{tag}");
    }
}

#[test]
fn init_requires_an_identity_directory() {
    let d = dirs("unset");
    let out = bin()
        .args(["identity", "init"])
        .env("SHARDX_DATA_DIR", &d.data)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("SHARDX_IDENTITY_DIR must be set"),
        "{}",
        stderr(&out)
    );
    assert!(!d.data.join("shardx.db").exists());
}

#[test]
fn init_refuses_an_identity_directory_inside_the_data_directory() {
    let d = dirs("inside");
    let inside = Dirs {
        identity: d.data.join("identity"),
        data: d.data.clone(),
    };
    std::fs::create_dir_all(&inside.identity).unwrap();
    let out = cli(&inside, &["identity", "init"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("must not equal, contain or sit inside"),
        "{}",
        stderr(&out)
    );
    assert_eq!(std::fs::read_dir(&inside.identity).unwrap().count(), 0);
}

#[tokio::test]
async fn a_running_server_holds_the_lock_against_commands_and_a_second_server() {
    let d = dirs("lock");
    let _server = spawn(&d, 38151, false);
    let c = http();
    ready(&c, 38151).await;

    for args in [&["identity", "init"][..], &["identity", "show"]] {
        let out = cli(&d, args);
        assert!(!out.status.success(), "{args:?}");
        assert!(
            stderr(&out).contains("another instance holds the data directory lock"),
            "{}",
            stderr(&out)
        );
    }
    assert_eq!(std::fs::read_dir(&d.identity).unwrap().count(), 0);

    let mut second = spawn(&d, 38152, false);
    assert!(!second.0.wait().unwrap().success());
}

/// Record durable, mirror missing: the state an interrupted `identity init`
/// leaves. Startup reports it and keeps v2 writes off; nothing repairs it.
#[tokio::test]
async fn an_interrupted_init_is_reported_and_never_repaired() {
    let d = dirs("crash");
    let pool = migrated(&d).await;
    sqlx::query(
        "CREATE TRIGGER fail_mirror BEFORE INSERT ON v2_server_state \
         BEGIN SELECT RAISE(ABORT, 'simulated crash'); END",
    )
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;

    let out = cli(&d, &["identity", "init"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("mirror insert failed"),
        "{}",
        stderr(&out)
    );
    let record = std::fs::read(d.identity.join(RECORD)).unwrap();
    identity_record::parse(&record).expect("the record was written first");

    let pool = db(&d).await;
    sqlx::query("DROP TRIGGER fail_mirror")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(count(&pool, "v2_server_state").await, 0);
    pool.close().await;

    let show = cli(&d, &["identity", "show"]);
    assert!(!show.status.success());
    assert_eq!(field(&show, "status"), "EPOCH_RECONCILIATION_REQUIRED");

    {
        let _server = spawn(&d, 38153, true);
        let c = http();
        let token = ready(&c, 38153).await;
        let (ws, wb, rs, rb) = v2_state(&c, 38153, &token).await;
        assert_eq!((ws, rs), (423, 423));
        assert_eq!(wb["code"], "EPOCH_RECONCILIATION_REQUIRED");
        assert_eq!(rb["code"], "EPOCH_RECONCILIATION_REQUIRED");
    }

    assert_eq!(std::fs::read(d.identity.join(RECORD)).unwrap(), record);
    let pool = db(&d).await;
    assert_eq!(count(&pool, "v2_server_state").await, 0);
}

#[tokio::test]
async fn show_detects_a_tampered_record_and_a_record_the_mirror_does_not_attest() {
    let d = dirs("tamper");
    assert!(cli(&d, &["identity", "init"]).status.success());
    let path = d.identity.join(RECORD);
    let good = std::fs::read(&path).unwrap();

    let mut flipped = good.clone();
    flipped[100] ^= 1;
    std::fs::write(&path, &flipped).unwrap();
    let out = cli(&d, &["identity", "show"]);
    assert!(!out.status.success());
    assert_eq!(field(&out, "status"), "EPOCH_AUTHORITY_CORRUPT");
    assert!(
        field(&out, "reason").contains("Checksum"),
        "{}",
        stdout(&out)
    );

    // A valid record for the same instance and epoch, but not the one the
    // mirror recorded.
    let original = identity_record::parse(&good).unwrap();
    let replaced = IdentityRecordV2::genesis(original.server_instance_id, 1)
        .encode()
        .unwrap();
    std::fs::write(&path, replaced).unwrap();
    let out = cli(&d, &["identity", "show"]);
    assert_eq!(field(&out, "status"), "EPOCH_AUTHORITY_BEHIND_DB");

    // A record from another instance.
    let foreign = IdentityRecordV2::genesis([9u8; 16], 1).encode().unwrap();
    std::fs::write(&path, foreign).unwrap();
    assert_eq!(
        field(&cli(&d, &["identity", "show"]), "status"),
        "EPOCH_AUTHORITY_BEHIND_DB"
    );

    std::fs::remove_file(&path).unwrap();
    assert_eq!(
        field(&cli(&d, &["identity", "show"]), "status"),
        "EPOCH_AUTHORITY_MISSING"
    );

    // Show never repaired anything along the way.
    std::fs::write(&path, &good).unwrap();
    assert_eq!(field(&cli(&d, &["identity", "show"]), "status"), "OK");
}

/// Without `SHARDX_IDENTITY_DIR` the server fails closed for v2 and keeps
/// serving v1, and it does not create a record on its own.
#[tokio::test]
async fn without_an_identity_directory_v2_writes_are_refused_and_v1_works() {
    let d = dirs("noidentity");
    let _server = spawn(&d, 38154, false);
    let c = http();
    let token = ready(&c, 38154).await;

    let (ws, wb, rs, rb) = v2_state(&c, 38154, &token).await;
    assert_eq!((ws, rs), (423, 423));
    assert_eq!(wb["code"], "EPOCH_AUTHORITY_MISSING");
    assert_eq!(rb["code"], "EPOCH_AUTHORITY_MISSING");

    // Every state-changing v2 route is behind the same gate.
    for path in [
        "/v2/devices/enrollment-challenges",
        "/v2/devices/enrollment-proofs",
        "/v2/device-approvals",
        "/v2/capability-grants",
        "/v2/tenant-root-key-grants",
        "/v2/root-key-generations/activate",
        "/v2/fleet-key-grants",
        "/v2/fleet-key-generations",
        "/v2/fleet-key-generations/activate",
        "/v2/operations",
        "/v2/operations/complete",
        "/v2/fleet/leases",
        "/v2/fleet/leases/release",
        "/v2/fleet/uploads",
        "/v2/fleet/uploads/00/00/chunk",
        "/v2/fleet/uploads/commit",
        "/v2/fleet/uploads/abort",
    ] {
        let r = c
            .post(format!("http://127.0.0.1:38154{path}"))
            .bearer_auth(&token)
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 423, "{path}");
    }

    let folder = c
        .post("http://127.0.0.1:38154/folders")
        .bearer_auth(&token)
        .json(&json!({ "name": "still-works" }))
        .send()
        .await
        .unwrap();
    assert!(folder.status().is_success(), "{}", folder.status());
    let listed: Value = c
        .get("http://127.0.0.1:38154/folders")
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(listed.to_string().contains("still-works"));

    assert_eq!(std::fs::read_dir(&d.identity).unwrap().count(), 0);
}

/// With a record the mirror attests, v2 writes reach their handlers.
#[tokio::test]
async fn a_verified_identity_opens_v2_writes() {
    let d = dirs("verified");
    let init = cli(&d, &["identity", "init"]);
    assert!(init.status.success(), "{}", stderr(&init));
    let _server = spawn(&d, 38155, true);
    let c = http();
    let token = ready(&c, 38155).await;

    let (ws, _, rs, rb) = v2_state(&c, 38155, &token).await;
    assert_eq!(
        ws, 400,
        "the handler, not the gate, rejects the bad tenant id"
    );
    assert_eq!(rs, 200);
    assert_eq!(
        rb["server_instance_id"].as_str().unwrap(),
        field(&init, "server_instance_id")
    );
}

const OWNER_PASSWORD: &str = "a-strong-unique-owner-pass";

/// Run `tenant create` with `input` on stdin.
fn tenant_create(d: &Dirs, slug: &str, extra: &[&str], input: &str) -> Output {
    let mut child = bin()
        .args([
            "tenant",
            "create",
            "--slug",
            slug,
            "--owner-username",
            "alice",
        ])
        .args(extra)
        .env("SHARDX_DATA_DIR", &d.data)
        .env("SHARDX_IDENTITY_DIR", &d.identity)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // A refusal may exit before reading stdin, so a closed pipe is fine.
    let _ = std::io::Write::write_all(&mut child.stdin.take().unwrap(), input.as_bytes());
    child.wait_with_output().unwrap()
}

async fn tenant_rows(d: &Dirs) -> [i64; 5] {
    let pool = db(d).await;
    let mut out = [0; 5];
    for (i, t) in [
        "v2_tenants",
        "v2_accounts",
        "v2_tenant_memberships",
        "v2_audit_events",
        "v2_bootstrap_guards",
    ]
    .iter()
    .enumerate()
    {
        out[i] = count(&pool, t).await;
    }
    pool.close().await;
    out
}

fn initialised(tag: &str) -> Dirs {
    let d = dirs(tag);
    let out = cli(&d, &["identity", "init"]);
    assert!(out.status.success(), "{}", stderr(&out));
    d
}

fn stdin_password() -> String {
    format!("{OWNER_PASSWORD}\n")
}

#[tokio::test]
async fn tenant_create_writes_tenant_owner_membership_and_offline_audit_together() {
    let d = initialised("tenant");
    let out = tenant_create(&d, "acme", &["--password-stdin"], &stdin_password());
    assert!(out.status.success(), "{}", stderr(&out));
    let tenant_id = field(&out, "tenant_id");
    assert!(!stdout(&out).contains(OWNER_PASSWORD) && !stderr(&out).contains(OWNER_PASSWORD));

    let pool = db(&d).await;
    let (slug, status, pointer): (String, String, Option<i64>) = sqlx::query_as(
        "SELECT slug, status, active_root_generation FROM v2_tenants WHERE hex(id) = upper(?)",
    )
    .bind(&tenant_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        (slug.as_str(), status.as_str(), pointer),
        ("acme", "active", None)
    );

    let (username, pw_hash, legacy, account_status): (String, String, Option<String>, String) =
        sqlx::query_as(
            "SELECT username, pw_hash, legacy_user_id, status FROM v2_accounts \
             WHERE hex(tenant_id) = upper(?)",
        )
        .bind(&tenant_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(username, "alice");
    assert!(pw_hash.starts_with("$argon2"), "argon2 hash expected");
    assert!(!pw_hash.contains(OWNER_PASSWORD));
    assert_eq!((legacy, account_status.as_str()), (None, "active"));

    let role: String = sqlx::query_scalar(
        "SELECT role FROM v2_tenant_memberships m JOIN v2_accounts a \
           ON a.tenant_id = m.tenant_id AND a.id = m.account_id \
         WHERE hex(m.tenant_id) = upper(?) AND m.status = 'active'",
    )
    .bind(&tenant_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(role, "owner");

    type AuditRow = (
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        String,
        String,
        String,
        String,
        i64,
    );
    let audit: AuditRow = sqlx::query_as(
        "SELECT actor_account_id, actor_device_id, action, hex(target_id), outcome, \
                reason_code, length(request_id) \
         FROM v2_audit_events WHERE hex(tenant_id) = upper(?)",
    )
    .bind(&tenant_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        audit,
        (
            None,
            None,
            "tenant.create".to_string(),
            tenant_id.to_uppercase(),
            "success".to_string(),
            "offline_operator_cli".to_string(),
            16
        )
    );

    // The tenant's one first-device opportunity, bound to this instance (R1).
    let guard: (String, Option<String>, bool) = sqlx::query_as(
        "SELECT g.state, g.recovery_reason, g.server_instance_id = s.server_instance_id          FROM v2_bootstrap_guards g, v2_server_state s WHERE hex(g.tenant_id) = upper(?)",
    )
    .bind(&tenant_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(guard, ("unused".to_string(), None, true));

    // No root key, grant, capability or device comes with the tenant (ADR Q3).
    for table in [
        "v2_root_key_generations",
        "v2_tenant_root_key_grants",
        "v2_capability_grants",
        "v2_devices",
    ] {
        assert_eq!(count(&pool, table).await, 0, "{table}");
    }
    pool.close().await;

    let again = tenant_create(&d, "acme", &["--password-stdin"], &stdin_password());
    assert!(!again.status.success());
    assert_eq!(tenant_rows(&d).await, [1, 1, 1, 1, 1]);
}

#[tokio::test]
async fn tenant_create_refuses_before_identity_init() {
    let d = dirs("tenant-noinit");
    let out = tenant_create(&d, "acme", &["--password-stdin"], &stdin_password());
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("EPOCH_AUTHORITY_MISSING"),
        "{}",
        stderr(&out)
    );
    // A refusal creates nothing beside the lock file it held: no database
    // file, no blob directory.
    let entries: Vec<String> = std::fs::read_dir(&d.data)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(entries, ["shardx.lock"]);

    // A database migrated by the server, but never initialised, is refused too.
    migrated(&d).await.close().await;
    let out = tenant_create(&d, "acme", &["--password-stdin"], &stdin_password());
    assert!(!out.status.success());
    assert_eq!(tenant_rows(&d).await, [0; 5]);
}

#[tokio::test]
async fn tenant_create_refuses_a_weak_password() {
    let d = initialised("tenant-weak");
    for weak in ["admin", "Password", "short7", ""] {
        let out = tenant_create(&d, "acme", &["--password-stdin"], &format!("{weak}\n"));
        assert!(!out.status.success(), "{weak:?}");
        assert!(
            stderr(&out).contains("weak owner password"),
            "{}",
            stderr(&out)
        );
    }
    assert_eq!(tenant_rows(&d).await, [0; 5]);
}

/// The password never comes from argv or the environment, and without a
/// terminal the command refuses instead of waiting on stdin.
#[tokio::test]
async fn tenant_create_takes_no_password_from_argv_or_env_and_never_blocks() {
    let d = initialised("tenant-argv");
    let out = tenant_create(&d, "acme", &["--password", OWNER_PASSWORD], "");
    assert_eq!(out.status.code(), Some(2));
    assert!(!stderr(&out).contains(OWNER_PASSWORD));

    // stdin is an open pipe that never delivers a line: a prompt would hang.
    let mut child = bin()
        .args([
            "tenant",
            "create",
            "--slug",
            "acme",
            "--owner-username",
            "alice",
        ])
        .env("SHARDX_DATA_DIR", &d.data)
        .env("SHARDX_IDENTITY_DIR", &d.identity)
        .env("SHARDX_OWNER_PASSWORD", OWNER_PASSWORD)
        .env("SHARDX_PASSWORD", OWNER_PASSWORD)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _open_stdin = child.stdin.take();
    let mut status = None;
    for _ in 0..150 {
        if let Some(s) = child.try_wait().unwrap() {
            status = Some(s);
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let Some(status) = status else {
        let _ = child.kill();
        panic!("tenant create blocked on a non-terminal stdin");
    };
    assert!(!status.success());
    let mut err = String::new();
    std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut err).unwrap();
    assert!(err.contains("--password-stdin"), "{err}");
    assert_eq!(tenant_rows(&d).await, [0; 5]);
}

/// The audit row is part of the transaction: if it cannot be written, the
/// tenant, account and membership are rolled back with it.
#[tokio::test]
async fn tenant_create_rolls_back_everything_when_the_audit_insert_fails() {
    let d = initialised("tenant-audit");
    let pool = db(&d).await;
    sqlx::query(
        "CREATE TRIGGER fail_audit BEFORE INSERT ON v2_audit_events \
         BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END",
    )
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;

    let out = tenant_create(&d, "acme", &["--password-stdin"], &stdin_password());
    assert!(!out.status.success());
    assert!(stderr(&out).contains("audit"), "{}", stderr(&out));
    assert_eq!(tenant_rows(&d).await, [0; 5]);
}
