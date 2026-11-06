//! The v0.2.2a custodian slice against a real team server (plan section 5).
//!
//! Each test spawns `server/target/debug/shardx-team-server`, built from this
//! tree with `cargo build --manifest-path server/Cargo.toml`, sets it up
//! through its CLI only (`identity init`, `tenant create`, `tenant
//! confirm-first-device`) and drives it over HTTP through the launcher's own
//! commands. There is no v1 admin and no token anywhere.
//!
//! These are lib tests, so the mock credential store and the config and data
//! roots apply. Each device files its credentials under its own namespace
//! (`credential::test_namespace`), and every await runs on the test's thread
//! (a current-thread runtime), where that namespace is set.

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use crate::fleet_client::{hex, AccountLogin, FleetClient};

const OWNER: &str = "owner";
const PASSWORD: &str = "custodian-it-owner-pass";
const PASSPHRASE: &str = "custodian-it-recovery-passphrase";

/// While the leak scan's worker runs, the directory it files every reply and
/// state file in, and the side file of the secrets the scan looks for (see
/// `the_journey_leaks_no_secret_to_output_state_or_replies`).
const SCAN_DIR: &str = "SHARDX_LEAK_SCAN_DIR";
const SECRETS_FILE: &str = "SHARDX_LEAK_SCAN_SECRETS";

/// A launcher command's reply, appended as the JSON its IPC reply carries to
/// the scan directory's `replies.jsonl` while a leak scan runs.
fn note<T: serde::Serialize>(reply: Result<T, String>) -> Result<T, String> {
    if let Some(dir) = std::env::var_os(SCAN_DIR) {
        use std::io::Write;
        let line = match &reply {
            Ok(value) => serde_json::to_string(value),
            Err(error) => serde_json::to_string(error),
        }
        .unwrap();
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(std::path::Path::new(&dir).join("replies.jsonl"))
            .unwrap();
        writeln!(file, "{line}").unwrap();
    }
    reply
}

/// Runs one launcher command on `rt`, and notes its reply.
fn call<T: serde::Serialize>(
    rt: &tokio::runtime::Runtime,
    command: impl std::future::Future<Output = Result<T, String>>,
) -> Result<T, String> {
    note(rt.block_on(command))
}

/// The server built by `cargo build --manifest-path server/Cargo.toml`, or
/// the one `SHARDX_TEAM_SERVER_BIN` names when it was built elsewhere.
fn server_binary() -> std::path::PathBuf {
    if let Some(bin) = std::env::var_os("SHARDX_TEAM_SERVER_BIN") {
        return bin.into();
    }
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

struct Server {
    child: Child,
    port: u16,
    data: tempfile::TempDir,
    identity: tempfile::TempDir,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Server {
    fn command(data: &std::path::Path, identity: &std::path::Path) -> Command {
        let mut c = Command::new(server_binary());
        c.env("SHARDX_DATA_DIR", data)
            .env("SHARDX_IDENTITY_DIR", identity)
            .env("SHARDX_TOKEN_SECRET", "custodian-it-secret");
        c
    }

    /// One offline CLI command, with `stdin` as its input. The server holds
    /// the data directory's lock, so it is stopped first and restarted after.
    fn cli(
        data: &std::path::Path,
        identity: &std::path::Path,
        args: &[&str],
        stdin: &str,
    ) -> String {
        use std::io::Write;
        let mut cli = Self::command(data, identity)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn the operator command");
        cli.stdin
            .take()
            .expect("stdin")
            .write_all(stdin.as_bytes())
            .expect("write the operator's answers");
        let out = cli.wait_with_output().expect("operator command");
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// Starts the server on `port` and waits until it listens.
    fn start(data: &std::path::Path, identity: &std::path::Path, port: u16) -> Child {
        let mut child = Self::command(data, identity)
            .env("SHARDX_BIND", format!("127.0.0.1:{port}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start the team server");
        for _ in 0..200 {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return child;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = child.kill();
        let _ = child.wait();
        panic!("the team server did not come up on port {port}");
    }

    fn operator(&mut self, args: &[&str], stdin: &str) -> String {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let out = Self::cli(self.data.path(), self.identity.path(), args, stdin);
        self.child = Self::start(self.data.path(), self.identity.path(), self.port);
        out
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// One integer the server database answers to `query`.
    fn count(&self, query: &str) -> i64 {
        use sqlx::Row;
        self.row(query).get::<i64, _>(0)
    }

    /// The one row the server database answers to `query`.
    fn row(&self, query: &str) -> sqlx::sqlite::SqliteRow {
        let db = self.data.path().join("shardx.db");
        let url = format!(
            "sqlite://{}?mode=ro",
            db.to_string_lossy().replace('\\', "/")
        );
        runtime().block_on(async {
            let pool = sqlx::sqlite::SqlitePoolOptions::new()
                .max_connections(1)
                .connect(&url)
                .await
                .expect("open the server database");
            let row = sqlx::query(query).fetch_one(&pool).await.expect(query);
            pool.close().await;
            row
        })
    }
}

/// One custodian device A on its own server, its config and data in temp
/// directories and its credentials in namespace `a`.
struct Harness {
    server: Server,
    _config: tempfile::TempDir,
    _data: tempfile::TempDir,
    tenant: String,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        crate::store::set_config_root(None);
        crate::store::set_data_root(None);
        crate::credential::test_namespace("");
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// A server with one CLI-created tenant, on port slot `slot`, and device A
/// enrolled, confirmed by the operator and bootstrapped as root custodian.
fn custodian(slot: u16, slug: &str, rt: &tokio::runtime::Runtime) -> Harness {
    let lock = crate::store::config_root_test_lock()
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let (server, tenant) = tenant_server(slot, slug);

    let (config, data) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    crate::store::set_config_root(Some(config.path().to_path_buf()));
    crate::store::set_data_root(Some(data.path().to_path_buf()));
    crate::credential::test_namespace("a");
    let mut h = Harness {
        server,
        _config: config,
        _data: data,
        tenant,
        _lock: lock,
    };

    note(crate::team_set_connection(
        h.server.url(),
        String::new(),
        h.tenant.clone(),
    ))
    .unwrap();
    let status = call(
        rt,
        crate::team_enroll_device("custodian".into(), OWNER.into(), PASSWORD.into()),
    )
    .unwrap();
    let c = crate::team_config::load().unwrap();
    let signing =
        shardx_core::keys::signing_key_id(c.signing_key().unwrap().verifying_key().as_bytes());
    let (_, hpke) = shardx_core::grants::derive_keypair(&c.hpke_seed().unwrap());
    h.server.operator(
        &[
            "tenant",
            "confirm-first-device",
            "--tenant",
            slug,
            "--device",
            &status.device_id,
        ],
        &format!(
            "{}\n{}\n",
            hex(&signing),
            hex(&shardx_core::keys::hpke_key_id(&hpke))
        ),
    );
    let recovery = config_path("recovery.shardx-recovery");
    let root = call(
        rt,
        crate::team_bootstrap_custody(OWNER.into(), PASSWORD.into(), recovery, PASSPHRASE.into()),
    )
    .unwrap();
    assert!(root.activated);
    h
}

/// A running server, on port slot `slot`, with one CLI-created tenant
/// `slug`, and that tenant's id.
fn tenant_server(slot: u16, slug: &str) -> (Server, String) {
    let bin = server_binary();
    assert!(
        bin.exists(),
        "team server binary missing at {}: build it first with \
         cargo build --manifest-path server/Cargo.toml",
        bin.display()
    );
    // Its own range, below the Linux ephemeral ports, one slot per test.
    let port = 26100 + (std::process::id() % 300) as u16 + slot * 400;
    let (data, identity) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    Server::cli(data.path(), identity.path(), &["identity", "init"], "");
    let created = Server::cli(
        data.path(),
        identity.path(),
        &[
            "tenant",
            "create",
            "--slug",
            slug,
            "--owner-username",
            OWNER,
            "--password-stdin",
        ],
        &format!("{PASSWORD}\n"),
    );
    let tenant = created
        .lines()
        .find_map(|l| l.strip_prefix("tenant_id="))
        .expect("tenant create prints the tenant id")
        .trim()
        .to_string();
    let server = Server {
        child: Server::start(data.path(), identity.path(), port),
        port,
        data,
        identity,
    };
    (server, tenant)
}

fn config_path(name: &str) -> String {
    crate::store::team_config_path()
        .unwrap()
        .with_file_name(name)
        .to_string_lossy()
        .into_owned()
}

/// Runs `f` with a device session of A, and ends it.
fn with_session<T>(
    rt: &tokio::runtime::Runtime,
    h: &Harness,
    f: impl AsyncFnOnce(&FleetClient, &str) -> T,
) -> T {
    let c = crate::team_config::load().unwrap();
    let client = FleetClient::new(&h.server.url(), "").unwrap();
    let login = AccountLogin {
        tenant_id: &h.tenant,
        username: OWNER,
        password: PASSWORD,
    };
    rt.block_on(async {
        let session = client
            .open_device_session(
                &login,
                &c.device_id,
                &c.signing_key().unwrap(),
                &c.hpke_seed().unwrap(),
            )
            .await
            .unwrap();
        let out = f(&client, &session.access_token).await;
        client.end_session(&session.access_token).await;
        out
    })
}

/// Every audit action the server wrote, with its count.
fn audit(h: &Harness) -> Vec<(String, i64)> {
    [
        "fleet.create",
        "capability.grant",
        "fleet.key_generation.create",
        "fleet.key_grant.create",
        "fleet.key_grant.ack",
        "fleet.key_generation.activate",
    ]
    .into_iter()
    .map(|action| {
        let n = h.server.count(&format!(
            "SELECT count(*) FROM v2_audit_events WHERE action = '{action}'"
        ));
        (action.to_string(), n)
    })
    .collect()
}

fn expected_audit() -> Vec<(String, i64)> {
    [
        ("fleet.create", 1),
        ("capability.grant", 6),
        ("fleet.key_generation.create", 1),
        ("fleet.key_grant.create", 2),
        ("fleet.key_grant.ack", 2),
        ("fleet.key_generation.activate", 1),
    ]
    .into_iter()
    .map(|(a, n)| (a.to_string(), n))
    .collect()
}

#[test]
fn the_custodian_creates_and_collects_the_fleet_key_against_the_real_server() {
    let rt = runtime();
    let h = custodian(0, "cs2-create", &rt);

    let status = call(
        &rt,
        crate::team_fleet_key_setup(OWNER.into(), PASSWORD.into()),
    )
    .unwrap();
    assert!(status.created && !status.setup_key_held, "{status:?}");

    // The session read reports generation 0 ACTIVE.
    let active = with_session(&rt, &h, async |client, access| {
        client
            .active_fleet_generation(access, &h.tenant, &h.tenant)
            .await
            .unwrap()
    });
    assert_eq!(active, Some(0));
    for table in ["v2_fleet_device_hpke_grants", "v2_fleet_recovery_grants"] {
        let acked = h.server.count(&format!(
            "SELECT count(*) FROM {table} WHERE acked_at IS NOT NULL"
        ));
        assert_eq!(acked, 1, "{table}");
    }
    assert_eq!(audit(&h), expected_audit());

    // The verified collect kept the key, and only then was the setup
    // reference released.
    let root = crate::root_bootstrap::load().unwrap();
    let binding = shardx_core::trust_chain::Binding {
        server_instance_id: crate::fleet_client::decode_hex16(&root.server_instance_id, "i")
            .unwrap(),
        tenant_id: crate::fleet_client::decode_hex16(&h.tenant, "t").unwrap(),
    };
    let fleet = binding.tenant_id;
    let ledger = crate::team::db::Db::open().unwrap();
    assert_eq!(
        crate::team::ledger::highest_generation(&ledger, &binding, &fleet).unwrap(),
        Some(0)
    );
    let state = crate::fleet_custody::load().unwrap();
    assert!(state.fkek_nonce.is_empty(), "the setup reference is gone");
    let (key, generation) = crate::fleet_keys::load()
        .unwrap()
        .active_key(&h.tenant)
        .expect("the collected fleet key");
    assert_eq!(generation, 0);
    assert_eq!(
        hex(&shardx_core::fleet_grants::fkek_key_id(&key)),
        state.fkek_key_id
    );
}

#[test]
fn a_fleet_setup_resumes_after_a_failed_save_and_a_replayed_run_against_the_real_server() {
    let rt = runtime();
    let h = custodian(1, "cs2-resume", &rt);

    // The first run holds the key, then its save of the key's id fails.
    let c = crate::team_config::load().unwrap();
    let (signer, seed) = (c.signing_key().unwrap(), c.hpke_seed().unwrap());
    let device = crate::fleet_custody::FleetDevice {
        tenant_id: &c.tenant_id,
        device_id: &c.device_id,
        account_id: &c.account_id,
        signer: &signer,
        hpke_seed: &seed,
        vault: &crate::fleet_custody::CredentialFkekStore,
    };
    let root = crate::root_bootstrap::load().unwrap();
    let err = with_session(&rt, &h, async |client, access| {
        let mut state = crate::fleet_custody::load().unwrap();
        let mut save = |s: &crate::fleet_custody::FleetCustodyState| {
            if s.fkek_key_id.is_empty() {
                crate::fleet_custody::save(s)
            } else {
                anyhow::bail!("disk-full")
            }
        };
        crate::fleet_custody::bootstrap_fleet(client, access, &device, &root, &mut state, &mut save)
            .await
            .unwrap_err()
    });
    assert!(err.to_string().contains("disk-full"), "{err}");
    let failed = crate::fleet_custody::load().unwrap();
    assert!(failed.fkek_key_id.is_empty() && failed.create_request.is_empty());
    let name = format!(
        "fleet-setup.{}.{}",
        h.tenant.to_ascii_lowercase(),
        failed.fkek_nonce
    );
    let held = hex(&shardx_core::fleet_grants::fkek_key_id(
        &crate::credential::load(&name).unwrap(),
    ));

    // The rerun reuses that key and completes.
    let status = call(
        &rt,
        crate::team_fleet_key_setup(OWNER.into(), PASSWORD.into()),
    )
    .unwrap();
    assert!(status.created && !status.setup_key_held, "{status:?}");
    assert_eq!(status.fkek_key_id, held);
    let gone = crate::credential::load(&name).unwrap_err();
    assert!(gone.to_string().contains("credential.missing"), "{gone}");
    assert_eq!(audit(&h), expected_audit());

    // A third run is answered from stored responses: nothing new is filed.
    let again = call(
        &rt,
        crate::team_fleet_key_setup(OWNER.into(), PASSWORD.into()),
    )
    .unwrap();
    assert_eq!(again, status);
    assert_eq!(audit(&h), expected_audit());
    assert_eq!(
        h.server
            .count("SELECT count(*) FROM v2_fleet_key_generations"),
        1
    );
    assert_eq!(
        h.server.count(&format!(
            "SELECT count(*) FROM v2_fleet_key_generations
              WHERE generation = 0 AND lower(hex(fkek_key_id)) = '{held}'"
        )),
        1
    );
}

/// Setup reports failure if retiring its temporary credential fails; that
/// failure must not leave a usable key, and a retry converges.
#[test]
fn a_setup_whose_cleanup_fails_leaves_no_usable_verified_key() {
    let rt = runtime();
    let h = custodian(15, "cleanup-fails", &rt);
    let c = crate::team_config::load().unwrap();
    let (signer, seed) = (c.signing_key().unwrap(), c.hpke_seed().unwrap());
    let device = crate::fleet_custody::FleetDevice {
        tenant_id: &c.tenant_id,
        device_id: &c.device_id,
        account_id: &c.account_id,
        signer: &signer,
        hpke_seed: &seed,
        vault: &crate::fleet_custody::CredentialFkekStore,
    };
    let root = crate::root_bootstrap::load().unwrap();
    // Model a crash after activation, before the first verified collect.
    with_session(&rt, &h, async |client, access| {
        let mut state = crate::fleet_custody::load().unwrap();
        crate::fleet_custody::bootstrap_fleet(
            client,
            access,
            &device,
            &root,
            &mut state,
            &mut |s| crate::fleet_custody::save(s),
        )
        .await
        .unwrap();
    });
    assert!(!crate::team_config::status().unwrap().has_fleet_key);
    let state = crate::fleet_custody::load().unwrap();
    let reference = format!(
        "fleet-setup.{}.{}",
        h.tenant.to_ascii_lowercase(),
        state.fkek_nonce
    );
    crate::credential::fail_next_call(&reference);
    let result = call(
        &rt,
        crate::team_fleet_key_setup(OWNER.into(), PASSWORD.into()),
    );
    assert!(result.is_err(), "the cleanup failure must reach the caller");
    assert!(crate::fleet_custody::status().unwrap().setup_key_held);
    assert!(
        !crate::team_config::status().unwrap().has_fleet_key,
        "a failed setup left a verified key usable for sealing"
    );
    // The retry releases the key, replays the saved bytes and collects the
    // same FKEK: nothing is generated again.
    let done = call(
        &rt,
        crate::team_fleet_key_setup(OWNER.into(), PASSWORD.into()),
    )
    .unwrap();
    assert!(done.created && !done.setup_key_held);
    assert_eq!(done.fkek_key_id, state.fkek_key_id);
    assert!(crate::team_config::status().unwrap().has_fleet_key);
}

/// A loopback proxy in front of `upstream` that reports every device grant
/// PENDING_ACK and answers 409 to any ack whose body is not in `allowed`.
/// It counts `[refused acks, rewritten readbacks]`.
fn pending_ack_proxy(
    rt: &tokio::runtime::Runtime,
    upstream: String,
    allowed: Vec<Vec<u8>>,
) -> (String, std::sync::Arc<[std::sync::atomic::AtomicUsize; 2]>) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let counts = std::sync::Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
    let count = counts.clone();
    let http = reqwest::Client::new();
    let app = axum::Router::new().fallback(
        move |method: axum::http::Method,
              uri: axum::http::Uri,
              headers: axum::http::HeaderMap,
              body: axum::body::Bytes| {
            let (http, upstream, allowed, count) = (
                http.clone(),
                upstream.clone(),
                allowed.clone(),
                count.clone(),
            );
            async move {
                let path = uri.path_and_query().map_or("/", |p| p.as_str()).to_string();
                if method == axum::http::Method::POST
                    && uri.path().ends_with("/ack")
                    && !allowed.iter().any(|a| a[..] == body[..])
                {
                    count[0].fetch_add(1, Ordering::SeqCst);
                    return (axum::http::StatusCode::CONFLICT, Vec::new()).into_response();
                }
                let mut req = http.request(method, format!("{upstream}{path}"));
                for (name, value) in &headers {
                    if name != axum::http::header::HOST {
                        req = req.header(name, value);
                    }
                }
                let res = req.body(body.to_vec()).send().await.unwrap();
                let status = axum::http::StatusCode::from_u16(res.status().as_u16()).unwrap();
                let content_type = res.headers().get("content-type").cloned();
                let mut bytes = res.bytes().await.unwrap().to_vec();
                if uri.path().contains("/grants/") {
                    // CBOR text(12) "ACKNOWLEDGED" becomes text(11) "PENDING_ACK".
                    let (from, to) = (b"\x6cACKNOWLEDGED", b"\x6bPENDING_ACK");
                    if let Some(i) = bytes.windows(from.len()).position(|w| w == from) {
                        bytes.splice(i..i + from.len(), to.iter().copied());
                        count[1].fetch_add(1, Ordering::SeqCst);
                    }
                }
                let mut out = (status, bytes).into_response();
                if let Some(ct) = content_type {
                    out.headers_mut().insert("content-type", ct);
                }
                out
            }
        },
    );
    use axum::response::IntoResponse;
    let url = rt.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    });
    (url, counts)
}

/// Step 7's ACKED receipt is the setup's ack: a server that then reports the
/// grant PENDING_ACK and refuses a new ack cannot fail setup after the key
/// is kept, so an error never comes with a usable key.
#[test]
fn a_setup_does_not_ack_again_after_its_acked_receipt() {
    let rt = runtime();
    let h = custodian(16, "pending-ack", &rt);
    let c = crate::team_config::load().unwrap();
    let (signer, seed) = (c.signing_key().unwrap(), c.hpke_seed().unwrap());
    let device = crate::fleet_custody::FleetDevice {
        tenant_id: &c.tenant_id,
        device_id: &c.device_id,
        account_id: &c.account_id,
        signer: &signer,
        hpke_seed: &seed,
        vault: &crate::fleet_custody::CredentialFkekStore,
    };
    let root = crate::root_bootstrap::load().unwrap();
    // Steps 1 to 8 against the real server: both grants acknowledged.
    with_session(&rt, &h, async |client, access| {
        let mut state = crate::fleet_custody::load().unwrap();
        crate::fleet_custody::bootstrap_fleet(
            client,
            access,
            &device,
            &root,
            &mut state,
            &mut |s| crate::fleet_custody::save(s),
        )
        .await
        .unwrap();
    });
    let state = crate::fleet_custody::load().unwrap();
    // Only the replay of step 7's saved acks is let through.
    let allowed = [&state.device_ack_request, &state.recovery_ack_request]
        .map(|r| crate::fleet_client::decode_hex(r).unwrap())
        .to_vec();
    let (proxy, counts) = pending_ack_proxy(&rt, h.server.url(), allowed);
    let mut c = crate::team_config::load().unwrap();
    c.server_url = proxy;
    crate::team_config::save(&c).unwrap();

    let result = call(
        &rt,
        crate::team_fleet_key_setup(OWNER.into(), PASSWORD.into()),
    );
    let usable = crate::team_config::status().unwrap().has_fleet_key;
    assert_eq!(result.is_err(), !usable, "{result:?}");
    assert!(result.is_ok(), "{result:?}");
    let [refused, rewritten] = counts
        .each_ref()
        .map(|n| n.load(std::sync::atomic::Ordering::SeqCst));
    assert!(
        rewritten >= 1,
        "the readback was never reported PENDING_ACK"
    );
    assert_eq!(refused, 0, "no new ack");
}

/// A second device B with config and data roots of its own, and its
/// credentials in namespace `b`.
struct Member {
    config: tempfile::TempDir,
    data: tempfile::TempDir,
}

/// Makes the device whose roots are `config` and `data` this thread's.
fn act_as(config: &std::path::Path, data: &std::path::Path, namespace: &str) {
    crate::store::set_config_root(Some(config.to_path_buf()));
    crate::store::set_data_root(Some(data.to_path_buf()));
    crate::credential::test_namespace(namespace);
}

impl Harness {
    fn act_as_a(&self) {
        act_as(self._config.path(), self._data.path(), "a");
    }
}

impl Member {
    fn act_as_b(&self) {
        act_as(self.config.path(), self.data.path(), "b");
    }
}

fn account() -> (Option<String>, Option<String>) {
    (Some(OWNER.into()), Some(PASSWORD.into()))
}

/// A stopped local profile with a user-data directory as `team::sync`'s
/// tests make one: a `Default` folder, preferences and incompressible noise.
fn local_profile(name: &str, seed: u32) -> String {
    let mut stored = crate::profile::StoredProfile {
        meta: Default::default(),
        config: serde_json::json!({ "name": name })
            .as_object()
            .unwrap()
            .clone(),
    };
    crate::profile::save_raw(&mut stored).unwrap();
    let udd = crate::profile::user_data_dir(&stored.meta.id).unwrap();
    std::fs::create_dir_all(udd.join("Default")).unwrap();
    std::fs::write(udd.join("Preferences"), b"{}").unwrap();
    let mut x = seed;
    let noise: Vec<u8> = (0..200_000)
        .map(|_| {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            (x >> 16) as u8
        })
        .collect();
    std::fs::write(udd.join("Default").join("noise.bin"), noise).unwrap();
    stored.meta.id
}

/// The files of `profile`'s user-data directory that the fixture writes.
fn files(profile: &str) -> Vec<Vec<u8>> {
    let udd = crate::profile::user_data_dir(profile).unwrap();
    [
        udd.join("Preferences"),
        udd.join("Default").join("noise.bin"),
    ]
    .iter()
    .map(|p| std::fs::read(p).unwrap())
    .collect()
}

/// The version `team-sync.db` pins for the local `profile`.
fn pinned_version(profile: &str) -> i64 {
    crate::team::sync::statuses(crate::root_bootstrap::now_ms())
        .unwrap()
        .profiles
        .into_iter()
        .find(|p| p.profile_id == profile)
        .expect("a bound profile")
        .remote_version
}

/// Custodian A and member B after the S3 journey, with A acting: both hold
/// generation 0 and share A's profile at version 2.
struct Journey {
    b: Member,
    h: Harness,
    b_id: String,
    a_profile: String,
    b_profile: String,
    profile_id: String,
}

#[test]
fn two_devices_share_a_profile_through_a_real_server_after_approval() {
    let rt = runtime();
    shared_profile(2, "cs3-join", &rt);
}

/// The S3 journey (plan section 5): B enrolls, A approves it, B joins and
/// collects, and the two pass one profile back and forth.
fn shared_profile(slot: u16, slug: &str, rt: &tokio::runtime::Runtime) -> Journey {
    let h = custodian(slot, slug, rt);
    let (user, pass) = account();
    let fleet_ref = format!("fleet-key.{}.0", h.tenant);
    let held = |r: &str| crate::credential::load(r).map(|k| *k);
    call(
        rt,
        crate::team_fleet_key_setup(OWNER.into(), PASSWORD.into()),
    )
    .unwrap();
    let a_key = held(&fleet_ref).expect("A's fleet key, in A's namespace");

    // 1. B enrolls. It may not list the fleet, and holds no generation 0.
    let b = Member {
        config: tempfile::tempdir().unwrap(),
        data: tempfile::tempdir().unwrap(),
    };
    b.act_as_b();
    note(crate::team_set_connection(
        h.server.url(),
        String::new(),
        h.tenant.clone(),
    ))
    .unwrap();
    let b_id = call(
        rt,
        crate::team_enroll_device("member".into(), OWNER.into(), PASSWORD.into()),
    )
    .unwrap()
    .device_id;
    let refused = call(
        rt,
        crate::sync_cmd::team_fleet_profiles(user.clone(), pass.clone()),
    )
    .unwrap_err();
    assert!(refused.contains("sync.noVerifiedFleetKey"), "{refused}");
    assert!(crate::fleet_keys::load()
        .unwrap()
        .active_key(&h.tenant)
        .is_none());
    let missing = held(&fleet_ref).unwrap_err();
    assert!(
        missing.to_string().contains("credential.missing"),
        "{missing}"
    );

    // 2. B's code is the one A computes for B's row.
    let code = call(rt, crate::team_join_code(OWNER.into(), PASSWORD.into())).unwrap();
    h.act_as_a();
    let rows = call(rt, crate::team_devices(OWNER.into(), PASSWORD.into())).unwrap();
    let row = rows.iter().find(|r| r.device_id == b_id).expect("B's row");
    assert_eq!(row.status, "pending");
    assert_eq!(row.sas, code.sas);
    assert_eq!(
        (&row.signing_key_id, &row.hpke_key_id),
        (&code.signing_key_id, &code.hpke_key_id)
    );
    assert_eq!(code.anchor, crate::root_bootstrap::load().unwrap().anchor);

    // 3. A approves B.
    call(
        rt,
        crate::team_approve_device(
            OWNER.into(),
            PASSWORD.into(),
            b_id.clone(),
            code.sas.clone(),
        ),
    )
    .unwrap();
    let of_b = |table: &str, extra: &str| {
        h.server.count(&format!(
            "SELECT count(*) FROM {table} WHERE lower(hex({col})) = '{b_id}' {extra}",
            col = if table == "v2_devices" {
                "id"
            } else {
                "subject_device_id"
            }
        ))
    };
    assert_eq!(of_b("v2_devices", "AND status = 'active'"), 1);
    assert_eq!(
        of_b("v2_device_approvals", "AND approval_scope_kind = 'fleet'"),
        1
    );
    assert_eq!(of_b("v2_capability_grants", ""), 3);
    assert_eq!(of_b("v2_fleet_device_hpke_grants", ""), 1);
    assert_eq!(held(&fleet_ref).unwrap(), a_key, "A's key is unchanged");

    // 4. B pins A0, then collects generation 0 and acknowledges it once.
    b.act_as_b();
    assert!(held(&fleet_ref).is_err(), "B's namespace holds no key yet");
    assert!(!crate::team_config::status().unwrap().has_fleet_key);
    call(
        rt,
        crate::team_join_confirm(
            OWNER.into(),
            PASSWORD.into(),
            code.anchor.clone(),
            code.sas.clone(),
        ),
    )
    .unwrap();
    call(
        rt,
        crate::team_collect_custody(OWNER.into(), PASSWORD.into()),
    )
    .unwrap();
    let (b_key, generation) = crate::fleet_keys::load()
        .unwrap()
        .active_key(&h.tenant)
        .expect("B holds generation 0");
    assert_eq!((b_key, generation), (a_key, 0));
    assert!(
        crate::team_config::status().unwrap().has_fleet_key,
        "B has joined"
    );
    assert_eq!(held(&fleet_ref).unwrap(), a_key, "now in B's namespace");
    assert_eq!(
        of_b("v2_fleet_device_hpke_grants", "AND acked_at IS NOT NULL"),
        1
    );
    let acks = || {
        h.server
            .count("SELECT count(*) FROM v2_audit_events WHERE action = 'fleet.key_grant.ack'")
    };
    let acked = acks();
    call(
        rt,
        crate::team_collect_custody(OWNER.into(), PASSWORD.into()),
    )
    .unwrap();
    assert_eq!(acks(), acked, "a second collect sends no ack");

    // A's key still lives only under A's namespace entry, B's under B's.
    h.act_as_a();
    assert_eq!(held(&fleet_ref).unwrap(), a_key);
    assert!(crate::fleet_custody::load()
        .unwrap()
        .members
        .contains_key(&b_id));

    // 5. A publishes and pushes version 1.
    let a_profile = local_profile("Shared", 1);
    let published = call(
        rt,
        crate::sync_cmd::profile_sync_publish(
            a_profile.clone(),
            Some("Shared".into()),
            user.clone(),
            pass.clone(),
        ),
    )
    .unwrap();
    let pushed = call(
        rt,
        crate::sync_cmd::profile_sync_push(
            a_profile.clone(),
            String::new(),
            0,
            user.clone(),
            pass.clone(),
        ),
    )
    .unwrap();
    assert_eq!(pushed.version, 1);
    let a_files = files(&a_profile);

    // 6. B lists, joins and pulls it: the files are A's.
    b.act_as_b();
    let listed = call(
        rt,
        crate::sync_cmd::team_fleet_profiles(user.clone(), pass.clone()),
    )
    .unwrap();
    let remote = listed
        .iter()
        .find(|p| p.remote_profile_id == published.profile_id)
        .expect("the published profile");
    assert_eq!(remote.label.as_deref(), Some("Shared"));
    let b_profile = local_profile("Shared", 2);
    std::fs::remove_dir_all(crate::profile::user_data_dir(&b_profile).unwrap()).unwrap();
    call(
        rt,
        crate::sync_cmd::team_join_profile(
            published.profile_id.clone(),
            b_profile.clone(),
            user.clone(),
            pass.clone(),
        ),
    )
    .unwrap();
    call(
        rt,
        crate::sync_cmd::profile_sync_pull(
            b_profile.clone(),
            String::new(),
            user.clone(),
            pass.clone(),
        ),
    )
    .unwrap();
    assert_eq!(files(&b_profile), a_files);

    // 7. B pushes version 2, and A pulls it.
    let udd = crate::profile::user_data_dir(&b_profile).unwrap();
    std::fs::write(udd.join("Preferences"), b"{\"from\":\"b\"}").unwrap();
    let pushed = call(
        rt,
        crate::sync_cmd::profile_sync_push(
            b_profile.clone(),
            String::new(),
            1,
            user.clone(),
            pass.clone(),
        ),
    )
    .unwrap();
    assert_eq!(pushed.version, 2);
    let b_files = files(&b_profile);
    let b_pin = pinned_version(&b_profile);
    h.act_as_a();
    call(
        rt,
        crate::sync_cmd::profile_sync_pull(
            a_profile.clone(),
            String::new(),
            user.clone(),
            pass.clone(),
        ),
    )
    .unwrap();
    assert_eq!(files(&a_profile), b_files);

    // 8. Both pins are the server head.
    let head = h.server.count(&format!(
        "SELECT current_version FROM v2_profiles WHERE lower(hex(id)) = '{}'",
        published.profile_id
    ));
    assert_eq!(head, 2);
    assert_eq!((pinned_version(&a_profile), b_pin), (head, head));
    Journey {
        b,
        h,
        b_id,
        a_profile,
        b_profile,
        profile_id: published.profile_id,
    }
}

#[test]
fn a_revoked_device_is_cut_off_but_keeps_the_key_it_already_holds_against_a_real_server() {
    let rt = runtime();
    let Journey {
        b,
        h,
        b_id,
        a_profile,
        profile_id,
        ..
    } = shared_profile(3, "cs4-revoke", &rt);
    let (user, pass) = account();

    // 1. A revokes B as retired.
    call(
        &rt,
        crate::team_revoke_device(
            OWNER.into(),
            PASSWORD.into(),
            b_id.clone(),
            "retired".into(),
        ),
    )
    .unwrap();
    let revoked = h.server.count(&format!(
        "SELECT count(*) FROM v2_devices WHERE lower(hex(id)) = '{b_id}' AND status = 'revoked'"
    ));
    assert_eq!(revoked, 1);
    assert_eq!(
        h.server
            .count("SELECT count(*) FROM v2_audit_events WHERE action = 'device.revoke'"),
        1
    );
    assert_eq!(
        h.server.count(&format!(
            "SELECT count(*) FROM v2_fleet_device_hpke_grants
              WHERE lower(hex(subject_device_id)) = '{b_id}' AND revoked_at IS NOT NULL"
        )),
        1,
        "B's fleet grant is revoked with it"
    );

    // 2. B is cut off from the server, but keeps generation 0.
    const REVOKED: &str = "the device is revoked and holds no live approval";
    b.act_as_b();
    let listed = call(
        &rt,
        crate::sync_cmd::team_fleet_profiles(user.clone(), pass.clone()),
    )
    .unwrap_err();
    assert!(listed.contains(REVOKED), "{listed}");
    let collected = call(
        &rt,
        crate::team_collect_custody(OWNER.into(), PASSWORD.into()),
    )
    .unwrap_err();
    assert!(collected.contains(REVOKED), "{collected}");
    let (b_key, generation) = crate::fleet_keys::load()
        .unwrap()
        .active_key(&h.tenant)
        .expect("B still holds generation 0");
    assert_eq!(generation, 0);
    let b_signing = shardx_core::keys::signing_key_id(
        crate::team_config::load()
            .unwrap()
            .signing_key()
            .unwrap()
            .verifying_key()
            .as_bytes(),
    );

    // 3. A new grant from A to B is refused.
    h.act_as_a();
    let c = crate::team_config::load().unwrap();
    let signer = c.signing_key().unwrap();
    let state = crate::fleet_custody::load().unwrap();
    let refused = with_session(&rt, &h, async |client, access| {
        use shardx_core::authz_record::{
            build_record, AuthorizationRecord, Payload, DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE,
        };
        use shardx_core::fleet_lifecycle::{FleetGrantVariant, FleetKeyGrantCreateV2};
        use shardx_core::mutation::{IdempotentMutationRequestV2, OperationKind};
        let saved = crate::fleet_client::decode_hex(&state.members[&b_id].grant_request).unwrap();
        let saved = IdempotentMutationRequestV2::parse(&saved).unwrap();
        let filing = FleetKeyGrantCreateV2::parse(&saved.canonical_payload_bytes).unwrap();
        let record = AuthorizationRecord::parse(&filing.exact_signed_grant_container_bytes)
            .unwrap()
            .verify_signature(signer.verifying_key().as_bytes())
            .unwrap();
        let Payload::DeviceHpkeGrant(mut grant) = record.payload().clone() else {
            panic!("B's device grant")
        };
        grant.common.replay_id = *uuid::Uuid::new_v4().as_bytes();
        let rows = client.list_tenant_devices(access, &h.tenant).await.unwrap();
        let row = rows.iter().find(|r| r.device_id == b_id).unwrap();
        let hpke = crate::fleet_client::decode_hex32(&row.hpke_public_key, "hpke").unwrap();
        shardx_core::grants::seal_device_fkek(&hpke, &mut grant, &b_key).unwrap();
        let container = build_record(&signer, DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE, &grant.encode());
        let hash = *AuthorizationRecord::parse(&container)
            .unwrap()
            .signed_container_hash();
        let fresh = FleetKeyGrantCreateV2::new(
            filing.grant.generation,
            FleetGrantVariant::DeviceHpke,
            grant.common.replay_id,
            hash,
            container,
        );
        let request = IdempotentMutationRequestV2 {
            operation_kind: OperationKind::FleetGrantCreate,
            idempotency_key: *uuid::Uuid::new_v4().as_bytes(),
            canonical_payload_bytes: fresh.encode(),
            client_request_nonce: *uuid::Uuid::new_v4().as_bytes(),
            server_instance_id: saved.server_instance_id,
            restore_epoch: saved.restore_epoch,
        };
        client
            .file_fleet_grant(access, &h.tenant, 0, &request.encode())
            .await
            .unwrap_err()
            .to_string()
    });
    assert!(
        refused.contains("the grant names no active device"),
        "{refused}"
    );
    assert_eq!(
        h.server.count(&format!(
            "SELECT count(*) FROM v2_fleet_device_hpke_grants
              WHERE lower(hex(subject_device_id)) = '{b_id}'"
        )),
        1
    );

    // 5. A pushes version 3 after the revoke. This comes before step 4: once
    // A's ledger counts the revocation, A's pin, version 2, has a signer
    // proven revoked, so it is quarantined SIGNER_REVOKED and an ordinary
    // push refuses (ADR 0002 rule 6, L1552-1553; unit test
    // `an_ordinary_push_refuses_over_a_pinned_head_whose_signer_is_proven_revoked`,
    // `team/sync.rs`). Version 3 is A's own, so pushing on it is not refused.
    let udd = crate::profile::user_data_dir(&a_profile).unwrap();
    std::fs::write(udd.join("Preferences"), b"{\"from\":\"a, after\"}").unwrap();
    let push = |base: i64| {
        call(
            &rt,
            crate::sync_cmd::profile_sync_push(
                a_profile.clone(),
                String::new(),
                base,
                user.clone(),
                pass.clone(),
            ),
        )
        .unwrap()
        .version
    };
    assert_eq!(push(2), 3);

    // 4. A's ledger counts the revocation, after step 5 for the reason given
    // there. The evidence holds B's approval only when B's key is asked for,
    // as a walk over B's heads asks; A's pin is A's own head now, so this
    // reads it the way `team::sync` walks do.
    let tenant = crate::fleet_client::decode_hex16(&h.tenant, "t").unwrap();
    let mut ledger = crate::team::db::Db::open().unwrap();
    let (binding, anchor, _) = crate::team::ledger::tenant_pin(&ledger, &tenant)
        .unwrap()
        .expect("A's pin");
    assert!(!crate::team::ledger::withdrawn(&ledger, &binding, &b_signing).unwrap());
    let pages = with_session(&rt, &h, async |client, access| {
        client
            .trust_evidence_of(access, &h.tenant, &[b_signing])
            .await
            .unwrap()
    });
    let now = crate::root_bootstrap::now_ms();
    let (seen, chain) = crate::team::ledger::evaluate(&ledger, &binding, &anchor, &pages, now)
        .unwrap()
        .expect("the evidence verifies to A's anchor");
    crate::team::ledger::record(&mut ledger, &binding, &seen, &chain, None, now).unwrap();
    assert!(crate::team::ledger::withdrawn(&ledger, &binding, &b_signing).unwrap());

    // 5, continued. Retired is advisory: generation 0 is not blocked, and A
    // still commits under it once its ledger counts the revocation.
    assert!(!crate::team::ledger::commit_blocked(&ledger, &binding, &anchor, &tenant, 0).unwrap());
    drop(ledger);
    std::fs::write(udd.join("Preferences"), b"{\"from\":\"a, counted\"}").unwrap();
    assert_eq!(push(3), 4);

    // 6. Section 7: version 3's ciphertext, leaked straight from the blob
    // store, opens with the generation-0 key B kept.
    let row = h.server.row(&format!(
        "SELECT snapshot_id, tenant_id, fleet_id, profile_id, key_generation,
                ciphertext_sha256, ciphertext_size, preamble_sha256, intent_hash,
                dek_slot_sha256, immutable_blob_path
           FROM v2_snapshots WHERE lower(hex(profile_id)) = '{profile_id}' AND version = 3"
    ));
    use sqlx::Row;
    let id16 = |c: &str| -> [u8; 16] { row.get::<Vec<u8>, _>(c).try_into().unwrap() };
    let id32 = |c: &str| -> [u8; 32] { row.get::<Vec<u8>, _>(c).try_into().unwrap() };
    assert_eq!(row.get::<i64, _>("key_generation"), 0);
    let blob = std::path::PathBuf::from(row.get::<String, _>("immutable_blob_path"));
    assert!(blob.starts_with(h.server.data.path()), "{}", blob.display());
    let scope = shardx_core::envelope_v2::Scope {
        snapshot_id: id16("snapshot_id"),
        tenant_id: id16("tenant_id"),
        fleet_id: id16("fleet_id"),
        profile_id: id16("profile_id"),
        target_version: 3,
        key_generation: 0,
    };
    let (sha, preamble, intent, slot) = (
        id32("ciphertext_sha256"),
        id32("preamble_sha256"),
        id32("intent_hash"),
        id32("dek_slot_sha256"),
    );
    let expected = shardx_core::envelope_v2::Expected {
        ciphertext_sha256: &sha,
        ciphertext_size: row.get::<i64, _>("ciphertext_size") as u64,
        preamble_sha256: &preamble,
        intent_hash: &intent,
        dek_slot_sha256: &slot,
        scope: &scope,
    };
    let open = |key: &[u8; 32]| {
        let mut plain = Vec::new();
        shardx_core::envelope_v2::open(
            &mut std::fs::File::open(&blob).unwrap(),
            &mut plain,
            key,
            &expected,
        )
        .map(|_| plain)
    };
    assert!(!open(&b_key).expect("B's key opens version 3").is_empty());
    assert!(open(&[0x5a; 32]).is_err(), "another key does not");
}

#[test]
fn the_journey_writes_one_audit_row_per_mutation() {
    let rt = runtime();
    let Journey { h, b_id, .. } = shared_profile(4, "cs5-audit", &rt);
    call(
        &rt,
        crate::team_revoke_device(OWNER.into(), PASSWORD.into(), b_id, "retired".into()),
    )
    .unwrap();
    let counts: Vec<(&str, i64)> = [
        "fleet.create",
        "capability.grant",
        "fleet.key_generation.create",
        "fleet.key_generation.activate",
        "fleet.key_grant.create",
        "fleet.key_grant.ack",
        "device.approve",
        "device.revoke",
    ]
    .into_iter()
    .map(|action| {
        let n = h.server.count(&format!(
            "SELECT count(*) FROM v2_audit_events WHERE action = '{action}'"
        ));
        (action, n)
    })
    .collect();
    assert_eq!(
        counts,
        [
            ("fleet.create", 1),
            // Six for A, three for B.
            ("capability.grant", 9),
            ("fleet.key_generation.create", 1),
            ("fleet.key_generation.activate", 1),
            // A's device and recovery grants, and B's device grant.
            ("fleet.key_grant.create", 3),
            ("fleet.key_grant.ack", 3),
            // D1 and B.
            ("device.approve", 2),
            ("device.revoke", 1),
        ]
    );
}

/// A fresh device with roots of its own, its credentials in `namespace`,
/// acting now and connected to `url` for `tenant`.
fn fresh_device(namespace: &str, url: String, tenant: String) -> Member {
    let m = Member {
        config: tempfile::tempdir().unwrap(),
        data: tempfile::tempdir().unwrap(),
    };
    act_as(m.config.path(), m.data.path(), namespace);
    note(crate::team_set_connection(url, String::new(), tenant)).unwrap();
    m
}

/// Imports the recovery bundle at `path` on the acting device.
fn import(rt: &tokio::runtime::Runtime, path: &str) -> Result<serde_json::Value, String> {
    call(
        rt,
        crate::team_import_recovery_bundle(
            path.into(),
            PASSPHRASE.into(),
            OWNER.into(),
            PASSWORD.into(),
            true,
        ),
    )
}

/// The server's audit rows other than device sessions and fleet grant acks,
/// and its fleet grant acks.
fn audit_rows(h: &Harness) -> (i64, i64) {
    (
        h.server.count(
            "SELECT count(*) FROM v2_audit_events
              WHERE action NOT IN ('auth.device_session', 'fleet.key_grant.ack')",
        ),
        h.server
            .count("SELECT count(*) FROM v2_audit_events WHERE action = 'fleet.key_grant.ack'"),
    )
}

/// S2 (plan v0.2.2b section 5): after the S3 journey A's machine is lost. A
/// fresh device C imports A's bootstrap bundle and keeps the team: it
/// approves a new device D, publishes, and revokes B.
#[test]
fn a_fresh_device_imports_the_recovery_bundle_and_keeps_the_team_against_a_real_server() {
    let rt = runtime();
    let Journey {
        b,
        h,
        b_id,
        b_profile,
        profile_id,
        ..
    } = shared_profile(6, "rs2-import", &rt);
    let (user, pass) = account();

    // A's seeds and fleet key are gone, and nothing reads A's roots again.
    h.act_as_a();
    let bundle = config_path("recovery.shardx-recovery");
    let a = crate::team_config::load().unwrap();
    for reference in [
        a.signing_credential_ref.clone(),
        a.hpke_credential_ref.clone(),
        format!("fleet-key.{}.0", h.tenant),
    ] {
        crate::credential::forget(&reference).unwrap();
    }

    // 1. C imports and holds generation 0; the import itself files nothing
    // but, at most, the collect's ack.
    let c = fresh_device("c", h.server.url(), h.tenant.clone());
    let before = audit_rows(&h);
    let report = import(&rt, &bundle).unwrap();
    let after = audit_rows(&h);
    assert_eq!(report["fleet_opened"], 1, "{report}");
    assert_eq!(after.0, before.0, "no audited mutation but the ack");
    assert!(after.1 - before.1 <= 1);
    let imported = crate::team_config::load().unwrap();
    assert_eq!(imported.device_id, a.device_id);
    assert_eq!(imported.fleet_id, h.tenant);
    assert!(crate::team_config::status().unwrap().has_fleet_key);

    // 2. D enrolls, C approves it, and D collects and pulls A's profile.
    let d = fresh_device("d", h.server.url(), h.tenant.clone());
    let d_id = call(
        &rt,
        crate::team_enroll_device("member-d".into(), OWNER.into(), PASSWORD.into()),
    )
    .unwrap()
    .device_id;
    let code = call(&rt, crate::team_join_code(OWNER.into(), PASSWORD.into())).unwrap();
    act_as(c.config.path(), c.data.path(), "c");
    let rows = call(&rt, crate::team_devices(OWNER.into(), PASSWORD.into())).unwrap();
    let row = rows.iter().find(|r| r.device_id == d_id).expect("D's row");
    assert_eq!(row.sas, code.sas);
    call(
        &rt,
        crate::team_approve_device(OWNER.into(), PASSWORD.into(), d_id, code.sas.clone()),
    )
    .unwrap();
    act_as(d.config.path(), d.data.path(), "d");
    call(
        &rt,
        crate::team_join_confirm(OWNER.into(), PASSWORD.into(), code.anchor, code.sas),
    )
    .unwrap();
    let collected = call(
        &rt,
        crate::team_collect_custody(OWNER.into(), PASSWORD.into()),
    )
    .unwrap();
    assert_eq!(collected["fleet_opened"], 1, "{collected}");
    let join_and_pull = |seed: u32| {
        let local = local_profile("Shared", seed);
        std::fs::remove_dir_all(crate::profile::user_data_dir(&local).unwrap()).unwrap();
        call(
            &rt,
            crate::sync_cmd::team_join_profile(
                profile_id.clone(),
                local.clone(),
                user.clone(),
                pass.clone(),
            ),
        )
        .unwrap();
        call(
            &rt,
            crate::sync_cmd::profile_sync_pull(
                local.clone(),
                String::new(),
                user.clone(),
                pass.clone(),
            ),
        )
        .unwrap();
        local
    };
    let d_profile = join_and_pull(4);
    let head = files(&d_profile);

    // 3. C publishes version 3, and B pulls it.
    act_as(c.config.path(), c.data.path(), "c");
    let c_profile = join_and_pull(3);
    assert_eq!(files(&c_profile), head);
    let udd = crate::profile::user_data_dir(&c_profile).unwrap();
    std::fs::write(udd.join("Preferences"), b"{\"from\":\"c\"}").unwrap();
    let pushed = call(
        &rt,
        crate::sync_cmd::profile_sync_push(
            c_profile.clone(),
            String::new(),
            2,
            user.clone(),
            pass.clone(),
        ),
    )
    .unwrap();
    assert_eq!(pushed.version, 3);
    let c_files = files(&c_profile);
    b.act_as_b();
    let pull_b = || {
        call(
            &rt,
            crate::sync_cmd::profile_sync_pull(
                b_profile.clone(),
                String::new(),
                user.clone(),
                pass.clone(),
            ),
        )
    };
    pull_b().unwrap();
    assert_eq!(files(&b_profile), c_files);

    // 4. C revokes B as lost; B's next pull is refused.
    act_as(c.config.path(), c.data.path(), "c");
    let revokes = || {
        h.server
            .count("SELECT count(*) FROM v2_audit_events WHERE action = 'device.revoke'")
    };
    let revoked_before = revokes();
    call(
        &rt,
        crate::team_revoke_device(OWNER.into(), PASSWORD.into(), b_id.clone(), "lost".into()),
    )
    .unwrap();
    assert_eq!(revokes(), revoked_before + 1);
    assert_eq!(
        h.server.count(&format!(
            "SELECT count(*) FROM v2_devices WHERE lower(hex(id)) = '{b_id}' AND status = 'revoked'"
        )),
        1
    );
    b.act_as_b();
    let refused = pull_b().unwrap_err();
    assert!(refused.contains("revoked"), "{refused}");
}

/// The state files a refused import must not leave on the acting device.
fn no_import_state(device: &str) {
    for path in [
        crate::store::custody_bootstrap_path(),
        crate::store::fleet_custody_path(),
        crate::store::fleet_keys_path(),
    ] {
        let path = path.unwrap();
        assert!(!path.exists(), "{}", path.display());
    }
    for kind in ["device-signing", "device-hpke"] {
        let err = crate::credential::load(&format!("{kind}.{device}")).unwrap_err();
        assert!(err.to_string().contains("credential.missing"), "{err}");
    }
}

#[test]
fn an_import_is_refused_for_a_v2_bundle_another_tenant_or_a_second_server_against_a_real_server() {
    let rt = runtime();
    let h = custodian(7, "rs2-refuse", &rt);
    let bundle = config_path("recovery.shardx-recovery");
    let a = crate::team_config::load().unwrap();
    let root = crate::root_bootstrap::load().unwrap();
    // A 2.7 bundle of this tenant: no root custodian.
    let v2 = config_path("v2.shardx-recovery");
    let (_, file) = shardx_core::recovery_bundle::seal(
        crate::fleet_client::decode_hex16(&h.tenant, "t").unwrap(),
        crate::fleet_client::decode_hex16(&root.server_instance_id, "i").unwrap(),
        0,
        crate::root_bootstrap::now_ms(),
        &shardx_core::recovery_bundle::RecoveryBundlePlaintextV2 {
            trk: [0x42; 32].into(),
            bootstrap_anchor_signing_key_id: [0; 32],
            retained_fkeks: Vec::new(),
            root_custodian: None,
        },
        PASSPHRASE,
    )
    .unwrap();
    std::fs::write(&v2, file).unwrap();
    let (second, other_tenant) = tenant_server(9, "rs2-other");

    for (url, tenant, path, code) in [
        (
            h.server.url(),
            h.tenant.clone(),
            &v2,
            "recovery.bundleWithoutCustodian",
        ),
        (
            second.url(),
            other_tenant.clone(),
            &bundle,
            "recovery.otherTenant",
        ),
        // The second server does not know the bundle's tenant.
        (
            second.url(),
            h.tenant.clone(),
            &bundle,
            "fleet.refusedLogin",
        ),
    ] {
        let _c = fresh_device("c", url, tenant);
        let team_json = std::fs::read(crate::store::team_config_path().unwrap()).unwrap();
        let err = import(&rt, path).unwrap_err();
        assert!(crate::errcode::has_code(&err, code), "{code}: {err}");
        assert_eq!(
            std::fs::read(crate::store::team_config_path().unwrap()).unwrap(),
            team_json
        );
        no_import_state(&a.device_id);
    }
}

#[test]
fn an_interrupted_import_resumes() {
    let rt = runtime();
    let h = custodian(8, "rs2-resume", &rt);
    call(
        &rt,
        crate::team_fleet_key_setup(OWNER.into(), PASSWORD.into()),
    )
    .unwrap();
    let bundle = config_path("recovery.shardx-recovery");
    let a = crate::team_config::load().unwrap();

    // The first run stores both seeds, then its team.json write fails.
    let c = fresh_device("c", h.server.url(), h.tenant.clone());
    let failed = rt.block_on(crate::recovery_import::run(
        std::path::Path::new(&bundle),
        PASSPHRASE,
        OWNER,
        PASSWORD,
        true,
        &mut |write| match write {
            crate::recovery_import::Write::Team(_) => anyhow::bail!("interrupted"),
            other => crate::recovery_import::save(other),
        },
    ));
    assert!(failed.is_err());
    assert!(crate::team_config::load().unwrap().device_id.is_empty());
    assert!(crate::credential::load(&format!("device-signing.{}", a.device_id)).is_ok());
    let saved = |path: anyhow::Result<std::path::PathBuf>| std::fs::read(path.unwrap()).unwrap();
    let root = saved(crate::store::custody_bootstrap_path());
    let custody = saved(crate::store::fleet_custody_path());

    // The second run resumes on the same states and finishes.
    let report = import(&rt, &bundle).unwrap();
    assert_eq!(report["fleet_opened"], 1, "{report}");
    assert_eq!(crate::team_config::load().unwrap().device_id, a.device_id);
    assert_eq!(saved(crate::store::custody_bootstrap_path()), root);
    assert_eq!(saved(crate::store::fleet_custody_path()), custody);
    let replaced = std::fs::read_dir(c.config.path())
        .unwrap()
        .filter(|e| {
            let name = e.as_ref().unwrap().file_name();
            name.to_string_lossy().contains(".replaced-")
        })
        .count();
    assert_eq!(replaced, 0, "no custody state was replaced");
}

/// The first `v2a.`, `v2t.` or `v2r.` token followed by 16 or more hex
/// digits in `text`.
fn session_token(text: &str) -> Option<&str> {
    let b = text.as_bytes();
    (0..b.len().saturating_sub(4)).find_map(|i| {
        let prefix = &b[i..i + 4];
        if &prefix[..2] != b"v2" || !matches!(prefix[2], b'a' | b't' | b'r') || prefix[3] != b'.' {
            return None;
        }
        let n = b[i + 4..]
            .iter()
            .take_while(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
            .count();
        (n >= 16).then(|| &text[i..i + 4 + n])
    })
}

/// Re-runs this test binary on the journey worker below, and scans what it
/// printed, every command reply and the devices' state files for the
/// account password, the recovery passphrase, the fleet key, the root key,
/// both HPKE private keys, every seed and any session token (plan v0.2.2a
/// section 8; v0.2.2b S2 adds the import).
#[test]
fn the_journey_leaks_no_secret_to_output_state_or_replies() {
    assert_eq!(
        session_token("x v2a.0123456789abcdef y"),
        Some("v2a.0123456789abcdef")
    );
    assert_eq!(session_token("v2t.0123456789abcde"), None);
    let scan = tempfile::tempdir().unwrap();
    let side = tempfile::tempdir().unwrap();
    let secrets_file = side.path().join("secrets.txt");
    let out = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "custodian_it::the_journey_leak_scan_worker",
            "--ignored",
            "--nocapture",
        ])
        .env(SCAN_DIR, scan.path())
        .env(SECRETS_FILE, &secrets_file)
        .output()
        .expect("re-run this test binary");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success() && stdout.contains("1 passed"),
        "the worker failed:\n{stdout}\n{stderr}"
    );

    let mut secrets: Vec<String> = std::fs::read_to_string(&secrets_file)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(
        secrets.len(),
        8,
        "the FKEK, the TRK, two HPKE private keys and both devices' four seeds"
    );
    secrets.push(PASSWORD.into());
    secrets.push(PASSPHRASE.into());
    let mut scanned = vec![
        ("stdout".to_string(), stdout),
        ("stderr".to_string(), stderr),
    ];
    for entry in std::fs::read_dir(scan.path()).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        scanned.push((
            name,
            String::from_utf8_lossy(&std::fs::read(&path).unwrap()).into_owned(),
        ));
    }
    let names: Vec<&str> = scanned.iter().map(|(n, _)| n.as_str()).collect();
    for expected in [
        "replies.jsonl",
        "a-team.json",
        "a-fleet-custody.json",
        "a-custody-bootstrap.json",
        "b-team.json",
        "c-team.json",
        "c-fleet-custody.json",
        "c-custody-bootstrap.json",
    ] {
        assert!(
            names.contains(&expected),
            "{expected} missing from {names:?}"
        );
    }
    let mut hits = Vec::new();
    for (name, text) in &scanned {
        let text = text.to_ascii_lowercase();
        for (n, secret) in secrets.iter().enumerate() {
            if text.contains(&secret.to_ascii_lowercase()) {
                hits.push(format!("{name}: secret #{n}"));
            }
        }
        if session_token(&text).is_some() {
            hits.push(format!("{name}: a session token"));
        }
    }
    assert!(hits.is_empty(), "{hits:?}");
    // Join codes belong in the deliberate IPC reply, but never in log lines.
    let replies = std::fs::read_to_string(scan.path().join("replies.jsonl")).unwrap();
    let codes: Vec<String> = replies
        .lines()
        .filter_map(|line| {
            serde_json::from_str::<serde_json::Value>(line)
                .ok()
                .and_then(|value| value.get("sas").and_then(|v| v.as_str()).map(str::to_owned))
        })
        .collect();
    assert!(
        !codes.is_empty(),
        "the journey must exercise a displayed join code"
    );
    for (_, output) in scanned
        .iter()
        .filter(|(name, _)| name == "stdout" || name == "stderr")
    {
        assert!(
            !codes.iter().any(|sas| output.contains(sas)),
            "a join code reached a log line"
        );
    }
}

/// Copies this device's team state files that exist into `dir`, each named
/// after `device`.
fn keep_state(dir: &std::path::Path, device: &str) {
    for path in [
        crate::store::team_config_path(),
        crate::store::fleet_custody_path(),
        crate::store::custody_bootstrap_path(),
    ] {
        let path = path.unwrap();
        if path.exists() {
            let name = path.file_name().unwrap().to_string_lossy();
            std::fs::copy(&path, dir.join(format!("{device}-{name}"))).unwrap();
        }
    }
}

/// The journey the leak scan watches: the S3 journey, A's revoke of B, B's
/// refused collect and a fresh device's import of A's recovery bundle. Each reply and each device's state files go to the
/// scan directory; the secrets to look for go to the side file.
#[test]
#[ignore = "a worker of the_journey_leaks_no_secret_to_output_state_or_replies"]
fn the_journey_leak_scan_worker() {
    let dir = std::path::PathBuf::from(std::env::var_os(SCAN_DIR).expect("run by the leak scan"));
    let secrets = std::env::var_os(SECRETS_FILE).expect("run by the leak scan");
    let rt = runtime();
    let Journey { b, h, b_id, .. } = shared_profile(5, "cs5-leak", &rt);
    call(
        &rt,
        crate::team_revoke_device(OWNER.into(), PASSWORD.into(), b_id, "retired".into()),
    )
    .unwrap();

    let fkek = crate::credential::load(&format!("fleet-key.{}.0", h.tenant)).unwrap();
    let c = crate::team_config::load().unwrap();
    let (a_sk, _) = shardx_core::grants::derive_keypair(&c.hpke_seed().unwrap());
    let a_signing_seed = c.signing_key().unwrap().to_bytes();
    let a_hpke_seed = c.hpke_seed().unwrap();
    let grants = with_session(&rt, &h, async |client, access| {
        client
            .root_key_grants(access, &h.tenant, &c.device_id)
            .await
            .unwrap()
    });
    let grant = grants.first().expect("A's root grant");
    let bytes = |s: &str| crate::fleet_client::decode_hex(s).unwrap();
    let trk = shardx_core::grants::open_trk_with_info(
        &a_sk,
        &bytes(&grant.hpke_info_hex),
        &bytes(&grant.hpke_encapped_key_hex),
        &bytes(&grant.hpke_wrapped_trk_hex),
    )
    .unwrap();
    keep_state(&dir, "a");
    let bundle = config_path("recovery.shardx-recovery");

    b.act_as_b();
    call(
        &rt,
        crate::team_collect_custody(OWNER.into(), PASSWORD.into()),
    )
    .unwrap_err();
    let b_config = crate::team_config::load().unwrap();
    let b_signing_seed = b_config.signing_key().unwrap().to_bytes();
    let b_hpke_seed = b_config.hpke_seed().unwrap();
    let (b_sk, _) = shardx_core::grants::derive_keypair(&b_hpke_seed);
    keep_state(&dir, "b");

    // A fresh device C imports A's bundle under its passphrase.
    let _c = fresh_device("c", h.server.url(), h.tenant.clone());
    import(&rt, &bundle).unwrap();
    keep_state(&dir, "c");
    std::fs::write(
        secrets,
        [
            hex(&*fkek),
            hex(&*trk),
            hex(&a_sk),
            hex(&b_sk),
            hex(&a_signing_seed),
            hex(&a_hpke_seed),
            hex(&b_signing_seed),
            hex(&b_hpke_seed),
        ]
        .join("\n"),
    )
    .unwrap();
}
