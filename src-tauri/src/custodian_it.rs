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
        let db = self.data.path().join("shardx.db");
        let url = format!(
            "sqlite://{}?mode=ro",
            db.to_string_lossy().replace('\\', "/")
        );
        runtime().block_on(async {
            use sqlx::Row;
            let pool = sqlx::sqlite::SqlitePoolOptions::new()
                .max_connections(1)
                .connect(&url)
                .await
                .expect("open the server database");
            let n = sqlx::query(query)
                .fetch_one(&pool)
                .await
                .expect(query)
                .get::<i64, _>(0);
            pool.close().await;
            n
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

    crate::team_set_connection(h.server.url(), String::new(), h.tenant.clone()).unwrap();
    let status = rt
        .block_on(crate::team_enroll_device(
            "custodian".into(),
            OWNER.into(),
            PASSWORD.into(),
        ))
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
    let root = rt
        .block_on(crate::team_bootstrap_custody(
            OWNER.into(),
            PASSWORD.into(),
            recovery,
            PASSPHRASE.into(),
        ))
        .unwrap();
    assert!(root.activated);
    h
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

    let status = rt
        .block_on(crate::team_fleet_key_setup(OWNER.into(), PASSWORD.into()))
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
    let status = rt
        .block_on(crate::team_fleet_key_setup(OWNER.into(), PASSWORD.into()))
        .unwrap();
    assert!(status.created && !status.setup_key_held, "{status:?}");
    assert_eq!(status.fkek_key_id, held);
    let gone = crate::credential::load(&name).unwrap_err();
    assert!(gone.to_string().contains("credential.missing"), "{gone}");
    assert_eq!(audit(&h), expected_audit());

    // A third run is answered from stored responses: nothing new is filed.
    let again = rt
        .block_on(crate::team_fleet_key_setup(OWNER.into(), PASSWORD.into()))
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
