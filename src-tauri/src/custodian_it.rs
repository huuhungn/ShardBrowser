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

#[test]
fn two_devices_share_a_profile_through_a_real_server_after_approval() {
    let rt = runtime();
    let h = custodian(2, "cs3-join", &rt);
    let (user, pass) = account();
    let fleet_ref = format!("fleet-key.{}.0", h.tenant);
    let held = |r: &str| crate::credential::load(r).map(|k| *k);
    rt.block_on(crate::team_fleet_key_setup(OWNER.into(), PASSWORD.into()))
        .unwrap();
    let a_key = held(&fleet_ref).expect("A's fleet key, in A's namespace");

    // 1. B enrolls. It may not list the fleet, and holds no generation 0.
    let b = Member {
        config: tempfile::tempdir().unwrap(),
        data: tempfile::tempdir().unwrap(),
    };
    b.act_as_b();
    crate::team_set_connection(h.server.url(), String::new(), h.tenant.clone()).unwrap();
    let b_id = rt
        .block_on(crate::team_enroll_device(
            "member".into(),
            OWNER.into(),
            PASSWORD.into(),
        ))
        .unwrap()
        .device_id;
    let refused = rt
        .block_on(crate::sync_cmd::team_fleet_profiles(
            user.clone(),
            pass.clone(),
        ))
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
    let code = rt
        .block_on(crate::team_join_code(OWNER.into(), PASSWORD.into()))
        .unwrap();
    h.act_as_a();
    let rows = rt
        .block_on(crate::team_devices(OWNER.into(), PASSWORD.into()))
        .unwrap();
    let row = rows.iter().find(|r| r.device_id == b_id).expect("B's row");
    assert_eq!(row.status, "pending");
    assert_eq!(row.sas, code.sas);
    assert_eq!(
        (&row.signing_key_id, &row.hpke_key_id),
        (&code.signing_key_id, &code.hpke_key_id)
    );
    assert_eq!(code.anchor, crate::root_bootstrap::load().unwrap().anchor);

    // 3. A approves B.
    rt.block_on(crate::team_approve_device(
        OWNER.into(),
        PASSWORD.into(),
        b_id.clone(),
        code.sas.clone(),
    ))
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
    rt.block_on(crate::team_join_confirm(
        OWNER.into(),
        PASSWORD.into(),
        code.anchor.clone(),
    ))
    .unwrap();
    rt.block_on(crate::team_collect_custody(OWNER.into(), PASSWORD.into()))
        .unwrap();
    let (b_key, generation) = crate::fleet_keys::load()
        .unwrap()
        .active_key(&h.tenant)
        .expect("B holds generation 0");
    assert_eq!((b_key, generation), (a_key, 0));
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
    rt.block_on(crate::team_collect_custody(OWNER.into(), PASSWORD.into()))
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
    let published = rt
        .block_on(crate::sync_cmd::profile_sync_publish(
            a_profile.clone(),
            Some("Shared".into()),
            user.clone(),
            pass.clone(),
        ))
        .unwrap();
    let pushed = rt
        .block_on(crate::sync_cmd::profile_sync_push(
            a_profile.clone(),
            String::new(),
            0,
            user.clone(),
            pass.clone(),
        ))
        .unwrap();
    assert_eq!(pushed.version, 1);
    let a_files = files(&a_profile);

    // 6. B lists, joins and pulls it: the files are A's.
    b.act_as_b();
    let listed = rt
        .block_on(crate::sync_cmd::team_fleet_profiles(
            user.clone(),
            pass.clone(),
        ))
        .unwrap();
    let remote = listed
        .iter()
        .find(|p| p.remote_profile_id == published.profile_id)
        .expect("the published profile");
    assert_eq!(remote.label.as_deref(), Some("Shared"));
    let b_profile = local_profile("Shared", 2);
    std::fs::remove_dir_all(crate::profile::user_data_dir(&b_profile).unwrap()).unwrap();
    rt.block_on(crate::sync_cmd::team_join_profile(
        published.profile_id.clone(),
        b_profile.clone(),
        user.clone(),
        pass.clone(),
    ))
    .unwrap();
    rt.block_on(crate::sync_cmd::profile_sync_pull(
        b_profile.clone(),
        String::new(),
        user.clone(),
        pass.clone(),
    ))
    .unwrap();
    assert_eq!(files(&b_profile), a_files);

    // 7. B pushes version 2, and A pulls it.
    let udd = crate::profile::user_data_dir(&b_profile).unwrap();
    std::fs::write(udd.join("Preferences"), b"{\"from\":\"b\"}").unwrap();
    let pushed = rt
        .block_on(crate::sync_cmd::profile_sync_push(
            b_profile.clone(),
            String::new(),
            1,
            user.clone(),
            pass.clone(),
        ))
        .unwrap();
    assert_eq!(pushed.version, 2);
    let b_files = files(&b_profile);
    let b_pin = pinned_version(&b_profile);
    h.act_as_a();
    rt.block_on(crate::sync_cmd::profile_sync_pull(
        a_profile.clone(),
        String::new(),
        user.clone(),
        pass.clone(),
    ))
    .unwrap();
    assert_eq!(files(&a_profile), b_files);

    // 8. Both pins are the server head.
    let head = h.server.count(&format!(
        "SELECT current_version FROM v2_profiles WHERE lower(hex(id)) = '{}'",
        published.profile_id
    ));
    assert_eq!(head, 2);
    assert_eq!((pinned_version(&a_profile), b_pin), (head, head));
    drop(b);
}
