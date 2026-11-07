//! Import recovery bundle (v0.2.2b plan, section 4.I).
//!
//! On a fresh device, or on the root custodian's own machine after its keys
//! were lost, a v3 recovery bundle restores the root custodian device itself:
//! its IDs, both key seeds and its first root self-grant. The server sees its
//! existing ACTIVE row with every grant it filed, and every member keeps the
//! anchor it pinned, so no server route is involved.
//!
//! Nothing is written until the bundle, the server's own listing of the
//! device, a session with the bundle's keys and the self-grant's readback all
//! agree. The state files are then written so that a crash leaves either
//! nothing usable or an import a second run resumes: `team.json` comes last.

use std::path::Path;

use anyhow::{anyhow, bail, Result};
use shardx_core::authz_record::{AuthorizationRecord, Payload};
use shardx_core::fleet_lifecycle::FleetKeyGrantAckV2;
use shardx_core::grants::derive_keypair;
use shardx_core::keys::{hpke_key_id, signing_key_id};
use shardx_core::mutation::{
    IdempotentMutationRequestV2, RootGenerationState, RootGrantState, TenantRootGrantDescriptorV2,
};
use shardx_core::recovery_bundle::{
    self as rb, RecoveryBundleHeaderV2, RecoveryBundlePlaintextV2, RootCustodian,
};
use shardx_core::signing::Ed25519SigningKey;

use crate::fleet_client::{decode_hex16, hex, AccountDeviceStatus, AccountLogin, FleetClient};
use crate::fleet_custody::FleetCustodyState;
use crate::root_bootstrap::{now_ms, own_grant, unhex_vec, BootstrapState};
use crate::team_config::TeamConfig;

/// One state write of step 6. Each goes through the caller's `save`, which
/// tests fail on purpose.
pub enum Write<'a> {
    Root(&'a BootstrapState),
    Custody(&'a FleetCustodyState),
    Team(&'a TeamConfig),
}

/// The launcher's own saves.
pub fn save(write: Write<'_>) -> Result<()> {
    match write {
        Write::Root(s) => crate::root_bootstrap::save(s),
        Write::Custody(s) => crate::fleet_custody::save(s),
        Write::Team(c) => crate::team_config::save(c),
    }
}

/// The opened bundle, and the exact file it came from.
pub(crate) struct Bundle<'a> {
    pub path: &'a Path,
    pub file: &'a [u8],
    pub header: RecoveryBundleHeaderV2,
    pub plaintext: RecoveryBundlePlaintextV2,
}

/// Logs how `step` ended, naming only the error's code: a refusal's server
/// text, which may echo anything, is never logged.
fn logged<T>(step: &str, result: Result<T>) -> Result<T> {
    match &result {
        Ok(_) => eprintln!("[recovery] import {step}: ok"),
        Err(e) => eprintln!(
            "[recovery] import {step}: refused {}",
            error_code(&e.to_string())
        ),
    }
    result
}

/// The code of the first error marker in `text`, or "error".
pub(crate) fn error_code(text: &str) -> &str {
    text.split("[[shardx:")
        .nth(1)
        .and_then(|rest| rest.split(['|', ']']).next())
        .unwrap_or("error")
}

/// Whether `e` is the `key` refusal with HTTP `status`, read from the
/// marker's own fields as `fleet_custody::outside_window` reads them: every
/// value is escaped, so no echoed text forges a field.
fn refused_with(e: &anyhow::Error, key: &str, status: &str) -> bool {
    let text = e.to_string();
    let open = format!("[[shardx:{key}|");
    let status = format!("status={status}");
    text.find(&open)
        .and_then(|i| text[i + open.len()..].split("]]").next())
        .is_some_and(|args| args.split('|').any(|field| field == status))
}

/// Step 4, run only once step 3 saw this device active with the bundle's
/// keys: a 409 on the session then means its row holds no live approval (the
/// server's other 409s are rare then, and read the same). Only the status
/// decides, never the server's text.
fn session_refusal(e: anyhow::Error) -> anyhow::Error {
    if refused_with(&e, "fleet.refusedSession", "409") {
        anyhow!(crate::errcode::code("recovery.approvalExpired"))
    } else {
        e
    }
}

/// Step 1, before the bundle is read.
fn preconditions(
    c: &TeamConfig,
    username: &str,
    password: &str,
    old_device_lost: bool,
) -> Result<()> {
    if c.server_url.is_empty() {
        bail!(crate::errcode::code("fleet.setServerFirst"));
    }
    if c.tenant_id.is_empty() {
        bail!(crate::errcode::code("fleet.setTenantFirst"));
    }
    if username.is_empty() || password.is_empty() {
        bail!(crate::errcode::code("fleet.setAccountFirst"));
    }
    if !old_device_lost {
        return Err(anyhow!(crate::errcode::code(
            "recovery.confirmOldDeviceLost"
        )));
    }
    Ok(())
}

/// Step 2, and step 1's identity rule (C1): the bundle carries a root
/// custodian of the saved tenant, and `team.json` names no device or that
/// one, whose seeds are the bundle's or no longer load.
fn custodian_of<'b>(
    c: &TeamConfig,
    header: &RecoveryBundleHeaderV2,
    plaintext: &'b RecoveryBundlePlaintextV2,
) -> Result<&'b RootCustodian> {
    let Some(custodian) = &plaintext.root_custodian else {
        return Err(anyhow!(crate::errcode::code(
            "recovery.bundleWithoutCustodian"
        )));
    };
    if decode_hex16(&c.tenant_id, "tenant_id").ok() != Some(header.tenant_id) {
        return Err(anyhow!(crate::errcode::code("recovery.otherTenant")));
    }
    let other = !c.device_id.is_empty()
        && (!c.device_id.eq_ignore_ascii_case(&hex(&custodian.device_id))
            || c.signing_key()
                .is_ok_and(|k| k.to_bytes() != *custodian.signing_key_seed)
            || c.hpke_seed().is_ok_and(|s| s != *custodian.hpke_key_seed));
    if other {
        return Err(anyhow!(crate::errcode::code("recovery.deviceHasIdentity")));
    }
    Ok(custodian)
}

/// A tenant this device already pinned keeps its anchor: a bundle naming
/// another one (a made-up bundle from a server posing as the team's) is
/// refused before any request.
fn check_pin(header: &RecoveryBundleHeaderV2, plaintext: &RecoveryBundlePlaintextV2) -> Result<()> {
    match crate::tenant_pin(&header.tenant_id)? {
        Some((_, anchor, _)) if anchor != plaintext.bootstrap_anchor_signing_key_id => {
            Err(anyhow!(crate::errcode::code("recovery.otherAnchor")))
        }
        _ => Ok(()),
    }
}

/// Step 3: the server is the bundle's, the ticket's account is the bundle's,
/// and it lists the bundle's device active with the bundle's key IDs.
fn check_listing(
    me: &AccountDeviceStatus,
    header: &RecoveryBundleHeaderV2,
    custodian: &RootCustodian,
    signing_id: &str,
    hpke_id: &str,
) -> Result<()> {
    if !me
        .server_instance_id
        .eq_ignore_ascii_case(&hex(&header.server_instance_id))
    {
        return Err(anyhow!(crate::errcode::code("recovery.otherServer")));
    }
    if !me
        .account_id
        .eq_ignore_ascii_case(&hex(&custodian.account_id))
    {
        return Err(anyhow!(crate::errcode::code("recovery.otherAccount")));
    }
    let active = me.device.as_ref().is_some_and(|d| {
        d.status == "active"
            && d.signing_key_id.eq_ignore_ascii_case(signing_id)
            && d.hpke_key_id.eq_ignore_ascii_case(hpke_id)
    });
    if !active {
        return Err(anyhow!(crate::errcode::code("recovery.deviceNotActive")));
    }
    Ok(())
}

/// Step 5: the server reads the bundle's self-grant back exactly,
/// acknowledged under an ACTIVE root generation, and it opens to the
/// bundle's TRK. Export again (section 4.X step 3) runs it too.
pub(crate) async fn check_root_grant(
    client: &FleetClient,
    access: &str,
    tenant: &str,
    container: &[u8],
    signer: &Ed25519SigningKey,
    hpke_secret: &[u8],
    trk: &[u8; 32],
) -> Result<()> {
    let missing = || anyhow!(crate::errcode::code("recovery.rootGrantMissing"));
    let (grant, grant_ref) = own_grant(container, signer).map_err(|_| missing())?;
    let descriptor = client
        .read_root_grant(
            access,
            tenant,
            grant.root_generation,
            &hex(&grant_ref.replay_id),
        )
        .await
        .map_err(|e| {
            if refused_with(&e, "fleet.refusedCustody", "404") {
                missing()
            } else {
                e
            }
        })?;
    let live = TenantRootGrantDescriptorV2::parse(&descriptor, signer.verifying_key().as_bytes())
        .is_ok_and(|d| {
            d.record().record().exact_signed_container_bytes() == container
                && matches!(d.grant_state(), RootGrantState::Acknowledged)
                && matches!(d.generation_state(), RootGenerationState::Active)
                && matches!(d.record().payload(), Payload::TenantRootKeyGrant(g)
                    if g.open_trk(hpke_secret).is_ok_and(|opened| *opened == *trk))
        });
    if !live {
        return Err(missing());
    }
    Ok(())
}

/// Runs the import of the bundle at `path` (section 4.I steps 1 to 6) as
/// `username`'s account. The passphrase and password serve this run only.
pub async fn run(
    path: &Path,
    passphrase: &str,
    username: &str,
    password: &str,
    old_device_lost: bool,
    save: &mut impl FnMut(Write<'_>) -> Result<()>,
) -> Result<()> {
    let mut c = crate::team_config::load()?;
    logged(
        "preconditions",
        preconditions(&c, username, password, old_device_lost),
    )?;
    // Neither the passphrase nor the file's content is in the error.
    let unopened = || anyhow!(crate::errcode::code("recovery.bundleDoesNotOpen"));
    let file = logged("read", std::fs::read(path).map_err(|_| unopened()))?;
    let (header, plaintext) = logged("open", rb::open(&file, passphrase).map_err(|_| unopened()))?;
    let bundle = Bundle {
        path,
        file: &file,
        header,
        plaintext,
    };
    import(&mut c, &bundle, username, password, save).await
}

/// Steps 2 to 6 for an opened bundle.
pub(crate) async fn import(
    c: &mut TeamConfig,
    bundle: &Bundle<'_>,
    username: &str,
    password: &str,
    save: &mut impl FnMut(Write<'_>) -> Result<()>,
) -> Result<()> {
    let custodian = logged("bundle", custodian_of(c, &bundle.header, &bundle.plaintext))?;
    logged("pin", check_pin(&bundle.header, &bundle.plaintext))?;
    let tenant = c.tenant_id.clone();
    let device = hex(&custodian.device_id);
    let signer = Ed25519SigningKey::from_bytes(&custodian.signing_key_seed);
    let (hpke_secret, hpke_public) = derive_keypair(&custodian.hpke_key_seed);
    let client = FleetClient::new(&c.server_url, &c.token)?;
    let login = AccountLogin {
        tenant_id: &tenant,
        username,
        password,
    };

    // 3. Before any session is opened.
    let me = logged(
        "listing",
        async {
            let me = client.account_device_status(&login, &device).await?;
            check_listing(
                &me,
                &bundle.header,
                custodian,
                &hex(&signing_key_id(signer.verifying_key().as_bytes())),
                &hex(&hpke_key_id(&hpke_public)),
            )?;
            Ok(me)
        }
        .await,
    )?;

    // 4 and 5.
    let session = logged(
        "session",
        client
            .open_device_session(&login, &device, &signer, &custodian.hpke_key_seed)
            .await
            .map_err(session_refusal),
    )?;
    let access = session.access_token.as_str();
    let checked = async {
        check_root_grant(
            &client,
            access,
            &tenant,
            &custodian.first_self_grant,
            &signer,
            &hpke_secret,
            &bundle.plaintext.trk,
        )
        .await?;
        // The tenant's one fleet has the tenant's id (`sync_cmd::fleet_id`).
        Ok::<_, anyhow::Error>(
            client
                .active_fleet_generation(access, &tenant, &tenant)
                .await?
                .is_some(),
        )
    }
    .await;
    client.end_session(access).await;
    let fleet_active = logged("root grant", checked)?;

    // 6.
    logged(
        "write",
        write(c, bundle, custodian, me.restore_epoch, fleet_active, save),
    )
}

/// `<path>.<suffix>-<ms>`: where a state file is copied aside.
fn aside(path: &Path, suffix: &str) -> std::path::PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    path.with_extension(format!("json.{suffix}-{stamp}"))
}

/// The signed container hash of the grant a saved ack request acknowledges.
fn acked_grant(request: &str) -> Option<[u8; 32]> {
    let request = IdempotentMutationRequestV2::parse(&unhex_vec(request).ok()?).ok()?;
    let ack = FleetKeyGrantAckV2::parse(&request.canonical_payload_bytes).ok()?;
    Some(ack.grant.signed_container_hash)
}

/// Step 6. Both custody states are checked before anything is written; then
/// the root state, the custody state, the fleet key index, the seeds and,
/// last, `team.json`.
fn write(
    c: &mut TeamConfig,
    bundle: &Bundle<'_>,
    custodian: &RootCustodian,
    restore_epoch: u64,
    fleet_active: bool,
    save: &mut impl FnMut(Write<'_>) -> Result<()>,
) -> Result<()> {
    let tenant = c.tenant_id.clone();
    let device = hex(&custodian.device_id);
    let ours =
        |t: &str, d: &str| t.eq_ignore_ascii_case(&tenant) && d.eq_ignore_ascii_case(&device);
    let anchor = hex(&bundle.plaintext.bootstrap_anchor_signing_key_id);
    let self_grant = hex(&custodian.first_self_grant);
    let instance = hex(&bundle.header.server_instance_id);

    // `team.json` may have changed during the network steps (Enroll, a new
    // connection): only the identity that was checked is written over.
    let now = crate::team_config::load()?;
    let unchanged = now.server_url == c.server_url
        && now.tenant_id == c.tenant_id
        && now.device_id == c.device_id
        && now.signing_credential_ref == c.signing_credential_ref
        && now.hpke_credential_ref == c.hpke_credential_ref;
    if !unchanged {
        bail!(crate::errcode::code("recovery.deviceHasIdentity"));
    }

    // A6: a root state on disk is kept only when it is this one.
    let root_on_disk = crate::store::custody_bootstrap_path()?.exists();
    let root = crate::root_bootstrap::load()?;
    let same_root = ours(&root.tenant_id, &root.device_id)
        && root.self_grant.eq_ignore_ascii_case(&self_grant)
        && root.anchor.eq_ignore_ascii_case(&anchor);
    if root_on_disk && !same_root {
        bail!(crate::errcode::code("fleet.custodyOtherDevice"));
    }
    // A2: a member's custody state is replaced, another custodian's refused.
    let custody_path = crate::store::fleet_custody_path()?;
    let custody_on_disk = custody_path.exists();
    let mut custody = crate::fleet_custody::load()?;
    let member = custody.create_request.is_empty()
        && !custody.imported
        && custody.capability_grants.is_empty();
    if custody_on_disk && !member && !ours(&custody.tenant_id, &custody.device_id) {
        bail!(crate::errcode::code("fleet.custodyOtherDevice"));
    }

    // 6.1. Inert until `team.json` names the device.
    if !root_on_disk {
        save(Write::Root(&BootstrapState {
            tenant_id: tenant.clone(),
            device_id: device.clone(),
            server_instance_id: instance.clone(),
            restore_epoch,
            self_grant,
            anchor,
            activated: true,
            recovery_path: bundle.path.to_string_lossy().into_owned(),
            recovery_bundle_sha256: hex(&rb::recovery_bundle_sha256(bundle.file)),
            ..Default::default()
        }))?;
    }

    // 6.2.
    if !custody_on_disk || member {
        if custody_on_disk {
            let copy = aside(&custody_path, "replaced");
            std::fs::copy(&custody_path, &copy)?;
            // Flushing needs a writable handle on Windows.
            std::fs::OpenOptions::new()
                .write(true)
                .open(&copy)?
                .sync_all()?;
            eprintln!(
                "[recovery] import: a member's custody state copied to {}",
                copy.display()
            );
        }
        save(Write::Custody(&FleetCustodyState {
            tenant_id: tenant.clone(),
            device_id: device.clone(),
            server_instance_id: instance,
            restore_epoch,
            imported: fleet_active,
            ..Default::default()
        }))?;
    } else {
        // G12: an ack saved for another device's grant would be resent by
        // the collect. An ack names only its grant, so one is kept only for
        // this custodian's own device grant.
        let own = unhex_vec(&custody.device_grant)
            .ok()
            .and_then(|g| AuthorizationRecord::parse(&g).ok())
            .map(|r| *r.signed_container_hash());
        let saved = custody.device_acks.len();
        custody
            .device_acks
            .retain(|_, request| own.is_some() && acked_grant(request) == own);
        if custody.device_acks.len() != saved {
            save(Write::Custody(&custody))?;
        }
    }

    // 6.3. Stored keys stay; the collect writes the key again.
    let removed = crate::fleet_keys::unindex_unopenable(&tenant)?;
    eprintln!("[recovery] import: unindexed fleet key generations {removed:?}");

    // 6.4. `store` reads each seed back.
    let signing_ref = format!("device-signing.{device}");
    let hpke_ref = format!("device-hpke.{device}");
    crate::credential::store(&signing_ref, &custodian.signing_key_seed)?;
    crate::credential::store(&hpke_ref, &custodian.hpke_key_seed)?;

    // 6.5. The commit point.
    if crate::store::team_config_path()?.exists() {
        let copy = crate::team_config::preserve_unreadable()?;
        eprintln!("[recovery] import: team.json copied to {}", copy.display());
    }
    c.device_id = device;
    c.account_id = hex(&custodian.account_id);
    c.fleet_id = tenant;
    c.signing_key_seed = Default::default();
    c.hpke_key_seed = Default::default();
    c.signing_credential_ref = signing_ref;
    c.hpke_credential_ref = hpke_ref;
    c.enrolled_at_ms = now_ms();
    save(Write::Team(c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleet_custody::tests::{mock, runtime, Reply, Seen};
    use crate::root_bootstrap::Context16;
    use std::sync::Arc;

    const TENANT: [u8; 16] = [0x1e; 16];
    const INSTANCE: [u8; 16] = [0x2e; 16];
    const ACCOUNT: [u8; 16] = [0x4e; 16];
    const DEVICE: [u8; 16] = [0x5e; 16];
    const SIGNING_SEED: [u8; 32] = [0x3e; 32];
    const HPKE_SEED: [u8; 32] = [0x7e; 32];
    const TRK: [u8; 32] = [0x9e; 32];

    /// One device's config root, and the bundle of a root custodian made from
    /// the constants above. The plaintext is built, not sealed: these tests
    /// cover what comes after `rb::open`, without an Argon2id run each.
    struct Fixture {
        _lock: std::sync::MutexGuard<'static, ()>,
        dir: tempfile::TempDir,
        self_grant: Vec<u8>,
        file: Vec<u8>,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            crate::store::set_config_root(None);
        }
    }

    fn signer() -> Ed25519SigningKey {
        Ed25519SigningKey::from_bytes(&SIGNING_SEED)
    }

    fn key_ids() -> (String, String) {
        let (_, pk) = derive_keypair(&HPKE_SEED);
        (
            hex(&signing_key_id(signer().verifying_key().as_bytes())),
            hex(&hpke_key_id(&pk)),
        )
    }

    fn fixture() -> Fixture {
        let lock = crate::store::config_root_test_lock()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().unwrap();
        crate::store::set_config_root(Some(dir.path().to_path_buf()));
        let (_, pk) = derive_keypair(&HPKE_SEED);
        let cx = Context16 {
            tenant: TENANT,
            instance: INSTANCE,
            epoch: 0,
            account: ACCOUNT,
            device: DEVICE,
            signing_key_id: signing_key_id(signer().verifying_key().as_bytes()),
            hpke_key_id: hpke_key_id(&pk),
        };
        let self_grant =
            crate::root_bootstrap::self_grant(&cx, &signer(), &pk, &TRK, [8; 16], now_ms())
                .unwrap();
        Fixture {
            _lock: lock,
            dir,
            self_grant,
            file: b"bundle file bytes".to_vec(),
        }
    }

    impl Fixture {
        fn bundle(&self) -> Bundle<'_> {
            Bundle {
                path: Path::new("recovery.shxrecovery"),
                file: &self.file,
                header: RecoveryBundleHeaderV2 {
                    tenant_id: TENANT,
                    server_instance_id: INSTANCE,
                    root_generation: 0,
                    root_key_id: shardx_core::keys::root_key_id(&TRK),
                    kdf_memory_kib: rb::DEFAULT_KDF_MEMORY_KIB,
                    kdf_iterations: rb::DEFAULT_KDF_ITERATIONS,
                    kdf_salt: [0; 16],
                    aead_nonce: [0; 12],
                    created_at_ms: 0,
                },
                plaintext: RecoveryBundlePlaintextV2 {
                    trk: TRK.into(),
                    bootstrap_anchor_signing_key_id: signing_key_id(
                        signer().verifying_key().as_bytes(),
                    ),
                    retained_fkeks: Vec::new(),
                    root_custodian: Some(RootCustodian {
                        account_id: ACCOUNT,
                        device_id: DEVICE,
                        signing_key_seed: SIGNING_SEED.into(),
                        hpke_key_seed: HPKE_SEED.into(),
                        first_self_grant: self.self_grant.clone(),
                    }),
                },
            }
        }

        /// Saves a connection to `server_url` for this tenant, as a fresh
        /// device has it.
        fn connected(&self, server_url: &str) -> TeamConfig {
            let c = TeamConfig {
                server_url: server_url.into(),
                tenant_id: hex(&TENANT),
                ..Default::default()
            };
            crate::team_config::save(&c).unwrap();
            c
        }

        /// Every file in the config root, with its bytes.
        fn files(&self) -> Vec<(String, Vec<u8>)> {
            let mut out: Vec<_> = std::fs::read_dir(self.dir.path())
                .unwrap()
                .map(|e| e.unwrap().path())
                .filter(|p| p.is_file())
                .map(|p| {
                    let name = p.file_name().unwrap().to_string_lossy().into_owned();
                    (name, std::fs::read(&p).unwrap())
                })
                .collect();
            out.sort();
            out
        }
    }

    /// A `/v2/me` reply for the ticket's `account`, listing this device as
    /// `status` with `key_ids`, from server `instance`.
    fn me(
        instance: [u8; 16],
        account: [u8; 16],
        status: &str,
        key_ids: (String, String),
    ) -> serde_json::Value {
        serde_json::json!({
            "kind": "pre_device",
            "account_id": hex(&account),
            "server_instance_id": hex(&instance),
            "restore_epoch": 0,
            "devices": [{
                "device_id": hex(&DEVICE),
                "status": status,
                "signing_key_id": key_ids.0,
                "hpke_key_id": key_ids.1,
            }],
        })
    }

    /// A server that logs a ticket in, answers `/v2/me` with `me` and the
    /// session challenge with `challenge`.
    fn server(me: serde_json::Value, challenge: (u16, &'static str)) -> Arc<Reply> {
        Arc::new(move |call: &str, _: &[u8]| match call {
            "POST /v2/auth/login" => (
                200,
                serde_json::to_vec(&serde_json::json!({
                    "ticket": "v2t.0123456789abcdef0123",
                    "ticket_id": hex(&[1; 16]),
                    "account_id": hex(&ACCOUNT),
                    "server_instance_id": hex(&INSTANCE),
                    "restore_epoch": 0,
                }))
                .unwrap(),
            ),
            "GET /v2/me" => (200, serde_json::to_vec(&me).unwrap()),
            "POST /v2/auth/logout" => (204, Vec::new()),
            "POST /v2/auth/device-session-challenges" => {
                (challenge.0, challenge.1.as_bytes().to_vec())
            }
            _ => (500, Vec::new()),
        })
    }

    /// One import against `reply`; returns its error, the requests the
    /// server saw, and whether the config root is as it was before.
    fn refused_by(f: &Fixture, reply: Arc<Reply>) -> (String, Vec<String>, bool) {
        let rt = runtime();
        let (client, seen): (FleetClient, Seen) = rt.block_on(mock(reply));
        let mut c = f.connected(client.base_url());
        let before = f.files();
        let err = rt
            .block_on(import(&mut c, &f.bundle(), "owner", "pw", &mut save))
            .unwrap_err()
            .to_string();
        let calls = seen
            .lock()
            .unwrap()
            .iter()
            .map(|(c, _)| c.clone())
            .collect();
        (err, calls, f.files() == before)
    }

    const CHALLENGE: &str = "POST /v2/auth/device-session-challenges";

    /// Step 5 runs over the device session, but the server got the account
    /// password at login: a root grant read that echoes it never returns it.
    #[test]
    fn a_root_grant_refusal_after_the_session_hides_the_login_password() {
        let f = fixture();
        let rt = runtime();
        let password = format!("account-password-{}", crate::fleet_client::random_id_hex());
        let echo = format!(r#"{{"error":"{password}"}}"#).into_bytes();
        let ordinary = server(me(INSTANCE, ACCOUNT, "active", key_ids()), (500, ""));
        // The login's ticket ID is [1; 16].
        let challenge = crate::fleet_client::tests::session_challenge(
            TENANT,
            INSTANCE,
            ACCOUNT,
            [1; 16],
            DEVICE,
            &signer(),
            &HPKE_SEED,
        );
        let reply: Arc<Reply> = Arc::new(move |call: &str, body: &[u8]| match call {
            CHALLENGE => (200, challenge.clone()),
            "POST /v2/auth/device-session-proofs" => (
                200,
                serde_json::to_vec(&serde_json::json!({
                    "session_id": "s",
                    "class": "full",
                    "access_token": "v2a.x",
                    "access_expires_at_ms": 1,
                    "refresh_token": "v2r.x",
                    "absolute_expires_at_ms": 2,
                }))
                .unwrap(),
            ),
            c if c.starts_with("GET /v2/tenants/") => (500, echo.clone()),
            _ => ordinary(call, body),
        });
        let (client, seen): (FleetClient, Seen) = rt.block_on(mock(reply));
        let mut c = f.connected(client.base_url());
        let before = f.files();
        let err = rt
            .block_on(import(&mut c, &f.bundle(), "owner", &password, &mut save))
            .unwrap_err()
            .to_string();
        assert!(
            seen.lock()
                .unwrap()
                .iter()
                .any(|(c, _)| c.starts_with("GET /v2/tenants/")),
            "the import did not reach the root grant read"
        );
        assert!(f.files() == before);
        assert!(
            crate::errcode::has_code(&err, "fleet.refusedCustody"),
            "another refusal than the root grant read's"
        );
        assert!(
            !err.contains(&password),
            "the account password reached the import error"
        );
    }

    #[test]
    fn import_error_does_not_echo_the_login_password_after_login() {
        let f = fixture();
        let ordinary = server(me(INSTANCE, ACCOUNT, "active", key_ids()), (500, ""));
        let reply: Arc<Reply> = Arc::new(move |call, body| {
            if call == "GET /v2/me" {
                (500, br#"{"error":"pw"}"#.to_vec())
            } else {
                ordinary(call, body)
            }
        });
        let (err, calls, unchanged) = refused_by(&f, reply);
        assert!(calls.iter().any(|c| c == "GET /v2/me"));
        assert!(unchanged);
        assert!(
            !err.contains("pw"),
            "account password reached the import error"
        );
    }

    #[test]
    fn import_rejects_a_different_hpke_id_without_writing() {
        let f = fixture();
        let listing = me(INSTANCE, ACCOUNT, "active", (key_ids().0, hex(&[0xee; 32])));
        let (err, calls, unchanged) = refused_by(&f, server(listing, (500, "")));
        assert!(crate::errcode::has_code(&err, "recovery.deviceNotActive"));
        assert!(!calls.iter().any(|c| c == CHALLENGE));
        assert!(unchanged);
    }

    #[test]
    fn another_server_is_refused_before_any_session_is_asked_for() {
        let f = fixture();
        let reply = server(me([0xee; 16], ACCOUNT, "active", key_ids()), (500, ""));
        let (err, calls, unchanged) = refused_by(&f, reply);
        assert!(
            crate::errcode::has_code(&err, "recovery.otherServer"),
            "{err}"
        );
        assert!(!calls.iter().any(|c| c == CHALLENGE), "{calls:?}");
        assert!(unchanged);
    }

    #[test]
    fn a_revoked_row_keys_that_differ_and_another_account_are_refused() {
        let f = fixture();
        let other_keys = (hex(&[1; 32]), key_ids().1);
        for (listing, code) in [
            (
                me(INSTANCE, ACCOUNT, "revoked", key_ids()),
                "recovery.deviceNotActive",
            ),
            (
                me(INSTANCE, ACCOUNT, "active", other_keys),
                "recovery.deviceNotActive",
            ),
            (
                me(INSTANCE, [0xac; 16], "active", key_ids()),
                "recovery.otherAccount",
            ),
        ] {
            let (err, calls, unchanged) = refused_by(&f, server(listing, (500, "")));
            assert!(crate::errcode::has_code(&err, code), "{code}: {err}");
            assert!(!calls.iter().any(|c| c == CHALLENGE), "{calls:?}");
            assert!(unchanged, "{code}");
        }
    }

    /// A5: the status decides, whatever the Conflict says.
    #[test]
    fn a_409_session_on_an_active_matching_row_is_an_expired_approval() {
        let f = fixture();
        for body in [
            r#"{"error":"the device is active and holds no live approval"}"#,
            r#"{"error":"something else entirely","code":"CONFLICT"}"#,
        ] {
            let reply = server(me(INSTANCE, ACCOUNT, "active", key_ids()), (409, body));
            let (err, calls, unchanged) = refused_by(&f, reply);
            assert!(
                crate::errcode::has_code(&err, "recovery.approvalExpired"),
                "{err}"
            );
            assert!(calls.iter().any(|c| c == CHALLENGE), "{calls:?}");
            assert!(unchanged);
        }
        // Another refusal of the session keeps its own error.
        let reply = server(me(INSTANCE, ACCOUNT, "active", key_ids()), (403, "{}"));
        let (err, _, unchanged) = refused_by(&f, reply);
        assert!(
            crate::errcode::has_code(&err, "fleet.refusedSession"),
            "{err}"
        );
        assert!(unchanged);
    }

    /// An echoed `status=409` in the server's text forges no field.
    #[test]
    fn an_echoed_status_is_not_read_as_a_409() {
        let echoed = anyhow!(crate::errcode::code_with(
            "fleet.refusedSession",
            &[("status", "500"), ("detail", "x|status=409")],
        ));
        let kept = session_refusal(echoed).to_string();
        assert!(
            crate::errcode::has_code(&kept, "fleet.refusedSession"),
            "{kept}"
        );
    }

    /// The readback of the bundle's self-grant must be acknowledged under an
    /// ACTIVE generation.
    #[test]
    fn a_self_grant_not_active_is_missing() {
        let f = fixture();
        let rt = runtime();
        let (hpke_secret, _) = derive_keypair(&HPKE_SEED);
        let check = |generation| {
            let record = AuthorizationRecord::parse(&f.self_grant)
                .unwrap()
                .verify_signature(signer().verifying_key().as_bytes())
                .unwrap();
            let descriptor =
                TenantRootGrantDescriptorV2::new(record, RootGrantState::Acknowledged, generation)
                    .unwrap()
                    .encode();
            let reply: Arc<Reply> = Arc::new(move |call: &str, _: &[u8]| {
                if call.starts_with("GET /v2/tenants/") {
                    (200, descriptor.clone())
                } else {
                    (500, Vec::new())
                }
            });
            let (client, _) = rt.block_on(mock(reply));
            rt.block_on(check_root_grant(
                &client,
                "v2a.access",
                &hex(&TENANT),
                &f.self_grant,
                &signer(),
                &hpke_secret,
                &TRK,
            ))
        };
        assert!(check(RootGenerationState::Active).is_ok());
        for state in [RootGenerationState::Preparing, RootGenerationState::Retired] {
            let err = check(state).unwrap_err().to_string();
            assert!(
                crate::errcode::has_code(&err, "recovery.rootGrantMissing"),
                "{err}"
            );
        }
    }

    #[test]
    fn an_unticked_confirmation_is_refused_before_the_bundle_is_read() {
        let f = fixture();
        f.connected("http://127.0.0.1:9");
        let before = f.files();
        let err = runtime()
            .block_on(run(
                Path::new("no-such-bundle"),
                "passphrase",
                "owner",
                "pw",
                false,
                &mut save,
            ))
            .unwrap_err()
            .to_string();
        assert!(
            crate::errcode::has_code(&err, "recovery.confirmOldDeviceLost"),
            "{err}"
        );
        assert_eq!(f.files(), before);
    }

    /// C1: only no device, or the bundle's own with its seeds or none that
    /// load, may be replaced.
    #[test]
    fn another_identity_in_team_json_is_refused() {
        let f = fixture();
        let bundle = f.bundle();
        let check = |c: &TeamConfig| custodian_of(c, &bundle.header, &bundle.plaintext).map(|_| ());
        let lost = |device: &str| TeamConfig {
            tenant_id: hex(&TENANT),
            device_id: device.into(),
            signing_credential_ref: format!("device-signing.{device}"),
            hpke_credential_ref: format!("device-hpke.{device}"),
            ..Default::default()
        };
        let readable = |device: &str, seed: u8| TeamConfig {
            signing_key_seed: hex(&[seed; 32]).into(),
            hpke_key_seed: hex(&HPKE_SEED).into(),
            ..lost(device)
        };
        let ours = hex(&DEVICE);
        let other = hex(&[0x6f; 16]);
        for c in [readable(&other, 0x3e), lost(&other), readable(&ours, 0x11)] {
            let err = check(&c).unwrap_err().to_string();
            assert!(
                crate::errcode::has_code(&err, "recovery.deviceHasIdentity"),
                "{c:?}: {err}"
            );
        }
        for c in [
            lost(""),
            lost(&ours),
            readable(&ours, 0x3e),
            readable(&ours.to_ascii_uppercase(), 0x3e),
        ] {
            assert!(check(&c).is_ok(), "{c:?}");
        }
        let elsewhere = TeamConfig {
            tenant_id: hex(&[0x77; 16]),
            ..lost("")
        };
        let err = check(&elsewhere).unwrap_err().to_string();
        assert!(
            crate::errcode::has_code(&err, "recovery.otherTenant"),
            "{err}"
        );
    }

    fn written(f: &Fixture, c: &mut TeamConfig, fleet_active: bool) -> Result<()> {
        let bundle = f.bundle();
        let custodian = bundle.plaintext.root_custodian.as_ref().unwrap();
        write(c, &bundle, custodian, 0, fleet_active, &mut save)
    }

    /// A6: a root state of another tenant, device, self-grant or anchor is
    /// refused before anything is written.
    #[test]
    fn a_root_state_that_is_not_the_bundles_is_refused() {
        let f = fixture();
        let mut c = f.connected("http://127.0.0.1:9");
        written(&f, &mut c, true).unwrap();
        let mine = crate::root_bootstrap::load().unwrap();
        let changes: [fn(&mut BootstrapState); 4] = [
            |s: &mut BootstrapState| s.tenant_id = hex(&[1; 16]),
            |s: &mut BootstrapState| s.device_id = hex(&[1; 16]),
            |s: &mut BootstrapState| s.self_grant = hex(&[1; 64]),
            |s: &mut BootstrapState| s.anchor = hex(&[1; 32]),
        ];
        for change in changes {
            let mut other = mine.clone();
            change(&mut other);
            crate::root_bootstrap::save(&other).unwrap();
            let mut fresh = f.connected("http://127.0.0.1:9");
            let before = f.files();
            let err = written(&f, &mut fresh, true).unwrap_err().to_string();
            assert!(
                crate::errcode::has_code(&err, "fleet.custodyOtherDevice"),
                "{err}"
            );
            assert_eq!(f.files(), before);
        }
    }

    /// A2: a member's custody state is copied aside and replaced; another
    /// custodian's is refused; this custodian's is kept, without an ack for
    /// another device's grant.
    #[test]
    fn custody_states_are_replaced_kept_or_refused() {
        let f = fixture();
        let mut c = f.connected("http://127.0.0.1:9");
        let member = FleetCustodyState {
            device_acks: [("f.0".to_string(), "00".to_string())].into(),
            ..Default::default()
        };
        crate::fleet_custody::save(&member).unwrap();
        written(&f, &mut c, true).unwrap();
        let state = crate::fleet_custody::load().unwrap();
        assert!(state.imported && state.device_acks.is_empty());
        assert!(state.device_id.eq_ignore_ascii_case(&hex(&DEVICE)));
        assert_eq!(state.server_instance_id, hex(&INSTANCE));
        let copies = f
            .files()
            .into_iter()
            .filter(|(n, _)| n.starts_with("fleet-custody.json.replaced-"))
            .count();
        assert_eq!(copies, 1);
        let saved = crate::team_config::load().unwrap();
        assert_eq!(saved.fleet_id, hex(&TENANT));
        assert_eq!(saved.signing_key().unwrap().to_bytes(), SIGNING_SEED);
        assert_eq!(saved.hpke_seed().unwrap(), HPKE_SEED);

        // This custodian's own state is kept, less a foreign ack; the ack of
        // its own device grant stays.
        let own = own_ack(&f.self_grant);
        let kept = FleetCustodyState {
            imported: true,
            device_grant: hex(&f.self_grant),
            device_acks: [
                ("f.0".to_string(), "00".to_string()),
                ("f.1".to_string(), own.clone()),
            ]
            .into(),
            ..state.clone()
        };
        crate::fleet_custody::save(&kept).unwrap();
        written(&f, &mut c, false).unwrap();
        let after = crate::fleet_custody::load().unwrap();
        assert!(after.imported);
        assert_eq!(after.device_acks, [("f.1".to_string(), own)].into());

        // Another custodian's state is refused, whether it holds a create
        // request or only the capability grants of a setup still preparing,
        // and nothing is written.
        let other = FleetCustodyState {
            device_id: hex(&[0x6f; 16]),
            imported: false,
            ..state
        };
        for other in [
            FleetCustodyState {
                create_request: "00".into(),
                ..other.clone()
            },
            FleetCustodyState {
                capability_grants: vec!["00".into()],
                ..other
            },
        ] {
            crate::fleet_custody::save(&other).unwrap();
            let before = f.files();
            let err = written(&f, &mut c, true).unwrap_err().to_string();
            assert!(
                crate::errcode::has_code(&err, "fleet.custodyOtherDevice"),
                "{err}"
            );
            assert_eq!(f.files(), before);
        }
    }

    /// A saved ack request of the grant whose exact container is `container`.
    fn own_ack(container: &[u8]) -> String {
        use shardx_core::fleet_lifecycle::{
            FleetGenerationRef, FleetGrantVariant, FleetKeyGrantCreateV2,
        };
        use shardx_core::mutation::OperationKind;
        let record = AuthorizationRecord::parse(container).unwrap();
        let grant = FleetKeyGrantCreateV2::new(
            FleetGenerationRef {
                tenant_id: TENANT,
                server_instance_id: INSTANCE,
                restore_epoch: 0,
                fleet_id: TENANT,
                generation: 0,
                fkek_key_id: [0x33; 32],
            },
            FleetGrantVariant::DeviceHpke,
            [1; 16],
            *record.signed_container_hash(),
            container.to_vec(),
        )
        .grant;
        let (_, pk) = derive_keypair(&HPKE_SEED);
        let cx = Context16 {
            tenant: TENANT,
            instance: INSTANCE,
            epoch: 0,
            account: ACCOUNT,
            device: DEVICE,
            signing_key_id: signing_key_id(signer().verifying_key().as_bytes()),
            hpke_key_id: hpke_key_id(&pk),
        };
        let request = cx
            .request(
                OperationKind::FleetGrantAck,
                FleetKeyGrantAckV2 { grant }.encode(),
            )
            .unwrap();
        let request = hex(&request);
        assert!(acked_grant(&request).is_some());
        request
    }

    /// `team.json` that changed after it was checked is not written over.
    #[test]
    fn a_team_json_that_changed_since_the_check_is_refused() {
        let f = fixture();
        let mut checked = f.connected("http://127.0.0.1:9");
        crate::team_config::save(&TeamConfig {
            device_id: hex(&[0x6f; 16]),
            signing_credential_ref: format!("device-signing.{}", hex(&[0x6f; 16])),
            ..checked.clone()
        })
        .unwrap();
        let before = f.files();
        let err = written(&f, &mut checked, true).unwrap_err().to_string();
        assert!(
            crate::errcode::has_code(&err, "recovery.deviceHasIdentity"),
            "{err}"
        );
        assert_eq!(f.files(), before);
    }

    /// A tenant pinned to another anchor is refused before any request.
    #[test]
    fn a_bundle_of_another_anchor_than_the_pinned_one_is_refused() {
        let f = fixture();
        let binding = shardx_core::trust_chain::Binding {
            server_instance_id: INSTANCE,
            tenant_id: TENANT,
        };
        let ledger = crate::team::db::Db::open().unwrap();
        assert!(crate::team::ledger::pin_anchor(
            &ledger,
            &binding,
            &[0xa0; 32],
            crate::team::ledger::JOIN,
            now_ms()
        )
        .unwrap());
        drop(ledger);
        let (err, calls, unchanged) = refused_by(&f, server(serde_json::json!({}), (500, "")));
        assert!(
            crate::errcode::has_code(&err, "recovery.otherAnchor"),
            "{err}"
        );
        assert!(calls.is_empty(), "{calls:?}");
        assert!(unchanged);
    }

    /// Only an acknowledged self-grant passes step 5: one still pending its
    /// ack, or revoked, reads as missing.
    #[test]
    fn a_pending_or_revoked_root_grant_is_refused() {
        let f = fixture();
        let rt = runtime();
        let (hpke_secret, _) = derive_keypair(&HPKE_SEED);
        for grant_state in [
            RootGrantState::Acknowledged,
            RootGrantState::PendingAck,
            RootGrantState::Revoked,
        ] {
            let record = AuthorizationRecord::parse(&f.self_grant)
                .unwrap()
                .verify_signature(signer().verifying_key().as_bytes())
                .unwrap();
            let descriptor =
                TenantRootGrantDescriptorV2::new(record, grant_state, RootGenerationState::Active)
                    .unwrap()
                    .encode();
            let reply: Arc<Reply> = Arc::new(move |_, _| (200, descriptor.clone()));
            let (client, _) = rt.block_on(mock(reply));
            let result = rt.block_on(check_root_grant(
                &client,
                "v2a.fixture",
                &hex(&TENANT),
                &f.self_grant,
                &signer(),
                &hpke_secret,
                &TRK,
            ));
            match grant_state {
                RootGrantState::Acknowledged => assert!(result.is_ok()),
                _ => assert!(crate::errcode::has_code(
                    &result.unwrap_err().to_string(),
                    "recovery.rootGrantMissing"
                )),
            }
        }
    }

    /// A v3 bundle whose custodian block does not check is refused at the
    /// full entry point before any request, and nothing is written.
    #[test]
    fn an_invalid_v3_bundle_never_reaches_the_listing_or_writes() {
        let f = fixture();
        let rt = runtime();
        let (client, seen) = rt.block_on(mock(server(serde_json::json!({}), (500, ""))));
        f.connected(client.base_url());
        let mut bundle = f.bundle();
        bundle
            .plaintext
            .root_custodian
            .as_mut()
            .unwrap()
            .hpke_key_seed = [0x7b; 32].into();
        let (_, file) =
            rb::seal(TENANT, INSTANCE, 0, 0, &bundle.plaintext, "test passphrase").unwrap();
        let path = f.dir.path().join("invalid-v3.bundle");
        std::fs::write(&path, &file).unwrap();
        let before = f.files();
        let result = rt.block_on(run(
            &path,
            "test passphrase",
            "owner",
            "pw",
            true,
            &mut save,
        ));
        assert!(crate::errcode::has_code(
            &result.unwrap_err().to_string(),
            "recovery.bundleDoesNotOpen"
        ));
        assert!(
            seen.lock().unwrap().is_empty(),
            "invalid bundle reached the server"
        );
        assert!(f.files() == before, "invalid bundle changed state");
    }

    /// A wrong passphrase, or a file that is not there, says only that the
    /// bundle does not open, and nothing is written.
    #[test]
    fn a_bundle_that_does_not_open_is_refused_with_its_own_code() {
        let f = fixture();
        f.connected("http://127.0.0.1:9");
        let bundle = f.bundle();
        let (_, file) = rb::seal(
            TENANT,
            INSTANCE,
            0,
            0,
            &bundle.plaintext,
            "right passphrase",
        )
        .unwrap();
        let path = f.dir.path().join("bundle.bin");
        std::fs::write(&path, file).unwrap();
        let before = f.files();
        for (path, passphrase) in [
            (path.as_path(), "wrong passphrase"),
            (Path::new("no-such-bundle"), "right passphrase"),
        ] {
            let err = runtime()
                .block_on(run(path, passphrase, "owner", "pw", true, &mut save))
                .unwrap_err()
                .to_string();
            assert!(
                crate::errcode::has_code(&err, "recovery.bundleDoesNotOpen"),
                "{err}"
            );
            assert!(!err.contains("passphrase"), "{err}");
            assert_eq!(f.files(), before);
        }
    }
}
