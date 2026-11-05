//! Create fleet key (v0.2.2a plan, section 4.F).
//!
//! The tenant's root custodian makes generation 0 of the tenant's fleet: it
//! files its own capability grants, its `DeviceHpkeGrant` and the
//! `RecoveryGrant` under the ACTIVE root, acknowledges both and activates
//! the generation. The verified collect that follows is the only step that
//! keeps the fleet key (FKEK) as this device's.
//!
//! The rules are the root bootstrap's (`root_bootstrap`): every request is
//! built once and saved, as exact bytes, before it leaves the device, and a
//! resumed run resends the saved bytes, which the server answers with its
//! stored response. The FKEK is held in the credential store before anything
//! names it, under a reference made unique by a nonce saved first; the state
//! keeps that nonce and the key's id, never the key.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use shardx_core::approval_receipt::{
    device_approve_request_hash, DeviceApprovalReceiptV2, MAX_FLEET_RECOVERY_GRANT_TTL_MS,
};
use shardx_core::authz_record::{
    build_record, ApprovalScopeKind, AuthorizationRecord, Capability, CapabilityScopeKind,
    DeviceApprovalV2, DeviceHpkeGrantV2, DeviceRevocationReason, DeviceRevocationV2, GrantSubject,
    Payload, RecoveryGrantV2, TenantCapabilityGrantV2, DOMAIN_DEVICE_APPROVAL,
    DOMAIN_DEVICE_REVOCATION, DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE, DOMAIN_FLEET_KEY_GRANT_RECOVERY,
    DOMAIN_TENANT_CAPABILITY_GRANT,
};
use shardx_core::fleet_grants::{fkek_key_id, generate_fkek};
use shardx_core::fleet_lifecycle::{
    FleetGenerationRef, FleetGenerationTerms, FleetGrantVariant, FleetKeyGenerationActivateV2,
    FleetKeyGenerationActivatedV2, FleetKeyGenerationCreateV2, FleetKeyGenerationCreatedV2,
    FleetKeyGrantAckV2, FleetKeyGrantAckedV2, FleetKeyGrantCreateV2, FleetKeyGrantCreatedV2,
    RECORD_TYPE_FLEET_GENERATION_ACTIVATED, RECORD_TYPE_FLEET_GENERATION_CREATED,
    RECORD_TYPE_FLEET_GRANT_ACKED, RECORD_TYPE_FLEET_GRANT_CREATED,
};
use shardx_core::grants::{derive_keypair, seal_device_fkek};
use shardx_core::keys::{hpke_key_id, signing_key_id};
use shardx_core::mutation::{
    fleet_device_grant_set_hash, DeviceRevokeRequestV2, DeviceRevokedV2,
    IdempotentMutationRequestV2, OperationKind, RECORD_TYPE_DEVICE_REVOKED,
};
use shardx_core::signing::Ed25519SigningKey;
use shardx_core::trust_chain::{join_sas, join_sas_display, Binding};

use crate::fleet_client::{decode_hex, decode_hex16, decode_hex32, hex, FleetClient, TenantDevice};
use crate::root_bootstrap::{
    commit, corrupt, is_missing, mismatch, nonce_ok, now_ms, own_grant, random, stored_payload,
    unhex_vec, BootstrapState, Context16,
};

/// Where the fleet key lives from its creation until the verified collect,
/// under the reference [`setup_ref`] names.
pub trait FkekStore: Sync {
    fn store(&self, credential_ref: &str, key: &[u8; 32]) -> Result<()>;
    fn load(&self, credential_ref: &str) -> Result<Zeroizing<[u8; 32]>>;
    fn forget(&self, credential_ref: &str) -> Result<()>;
}

/// The launcher's credential store: the OS store, else the open key file.
pub struct CredentialFkekStore;

impl FkekStore for CredentialFkekStore {
    fn store(&self, credential_ref: &str, key: &[u8; 32]) -> Result<()> {
        crate::credential::store(credential_ref, key)
    }
    fn load(&self, credential_ref: &str) -> Result<Zeroizing<[u8; 32]>> {
        crate::credential::load(credential_ref)
    }
    fn forget(&self, credential_ref: &str) -> Result<()> {
        crate::credential::forget(credential_ref)
    }
}

/// What Create fleet key keeps between attempts, hex-encoded, written before
/// each request leaves the device. No key is among it.
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct FleetCustodyState {
    #[serde(default)]
    pub tenant_id: String,
    #[serde(default)]
    pub device_id: String,
    #[serde(default)]
    pub server_instance_id: String,
    #[serde(default)]
    pub restore_epoch: u64,
    /// The exact capability grants this custodian files for itself.
    #[serde(default)]
    pub capability_grants: Vec<String>,
    /// Names this run's setup key: saved before the key is stored, cleared
    /// once the key is released after the verified collect.
    #[serde(default)]
    pub fkek_nonce: String,
    /// The id of the setup key, saved once the store holds the key.
    #[serde(default)]
    pub fkek_key_id: String,
    #[serde(default)]
    pub device_grant: String,
    #[serde(default)]
    pub recovery_grant: String,
    #[serde(default)]
    pub create_request: String,
    #[serde(default)]
    pub device_grant_request: String,
    #[serde(default)]
    pub recovery_grant_request: String,
    #[serde(default)]
    pub device_ack_request: String,
    #[serde(default)]
    pub recovery_ack_request: String,
    #[serde(default)]
    pub activate_request: String,
    /// This device's ack of its own fleet grant, per `{fleet}.{generation}`,
    /// as a collect sent it.
    #[serde(default)]
    pub device_acks: BTreeMap<String, String>,
    /// Approve (section 4.A), per lower-case device id.
    #[serde(default)]
    pub members: BTreeMap<String, MemberApproval>,
    /// Revoke (section 4.R): the exact request, per lower-case device id.
    #[serde(default)]
    pub revocations: BTreeMap<String, String>,
}

impl std::fmt::Debug for FleetCustodyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FleetCustodyState")
            .field("tenant_id", &self.tenant_id)
            .field("device_id", &self.device_id)
            .field("fkek_key_id", &self.fkek_key_id)
            .field("created", &!self.create_request.is_empty())
            .finish_non_exhaustive()
    }
}

/// The root custodian that creates the fleet key, and its keys.
pub struct FleetDevice<'a> {
    pub tenant_id: &'a str,
    pub device_id: &'a str,
    pub account_id: &'a str,
    pub signer: &'a Ed25519SigningKey,
    pub hpke_seed: &'a [u8; 32],
    pub vault: &'a dyn FkekStore,
}

/// The reference the setup key of one run of `tenant_hex` is stored under.
fn setup_ref(tenant_hex: &str, nonce: &str) -> String {
    format!("fleet-setup.{}.{nonce}", tenant_hex.to_ascii_lowercase())
}

fn own_setup_ref(state: &FleetCustodyState) -> Result<String> {
    if !nonce_ok(&state.fkek_nonce) {
        return Err(corrupt());
    }
    Ok(setup_ref(&state.tenant_id, &state.fkek_nonce))
}

/// Step 3: the fleet key is held before anything names it.
///
/// A key under this run's reference is reused: left by a run that stopped
/// before saving its id, nothing names it yet. A new key is made only when
/// the store answers `credential.missing` and no id is saved; any other
/// answer, or a held key whose id is not the saved one, stops the run.
/// `fleet_keys` is not used here because it marks every key it keeps
/// verified.
fn hold_fkek(
    vault: &dyn FkekStore,
    state: &mut FleetCustodyState,
    save: &mut impl FnMut(&FleetCustodyState) -> Result<()>,
) -> Result<Zeroizing<[u8; 32]>> {
    if state.fkek_nonce.is_empty() {
        let nonce = hex(&random::<16>()?);
        commit(state, save, |s| s.fkek_nonce = nonce)?;
    }
    let name = own_setup_ref(state)?;
    let key = match vault.load(&name) {
        Ok(key) => key,
        Err(e) if is_missing(&e) && state.fkek_key_id.is_empty() => {
            let key = generate_fkek();
            vault.store(&name, &key)?;
            key
        }
        Err(e) => return Err(e),
    };
    let id = hex(&fkek_key_id(&key));
    if state.fkek_key_id.is_empty() {
        commit(state, save, |s| s.fkek_key_id = id)?;
    } else if state.fkek_key_id != id {
        return Err(corrupt());
    }
    Ok(key)
}

/// Deletes the setup key, then drops its reference. The reference stays
/// until the key is gone, so a store that refuses is retried.
fn release_fkek(
    vault: &dyn FkekStore,
    state: &mut FleetCustodyState,
    save: &mut impl FnMut(&FleetCustodyState) -> Result<()>,
) -> Result<()> {
    if state.fkek_nonce.is_empty() {
        return Ok(());
    }
    vault.forget(&own_setup_ref(state)?)?;
    commit(state, save, |s| s.fkek_nonce.clear())
}

/// This custodian's own operating grants (plan OQ5): `fleet.manage` and the
/// profile capabilities on the fleet, device approval and revocation
/// tenant-wide.
fn own_grants(cx: &Context16, fleet: [u8; 16]) -> [(Capability, CapabilityScopeKind, [u8; 16]); 6] {
    use CapabilityScopeKind::{Fleet, Tenant};
    [
        (Capability::FleetManage, Fleet, fleet),
        (Capability::DeviceApprove, Tenant, cx.tenant),
        (Capability::DeviceRevoke, Tenant, cx.tenant),
        (Capability::ProfilePublish, Fleet, fleet),
        (Capability::ProfileCheckout, Fleet, fleet),
        (Capability::ProfileCommit, Fleet, fleet),
    ]
}

/// The capability grants `list` names for `subject`, signed by `signer`.
fn capability_grants(
    cx: &Context16,
    signer: &Ed25519SigningKey,
    subject: &GrantSubject,
    list: impl IntoIterator<Item = (Capability, CapabilityScopeKind, [u8; 16])>,
    now: u64,
) -> Result<Vec<String>> {
    list.into_iter()
        .map(|(capability, scope_kind, scope_id)| {
            let g = TenantCapabilityGrantV2 {
                common: cx.common(random()?, now),
                subject: subject.clone(),
                scope_kind,
                scope_id,
                capability,
            };
            Ok(hex(&build_record(
                signer,
                DOMAIN_TENANT_CAPABILITY_GRANT,
                &g.encode(),
            )))
        })
        .collect()
}

fn container_hash(container: &[u8]) -> Result<[u8; 32]> {
    AuthorizationRecord::parse(container)
        .map(|r| *r.signed_container_hash())
        .map_err(|_| corrupt())
}

/// Steps 3 and 4: holds the key, then builds generation 0 and every request
/// that files, acknowledges and activates it, and saves them together. The
/// TRK is opened from the root self-grant only to seal the recovery grant.
fn prepare(
    cx: &Context16,
    device: &FleetDevice<'_>,
    root: &BootstrapState,
    state: &mut FleetCustodyState,
    save: &mut impl FnMut(&FleetCustodyState) -> Result<()>,
) -> Result<()> {
    let fkek = hold_fkek(device.vault, state, save)?;
    let (hpke_secret, hpke_public) = derive_keypair(device.hpke_seed);
    let (root_grant, _) = own_grant(&unhex_vec(&root.self_grant)?, device.signer)?;
    let generation = FleetGenerationRef {
        tenant_id: cx.tenant,
        server_instance_id: cx.instance,
        restore_epoch: cx.epoch,
        fleet_id: cx.tenant,
        generation: 0,
        fkek_key_id: fkek_key_id(&fkek),
    };
    let now = now_ms();

    let mut grant = DeviceHpkeGrantV2 {
        common: cx.common(random()?, now),
        fleet_id: generation.fleet_id,
        fkek_key_id: generation.fkek_key_id,
        generation: 0,
        subject_account_id: cx.account,
        subject_device_id: cx.device,
        subject_signing_key_id: cx.signing_key_id,
        recipient_hpke_key_id: cx.hpke_key_id,
        hpke_encapped_key_bytes: Vec::new(),
        hpke_wrapped_fleet_key_bytes: Vec::new(),
    };
    seal_device_fkek(&hpke_public, &mut grant, &fkek).map_err(|_| corrupt())?;
    let device_replay = grant.common.replay_id;
    let device_grant = build_record(
        device.signer,
        DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE,
        &grant.encode(),
    );

    let mut common = cx.common(random()?, now);
    common.not_after_ms = common.not_before_ms + MAX_FLEET_RECOVERY_GRANT_TTL_MS;
    let mut recovery = RecoveryGrantV2 {
        common,
        fleet_id: generation.fleet_id,
        fkek_key_id: generation.fkek_key_id,
        generation: 0,
        recipient_root_key_id: root_grant.root_key_id,
        recipient_root_generation: root_grant.root_generation,
        root_wrap_nonce_bytes: [0; 12],
        wrapped_fleet_key_bytes: [0; 48],
    };
    {
        let trk = root_grant.open_trk(&hpke_secret).map_err(|_| corrupt())?;
        recovery.seal(&trk, &fkek).map_err(|_| corrupt())?;
    }
    let recovery_replay = recovery.common.replay_id;
    let recovery_grant = build_record(
        device.signer,
        DOMAIN_FLEET_KEY_GRANT_RECOVERY,
        &recovery.encode(),
    );

    let terms = FleetGenerationTerms {
        generation,
        required_device_grant_count: 1,
        required_device_grant_set_hash: fleet_device_grant_set_hash(&[container_hash(
            &device_grant,
        )?])
        .ok_or_else(mismatch)?,
        recovery_grant_signed_container_hash: container_hash(&recovery_grant)?,
        rotation: None,
    };
    let create = FleetKeyGenerationCreateV2 {
        terms,
        root_generation: root_grant.root_generation,
    };
    let filing = |variant, replay, container: &[u8]| -> Result<FleetKeyGrantCreateV2> {
        Ok(FleetKeyGrantCreateV2::new(
            generation,
            variant,
            replay,
            container_hash(container)?,
            container.to_vec(),
        ))
    };
    let device_filing = filing(FleetGrantVariant::DeviceHpke, device_replay, &device_grant)?;
    let recovery_filing = filing(
        FleetGrantVariant::Recovery,
        recovery_replay,
        &recovery_grant,
    )?;
    let request = |kind, payload: Vec<u8>| cx.request(kind, payload).map(|r| hex(&r));
    let requests = [
        request(OperationKind::FleetGenerationCreate, create.encode())?,
        request(OperationKind::FleetGrantCreate, device_filing.encode())?,
        request(OperationKind::FleetGrantCreate, recovery_filing.encode())?,
        request(
            OperationKind::FleetGrantAck,
            FleetKeyGrantAckV2 {
                grant: device_filing.grant,
            }
            .encode(),
        )?,
        request(
            OperationKind::FleetGrantAck,
            FleetKeyGrantAckV2 {
                grant: recovery_filing.grant,
            }
            .encode(),
        )?,
        request(
            OperationKind::FleetGenerationActivate,
            FleetKeyGenerationActivateV2 { terms }.encode(),
        )?,
    ];
    commit(state, save, |s| {
        let [create, device_filing, recovery_filing, device_ack, recovery_ack, activate] = requests;
        s.device_grant = hex(&device_grant);
        s.recovery_grant = hex(&recovery_grant);
        s.create_request = create;
        s.device_grant_request = device_filing;
        s.recovery_grant_request = recovery_filing;
        s.device_ack_request = device_ack;
        s.recovery_ack_request = recovery_ack;
        s.activate_request = activate;
    })
}

fn saved_request(saved: &str) -> Result<IdempotentMutationRequestV2> {
    IdempotentMutationRequestV2::parse(&unhex_vec(saved)?).map_err(|_| corrupt())
}

/// Runs, or resumes, Create fleet key through step 8 under the device
/// session `access`. `save` persists `state`; every step that builds new
/// bytes saves them before sending, and a failed save stops the run.
pub async fn bootstrap_fleet(
    client: &FleetClient,
    access: &str,
    device: &FleetDevice<'_>,
    root: &BootstrapState,
    state: &mut FleetCustodyState,
    save: &mut impl FnMut(&FleetCustodyState) -> Result<()>,
) -> Result<()> {
    let ours = |tenant: &str, id: &str| {
        tenant.eq_ignore_ascii_case(device.tenant_id) && id.eq_ignore_ascii_case(device.device_id)
    };
    if !root.activated || !ours(&root.tenant_id, &root.device_id) {
        bail!(crate::errcode::code("fleet.notCustodian"));
    }
    if !state.tenant_id.is_empty() && !ours(&state.tenant_id, &state.device_id) {
        bail!(crate::errcode::code("fleet.custodyOtherDevice"));
    }

    // 1. The server is the one the root custody and this setup began on.
    let id = client.server_identity(access).await?;
    let instance =
        decode_hex16(&id.server_instance_id, "server_instance_id").map_err(|_| mismatch())?;
    let epoch = u64::try_from(id.restore_epoch).map_err(|_| mismatch())?;
    let same = |saved: &str, saved_epoch: u64| {
        saved.eq_ignore_ascii_case(&hex(&instance)) && saved_epoch == epoch
    };
    if !same(&root.server_instance_id, root.restore_epoch)
        || !(state.server_instance_id.is_empty()
            || same(&state.server_instance_id, state.restore_epoch))
    {
        bail!(crate::errcode::code("fleet.custodyServerChanged"));
    }
    if state.server_instance_id.is_empty() {
        commit(state, save, |s| {
            s.tenant_id = device.tenant_id.to_string();
            s.device_id = device.device_id.to_string();
            s.server_instance_id = hex(&instance);
            s.restore_epoch = epoch;
        })?;
    }
    let (_, hpke_public) = derive_keypair(device.hpke_seed);
    let cx = Context16 {
        tenant: decode_hex16(device.tenant_id, "tenant_id")?,
        instance,
        epoch,
        account: decode_hex16(device.account_id, "account_id")?,
        device: decode_hex16(device.device_id, "device_id")?,
        signing_key_id: signing_key_id(device.signer.verifying_key().as_bytes()),
        hpke_key_id: hpke_key_id(&hpke_public),
    };
    // The tenant's one fleet has the tenant's id (`sync_cmd::fleet_id`).
    let fleet = hex(&cx.tenant);
    if state.create_request.is_empty()
        && client
            .active_fleet_generation(access, device.tenant_id, &fleet)
            .await?
            .is_some()
    {
        bail!(crate::errcode::code("fleet.fleetKeyExists"));
    }

    // 2. The custodian's own capability grants, filed whole.
    if state.capability_grants.is_empty() {
        let me = GrantSubject::Device {
            account_id: cx.account,
            device_id: cx.device,
            signing_key_id: cx.signing_key_id,
            hpke_key_id: cx.hpke_key_id,
        };
        let grants = capability_grants(
            &cx,
            device.signer,
            &me,
            own_grants(&cx, cx.tenant),
            now_ms(),
        )?;
        commit(state, save, |s| s.capability_grants = grants)?;
    }
    for grant in &state.capability_grants {
        let grant = unhex_vec(grant)?;
        if client.file_capability_grant(access, &grant).await? != grant {
            return Err(mismatch());
        }
    }

    // 3 and 4. Nothing is built again once the create request is saved.
    if state.create_request.is_empty() {
        prepare(&cx, device, root, state, save)?;
    }

    // 5. The generation, now PREPARING.
    let create = saved_request(&state.create_request)?;
    let expected = FleetKeyGenerationCreateV2::parse(&create.canonical_payload_bytes)
        .map_err(|_| corrupt())?;
    let stored = client
        .create_fleet_generation(access, &fleet, &create.encode())
        .await?;
    let created = FleetKeyGenerationCreatedV2::parse(&stored_payload(
        &stored,
        &create,
        RECORD_TYPE_FLEET_GENERATION_CREATED,
    )?)
    .map_err(|_| mismatch())?;
    if created.create != expected {
        return Err(mismatch());
    }

    // 6. The device grant, under the own-first-grant rule, and the recovery
    // grant under the ACTIVE root.
    for saved in [&state.device_grant_request, &state.recovery_grant_request] {
        let filing = saved_request(saved)?;
        let grant = FleetKeyGrantCreateV2::parse(&filing.canonical_payload_bytes)
            .map_err(|_| corrupt())?
            .grant;
        let stored = client
            .file_fleet_grant(access, &fleet, 0, &filing.encode())
            .await?;
        let created = FleetKeyGrantCreatedV2::parse(&stored_payload(
            &stored,
            &filing,
            RECORD_TYPE_FLEET_GRANT_CREATED,
        )?)
        .map_err(|_| mismatch())?;
        if created.grant != grant {
            return Err(mismatch());
        }
    }

    // 7. Each grant acknowledged once.
    for saved in [&state.device_ack_request, &state.recovery_ack_request] {
        let ack = saved_request(saved)?;
        let grant = FleetKeyGrantAckV2::parse(&ack.canonical_payload_bytes)
            .map_err(|_| corrupt())?
            .grant;
        let stored = client
            .ack_fleet_grant(access, &fleet, 0, &ack.encode())
            .await?;
        let acked = FleetKeyGrantAckedV2::parse(&stored_payload(
            &stored,
            &ack,
            RECORD_TYPE_FLEET_GRANT_ACKED,
        )?)
        .map_err(|_| mismatch())?;
        if acked.grant != grant {
            return Err(mismatch());
        }
    }

    // 8. Activation.
    let activate = saved_request(&state.activate_request)?;
    let terms = FleetKeyGenerationActivateV2::parse(&activate.canonical_payload_bytes)
        .map_err(|_| corrupt())?
        .terms;
    let stored = client
        .activate_fleet_generation(access, &fleet, 0, &activate.encode())
        .await?;
    let activated = FleetKeyGenerationActivatedV2::parse(&stored_payload(
        &stored,
        &activate,
        RECORD_TYPE_FLEET_GENERATION_ACTIVATED,
    )?)
    .map_err(|_| mismatch())?;
    if activated.terms != terms {
        return Err(mismatch());
    }
    Ok(())
}

/// Section 4.J step 5: acknowledges this device's own opened
/// `DeviceHpkeGrant` once. A grant the readback reports acknowledged is
/// skipped; otherwise the ack is built once, saved per fleet and generation
/// before it is sent, and a retry resends the saved bytes.
pub async fn ack_device_grant(
    client: &FleetClient,
    access: &str,
    container: &[u8],
    acknowledged: bool,
) -> Result<()> {
    if acknowledged {
        return Ok(());
    }
    let record = AuthorizationRecord::parse(container).map_err(|_| mismatch())?;
    let g = DeviceHpkeGrantV2::parse(record.canonical_payload_bytes()).map_err(|_| mismatch())?;
    let grant = FleetKeyGrantCreateV2::new(
        FleetGenerationRef {
            tenant_id: g.common.tenant_id,
            server_instance_id: g.common.server_instance_id,
            restore_epoch: g.common.restore_epoch,
            fleet_id: g.fleet_id,
            generation: g.generation,
            fkek_key_id: g.fkek_key_id,
        },
        FleetGrantVariant::DeviceHpke,
        g.common.replay_id,
        *record.signed_container_hash(),
        container.to_vec(),
    )
    .grant;
    let fleet = hex(&g.fleet_id);
    let key = format!("{fleet}.{}", g.generation);
    let mut state = load()?;
    if !state.device_acks.contains_key(&key) {
        let cx = Context16 {
            tenant: g.common.tenant_id,
            instance: g.common.server_instance_id,
            epoch: g.common.restore_epoch,
            account: g.subject_account_id,
            device: g.subject_device_id,
            signing_key_id: g.subject_signing_key_id,
            hpke_key_id: g.recipient_hpke_key_id,
        };
        let request = hex(&cx.request(
            OperationKind::FleetGrantAck,
            FleetKeyGrantAckV2 { grant }.encode(),
        )?);
        commit(&mut state, &mut |s| save(s), |s| {
            s.device_acks.insert(key.clone(), request);
        })?;
    }
    let ack = saved_request(&state.device_acks[&key])?;
    let stored = client
        .ack_fleet_grant(access, &fleet, g.generation, &ack.encode())
        .await?;
    let acked = FleetKeyGrantAckedV2::parse(&stored_payload(
        &stored,
        &ack,
        RECORD_TYPE_FLEET_GRANT_ACKED,
    )?)
    .map_err(|_| mismatch())?;
    if acked.grant != grant {
        return Err(mismatch());
    }
    Ok(())
}

/// How long an approval may be built after this custodian first saw the
/// pending device, and a joiner may pin after its own enrollment (ADR "Join
/// window rule").
pub const JOIN_WINDOW_MS: u64 = 10 * 60_000;

/// What Approve keeps for one device: when this custodian first saw it
/// pending, by its own clock and never reset, and the exact requests that
/// approve it, saved before the first is sent.
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct MemberApproval {
    #[serde(default)]
    pub first_seen_ms: u64,
    #[serde(default)]
    pub approval: String,
    #[serde(default)]
    pub capability_grants: Vec<String>,
    #[serde(default)]
    pub grant_request: String,
}

/// A device of the tenant as the Approve screen shows it.
#[derive(Serialize, Debug, PartialEq)]
pub struct ListedDevice {
    pub device_id: String,
    pub account_id: String,
    pub status: String,
    pub label: String,
    pub signing_key_id: String,
    pub hpke_key_id: String,
    /// The code the joiner must show, from this custodian's pin and the
    /// listed key IDs (ADR 0002 Q-12).
    pub sas: String,
    /// For a pending device: until when an approval may be built here.
    pub approve_until_ms: Option<u64>,
}

fn code_of(
    (binding, anchor): &(Binding, [u8; 32]),
    signing_key_id: &[u8; 32],
    hpke_key_id: &[u8; 32],
) -> String {
    join_sas_display(&join_sas(
        &binding.server_instance_id,
        &binding.tenant_id,
        anchor,
        signing_key_id,
        hpke_key_id,
    ))
}

/// Section 4.A step 1: notes the first sight of each pending device of
/// `rows`, which is never reset, and lists every row with its code.
pub fn see_devices(
    rows: &[TenantDevice],
    pin: &(Binding, [u8; 32]),
    now: u64,
    state: &mut FleetCustodyState,
    save: &mut impl FnMut(&FleetCustodyState) -> Result<()>,
) -> Result<Vec<ListedDevice>> {
    let new: Vec<String> = rows
        .iter()
        .filter(|r| r.status == "pending")
        .map(|r| r.device_id.to_ascii_lowercase())
        .filter(|id| !state.members.contains_key(id))
        .collect();
    if !new.is_empty() {
        commit(state, save, |s| {
            for id in new {
                s.members.insert(
                    id,
                    MemberApproval {
                        first_seen_ms: now,
                        ..Default::default()
                    },
                );
            }
        })?;
    }
    rows.iter()
        .map(|r| {
            let bad = |_| anyhow::anyhow!(crate::errcode::code("fleet.badReplyCustody"));
            let signing = decode_hex32(&r.signing_key_id, "signing_key_id").map_err(bad)?;
            let hpke = decode_hex32(&r.hpke_key_id, "hpke_key_id").map_err(bad)?;
            let first = state
                .members
                .get(&r.device_id.to_ascii_lowercase())
                .filter(|_| r.status == "pending");
            Ok(ListedDevice {
                device_id: r.device_id.clone(),
                account_id: r.account_id.clone(),
                status: r.status.clone(),
                label: decode_hex(&r.label_hex)
                    .map(|b| String::from_utf8_lossy(&b).into_owned())
                    .unwrap_or_default(),
                signing_key_id: hex(&signing),
                hpke_key_id: hex(&hpke),
                sas: code_of(pin, &signing, &hpke),
                approve_until_ms: first.map(|m| m.first_seen_ms + JOIN_WINDOW_MS),
            })
        })
        .collect()
}

/// The listed device's key IDs and HPKE public key, once each listed ID
/// hashes from its listed key.
fn listed_keys(row: &TenantDevice) -> Result<([u8; 32], [u8; 32], [u8; 32])> {
    let refused = || anyhow::anyhow!(crate::errcode::code("fleet.deviceKeysMismatch"));
    let key = |s: &str| decode_hex32(s, "public_key").map_err(|_| refused());
    let (signing_pk, hpke_pk) = (key(&row.signing_public_key)?, key(&row.hpke_public_key)?);
    let ids = (signing_key_id(&signing_pk), hpke_key_id(&hpke_pk));
    if hex(&ids.0) != row.signing_key_id.to_ascii_lowercase()
        || hex(&ids.1) != row.hpke_key_id.to_ascii_lowercase()
    {
        return Err(refused());
    }
    Ok((ids.0, ids.1, hpke_pk))
}

/// Section 4.A step 2: the checks that gate building an approval of `row`.
fn check_member(
    row: &TenantDevice,
    pin: &(Binding, [u8; 32]),
    first_seen_ms: u64,
    now: u64,
    sas: &str,
) -> Result<([u8; 32], [u8; 32], [u8; 32])> {
    let keys = listed_keys(row)?;
    if now.saturating_sub(first_seen_ms) > JOIN_WINDOW_MS {
        bail!(crate::errcode::code("fleet.approvalWindowClosed"));
    }
    let typed: String = sas
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_ascii_lowercase();
    if typed != code_of(pin, &keys.0, &keys.1).replace(' ', "") {
        bail!(crate::errcode::code("fleet.joinCodeMismatch"));
    }
    Ok(keys)
}

/// Section 4.A step 3: the fleet-scoped approval of `row`, its three
/// profile capability grants, and the request filing its `DeviceHpkeGrant`
/// of `generation`, sealed to the listed HPKE key.
#[allow(clippy::too_many_arguments)]
fn build_member(
    cx: &Context16,
    signer: &Ed25519SigningKey,
    row: &TenantDevice,
    (signing, hpke, hpke_pk): ([u8; 32], [u8; 32], [u8; 32]),
    fkek: &[u8; 32],
    generation: u64,
    now: u64,
    first_seen_ms: u64,
) -> Result<MemberApproval> {
    let account = decode_hex16(&row.account_id, "account_id")?;
    let device = decode_hex16(&row.device_id, "device_id")?;
    let fleet = cx.tenant;
    let approval = DeviceApprovalV2 {
        common: cx.common(random()?, now),
        subject_account_id: account,
        subject_device_id: device,
        subject_signing_key_id: signing,
        subject_hpke_key_id: hpke,
        approval_scope_kind: ApprovalScopeKind::Fleet,
        approval_scope_id: fleet,
    };
    let subject = GrantSubject::Device {
        account_id: account,
        device_id: device,
        signing_key_id: signing,
        hpke_key_id: hpke,
    };
    use CapabilityScopeKind::Fleet;
    let grants = capability_grants(
        cx,
        signer,
        &subject,
        [
            (Capability::ProfilePublish, Fleet, fleet),
            (Capability::ProfileCheckout, Fleet, fleet),
            (Capability::ProfileCommit, Fleet, fleet),
        ],
        now,
    )?;
    let generation = FleetGenerationRef {
        tenant_id: cx.tenant,
        server_instance_id: cx.instance,
        restore_epoch: cx.epoch,
        fleet_id: fleet,
        generation,
        fkek_key_id: fkek_key_id(fkek),
    };
    let mut grant = DeviceHpkeGrantV2 {
        common: cx.common(random()?, now),
        fleet_id: fleet,
        fkek_key_id: generation.fkek_key_id,
        generation: generation.generation,
        subject_account_id: account,
        subject_device_id: device,
        subject_signing_key_id: signing,
        recipient_hpke_key_id: hpke,
        hpke_encapped_key_bytes: Vec::new(),
        hpke_wrapped_fleet_key_bytes: Vec::new(),
    };
    seal_device_fkek(&hpke_pk, &mut grant, fkek).map_err(|_| corrupt())?;
    let container = build_record(signer, DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE, &grant.encode());
    let filing = FleetKeyGrantCreateV2::new(
        generation,
        FleetGrantVariant::DeviceHpke,
        grant.common.replay_id,
        container_hash(&container)?,
        container,
    );
    Ok(MemberApproval {
        first_seen_ms,
        approval: hex(&build_record(
            signer,
            DOMAIN_DEVICE_APPROVAL,
            &approval.encode(),
        )),
        capability_grants: grants,
        grant_request: hex(&cx.request(OperationKind::FleetGrantCreate, filing.encode())?),
    })
}

/// The facts this custodian's records name, once `state` holds its own
/// Create fleet key.
fn custodian(me: &FleetDevice<'_>, state: &FleetCustodyState) -> Result<Context16> {
    let ours = state.tenant_id.eq_ignore_ascii_case(me.tenant_id)
        && state.device_id.eq_ignore_ascii_case(me.device_id);
    if !ours || state.create_request.is_empty() {
        bail!(crate::errcode::code("fleet.notCustodian"));
    }
    let (_, hpke_public) = derive_keypair(me.hpke_seed);
    Ok(Context16 {
        tenant: decode_hex16(me.tenant_id, "tenant_id")?,
        instance: decode_hex16(&state.server_instance_id, "server_instance_id")?,
        epoch: state.restore_epoch,
        account: decode_hex16(me.account_id, "account_id")?,
        device: decode_hex16(me.device_id, "device_id")?,
        signing_key_id: signing_key_id(me.signer.verifying_key().as_bytes()),
        hpke_key_id: hpke_key_id(&hpke_public),
    })
}

/// Runs, or resumes, Approve of `row` (section 4.A) under the device session
/// `access`. A device with saved requests gets exactly those resent: the
/// window, code and key checks gate only building new ones. `fleet_key`
/// gives the verified FKEK of the fleet's ACTIVE generation.
#[allow(clippy::too_many_arguments)]
pub async fn approve_member(
    client: &FleetClient,
    access: &str,
    me: &FleetDevice<'_>,
    pin: &(Binding, [u8; 32]),
    row: &TenantDevice,
    sas: &str,
    fleet_key: impl FnOnce(u64) -> Result<Zeroizing<[u8; 32]>>,
    now: u64,
    state: &mut FleetCustodyState,
    save: &mut impl FnMut(&FleetCustodyState) -> Result<()>,
) -> Result<()> {
    let cx = custodian(me, state)?;
    let fleet = hex(&cx.tenant);
    see_devices(std::slice::from_ref(row), pin, now, state, save)?;
    let id = row.device_id.to_ascii_lowercase();
    let first_seen = match state.members.get(&id) {
        Some(m) if !m.approval.is_empty() => None,
        Some(m) => Some(m.first_seen_ms),
        None => bail!(crate::errcode::code("fleet.deviceNotPending")),
    };
    if let Some(first_seen) = first_seen {
        let keys = check_member(row, pin, first_seen, now, sas)?;
        let generation = client
            .active_fleet_generation(access, me.tenant_id, &fleet)
            .await?
            .ok_or_else(|| anyhow::anyhow!(crate::errcode::code("fleet.createFleetKeyFirst")))?;
        let fkek = fleet_key(generation)?;
        let built = build_member(
            &cx, me.signer, row, keys, &fkek, generation, now, first_seen,
        )?;
        commit(state, save, |s| {
            s.members.insert(id.clone(), built);
        })?;
    }
    let m = state.members[&id].clone();

    // 4. The approval, the three capability grants, then the fleet grant.
    let approval = unhex_vec(&m.approval)?;
    let replay = match AuthorizationRecord::parse(&approval)
        .and_then(|r| r.verify_signature(me.signer.verifying_key().as_bytes()))
        .map(|v| v.payload().clone())
    {
        Ok(Payload::DeviceApproval(a)) => a.common.replay_id,
        _ => return Err(corrupt()),
    };
    let subject = decode_hex16(&id, "device_id")?;
    let receipt =
        DeviceApprovalReceiptV2::parse(&client.approve_device(access, &id, &approval).await?)
            .map_err(|_| mismatch())?;
    let hash = device_approve_request_hash(
        &cx.instance,
        cx.epoch,
        &cx.tenant,
        &cx.account,
        &cx.device,
        &subject,
        &approval,
    );
    if receipt.request_hash != hash
        || (
            receipt.server_instance_id,
            receipt.restore_epoch,
            receipt.tenant_id,
        ) != (cx.instance, cx.epoch, cx.tenant)
        || (receipt.actor_account_id, receipt.actor_device_id) != (cx.account, cx.device)
        || (receipt.subject_device_id, receipt.approval_replay_id) != (subject, replay)
    {
        return Err(mismatch());
    }
    for grant in &m.capability_grants {
        let grant = unhex_vec(grant)?;
        if client.file_capability_grant(access, &grant).await? != grant {
            return Err(mismatch());
        }
    }
    let filing = saved_request(&m.grant_request)?;
    let grant = FleetKeyGrantCreateV2::parse(&filing.canonical_payload_bytes)
        .map_err(|_| corrupt())?
        .grant;
    let stored = client
        .file_fleet_grant(
            access,
            &fleet,
            grant.generation.generation,
            &filing.encode(),
        )
        .await?;
    let created = FleetKeyGrantCreatedV2::parse(&stored_payload(
        &stored,
        &filing,
        RECORD_TYPE_FLEET_GRANT_CREATED,
    )?)
    .map_err(|_| mismatch())?;
    if created.grant != grant {
        return Err(mismatch());
    }
    Ok(())
}

/// ADR 0002 D-6: a revocation runs at most the server's 30 days.
const REVOCATION_VALIDITY_MS: u64 = 30 * 86_400_000;

/// The reasons Revoke offers (section 4.R): `retired` and `lost` only.
pub fn revoke_reason(reason: &str) -> Result<DeviceRevocationReason> {
    match reason {
        "retired" => Ok(DeviceRevocationReason::Retired),
        "lost" => Ok(DeviceRevocationReason::Lost),
        _ => bail!(crate::errcode::code("fleet.revokeReasonUnsupported")),
    }
}

/// Runs, or resumes, Revoke of `row` as `reason` (section 4.R) under the
/// device session `access`. A saved revocation is resent as saved, whatever
/// `reason` now says. This device never revokes itself.
#[allow(clippy::too_many_arguments)]
pub async fn revoke_member(
    client: &FleetClient,
    access: &str,
    me: &FleetDevice<'_>,
    row: &TenantDevice,
    reason: DeviceRevocationReason,
    now: u64,
    state: &mut FleetCustodyState,
    save: &mut impl FnMut(&FleetCustodyState) -> Result<()>,
) -> Result<()> {
    if row.device_id.eq_ignore_ascii_case(me.device_id) {
        bail!(crate::errcode::code("fleet.cannotRevokeSelf"));
    }
    let cx = custodian(me, state)?;
    let id = row.device_id.to_ascii_lowercase();
    let subject = decode_hex16(&id, "device_id")?;
    if !state.revocations.contains_key(&id) {
        let (signing, hpke, _) = listed_keys(row)?;
        let mut common = cx.common(random()?, now);
        common.not_after_ms = common.not_before_ms + REVOCATION_VALIDITY_MS;
        let revocation = DeviceRevocationV2 {
            common,
            subject_account_id: decode_hex16(&row.account_id, "account_id")?,
            subject_device_id: subject,
            subject_signing_key_id: signing,
            subject_hpke_key_id: hpke,
            reason_code: reason,
        };
        let container = build_record(me.signer, DOMAIN_DEVICE_REVOCATION, &revocation.encode());
        let payload = DeviceRevokeRequestV2 {
            signed_container_hash: container_hash(&container)?,
            exact_signed_revocation_container_bytes: container,
            activations: Vec::new(),
        };
        let request = hex(&cx.request(OperationKind::DeviceRevoke, payload.encode())?);
        commit(state, save, |s| {
            s.revocations.insert(id.clone(), request);
        })?;
    }
    let exact = unhex_vec(&state.revocations[&id])?;
    let request = IdempotentMutationRequestV2::parse(&exact).map_err(|_| corrupt())?;
    let sent =
        DeviceRevokeRequestV2::parse(&request.canonical_payload_bytes).map_err(|_| corrupt())?;
    let stored = client.revoke_device(access, &id, &exact).await?;
    let revoked = DeviceRevokedV2::parse(&stored_payload(
        &stored,
        &request,
        RECORD_TYPE_DEVICE_REVOKED,
    )?)
    .map_err(|_| mismatch())?;
    if (
        revoked.tenant_id,
        revoked.subject_device_id,
        revoked.signed_container_hash,
    ) != (cx.tenant, subject, sent.signed_container_hash)
    {
        return Err(mismatch());
    }
    Ok(())
}

/// Set while Create fleet key runs in this process; the single-instance
/// plugin keeps the launcher to one process.
static RUNNING: AtomicBool = AtomicBool::new(false);

/// Held for one run: a second run while one is going is refused, so two runs
/// never build different requests from the same empty state.
pub struct Running(());

impl Drop for Running {
    fn drop(&mut self) {
        RUNNING.store(false, Ordering::SeqCst);
    }
}

pub fn begin() -> Result<Running> {
    if RUNNING.swap(true, Ordering::SeqCst) {
        bail!(crate::errcode::code("fleet.custodyBusy"));
    }
    Ok(Running(()))
}

/// How far Create fleet key got, for the UI: no secret of the state.
#[derive(Serialize, Debug, PartialEq)]
pub struct FleetCustodyStatus {
    /// Some step ran, so a new attempt resumes rather than starts over.
    pub started: bool,
    /// Generation 0 was built; it is done once its setup key is released.
    pub created: bool,
    pub setup_key_held: bool,
    /// The public id of the fleet key, once it was made.
    pub fkek_key_id: String,
}

/// Releases the setup key of the state on disk, after the verified collect,
/// which may itself have saved an ack there.
pub fn release(vault: &dyn FkekStore) -> Result<()> {
    let mut state = load()?;
    release_fkek(vault, &mut state, &mut |s| save(s))
}

/// The saved progress.
pub fn status() -> Result<FleetCustodyStatus> {
    let s = load()?;
    Ok(FleetCustodyStatus {
        started: !s.tenant_id.is_empty(),
        created: !s.create_request.is_empty(),
        setup_key_held: !s.fkek_nonce.is_empty(),
        fkek_key_id: s.fkek_key_id,
    })
}

/// Loads the state; none yet is the empty state.
pub fn load() -> Result<FleetCustodyState> {
    let path = crate::store::fleet_custody_path()?;
    if !path.exists() {
        return Ok(FleetCustodyState::default());
    }
    serde_json::from_str(&std::fs::read_to_string(&path)?).map_err(|_| corrupt())
}

/// Saves the state durably: a torn write must not lose a request the server
/// may already hold.
pub fn save(state: &FleetCustodyState) -> Result<()> {
    let path = crate::store::fleet_custody_path()?;
    crate::durable::write_private(&path, serde_json::to_string_pretty(state)?.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleet_keys;
    use shardx_core::mutation::IdempotentStoredResponseV2;
    use std::sync::atomic::{AtomicU16, AtomicUsize};
    use std::sync::{Arc, Mutex};

    const DAY_MS: u64 = 86_400_000;
    const TRK: [u8; 32] = [9; 32];

    /// One device's custody, under a tenant id of its own so the process-wide
    /// mock credential store never mixes two tests' keys.
    struct Fixture {
        _lock: std::sync::MutexGuard<'static, ()>,
        _dir: tempfile::TempDir,
        signer: Ed25519SigningKey,
        seed: [u8; 32],
        cx: Context16,
        root: BootstrapState,
        tenant: String,
        device: String,
        account: String,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            crate::store::set_config_root(None);
        }
    }

    fn fixture() -> Fixture {
        let lock = crate::store::config_root_test_lock()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().unwrap();
        crate::store::set_config_root(Some(dir.path().to_path_buf()));
        let signer = Ed25519SigningKey::from_bytes(&[3; 32]);
        let seed = [7; 32];
        let (_, pk) = derive_keypair(&seed);
        let cx = Context16 {
            tenant: *uuid::Uuid::new_v4().as_bytes(),
            instance: [2; 16],
            epoch: 0,
            account: [4; 16],
            device: [5; 16],
            signing_key_id: signing_key_id(signer.verifying_key().as_bytes()),
            hpke_key_id: hpke_key_id(&pk),
        };
        let grant =
            crate::root_bootstrap::self_grant(&cx, &signer, &pk, &TRK, [8; 16], now_ms()).unwrap();
        let root = BootstrapState {
            tenant_id: hex(&cx.tenant),
            device_id: hex(&cx.device),
            server_instance_id: hex(&cx.instance),
            self_grant: hex(&grant),
            activated: true,
            ..Default::default()
        };
        Fixture {
            _lock: lock,
            _dir: dir,
            tenant: hex(&cx.tenant),
            device: hex(&cx.device),
            account: hex(&cx.account),
            signer,
            seed,
            cx,
            root,
        }
    }

    impl Fixture {
        fn device<'a>(&'a self, vault: &'a dyn FkekStore) -> FleetDevice<'a> {
            FleetDevice {
                tenant_id: &self.tenant,
                device_id: &self.device,
                account_id: &self.account,
                signer: &self.signer,
                hpke_seed: &self.seed,
                vault,
            }
        }

        /// A state that already names this device and server.
        fn state(&self) -> FleetCustodyState {
            FleetCustodyState {
                tenant_id: self.tenant.clone(),
                device_id: self.device.clone(),
                server_instance_id: hex(&self.cx.instance),
                ..Default::default()
            }
        }

        fn prepared(&self) -> FleetCustodyState {
            let mut state = self.state();
            prepare(
                &self.cx,
                &self.device(&CredentialFkekStore),
                &self.root,
                &mut state,
                &mut |s| save(s),
            )
            .unwrap();
            state
        }
    }

    fn held(state: &FleetCustodyState) -> Zeroizing<[u8; 32]> {
        CredentialFkekStore
            .load(&setup_ref(&state.tenant_id, &state.fkek_nonce))
            .unwrap()
    }

    fn payload<T, E: std::fmt::Debug>(
        saved: &str,
        parse: fn(&[u8]) -> std::result::Result<T, E>,
    ) -> T {
        parse(&saved_request(saved).unwrap().canonical_payload_bytes).unwrap()
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    type Seen = Arc<Mutex<Vec<(String, Vec<u8>)>>>;
    type Reply = dyn Fn(&str, &[u8]) -> (u16, Vec<u8>) + Send + Sync;

    /// A server on this machine that records every request as
    /// `"METHOD /path"` and its body, and answers with `reply`.
    async fn mock(reply: Arc<Reply>) -> (FleetClient, Seen) {
        use axum::http::{Method, StatusCode, Uri};
        let seen: Seen = Arc::default();
        let log = seen.clone();
        let app = axum::Router::new().fallback(
            move |method: Method, uri: Uri, body: axum::body::Bytes| {
                let (log, reply) = (log.clone(), reply.clone());
                async move {
                    let call = format!("{method} {}", uri.path());
                    log.lock().unwrap().push((call.clone(), body.to_vec()));
                    let (status, body) = reply(&call, &body);
                    (StatusCode::from_u16(status).unwrap(), body)
                }
            },
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (
            FleetClient::new(&format!("http://{addr}"), "").unwrap(),
            seen,
        )
    }

    /// A server that knows the fixture's identity, has no ACTIVE generation,
    /// keeps every capability grant, and answers a create with `create`.
    fn setup_server(create: u16) -> Arc<Reply> {
        Arc::new(move |call: &str, body: &[u8]| match call {
            "GET /v2/server-identity" => (
                200,
                serde_json::to_vec(&serde_json::json!({
                    "server_instance_id": hex(&[2; 16]),
                    "restore_epoch": 0,
                }))
                .unwrap(),
            ),
            c if c.ends_with("/key-generation") => (200, b"null".to_vec()),
            "POST /v2/capability-grants" => (201, body.to_vec()),
            c if c.starts_with("POST /v2/fleets/") && c.ends_with("/key-generations") => {
                (create, b"{\"code\":\"FLEET_KEY_REUSED\"}".to_vec())
            }
            _ => (500, Vec::new()),
        })
    }

    /// One run from the state on disk, saving to disk.
    fn run_setup(
        rt: &tokio::runtime::Runtime,
        f: &Fixture,
        client: &FleetClient,
        vault: &dyn FkekStore,
    ) -> Result<()> {
        let mut state = load()?;
        rt.block_on(bootstrap_fleet(
            client,
            "access",
            &f.device(vault),
            &f.root,
            &mut state,
            &mut |s| save(s),
        ))
    }

    /// Counts the keys it stores; the credential store keeps them.
    struct Counting(AtomicUsize);

    impl FkekStore for Counting {
        fn store(&self, credential_ref: &str, key: &[u8; 32]) -> Result<()> {
            self.0.fetch_add(1, Ordering::SeqCst);
            CredentialFkekStore.store(credential_ref, key)
        }
        fn load(&self, credential_ref: &str) -> Result<Zeroizing<[u8; 32]>> {
            CredentialFkekStore.load(credential_ref)
        }
        fn forget(&self, credential_ref: &str) -> Result<()> {
            CredentialFkekStore.forget(credential_ref)
        }
    }

    #[test]
    fn the_fleet_key_is_held_before_any_request_names_it() {
        let f = fixture();
        let mut state = f.state();
        let mut checked = 0;
        let mut save = |s: &FleetCustodyState| {
            if !s.fkek_key_id.is_empty() || !s.create_request.is_empty() {
                let key = CredentialFkekStore
                    .load(&setup_ref(&s.tenant_id, &s.fkek_nonce))
                    .expect("the key is stored before its id or a request is saved");
                assert_eq!(s.fkek_key_id, hex(&fkek_key_id(&key)));
                checked += 1;
            }
            Ok(())
        };
        prepare(
            &f.cx,
            &f.device(&CredentialFkekStore),
            &f.root,
            &mut state,
            &mut save,
        )
        .unwrap();
        assert_eq!(checked, 2, "the id, then every request");
        let create = payload(&state.create_request, FleetKeyGenerationCreateV2::parse);
        assert_eq!(hex(&create.terms.generation.fkek_key_id), state.fkek_key_id);
    }

    #[test]
    fn a_crash_between_holding_and_saving_the_fleet_key_reuses_the_held_key() {
        let f = fixture();
        let mut state = f.state();
        let mut crash = |s: &FleetCustodyState| {
            if s.fkek_key_id.is_empty() {
                Ok(())
            } else {
                bail!("crash")
            }
        };
        assert!(hold_fkek(&CredentialFkekStore, &mut state, &mut crash).is_err());
        assert!(state.fkek_key_id.is_empty() && !state.fkek_nonce.is_empty());
        let first = held(&state);
        let vault = Counting(AtomicUsize::new(0));
        let key = hold_fkek(&vault, &mut state, &mut |_| Ok(())).unwrap();
        assert_eq!(*key, *first);
        assert_eq!(vault.0.load(Ordering::SeqCst), 0, "no second key");
        assert_eq!(state.fkek_key_id, hex(&fkek_key_id(&first)));
    }

    #[test]
    fn a_missing_or_locked_setup_key_after_its_id_is_saved_stops_and_never_regenerates() {
        let f = fixture();
        let mut state = f.state();
        state.fkek_nonce = hex(&[1; 16]);
        state.fkek_key_id = hex(&[2; 32]);
        let name = setup_ref(&state.tenant_id, &state.fkek_nonce);
        let vault = Counting(AtomicUsize::new(0));
        let stops = |want: &str| {
            let mut s = state.clone();
            let err = hold_fkek(&vault, &mut s, &mut |_| bail!("nothing is saved")).unwrap_err();
            assert!(err.to_string().contains(want), "{err}");
        };

        stops("credential.missing");
        crate::credential::OS_STORE_DOWN.with(|d| d.set(true));
        stops("credential.unavailable");
        crate::credential::OS_STORE_DOWN.with(|d| d.set(false));
        assert_eq!(vault.0.load(Ordering::SeqCst), 0, "nothing was made up");
        assert!(is_missing(&CredentialFkekStore.load(&name).unwrap_err()));

        // A key whose id is not the saved one is neither used nor replaced.
        CredentialFkekStore.store(&name, &[0x33; 32]).unwrap();
        stops("fleet.custodyStateCorrupt");
        assert_eq!(*CredentialFkekStore.load(&name).unwrap(), [0x33; 32]);
    }

    #[test]
    fn a_failed_setup_leaves_no_verified_key() {
        let f = fixture();
        let rt = runtime();
        let (client, seen) = rt.block_on(mock(setup_server(409)));
        let err = run_setup(&rt, &f, &client, &CredentialFkekStore).unwrap_err();
        assert!(err.to_string().contains("fleet.refusedCustody"), "{err}");
        assert!(seen
            .lock()
            .unwrap()
            .iter()
            .any(|(call, _)| call.ends_with("/key-generations")));
        assert!(fleet_keys::load().unwrap().active_key(&f.tenant).is_none());
        assert!(!crate::store::fleet_keys_path().unwrap().exists());
        let state = load().unwrap();
        assert!(!state.fkek_nonce.is_empty(), "the setup key is still named");
        assert_eq!(hex(&fkek_key_id(&held(&state))), state.fkek_key_id);
    }

    #[test]
    fn the_create_request_commits_to_the_one_device_grant_and_the_recovery_grant() {
        let f = fixture();
        let state = f.prepared();
        let device_grant = unhex_vec(&state.device_grant).unwrap();
        let recovery_grant = unhex_vec(&state.recovery_grant).unwrap();
        let create = payload(&state.create_request, FleetKeyGenerationCreateV2::parse);
        let t = create.terms;
        assert_eq!(
            (
                t.required_device_grant_count,
                t.rotation,
                create.root_generation
            ),
            (1, None, 0)
        );
        assert_eq!(
            t.required_device_grant_set_hash,
            fleet_device_grant_set_hash(&[container_hash(&device_grant).unwrap()]).unwrap()
        );
        assert_eq!(
            t.recovery_grant_signed_container_hash,
            container_hash(&recovery_grant).unwrap()
        );
        let g = t.generation;
        assert_eq!(
            (
                g.tenant_id,
                g.fleet_id,
                g.server_instance_id,
                g.restore_epoch,
                g.generation
            ),
            (f.cx.tenant, f.cx.tenant, f.cx.instance, 0, 0)
        );
        assert_eq!(g.fkek_key_id, fkek_key_id(&held(&state)));

        // The filings carry exactly those containers, the acks name the same
        // grants, and the activation restates the terms.
        for (filing, ack, container, variant) in [
            (
                &state.device_grant_request,
                &state.device_ack_request,
                &device_grant,
                FleetGrantVariant::DeviceHpke,
            ),
            (
                &state.recovery_grant_request,
                &state.recovery_ack_request,
                &recovery_grant,
                FleetGrantVariant::Recovery,
            ),
        ] {
            let filing = payload(filing, FleetKeyGrantCreateV2::parse);
            assert_eq!(&filing.exact_signed_grant_container_bytes, container);
            assert_eq!(filing.grant.grant_variant, variant);
            assert_eq!(filing.grant.generation, g);
            assert_eq!(payload(ack, FleetKeyGrantAckV2::parse).grant, filing.grant);
        }
        assert_eq!(
            payload(&state.activate_request, FleetKeyGenerationActivateV2::parse).terms,
            t
        );
    }

    #[test]
    fn the_recovery_grant_opens_to_the_fleet_key_and_runs_ten_years() {
        let f = fixture();
        let state = f.prepared();
        let key = held(&state);
        let issuer = f.signer.verifying_key().to_bytes();
        let verified = |hex_container: &str| {
            AuthorizationRecord::parse(&unhex_vec(hex_container).unwrap())
                .unwrap()
                .verify_signature(&issuer)
                .unwrap()
                .payload()
                .clone()
        };
        let Payload::RecoveryGrant(r) = verified(&state.recovery_grant) else {
            panic!("a recovery grant")
        };
        assert_eq!(*r.open_fkek(&TRK).unwrap(), *key);
        assert_eq!(
            (r.recipient_root_key_id, r.recipient_root_generation),
            (shardx_core::keys::root_key_id(&TRK), 0)
        );
        assert_eq!(
            r.common.not_after_ms - r.common.not_before_ms,
            MAX_FLEET_RECOVERY_GRANT_TTL_MS
        );
        assert_eq!(MAX_FLEET_RECOVERY_GRANT_TTL_MS, 3650 * DAY_MS);

        // Every other grant runs a year.
        let Payload::DeviceHpkeGrant(d) = verified(&state.device_grant) else {
            panic!("a device grant")
        };
        let (sk, _) = derive_keypair(&f.seed);
        assert_eq!(
            *shardx_core::grants::open_device_fkek(&sk, &d).unwrap(),
            *key
        );
        assert_eq!(d.common.not_after_ms - d.common.not_before_ms, 365 * DAY_MS);
        for grant in &state.capability_grants {
            let Payload::TenantCapabilityGrant(g) = verified(grant) else {
                panic!("a capability grant")
            };
            assert_eq!(g.common.not_after_ms - g.common.not_before_ms, 365 * DAY_MS);
        }
    }

    #[test]
    fn a_resumed_setup_resends_the_saved_bytes_and_never_makes_a_second_fleet_key() {
        let f = fixture();
        let rt = runtime();
        let (client, seen) = rt.block_on(mock(setup_server(503)));
        let vault = Counting(AtomicUsize::new(0));
        assert!(run_setup(&rt, &f, &client, &vault).is_err());
        let first = load().unwrap();
        let key = held(&first);
        assert!(run_setup(&rt, &f, &client, &vault).is_err());
        let second = load().unwrap();
        assert_eq!(vault.0.load(Ordering::SeqCst), 1, "one fleet key");
        assert_eq!(*held(&second), *key);
        assert_eq!(
            (
                &second.fkek_nonce,
                &second.fkek_key_id,
                &second.create_request
            ),
            (&first.fkek_nonce, &first.fkek_key_id, &first.create_request)
        );
        let sent = |prefix: &str| -> Vec<Vec<u8>> {
            seen.lock()
                .unwrap()
                .iter()
                .filter(|(call, _)| call.starts_with(prefix))
                .map(|(_, body)| body.clone())
                .collect()
        };
        let creates = sent("POST /v2/fleets/");
        assert_eq!(creates.len(), 2);
        assert_eq!(creates[0], creates[1]);
        assert_eq!(creates[0], unhex_vec(&first.create_request).unwrap());
        let grants = sent("POST /v2/capability-grants");
        assert_eq!(grants.len(), 12);
        assert_eq!(grants[..6], grants[6..]);
    }

    #[test]
    fn a_setup_saved_for_another_tenant_device_or_server_is_refused() {
        let f = fixture();
        let rt = runtime();
        let (client, seen) = rt.block_on(mock(setup_server(503)));
        let run = |root: &BootstrapState, mut state: FleetCustodyState| {
            rt.block_on(bootstrap_fleet(
                &client,
                "access",
                &f.device(&CredentialFkekStore),
                root,
                &mut state,
                &mut |_| bail!("nothing is saved"),
            ))
            .unwrap_err()
            .to_string()
        };
        let other = hex(&[0xee; 16]);
        type Edit = fn(&mut FleetCustodyState, &str);
        let cases: [(Edit, &str); 4] = [
            (|s, o| s.tenant_id = o.into(), "fleet.custodyOtherDevice"),
            (|s, o| s.device_id = o.into(), "fleet.custodyOtherDevice"),
            (
                |s, o| s.server_instance_id = o.into(),
                "fleet.custodyServerChanged",
            ),
            (|s, _| s.restore_epoch = 1, "fleet.custodyServerChanged"),
        ];
        for (edit, want) in cases {
            let mut state = f.state();
            edit(&mut state, &other);
            let err = run(&f.root, state);
            assert!(err.contains(want), "{want}: {err}");
        }
        type RootEdit = fn(&mut BootstrapState, &str);
        let roots: [RootEdit; 4] = [
            |r, _| r.activated = false,
            |r, o| r.device_id = o.into(),
            |r, o| r.tenant_id = o.into(),
            |r, o| r.server_instance_id = o.into(),
        ];
        for (n, edit) in roots.into_iter().enumerate() {
            let mut root = f.root.clone();
            edit(&mut root, &other);
            let err = run(&root, f.state());
            let want = if n < 3 {
                "fleet.notCustodian"
            } else {
                "fleet.custodyServerChanged"
            };
            assert!(err.contains(want), "{want}: {err}");
        }
        assert!(seen
            .lock()
            .unwrap()
            .iter()
            .all(|(call, _)| call == "GET /v2/server-identity"));
    }

    #[test]
    fn the_saved_state_and_its_debug_output_hold_no_key() {
        let f = fixture();
        let state = f.prepared();
        let key = hex(&*held(&state));
        let file = std::fs::read_to_string(crate::store::fleet_custody_path().unwrap()).unwrap();
        let debug = format!("{state:?}");
        assert!(!state.fkek_key_id.is_empty() && file.contains(&state.fkek_key_id));
        for text in [&file, &debug] {
            assert!(!text.contains(&key), "the fleet key");
            assert!(!text.contains(&hex(&TRK)), "the TRK");
            assert!(!text.contains(&hex(&f.seed)), "the HPKE seed");
        }
        assert!(!debug.contains(&state.create_request) && !debug.contains(&state.device_grant));
    }

    #[test]
    fn collect_custody_uses_the_tenant_fleet_when_none_is_configured() {
        let f = fixture();
        let c = crate::team_config::TeamConfig {
            tenant_id: f.tenant.clone(),
            device_id: f.device.clone(),
            ..Default::default()
        };
        assert!(c.fleet_id.is_empty());
        let rt = runtime();
        let (client, seen) = rt.block_on(mock(Arc::new(|call: &str, _: &[u8]| {
            if call.ends_with("/key-generation") {
                (200, b"{\"generation\":0}".to_vec())
            } else {
                (404, Vec::new())
            }
        })));
        let fleet = rt
            .block_on(crate::collect_fleet_grant(&client, &c, "access", &[0; 32]))
            .unwrap();
        assert_eq!(fleet, crate::FleetGrant::None);
        let calls: Vec<String> = seen
            .lock()
            .unwrap()
            .iter()
            .map(|(c, _)| c.clone())
            .collect();
        assert_eq!(
            calls,
            [
                format!("GET /v2/tenants/{0}/fleets/{0}/key-generation", f.tenant),
                format!(
                    "GET /v2/fleets/{}/key-generations/0/grants/{}",
                    f.tenant, f.device
                ),
            ]
        );
    }

    /// Answers an ack with the stored response the server would keep.
    fn acked(body: &[u8]) -> Vec<u8> {
        let req = IdempotentMutationRequestV2::parse(body).unwrap();
        let ack = FleetKeyGrantAckV2::parse(&req.canonical_payload_bytes).unwrap();
        IdempotentStoredResponseV2 {
            operation_kind: req.operation_kind,
            idempotency_key: req.idempotency_key,
            exact_request_hash: req.canonical_request_hash(),
            response_record_type: RECORD_TYPE_FLEET_GRANT_ACKED.into(),
            canonical_response_payload_bytes: FleetKeyGrantAckedV2 {
                grant: ack.grant,
                acked_at_ms: 1,
            }
            .encode(),
            server_instance_id: req.server_instance_id,
            restore_epoch: req.restore_epoch,
            committed_at_ms: 1,
            receipt_id: [0; 16],
        }
        .encode()
    }

    #[test]
    fn collect_skips_the_ack_of_an_acknowledged_grant() {
        let f = fixture();
        let container = unhex_vec(&f.prepared().device_grant).unwrap();
        let rt = runtime();
        let (client, seen) = rt.block_on(mock(Arc::new(|call: &str, body: &[u8]| {
            if call.ends_with("/ack") {
                (201, acked(body))
            } else {
                (500, Vec::new())
            }
        })));
        let ack = |acknowledged| {
            rt.block_on(ack_device_grant(
                &client,
                "access",
                &container,
                acknowledged,
            ))
        };

        ack(true).unwrap();
        assert!(seen.lock().unwrap().is_empty(), "nothing is sent");
        assert!(load().unwrap().device_acks.is_empty(), "nothing is built");

        // A pending grant is acknowledged with bytes saved first, and a retry
        // after a lost reply resends exactly those bytes.
        ack(false).unwrap();
        ack(false).unwrap();
        let saved = load().unwrap().device_acks;
        let key = format!("{}.0", f.tenant);
        assert_eq!(saved.keys().collect::<Vec<_>>(), [&key]);
        let sent = seen.lock().unwrap().clone();
        let path = format!("POST /v2/fleets/{}/key-generations/0/ack", f.tenant);
        assert_eq!(sent.len(), 2);
        for (call, body) in &sent {
            assert_eq!((call, body), (&path, &unhex_vec(&saved[&key]).unwrap()));
        }
        let ack = payload(&saved[&key], FleetKeyGrantAckV2::parse);
        assert_eq!(ack.grant.grant_variant, FleetGrantVariant::DeviceHpke);
        assert_eq!(
            ack.grant.signed_container_hash,
            container_hash(&container).unwrap()
        );
    }

    /// Step 9 as `team_fleet_key_setup` runs it, with a server that still
    /// reports the device grant PENDING_ACK after step 7: the collect saves
    /// its ack, and releasing the setup key afterwards keeps that ack.
    #[test]
    fn a_setup_where_the_server_reports_pending_ack_keeps_the_saved_ack_after_release() {
        let f = fixture();
        let setup = f.prepared();
        let container = unhex_vec(&setup.device_grant).unwrap();
        let rt = runtime();
        let (client, _) = rt.block_on(mock(Arc::new(|call: &str, body: &[u8]| {
            if call.ends_with("/ack") {
                (201, acked(body))
            } else {
                (500, Vec::new())
            }
        })));
        rt.block_on(ack_device_grant(&client, "access", &container, false))
            .unwrap();
        release(&CredentialFkekStore).unwrap();

        let after = load().unwrap();
        assert_eq!(after.device_acks.len(), 1, "the collect's ack is kept");
        assert!(
            after.fkek_nonce.is_empty(),
            "the setup reference is released"
        );
        let gone = CredentialFkekStore
            .load(&setup_ref(&setup.tenant_id, &setup.fkek_nonce))
            .unwrap_err();
        assert!(is_missing(&gone), "{gone}");
    }

    #[test]
    fn a_setup_collect_that_keeps_no_key_reports_its_own_error() {
        use crate::FleetGrant as G;
        let fetch = "[[shardx:fleet.unreachableCustody]]".to_string();
        for (fleet, want) in [
            (G::Opened(0), None),
            (G::Unfetched(fetch.clone()), Some(fetch.as_str())),
            (G::Failed, Some("fleet.trustEvidenceRefused")),
            (G::Substituted, Some("fleet.keySubstitutionDetected")),
            (G::Waiting, Some("fleet.custodyStateCorrupt")),
            (G::None, Some("fleet.custodyReplyMismatch")),
            (G::Opened(1), Some("fleet.custodyReplyMismatch")),
        ] {
            let got = crate::setup_collect_error(fleet.clone());
            match want {
                None => assert_eq!(got, None, "{fleet:?}"),
                Some(want) => {
                    let got = got.unwrap();
                    assert!(got.contains(want), "{fleet:?}: {got}");
                    if want != "fleet.trustEvidenceRefused" {
                        assert!(!got.contains("trustEvidenceRefused"), "{fleet:?}: {got}");
                    }
                }
            }
        }
    }

    #[test]
    fn an_old_server_without_the_listing_route_reports_server_too_old() {
        let status = Arc::new(AtomicU16::new(404));
        let answer = status.clone();
        let rt = runtime();
        let (client, _) = rt.block_on(mock(Arc::new(move |call: &str, _: &[u8]| {
            if call == "POST /v2/auth/login" {
                let ticket = serde_json::json!({
                    "ticket": "v2t.fresh",
                    "ticket_id": hex(&[1; 16]),
                    "account_id": hex(&[4; 16]),
                    "server_instance_id": hex(&[2; 16]),
                    "restore_epoch": 0,
                });
                (200, serde_json::to_vec(&ticket).unwrap())
            } else {
                (answer.load(Ordering::SeqCst), Vec::new())
            }
        })));
        let tenant = hex(&[1; 16]);
        let login = crate::fleet_client::AccountLogin {
            tenant_id: &tenant,
            username: "u",
            password: "p",
        };
        let code = |r: Result<()>| r.unwrap_err().to_string();
        let listing = || {
            code(
                rt.block_on(client.list_tenant_devices("s", &tenant))
                    .map(drop),
            )
        };
        let identity = |bearer| code(rt.block_on(client.server_identity(bearer)).map(drop));
        let fresh = || {
            code(
                rt.block_on(client.server_identity_with_login(&login))
                    .map(drop),
            )
        };
        let active = || {
            code(
                rt.block_on(client.active_fleet_generation("s", &tenant, &tenant))
                    .map(drop),
            )
        };

        // The two replies only an old server gives.
        assert!(listing().contains("fleet.serverTooOld"));
        status.store(401, Ordering::SeqCst);
        assert!(fresh().contains("fleet.serverTooOld"));

        // Every other 401 or 404 keeps its own error: a ticket that is reused
        // or expired, a refused listing, or a 404 from any other route.
        for (got, want) in [
            (identity("v2t.expired"), "fleet.refusedIdentity"),
            (listing(), "fleet.refusedCustody"),
        ] {
            assert!(got.contains(want) && !got.contains("serverTooOld"), "{got}");
        }
        status.store(404, Ordering::SeqCst);
        for (got, want) in [
            (identity("s"), "fleet.refusedIdentity"),
            (fresh(), "fleet.refusedIdentity"),
            (active(), "fleet.refusedTeamKeys"),
        ] {
            assert!(got.contains(want) && !got.contains("serverTooOld"), "{got}");
        }
    }

    #[test]
    fn team_commands_need_no_admin_token() {
        let f = fixture();
        let rt = runtime();
        let (client, _) = rt.block_on(mock(Arc::new(|_: &str, _: &[u8]| (401, Vec::new()))));
        crate::team_config::save(&crate::team_config::TeamConfig {
            server_url: client.base_url().to_string(),
            tenant_id: f.tenant.clone(),
            ..Default::default()
        })
        .unwrap();
        assert!(crate::team_config::load().unwrap().token.is_empty());
        // Both reach the server's login: neither stops at a token guard.
        let test = rt.block_on(crate::team_test_connection("u".into(), "p".into()));
        let enroll = rt.block_on(crate::team_enroll_device(
            "l".into(),
            "u".into(),
            "p".into(),
        ));
        for err in [test.unwrap_err(), enroll.map(drop).unwrap_err()] {
            assert!(err.contains("fleet.refusedLogin"), "{err}");
        }
    }

    // ---- Approve (section 4.A) ----

    const MINUTE: u64 = 60_000;
    const FKEK: [u8; 32] = [0x66; 32];

    /// A pending joiner D as the listing reports it, with its HPKE secret.
    fn joiner() -> (TenantDevice, Zeroizing<Vec<u8>>) {
        let signer = Ed25519SigningKey::from_bytes(&[0x0d; 32]);
        let (sk, pk) = derive_keypair(&[0x0e; 32]);
        let vk = signer.verifying_key().to_bytes();
        let row = TenantDevice {
            device_id: hex(&[0x0d; 16]),
            account_id: hex(&[4; 16]),
            status: "pending".into(),
            label_hex: hex(b"B"),
            signing_public_key: hex(&vk),
            hpke_public_key: hex(&pk),
            signing_key_id: hex(&signing_key_id(&vk)),
            hpke_key_id: hex(&hpke_key_id(&pk)),
        };
        (row, sk)
    }

    impl Fixture {
        fn pin(&self) -> (Binding, [u8; 32]) {
            (
                Binding {
                    server_instance_id: self.cx.instance,
                    tenant_id: self.cx.tenant,
                },
                self.cx.signing_key_id,
            )
        }

        fn code(&self, row: &TenantDevice) -> String {
            let (s, h, _) = listed_keys(row).unwrap();
            code_of(&self.pin(), &s, &h)
        }
    }

    /// A server that reports generation 0 ACTIVE and refuses everything else.
    fn approve_server() -> Arc<Reply> {
        Arc::new(|call: &str, _: &[u8]| {
            if call.ends_with("/key-generation") {
                (200, b"{\"generation\":0}".to_vec())
            } else {
                (503, Vec::new())
            }
        })
    }

    fn approve(
        rt: &tokio::runtime::Runtime,
        f: &Fixture,
        client: &FleetClient,
        row: &TenantDevice,
        sas: &str,
        now: u64,
    ) -> String {
        let mut state = load().unwrap();
        rt.block_on(approve_member(
            client,
            "access",
            &f.device(&CredentialFkekStore),
            &f.pin(),
            row,
            sas,
            |_| Ok(Zeroizing::new(FKEK)),
            now,
            &mut state,
            &mut |s| save(s),
        ))
        .unwrap_err()
        .to_string()
    }

    fn sent(seen: &Seen) -> Vec<(String, Vec<u8>)> {
        seen.lock()
            .unwrap()
            .iter()
            .filter(|(call, _)| call.starts_with("POST "))
            .cloned()
            .collect()
    }

    #[test]
    fn approval_is_refused_when_a_listed_key_does_not_hash_to_its_id() {
        let f = fixture();
        save(&f.prepared()).unwrap();
        let rt = runtime();
        let (client, seen) = rt.block_on(mock(approve_server()));
        let (row, _) = joiner();
        let other = hex(&[0x77; 32]);
        type Edit = fn(&mut TenantDevice, &str);
        let edits: [Edit; 4] = [
            |r, o| r.signing_key_id = o.into(),
            |r, o| r.hpke_key_id = o.into(),
            |r, o| r.signing_public_key = o.into(),
            |r, o| r.hpke_public_key = o.into(),
        ];
        let now = now_ms();
        for edit in edits {
            let mut bad = row.clone();
            edit(&mut bad, &other);
            let err = approve(&rt, &f, &client, &bad, &f.code(&row), now);
            assert!(err.contains("fleet.deviceKeysMismatch"), "{err}");
        }
        assert!(sent(&seen).is_empty(), "nothing is filed");
        assert!(load()
            .unwrap()
            .members
            .values()
            .all(|m| m.approval.is_empty()));
    }

    #[test]
    fn the_custodian_window_starts_when_it_first_sees_the_row_and_never_resets() {
        let f = fixture();
        let mut state = f.prepared();
        let (row, _) = joiner();
        let t0 = now_ms();
        let active = TenantDevice {
            device_id: hex(&[0x0a; 16]),
            status: "active".into(),
            ..row.clone()
        };
        let rows = [row.clone(), active];
        let listed = see_devices(&rows, &f.pin(), t0, &mut state, &mut |s| save(s)).unwrap();
        assert_eq!(listed[0].approve_until_ms, Some(t0 + 10 * MINUTE));
        assert_eq!(listed[0].sas, f.code(&row));
        assert_eq!(listed[0].label, "B");
        assert_eq!(listed[1].approve_until_ms, None, "only a pending row");
        assert_eq!(load().unwrap().members.len(), 1);

        // Seen again later, by another listing or the approval itself.
        let later = see_devices(&rows, &f.pin(), t0 + 5 * MINUTE, &mut state, &mut |s| {
            save(s)
        });
        assert_eq!(later.unwrap()[0].approve_until_ms, Some(t0 + 10 * MINUTE));
        let id = row.device_id.to_ascii_lowercase();
        assert_eq!(load().unwrap().members[&id].first_seen_ms, t0);
        let sas = f.code(&row);
        assert!(check_member(&row, &f.pin(), t0, t0 + 10 * MINUTE, &sas).is_ok());
        let err = check_member(&row, &f.pin(), t0, t0 + 10 * MINUTE + 1, &sas).unwrap_err();
        assert!(
            err.to_string().contains("fleet.approvalWindowClosed"),
            "{err}"
        );
    }

    #[test]
    fn approval_is_refused_ten_minutes_after_first_sight() {
        let f = fixture();
        let mut state = f.prepared();
        let (row, _) = joiner();
        let t0 = now_ms() - 11 * MINUTE;
        see_devices(
            std::slice::from_ref(&row),
            &f.pin(),
            t0,
            &mut state,
            &mut |s| save(s),
        )
        .unwrap();
        let rt = runtime();
        let (client, seen) = rt.block_on(mock(approve_server()));
        let err = approve(&rt, &f, &client, &row, &f.code(&row), t0 + 10 * MINUTE + 1);
        assert!(err.contains("fleet.approvalWindowClosed"), "{err}");
        assert!(seen.lock().unwrap().is_empty(), "nothing is asked or filed");
        let id = row.device_id.to_ascii_lowercase();
        let kept = &load().unwrap().members[&id];
        assert_eq!((kept.first_seen_ms, kept.approval.as_str()), (t0, ""));
    }

    #[test]
    fn approval_is_refused_when_the_confirmed_code_differs() {
        let f = fixture();
        save(&f.prepared()).unwrap();
        let (row, _) = joiner();
        let rt = runtime();
        let (client, seen) = rt.block_on(mock(approve_server()));
        let right = f.code(&row);
        let wrong = format!("{}0", &right[..right.len() - 1]);
        let wrong = if wrong == right {
            right.replace('0', "1")
        } else {
            wrong
        };
        let now = now_ms();
        for sas in [wrong.as_str(), "", &right[..right.len() - 5]] {
            let err = approve(&rt, &f, &client, &row, sas, now);
            assert!(err.contains("fleet.joinCodeMismatch"), "{err}");
        }
        assert!(seen.lock().unwrap().is_empty(), "nothing is asked or filed");
        // The code is read as shown, with or without its spaces.
        for typed in [
            right.clone(),
            right.replace(' ', ""),
            right.replace(' ', "-").to_uppercase(),
        ] {
            assert!(
                check_member(&row, &f.pin(), now, now, &typed).is_ok(),
                "{typed}"
            );
        }
    }

    #[test]
    fn a_saved_approval_is_resent_after_the_window_closes() {
        let f = fixture();
        save(&f.prepared()).unwrap();
        let (row, _) = joiner();
        let rt = runtime();
        let (client, seen) = rt.block_on(mock(approve_server()));
        let t0 = now_ms();

        // The first run builds and saves every request, then the approval's
        // reply is lost.
        let err = approve(&rt, &f, &client, &row, &f.code(&row), t0);
        assert!(err.contains("fleet.refusedCustody"), "{err}");
        let id = row.device_id.to_ascii_lowercase();
        let saved = load().unwrap().members[&id].clone();
        assert!(!saved.approval.is_empty() && !saved.grant_request.is_empty());
        assert_eq!(saved.capability_grants.len(), 3);

        // An hour later, with no code at all, the same bytes go out again.
        let err = approve(&rt, &f, &client, &row, "", t0 + 60 * MINUTE);
        assert!(err.contains("fleet.refusedCustody"), "{err}");
        let path = format!("POST /v2/devices/{id}/approve");
        let approvals = sent(&seen);
        assert_eq!(approvals.len(), 2);
        for (call, body) in &approvals {
            assert_eq!((call, body), (&path, &unhex_vec(&saved.approval).unwrap()));
        }
        let again = load().unwrap().members[&id].clone();
        assert_eq!(
            (again.approval, again.capability_grants, again.grant_request),
            (saved.approval, saved.capability_grants, saved.grant_request)
        );
    }

    #[test]
    fn the_member_grant_is_sealed_to_the_listed_hpke_key_and_opens_with_it() {
        let f = fixture();
        let (row, sk) = joiner();
        let keys = listed_keys(&row).unwrap();
        let now = now_ms();
        let m = build_member(&f.cx, &f.signer, &row, keys, &FKEK, 0, now, now).unwrap();
        let issuer = f.signer.verifying_key().to_bytes();
        let verified = |container: &[u8]| {
            AuthorizationRecord::parse(container)
                .unwrap()
                .verify_signature(&issuer)
                .unwrap()
                .payload()
                .clone()
        };
        let d = (decode_hex16(&row.device_id, "d").unwrap(), [4; 16]);

        let filing = payload(&m.grant_request, FleetKeyGrantCreateV2::parse);
        let Payload::DeviceHpkeGrant(g) = verified(&filing.exact_signed_grant_container_bytes)
        else {
            panic!("a device grant")
        };
        assert_eq!(
            *shardx_core::grants::open_device_fkek(&sk, &g).unwrap(),
            FKEK
        );
        assert_eq!((g.subject_device_id, g.subject_account_id), (d.0, d.1));
        assert_eq!(
            (g.subject_signing_key_id, g.recipient_hpke_key_id),
            (keys.0, keys.1)
        );
        assert_eq!(
            (g.fleet_id, g.generation, g.fkek_key_id),
            (f.cx.tenant, 0, fkek_key_id(&FKEK))
        );
        assert_eq!(filing.grant.grant_variant, FleetGrantVariant::DeviceHpke);
        // Another device's HPKE key does not open it.
        let (other, _) = derive_keypair(&f.seed);
        assert!(shardx_core::grants::open_device_fkek(&other, &g).is_err());

        let Payload::DeviceApproval(a) = verified(&unhex_vec(&m.approval).unwrap()) else {
            panic!("an approval")
        };
        assert_eq!(
            (a.approval_scope_kind, a.approval_scope_id),
            (ApprovalScopeKind::Fleet, f.cx.tenant)
        );
        assert_eq!((a.subject_device_id, a.subject_hpke_key_id), (d.0, keys.1));
        let caps: Vec<_> = m
            .capability_grants
            .iter()
            .map(|c| match verified(&unhex_vec(c).unwrap()) {
                Payload::TenantCapabilityGrant(g) => {
                    assert_eq!(
                        g.subject,
                        GrantSubject::Device {
                            account_id: d.1,
                            device_id: d.0,
                            signing_key_id: keys.0,
                            hpke_key_id: keys.1,
                        }
                    );
                    (g.capability, g.scope_kind, g.scope_id)
                }
                _ => panic!("a capability grant"),
            })
            .collect();
        use CapabilityScopeKind::Fleet;
        assert_eq!(
            caps,
            [
                (Capability::ProfilePublish, Fleet, f.cx.tenant),
                (Capability::ProfileCheckout, Fleet, f.cx.tenant),
                (Capability::ProfileCommit, Fleet, f.cx.tenant),
            ]
        );
    }

    // ---- Revoke (section 4.R) ----

    fn refuse_all() -> Arc<Reply> {
        Arc::new(|_: &str, _: &[u8]| (503, Vec::new()))
    }

    fn revoke(
        rt: &tokio::runtime::Runtime,
        f: &Fixture,
        client: &FleetClient,
        row: &TenantDevice,
        reason: DeviceRevocationReason,
        now: u64,
    ) -> String {
        let mut state = load().unwrap();
        rt.block_on(revoke_member(
            client,
            "access",
            &f.device(&CredentialFkekStore),
            row,
            reason,
            now,
            &mut state,
            &mut |s| save(s),
        ))
        .unwrap_err()
        .to_string()
    }

    #[test]
    fn only_retired_and_lost_are_accepted() {
        assert_eq!(
            revoke_reason("retired").unwrap(),
            DeviceRevocationReason::Retired
        );
        assert_eq!(revoke_reason("lost").unwrap(), DeviceRevocationReason::Lost);
        for other in ["compromised", "rekeyed", "", "Retired", " lost"] {
            let err = revoke_reason(other).unwrap_err().to_string();
            assert!(
                err.contains("fleet.revokeReasonUnsupported"),
                "{other}: {err}"
            );
        }
        // The command refuses it before anything else.
        let err = runtime()
            .block_on(crate::team_revoke_device(
                "o".into(),
                "p".into(),
                hex(&[0x0d; 16]),
                "compromised".into(),
            ))
            .unwrap_err();
        assert!(err.contains("fleet.revokeReasonUnsupported"), "{err}");
    }

    #[test]
    fn a_custodian_does_not_revoke_itself() {
        let f = fixture();
        save(&f.prepared()).unwrap();
        let rt = runtime();
        let (client, seen) = rt.block_on(mock(refuse_all()));
        let (_, pk) = derive_keypair(&f.seed);
        let vk = f.signer.verifying_key().to_bytes();
        let me = TenantDevice {
            device_id: f.device.to_ascii_uppercase(),
            account_id: f.account.clone(),
            status: "active".into(),
            label_hex: hex(b"A"),
            signing_public_key: hex(&vk),
            hpke_public_key: hex(&pk),
            signing_key_id: hex(&f.cx.signing_key_id),
            hpke_key_id: hex(&f.cx.hpke_key_id),
        };
        for reason in [
            DeviceRevocationReason::Retired,
            DeviceRevocationReason::Lost,
        ] {
            let err = revoke(&rt, &f, &client, &me, reason, now_ms());
            assert!(err.contains("fleet.cannotRevokeSelf"), "{err}");
        }
        assert!(seen.lock().unwrap().is_empty(), "nothing is asked or filed");
        assert!(load().unwrap().revocations.is_empty());
    }

    #[test]
    fn a_resumed_revocation_resends_the_same_bytes() {
        let f = fixture();
        save(&f.prepared()).unwrap();
        let (row, _) = joiner();
        let row = TenantDevice {
            status: "active".into(),
            ..row
        };
        let rt = runtime();
        let (client, seen) = rt.block_on(mock(refuse_all()));
        let t0 = now_ms();

        // The first run builds and saves the request, then its reply is lost.
        let err = revoke(&rt, &f, &client, &row, DeviceRevocationReason::Retired, t0);
        assert!(err.contains("fleet.refusedCustody"), "{err}");
        let id = row.device_id.to_ascii_lowercase();
        let saved = load().unwrap().revocations[&id].clone();

        // A day later, asked as lost, the same bytes go out again.
        let err = revoke(
            &rt,
            &f,
            &client,
            &row,
            DeviceRevocationReason::Lost,
            t0 + DAY_MS,
        );
        assert!(err.contains("fleet.refusedCustody"), "{err}");
        let path = format!("POST /v2/devices/{id}/revoke");
        let revokes = sent(&seen);
        assert_eq!(revokes.len(), 2);
        for (call, body) in &revokes {
            assert_eq!((call, body), (&path, &unhex_vec(&saved).unwrap()));
        }
        assert_eq!(load().unwrap().revocations[&id], saved);

        // What was saved: the retired revocation of the listed keys, for 30
        // days, with no activation.
        assert_eq!(
            saved_request(&saved).unwrap().operation_kind,
            OperationKind::DeviceRevoke
        );
        let request = payload(&saved, DeviceRevokeRequestV2::parse);
        assert!(request.activations.is_empty());
        let issuer = f.signer.verifying_key().to_bytes();
        let Payload::DeviceRevocation(r) =
            AuthorizationRecord::parse(&request.exact_signed_revocation_container_bytes)
                .unwrap()
                .verify_signature(&issuer)
                .unwrap()
                .payload()
                .clone()
        else {
            panic!("a revocation")
        };
        let (signing, hpke, _) = listed_keys(&row).unwrap();
        assert_eq!(
            (
                r.subject_device_id,
                r.subject_signing_key_id,
                r.subject_hpke_key_id,
                r.reason_code
            ),
            ([0x0d; 16], signing, hpke, DeviceRevocationReason::Retired)
        );
        assert_eq!(r.common.not_after_ms - r.common.not_before_ms, 30 * DAY_MS);
    }
}
