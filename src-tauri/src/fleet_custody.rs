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

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use shardx_core::approval_receipt::{
    device_approve_request_hash, DeviceApprovalReceiptV2, MAX_FLEET_RECOVERY_GRANT_TTL_MS,
    MAX_FLEET_ROTATION_GRANT_TTL_MS,
};
use shardx_core::authz_record::{
    build_record, ApprovalScopeKind, AuthorizationRecord, Capability, CapabilityScopeKind,
    DeviceApprovalV2, DeviceHpkeGrantV2, DeviceRevocationReason, DeviceRevocationV2, GrantSubject,
    Payload, RecoveryGrantV2, RotationGrantV2, TenantCapabilityGrantV2, DOMAIN_DEVICE_APPROVAL,
    DOMAIN_DEVICE_REVOCATION, DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE, DOMAIN_FLEET_KEY_GRANT_RECOVERY,
    DOMAIN_FLEET_KEY_GRANT_ROTATION, DOMAIN_TENANT_CAPABILITY_GRANT,
};
use shardx_core::fleet_grants::{fkek_key_id, generate_fkek};
use shardx_core::fleet_lifecycle::{
    FleetGenerationRef, FleetGenerationTerms, FleetGrantVariant, FleetKeyGenerationActivateV2,
    FleetKeyGenerationActivatedV2, FleetKeyGenerationCreateV2, FleetKeyGenerationCreatedV2,
    FleetKeyGrantAckV2, FleetKeyGrantAckedV2, FleetKeyGrantCreateV2, FleetKeyGrantCreatedV2,
    FleetRotation, RECORD_TYPE_FLEET_GENERATION_ACTIVATED, RECORD_TYPE_FLEET_GENERATION_CREATED,
    RECORD_TYPE_FLEET_GRANT_ACKED, RECORD_TYPE_FLEET_GRANT_CREATED,
};
use shardx_core::grants::{derive_keypair, seal_device_fkek};
use shardx_core::keys::{hpke_key_id, signing_key_id};
use shardx_core::mutation::{
    fleet_device_grant_set_hash, DeviceRevokeRequestV2, DeviceRevokedV2,
    IdempotentMutationRequestV2, OperationKind, RECORD_TYPE_DEVICE_REVOKED,
};
use shardx_core::signing::Ed25519SigningKey;
use shardx_core::trust_chain::{
    join_sas, join_sas_display, Binding, Scope, TrustChain, CLOCK_TOLERANCE_MS,
};
use shardx_core::trust_evidence::TenantTrustEvidencePageV2;

use crate::fleet_client::{decode_hex, decode_hex16, decode_hex32, hex, FleetClient, TenantDevice};
use crate::root_bootstrap::{
    commit, corrupt, current_root_grant, is_missing, mismatch, nonce_ok, now_ms, random,
    stored_payload, unhex_vec, BootstrapState, Context16,
};

/// Where the fleet key lives from its creation until the generation is
/// activated,
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
    /// once the key is released after activation, before the verified collect.
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
    /// When this custodian first saw each signing and HPKE key ID on a
    /// pending row, per lower-case key ID; never reset.
    #[serde(default)]
    pub key_first_seen: BTreeMap<String, u64>,
    /// Revoke (section 4.R): the exact request, per lower-case device id.
    #[serde(default)]
    pub revocations: BTreeMap<String, String>,
    /// Written by a recovery import while the fleet had an ACTIVE generation:
    /// this device is its custodian without a saved create request.
    #[serde(default)]
    pub imported: bool,
    /// Rotate fleet key (sequence K): the latest rotation, kept once done or
    /// expired until the next one starts.
    #[serde(default)]
    pub rotation: Option<FleetRotationState>,
    /// Set by a finished rotation: the recovery bundle no longer opens the
    /// newest fleet key.
    #[serde(default)]
    pub export_due: bool,
    /// Re-seal all profiles (v2.10 4.S): the latest run, kept until the next
    /// one starts.
    #[serde(default)]
    pub reseal: Option<ResealRun>,
    /// The device this root custodian handed its custody to (v2.10 4.H step
    /// 1, U6), lower-case; empty while it holds custody. Once it is set,
    /// Re-seal all profiles refuses with `fleet.custodyHandedOver`.
    #[serde(default)]
    pub handed_over_to: String,
}

/// One run of Re-seal all profiles (v2.10 4.S). No key is among it.
#[derive(Default, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResealRun {
    /// The ACTIVE generation the run seals under.
    pub generation: u64,
    /// The outgoing custodian's signing key ID during a hand-over, hex.
    #[serde(default)]
    pub outgoing: String,
    pub started_ms: u64,
    /// Set once the run went through its list; `None` while it runs.
    #[serde(default)]
    pub ended_ms: Option<u64>,
    /// Per remote profile ID: `walking`, `sealing:<version>:<head>`,
    /// `resealed:<version>`, `current` or `skipped:<reason>`.
    #[serde(default)]
    pub profiles: BTreeMap<String, String>,
}

impl std::fmt::Debug for FleetCustodyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FleetCustodyState")
            .field("tenant_id", &self.tenant_id)
            .field("device_id", &self.device_id)
            .field("fkek_key_id", &self.fkek_key_id)
            .field(
                "created",
                &(!self.create_request.is_empty() || self.imported),
            )
            .field("rotation", &self.rotation)
            .field("reseal", &self.reseal)
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

/// The nonce and id fields of one run's setup key: Create fleet key's, or
/// the saved rotation's (sequence K step 3).
type SetupKey = fn(&mut FleetCustodyState) -> (&mut String, &mut String);

fn bootstrap_key(s: &mut FleetCustodyState) -> (&mut String, &mut String) {
    (&mut s.fkek_nonce, &mut s.fkek_key_id)
}

fn rotation_key(s: &mut FleetCustodyState) -> (&mut String, &mut String) {
    let r = s.rotation.get_or_insert_with(Default::default);
    (&mut r.fkek_nonce, &mut r.fkek_key_id)
}

fn own_setup_ref(state: &mut FleetCustodyState, slot: SetupKey) -> Result<String> {
    let nonce = slot(state).0.clone();
    if !nonce_ok(&nonce) {
        return Err(corrupt());
    }
    Ok(setup_ref(&state.tenant_id, &nonce))
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
    slot: SetupKey,
    save: &mut impl FnMut(&FleetCustodyState) -> Result<()>,
) -> Result<Zeroizing<[u8; 32]>> {
    if slot(state).0.is_empty() {
        let nonce = hex(&random::<16>()?);
        commit(state, save, |s| *slot(s).0 = nonce)?;
    }
    let name = own_setup_ref(state, slot)?;
    let saved = slot(state).1.clone();
    let key = match vault.load(&name) {
        Ok(key) => key,
        Err(e) if is_missing(&e) && saved.is_empty() => {
            let key = generate_fkek();
            vault.store(&name, &key)?;
            key
        }
        Err(e) => return Err(e),
    };
    let id = hex(&fkek_key_id(&key));
    if saved.is_empty() {
        commit(state, save, |s| *slot(s).1 = id)?;
    } else if saved != id {
        return Err(corrupt());
    }
    Ok(key)
}

/// Deletes the setup key, then drops its reference. The reference stays
/// until the key is gone, so a store that refuses is retried.
fn release_fkek(
    vault: &dyn FkekStore,
    state: &mut FleetCustodyState,
    slot: SetupKey,
    save: &mut impl FnMut(&FleetCustodyState) -> Result<()>,
) -> Result<()> {
    if slot(state).0.is_empty() {
        return Ok(());
    }
    vault.forget(&own_setup_ref(state, slot)?)?;
    commit(state, save, |s| slot(s).0.clear())
}

/// This custodian's own operating grants (plan OQ5): `fleet.manage` and the
/// profile capabilities on the fleet, device approval and revocation
/// tenant-wide.
pub(crate) fn own_grants(
    cx: &Context16,
    fleet: [u8; 16],
) -> [(Capability, CapabilityScopeKind, [u8; 16]); 6] {
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
pub(crate) fn capability_grants(
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

/// Two containers with their replay IDs, and a root generation.
type OwnGrants = ((Vec<u8>, [u8; 16]), (Vec<u8>, [u8; 16]), u64);

/// This device's own grants of `fkek` as `generation`: its `DeviceHpkeGrant`
/// and the `RecoveryGrant` under the root of its current root grant (Q-52),
/// each with its replay ID, and that root's generation. The TRK is opened
/// from that grant only to seal the recovery grant.
fn own_fleet_grants(
    cx: &Context16,
    device: &FleetDevice<'_>,
    root: &BootstrapState,
    generation: &FleetGenerationRef,
    fkek: &[u8; 32],
    now: u64,
) -> Result<OwnGrants> {
    let (hpke_secret, hpke_public) = derive_keypair(device.hpke_seed);
    let (root_grant, _, _) = current_root_grant(root, device.signer)?;
    let mut grant = DeviceHpkeGrantV2 {
        common: cx.common(random()?, now),
        fleet_id: generation.fleet_id,
        fkek_key_id: generation.fkek_key_id,
        generation: generation.generation,
        subject_account_id: cx.account,
        subject_device_id: cx.device,
        subject_signing_key_id: cx.signing_key_id,
        recipient_hpke_key_id: cx.hpke_key_id,
        hpke_encapped_key_bytes: Vec::new(),
        hpke_wrapped_fleet_key_bytes: Vec::new(),
    };
    seal_device_fkek(&hpke_public, &mut grant, fkek).map_err(|_| corrupt())?;
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
        generation: generation.generation,
        recipient_root_key_id: root_grant.root_key_id,
        recipient_root_generation: root_grant.root_generation,
        root_wrap_nonce_bytes: [0; 12],
        wrapped_fleet_key_bytes: [0; 48],
    };
    {
        let trk = root_grant.open_trk(&hpke_secret).map_err(|_| corrupt())?;
        recovery.seal(&trk, fkek).map_err(|_| corrupt())?;
    }
    let recovery_grant = build_record(
        device.signer,
        DOMAIN_FLEET_KEY_GRANT_RECOVERY,
        &recovery.encode(),
    );
    Ok((
        (device_grant, grant.common.replay_id),
        (recovery_grant, recovery.common.replay_id),
        root_grant.root_generation,
    ))
}

/// Step 4's requests for `create`: the create, one filing and one ack per
/// grant of `grants` (variant, replay ID, exact container), in that order,
/// and the activation that restates the terms.
fn generation_requests(
    cx: &Context16,
    create: &FleetKeyGenerationCreateV2,
    grants: &[(FleetGrantVariant, [u8; 16], &[u8])],
) -> Result<(String, Vec<String>, Vec<String>, String)> {
    let request = |kind, payload: Vec<u8>| cx.request(kind, payload).map(|r| hex(&r));
    let mut filings = Vec::new();
    let mut acks = Vec::new();
    for (variant, replay, container) in grants {
        let filing = FleetKeyGrantCreateV2::new(
            create.terms.generation,
            *variant,
            *replay,
            container_hash(container)?,
            container.to_vec(),
        );
        filings.push(request(OperationKind::FleetGrantCreate, filing.encode())?);
        let ack = FleetKeyGrantAckV2 {
            grant: filing.grant,
        };
        acks.push(request(OperationKind::FleetGrantAck, ack.encode())?);
    }
    let activate = FleetKeyGenerationActivateV2 {
        terms: create.terms,
    };
    Ok((
        request(OperationKind::FleetGenerationCreate, create.encode())?,
        filings,
        acks,
        request(OperationKind::FleetGenerationActivate, activate.encode())?,
    ))
}

/// Steps 3 and 4: holds the key, then builds generation 0 and every request
/// that files, acknowledges and activates it, and saves them together.
fn prepare(
    cx: &Context16,
    device: &FleetDevice<'_>,
    root: &BootstrapState,
    state: &mut FleetCustodyState,
    save: &mut impl FnMut(&FleetCustodyState) -> Result<()>,
) -> Result<()> {
    let fkek = hold_fkek(device.vault, state, bootstrap_key, save)?;
    let generation = FleetGenerationRef {
        tenant_id: cx.tenant,
        server_instance_id: cx.instance,
        restore_epoch: cx.epoch,
        fleet_id: cx.tenant,
        generation: 0,
        fkek_key_id: fkek_key_id(&fkek),
    };
    let ((device_grant, device_replay), (recovery_grant, recovery_replay), root_generation) =
        own_fleet_grants(cx, device, root, &generation, &fkek, now_ms())?;
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
        root_generation,
    };
    let (create, filings, acks, activate) = generation_requests(
        cx,
        &create,
        &[
            (FleetGrantVariant::DeviceHpke, device_replay, &device_grant),
            (
                FleetGrantVariant::Recovery,
                recovery_replay,
                &recovery_grant,
            ),
        ],
    )?;
    let [device_filing, recovery_filing]: [String; 2] =
        filings.try_into().map_err(|_| corrupt())?;
    let [device_ack, recovery_ack]: [String; 2] = acks.try_into().map_err(|_| corrupt())?;
    commit(state, save, |s| {
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

/// Sequence K steps 3 and 4: holds the new key, whose ID is not N's, then
/// builds N+1 in rotation mode with its device, recovery and rotation grants
/// (required set: this device alone, Q-44), every request that creates,
/// files, acknowledges and activates it, and the deadline, and saves them
/// together.
fn prepare_rotation(
    cx: &Context16,
    device: &FleetDevice<'_>,
    root: &BootstrapState,
    now: u64,
    state: &mut FleetCustodyState,
    save: &mut impl FnMut(&FleetCustodyState) -> Result<()>,
) -> Result<()> {
    let fkek = hold_fkek(device.vault, state, rotation_key, save)?;
    let r = state.rotation.clone().ok_or_else(corrupt)?;
    let previous_fkek_key_id =
        decode_hex32(&r.previous_fkek_key_id, "fkek_key_id").map_err(|_| corrupt())?;
    let generation = FleetGenerationRef {
        tenant_id: cx.tenant,
        server_instance_id: cx.instance,
        restore_epoch: cx.epoch,
        fleet_id: cx.tenant,
        generation: r.generation,
        fkek_key_id: fkek_key_id(&fkek),
    };
    if generation.fkek_key_id == previous_fkek_key_id {
        return Err(corrupt());
    }
    let ((device_grant, device_replay), (recovery_grant, recovery_replay), root_generation) =
        own_fleet_grants(cx, device, root, &generation, &fkek, now)?;
    let set_hash =
        fleet_device_grant_set_hash(&[container_hash(&device_grant)?]).ok_or_else(mismatch)?;
    let recovery_hash = container_hash(&recovery_grant)?;
    let mut common = cx.common(random()?, now);
    common.not_after_ms = common.not_before_ms + MAX_FLEET_ROTATION_GRANT_TTL_MS;
    let issued_at_ms = common.issued_at_ms;
    let rotation = RotationGrantV2 {
        common,
        fleet_id: generation.fleet_id,
        fkek_key_id: generation.fkek_key_id,
        generation: r.generation,
        previous_fkek_key_id,
        previous_generation: r.previous_generation,
        required_device_grant_count: 1,
        required_device_grant_set_hash: set_hash,
        recovery_grant_signed_container_hash: recovery_hash,
        activation_not_before_ms: issued_at_ms,
    };
    let rotation_grant = build_record(
        device.signer,
        DOMAIN_FLEET_KEY_GRANT_ROTATION,
        &rotation.encode(),
    );
    let create = FleetKeyGenerationCreateV2 {
        terms: FleetGenerationTerms {
            generation,
            required_device_grant_count: 1,
            required_device_grant_set_hash: set_hash,
            recovery_grant_signed_container_hash: recovery_hash,
            rotation: Some(FleetRotation {
                previous_generation: r.previous_generation,
                previous_fkek_key_id,
                rotation_grant_signed_container_hash: container_hash(&rotation_grant)?,
            }),
        },
        root_generation,
    };
    let (create, filings, acks, activate) = generation_requests(
        cx,
        &create,
        &[
            (FleetGrantVariant::DeviceHpke, device_replay, &device_grant),
            (
                FleetGrantVariant::Recovery,
                recovery_replay,
                &recovery_grant,
            ),
            (
                FleetGrantVariant::Rotation,
                rotation.common.replay_id,
                &rotation_grant,
            ),
        ],
    )?;
    commit(state, save, |s| {
        let r = s.rotation.get_or_insert_with(Default::default);
        r.device_grant = hex(&device_grant);
        r.recovery_grant = hex(&recovery_grant);
        r.rotation_grant = hex(&rotation_grant);
        r.create_request = create;
        r.grant_requests = filings;
        r.ack_requests = acks;
        r.activate_request = activate;
        r.deadline_ms = Some(rotation.common.not_after_ms);
    })
}

fn saved_request(saved: &str) -> Result<IdempotentMutationRequestV2> {
    IdempotentMutationRequestV2::parse(&unhex_vec(saved)?).map_err(|_| corrupt())
}

/// Runs, or resumes, Create fleet key through step 8 under the device
/// session `access`. `save` persists `state`; every step that builds new
/// bytes saves them before sending, and a failed save stops the run.
///
/// No request here has the server check its `issued_at_ms`, only its
/// validity window (`v2_fleet.rs`, `v2_capability.rs`).
/// shortcut: a saved request not filed within its window (365 days, the
/// recovery grant 3650) is refused for good; a rebuilt grant cannot match the
/// committed required set, so this needs a server route to finish or discard
/// the PREPARING generation (fleet key rotation).
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
    /// The trust ledger here counts the row's key as a root custodian: the
    /// Team page offers it no `compromised` (Q-57). Set by the command.
    pub custodian: bool,
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
/// `rows`, and of each key ID it lists, which are never reset, and lists every
/// row with its code.
pub fn see_devices(
    rows: &[TenantDevice],
    pin: &(Binding, [u8; 32]),
    now: u64,
    state: &mut FleetCustodyState,
    save: &mut impl FnMut(&FleetCustodyState) -> Result<()>,
) -> Result<Vec<ListedDevice>> {
    let pending = || rows.iter().filter(|r| r.status == "pending");
    let unseen = pending().any(|r| {
        !state
            .members
            .contains_key(&r.device_id.to_ascii_lowercase())
            || [&r.signing_key_id, &r.hpke_key_id]
                .iter()
                .any(|k| !state.key_first_seen.contains_key(&k.to_ascii_lowercase()))
    });
    if unseen {
        commit(state, save, |s| {
            for r in pending() {
                s.members
                    .entry(r.device_id.to_ascii_lowercase())
                    .or_insert_with(|| MemberApproval {
                        first_seen_ms: now,
                        ..Default::default()
                    });
                for key in [&r.signing_key_id, &r.hpke_key_id] {
                    s.key_first_seen
                        .entry(key.to_ascii_lowercase())
                        .or_insert(now);
                }
            }
        })?;
    }
    rows.iter()
        .map(|r| {
            let bad = |_| anyhow::anyhow!(crate::errcode::code("fleet.badReplyCustody"));
            let signing = decode_hex32(&r.signing_key_id, "signing_key_id").map_err(bad)?;
            let hpke = decode_hex32(&r.hpke_key_id, "hpke_key_id").map_err(bad)?;
            let first = window_start(state, r).filter(|_| r.status == "pending");
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
                approve_until_ms: first.map(|m| m + JOIN_WINDOW_MS),
                custodian: false,
            })
        })
        .collect()
}

/// When the approval window of `row` started: the first sight of its device
/// or of either key ID it lists, whichever came first, so neither a new row
/// ID nor a swap of keys opens a fresh window for keys already seen.
fn window_start(state: &FleetCustodyState, row: &TenantDevice) -> Option<u64> {
    let first = state.members.get(&row.device_id.to_ascii_lowercase())?;
    let key = |k: &str| state.key_first_seen.get(&k.to_ascii_lowercase()).copied();
    Some(
        [key(&row.signing_key_id), key(&row.hpke_key_id)]
            .into_iter()
            .flatten()
            .fold(first.first_seen_ms, u64::min),
    )
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
    Ok(MemberApproval {
        first_seen_ms,
        approval: hex(&build_record(
            signer,
            DOMAIN_DEVICE_APPROVAL,
            &approval.encode(),
        )),
        capability_grants: grants,
        grant_request: member_grant(
            cx,
            signer,
            (account, device),
            (signing, hpke, hpke_pk),
            fkek,
            generation,
            now,
        )?,
    })
}

/// The request filing the `DeviceHpkeGrant` of `fkek` as `generation` of
/// this custodian's fleet for `(account, device)` under `(signing, hpke)`,
/// sealed to the HPKE key `hpke_pk`.
pub(crate) fn member_grant(
    cx: &Context16,
    signer: &Ed25519SigningKey,
    (account, device): ([u8; 16], [u8; 16]),
    (signing, hpke, hpke_pk): ([u8; 32], [u8; 32], [u8; 32]),
    fkek: &[u8; 32],
    generation: u64,
    now: u64,
) -> Result<String> {
    let generation = FleetGenerationRef {
        tenant_id: cx.tenant,
        server_instance_id: cx.instance,
        restore_epoch: cx.epoch,
        fleet_id: cx.tenant,
        generation,
        fkek_key_id: fkek_key_id(fkek),
    };
    let mut grant = DeviceHpkeGrantV2 {
        common: cx.common(random()?, now),
        fleet_id: generation.fleet_id,
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
    Ok(hex(&cx.request(
        OperationKind::FleetGrantCreate,
        filing.encode(),
    )?))
}

/// The facts this custodian's records name, once `state` holds its own
/// Create fleet key or a recovery import of it.
fn custodian(me: &FleetDevice<'_>, state: &FleetCustodyState) -> Result<Context16> {
    let ours = state.tenant_id.eq_ignore_ascii_case(me.tenant_id)
        && state.device_id.eq_ignore_ascii_case(me.device_id);
    if !ours || (state.create_request.is_empty() && !state.imported) {
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
/// gives the verified FKEK of the fleet's ACTIVE generation; `withdrawn`
/// tells whether the trust ledger holds a signing key withdrawn.
#[allow(clippy::too_many_arguments)]
pub async fn approve_member(
    client: &FleetClient,
    access: &str,
    me: &FleetDevice<'_>,
    pin: &(Binding, [u8; 32]),
    row: &TenantDevice,
    sas: &str,
    fleet_key: impl Fn(u64) -> Result<Zeroizing<[u8; 32]>>,
    withdrawn: impl Fn(&[u8; 32]) -> Result<bool>,
    now: u64,
    state: &mut FleetCustodyState,
    save: &mut impl FnMut(&FleetCustodyState) -> Result<()>,
) -> Result<()> {
    let cx = custodian(me, state)?;
    // ADR 0002 Q-48: a device approved now would get no N+1 grant.
    if state
        .rotation
        .as_ref()
        .is_some_and(|r| r.phase.unfinished())
    {
        bail!(crate::errcode::code("fleet.rotationInProgress"));
    }
    let fleet = hex(&cx.tenant);
    see_devices(std::slice::from_ref(row), pin, now, state, save)?;
    let id = row.device_id.to_ascii_lowercase();
    let first_seen = match state.members.get(&id) {
        Some(m) if !m.approval.is_empty() => None,
        Some(_) => window_start(state, row),
        None => bail!(crate::errcode::code("fleet.deviceNotPending")),
    };
    if let Some(first_seen) = first_seen {
        let started = std::time::Instant::now();
        check_member(row, pin, first_seen, now, sas)?;
        let generation = client
            .active_fleet_generation(access, me.tenant_id, &fleet)
            .await?
            .ok_or_else(|| anyhow::anyhow!(crate::errcode::code("fleet.createFleetKeyFirst")))?;
        let fkek = fleet_key(generation)?;
        // The read may outlast the window: check it again at signing time,
        // and sign at that time.
        let now = now + started.elapsed().as_millis() as u64;
        let keys = check_member(row, pin, first_seen, now, sas)?;
        let built = build_member(
            &cx, me.signer, row, keys, &fkek, generation, now, first_seen,
        )?;
        commit(state, save, |s| {
            s.members.insert(id.clone(), built);
        })?;
    }
    // No request here has the server check its `issued_at_ms`, only its
    // validity window (`v2_approval.rs`, `v2_capability.rs`, `v2_fleet.rs`).
    // shortcut: saved requests not filed within 365 days are refused for
    // good; rebuild them once an approval resumed that late is seen.
    let m = state.members[&id].clone();

    // 4. The approval, the three capability grants, then the fleet grant.
    let approval = unhex_vec(&m.approval)?;
    let approved = match AuthorizationRecord::parse(&approval)
        .and_then(|r| r.verify_signature(me.signer.verifying_key().as_bytes()))
        .map(|v| v.payload().clone())
    {
        Ok(Payload::DeviceApproval(a)) => a,
        _ => return Err(corrupt()),
    };
    let replay = approved.common.replay_id;
    let subject = decode_hex16(&id, "device_id")?;
    let not_pending = || crate::errcode::code("fleet.deviceNotPending");
    // Resumed: nothing is resent to a device revoked here or whose key the
    // ledger holds withdrawn.
    if first_seen.is_none()
        && (state.revocations.contains_key(&id) || withdrawn(&approved.subject_signing_key_id)?)
    {
        bail!(not_pending());
    }
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
    let mut filing = saved_request(&m.grant_request)?;
    let mut grant = FleetKeyGrantCreateV2::parse(&filing.canonical_payload_bytes)
        .map_err(|_| corrupt())?
        .grant;
    // Resumed: before a saved grant is resent, or one for a newer ACTIVE
    // generation is built once and saved, the device must still be eligible
    // for the grant's generation: not found ineligible or filed by that
    // rotation's member step (revoked here or withdrawn is refused above). A
    // saved grant may already be a rebuilt one, so this runs every resume.
    if first_seen.is_none() {
        let active = client
            .active_fleet_generation(access, me.tenant_id, &fleet)
            .await?;
        let rebuild = active.filter(|g| *g > grant.generation.generation);
        let target = rebuild.unwrap_or(grant.generation.generation);
        let rotation = state.rotation.as_ref().filter(|r| r.generation == target);
        match rotation
            .and_then(|r| r.member_results.get(&id))
            .map(String::as_str)
        {
            Some("filed") => return Ok(()),
            // The rotation found it ineligible (revoked, withdrawn, no
            // approval) or the server refused it.
            Some(_) => bail!(not_pending()),
            None => {}
        }
        if let Some(active) = rebuild {
            let keys = listed_keys(row)?;
            if (keys.0, keys.1)
                != (
                    approved.subject_signing_key_id,
                    approved.subject_hpke_key_id,
                )
            {
                bail!(crate::errcode::code("fleet.deviceKeysMismatch"));
            }
            let ids = (approved.subject_account_id, approved.subject_device_id);
            let fkek = fleet_key(active)?;
            let built = member_grant(&cx, me.signer, ids, keys, &fkek, active, now)?;
            commit(state, save, |s| {
                if let Some(m) = s.members.get_mut(&id) {
                    m.grant_request = built.clone();
                }
            })?;
            filing = saved_request(&built)?;
            grant = FleetKeyGrantCreateV2::parse(&filing.canonical_payload_bytes)
                .map_err(|_| corrupt())?
                .grant;
        }
    }
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
/// The revocation in the saved request `saved`, signed by `issuer`.
fn saved_revocation(saved: &str, issuer: &[u8; 32]) -> Result<DeviceRevocationV2> {
    let request = saved_request(saved)?;
    let sent =
        DeviceRevokeRequestV2::parse(&request.canonical_payload_bytes).map_err(|_| corrupt())?;
    match AuthorizationRecord::parse(&sent.exact_signed_revocation_container_bytes)
        .and_then(|r| r.verify_signature(issuer))
        .map(|v| v.payload().clone())
    {
        Ok(Payload::DeviceRevocation(r)) => Ok(r),
        _ => Err(corrupt()),
    }
}

/// The `issued_at_ms` of the saved revocation request `saved`, signed here.
#[cfg(test)]
fn issued_at(saved: &str, signer: &Ed25519SigningKey) -> Result<u64> {
    saved_revocation(saved, signer.verifying_key().as_bytes()).map(|r| r.common.issued_at_ms)
}

/// How urgently a revocation asks for a fleet key rotation (ADR 0002 Q-20).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RotationRequired {
    Routine,
    Urgent,
}

/// D5 (B-1): the most urgent of this custodian's saved revocations whose
/// device is a known holder of `active`, the highest fleet generation this
/// device verified: a saved approval grant or rotation member grant for it
/// names that device, or `held` (the ledger's holdings) says its signing key
/// holds it. `lost`, or a revocation that does not verify under `issuer`
/// (this device's key), is urgent; `retired` is routine. A rotation clears
/// it: a revoked device gets no grant for the new generation.
pub fn rotation_required(
    state: &FleetCustodyState,
    issuer: &[u8; 32],
    active: u64,
    held: impl Fn(&[u8; 32]) -> bool,
) -> Option<RotationRequired> {
    let granted = |id: &str| {
        let approved = state.members.get(id).is_some_and(|m| {
            saved_request(&m.grant_request)
                .ok()
                .and_then(|r| FleetKeyGrantCreateV2::parse(&r.canonical_payload_bytes).ok())
                .is_some_and(|f| f.grant.generation.generation == active)
        });
        let rotated = state.rotation.as_ref().is_some_and(|r| {
            (r.generation == active
                && r.member_results.get(id).map(String::as_str) == Some("filed"))
                || (r.previous_generation == active && r.previous_holders.contains(id))
        });
        approved || rotated
    };
    state
        .revocations
        .iter()
        .filter_map(|(id, saved)| match saved_revocation(saved, issuer) {
            Ok(r) if granted(id) || held(&r.subject_signing_key_id) => Some(match r.reason_code {
                DeviceRevocationReason::Retired => RotationRequired::Routine,
                _ => RotationRequired::Urgent,
            }),
            Ok(_) => None,
            Err(_) => granted(id).then_some(RotationRequired::Urgent),
        })
        .max()
}

/// One more than the newest generation of a recovery bundle written while
/// another custody run held the state; 0 when none. That run applies it as
/// it ends ([`Running`]'s drop).
static EXPORTED_WHILE_BUSY: AtomicU64 = AtomicU64::new(0);

/// Ends the re-export prompt of a finished rotation once a recovery bundle
/// holding `newest`, the newest generation it carries, was written. While
/// another custody run holds the state, it is applied when that run ends,
/// so the run's own saves never bring the prompt back.
pub fn exported(newest: u64) -> Result<()> {
    let Ok(_running) = begin() else {
        EXPORTED_WHILE_BUSY.fetch_max(newest.saturating_add(1), Ordering::SeqCst);
        return Ok(());
    };
    clear_export_due(newest)
}

/// [`exported`] under the custody lock: a rotation past `newest` keeps the
/// prompt.
fn clear_export_due(newest: u64) -> Result<()> {
    let mut state = load()?;
    let covered = state
        .rotation
        .as_ref()
        .is_none_or(|r| r.generation <= newest);
    if state.export_due && covered {
        state.export_due = false;
        save(&state)?;
    }
    Ok(())
}

/// The reasons Revoke offers (section 4.R): `retired`, `lost` and, for a
/// member device only (Q-57, [`revoke_member`]), `compromised`.
pub fn revoke_reason(reason: &str) -> Result<DeviceRevocationReason> {
    match reason {
        "retired" => Ok(DeviceRevocationReason::Retired),
        "lost" => Ok(DeviceRevocationReason::Lost),
        "compromised" => Ok(DeviceRevocationReason::Compromised),
        _ => bail!(crate::errcode::code("fleet.revokeReasonUnsupported")),
    }
}

/// Runs, or resumes, Revoke of `row` as `reason` (section 4.R) under the
/// device session `access`. A saved revocation is resent as saved, whatever
/// `reason` now says, unless the server refuses it as one it cannot file now.
/// This device never revokes itself. `compromised` is built only once fresh
/// trust evidence, evaluated in `custody` to the pin, does not count the
/// row's key as a custodian (D10, Q-57); without `custody` it is refused.
#[allow(clippy::too_many_arguments)]
pub async fn revoke_member(
    client: &FleetClient,
    access: &str,
    me: &FleetDevice<'_>,
    row: &TenantDevice,
    reason: DeviceRevocationReason,
    mut custody: Option<&mut Ledger<'_>>,
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
    let mut build = !state.revocations.contains_key(&id);
    loop {
        if build {
            let (signing, hpke, _) = listed_keys(row)?;
            if reason == DeviceRevocationReason::Compromised {
                let refused =
                    || anyhow::anyhow!(crate::errcode::code("fleet.compromisedCustodian"));
                let ledger = custody.as_deref_mut().ok_or_else(refused)?;
                let pages = client.trust_evidence(access, me.tenant_id).await?;
                let (_, chain) = ledger.evaluate(&pages, now)?;
                // As strict as the Team page, which reads the ledger.
                if chain.custodians().any(|(k, ..)| *k == signing)
                    || crate::team::ledger::held_custody(ledger.db, &ledger.pin.0, &signing)?
                {
                    return Err(refused());
                }
            }
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
        let filed = async {
            let exact = unhex_vec(&state.revocations[&id])?;
            let request = IdempotentMutationRequestV2::parse(&exact).map_err(|_| corrupt())?;
            let sent = DeviceRevokeRequestV2::parse(&request.canonical_payload_bytes)
                .map_err(|_| corrupt())?;
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
        .await;
        // The server refuses, with a 403 coded `REVOCATION_OUTSIDE_WINDOW`, a
        // revocation it has not filed whose time window does not hold now on
        // its clock (`v2_device_revoke.rs`), and filing one revokes the row.
        // So only a saved one refused so, of a row still not revoked, is
        // built anew, once; any other 403 leaves the saved bytes as they are.
        match filed {
            Err(e) if !build && row.status != "revoked" && outside_window(&e) => {
                build = true;
            }
            filed => return filed,
        }
    }
}

/// Whether `e` is the custody refusal with status 403 and the top-level code
/// `REVOCATION_OUTSIDE_WINDOW`, read from the marker's own fields:
/// `fleet_client` fills `code` only from the reply's top-level JSON, and
/// escapes `|` and `]` in every value, so no echoed text forges a field.
fn outside_window(e: &anyhow::Error) -> bool {
    refused_with(e, 403, Some("REVOCATION_OUTSIDE_WINDOW"))
}

/// Whether `e` is the custody refusal with `status` and, when given, the
/// top-level `code`, read from the marker's own fields as [`outside_window`]
/// reads them.
fn refused_with(e: &anyhow::Error, status: u16, code: Option<&str>) -> bool {
    let text = e.to_string();
    let open = "[[shardx:fleet.refusedCustody|";
    text.find(open)
        .and_then(|i| text[i + open.len()..].split("]]").next())
        .is_some_and(|args| {
            let fields: Vec<&str> = args.split('|').collect();
            fields.contains(&format!("status={status}").as_str())
                && code.is_none_or(|c| fields.contains(&format!("code={c}").as_str()))
        })
}

/// Whether `e` is the server's refusal of the request itself: the custody
/// marker with a 4xx status other than 401, 408 or 429, which a resend of
/// the same bytes would not change.
fn refused_for_good(e: &anyhow::Error) -> bool {
    (400..500)
        .filter(|s| ![401, 408, 429].contains(s))
        .any(|s| refused_with(e, s, None))
}

// ---- Rotate fleet key (sequence K, ADR 0002 D-9) ----

/// The most signers one trust evidence request may name (`MAX_SIGNERS`,
/// `server/src/routes/v2_trust.rs`).
pub(crate) const MAX_SIGNERS: usize = 64;

/// Where a rotation stands.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RotationPhase {
    /// Steps 1-9: N+1 is not known to be ACTIVE.
    #[default]
    Preparing,
    /// Step 10 is done: N+1 is ACTIVE and this device holds it.
    Activated,
    /// Step 12: the members' grants are filed or recorded.
    Done,
    /// It can no longer activate, and the server showed N still ACTIVE.
    Expired,
}

impl RotationPhase {
    /// While a rotation is unfinished, approvals wait (ADR 0002 Q-48).
    fn unfinished(self) -> bool {
        matches!(self, Self::Preparing | Self::Activated)
    }
}

/// What one rotation keeps, hex-encoded, written before each request leaves
/// the device. No key is among it.
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct FleetRotationState {
    #[serde(default)]
    pub generation: u64,
    #[serde(default)]
    pub previous_generation: u64,
    #[serde(default)]
    pub previous_fkek_key_id: String,
    /// The server's restore epoch when the rotation started.
    #[serde(default)]
    pub restore_epoch: u64,
    /// Step 2: this device's `key.rotate` over the fleet (Q-51).
    #[serde(default)]
    pub rotate_grant: String,
    /// Names the rotation's setup key, as `FleetCustodyState::fkek_nonce`.
    #[serde(default)]
    pub fkek_nonce: String,
    #[serde(default)]
    pub fkek_key_id: String,
    #[serde(default)]
    pub device_grant: String,
    #[serde(default)]
    pub recovery_grant: String,
    #[serde(default)]
    pub rotation_grant: String,
    #[serde(default)]
    pub create_request: String,
    /// The device, recovery and rotation grant filings, in that order.
    #[serde(default)]
    pub grant_requests: Vec<String>,
    /// Their acks, in the same order.
    #[serde(default)]
    pub ack_requests: Vec<String>,
    #[serde(default)]
    pub activate_request: String,
    /// The end of the rotation grant's window, saved with step 4.
    #[serde(default)]
    pub deadline_ms: Option<u64>,
    #[serde(default)]
    pub phase: RotationPhase,
    /// Step 11: the filing of each member's N+1 grant, per lower-case
    /// device id.
    #[serde(default)]
    pub member_grants: BTreeMap<String, String>,
    /// Step 12: `filed`, `refused` or `skipped:<reason>`, per device id.
    #[serde(default)]
    pub member_results: BTreeMap<String, String>,
    /// The member whose grant filing last failed with an error a resend
    /// may cure, until the run is done or its filing goes through; empty
    /// when none.
    #[serde(default)]
    pub failing_member: String,
    /// How many runs in a row `failing_member`'s filing failed so.
    #[serde(default)]
    pub failing_runs: u32,
    /// Members the custodian chose to leave without the new key, per device
    /// id: recorded `skipped:custodian`.
    #[serde(default)]
    pub skipped_members: BTreeSet<String>,
    /// The devices a rotation's member step filed `previous_generation` for,
    /// kept from the rotation this one replaced, so a revoked holder keeps
    /// its banner if this one never activates.
    #[serde(default)]
    pub previous_holders: BTreeSet<String>,
    #[serde(default)]
    pub activated_at_ms: u64,
}

/// Runs in a row a member's grant filing must fail before the custodian
/// may skip it: one timeout never offers the irreversible skip.
const SKIP_AFTER_FAILED_RUNS: u32 = 2;

impl FleetRotationState {
    /// The member [`skip_member`] may leave out: its filing failed in
    /// [`SKIP_AFTER_FAILED_RUNS`] runs in a row of this activated rotation.
    fn skippable(&self) -> Option<&str> {
        (self.phase == RotationPhase::Activated
            && self.failing_runs >= SKIP_AFTER_FAILED_RUNS
            && !self.failing_member.is_empty())
        .then_some(self.failing_member.as_str())
    }
}

impl std::fmt::Debug for FleetRotationState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FleetRotationState")
            .field("generation", &self.generation)
            .field("phase", &self.phase)
            .field("fkek_key_id", &self.fkek_key_id)
            .field("deadline_ms", &self.deadline_ms)
            .field("member_results", &self.member_results)
            .finish_non_exhaustive()
    }
}

fn rotation_mut(s: &mut FleetCustodyState) -> &mut FleetRotationState {
    s.rotation.get_or_insert_with(Default::default)
}

/// The trust ledger a rotation evaluates evidence in, and this device's pin.
pub struct Ledger<'a> {
    pub db: &'a mut crate::team::db::Db,
    pub pin: &'a (Binding, [u8; 32]),
}

impl Ledger<'_> {
    fn evaluate(
        &mut self,
        pages: &[TenantTrustEvidencePageV2],
        now: u64,
    ) -> Result<(Vec<TenantTrustEvidencePageV2>, TrustChain)> {
        crate::team::ledger::evaluate(self.db, &self.pin.0, &self.pin.1, pages, now)?
            .ok_or_else(|| anyhow::anyhow!(crate::errcode::code("fleet.trustEvidenceRefused")))
    }
}

/// Runs, or resumes, Rotate fleet key (sequence K) through step 9 under the
/// device session `access`, `clock` giving the time. At Start, `previous_key` gives this
/// device's verified key of the ACTIVE generation N. `Ok` means N+1 is
/// ACTIVE: the command then releases the setup key and collects N+1 (step
/// 10) and runs [`grant_members`]. `save` persists `state`; every step that
/// builds new bytes saves them before sending, and a failed save stops the
/// run.
///
/// An expired rotation does not refuse Start: a new one is built, and the
/// server's create refusal `FLEET_GENERATION_EXISTS` (N+1 is still
/// PREPARING, Q-24) ends it `expired` again with `fleet.rotationStuck`. A
/// rotation whose N+1 never reached the server (its create never filed, or
/// undone by a restore) so starts over.
#[allow(clippy::too_many_arguments)]
pub async fn rotate_fleet(
    client: &FleetClient,
    access: &str,
    device: &FleetDevice<'_>,
    root: &BootstrapState,
    ledger: &mut Ledger<'_>,
    previous_key: impl FnOnce(u64) -> Result<Zeroizing<[u8; 32]>>,
    clock: impl Fn() -> u64,
    state: &mut FleetCustodyState,
    save: &mut impl FnMut(&FleetCustodyState) -> Result<()>,
) -> Result<()> {
    let now = clock();
    let ours = root.tenant_id.eq_ignore_ascii_case(device.tenant_id)
        && root.device_id.eq_ignore_ascii_case(device.device_id);
    if !root.activated || !ours {
        bail!(crate::errcode::code("fleet.notCustodian"));
    }
    let cx = custodian(device, state)?;
    // The deadline is checked at each send's time, not this call's: a wait
    // for the server may cross it.
    let past = |s: &FleetCustodyState| {
        let deadline = s.rotation.as_ref().and_then(|r| r.deadline_ms);
        deadline.is_some_and(|d| clock() >= d)
    };

    // 1. The server is the one this custody began on; a restore of it is
    // the expiry decision's.
    let id = client.server_identity(access).await?;
    let instance =
        decode_hex16(&id.server_instance_id, "server_instance_id").map_err(|_| mismatch())?;
    let epoch = u64::try_from(id.restore_epoch).map_err(|_| mismatch())?;
    if instance != cx.instance {
        bail!(crate::errcode::code("fleet.custodyServerChanged"));
    }
    let fleet = hex(&cx.tenant);
    // Stopped before step 4 across a server restore: nothing of N+1 is on
    // the server, and the saved requests name the old epoch, so it starts
    // over.
    let mut restarted = None;
    if state.rotation.as_ref().is_some_and(|r| {
        r.phase == RotationPhase::Preparing && r.deadline_ms.is_none() && r.restore_epoch != epoch
    }) {
        // The holders it kept from the rotation before still hold that key.
        restarted = state
            .rotation
            .as_ref()
            .map(|r| (r.previous_generation, r.previous_holders.clone()));
        release_fkek(device.vault, state, rotation_key, save)?;
        commit(state, save, |s| s.rotation = None)?;
        eprintln!("[rotation] restarted after a server restore before step 4");
    }
    match state
        .rotation
        .as_ref()
        .map(|r| (r.phase, r.deadline_ms, r.restore_epoch))
    {
        Some((RotationPhase::Activated, ..)) => return Ok(()),
        // Only once step 4 saved the deadline: nothing of N+1 is on the
        // server before.
        Some((RotationPhase::Preparing, Some(deadline), saved))
            if clock() >= deadline || saved != epoch =>
        {
            return expiry_decision(client, access, device, &fleet, clock(), None, state, save)
                .await;
        }
        Some((RotationPhase::Preparing, ..)) => {}
        _ => {
            let previous = client
                .active_fleet_generation(access, device.tenant_id, &fleet)
                .await?
                .ok_or_else(|| {
                    anyhow::anyhow!(crate::errcode::code("fleet.createFleetKeyFirst"))
                })?;
            let key = previous_key(previous)?;
            let pages = client.trust_evidence(access, device.tenant_id).await?;
            let (_, chain) = ledger.evaluate(&pages, now)?;
            if !chain.approval_valid_at(&cx.signing_key_id, Scope::Fleet(cx.tenant), now) {
                bail!(crate::errcode::code(
                    "fleet.rotationCustodianApprovalExpired"
                ));
            }
            let generation = previous.checked_add(1).ok_or_else(mismatch)?;
            let previous_holders = match (&state.rotation, restarted) {
                (Some(r), _) if r.generation == previous => r
                    .member_results
                    .iter()
                    .filter(|(_, result)| *result == "filed")
                    .map(|(id, _)| id.clone())
                    .collect(),
                (Some(r), _) if r.previous_generation == previous => r.previous_holders.clone(),
                (None, Some((generation, holders))) if generation == previous => holders,
                _ => BTreeSet::new(),
            };
            commit(state, save, |s| {
                s.rotation = Some(FleetRotationState {
                    generation,
                    previous_generation: previous,
                    previous_fkek_key_id: hex(&fkek_key_id(&key)),
                    restore_epoch: epoch,
                    previous_holders,
                    ..Default::default()
                })
            })?;
            eprintln!("[rotation] start: generation {previous} to {generation}");
        }
    }
    let cx = Context16 {
        epoch: state.rotation.as_ref().ok_or_else(corrupt)?.restore_epoch,
        ..cx
    };

    // 2. S0, filed whole.
    if rotation_mut(state).rotate_grant.is_empty() {
        let me = GrantSubject::Device {
            account_id: cx.account,
            device_id: cx.device,
            signing_key_id: cx.signing_key_id,
            hpke_key_id: cx.hpke_key_id,
        };
        let rotate = (Capability::KeyRotate, CapabilityScopeKind::Fleet, cx.tenant);
        let grant = capability_grants(&cx, device.signer, &me, [rotate], now)?
            .pop()
            .ok_or_else(corrupt)?;
        commit(state, save, |s| rotation_mut(s).rotate_grant = grant)?;
    }
    let grant = unhex_vec(&rotation_mut(state).rotate_grant)?;
    if client.file_capability_grant(access, &grant).await? != grant {
        return Err(mismatch());
    }

    // 3 and 4. Nothing is built again once the create request is saved.
    if rotation_mut(state).create_request.is_empty() {
        prepare_rotation(&cx, device, root, now, state, save)?;
    }
    let r = state.rotation.clone().ok_or_else(corrupt)?;
    if r.grant_requests.len() != 3 || r.ack_requests.len() != 3 {
        return Err(corrupt());
    }

    // 5. N+1, now PREPARING.
    if past(state) {
        return expiry_decision(client, access, device, &fleet, clock(), None, state, save).await;
    }
    let create = saved_request(&r.create_request)?;
    let expected = FleetKeyGenerationCreateV2::parse(&create.canonical_payload_bytes)
        .map_err(|_| corrupt())?;
    let stored = match client
        .create_fleet_generation(access, &fleet, &create.encode())
        .await
    {
        // Another create made N+1, and no route discards it (Q-24).
        Err(e) if refused_with(&e, 409, Some("FLEET_GENERATION_EXISTS")) => {
            expire(device.vault, state, save)?;
            bail!(crate::errcode::code("fleet.rotationStuck"));
        }
        stored => stored?,
    };
    let created = FleetKeyGenerationCreatedV2::parse(&stored_payload(
        &stored,
        &create,
        RECORD_TYPE_FLEET_GENERATION_CREATED,
    )?)
    .map_err(|_| mismatch())?;
    if created.create != expected {
        return Err(mismatch());
    }

    // 6 and 7. A 403 is the server's window check: the expiry decision.
    let sends = r.grant_requests.iter().map(|s| (s, false));
    for (saved, ack) in sends.chain(r.ack_requests.iter().map(|s| (s, true))) {
        if past(state) {
            return expiry_decision(client, access, device, &fleet, clock(), None, state, save)
                .await;
        }
        match send_grant(client, access, &fleet, r.generation, saved, ack).await {
            Err(e) if refused_with(&e, 403, None) => {
                let now = clock();
                return expiry_decision(client, access, device, &fleet, now, Some(e), state, save)
                    .await;
            }
            sent => sent?,
        }
    }

    // 8 and 9. Activation is due from `issued_at`: refused before it, only
    // a skewed clock can be early.
    if clock() >= r.deadline_ms.ok_or_else(corrupt)? {
        return expiry_decision(client, access, device, &fleet, clock(), None, state, save).await;
    }
    match activate(client, access, &fleet, &r).await {
        Err(e) if refused_with(&e, 409, Some("FLEET_GRANTS_INCOMPLETE")) => {
            bail!(crate::errcode::code("fleet.rotationNotYetDue"))
        }
        activated => activated,
    }
}

/// Sends the saved grant filing, or with `ack` the saved ack, of
/// `generation`, and checks that the stored reply names exactly its grant.
async fn send_grant(
    client: &FleetClient,
    access: &str,
    fleet: &str,
    generation: u64,
    saved: &str,
    ack: bool,
) -> Result<()> {
    let request = saved_request(saved)?;
    let payload = &request.canonical_payload_bytes;
    let (sent, answered) = if ack {
        let grant = FleetKeyGrantAckV2::parse(payload)
            .map_err(|_| corrupt())?
            .grant;
        let stored = client
            .ack_fleet_grant(access, fleet, generation, &request.encode())
            .await?;
        let acked = FleetKeyGrantAckedV2::parse(&stored_payload(
            &stored,
            &request,
            RECORD_TYPE_FLEET_GRANT_ACKED,
        )?)
        .map_err(|_| mismatch())?;
        (grant, acked.grant)
    } else {
        let grant = FleetKeyGrantCreateV2::parse(payload)
            .map_err(|_| corrupt())?
            .grant;
        let stored = client
            .file_fleet_grant(access, fleet, generation, &request.encode())
            .await?;
        let created = FleetKeyGrantCreatedV2::parse(&stored_payload(
            &stored,
            &request,
            RECORD_TYPE_FLEET_GRANT_CREATED,
        )?)
        .map_err(|_| mismatch())?;
        (grant, created.grant)
    };
    if sent != answered {
        return Err(mismatch());
    }
    Ok(())
}

/// Step 9: the saved activation, sent as saved; the stored reply restates
/// exactly its terms. A replay of one the server stored gets that reply.
async fn activate(
    client: &FleetClient,
    access: &str,
    fleet: &str,
    r: &FleetRotationState,
) -> Result<()> {
    let activate = saved_request(&r.activate_request)?;
    let terms = FleetKeyGenerationActivateV2::parse(&activate.canonical_payload_bytes)
        .map_err(|_| corrupt())?
        .terms;
    let stored = client
        .activate_fleet_generation(access, fleet, r.generation, &activate.encode())
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
    eprintln!("[rotation] step 9: generation {} ACTIVE", r.generation);
    Ok(())
}

/// The expiry decision (Q-49), past the deadline, after a server restore,
/// or on `refused`, a 403 to a rotation filing or ack: the server decides,
/// never this device's clock alone. N+1 ACTIVE: the saved activation is
/// resent, and only the server's stored reply for exactly its terms goes on
/// to step 10 (`Ok`). N ACTIVE: `expired`, except that `refused` is returned
/// as it is while `now` is before the deadline by more than the clock
/// tolerance. Anything else changes nothing.
#[allow(clippy::too_many_arguments)]
async fn expiry_decision(
    client: &FleetClient,
    access: &str,
    device: &FleetDevice<'_>,
    fleet: &str,
    now: u64,
    refused: Option<anyhow::Error>,
    state: &mut FleetCustodyState,
    save: &mut impl FnMut(&FleetCustodyState) -> Result<()>,
) -> Result<()> {
    let r = state.rotation.clone().ok_or_else(corrupt)?;
    let unknown = || anyhow::anyhow!(crate::errcode::code("fleet.rotationStateUnknown"));
    let active = client
        .active_fleet_generation(access, device.tenant_id, fleet)
        .await?;
    eprintln!(
        "[rotation] expiry decision: generation {}, server ACTIVE {active:?}",
        r.generation
    );
    if active == Some(r.generation) {
        return activate(client, access, fleet, &r)
            .await
            .map_err(|_| unknown());
    }
    if active != Some(r.previous_generation) {
        return Err(unknown());
    }
    if let Some(e) = refused {
        if r.deadline_ms
            .is_some_and(|d| now < d.saturating_sub(CLOCK_TOLERANCE_MS))
        {
            return Err(e);
        }
    }
    expire(device.vault, state, save)?;
    bail!(crate::errcode::code("fleet.rotationExpired"))
}

/// Phase `expired`: the setup key is released first; N stays ACTIVE.
fn expire(
    vault: &dyn FkekStore,
    state: &mut FleetCustodyState,
    save: &mut impl FnMut(&FleetCustodyState) -> Result<()>,
) -> Result<()> {
    release_fkek(vault, state, rotation_key, save)?;
    commit(state, save, |s| {
        rotation_mut(s).phase = RotationPhase::Expired
    })?;
    eprintln!("[rotation] expired");
    Ok(())
}

/// Step 10, before the verified collect of N+1: the rotation's setup key
/// goes, as Create fleet key's does.
pub fn release_rotation_key(
    vault: &dyn FkekStore,
    state: &mut FleetCustodyState,
    save: &mut impl FnMut(&FleetCustodyState) -> Result<()>,
) -> Result<()> {
    if state.rotation.is_none() {
        return Ok(());
    }
    release_fkek(vault, state, rotation_key, save)
}

/// Step 10, once the verified collect kept N+1: phase `activated`.
pub fn rotation_collected(
    now: u64,
    state: &mut FleetCustodyState,
    save: &mut impl FnMut(&FleetCustodyState) -> Result<()>,
) -> Result<()> {
    commit(state, save, |s| {
        let r = rotation_mut(s);
        r.phase = RotationPhase::Activated;
        r.activated_at_ms = now;
    })
}

/// Whether `saved`, an approval this custodian signed under `vk`, is in
/// force at `now`, covers `fleet` and names exactly these keys (Q-45).
fn approval_names(
    saved: &str,
    vk: &[u8; 32],
    (account, device): ([u8; 16], [u8; 16]),
    (signing, hpke, _): &([u8; 32], [u8; 32], [u8; 32]),
    fleet: [u8; 16],
    now: u64,
) -> bool {
    let Ok(bytes) = unhex_vec(saved) else {
        return false;
    };
    let Ok(Payload::DeviceApproval(a)) = AuthorizationRecord::parse(&bytes)
        .and_then(|r| r.verify_signature(vk))
        .map(|v| v.payload().clone())
    else {
        return false;
    };
    let subject = (
        a.subject_account_id,
        a.subject_device_id,
        a.subject_signing_key_id,
        a.subject_hpke_key_id,
    );
    a.common.not_before_ms <= now
        && now < a.common.not_after_ms
        && subject == (account, device, *signing, *hpke)
        && (matches!(a.approval_scope_kind, ApprovalScopeKind::Tenant)
            || a.approval_scope_id == fleet)
}

/// Sequence K steps 11 and 12 under the device session `access`, at `now`,
/// once N+1 is ACTIVE and `fkek` is this device's verified key of it.
///
/// A listed active device other than this one gets a `DeviceHpkeGrant` of
/// N+1, built once and saved before it is filed, only when its exact keys
/// are named by an approval this custodian saved, verifying under its key
/// and in force now, or by an approval valid now in the chain of fresh
/// evidence for exactly the listed signers (Q-45); and only when it is not
/// in `revocations`, not reported revoked and its signing key is not
/// withdrawn. The server's list is a hint: an evidence fetch that fails
/// stops the step before anything is filed, and never falls back to it. A
/// refused filing is recorded `refused`, an ineligible device
/// `skipped:<reason>`.
#[allow(clippy::too_many_arguments)]
pub async fn grant_members(
    client: &FleetClient,
    access: &str,
    me: &FleetDevice<'_>,
    ledger: &mut Ledger<'_>,
    fkek: &[u8; 32],
    now: u64,
    state: &mut FleetCustodyState,
    save: &mut impl FnMut(&FleetCustodyState) -> Result<()>,
) -> Result<()> {
    let r = state
        .rotation
        .clone()
        .filter(|r| r.phase == RotationPhase::Activated)
        .ok_or_else(corrupt)?;
    let cx = Context16 {
        epoch: r.restore_epoch,
        ..custodian(me, state)?
    };
    let fleet = hex(&cx.tenant);
    let rows = client.list_tenant_devices(access, me.tenant_id).await?;
    let mut results = BTreeMap::new();
    let mut listed = Vec::new();
    for row in rows
        .iter()
        .filter(|r| r.status == "active" && !r.device_id.eq_ignore_ascii_case(me.device_id))
    {
        let id = row.device_id.to_ascii_lowercase();
        let ids = decode_hex16(&row.account_id, "account_id")
            .and_then(|a| Ok((a, decode_hex16(&id, "device_id")?)));
        match (ids, listed_keys(row)) {
            (Ok(ids), Ok(keys)) => listed.push((id, ids, keys)),
            _ => {
                results.insert(id, "skipped:keys".to_string());
            }
        }
    }

    let vk = me.signer.verifying_key().to_bytes();
    let mut eligible = Vec::new();
    for batch in listed.chunks(MAX_SIGNERS) {
        let signers: Vec<[u8; 32]> = batch.iter().map(|(_, _, k)| k.0).collect();
        let (pages, closure) = crate::team::ledger::closure_evidence(
            client,
            access,
            me.tenant_id,
            ledger.db,
            ledger.pin,
            &signers,
            now,
        )
        .await?;
        let (seen, chain) = ledger.evaluate(&pages, now)?;
        crate::team::ledger::record(ledger.db, &ledger.pin.0, &seen, &chain, None, closure, now)?;
        for (id, ids, keys) in batch {
            let skip =
                if state.revocations.contains_key(id) || chain.reported_revoked_at(&keys.0, now) {
                    Some("revoked")
                } else if crate::team::ledger::withdrawn(ledger.db, &ledger.pin.0, &keys.0)? {
                    Some("withdrawn")
                } else if state
                    .members
                    .get(id)
                    .is_some_and(|m| approval_names(&m.approval, &vk, *ids, keys, cx.tenant, now))
                    || chain.approves_keys(
                        &keys.0,
                        &keys.1,
                        &ids.1,
                        &ids.0,
                        Scope::Fleet(cx.tenant),
                        now,
                    )
                {
                    None
                } else {
                    Some("no-approval")
                };
            match skip {
                Some(why) => {
                    results.insert(id.clone(), format!("skipped:{why}"));
                }
                None => eligible.push((id.clone(), *ids, *keys)),
            }
        }
    }

    for (id, ids, keys) in eligible {
        if r.skipped_members.contains(&id) {
            results.insert(id, "skipped:custodian".to_string());
            continue;
        }
        let saved = rotation_mut(state).member_grants.get(&id).cloned();
        let filing = match saved {
            Some(filing) => filing,
            None => {
                let built = member_grant(&cx, me.signer, ids, keys, fkek, r.generation, now)?;
                commit(state, save, |s| {
                    rotation_mut(s)
                        .member_grants
                        .insert(id.clone(), built.clone());
                })?;
                built
            }
        };
        // Anything but the server's refusal stops here, phase `activated`: a
        // resume resends the saved filing, which the server replays.
        let result = match send_grant(client, access, &fleet, r.generation, &filing, false).await {
            Ok(()) => "filed",
            Err(e) if refused_for_good(&e) => "refused",
            Err(e) => {
                // Counted for the custodian, who may skip it once it keeps
                // failing ([`skip_member`]).
                commit(state, save, |s| {
                    let r = rotation_mut(s);
                    r.failing_runs = if r.failing_member == id {
                        r.failing_runs.saturating_add(1)
                    } else {
                        1
                    };
                    r.failing_member = id.clone();
                })?;
                return Err(e);
            }
        };
        if rotation_mut(state).failing_member == id {
            commit(state, save, |s| {
                let r = rotation_mut(s);
                r.failing_member.clear();
                r.failing_runs = 0;
            })?;
        }
        results.insert(id, result.to_string());
    }
    for (id, result) in &results {
        eprintln!("[rotation] member {id}: {result}");
    }
    commit(state, save, |s| {
        s.export_due = true;
        let r = rotation_mut(s);
        r.member_results = results;
        r.failing_member.clear();
        r.failing_runs = 0;
        r.phase = RotationPhase::Done;
    })?;
    eprintln!("[rotation] done: generation {}", r.generation);
    Ok(())
}

/// The custodian leaves `device_id`, the member whose grant filing failed
/// in two runs in a row of the activated rotation, without the new key: the next run
/// records it `skipped:custodian` and finishes. It must then be revoked and
/// enroll again, as a refused member must.
pub fn skip_member(
    state: &mut FleetCustodyState,
    device_id: &str,
    save: &mut impl FnMut(&FleetCustodyState) -> Result<()>,
) -> Result<()> {
    let id = device_id.trim().to_ascii_lowercase();
    let failing = state
        .rotation
        .as_ref()
        .and_then(FleetRotationState::skippable)
        == Some(id.as_str());
    if !failing {
        bail!(crate::errcode::code("fleet.rotationSkipRefused"));
    }
    eprintln!("[rotation] member {id}: skipped by the custodian");
    commit(state, save, |s| {
        rotation_mut(s).skipped_members.insert(id.clone());
    })
}

/// Set while Create fleet key runs in this process; the single-instance
/// plugin keeps the launcher to one process.
static RUNNING: AtomicBool = AtomicBool::new(false);

/// Held for one run: a second run while one is going is refused, so two runs
/// never build different requests from the same empty state.
pub struct Running(());

impl Drop for Running {
    fn drop(&mut self) {
        // Still under the lock: an export that finished meanwhile ends the
        // prompt now ([`exported`]).
        let pending = EXPORTED_WHILE_BUSY.swap(0, Ordering::SeqCst);
        if let Some(newest) = pending.checked_sub(1) {
            if let Err(e) = clear_export_due(newest) {
                eprintln!("[recovery] export prompt: not cleared ({e:#})");
            }
        }
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
    /// The latest fleet key rotation, if any.
    pub rotation: Option<RotationStatus>,
    /// A finished rotation asks for the recovery bundle to be exported again.
    pub export_due: bool,
    /// Set by the command from [`rotation_required`]; `status` leaves it out.
    pub rotation_required: Option<RotationRequired>,
    /// The latest Re-seal all profiles run, if any.
    pub reseal: Option<ResealRun>,
}

/// How far the latest rotation got: no secret of it.
#[derive(Serialize, Debug, PartialEq)]
pub struct RotationStatus {
    pub generation: u64,
    pub phase: RotationPhase,
    pub deadline_ms: Option<u64>,
    pub members_filed: usize,
    pub members_refused: usize,
    pub members_skipped: usize,
    /// The member whose grant keeps failing, which the custodian may skip.
    pub failing_member: Option<String>,
}

/// Releases the setup key of the state on disk once generation 0 is active,
/// before the verified collect: no later step reads it.
pub fn release(vault: &dyn FkekStore) -> Result<()> {
    let mut state = load()?;
    release_fkek(vault, &mut state, bootstrap_key, &mut |s| save(s))
}

/// The saved progress.
pub fn status() -> Result<FleetCustodyStatus> {
    let s = load()?;
    Ok(FleetCustodyStatus {
        started: !s.tenant_id.is_empty(),
        created: !s.create_request.is_empty() || s.imported,
        setup_key_held: !s.fkek_nonce.is_empty(),
        fkek_key_id: s.fkek_key_id,
        rotation: s.rotation.map(|r| {
            let count = |what: &str| {
                r.member_results
                    .values()
                    .filter(|v| v.starts_with(what))
                    .count()
            };
            RotationStatus {
                generation: r.generation,
                phase: r.phase,
                deadline_ms: r.deadline_ms,
                members_filed: count("filed"),
                members_refused: count("refused"),
                members_skipped: count("skipped"),
                failing_member: r.skippable().map(str::to_owned),
            }
        }),
        export_due: s.export_due,
        rotation_required: None,
        reseal: s.reseal,
    })
}

/// Drops the saved fleet grant acks (G12) when this device's identity goes:
/// an ack names its grant, not the device, so a new identity of this device
/// would resend the old one.
pub fn forget_device_acks() -> Result<()> {
    let mut state = load()?;
    if state.device_acks.is_empty() {
        return Ok(());
    }
    state.device_acks.clear();
    save(&state)
}

/// Loads the state; none yet is the empty state.
pub fn load() -> Result<FleetCustodyState> {
    let path = crate::store::fleet_custody_path()?;
    if !path.try_exists()? {
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
pub(crate) mod tests {
    use super::*;
    use crate::fleet_keys;
    use shardx_core::mutation::IdempotentStoredResponseV2;
    use std::sync::atomic::{AtomicU16, AtomicU64, AtomicUsize};
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

    pub(crate) fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    pub(crate) type Seen = Arc<Mutex<Vec<(String, Vec<u8>)>>>;
    pub(crate) type Reply = dyn Fn(&str, &[u8]) -> (u16, Vec<u8>) + Send + Sync;

    /// A server on this machine that records every request as
    /// `"METHOD /path"`, or `"METHOD /path?query"`, and its body, and
    /// answers with `reply`.
    pub(crate) async fn mock(reply: Arc<Reply>) -> (FleetClient, Seen) {
        use axum::http::{Method, StatusCode, Uri};
        let seen: Seen = Arc::default();
        let log = seen.clone();
        let app = axum::Router::new().fallback(
            move |method: Method, uri: Uri, body: axum::body::Bytes| {
                let (log, reply) = (log.clone(), reply.clone());
                async move {
                    let call = match uri.query() {
                        Some(q) => format!("{method} {}?{q}", uri.path()),
                        None => format!("{method} {}", uri.path()),
                    };
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
        assert!(hold_fkek(&CredentialFkekStore, &mut state, bootstrap_key, &mut crash).is_err());
        assert!(state.fkek_key_id.is_empty() && !state.fkek_nonce.is_empty());
        let first = held(&state);
        let vault = Counting(AtomicUsize::new(0));
        let key = hold_fkek(&vault, &mut state, bootstrap_key, &mut |_| Ok(())).unwrap();
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
            let err = hold_fkek(&vault, &mut s, bootstrap_key, &mut |_| {
                bail!("nothing is saved")
            })
            .unwrap_err();
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

    /// A recovery import's state is this device's custody without a saved
    /// create request; a member's is not.
    #[test]
    fn an_imported_state_is_custody_without_a_create_request() {
        let f = fixture();
        let device = f.device(&CredentialFkekStore);
        let mut state = f.state();
        assert!(custodian(&device, &state).is_err());
        save(&state).unwrap();
        assert!(!status().unwrap().created);
        state.imported = true;
        assert!(custodian(&device, &state).is_ok());
        save(&state).unwrap();
        assert!(status().unwrap().created);
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
            .block_on(crate::collect_fleet_grant(
                &client, &c, "access", &[0; 32], true,
            ))
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

    /// An ack Collect key custody saved for a grant still PENDING_ACK is kept
    /// when the setup key is released afterwards.
    #[test]
    fn a_collected_ack_survives_a_later_release_of_the_setup_key() {
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
            let got = crate::setup_collect_error(fleet.clone(), 0);
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
            |_| Ok(false),
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
    fn a_successful_device_listing_does_not_echo_its_access_token_to_ipc() {
        let f = fixture();
        let rt = runtime();
        let access = format!("v2a.{}", "6f".repeat(32));
        let (mut row, _) = joiner();
        // A hostile server knows the bearer it just received. Return it in
        // the label encoding the client decodes before forming its IPC reply.
        row.label_hex = hex(access.as_bytes());
        let body = serde_json::to_vec(&serde_json::json!({ "devices": [{
            "device_id": row.device_id, "account_id": row.account_id,
            "status": row.status, "label_hex": row.label_hex,
            "signing_key_id": row.signing_key_id, "hpke_key_id": row.hpke_key_id,
            "signing_public_key": row.signing_public_key,
            "hpke_public_key": row.hpke_public_key,
        }] }))
        .unwrap();
        let (client, _) = rt.block_on(mock(Arc::new(move |call, _| {
            assert!(call.ends_with("/devices"));
            (200, body.clone())
        })));
        let rows = rt
            .block_on(client.list_tenant_devices(&access, &f.tenant))
            .unwrap();
        let mut state = f.state();
        let listed = see_devices(&rows, &f.pin(), now_ms(), &mut state, &mut |_| Ok(())).unwrap();
        let reply = serde_json::to_string(&listed).unwrap();
        assert!(
            !reply.contains(&access),
            "the device-list IPC reply leaked the access token"
        );
    }

    /// Lists `row` as the server answers it to the bearer `access`, then sees
    /// it, saving into `saved`: the IPC reply, or the error.
    fn list_and_see(access: &str, row: &TenantDevice, saved: &mut Vec<String>) -> Result<String> {
        let f = fixture();
        let rt = runtime();
        let body = serde_json::to_vec(&serde_json::json!({ "devices": [{
            "device_id": row.device_id, "account_id": row.account_id,
            "status": row.status, "label_hex": row.label_hex,
            "signing_key_id": row.signing_key_id, "hpke_key_id": row.hpke_key_id,
            "signing_public_key": row.signing_public_key,
            "hpke_public_key": row.hpke_public_key,
        }] }))
        .unwrap();
        let (client, _) = rt.block_on(mock(Arc::new(move |_, _| (200, body.clone()))));
        let rows = rt.block_on(client.list_tenant_devices(access, &f.tenant))?;
        let mut state = f.state();
        let listed = see_devices(&rows, &f.pin(), now_ms(), &mut state, &mut |s| {
            saved.push(serde_json::to_string(s).unwrap());
            Ok(())
        })?;
        Ok(serde_json::to_string(&listed).unwrap())
    }

    #[test]
    fn a_device_row_with_a_bad_key_id_is_refused_before_anything_is_saved() {
        let access = format!("v2a.{}", "6e".repeat(32));
        let (mut row, _) = joiner();
        assert_eq!(row.status, "pending");
        row.signing_key_id = access.clone();
        let mut saved = Vec::new();
        let err = list_and_see(&access, &row, &mut saved)
            .unwrap_err()
            .to_string();
        assert!(err.contains("fleet.badReplyCustody"), "{err}");
        assert!(
            saved.iter().all(|s| !s.contains(&access)),
            "the state kept the token"
        );
    }

    #[test]
    fn a_device_label_holding_the_token_body_is_not_echoed_to_ipc() {
        let body = "6d".repeat(32);
        let access = format!("v2a.{body}");
        // The server reads hex in either case: so must the scrub.
        for echoed in [body.clone(), body.to_ascii_uppercase()] {
            let (mut row, _) = joiner();
            row.label_hex = hex(format!("label {echoed}").as_bytes());
            let reply = list_and_see(&access, &row, &mut Vec::new()).unwrap();
            assert!(
                !reply.to_ascii_lowercase().contains(&body),
                "the IPC reply leaked the token body as {echoed}"
            );
        }
    }

    /// A hex account password is also a well-formed ID: a server that got it
    /// at login and lists it as a device or account ID is refused before
    /// state, IPC or a log sees it, in either case.
    #[test]
    fn a_listed_id_equal_to_the_account_password_is_refused() {
        let f = fixture();
        let rt = runtime();
        let password = crate::fleet_client::random_id_hex();
        for (account, echoed) in [
            (false, password.clone()),
            (false, password.to_ascii_uppercase()),
            (true, password.clone()),
        ] {
            let (mut row, _) = joiner();
            if account {
                row.account_id = echoed;
            } else {
                row.device_id = echoed;
            }
            let body = serde_json::to_vec(&serde_json::json!({ "devices": [{
                "device_id": row.device_id, "account_id": row.account_id,
                "status": row.status, "label_hex": row.label_hex,
                "signing_key_id": row.signing_key_id, "hpke_key_id": row.hpke_key_id,
                "signing_public_key": row.signing_public_key,
                "hpke_public_key": row.hpke_public_key,
            }] }))
            .unwrap();
            let (client, _) = rt.block_on(mock(Arc::new(move |call: &str, _: &[u8]| match call {
                c if c.ends_with("/devices") => (200, body.clone()),
                _ => (401, Vec::new()),
            })));
            let login = crate::fleet_client::AccountLogin {
                tenant_id: &f.tenant,
                username: "owner",
                password: &password,
            };
            // The login is refused, but the server got the password.
            assert!(rt
                .block_on(client.server_identity_with_login(&login))
                .is_err());
            let err = rt
                .block_on(client.list_tenant_devices("v2a.access", &f.tenant))
                .unwrap_err()
                .to_string();
            assert!(err.contains("fleet.badReplyCustody"), "{account}: {err}");
            assert!(!err.to_ascii_lowercase().contains(&password), "{account}");
        }
    }

    /// A bearer body is also a well-formed key ID, but no listed key hashes
    /// to it: neither the IPC reply nor any saved state may carry it.
    #[test]
    fn device_key_ids_do_not_echo_the_session_token_body() {
        let body = "9b".repeat(32);
        let access = format!("v2a.{body}");
        let mut ipc_leaks = 0;
        let mut state_leaks = 0;
        for hpke in [false, true] {
            for echoed in [body.clone(), body.to_ascii_uppercase()] {
                let (mut row, _) = joiner();
                if hpke {
                    row.hpke_key_id = echoed;
                } else {
                    row.signing_key_id = echoed;
                }
                let mut saved = Vec::new();
                let result = list_and_see(&access, &row, &mut saved);
                if let Ok(reply) = result {
                    ipc_leaks += usize::from(reply.to_ascii_lowercase().contains(&body));
                }
                state_leaks +=
                    usize::from(saved.iter().any(|s| s.to_ascii_lowercase().contains(&body)));
            }
        }
        // Report counts only, never the token or captured output.
        assert_eq!(
            (ipc_leaks, state_leaks),
            (0, 0),
            "bearer body crossed a custody boundary"
        );
    }

    /// An honest server keeps listing a revoked or quarantined row whose
    /// stored key IDs no longer hash from its keys (`integrity.rs`): the
    /// listing survives and shows the derived IDs, never what stood in for
    /// them. A pending row like that is still refused.
    #[test]
    fn a_settled_row_with_a_bad_key_id_is_listed_by_its_derived_ids() {
        let body = "9a".repeat(32);
        let access = format!("v2a.{body}");
        let (good, _) = joiner();
        for status in ["revoked", "quarantined", "pending"] {
            for hpke in [false, true] {
                for echoed in [body.clone(), body.to_ascii_uppercase()] {
                    let mut row = TenantDevice {
                        status: status.into(),
                        ..good.clone()
                    };
                    if hpke {
                        row.hpke_key_id = echoed;
                    } else {
                        row.signing_key_id = echoed;
                    }
                    let mut saved = Vec::new();
                    let reply = list_and_see(&access, &row, &mut saved);
                    assert!(saved
                        .iter()
                        .all(|s| !s.to_ascii_lowercase().contains(&body)));
                    if status == "pending" {
                        let err = reply.unwrap_err().to_string();
                        assert!(err.contains("fleet.badReplyCustody"), "{err}");
                        continue;
                    }
                    let reply = reply.unwrap();
                    assert!(!reply.to_ascii_lowercase().contains(&body), "{status}");
                    let listed: serde_json::Value = serde_json::from_str(&reply).unwrap();
                    assert_eq!(listed.as_array().unwrap().len(), 1, "{status}");
                    assert_eq!(listed[0]["status"], status);
                    assert_eq!(listed[0]["signing_key_id"], good.signing_key_id);
                    assert_eq!(listed[0]["hpke_key_id"], good.hpke_key_id);
                }
            }
        }
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
            None,
            now,
            &mut state,
            &mut |s| save(s),
        ))
        .unwrap_err()
        .to_string()
    }

    #[test]
    fn only_retired_lost_and_compromised_are_accepted() {
        assert_eq!(
            revoke_reason("retired").unwrap(),
            DeviceRevocationReason::Retired
        );
        assert_eq!(revoke_reason("lost").unwrap(), DeviceRevocationReason::Lost);
        for other in ["rekeyed", "", "Retired", " lost", "Compromised"] {
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
                "rekeyed".into(),
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

        // A minute later, asked as lost, the same bytes go out again.
        let err = revoke(
            &rt,
            &f,
            &client,
            &row,
            DeviceRevocationReason::Lost,
            t0 + MINUTE,
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

    #[test]
    fn a_stale_unfiled_revocation_is_rebuilt() {
        let f = fixture();
        save(&f.prepared()).unwrap();
        let (row, _) = joiner();
        let active = TenantDevice {
            status: "active".into(),
            ..row
        };
        let filed = TenantDevice {
            status: "revoked".into(),
            ..active.clone()
        };
        let rt = runtime();
        // Every request is refused as the server refuses an issue time it
        // finds too far from its clock.
        let (client, seen) = rt.block_on(mock(Arc::new(|_: &str, _: &[u8]| {
            (
                403,
                br#"{"code":"REVOCATION_OUTSIDE_WINDOW","error":"window"}"#.to_vec(),
            )
        })));
        let t0 = now_ms();
        let id = active.device_id.to_ascii_lowercase();
        let issued = || issued_at(&load().unwrap().revocations[&id], &f.signer).unwrap();
        let retired = DeviceRevocationReason::Retired;

        // The first request is refused.
        revoke(&rt, &f, &client, &active, retired, t0);
        let first = load().unwrap().revocations[&id].clone();

        // Ten minutes on, a row the server shows revoked filed it: resent.
        let later = t0 + 10 * MINUTE;
        revoke(&rt, &f, &client, &filed, retired, later);
        assert_eq!(load().unwrap().revocations[&id], first);

        // A row still active means it was never filed: the saved one is sent
        // first, and once refused, a fresh one is built, saved and sent.
        revoke(&rt, &f, &client, &active, retired, later);
        let second = load().unwrap().revocations[&id].clone();
        assert_ne!(second, first);
        assert_eq!(issued(), later - MINUTE);
        let bodies: Vec<Vec<u8>> = sent(&seen).into_iter().map(|(_, b)| b).collect();
        let (first, second) = (unhex_vec(&first).unwrap(), unhex_vec(&second).unwrap());
        assert_eq!(bodies, [first.clone(), first.clone(), first, second]);
    }

    #[test]
    fn a_new_row_id_for_the_same_keys_keeps_the_first_sight_window() {
        let f = fixture();
        let mut state = f.prepared();
        let (row, _) = joiner();
        let t0 = now_ms();
        see_devices(
            std::slice::from_ref(&row),
            &f.pin(),
            t0,
            &mut state,
            &mut |s| save(s),
        )
        .unwrap();
        let alias = TenantDevice {
            device_id: hex(&[0x6f; 16]),
            ..row.clone()
        };
        assert!(
            f.code(&row) == f.code(&alias),
            "the ceremony inputs did not change"
        );
        let rt = runtime();
        let (client, seen) = rt.block_on(mock(approve_server()));
        let _error = approve(&rt, &f, &client, &alias, &f.code(&row), t0 + 11 * MINUTE);
        assert!(
            sent(&seen).is_empty(),
            "a row alias extended the approval window without new keys"
        );
    }

    /// `row` with fresh keys from `seed`, so its code differs.
    fn rekeyed(row: &TenantDevice, seed: u8) -> TenantDevice {
        let vk = Ed25519SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes();
        let (_, pk) = derive_keypair(&[seed ^ 0xff; 32]);
        TenantDevice {
            signing_public_key: hex(&vk),
            hpke_public_key: hex(&pk),
            signing_key_id: hex(&signing_key_id(&vk)),
            hpke_key_id: hex(&hpke_key_id(&pk)),
            ..row.clone()
        }
    }

    /// Lists `rows` at `now`, as Show devices does.
    fn list(f: &Fixture, rows: &[TenantDevice], now: u64) {
        let mut state = load().unwrap();
        see_devices(rows, &f.pin(), now, &mut state, &mut |s| save(s)).unwrap();
    }

    #[test]
    fn keys_moved_onto_a_row_seen_later_keep_their_first_sight_window() {
        let f = fixture();
        save(&f.prepared()).unwrap();
        let (a, _) = joiner();
        let b = TenantDevice {
            device_id: hex(&[0x6f; 16]),
            ..rekeyed(&a, 0x1d)
        };
        let t0 = now_ms();
        list(&f, std::slice::from_ref(&a), t0);
        list(&f, std::slice::from_ref(&b), t0 + 5 * MINUTE);
        // B now lists A's keys, twelve minutes after they were first seen.
        let moved = TenantDevice {
            device_id: b.device_id.clone(),
            ..a.clone()
        };
        let rt = runtime();
        let (client, seen) = rt.block_on(mock(approve_server()));
        let err = approve(&rt, &f, &client, &moved, &f.code(&a), t0 + 12 * MINUTE);
        assert!(err.contains("fleet.approvalWindowClosed"), "{err}");
        assert!(sent(&seen).is_empty(), "nothing is asked or filed");
        let listed = see_devices(
            std::slice::from_ref(&moved),
            &f.pin(),
            t0 + 12 * MINUTE,
            &mut load().unwrap(),
            &mut |s| save(s),
        )
        .unwrap();
        assert_eq!(listed[0].approve_until_ms, Some(t0 + 10 * MINUTE));
    }

    #[test]
    fn keys_first_seen_after_a_swap_start_their_window_then() {
        let f = fixture();
        save(&f.prepared()).unwrap();
        let (a, _) = joiner();
        let t0 = now_ms();
        list(&f, &[rekeyed(&a, 0x1d)], t0);
        // A swaps to keys K, first seen now; B then lists K too.
        let tk = t0 + MINUTE;
        list(&f, std::slice::from_ref(&a), tk);
        let b = TenantDevice {
            device_id: hex(&[0x6f; 16]),
            ..a.clone()
        };
        list(&f, std::slice::from_ref(&b), tk + 5 * MINUTE);
        let rt = runtime();
        let (client, seen) = rt.block_on(mock(approve_server()));
        let err = approve(&rt, &f, &client, &b, &f.code(&a), tk + 11 * MINUTE);
        assert!(err.contains("fleet.approvalWindowClosed"), "{err}");
        assert!(sent(&seen).is_empty(), "nothing is asked or filed");
    }

    #[test]
    fn a_retry_resends_a_saved_revocation_the_server_may_still_file() {
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
        revoke(&rt, &f, &client, &row, DeviceRevocationReason::Retired, t0);
        let saved = load().unwrap().revocations[&row.device_id].clone();
        // The server clock is one minute behind this custodian's. At retry,
        // the saved issued_at is only 270 seconds old on that server.
        let retry = t0 + 270_000;
        let server_now = retry - MINUTE;
        assert!(server_now - issued_at(&saved, &f.signer).unwrap() < 300_000);
        revoke(
            &rt,
            &f,
            &client,
            &row,
            DeviceRevocationReason::Retired,
            retry,
        );
        let posts = sent(&seen);
        assert_eq!(posts.len(), 2);
        assert!(
            posts[0].1 == posts[1].1,
            "a still-valid saved revocation was replaced"
        );
    }

    #[test]
    fn an_approval_is_not_signed_once_the_window_closes_during_the_generation_read() {
        let f = fixture();
        save(&f.prepared()).unwrap();
        let (row, _) = joiner();
        let rt = runtime();
        let t0 = now_ms();
        let first_seen = t0 - JOIN_WINDOW_MS + 50;
        list(&f, std::slice::from_ref(&row), first_seen);
        let (client, seen) = rt.block_on(mock(Arc::new(move |call, _| {
            if call.ends_with("/key-generation") {
                std::thread::sleep(std::time::Duration::from_millis(150));
                (200, b"{\"generation\":0}".to_vec())
            } else {
                (503, Vec::new())
            }
        })));
        let error = approve(&rt, &f, &client, &row, &f.code(&row), t0);
        assert!(error.contains("fleet.approvalWindowClosed"), "{error}");
        assert!(now_ms() > first_seen + JOIN_WINDOW_MS);
        assert!(
            sent(&seen).is_empty(),
            "a new approval was sent after its local deadline"
        );
    }

    #[test]
    fn a_generic_403_does_not_replace_a_saved_revocation() {
        let f = fixture();
        save(&f.prepared()).unwrap();
        let (mut row, _) = joiner();
        row.status = "active".into();
        let rt = runtime();
        let (client, seen) = rt.block_on(mock(Arc::new(|_, _| (403, Vec::new()))));
        let t0 = now_ms();
        revoke(&rt, &f, &client, &row, DeviceRevocationReason::Retired, t0);
        let saved = load().unwrap().revocations[&row.device_id].clone();
        let retry = t0 + 270_000;
        let server_now = retry - MINUTE;
        assert!(server_now - issued_at(&saved, &f.signer).unwrap() < 300_000);
        revoke(
            &rt,
            &f,
            &client,
            &row,
            DeviceRevocationReason::Retired,
            retry,
        );
        let posts = sent(&seen);
        assert!(
            posts.len() >= 2,
            "both attempts must reach the loopback server"
        );
        assert!(
            posts
                .iter()
                .all(|(_, body)| body == &unhex_vec(&saved).unwrap()),
            "HTTP 403 replaced a request still valid on the server clock"
        );
    }

    #[test]
    fn a_nested_error_code_does_not_replace_a_valid_saved_revocation() {
        let f = fixture();
        save(&f.prepared()).unwrap();
        let (mut row, _) = joiner();
        row.status = "active".into();
        let rt = runtime();
        let (client, seen) = rt.block_on(mock(Arc::new(|_, _| {
            (
                403,
                br#"{"code":"FORBIDDEN","context":{"code":"REVOCATION_OUTSIDE_WINDOW"}}"#.to_vec(),
            )
        })));
        let t0 = now_ms();
        revoke(&rt, &f, &client, &row, DeviceRevocationReason::Retired, t0);
        let saved = load().unwrap().revocations[&row.device_id].clone();
        assert_eq!(sent(&seen).len(), 1);
        revoke(
            &rt,
            &f,
            &client,
            &row,
            DeviceRevocationReason::Retired,
            t0 + 1_000,
        );
        assert!(
            sent(&seen)
                .iter()
                .all(|(_, body)| body == &unhex_vec(&saved).unwrap()),
            "a nested context code replaced a still-valid saved revocation"
        );
    }

    #[test]
    fn a_refused_device_listing_hides_the_access_token_body() {
        let f = fixture();
        let rt = runtime();
        let token_body = "9c".repeat(32);
        let access = format!("v2a.{token_body}");
        let echoed = token_body.clone();
        let (client, _) = rt.block_on(mock(Arc::new(move |_, _| {
            (
                403,
                serde_json::to_vec(&serde_json::json!({"error": echoed})).unwrap(),
            )
        })));
        let error = rt
            .block_on(client.list_tenant_devices(&access, &f.tenant))
            .unwrap_err()
            .to_string();
        assert!(error.contains("fleet.refusedCustody|status=403|"));
        assert!(
            !error.to_ascii_lowercase().contains(&token_body),
            "the error returned to IPC contains the bearer token body"
        );
    }

    #[test]
    fn a_formatted_window_error_recovers_a_stale_unfiled_revocation() {
        let f = fixture();
        save(&f.prepared()).unwrap();
        let (mut row, _) = joiner();
        row.status = "active".into();
        let rt = runtime();
        let (offline, _) = rt.block_on(mock(refuse_all()));
        let t0 = now_ms();
        revoke(&rt, &f, &offline, &row, DeviceRevocationReason::Retired, t0);
        let saved = load().unwrap().revocations[&row.device_id].clone();
        let body = serde_json::to_vec_pretty(&serde_json::json!({
            "code": "REVOCATION_OUTSIDE_WINDOW", "error": "window"
        }))
        .unwrap();
        let (client, seen) = rt.block_on(mock(Arc::new(move |_, _| (403, body.clone()))));
        let error = revoke(
            &rt,
            &f,
            &client,
            &row,
            DeviceRevocationReason::Retired,
            t0 + 10 * MINUTE,
        );
        assert!(error.contains("fleet.refusedCustody|status=403|"));
        assert!(
            load().unwrap().revocations[&row.device_id] != saved,
            "equivalent JSON whitespace stranded the expired unfiled revocation"
        );
        assert_eq!(
            sent(&seen).len(),
            2,
            "retry the saved bytes then the rebuilt request"
        );
    }

    #[test]
    fn a_refused_custody_post_hides_the_access_token_body() {
        let rt = runtime();
        let token_body = "ad".repeat(32);
        let access = format!("v2a.{token_body}");
        let echoed = token_body.to_ascii_uppercase();
        let (client, _) = rt.block_on(mock(Arc::new(move |_, _| {
            (
                403,
                serde_json::to_vec(&serde_json::json!({"code": echoed, "error": echoed})).unwrap(),
            )
        })));
        let error = rt
            .block_on(client.revoke_device(&access, &"11".repeat(16), b"request"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("fleet.refusedCustody|status=403|"));
        assert!(
            !error.to_ascii_lowercase().contains(&token_body),
            "the custody refusal returned to IPC contains the bearer token body"
        );
    }

    #[test]
    fn an_echoed_marker_field_is_not_read_as_the_window_code() {
        let rt = runtime();
        let (client, _) = rt.block_on(mock(Arc::new(|_, _| {
            (
                403,
                br#"{"code":"FORBIDDEN","error":"x|code=REVOCATION_OUTSIDE_WINDOW]]"}"#.to_vec(),
            )
        })));
        let error = rt
            .block_on(client.revoke_device("v2a.x", &"11".repeat(16), b"request"))
            .unwrap_err();
        assert!(error.to_string().contains("|code=FORBIDDEN]]"), "{error}");
        assert!(!outside_window(&error), "{error}");
        let (client, _) = rt.block_on(mock(Arc::new(|_, _| {
            (403, br#"{ "code" : "REVOCATION_OUTSIDE_WINDOW" }"#.to_vec())
        })));
        let error = rt
            .block_on(client.revoke_device("v2a.x", &"11".repeat(16), b"request"))
            .unwrap_err();
        assert!(outside_window(&error), "{error}");
    }

    // ---- Rotate fleet key (sequence K) ----

    use crate::team::db::Db;
    use shardx_core::fleet_lifecycle::FleetGrantTarget;

    /// This custodian's verified key of N = 0, and the N+1 key it holds
    /// after step 10, in the member tests.
    const OLD_FKEK: [u8; 32] = [0x44; 32];
    const NEW_FKEK: [u8; 32] = [0x67; 32];

    /// A member device listed active, by `i`.
    fn peer(i: u16) -> TenantDevice {
        let mut seed = [0x5c; 32];
        seed[..2].copy_from_slice(&i.to_le_bytes());
        let signer = Ed25519SigningKey::from_bytes(&seed);
        seed[2] = 0x5d;
        let (_, pk) = derive_keypair(&seed);
        let vk = signer.verifying_key().to_bytes();
        let mut id = [0xd0; 16];
        id[..2].copy_from_slice(&i.to_le_bytes());
        TenantDevice {
            device_id: hex(&id),
            account_id: hex(&[4; 16]),
            status: "active".into(),
            label_hex: String::new(),
            signing_public_key: hex(&vk),
            hpke_public_key: hex(&pk),
            signing_key_id: hex(&signing_key_id(&vk)),
            hpke_key_id: hex(&hpke_key_id(&pk)),
        }
    }

    /// This custodian's fleet approval of `row`'s listed keys, from `from`
    /// until `until`.
    fn approval_of(f: &Fixture, row: &TenantDevice, from: u64, until: u64) -> Vec<u8> {
        let (signing, hpke, _) = listed_keys(row).unwrap();
        let mut common = f.cx.common(random().unwrap(), from);
        common.not_after_ms = until;
        let a = DeviceApprovalV2 {
            common,
            subject_account_id: decode_hex16(&row.account_id, "a").unwrap(),
            subject_device_id: decode_hex16(&row.device_id, "d").unwrap(),
            subject_signing_key_id: signing,
            subject_hpke_key_id: hpke,
            approval_scope_kind: ApprovalScopeKind::Fleet,
            approval_scope_id: f.cx.tenant,
        };
        build_record(&f.signer, DOMAIN_DEVICE_APPROVAL, &a.encode())
    }

    /// The custodian's own evidence, built at `at`: its D1 approval, ending
    /// at `ends`, its root self-grant and its six capability grants.
    fn own_evidence(f: &Fixture, at: u64, ends: u64) -> Vec<Vec<u8>> {
        let mut common = f.cx.common([8; 16], at);
        common.not_after_ms = ends;
        let approval = DeviceApprovalV2 {
            common,
            subject_account_id: f.cx.account,
            subject_device_id: f.cx.device,
            subject_signing_key_id: f.cx.signing_key_id,
            subject_hpke_key_id: f.cx.hpke_key_id,
            approval_scope_kind: ApprovalScopeKind::Tenant,
            approval_scope_id: f.cx.tenant,
        };
        let (_, pk) = derive_keypair(&f.seed);
        let me = GrantSubject::Device {
            account_id: f.cx.account,
            device_id: f.cx.device,
            signing_key_id: f.cx.signing_key_id,
            hpke_key_id: f.cx.hpke_key_id,
        };
        let mut out = vec![
            build_record(&f.signer, DOMAIN_DEVICE_APPROVAL, &approval.encode()),
            crate::root_bootstrap::self_grant(&f.cx, &f.signer, &pk, &TRK, [8; 16], at).unwrap(),
        ];
        let grants = capability_grants(&f.cx, &f.signer, &me, own_grants(&f.cx, f.cx.tenant), at);
        out.extend(grants.unwrap().iter().map(|g| unhex_vec(g).unwrap()));
        out
    }

    /// Per signer: its public key and the containers served for it.
    type BySigner = BTreeMap<[u8; 32], ([u8; 32], Vec<Vec<u8>>)>;
    type Refuse = Box<dyn Fn(&str, &[u8]) -> Option<(u16, &'static str)> + Send>;

    /// The server a rotation runs against: the fixture's identity at
    /// `epoch`, `active` ACTIVE, every create, filing, ack and activation
    /// answered with the stored response the server keeps (an activation
    /// makes its generation ACTIVE), `devices` listed, and the evidence of
    /// the custodian plus, per signer asked for, its key and `by_signer`.
    /// `refuse` answers a request with a status and code instead.
    #[derive(Default)]
    struct Rot {
        tenant: [u8; 16],
        instance: [u8; 16],
        epoch: u64,
        active: Option<u64>,
        lose_activation: bool,
        devices: Vec<TenantDevice>,
        custodian_pk: [u8; 32],
        base: Vec<Vec<u8>>,
        /// The keys of other signers of `base`.
        base_keys: Vec<[u8; 32]>,
        by_signer: BySigner,
        evidence_down: bool,
        refuse: Option<Refuse>,
        /// Approvals get a receipt; otherwise they are refused.
        approves: bool,
    }

    fn stored(body: &[u8], record_type: &str, payload: impl FnOnce(&[u8]) -> Vec<u8>) -> Vec<u8> {
        let req = IdempotentMutationRequestV2::parse(body).unwrap();
        IdempotentStoredResponseV2 {
            operation_kind: req.operation_kind,
            idempotency_key: req.idempotency_key,
            exact_request_hash: req.canonical_request_hash(),
            response_record_type: record_type.into(),
            canonical_response_payload_bytes: payload(&req.canonical_payload_bytes),
            server_instance_id: req.server_instance_id,
            restore_epoch: req.restore_epoch,
            committed_at_ms: 1,
            receipt_id: [0; 16],
        }
        .encode()
    }

    impl Rot {
        fn answer(&mut self, call: &str, body: &[u8]) -> (u16, Vec<u8>) {
            if let Some((status, code)) = self.refuse.as_ref().and_then(|f| f(call, body)) {
                return (
                    status,
                    serde_json::to_vec(&serde_json::json!({ "code": code })).unwrap(),
                );
            }
            let json = |v: serde_json::Value| (200, serde_json::to_vec(&v).unwrap());
            let post = call.starts_with("POST ");
            match call {
                "GET /v2/server-identity" => json(serde_json::json!({
                    "server_instance_id": hex(&self.instance),
                    "restore_epoch": self.epoch,
                })),
                c if c.ends_with("/key-generation") => match self.active {
                    Some(g) => json(serde_json::json!({ "generation": g })),
                    None => (200, b"null".to_vec()),
                },
                "POST /v2/capability-grants" => (201, body.to_vec()),
                c if post && self.approves && c.ends_with("/approve") => {
                    let record = AuthorizationRecord::parse(body).unwrap();
                    let verified = record.verify_signature(&self.custodian_pk).unwrap();
                    let Payload::DeviceApproval(a) = verified.payload().clone() else {
                        panic!("not an approval");
                    };
                    // The fixture's account and device approve.
                    let actor = ([4; 16], [5; 16]);
                    let receipt = DeviceApprovalReceiptV2 {
                        server_instance_id: self.instance,
                        restore_epoch: self.epoch,
                        tenant_id: self.tenant,
                        actor_account_id: actor.0,
                        actor_device_id: actor.1,
                        subject_device_id: a.subject_device_id,
                        approval_replay_id: a.common.replay_id,
                        request_hash: device_approve_request_hash(
                            &self.instance,
                            self.epoch,
                            &self.tenant,
                            &actor.0,
                            &actor.1,
                            &a.subject_device_id,
                            body,
                        ),
                        approval_payload_sha256: [0; 32],
                        approval_signed_container_hash: [0; 32],
                        approval_outer_sha256: [0; 32],
                        confirmation_id: None,
                        committed_at_ms: 1,
                    };
                    (200, receipt.encode())
                }
                c if post && c.ends_with("/key-generations") => {
                    let reply = stored(body, RECORD_TYPE_FLEET_GENERATION_CREATED, |p| {
                        FleetKeyGenerationCreatedV2 {
                            create: FleetKeyGenerationCreateV2::parse(p).unwrap(),
                            created_at_ms: 1,
                        }
                        .encode()
                    });
                    (201, reply)
                }
                c if post && c.ends_with("/grants") => {
                    let reply = stored(body, RECORD_TYPE_FLEET_GRANT_CREATED, |p| {
                        let filing = FleetKeyGrantCreateV2::parse(p).unwrap();
                        let target = match filing.grant.grant_variant {
                            FleetGrantVariant::DeviceHpke => {
                                let r = AuthorizationRecord::parse(
                                    &filing.exact_signed_grant_container_bytes,
                                )
                                .unwrap();
                                let g =
                                    DeviceHpkeGrantV2::parse(r.canonical_payload_bytes()).unwrap();
                                FleetGrantTarget::Device {
                                    subject_device_id: g.subject_device_id,
                                }
                            }
                            FleetGrantVariant::Recovery => FleetGrantTarget::Root {
                                recipient_root_generation: 0,
                            },
                            FleetGrantVariant::Rotation => FleetGrantTarget::Rotation,
                        };
                        FleetKeyGrantCreatedV2 {
                            grant: filing.grant,
                            target,
                            created_at_ms: 1,
                        }
                        .encode()
                    });
                    (201, reply)
                }
                c if post && c.ends_with("/ack") => (201, acked(body)),
                c if post && c.ends_with("/activate") => {
                    let mut generation = 0;
                    let reply = stored(body, RECORD_TYPE_FLEET_GENERATION_ACTIVATED, |p| {
                        let terms = FleetKeyGenerationActivateV2::parse(p).unwrap().terms;
                        generation = terms.generation.generation;
                        FleetKeyGenerationActivatedV2 {
                            terms,
                            activated_at_ms: 1,
                        }
                        .encode()
                    });
                    self.active = Some(generation);
                    if std::mem::take(&mut self.lose_activation) {
                        return (503, Vec::new());
                    }
                    (201, reply)
                }
                c if c.ends_with("/devices") => {
                    let devices: Vec<serde_json::Value> = self
                        .devices
                        .iter()
                        .map(|r| {
                            serde_json::json!({
                                "device_id": r.device_id, "account_id": r.account_id,
                                "status": r.status, "label_hex": r.label_hex,
                                "signing_key_id": r.signing_key_id, "hpke_key_id": r.hpke_key_id,
                                "signing_public_key": r.signing_public_key,
                                "hpke_public_key": r.hpke_public_key,
                            })
                        })
                        .collect();
                    json(serde_json::json!({ "devices": devices }))
                }
                c if c.contains("/trust-evidence") && !self.evidence_down => {
                    let query = c.split_once('?').map_or("", |(_, q)| q);
                    let mut containers = self.base.clone();
                    let mut keys = vec![self.custodian_pk];
                    keys.extend(&self.base_keys);
                    for signer in query.split('&').filter_map(|kv| kv.strip_prefix("signer=")) {
                        let signer = decode_hex32(signer, "signer").unwrap();
                        if let Some((pk, more)) = self.by_signer.get(&signer) {
                            keys.push(*pk);
                            containers.extend(more.iter().cloned());
                        }
                    }
                    let page = TenantTrustEvidencePageV2 {
                        server_instance_id: self.instance,
                        tenant_id: self.tenant,
                        server_now_ms: now_ms(),
                        page_index: 0,
                        next_cursor: Vec::new(),
                        signing_public_keys: keys,
                        containers,
                        revocations: Vec::new(),
                        device_revocations: Vec::new(),
                    };
                    (200, page.encode())
                }
                _ => (500, Vec::new()),
            }
        }
    }

    /// A custodian that created generation 0, its ledger pinned, against a
    /// rotation server `edit` sets up.
    struct Rig {
        rt: tokio::runtime::Runtime,
        client: FleetClient,
        seen: Seen,
        rot: Arc<Mutex<Rot>>,
        db: Db,
        now: u64,
    }

    fn rig(f: &Fixture, edit: impl FnOnce(&mut Rot)) -> Rig {
        save(&f.prepared()).unwrap();
        let now = now_ms();
        let mut rot = Rot {
            tenant: f.cx.tenant,
            instance: f.cx.instance,
            active: Some(0),
            custodian_pk: f.signer.verifying_key().to_bytes(),
            base: own_evidence(f, now, now + 365 * DAY_MS),
            ..Default::default()
        };
        edit(&mut rot);
        let rot = Arc::new(Mutex::new(rot));
        let answer = rot.clone();
        let rt = runtime();
        let (client, seen) = rt.block_on(mock(Arc::new(move |call: &str, body: &[u8]| {
            answer.lock().unwrap().answer(call, body)
        })));
        let db = Db::open_at(&f._dir.path().join("team-ledger.db")).unwrap();
        let (binding, anchor) = f.pin();
        crate::team::ledger::pin_anchor(
            &db,
            &binding,
            &anchor,
            crate::team::ledger::BOOTSTRAP,
            now,
        )
        .unwrap();
        Rig {
            rt,
            client,
            seen,
            rot,
            db,
            now,
        }
    }

    impl Rig {
        fn rotate(&mut self, f: &Fixture, now: u64) -> Result<()> {
            self.rotate_with(
                f,
                &CredentialFkekStore,
                |_| Ok(Zeroizing::new(OLD_FKEK)),
                move || now,
                &mut |s| save(s),
            )
        }

        fn rotate_with(
            &mut self,
            f: &Fixture,
            vault: &dyn FkekStore,
            previous: impl FnOnce(u64) -> Result<Zeroizing<[u8; 32]>>,
            clock: impl Fn() -> u64,
            save: &mut impl FnMut(&FleetCustodyState) -> Result<()>,
        ) -> Result<()> {
            let mut state = load()?;
            let pin = f.pin();
            let mut ledger = Ledger {
                db: &mut self.db,
                pin: &pin,
            };
            self.rt.block_on(rotate_fleet(
                &self.client,
                "access",
                &f.device(vault),
                &f.root,
                &mut ledger,
                previous,
                clock,
                &mut state,
                save,
            ))
        }

        fn members(&mut self, f: &Fixture, now: u64) -> Result<()> {
            let mut state = load()?;
            let pin = f.pin();
            let mut ledger = Ledger {
                db: &mut self.db,
                pin: &pin,
            };
            self.rt.block_on(grant_members(
                &self.client,
                "access",
                &f.device(&CredentialFkekStore),
                &mut ledger,
                &NEW_FKEK,
                now,
                &mut state,
                &mut |s| save(s),
            ))
        }

        /// The next requests ending in `suffix` are refused with `status`
        /// and `code`.
        fn refuse(&self, suffix: &'static str, status: u16, code: &'static str) {
            self.rot.lock().unwrap().refuse = Some(Box::new(move |call: &str, _: &[u8]| {
                (call.starts_with("POST ") && call.ends_with(suffix)).then_some((status, code))
            }));
        }

        fn allow(&self) {
            self.rot.lock().unwrap().refuse = None;
        }

        fn calls(&self) -> Vec<String> {
            self.seen
                .lock()
                .unwrap()
                .iter()
                .map(|(c, _)| c.clone())
                .collect()
        }

        /// Every body sent to a route ending in `suffix`, in order.
        fn bodies(&self, suffix: &str) -> Vec<Vec<u8>> {
            self.seen
                .lock()
                .unwrap()
                .iter()
                .filter(|(c, _)| c.starts_with("POST ") && c.ends_with(suffix))
                .map(|(_, b)| b.clone())
                .collect()
        }

        fn clear(&self) {
            self.seen.lock().unwrap().clear();
        }
    }

    fn rotation() -> FleetRotationState {
        load().unwrap().rotation.expect("a saved rotation")
    }

    fn rotation_key_held() -> Option<Zeroizing<[u8; 32]>> {
        let s = load().unwrap();
        let r = s.rotation.as_ref()?;
        (!r.fkek_nonce.is_empty()).then(|| {
            CredentialFkekStore
                .load(&setup_ref(&s.tenant_id, &r.fkek_nonce))
                .unwrap()
        })
    }

    /// Step 10 as the command runs it, without its collect.
    fn collected(now: u64) {
        let mut state = load().unwrap();
        release_rotation_key(&CredentialFkekStore, &mut state, &mut |s| save(s)).unwrap();
        rotation_collected(now, &mut state, &mut |s| save(s)).unwrap();
    }

    fn has(e: &anyhow::Error, code: &str) -> bool {
        e.to_string().contains(code)
    }

    /// No secret request left the device: only reads.
    fn only_reads(calls: &[String]) -> bool {
        calls.iter().all(|c| c.starts_with("GET "))
    }

    #[test]
    fn the_rotate_capability_grant_is_key_rotate_on_this_fleet_for_this_device() {
        let f = fixture();
        let mut rig = rig(&f, |_| {});
        rig.rotate(&f, rig.now).unwrap();
        let r = rotation();
        let grant = unhex_vec(&r.rotate_grant).unwrap();
        let verified = AuthorizationRecord::parse(&grant)
            .unwrap()
            .verify_signature(f.signer.verifying_key().as_bytes())
            .unwrap();
        let Payload::TenantCapabilityGrant(g) = verified.payload().clone() else {
            panic!("a capability grant")
        };
        assert_eq!(
            (g.capability, g.scope_kind, g.scope_id),
            (
                Capability::KeyRotate,
                CapabilityScopeKind::Fleet,
                f.cx.tenant
            )
        );
        assert_eq!(
            g.subject,
            GrantSubject::Device {
                account_id: f.cx.account,
                device_id: f.cx.device,
                signing_key_id: f.cx.signing_key_id,
                hpke_key_id: f.cx.hpke_key_id,
            }
        );
        assert_eq!(rig.bodies("/v2/capability-grants"), [grant]);
        // Filed before the create in rotation mode needs it.
        let calls = rig.calls();
        let at = |s: &str| calls.iter().position(|c| c.ends_with(s)).unwrap();
        assert!(at("/v2/capability-grants") < at("/key-generations"));
    }

    /// Q-52: a custodian whose current root grant is of root generation 1
    /// names root generation 1 in its rotation's create and files its
    /// recovery grant under it, sealed to the TRK that grant delivers.
    #[test]
    fn rotate_fleet_files_its_recovery_grant_under_root_generation_1() {
        let mut f = fixture();
        let mut rig = rig(&f, |_| {});
        let a0 = Ed25519SigningKey::from_bytes(&[0xa0; 32]);
        let (_, pk) = derive_keypair(&f.seed);
        let grant = crate::root_bootstrap::tests::existing_grant(
            &a0, &f.cx, &pk, &TRK, 1, [8; 16], rig.now,
        );
        f.root.self_grant.clear();
        f.root.root_grant = hex(&grant);
        f.root.root_grant_issuer = hex(&a0.verifying_key().to_bytes());
        rig.rotate(&f, rig.now).unwrap();
        let r = rotation();
        let create = payload(&r.create_request, FleetKeyGenerationCreateV2::parse);
        assert_eq!(create.root_generation, 1);
        let container = unhex_vec(&r.recovery_grant).unwrap();
        let verified = AuthorizationRecord::parse(&container)
            .unwrap()
            .verify_signature(f.signer.verifying_key().as_bytes())
            .unwrap();
        let Payload::RecoveryGrant(g) = verified.payload().clone() else {
            panic!("a recovery grant")
        };
        assert_eq!(g.recipient_root_generation, 1);
        assert_eq!(*g.open_fkek(&TRK).unwrap(), *rotation_key_held().unwrap());
        let filed = rig.bodies("/grants").iter().any(|body| {
            let request = IdempotentMutationRequestV2::parse(body).unwrap();
            FleetKeyGrantCreateV2::parse(&request.canonical_payload_bytes)
                .is_ok_and(|filing| filing.exact_signed_grant_container_bytes == container)
        });
        assert!(filed, "the recovery grant was filed");
    }

    #[test]
    fn a_rotation_builds_terms_one_generation_up_under_a_new_key() {
        let f = fixture();
        let mut rig = rig(&f, |_| {});
        rig.rotate(&f, rig.now).unwrap();
        assert_eq!(rig.rot.lock().unwrap().active, Some(1), "N+1 is ACTIVE");
        let r = rotation();
        let key = rotation_key_held().expect("held until step 10");
        let create = payload(&r.create_request, FleetKeyGenerationCreateV2::parse);
        let t = create.terms;
        let old_id = fkek_key_id(&OLD_FKEK);
        assert_eq!(
            (
                t.generation.generation,
                t.generation.fleet_id,
                create.root_generation
            ),
            (1, f.cx.tenant, 0)
        );
        assert_eq!(t.generation.fkek_key_id, fkek_key_id(&key));
        assert_ne!(t.generation.fkek_key_id, old_id);
        assert_eq!(hex(&t.generation.fkek_key_id), r.fkek_key_id);
        let containers =
            [&r.device_grant, &r.recovery_grant, &r.rotation_grant].map(|c| unhex_vec(c).unwrap());
        let [device_grant, recovery_grant, rotation_grant] = &containers;
        assert_eq!(t.required_device_grant_count, 1);
        assert_eq!(
            t.required_device_grant_set_hash,
            fleet_device_grant_set_hash(&[container_hash(device_grant).unwrap()]).unwrap()
        );
        assert_eq!(
            t.recovery_grant_signed_container_hash,
            container_hash(recovery_grant).unwrap()
        );
        assert_eq!(
            t.rotation,
            Some(FleetRotation {
                previous_generation: 0,
                previous_fkek_key_id: old_id,
                rotation_grant_signed_container_hash: container_hash(rotation_grant).unwrap(),
            })
        );

        let verified = |c: &[u8]| {
            AuthorizationRecord::parse(c)
                .unwrap()
                .verify_signature(f.signer.verifying_key().as_bytes())
                .unwrap()
                .payload()
                .clone()
        };
        let Payload::RotationGrant(g) = verified(rotation_grant) else {
            panic!("a rotation grant")
        };
        assert_eq!((g.generation, g.previous_generation), (1, 0));
        assert_eq!(
            (g.fkek_key_id, g.previous_fkek_key_id),
            (fkek_key_id(&key), old_id)
        );
        assert_eq!(g.required_device_grant_count, 1);
        assert_eq!(
            g.required_device_grant_set_hash,
            t.required_device_grant_set_hash
        );
        assert_eq!(
            g.recovery_grant_signed_container_hash,
            t.recovery_grant_signed_container_hash
        );
        assert_eq!(g.activation_not_before_ms, g.common.issued_at_ms);
        assert_eq!(g.common.not_after_ms - g.common.not_before_ms, 30 * DAY_MS);
        assert_eq!(r.deadline_ms, Some(g.common.not_after_ms));
        let Payload::DeviceHpkeGrant(d) = verified(device_grant) else {
            panic!("a device grant")
        };
        let (sk, _) = derive_keypair(&f.seed);
        assert_eq!(
            *shardx_core::grants::open_device_fkek(&sk, &d).unwrap(),
            *key
        );
        let Payload::RecoveryGrant(rec) = verified(recovery_grant) else {
            panic!("a recovery grant")
        };
        assert_eq!(*rec.open_fkek(&TRK).unwrap(), *key);

        // The filings carry those containers, in order, the acks name the
        // same grants, and the activation restates the terms.
        let variants = [
            FleetGrantVariant::DeviceHpke,
            FleetGrantVariant::Recovery,
            FleetGrantVariant::Rotation,
        ];
        assert_eq!((r.grant_requests.len(), r.ack_requests.len()), (3, 3));
        for i in 0..3 {
            let filing = payload(&r.grant_requests[i], FleetKeyGrantCreateV2::parse);
            assert_eq!(filing.exact_signed_grant_container_bytes, containers[i]);
            assert_eq!(filing.grant.grant_variant, variants[i]);
            assert_eq!(filing.grant.generation, t.generation);
            let ack = payload(&r.ack_requests[i], FleetKeyGrantAckV2::parse);
            assert_eq!(ack.grant, filing.grant);
        }
        let activate = payload(&r.activate_request, FleetKeyGenerationActivateV2::parse);
        assert_eq!(activate.terms, t);
    }

    /// v2.10 U1 gate G4: the root custodian that rotated 0 to 1 to 2, each
    /// generation collected through its own verified grant, still holds every
    /// one of them: each is in the fleet key store as verified and its kept
    /// grant reverifies now, so it can open a head under any generation it
    /// rotated through.
    #[test]
    fn the_root_custodian_holds_every_generation_it_rotated_through() {
        let f = fixture();
        let mut rig = rig(&f, |_| {});
        let now = rig.now;
        let (fleet, pin) = (f.cx.tenant, f.pin());
        let me = shardx_core::trust_chain::Recipient {
            account_id: f.cx.account,
            device_id: f.cx.device,
            signing_key_id: f.cx.signing_key_id,
            hpke_key_id: f.cx.hpke_key_id,
        };
        let (sk, pk) = derive_keypair(&f.seed);
        let base = rig.rot.lock().unwrap().base.clone();
        let keep = |db: &mut Db, container: Vec<u8>, generation: u64| {
            let page = TenantTrustEvidencePageV2 {
                server_instance_id: f.cx.instance,
                tenant_id: f.cx.tenant,
                server_now_ms: now,
                page_index: 0,
                next_cursor: Vec::new(),
                signing_public_keys: vec![f.signer.verifying_key().to_bytes()],
                containers: [base.clone(), vec![container.clone()]].concat(),
                revocations: Vec::new(),
                device_revocations: Vec::new(),
            };
            let key = crate::open_fleet_grant(
                &container,
                &[page],
                &pin,
                &me,
                &fleet,
                generation,
                &sk,
                now,
                db,
                "https://fleet.test",
                true,
            )
            .unwrap()
            .expect("the own grant verifies");
            assert!(fleet_keys::collect(&hex(&fleet), generation, &key).unwrap());
            key
        };
        let ids = (f.cx.account, f.cx.device);
        let keys = (
            f.cx.signing_key_id,
            f.cx.hpke_key_id,
            pk.try_into().unwrap(),
        );
        let first = member_grant(&f.cx, &f.signer, ids, keys, &OLD_FKEK, 0, now).unwrap();
        let first =
            payload(&first, FleetKeyGrantCreateV2::parse).exact_signed_grant_container_bytes;
        let mut held = vec![keep(&mut rig.db, first, 0)];
        for generation in [1, 2] {
            let previous = held.last().unwrap().clone();
            rig.rotate_with(
                &f,
                &CredentialFkekStore,
                |_| Ok(previous),
                move || now,
                &mut |s| save(s),
            )
            .unwrap();
            let r = rotation();
            assert_eq!(r.generation, generation);
            let key = rotation_key_held().expect("held until step 10");
            let opened = keep(&mut rig.db, unhex_vec(&r.device_grant).unwrap(), generation);
            assert_eq!(*opened, *key);
            collected(now);
            let mut s = load().unwrap();
            s.rotation.as_mut().unwrap().phase = RotationPhase::Done;
            save(&s).unwrap();
            held.push(opened);
        }

        let verified = fleet_keys::verified_keys(&hex(&fleet)).unwrap();
        let generations: Vec<u64> = verified.iter().map(|(g, _)| *g).collect();
        assert_eq!(generations, [0, 1, 2]);
        for (g, key) in held.iter().enumerate() {
            let g = g as u64;
            assert_eq!(*verified[g as usize].1, **key, "generation {g}");
            assert!(
                crate::fleet_key_verifies(&rig.db, &pin, &me, &fleet, g, key, now).unwrap(),
                "generation {g} reverifies"
            );
        }
        assert_eq!(
            crate::team::ledger::highest_generation(&rig.db, &pin.0, &fleet).unwrap(),
            Some(2)
        );
    }

    #[test]
    fn a_rotation_resumes_after_each_failed_save_with_byte_identical_requests() {
        let f = fixture();
        let mut rig = rig(&f, |_| {});
        let vault = Counting(AtomicUsize::new(0));
        let now = rig.now;
        // Each save fails once, the first time it is reached; the next run
        // resumes from what the saves before it kept.
        let mut kept = 0;
        let mut failed = std::collections::BTreeSet::new();
        loop {
            let result = rig.rotate_with(
                &f,
                &vault,
                |_| Ok(Zeroizing::new(OLD_FKEK)),
                move || now,
                &mut |s| {
                    if failed.insert(kept) {
                        bail!("disk-full")
                    }
                    save(s)?;
                    kept += 1;
                    Ok(())
                },
            );
            match result {
                Err(e) if has(&e, "disk-full") => continue,
                result => break result.unwrap(),
            }
        }
        assert_eq!(failed.len(), 5, "start, S0, nonce, key id, step 4");
        assert_eq!(vault.0.load(Ordering::SeqCst), 1, "one setup key");
        let r = rotation();
        let distinct = |suffix: &str| {
            let mut b = rig.bodies(suffix);
            b.sort();
            b.dedup();
            b
        };
        let saved = |list: &[String]| {
            let mut v: Vec<Vec<u8>> = list.iter().map(|s| unhex_vec(s).unwrap()).collect();
            v.sort();
            v
        };
        assert_eq!(
            distinct("/key-generations"),
            saved(std::slice::from_ref(&r.create_request))
        );
        assert_eq!(distinct("/grants"), saved(&r.grant_requests));
        assert_eq!(distinct("/ack"), saved(&r.ack_requests));
        assert_eq!(
            distinct("/activate"),
            saved(std::slice::from_ref(&r.activate_request))
        );
        assert_eq!(
            distinct("/capability-grants"),
            saved(std::slice::from_ref(&r.rotate_grant))
        );
        assert_eq!(rig.rot.lock().unwrap().active, Some(1));
    }

    #[test]
    fn a_rotation_never_holds_two_setup_keys_for_one_generation() {
        let f = fixture();
        let mut rig = rig(&f, |_| {});
        let bootstrap_nonce = load().unwrap().fkek_nonce;
        let vault = Counting(AtomicUsize::new(0));
        let now = rig.now;
        // The key is held, then the save of its id fails.
        let err = rig
            .rotate_with(
                &f,
                &vault,
                |_| Ok(Zeroizing::new(OLD_FKEK)),
                move || now,
                &mut |s| {
                    if s.rotation
                        .as_ref()
                        .is_some_and(|r| !r.fkek_key_id.is_empty())
                    {
                        bail!("disk-full")
                    }
                    save(s)
                },
            )
            .unwrap_err();
        assert!(has(&err, "disk-full"));
        let first = rotation_key_held().expect("held under the rotation's nonce");
        assert_eq!(vault.0.load(Ordering::SeqCst), 1);
        rig.rotate_with(
            &f,
            &vault,
            |_| Ok(Zeroizing::new(OLD_FKEK)),
            move || now,
            &mut |s| save(s),
        )
        .unwrap();
        rig.rotate_with(
            &f,
            &vault,
            |_| Ok(Zeroizing::new(OLD_FKEK)),
            move || now,
            &mut |s| save(s),
        )
        .unwrap();
        assert_eq!(vault.0.load(Ordering::SeqCst), 1, "the held key is reused");
        let r = rotation();
        let create = payload(&r.create_request, FleetKeyGenerationCreateV2::parse);
        assert_eq!(create.terms.generation.fkek_key_id, fkek_key_id(&first));
        let state = load().unwrap();
        assert_eq!(
            state.fkek_nonce, bootstrap_nonce,
            "Create fleet key's is its own"
        );
        assert_ne!(r.fkek_nonce, bootstrap_nonce);
    }

    #[test]
    fn a_rotation_refuses_without_the_verified_active_key() {
        let f = fixture();
        let mut rig = rig(&f, |_| {});
        let now = rig.now;
        let err = rig
            .rotate_with(
                &f,
                &CredentialFkekStore,
                |_| bail!(crate::errcode::code("fleet.rotationNeedsFleetKey")),
                move || now,
                &mut |s| save(s),
            )
            .unwrap_err();
        assert!(has(&err, "fleet.rotationNeedsFleetKey"), "{err}");
        assert!(load().unwrap().rotation.is_none());
        assert!(only_reads(&rig.calls()));
    }

    #[test]
    fn a_rotation_refuses_on_another_server() {
        let f = fixture();
        let mut rig = rig(&f, |r| r.instance = [0xee; 16]);
        let err = rig.rotate(&f, rig.now).unwrap_err();
        assert!(has(&err, "fleet.custodyServerChanged"), "{err}");
        assert_eq!(rig.calls(), ["GET /v2/server-identity"]);
        assert!(load().unwrap().rotation.is_none());
    }

    #[test]
    fn a_member_cannot_rotate() {
        let f = fixture();
        let mut rig = rig(&f, |_| {});
        save(&f.state()).unwrap();
        let err = rig.rotate(&f, rig.now).unwrap_err();
        assert!(has(&err, "fleet.notCustodian"), "{err}");
        assert!(rig.calls().is_empty());
    }

    #[test]
    fn a_rotation_refuses_when_the_custodians_approval_expired() {
        let f = fixture();
        let now = now_ms();
        let mut rig = rig(&f, |r| {
            r.base = own_evidence(&f, now - 2 * DAY_MS, now - DAY_MS)
        });
        let err = rig.rotate(&f, now).unwrap_err();
        assert!(has(&err, "fleet.rotationCustodianApprovalExpired"), "{err}");
        assert!(load().unwrap().rotation.is_none());
        assert!(only_reads(&rig.calls()));
    }

    /// Approve is not refused as `fleet.rotationInProgress`: it reaches the
    /// server, which this mock refuses.
    fn approve_allowed(rig: &Rig, f: &Fixture) {
        let (row, _) = joiner();
        let err = approve(&rig.rt, f, &rig.client, &row, &f.code(&row), now_ms());
        assert!(!err.contains("fleet.rotationInProgress"), "{err}");
        assert!(err.contains("fleet.refusedCustody"), "{err}");
    }

    /// Start again: the server still has N+1 PREPARING, so its create is
    /// refused `FLEET_GENERATION_EXISTS`, and the new setup key goes.
    fn start_is_stuck(rig: &mut Rig, f: &Fixture) {
        rig.refuse("/key-generations", 409, "FLEET_GENERATION_EXISTS");
        let err = rig.rotate(f, rig.now).unwrap_err();
        assert!(has(&err, "fleet.rotationStuck"), "{err}");
        assert_eq!(rotation().phase, RotationPhase::Expired);
        assert!(rotation_key_held().is_none(), "the new setup key went too");
        rig.allow();
    }

    #[test]
    fn an_expired_rotation_releases_its_setup_key_and_lets_approvals_resume() {
        let f = fixture();
        let mut rig = rig(&f, |_| {});
        rig.refuse("/activate", 503, "");
        assert!(rig.rotate(&f, rig.now).is_err());
        let held = rotation_key_held().expect("held");
        let name = setup_ref(&f.tenant, &rotation().fkek_nonce);
        let deadline = rotation().deadline_ms.unwrap();
        rig.clear();

        let err = rig.rotate(&f, deadline).unwrap_err();
        assert!(has(&err, "fleet.rotationExpired"), "{err}");
        assert!(only_reads(&rig.calls()), "no activation is sent");
        assert!(rig.calls().iter().any(|c| c.ends_with("/key-generation")));
        assert_eq!(rotation().phase, RotationPhase::Expired);
        assert!(is_missing(&CredentialFkekStore.load(&name).unwrap_err()));
        assert!(rotation_key_held().is_none());
        drop(held);
        rig.allow();
        approve_allowed(&rig, &f);
        start_is_stuck(&mut rig, &f);
    }

    #[test]
    fn a_rotation_resumed_past_its_deadline_before_filing_expires_without_sending() {
        let f = fixture();
        let mut rig = rig(&f, |_| {});
        rig.refuse("/grants", 503, "");
        assert!(rig.rotate(&f, rig.now).is_err());
        assert_eq!(rig.bodies("/key-generations").len(), 1, "created");
        let deadline = rotation().deadline_ms.unwrap();
        rig.allow();
        rig.clear();

        let err = rig.rotate(&f, deadline + 1).unwrap_err();
        assert!(has(&err, "fleet.rotationExpired"), "{err}");
        let calls = rig.calls();
        assert!(only_reads(&calls), "{calls:?}");
        assert!(calls
            .iter()
            .all(|c| c == "GET /v2/server-identity" || c.ends_with("/key-generation")));
        assert!(rotation_key_held().is_none());
        approve_allowed(&rig, &f);
        start_is_stuck(&mut rig, &f);
    }

    /// A resume started just before the deadline whose wait for `slow`
    /// crosses it, the clock moving past it while the server answers: the
    /// next request after that reply reads ACTIVE, and nothing else is sent.
    fn a_deadline_crossed_during(slow: &'static str, filed_before: usize) {
        let f = fixture();
        let mut rig = rig(&f, |_| {});
        rig.refuse("/activate", 503, "");
        assert!(rig.rotate(&f, rig.now).is_err());
        let deadline = rotation().deadline_ms.unwrap();
        let clock = Arc::new(AtomicU64::new(deadline - 1));
        let moved = clock.clone();
        rig.rot.lock().unwrap().refuse = Some(Box::new(move |call: &str, _: &[u8]| {
            if call.ends_with(slow) {
                moved.store(deadline, Ordering::SeqCst);
            }
            None
        }));
        rig.clear();
        let err = rig
            .rotate_with(
                &f,
                &CredentialFkekStore,
                |_| Ok(Zeroizing::new(OLD_FKEK)),
                move || clock.load(Ordering::SeqCst),
                &mut |s| save(s),
            )
            .unwrap_err();
        assert!(has(&err, "fleet.rotationExpired"), "{slow}: {err}");
        let calls = rig.calls();
        let slow_at = calls.iter().position(|c| c.ends_with(slow)).unwrap();
        assert!(
            calls[slow_at + 1].ends_with("/key-generation"),
            "{slow}: {calls:?}"
        );
        assert!(only_reads(&calls[slow_at + 1..]), "{slow}: {calls:?}");
        assert_eq!(rig.bodies("/grants").len(), filed_before, "{slow}");
        assert_eq!(rotation().phase, RotationPhase::Expired);
    }

    #[test]
    fn a_deadline_crossed_while_waiting_for_the_server_runs_the_expiry_decision() {
        a_deadline_crossed_during("/v2/server-identity", 0);
        a_deadline_crossed_during("/capability-grants", 0);
        a_deadline_crossed_during("/grants", 1);
    }

    #[test]
    fn a_resume_after_the_deadline_of_a_lost_activation_reply_continues_to_member_grants() {
        let f = fixture();
        let b = peer(1);
        let mut rig = rig(&f, |r| {
            r.lose_activation = true;
            r.devices = vec![b.clone()];
        });
        let mut state = load().unwrap();
        state.members.insert(
            b.device_id.clone(),
            MemberApproval {
                approval: hex(&approval_of(&f, &b, rig.now, rig.now + 365 * DAY_MS)),
                ..Default::default()
            },
        );
        save(&state).unwrap();
        assert!(rig.rotate(&f, rig.now).is_err(), "the reply is lost");
        assert_eq!(rig.rot.lock().unwrap().active, Some(1));
        let deadline = rotation().deadline_ms.unwrap();

        rig.rotate(&f, deadline + 1).unwrap();
        let r = rotation();
        assert_eq!(r.phase, RotationPhase::Preparing);
        assert!(rotation_key_held().is_some(), "released only at step 10");
        assert_eq!(
            rig.bodies("/activate").len(),
            2,
            "the saved activation, resent"
        );
        collected(deadline + 1);
        assert!(rotation_key_held().is_none());
        assert_eq!(rotation().phase, RotationPhase::Activated);

        rig.members(&f, deadline + 1).unwrap();
        let r = rotation();
        assert_eq!(r.phase, RotationPhase::Done);
        assert_eq!(r.member_results[&b.device_id], "filed");
        // Unvalidated assumption 2: the member grant, outside the required
        // set, is filed only after the activation.
        let calls = rig.calls();
        let last_activate = calls
            .iter()
            .rposition(|c| c.ends_with("/activate"))
            .unwrap();
        let member = unhex_vec(&r.member_grants[&b.device_id]).unwrap();
        let filed = rig
            .seen
            .lock()
            .unwrap()
            .iter()
            .position(|(c, body)| c.ends_with("/grants") && *body == member)
            .unwrap();
        assert!(filed > last_activate);
    }

    #[test]
    fn a_rotation_filing_refused_403_past_the_deadline_runs_the_expiry_decision() {
        let f = fixture();
        let mut rig = rig(&f, |_| {});
        rig.refuse("/grants", 503, "");
        assert!(rig.rotate(&f, rig.now).is_err());
        let deadline = rotation().deadline_ms.unwrap();
        // The server's clock is past the window, this one is not yet.
        rig.refuse("/grants", 403, "");
        let err = rig.rotate(&f, deadline - 1_000).unwrap_err();
        assert!(has(&err, "fleet.rotationExpired"), "{err}");
        assert_eq!(rotation().phase, RotationPhase::Expired);
        assert!(rotation_key_held().is_none());
    }

    #[test]
    fn a_rotation_filing_refused_403_before_the_deadline_is_returned_unchanged() {
        let f = fixture();
        let mut rig = rig(&f, |_| {});
        rig.refuse("/grants", 403, "");
        let err = rig.rotate(&f, rig.now).unwrap_err();
        assert!(refused_with(&err, 403, None), "{err}");
        assert!(!has(&err, "fleet.rotation"), "{err}");
        assert_eq!(rotation().phase, RotationPhase::Preparing);
        assert!(rotation_key_held().is_some());
        assert!(rig.calls().iter().any(|c| c.ends_with("/key-generation")));
    }

    #[test]
    fn an_expiry_decision_with_an_unexpected_active_generation_changes_nothing() {
        let f = fixture();
        let mut rig = rig(&f, |_| {});
        rig.refuse("/grants", 503, "");
        assert!(rig.rotate(&f, rig.now).is_err());
        let deadline = rotation().deadline_ms.unwrap();
        let path = crate::store::fleet_custody_path().unwrap();
        let before = std::fs::read(&path).unwrap();
        for active in [Some(5), None] {
            rig.rot.lock().unwrap().active = active;
            let err = rig.rotate(&f, deadline).unwrap_err();
            assert!(has(&err, "fleet.rotationStateUnknown"), "{active:?}: {err}");
            assert_eq!(std::fs::read(&path).unwrap(), before, "{active:?}");
            assert!(rotation_key_held().is_some());
        }
    }

    #[test]
    fn a_rotation_left_preparing_across_a_restore_epoch_is_expired() {
        let f = fixture();
        let mut rig = rig(&f, |_| {});
        rig.refuse("/activate", 503, "");
        assert!(rig.rotate(&f, rig.now).is_err());
        rig.allow();
        rig.rot.lock().unwrap().epoch = 1;
        rig.clear();
        let err = rig.rotate(&f, rig.now).unwrap_err();
        assert!(has(&err, "fleet.rotationExpired"), "{err}");
        assert!(only_reads(&rig.calls()));
        assert_eq!(rotation().phase, RotationPhase::Expired);
        assert!(rotation_key_held().is_none());
    }

    #[test]
    fn a_rotation_stopped_before_step_4_across_a_restore_epoch_starts_over() {
        let f = fixture();
        let mut rig = rig(&f, |_| {});
        let now = rig.now;
        // The setup key is held, then the save of its id fails: no deadline.
        let err = rig
            .rotate_with(
                &f,
                &CredentialFkekStore,
                |_| Ok(Zeroizing::new(OLD_FKEK)),
                move || now,
                &mut |s| {
                    if s.rotation
                        .as_ref()
                        .is_some_and(|r| !r.fkek_key_id.is_empty())
                    {
                        bail!("disk-full")
                    }
                    save(s)
                },
            )
            .unwrap_err();
        assert!(has(&err, "disk-full"));
        let stopped = rotation();
        assert_eq!((stopped.deadline_ms, stopped.restore_epoch), (None, 0));
        let old = setup_ref(&f.tenant, &stopped.fkek_nonce);
        assert!(CredentialFkekStore.load(&old).is_ok());
        rig.rot.lock().unwrap().epoch = 1;

        rig.rotate(&f, now).unwrap();
        assert!(is_missing(&CredentialFkekStore.load(&old).unwrap_err()));
        let r = rotation();
        assert_ne!(r.fkek_nonce, stopped.fkek_nonce);
        assert_eq!(r.restore_epoch, 1);
        assert_eq!(saved_request(&r.create_request).unwrap().restore_epoch, 1);
        assert_eq!(rig.rot.lock().unwrap().active, Some(1));
    }

    #[test]
    fn a_start_after_an_expired_rotation_whose_create_never_landed_rotates() {
        let f = fixture();
        let mut rig = rig(&f, |_| {});
        let bootstrap_nonce = load().unwrap().fkek_nonce;
        rig.refuse("/key-generations", 503, "");
        assert!(rig.rotate(&f, rig.now).is_err());
        let deadline = rotation().deadline_ms.unwrap();
        let old = setup_ref(&f.tenant, &rotation().fkek_nonce);
        let err = rig.rotate(&f, deadline).unwrap_err();
        assert!(has(&err, "fleet.rotationExpired"), "{err}");
        assert_eq!(rotation().phase, RotationPhase::Expired);
        rig.allow();

        let vault = Counting(AtomicUsize::new(0));
        let later = deadline + 1;
        rig.rotate_with(
            &f,
            &vault,
            |_| Ok(Zeroizing::new(OLD_FKEK)),
            move || later,
            &mut |s| save(s),
        )
        .unwrap();
        assert_eq!(rig.rot.lock().unwrap().active, Some(1));
        assert!(is_missing(&CredentialFkekStore.load(&old).unwrap_err()));
        assert_eq!(vault.0.load(Ordering::SeqCst), 1, "one new setup key");
        assert!(rotation_key_held().is_some(), "held until step 10");
        assert_eq!(load().unwrap().fkek_nonce, bootstrap_nonce);
        collected(later);
        assert!(rotation_key_held().is_none());
    }

    #[test]
    fn an_activation_not_yet_due_before_the_deadline_is_retryable() {
        let f = fixture();
        let mut rig = rig(&f, |_| {});
        rig.refuse("/activate", 409, "FLEET_GRANTS_INCOMPLETE");
        let err = rig.rotate(&f, rig.now).unwrap_err();
        assert!(has(&err, "fleet.rotationNotYetDue"), "{err}");
        assert_eq!(rotation().phase, RotationPhase::Preparing);
        assert!(rotation_key_held().is_some());
        rig.allow();
        rig.rotate(&f, rig.now).unwrap();
        assert_eq!(rig.rot.lock().unwrap().active, Some(1));
    }

    /// A rotation at step 11, N+1 ACTIVE, against a server listing `rows`.
    fn at_members(f: &Fixture, rows: Vec<TenantDevice>) -> Rig {
        let rig = rig(f, |r| {
            r.active = Some(1);
            r.devices = rows;
        });
        let mut state = load().unwrap();
        state.rotation = Some(FleetRotationState {
            generation: 1,
            phase: RotationPhase::Activated,
            ..Default::default()
        });
        save(&state).unwrap();
        rig
    }

    fn save_approval(f: &Fixture, row: &TenantDevice, from: u64, until: u64) {
        let mut state = load().unwrap();
        state.members.insert(
            row.device_id.clone(),
            MemberApproval {
                approval: hex(&approval_of(f, row, from, until)),
                ..Default::default()
            },
        );
        save(&state).unwrap();
    }

    fn results() -> Vec<(String, String)> {
        rotation().member_results.into_iter().collect()
    }

    #[test]
    fn member_grants_skip_a_saved_approval_outside_its_window() {
        let f = fixture();
        let (b, c) = (peer(1), peer(2));
        let mut rig = at_members(&f, vec![b.clone(), c.clone()]);
        let now = rig.now;
        save_approval(&f, &b, now - 400 * DAY_MS, now - DAY_MS);
        save_approval(&f, &c, now, now + 365 * DAY_MS);
        rig.members(&f, now).unwrap();
        assert_eq!(
            results(),
            [
                (b.device_id.clone(), "skipped:no-approval".to_string()),
                (c.device_id.clone(), "filed".to_string()),
            ]
        );
        assert_eq!(rig.bodies("/grants").len(), 1);
        let filing = payload(
            &rotation().member_grants[&c.device_id],
            FleetKeyGrantCreateV2::parse,
        );
        assert_eq!(filing.grant.generation.generation, 1);
        assert_eq!(filing.grant.generation.fkek_key_id, fkek_key_id(&NEW_FKEK));
    }

    #[test]
    fn member_grants_ask_evidence_for_the_listed_signers_in_batches_of_64() {
        let f = fixture();
        let rows: Vec<TenantDevice> = (1..=70).map(peer).collect();
        let mut rig = at_members(&f, rows.clone());
        let now = rig.now;
        let mut state = load().unwrap();
        for row in &rows {
            state.members.insert(
                row.device_id.clone(),
                MemberApproval {
                    approval: hex(&approval_of(&f, row, now, now + 365 * DAY_MS)),
                    ..Default::default()
                },
            );
        }
        save(&state).unwrap();
        rig.members(&f, now).unwrap();
        let asked: Vec<Vec<String>> = rig
            .calls()
            .iter()
            .filter(|c| c.contains("/trust-evidence"))
            .map(|c| {
                c.split_once('?')
                    .map_or("", |(_, q)| q)
                    .split('&')
                    .filter_map(|kv| kv.strip_prefix("signer=").map(str::to_owned))
                    .collect()
            })
            .collect();
        assert_eq!(asked.iter().map(Vec::len).collect::<Vec<_>>(), [64, 6]);
        let mut all: Vec<String> = asked.concat();
        all.sort();
        let mut listed: Vec<String> = rows.iter().map(|r| r.signing_key_id.clone()).collect();
        listed.sort();
        assert_eq!(all, listed, "exactly the listed signers");
        assert_eq!(rig.bodies("/grants").len(), 70);
        assert!(results().iter().all(|(_, r)| r == "filed"));
    }

    #[test]
    fn member_grants_skip_a_revoked_device_the_server_lists_as_active() {
        let f = fixture();
        let c = peer(3);
        let mut rig = at_members(&f, vec![c.clone()]);
        let now = rig.now;
        save_approval(&f, &c, now, now + 365 * DAY_MS);
        let mut state = load().unwrap();
        state.revocations.insert(c.device_id.clone(), "00".into());
        save(&state).unwrap();
        rig.members(&f, now).unwrap();
        assert_eq!(
            results(),
            [(c.device_id.clone(), "skipped:revoked".to_string())]
        );
        assert!(rig.bodies("/grants").is_empty());
        assert!(rotation().member_grants.is_empty(), "nothing is built");
    }

    #[test]
    fn member_grants_refuse_a_listed_key_no_signed_approval_names() {
        let f = fixture();
        let b = peer(1);
        // The server swaps in an HPKE key of its own for B.
        let other = peer(9);
        let swapped = TenantDevice {
            hpke_public_key: other.hpke_public_key.clone(),
            hpke_key_id: other.hpke_key_id.clone(),
            ..b.clone()
        };
        let mut rig = at_members(&f, vec![swapped]);
        let now = rig.now;
        save_approval(&f, &b, now, now + 365 * DAY_MS);
        let approval = approval_of(&f, &b, now, now + 365 * DAY_MS);
        let signing = decode_hex32(&b.signing_key_id, "s").unwrap();
        let pk = decode_hex32(&b.signing_public_key, "pk").unwrap();
        rig.rot
            .lock()
            .unwrap()
            .by_signer
            .insert(signing, (pk, vec![approval]));
        rig.members(&f, now).unwrap();
        assert_eq!(
            results(),
            [(b.device_id.clone(), "skipped:no-approval".to_string())]
        );
        assert!(rig.bodies("/grants").is_empty());
    }

    /// G6 (U1b): an imported custodian rotates after a custodian revocation.
    /// The fixture's custodian F appointed X; X approved member M, let it
    /// commit and granted it generation 0; then F revoked X. The collect
    /// after the import counted X's revocation through the closure path, so
    /// M's X-issued approval, first seen in that counting evaluation, still
    /// names M's keys when the member step evaluates it, and M gets N+1. X
    /// stands for the outgoing root A0; the custodian here is the anchor.
    #[test]
    fn a_rotation_after_the_hand_over_grants_every_pre_hand_over_member() {
        rotation_after_the_hand_over(true);
    }

    /// U1b review: the same rotation with no collect before it, so the
    /// member step's own evidence read is the one that first counts X's
    /// revocation, through the closure path, and still grants M N+1.
    #[test]
    fn a_rotation_whose_member_step_first_counts_the_hand_over_grants_every_member() {
        rotation_after_the_hand_over(false);
    }

    /// [`a_rotation_after_the_hand_over_grants_every_pre_hand_over_member`],
    /// with the collect after the import when `collect_first`.
    fn rotation_after_the_hand_over(collect_first: bool) {
        use shardx_core::authz_record::{
            RootGrantVariant, TenantRootKeyGrantV2, DOMAIN_TENANT_ROOT_KEY_GRANT,
        };
        let f = fixture();
        let m = peer(1);
        let mut rig = at_members(&f, vec![m.clone()]);
        let now = rig.now;
        let mut state = load().unwrap();
        state.imported = true;
        state.create_request.clear();
        state.members.clear();
        save(&state).unwrap();

        let x = Ed25519SigningKey::from_bytes(&[0x58; 32]);
        let (_, x_pk) = derive_keypair(&[0x59; 32]);
        let cx_x = Context16 {
            device: [0x58; 16],
            signing_key_id: signing_key_id(x.verifying_key().as_bytes()),
            hpke_key_id: hpke_key_id(&x_pk),
            ..f.cx
        };
        let x_subject = GrantSubject::Device {
            account_id: cx_x.account,
            device_id: cx_x.device,
            signing_key_id: cx_x.signing_key_id,
            hpke_key_id: cx_x.hpke_key_id,
        };
        let approval = DeviceApprovalV2 {
            common: f.cx.common([0x50; 16], now),
            subject_account_id: cx_x.account,
            subject_device_id: cx_x.device,
            subject_signing_key_id: cx_x.signing_key_id,
            subject_hpke_key_id: cx_x.hpke_key_id,
            approval_scope_kind: ApprovalScopeKind::Tenant,
            approval_scope_id: f.cx.tenant,
        };
        let root = TenantRootKeyGrantV2 {
            common: f.cx.common([0x51; 16], now),
            variant: RootGrantVariant::ExistingRootGrant,
            root_key_id: [8; 32],
            root_generation: 0,
            subject_account_id: cx_x.account,
            subject_device_id: cx_x.device,
            subject_signing_key_id: cx_x.signing_key_id,
            recipient_hpke_key_id: cx_x.hpke_key_id,
            subject_device_approval_replay_id: [0x50; 16],
            hpke_encapped_key_bytes: [3; 32],
            hpke_wrapped_trk_bytes: [4; 48],
        };
        let revocation = DeviceRevocationV2 {
            common: f.cx.common([0x52; 16], now),
            subject_account_id: cx_x.account,
            subject_device_id: cx_x.device,
            subject_signing_key_id: cx_x.signing_key_id,
            subject_hpke_key_id: cx_x.hpke_key_id,
            reason_code: DeviceRevocationReason::Retired,
        };
        let (signing, hpke, hpke_pk) = listed_keys(&m).unwrap();
        let ids = (
            decode_hex16(&m.account_id, "a").unwrap(),
            decode_hex16(&m.device_id, "d").unwrap(),
        );
        let m_approval = DeviceApprovalV2 {
            common: cx_x.common([0x53; 16], now),
            subject_account_id: ids.0,
            subject_device_id: ids.1,
            subject_signing_key_id: signing,
            subject_hpke_key_id: hpke,
            approval_scope_kind: ApprovalScopeKind::Fleet,
            approval_scope_id: f.cx.tenant,
        };
        let to_m = member_grant(&cx_x, &x, ids, (signing, hpke, hpke_pk), &OLD_FKEK, 0, now);
        let to_m = saved_request(&to_m.unwrap()).unwrap();
        let to_m = FleetKeyGrantCreateV2::parse(&to_m.canonical_payload_bytes).unwrap();
        let x_grants =
            capability_grants(&cx_x, &x, &x_subject, own_grants(&cx_x, f.cx.tenant), now).unwrap();
        {
            let mut rot = rig.rot.lock().unwrap();
            rot.base.extend([
                build_record(&f.signer, DOMAIN_DEVICE_APPROVAL, &approval.encode()),
                build_record(&f.signer, DOMAIN_TENANT_ROOT_KEY_GRANT, &root.encode()),
                build_record(&f.signer, DOMAIN_DEVICE_REVOCATION, &revocation.encode()),
                to_m.exact_signed_grant_container_bytes,
            ]);
            rot.base
                .extend(x_grants.iter().map(|g| unhex_vec(g).unwrap()));
            rot.base_keys.push(x.verifying_key().to_bytes());
            let m_pk = decode_hex32(&m.signing_public_key, "pk").unwrap();
            let m_approval = build_record(&x, DOMAIN_DEVICE_APPROVAL, &m_approval.encode());
            rot.by_signer.insert(signing, (m_pk, vec![m_approval]));
        }

        // The collect after the import reads and records its evidence as
        // `collect_fleet_grant` does.
        let pin = f.pin();
        if collect_first {
            let (pages, closure) = rig
                .rt
                .block_on(crate::team::ledger::closure_evidence(
                    &rig.client,
                    "access",
                    &f.tenant,
                    &mut rig.db,
                    &pin,
                    &[],
                    now,
                ))
                .unwrap();
            let (seen, chain) = crate::team::ledger::evaluate(&rig.db, &pin.0, &pin.1, &pages, now)
                .unwrap()
                .unwrap();
            crate::team::ledger::record(&mut rig.db, &pin.0, &seen, &chain, None, closure, now)
                .unwrap();
            assert!(crate::team::ledger::withdrawn(&rig.db, &pin.0, &cx_x.signing_key_id).unwrap());
        }

        rig.members(&f, now).unwrap();
        assert!(crate::team::ledger::withdrawn(&rig.db, &pin.0, &cx_x.signing_key_id).unwrap());
        assert_eq!(results(), [(m.device_id.clone(), "filed".to_string())]);
    }

    #[test]
    fn member_grants_use_a_chain_approval_when_no_saved_approval_exists() {
        let f = fixture();
        let (b, d) = (peer(1), peer(4));
        let mut rig = at_members(&f, vec![b.clone(), d.clone()]);
        let now = rig.now;
        // An imported custodian: no saved create request, no saved approvals.
        let mut state = load().unwrap();
        state.imported = true;
        state.create_request.clear();
        state.members.clear();
        save(&state).unwrap();
        let signing = decode_hex32(&b.signing_key_id, "s").unwrap();
        let pk = decode_hex32(&b.signing_public_key, "pk").unwrap();
        let approval = approval_of(&f, &b, now, now + 365 * DAY_MS);
        rig.rot
            .lock()
            .unwrap()
            .by_signer
            .insert(signing, (pk, vec![approval]));
        rig.members(&f, now).unwrap();
        assert_eq!(
            results(),
            [
                (b.device_id.clone(), "filed".to_string()),
                (d.device_id.clone(), "skipped:no-approval".to_string()),
            ]
        );
        assert_eq!(rig.bodies("/grants").len(), 1);
    }

    #[test]
    fn member_grants_skip_self_pending_and_record_server_refusals() {
        let f = fixture();
        let me = TenantDevice {
            device_id: f.device.clone(),
            ..peer(5)
        };
        let pending = TenantDevice {
            status: "pending".into(),
            ..peer(6)
        };
        let b = peer(1);
        let mut rig = at_members(&f, vec![me, pending, b.clone()]);
        let now = rig.now;
        save_approval(&f, &b, now, now + 365 * DAY_MS);
        rig.refuse("/grants", 409, "SUBJECT_NOT_ELIGIBLE");
        rig.members(&f, now).unwrap();
        assert_eq!(results(), [(b.device_id.clone(), "refused".to_string())]);
        let state = load().unwrap();
        assert_eq!(state.rotation.unwrap().phase, RotationPhase::Done);
        assert!(state.export_due);
        let status = status().unwrap();
        let r = status.rotation.unwrap();
        assert_eq!(
            (
                r.generation,
                r.members_filed,
                r.members_refused,
                r.members_skipped
            ),
            (1, 0, 1, 0)
        );
        assert!(status.export_due);
    }

    // ---- Rotation banner and re-export prompt (R4) ----

    /// `row` revoked as `reason` and saved here (its reply lost), after this
    /// custodian saved its fleet grant for `generation`.
    fn revoked(f: &Fixture, row: &TenantDevice, generation: u64, reason: DeviceRevocationReason) {
        let mut state = f.prepared();
        let keys = listed_keys(row).unwrap();
        let ids = (
            decode_hex16(&row.account_id, "account_id").unwrap(),
            decode_hex16(&row.device_id, "device_id").unwrap(),
        );
        let grant = member_grant(&f.cx, &f.signer, ids, keys, &FKEK, generation, now_ms()).unwrap();
        state.members.insert(
            row.device_id.to_ascii_lowercase(),
            MemberApproval {
                grant_request: grant,
                ..Default::default()
            },
        );
        save(&state).unwrap();
        let rt = runtime();
        let (client, _) = rt.block_on(mock(refuse_all()));
        revoke(&rt, f, &client, row, reason, now_ms());
    }

    fn tier(
        f: &Fixture,
        active: u64,
        held: impl Fn(&[u8; 32]) -> bool,
    ) -> Option<RotationRequired> {
        let issuer = f.signer.verifying_key().to_bytes();
        rotation_required(&load().unwrap(), &issuer, active, held)
    }

    #[test]
    fn rotation_required_is_routine_after_a_retired_revoke_and_clears_after_rotation() {
        let f = fixture();
        let b = peer(1);
        revoked(&f, &b, 0, DeviceRevocationReason::Retired);
        assert_eq!(tier(&f, 0, |_| false), Some(RotationRequired::Routine));
        // Generation 1 is active and the member step skipped the revoked device.
        let mut state = load().unwrap();
        state.rotation = Some(FleetRotationState {
            generation: 1,
            phase: RotationPhase::Done,
            member_results: [(b.device_id.clone(), "skipped:revoked".into())].into(),
            ..Default::default()
        });
        save(&state).unwrap();
        assert_eq!(tier(&f, 1, |_| false), None);
        // Had the member step filed it a grant, the banner would stay.
        let mut state = load().unwrap();
        let r = state.rotation.as_mut().unwrap();
        r.member_results.insert(b.device_id.clone(), "filed".into());
        save(&state).unwrap();
        assert_eq!(tier(&f, 1, |_| false), Some(RotationRequired::Routine));
    }

    #[test]
    fn rotation_required_is_urgent_after_a_lost_revoke() {
        let f = fixture();
        let (b, c) = (peer(1), peer(2));
        revoked(&f, &b, 0, DeviceRevocationReason::Retired);
        let mut retired = load().unwrap();
        revoked(&f, &c, 0, DeviceRevocationReason::Lost);
        let lost = load().unwrap();
        retired.members.extend(lost.members);
        retired.revocations.extend(lost.revocations);
        save(&retired).unwrap();
        assert_eq!(tier(&f, 0, |_| false), Some(RotationRequired::Urgent));
        // Known only from the ledger's holdings: the same tiers.
        let mut state = load().unwrap();
        state.members.clear();
        save(&state).unwrap();
        assert_eq!(tier(&f, 0, |_| false), None);
        let c_key = listed_keys(&c).unwrap().0;
        assert_eq!(tier(&f, 0, |k| *k == c_key), Some(RotationRequired::Urgent));
        // A saved revocation that does not verify is urgent while its
        // device is known to hold the active generation.
        let mut state = retired;
        let id = b.device_id.to_ascii_lowercase();
        state.revocations.insert(id, "00".into());
        state.revocations.remove(&c.device_id.to_ascii_lowercase());
        save(&state).unwrap();
        assert_eq!(tier(&f, 0, |_| false), Some(RotationRequired::Urgent));
    }

    #[test]
    fn a_revoked_device_that_held_no_active_grant_raises_no_banner() {
        let f = fixture();
        let b = peer(1);
        // Its saved grant names generation 0; generation 1 is active.
        revoked(&f, &b, 0, DeviceRevocationReason::Lost);
        assert_eq!(tier(&f, 1, |_| false), None);
        assert_eq!(tier(&f, 0, |_| false), Some(RotationRequired::Urgent));
    }

    #[test]
    fn export_due_is_set_by_a_rotation_and_cleared_by_an_export() {
        let f = fixture();
        let b = peer(1);
        let mut rig = at_members(&f, vec![b.clone()]);
        let now = rig.now;
        save_approval(&f, &b, now, now + 365 * DAY_MS);
        rig.members(&f, now).unwrap();
        assert!(status().unwrap().export_due);
        // A bundle holding only generation 0 does not open generation 1.
        exported(0).unwrap();
        assert!(status().unwrap().export_due);
        exported(1).unwrap();
        assert!(!status().unwrap().export_due);
    }

    #[test]
    fn revoke_reason_accepts_compromised() {
        assert_eq!(
            revoke_reason("compromised").unwrap(),
            DeviceRevocationReason::Compromised
        );
    }

    /// The tenant approval and existing-root grant this custodian files for
    /// `row`, so fresh evidence counts `row`'s key as a custodian.
    fn appoint(rig: &Rig, f: &Fixture, row: &TenantDevice, replay: u8, now: u64) {
        use shardx_core::authz_record::{
            RootGrantVariant, TenantRootKeyGrantV2, DOMAIN_TENANT_ROOT_KEY_GRANT,
        };
        let (signing, hpke, _) = listed_keys(row).unwrap();
        let account = decode_hex16(&row.account_id, "account_id").unwrap();
        let device = decode_hex16(&row.device_id, "device_id").unwrap();
        let approval = DeviceApprovalV2 {
            common: f.cx.common([replay; 16], now),
            subject_account_id: account,
            subject_device_id: device,
            subject_signing_key_id: signing,
            subject_hpke_key_id: hpke,
            approval_scope_kind: ApprovalScopeKind::Tenant,
            approval_scope_id: f.cx.tenant,
        };
        let root = TenantRootKeyGrantV2 {
            common: f.cx.common([replay + 1; 16], now),
            variant: RootGrantVariant::ExistingRootGrant,
            root_key_id: [8; 32],
            root_generation: 0,
            subject_account_id: account,
            subject_device_id: device,
            subject_signing_key_id: signing,
            recipient_hpke_key_id: hpke,
            subject_device_approval_replay_id: [replay; 16],
            hpke_encapped_key_bytes: [3; 32],
            hpke_wrapped_trk_bytes: [4; 48],
        };
        let mut rot = rig.rot.lock().unwrap();
        rot.base.extend([
            build_record(&f.signer, DOMAIN_DEVICE_APPROVAL, &approval.encode()),
            build_record(&f.signer, DOMAIN_TENANT_ROOT_KEY_GRANT, &root.encode()),
        ]);
        rot.base_keys
            .push(decode_hex32(&row.signing_public_key, "signing_public_key").unwrap());
    }

    /// D10 (Q-57): `compromised` is refused for a row whose key fresh
    /// evidence counts as a custodian, or that the ledger here once counted
    /// so (what the Team page reads), and without evidence to check it
    /// against, before any request is saved or sent; a member row is revoked
    /// as `compromised`.
    #[test]
    fn a_compromised_revoke_of_a_custodian_row_is_refused_before_anything_is_sent() {
        let f = fixture();
        let (x, m) = (peer(1), peer(2));
        let mut rig = rig(&f, |_| {});
        let now = rig.now;
        appoint(&rig, &f, &x, 0x50, now);
        let pin = f.pin();
        // Y held custody in an evaluation recorded here, then the server
        // stopped serving its root grant.
        let y = peer(3);
        let served = rig.rot.lock().unwrap().base.len();
        appoint(&rig, &f, &y, 0x60, now);
        let pages = rig
            .rt
            .block_on(rig.client.trust_evidence("access", &f.tenant))
            .unwrap();
        let (seen, chain) = crate::team::ledger::evaluate(&rig.db, &pin.0, &pin.1, &pages, now)
            .unwrap()
            .unwrap();
        crate::team::ledger::record(&mut rig.db, &pin.0, &seen, &chain, None, false, now).unwrap();
        let y_key = listed_keys(&y).unwrap().0;
        assert!(crate::team::ledger::held_custody(&rig.db, &pin.0, &y_key).unwrap());
        {
            let mut rot = rig.rot.lock().unwrap();
            rot.base.truncate(served);
            rot.base_keys.pop();
        }
        rig.clear();
        let revoke_as_compromised = |rig: &mut Rig, row: &TenantDevice, checked: bool| {
            let mut state = load().unwrap();
            let mut ledger = Ledger {
                db: &mut rig.db,
                pin: &pin,
            };
            rig.rt.block_on(revoke_member(
                &rig.client,
                "access",
                &f.device(&CredentialFkekStore),
                row,
                DeviceRevocationReason::Compromised,
                checked.then_some(&mut ledger),
                now,
                &mut state,
                &mut |s| save(s),
            ))
        };
        for (row, checked) in [(&x, true), (&x, false), (&y, true)] {
            let err = revoke_as_compromised(&mut rig, row, checked).unwrap_err();
            assert!(has(&err, "fleet.compromisedCustodian"), "{err}");
            assert!(load().unwrap().revocations.is_empty(), "nothing saved");
            let posts: Vec<String> = rig
                .calls()
                .into_iter()
                .filter(|c| c.starts_with("POST "))
                .collect();
            assert!(posts.is_empty(), "nothing sent: {posts:?}");
        }

        // The rig answers the revoke itself with a 500: it was sent.
        let _ = revoke_as_compromised(&mut rig, &m, true);
        let saved = &load().unwrap().revocations[&m.device_id];
        let issuer = f.signer.verifying_key().to_bytes();
        assert_eq!(
            saved_revocation(saved, &issuer).unwrap().reason_code,
            DeviceRevocationReason::Compromised
        );
        assert!(rig
            .calls()
            .iter()
            .any(|c| c.starts_with("POST ") && c.contains(&m.device_id)));
    }

    /// v2.9.0 "Member grant errors": a member whose grant filing failed in
    /// two runs in a row is named in the status (one failure is not); once
    /// the custodian skips it, the rotation finishes without it and nothing
    /// more is sent for it. Only that member can be skipped.
    #[test]
    fn a_member_skipped_by_the_custodian_lets_the_rotation_finish() {
        let f = fixture();
        let (b, c) = (peer(1), peer(2));
        let mut rig = at_members(&f, vec![b.clone(), c.clone()]);
        let now = rig.now;
        save_approval(&f, &b, now, now + 365 * DAY_MS);
        save_approval(&f, &c, now, now + 365 * DAY_MS);
        let b_id = decode_hex16(&b.device_id, "device_id").unwrap();
        rig.rot.lock().unwrap().refuse = Some(Box::new(move |call: &str, body: &[u8]| {
            (call.starts_with("POST ")
                && call.ends_with("/grants")
                && body.windows(16).any(|w| w == b_id))
            .then_some((503, ""))
        }));
        assert!(rig.members(&f, now).is_err());
        assert_eq!(rotation().phase, RotationPhase::Activated);
        assert_eq!(status().unwrap().rotation.unwrap().failing_member, None);
        let mut state = load().unwrap();
        let err = skip_member(&mut state, &b.device_id, &mut |s| save(s)).unwrap_err();
        assert!(
            has(&err, "fleet.rotationSkipRefused"),
            "after one failure: {err}"
        );

        assert!(rig.members(&f, now).is_err());
        let failing = status().unwrap().rotation.unwrap().failing_member;
        assert_eq!(failing.as_deref(), Some(b.device_id.as_str()));

        let mut state = load().unwrap();
        let err = skip_member(&mut state, &c.device_id, &mut |s| save(s)).unwrap_err();
        assert!(has(&err, "fleet.rotationSkipRefused"), "{err}");
        skip_member(&mut state, &b.device_id.to_ascii_uppercase(), &mut |s| {
            save(s)
        })
        .unwrap();
        rig.clear();
        rig.members(&f, now).unwrap();
        assert_eq!(
            results(),
            [
                (b.device_id.clone(), "skipped:custodian".to_string()),
                (c.device_id.clone(), "filed".to_string()),
            ]
        );
        assert_eq!(rotation().phase, RotationPhase::Done);
        assert_eq!(status().unwrap().rotation.unwrap().failing_member, None);
        assert_eq!(rig.bodies("/grants").len(), 1, "c's grant only");
    }

    /// v2.9.0 "Back-to-back rotations": a revoked device known to hold the
    /// active generation only from the previous rotation's member results
    /// keeps its banner when the next rotation expires.
    #[test]
    fn a_revoked_holder_keeps_its_banner_after_a_second_rotation_expires() {
        let f = fixture();
        let b = peer(1);
        let mut rig = at_members(&f, vec![b.clone()]);
        let now = rig.now;
        save_approval(&f, &b, now, now + 365 * DAY_MS);
        rig.members(&f, now).unwrap();
        let rt = runtime();
        let (client, _) = rt.block_on(mock(refuse_all()));
        revoke(&rt, &f, &client, &b, DeviceRevocationReason::Retired, now);
        assert_eq!(tier(&f, 1, |_| false), Some(RotationRequired::Routine));

        rig.refuse("/activate", 503, "");
        assert!(rig.rotate(&f, now).is_err());
        let deadline = rotation().deadline_ms.unwrap();
        let err = rig.rotate(&f, deadline).unwrap_err();
        assert!(has(&err, "fleet.rotationExpired"), "{err}");
        assert_eq!(rotation().phase, RotationPhase::Expired);
        assert_eq!(tier(&f, 1, |_| false), Some(RotationRequired::Routine));
    }

    /// The same across a rotation that stopped before step 4 and starts over
    /// after a server restore: the restarted one keeps the holders.
    #[test]
    fn a_revoked_holder_keeps_its_banner_across_a_rotation_restarted_by_a_restore() {
        let f = fixture();
        let b = peer(1);
        let mut rig = at_members(&f, vec![b.clone()]);
        let now = rig.now;
        save_approval(&f, &b, now, now + 365 * DAY_MS);
        rig.members(&f, now).unwrap();
        let rt = runtime();
        let (client, _) = rt.block_on(mock(refuse_all()));
        revoke(&rt, &f, &client, &b, DeviceRevocationReason::Retired, now);

        // The setup key's id is never saved: stopped before step 4.
        let err = rig
            .rotate_with(
                &f,
                &CredentialFkekStore,
                |_| Ok(Zeroizing::new(OLD_FKEK)),
                move || now,
                &mut |s| {
                    if s.rotation
                        .as_ref()
                        .is_some_and(|r| !r.fkek_key_id.is_empty())
                    {
                        bail!("disk-full")
                    }
                    save(s)
                },
            )
            .unwrap_err();
        assert!(has(&err, "disk-full"));
        assert_eq!(tier(&f, 1, |_| false), Some(RotationRequired::Routine));
        rig.rot.lock().unwrap().epoch = 1;
        rig.refuse("/activate", 503, "");
        assert!(rig.rotate(&f, now).is_err());
        assert_eq!(rotation().restore_epoch, 1, "started over");
        assert_eq!(tier(&f, 1, |_| false), Some(RotationRequired::Routine));
    }

    /// v2.9.0 "Re-export prompt": an export that finished while another
    /// custody action held the state ends the prompt once that action ends,
    /// unless that action rotated past what the bundle holds.
    #[test]
    fn an_export_finished_while_another_custody_action_ran_clears_the_prompt() {
        let f = fixture();
        let mut state = f.prepared();
        state.export_due = true;
        state.rotation = Some(FleetRotationState {
            generation: 1,
            phase: RotationPhase::Done,
            ..Default::default()
        });
        save(&state).unwrap();
        let running = begin().unwrap();
        exported(1).unwrap();
        assert!(
            status().unwrap().export_due,
            "the running action owns the state"
        );
        drop(running);
        assert!(!status().unwrap().export_due);

        // A bundle written before a rotation the other action finished.
        save(&state).unwrap();
        let running = begin().unwrap();
        exported(0).unwrap();
        drop(running);
        assert!(status().unwrap().export_due);
    }

    #[test]
    fn member_grants_stop_without_fresh_evidence() {
        let f = fixture();
        let b = peer(1);
        let mut rig = at_members(&f, vec![b.clone()]);
        let now = rig.now;
        save_approval(&f, &b, now, now + 365 * DAY_MS);
        rig.rot.lock().unwrap().evidence_down = true;
        let err = rig.members(&f, now).unwrap_err();
        assert!(has(&err, "fleet.refusedCustody"), "{err}");
        assert!(only_reads(&rig.calls()), "nothing is filed");
        let r = rotation();
        assert_eq!(r.phase, RotationPhase::Activated);
        assert!(r.member_grants.is_empty() && r.member_results.is_empty());
    }

    #[test]
    fn member_grants_resume_after_a_transport_failure_with_the_saved_filing() {
        let f = fixture();
        let b = peer(1);
        let mut rig = at_members(&f, vec![b.clone()]);
        let now = rig.now;
        save_approval(&f, &b, now, now + 365 * DAY_MS);
        rig.refuse("/grants", 503, "");
        assert!(rig.members(&f, now).is_err());
        let r = rotation();
        assert_eq!(r.phase, RotationPhase::Activated);
        assert!(r.member_results.is_empty());
        let saved = unhex_vec(&r.member_grants[&b.device_id]).unwrap();
        rig.allow();

        rig.members(&f, now + 1).unwrap();
        assert_eq!(rig.bodies("/grants"), [saved.clone(), saved]);
        assert_eq!(results(), [(b.device_id.clone(), "filed".to_string())]);
        assert_eq!(rotation().phase, RotationPhase::Done);
    }

    #[test]
    fn an_unfinished_rotation_cannot_be_started_again() {
        let f = fixture();
        let mut rig = rig(&f, |_| {});
        let vault = Counting(AtomicUsize::new(0));
        rig.refuse("/key-generations", 503, "");
        let now = rig.now;
        let run = |rig: &mut Rig| {
            rig.rotate_with(
                &f,
                &vault,
                |_| Ok(Zeroizing::new(OLD_FKEK)),
                move || now,
                &mut |s| save(s),
            )
        };
        assert!(run(&mut rig).is_err());
        let first = rotation();
        assert!(run(&mut rig).is_err());
        let second = rotation();
        assert_eq!(
            (first.generation, &first.fkek_nonce, &first.create_request),
            (
                second.generation,
                &second.fkek_nonce,
                &second.create_request
            )
        );
        assert_eq!(vault.0.load(Ordering::SeqCst), 1);
        let starts = rig
            .calls()
            .iter()
            .filter(|c| c.contains("/trust-evidence"))
            .count();
        assert_eq!(starts, 1, "the second run resumed");
        assert_eq!(rig.bodies("/key-generations").len(), 2);
    }

    #[test]
    fn approving_a_device_while_a_rotation_is_unfinished_is_refused() {
        let f = fixture();
        let rig = rig(&f, |_| {});
        let (row, _) = joiner();
        for phase in [RotationPhase::Preparing, RotationPhase::Activated] {
            let mut state = load().unwrap();
            state.rotation = Some(FleetRotationState {
                generation: 1,
                phase,
                ..Default::default()
            });
            save(&state).unwrap();
            let err = approve(&rig.rt, &f, &rig.client, &row, &f.code(&row), now_ms());
            assert!(err.contains("fleet.rotationInProgress"), "{phase:?}: {err}");
            assert!(rig.calls().is_empty(), "{phase:?}");
        }
        for phase in [RotationPhase::Done, RotationPhase::Expired] {
            let mut state = load().unwrap();
            state.rotation.as_mut().unwrap().phase = phase;
            save(&state).unwrap();
            approve_allowed(&rig, &f);
        }
    }

    /// Approve of `row` against the rig, the verified ACTIVE key being `key`.
    fn approve_on(rig: &Rig, f: &Fixture, row: &TenantDevice, sas: &str) -> Result<()> {
        let mut state = load().unwrap();
        rig.rt.block_on(approve_member(
            &rig.client,
            "access",
            &f.device(&CredentialFkekStore),
            &f.pin(),
            row,
            sas,
            |generation| match generation {
                0 => Ok(Zeroizing::new(FKEK)),
                1 => Ok(Zeroizing::new(NEW_FKEK)),
                _ => bail!("no verified key of generation {generation}"),
            },
            |key| crate::team::ledger::withdrawn(&rig.db, &f.pin().0, key),
            now_ms(),
            &mut state,
            &mut |s| save(s),
        ))
    }

    /// An approval built and saved under generation 0 whose approve reply
    /// was lost, then a rotation to 1 that finished, its member step having
    /// recorded `result` for the device, if anything. The rig, the device
    /// and its saved requests.
    fn approval_across_a_rotation(
        f: &Fixture,
        result: Option<&str>,
    ) -> (Rig, TenantDevice, MemberApproval) {
        let rig = rig(f, |r| r.approves = true);
        let (row, _) = joiner();
        rig.refuse("/approve", 503, "");
        assert!(approve_on(&rig, f, &row, &f.code(&row)).is_err());
        let id = row.device_id.to_ascii_lowercase();
        let saved = load().unwrap().members[&id].clone();
        let filing = payload(&saved.grant_request, FleetKeyGrantCreateV2::parse);
        assert_eq!(filing.grant.generation.generation, 0);
        rig.allow();
        rig.rot.lock().unwrap().active = Some(1);
        let mut state = load().unwrap();
        state.rotation = Some(FleetRotationState {
            generation: 1,
            phase: RotationPhase::Done,
            member_results: result.map(|r| (id, r.to_string())).into_iter().collect(),
            ..Default::default()
        });
        save(&state).unwrap();
        rig.clear();
        (rig, row, saved)
    }

    /// The approval and capability grants `saved` holds went out once each,
    /// byte for byte.
    fn resent_as_saved(rig: &Rig, saved: &MemberApproval) {
        assert_eq!(
            rig.bodies("/approve"),
            [unhex_vec(&saved.approval).unwrap()]
        );
        let grants: Vec<Vec<u8>> = saved
            .capability_grants
            .iter()
            .map(|g| unhex_vec(g).unwrap())
            .collect();
        assert_eq!(rig.bodies("/capability-grants"), grants);
    }

    #[test]
    fn an_approval_saved_before_a_rotation_files_its_fleet_grant_under_the_active_generation() {
        let f = fixture();
        let (rig, row, saved) = approval_across_a_rotation(&f, None);
        approve_on(&rig, &f, &row, "").unwrap();
        resent_as_saved(&rig, &saved);
        let id = row.device_id.to_ascii_lowercase();
        let rebuilt = load().unwrap().members[&id].grant_request.clone();
        let filing = payload(&rebuilt, FleetKeyGrantCreateV2::parse);
        assert_eq!(
            (
                filing.grant.generation.generation,
                filing.grant.generation.fkek_key_id
            ),
            (1, fkek_key_id(&NEW_FKEK))
        );
        let filed = rig.bodies("/grants");
        assert_eq!(filed, [saved_request(&rebuilt).unwrap().encode()]);
        // Built once: a later resume resends the same bytes.
        rig.clear();
        approve_on(&rig, &f, &row, "").unwrap();
        assert_eq!(rig.bodies("/grants"), filed);
        // An ACTIVE generation below the saved one rebuilds nothing: the
        // saved grant goes out as it is and stays saved.
        rig.rot.lock().unwrap().active = Some(0);
        rig.clear();
        approve_on(&rig, &f, &row, "").unwrap();
        assert_eq!(rig.bodies("/grants"), filed);
        assert_eq!(load().unwrap().members[&id].grant_request, rebuilt);
    }

    /// A resume never grants N+1 to a device the rotation found ineligible
    /// or this custodian revoked, whatever the listing says.
    #[test]
    fn an_approval_resumed_after_a_rotation_refuses_a_revoked_device() {
        for revoked_here in [false, true] {
            let f = fixture();
            let result = (!revoked_here).then_some("skipped:revoked");
            let (rig, row, saved) = approval_across_a_rotation(&f, result);
            let id = row.device_id.to_ascii_lowercase();
            if revoked_here {
                let mut state = load().unwrap();
                state.revocations.insert(id.clone(), "00".into());
                save(&state).unwrap();
            }
            let err = approve_on(&rig, &f, &row, "").unwrap_err();
            assert!(has(&err, "fleet.deviceNotPending"), "{revoked_here}: {err}");
            assert!(rig.bodies("/grants").is_empty(), "{revoked_here}");
            assert!(
                !revoked_here || only_reads(&rig.calls()),
                "nothing is resent"
            );
            assert_eq!(
                load().unwrap().members[&id].grant_request,
                saved.grant_request,
                "{revoked_here}"
            );
        }
    }

    /// A rebuilt N+1 grant saved, then the device revoked before it went out:
    /// the next resume, ACTIVE now naming the saved grant, sends it nowhere.
    #[test]
    fn a_saved_rebuilt_grant_is_not_sent_once_the_device_is_revoked() {
        let f = fixture();
        let (rig, row, _) = approval_across_a_rotation(&f, None);
        let id = row.device_id.to_ascii_lowercase();
        rig.refuse("/grants", 503, "");
        assert!(approve_on(&rig, &f, &row, "").is_err());
        let rebuilt = load().unwrap().members[&id].grant_request.clone();
        let filing = payload(&rebuilt, FleetKeyGrantCreateV2::parse);
        assert_eq!(filing.grant.generation.generation, 1);
        let mut state = load().unwrap();
        state.revocations.insert(id.clone(), "00".into());
        save(&state).unwrap();
        rig.allow();
        rig.clear();
        let err = approve_on(&rig, &f, &row, "").unwrap_err();
        assert!(has(&err, "fleet.deviceNotPending"), "{err}");
        assert!(only_reads(&rig.calls()), "nothing is resent");
        assert_eq!(load().unwrap().members[&id].grant_request, rebuilt);
    }

    /// No member result names the device, but the ledger holds its key
    /// withdrawn: no N+1 grant is built or sent.
    #[test]
    fn an_approval_resumed_after_a_rotation_refuses_a_key_the_ledger_holds_withdrawn() {
        let f = fixture();
        let (rig, row, saved) = approval_across_a_rotation(&f, None);
        let key = decode_hex32(&row.signing_key_id, "signing_key_id").unwrap();
        crate::team::ledger::distrust_key(&rig.db, &f.pin().0, &key, now_ms()).unwrap();
        let err = approve_on(&rig, &f, &row, "").unwrap_err();
        assert!(has(&err, "fleet.deviceNotPending"), "{err}");
        assert!(only_reads(&rig.calls()), "nothing is resent");
        let id = row.device_id.to_ascii_lowercase();
        assert_eq!(
            load().unwrap().members[&id].grant_request,
            saved.grant_request
        );
    }

    #[test]
    fn an_approval_resumed_after_a_rotation_does_not_file_a_second_grant() {
        let f = fixture();
        let (rig, row, saved) = approval_across_a_rotation(&f, Some("filed"));
        approve_on(&rig, &f, &row, "").unwrap();
        resent_as_saved(&rig, &saved);
        assert!(rig.bodies("/grants").is_empty(), "the rotation filed it");
        let id = row.device_id.to_ascii_lowercase();
        assert_eq!(
            load().unwrap().members[&id].grant_request,
            saved.grant_request
        );
    }

    /// The N+1 grant a resume builds is sealed only to the keys the saved
    /// approval names: a listing that swapped the HPKE key gets nothing.
    #[test]
    fn an_approval_resumed_after_a_rotation_refuses_a_swapped_listed_key() {
        let f = fixture();
        let (rig, mut row, saved) = approval_across_a_rotation(&f, None);
        let other = peer(1);
        (row.hpke_public_key, row.hpke_key_id) = (other.hpke_public_key, other.hpke_key_id);
        let err = approve_on(&rig, &f, &row, "").unwrap_err();
        assert!(has(&err, "fleet.deviceKeysMismatch"), "{err}");
        assert!(rig.bodies("/grants").is_empty());
        let id = row.device_id.to_ascii_lowercase();
        assert_eq!(
            load().unwrap().members[&id].grant_request,
            saved.grant_request
        );
    }

    #[test]
    fn the_rotation_state_holds_no_key_bytes() {
        let f = fixture();
        let b = peer(1);
        let mut rig = rig(&f, |r| r.devices = vec![b.clone()]);
        let now = rig.now;
        save_approval(&f, &b, now, now + 365 * DAY_MS);
        rig.rotate(&f, now).unwrap();
        let key = hex(&*rotation_key_held().unwrap());
        collected(now);
        rig.members(&f, now).unwrap();
        let state = load().unwrap();
        let r = state.rotation.clone().unwrap();
        assert_eq!(r.phase, RotationPhase::Done);
        let file = std::fs::read_to_string(crate::store::fleet_custody_path().unwrap()).unwrap();
        let debug = format!("{state:?}");
        assert!(file.contains(&r.fkek_key_id) && debug.contains(&r.fkek_key_id));
        for text in [&file, &debug] {
            for (secret, what) in [
                (&key, "the new fleet key"),
                (&hex(&OLD_FKEK), "the old fleet key"),
                (&hex(&NEW_FKEK), "the key members get"),
                (&hex(&TRK), "the TRK"),
                (&hex(&f.seed), "the HPKE seed"),
                (&hex(&f.signer.to_bytes()), "the signing seed"),
            ] {
                assert!(!text.contains(secret.as_str()), "{what}");
            }
        }
        for saved in [
            &r.create_request,
            &r.rotate_grant,
            &r.device_grant,
            &r.activate_request,
            &r.member_grants[&b.device_id],
        ] {
            assert!(!debug.contains(saved.as_str()));
        }
    }
}
