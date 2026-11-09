//! Root key rotation (v2.11 sequence RR, ADR 0002 Q-59).
//!
//! The tenant's root custodian replaces the ACTIVE root key `N` with a new
//! one, `N + 1`. Every retained fleet key is unwrapped from the
//! chain-verified `RecoveryGrant`s under `N` with the old TRK (D7) and
//! wrapped again under the new one; the recovery bundle, v4 with this
//! device's own `RotationGrant` (D6), is written and pinned before the
//! create. The fleet key rotation that follows is the custodian's next step
//! (D8).
//!
//! The rules are the bootstrap's: the new TRK is held in the credential store
//! before anything names it, every record and request is built once and
//! saved before the first is sent, a resumed run resends the saved bytes, and
//! every reply is checked against the request it answers. The state holds
//! requests and the new key's reference, never a key.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use shardx_core::approval_receipt::MAX_FLEET_RECOVERY_GRANT_TTL_MS;
use shardx_core::authz_record::{
    build_record, ApprovalScopeKind, AuthorizationRecord, Capability, CapabilityScopeKind,
    GrantSubject, Payload, RecoveryGrantV2, RootGrantVariant, TenantRootKeyGrantV2,
    DOMAIN_FLEET_KEY_GRANT_RECOVERY,
};
use shardx_core::fleet_lifecycle::{
    FleetGenerationRef, FleetGrantVariant, FleetKeyGrantAckV2, FleetKeyGrantAckedV2,
    FleetKeyGrantCreateV2, FleetKeyGrantCreatedV2, RECORD_TYPE_FLEET_GRANT_ACKED,
    RECORD_TYPE_FLEET_GRANT_CREATED,
};
use shardx_core::grants::derive_keypair;
use shardx_core::keys::{root_key_id, signing_key_id};
use shardx_core::mutation::{
    root_custodian_grant_set_hash, PreviousRoot, RootGenerationMode, RootGenerationState,
    RootGenerationTarget, RootGrantState, TenantRootGenerationActivateV2,
    TenantRootGenerationActivatedV2, TenantRootGenerationCreateV2, TenantRootGenerationCreatedV2,
    TenantRootGrantAckV2, TenantRootGrantAckedV2, TenantRootGrantCreateV2,
    TenantRootGrantCreatedV2, TenantRootGrantDescriptorV2, RECORD_TYPE_ROOT_GENERATION_ACTIVATED,
    RECORD_TYPE_ROOT_GENERATION_CREATED, RECORD_TYPE_ROOT_GRANT_ACKED,
    RECORD_TYPE_ROOT_GRANT_CREATED,
};
use shardx_core::recovery_bundle::{RecoveryBundlePlaintextV2, RetainedFkek, RootCustodian};

use crate::fleet_client::{decode_hex16, hex, FleetClient};
use crate::fleet_custody::{
    refused_for_good, refused_with, FleetCustodyState, Ledger, RotationPhase,
};
use crate::root_bootstrap::{
    check_bundle, commit, corrupt, current_root_grant, is_missing, mismatch, nonce_ok, random,
    renewal_context, saved, sealed_root_grant, stored_payload, trk_ref, unhex, unhex_vec,
    verified_root_grant, write_bundle, BootstrapState, Context16, RecoveryExport, RenewingDevice,
    TrkStore, CLOCK_SKEW_MS, RENEWED_VALIDITY_MS,
};

/// One root key rotation: every record and request, hex, built once and
/// saved before the first is sent, and the reference of the new TRK. No key
/// is among it.
#[derive(Default, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RootRotation {
    /// The generation it activates, `N + 1`.
    #[serde(default)]
    pub generation: u64,
    /// Names the new TRK's credential reference; saved before the key is
    /// stored, cleared once the key is released after activation.
    #[serde(default)]
    pub trk_nonce: String,
    /// The new TRK's public `root_key_id`, saved once the store holds it.
    #[serde(default)]
    pub root_key_id: String,
    /// This device's tenant-wide `key.rotate` (ADR 0002 Q-51).
    #[serde(default)]
    pub capability_grant: String,
    /// The `RotationGrant` of `N + 1` to this device.
    #[serde(default)]
    pub root_grant: String,
    #[serde(default)]
    pub create_request: String,
    #[serde(default)]
    pub root_grant_request: String,
    #[serde(default)]
    pub ack_request: String,
    /// One `RecoveryGrant` filing per retained fleet generation, and its ack.
    #[serde(default)]
    pub recovery_requests: Vec<String>,
    #[serde(default)]
    pub recovery_ack_requests: Vec<String>,
    #[serde(default)]
    pub activate_request: String,
    /// The bundle the create pins, and where it was written.
    #[serde(default)]
    pub recovery_bundle_sha256: String,
    #[serde(default)]
    pub recovery_path: String,
    /// The next step to send, saved once the one before it is answered: the
    /// capability grant, the create, the root grant, its ack, each recovery
    /// grant and its ack, the activation.
    #[serde(default)]
    pub step: u32,
    /// `N + 1` is ACTIVE and its records are this device's current ones.
    #[serde(default)]
    pub done: bool,
}

/// A rotation started and has not activated.
pub(crate) fn unfinished(state: &BootstrapState) -> bool {
    state.root_rotation.as_ref().is_some_and(|r| !r.done)
}

#[cfg(test)]
thread_local! {
    /// Stops this thread's run as a lost reply would, right after the step
    /// with this index is saved as answered: a real-server crash test.
    pub(crate) static CRASH_AFTER_STEP: std::cell::Cell<u32> = const { std::cell::Cell::new(u32::MAX) };
}

fn code(key: &str) -> anyhow::Error {
    anyhow!(crate::errcode::code(key))
}

fn rotation_mut(s: &mut BootstrapState) -> &mut RootRotation {
    s.root_rotation.get_or_insert_with(Default::default)
}

/// RR step 1: nothing is filed while a hand-over, fleet rotation, re-seal or
/// renewal is unfinished.
fn refuse_start(state: &BootstrapState, custody: &FleetCustodyState) -> Result<()> {
    crate::fleet_custody::refuse_handed_over(custody)?;
    let busy = custody.handover.as_ref().is_some_and(|h| h.phase != "done")
        || custody.rotation.as_ref().is_some_and(|r| {
            matches!(r.phase, RotationPhase::Preparing | RotationPhase::Activated)
        })
        || custody
            .reseal
            .as_ref()
            .is_some_and(|r| r.ended_ms.is_none())
        || state.renewal.as_ref().is_some_and(|r| !r.done);
    if busy {
        return Err(code("fleet.rootRotationWaitsForCustodyStep"));
    }
    Ok(())
}

/// Step 3: the new TRK is held before anything names it. A key under this
/// run's reference whose id is not saved yet was named by nothing and is
/// reused; a new one is made only when the store answers
/// `credential.missing` and no id is saved. A key the store lost once the
/// saved `RotationGrant` (sealed to this device, `own`) names it is reopened
/// from that grant with `hpke_secret` and stored again.
fn hold_trk(
    vault: &dyn TrkStore,
    own: &[u8; 32],
    hpke_secret: &[u8],
    state: &mut BootstrapState,
    save: &mut impl FnMut(&BootstrapState) -> Result<()>,
) -> Result<Zeroizing<[u8; 32]>> {
    if rotation_mut(state).trk_nonce.is_empty() {
        let nonce = hex(&random::<16>()?);
        commit(state, save, |s| rotation_mut(s).trk_nonce = nonce)?;
    }
    let r = state.root_rotation.clone().ok_or_else(corrupt)?;
    if !nonce_ok(&r.trk_nonce) {
        return Err(corrupt());
    }
    let name = trk_ref(&state.tenant_id, &r.trk_nonce);
    let key = match vault.load(&name) {
        Ok(key) => key,
        Err(e) if is_missing(&e) && r.root_key_id.is_empty() => {
            let key = Zeroizing::new(random::<32>()?);
            vault.store(&name, &key)?;
            key
        }
        Err(e) if is_missing(&e) && !r.root_grant.is_empty() => {
            let (grant, _) = verified_root_grant(&unhex_vec(&r.root_grant)?, own)?;
            let key = grant.open_trk(hpke_secret).map_err(|_| corrupt())?;
            vault.store(&name, &key)?;
            key
        }
        Err(e) => return Err(e),
    };
    let id = hex(&root_key_id(&key));
    if r.root_key_id.is_empty() {
        commit(state, save, |s| rotation_mut(s).root_key_id = id)?;
    } else if r.root_key_id != id {
        return Err(corrupt());
    }
    Ok(key)
}

/// Forgets the new TRK's stored copy, if the run names one; forgetting it
/// again does no harm.
fn forget_trk(vault: &dyn TrkStore, state: &BootstrapState) -> Result<bool> {
    let Some(nonce) = state
        .root_rotation
        .as_ref()
        .map(|r| r.trk_nonce.as_str())
        .filter(|n| !n.is_empty())
    else {
        return Ok(false);
    };
    if !nonce_ok(nonce) {
        return Err(corrupt());
    }
    vault.forget(&trk_ref(&state.tenant_id, nonce))?;
    Ok(true)
}

/// Forgets the new TRK's stored copy, then drops its reference: once `N + 1`
/// is active this device reopens it from its `RotationGrant`.
fn release_trk(
    vault: &dyn TrkStore,
    state: &mut BootstrapState,
    save: &mut impl FnMut(&BootstrapState) -> Result<()>,
) -> Result<()> {
    if !forget_trk(vault, state)? {
        return Ok(());
    }
    commit(state, save, |s| rotation_mut(s).trk_nonce.clear())
}

/// What step 2 found: the server time `T`, every retained fleet key and the
/// replay ID of this device's live tenant approval.
struct Retained {
    t: u64,
    keys: Vec<RetainedFkek>,
    approval_replay: [u8; 16],
}

/// RR step 2 (D7) at the server's time: the chain from the saved anchor
/// counts this device as a custodian; every fleet generation the server
/// knows of (0 to the ACTIVE one, and every one a fleet grant names) has a
/// `RecoveryGrant` under the ACTIVE root, issued by a custodian at its
/// `issued_at`, that opens with `old_trk`, and matches the key this device
/// holds for it. A generation above the ACTIVE one is PREPARING: D-5 could
/// never pass, so nothing is filed.
#[allow(clippy::too_many_arguments)]
async fn retained_keys(
    client: &FleetClient,
    access: &str,
    ledger: &mut Ledger<'_>,
    cx: &Context16,
    current: &TenantRootKeyGrantV2,
    old_trk: &[u8; 32],
    local_keys: &[(u64, Zeroizing<[u8; 32]>)],
    local_now: u64,
) -> Result<Retained> {
    let tenant = hex(&cx.tenant);
    // Q-62: complete listings, read again naming every known signer when a
    // custodian revocation is to be counted.
    let (listings, _) = crate::team::ledger::closure_evidence(
        client,
        access,
        &tenant,
        ledger.db,
        ledger.pin,
        &[cx.signing_key_id],
        local_now,
    )
    .await?;
    let server_now = listings
        .iter()
        .flatten()
        .map(|p| p.server_now_ms)
        .min()
        .unwrap_or(0);
    if server_now == 0 {
        return Err(mismatch());
    }
    let t = local_now.min(server_now).saturating_sub(CLOCK_SKEW_MS);
    let (_, chain) =
        crate::team::ledger::evaluate(ledger.db, &ledger.pin.0, &ledger.pin.1, &listings, t)?
            .ok_or_else(|| code("fleet.trustEvidenceRefused"))?;
    let pages = listings.concat();
    if !chain.custodian_now(&cx.signing_key_id, t) {
        return Err(code("fleet.notCustodian"));
    }
    let keys: BTreeMap<[u8; 32], [u8; 32]> = pages
        .iter()
        .flat_map(|p| &p.signing_public_keys)
        .map(|k| (signing_key_id(k), *k))
        .collect();
    let records: Vec<([u8; 32], Payload)> = pages
        .iter()
        .flat_map(|p| &p.containers)
        .filter_map(|c| {
            let r = AuthorizationRecord::parse(c).ok()?;
            let issuer = *r.issuer_signing_key_id();
            let p = r
                .verify_signature(keys.get(&issuer)?)
                .ok()?
                .payload()
                .clone();
            let common = p.common();
            (common.tenant_id == cx.tenant && common.server_instance_id == cx.instance)
                .then_some((issuer, p))
        })
        .collect();

    let approval_replay = records
        .iter()
        .filter_map(|(_, p)| match p {
            Payload::DeviceApproval(a)
                if (
                    a.subject_account_id,
                    a.subject_device_id,
                    a.subject_signing_key_id,
                    a.subject_hpke_key_id,
                ) == (cx.account, cx.device, cx.signing_key_id, cx.hpke_key_id)
                    && matches!(a.approval_scope_kind, ApprovalScopeKind::Tenant)
                    && a.common.not_before_ms <= t
                    && t < a.common.not_after_ms =>
            {
                Some((a.common.not_after_ms, a.common.replay_id))
            }
            _ => None,
        })
        .max()
        .map(|(_, replay)| replay)
        .ok_or_else(|| code("fleet.rotationCustodianApprovalExpired"))?;

    let fleet = cx.tenant;
    let active = client
        .active_fleet_generation(access, &tenant, &hex(&fleet))
        .await?;
    let mut generations: BTreeSet<([u8; 16], u64)> = active
        .map(|a| (0..=a).map(|g| (fleet, g)).collect())
        .unwrap_or_default();
    let mut opened = BTreeMap::new();
    for (issuer, p) in &records {
        let named = match p {
            Payload::DeviceHpkeGrant(g) => (g.fleet_id, g.generation),
            Payload::RotationGrant(g) => (g.fleet_id, g.generation),
            Payload::RecoveryGrant(g) => {
                let under = (g.recipient_root_generation, g.recipient_root_key_id)
                    == (current.root_generation, current.root_key_id);
                if under && chain.custodian_at(issuer, g.common.issued_at_ms) {
                    if let Ok(key) = g.open_fkek(old_trk) {
                        opened.entry((g.fleet_id, g.generation)).or_insert(key);
                    }
                }
                (g.fleet_id, g.generation)
            }
            _ => continue,
        };
        generations.insert(named);
    }
    if generations
        .iter()
        .any(|&(f, g)| f == fleet && active.is_none_or(|a| g > a))
    {
        return Err(code("fleet.rootRotationWaitsForFleetDiscard"));
    }
    let mut retained = Vec::with_capacity(generations.len());
    for (f, g) in generations {
        let missing = || {
            anyhow!(crate::errcode::code_with(
                "fleet.rootRotationMissingFleetKey",
                &[("fleet", &hex(&f)), ("generation", &g.to_string())],
            ))
        };
        let key = opened.remove(&(f, g)).ok_or_else(missing)?;
        if f == fleet && local_keys.iter().any(|(lg, lk)| *lg == g && **lk != *key) {
            return Err(missing());
        }
        retained.push(RetainedFkek {
            fleet_id: f,
            generation: g,
            fkek: key,
        });
    }
    Ok(Retained {
        t,
        keys: retained,
        approval_replay,
    })
}

/// RR steps 3 and 4 at `T`: the tenant `key.rotate` (a year), the
/// `RotationGrant` to this device (exactly 730 days, linking its live
/// tenant approval), one `RecoveryGrant` per retained generation under the
/// new TRK (ten years), the bundle written and read back, then the create
/// pinning its hash, the filings, acks and activation, saved together.
#[allow(clippy::too_many_arguments)]
fn build(
    cx: &Context16,
    me: &RenewingDevice<'_>,
    current: &TenantRootKeyGrantV2,
    new_trk: &[u8; 32],
    retained: Retained,
    recovery: &RecoveryExport<'_>,
    local_now: u64,
    state: &mut BootstrapState,
    save: &mut impl FnMut(&BootstrapState) -> Result<()>,
) -> Result<()> {
    let generation = state.root_rotation.as_ref().ok_or_else(corrupt)?.generation;
    let own = me.signer.verifying_key().to_bytes();
    // `common` backdates by the skew: built at `start`, records begin at `T`.
    let start = retained.t + CLOCK_SKEW_MS;
    let me_subject = GrantSubject::Device {
        account_id: cx.account,
        device_id: cx.device,
        signing_key_id: cx.signing_key_id,
        hpke_key_id: cx.hpke_key_id,
    };
    let rotate = (
        Capability::KeyRotate,
        CapabilityScopeKind::Tenant,
        cx.tenant,
    );
    let capability_grant =
        crate::fleet_custody::capability_grants(cx, me.signer, &me_subject, [rotate], start)?
            .pop()
            .ok_or_else(corrupt)?;

    let new_id = root_key_id(new_trk);
    let mut common = cx.common(random()?, start);
    common.not_after_ms = common.not_before_ms + RENEWED_VALIDITY_MS;
    let grant = TenantRootKeyGrantV2 {
        common,
        variant: RootGrantVariant::RotationGrant {
            previous_root_key_id: current.root_key_id,
            previous_root_generation: current.root_generation,
        },
        root_key_id: new_id,
        root_generation: generation,
        subject_account_id: cx.account,
        subject_device_id: cx.device,
        subject_signing_key_id: cx.signing_key_id,
        recipient_hpke_key_id: cx.hpke_key_id,
        subject_device_approval_replay_id: retained.approval_replay,
        hpke_encapped_key_bytes: [0; 32],
        hpke_wrapped_trk_bytes: [0; 48],
    };
    let (_, hpke_public) = derive_keypair(me.hpke_seed);
    let root_grant = sealed_root_grant(me.signer, &hpke_public, new_trk, grant)?;
    let (_, grant_ref) = verified_root_grant(&root_grant, &own)?;

    let mut recovery_requests = Vec::with_capacity(retained.keys.len());
    let mut recovery_ack_requests = Vec::with_capacity(retained.keys.len());
    for r in &retained.keys {
        let mut common = cx.common(random()?, start);
        common.not_after_ms = common.not_before_ms + MAX_FLEET_RECOVERY_GRANT_TTL_MS;
        let mut g = RecoveryGrantV2 {
            common,
            fleet_id: r.fleet_id,
            fkek_key_id: shardx_core::fleet_grants::fkek_key_id(&r.fkek),
            generation: r.generation,
            recipient_root_key_id: new_id,
            recipient_root_generation: generation,
            root_wrap_nonce_bytes: [0; 12],
            wrapped_fleet_key_bytes: [0; 48],
        };
        g.seal(new_trk, &r.fkek).map_err(|_| corrupt())?;
        let container = build_record(me.signer, DOMAIN_FLEET_KEY_GRANT_RECOVERY, &g.encode());
        let hash = *AuthorizationRecord::parse(&container)
            .map_err(|_| corrupt())?
            .signed_container_hash();
        let target = FleetGenerationRef {
            tenant_id: cx.tenant,
            server_instance_id: cx.instance,
            restore_epoch: cx.epoch,
            fleet_id: r.fleet_id,
            generation: r.generation,
            fkek_key_id: g.fkek_key_id,
        };
        let filing = FleetKeyGrantCreateV2::new(
            target,
            FleetGrantVariant::Recovery,
            g.common.replay_id,
            hash,
            container,
        );
        recovery_requests.push(hex(&cx.request(
            shardx_core::mutation::OperationKind::FleetGrantCreate,
            filing.encode(),
        )?));
        let ack = FleetKeyGrantAckV2 {
            grant: filing.grant,
        };
        recovery_ack_requests.push(hex(&cx.request(
            shardx_core::mutation::OperationKind::FleetGrantAck,
            ack.encode(),
        )?));
    }

    // 4. The bundle the create pins: the new TRK, every retained key, this
    // device's seeds and its RotationGrant from itself.
    let plaintext = RecoveryBundlePlaintextV2 {
        trk: (*new_trk).into(),
        bootstrap_anchor_signing_key_id: unhex(&state.anchor)?,
        retained_fkeks: retained.keys,
        root_custodian: Some(RootCustodian {
            account_id: cx.account,
            device_id: cx.device,
            signing_key_seed: me.signer.to_bytes().into(),
            hpke_key_seed: (*me.hpke_seed).into(),
            root_grant: root_grant.clone(),
            root_grant_issuer: Some(own),
        }),
    };
    let sha = write_bundle(
        (cx.tenant, cx.instance, generation),
        &plaintext,
        recovery,
        local_now,
    )?;

    use shardx_core::mutation::OperationKind;
    let previous = PreviousRoot {
        root_key_id: current.root_key_id,
        root_generation: current.root_generation,
    };
    let target = RootGenerationTarget {
        tenant_id: cx.tenant,
        server_instance_id: cx.instance,
        restore_epoch: cx.epoch,
        root_key_id: new_id,
        root_generation: generation,
        required_custodian_grant_count: 1,
        required_custodian_grant_set_hash: root_custodian_grant_set_hash(&[
            grant_ref.signed_container_hash
        ])
        .ok_or_else(mismatch)?,
        recovery_bundle_sha256: sha,
    };
    let create = TenantRootGenerationCreateV2 {
        target: target.clone(),
        mode: RootGenerationMode::Rotation {
            previous_root_key_id: previous.root_key_id,
            previous_root_generation: previous.root_generation,
        },
    };
    let filing = TenantRootGrantCreateV2 {
        grant: grant_ref.clone(),
        exact_signed_grant_container_bytes: root_grant.clone(),
    };
    let ack = TenantRootGrantAckV2 { grant: grant_ref };
    let activate = TenantRootGenerationActivateV2 {
        target,
        previous: Some(previous),
    };
    let create_request = hex(&cx.request(OperationKind::RootGenerationCreate, create.encode())?);
    let root_grant_request = hex(&cx.request(OperationKind::RootGrantCreate, filing.encode())?);
    let ack_request = hex(&cx.request(OperationKind::RootGrantAck, ack.encode())?);
    let activate_request =
        hex(&cx.request(OperationKind::RootGenerationActivate, activate.encode())?);
    let path = recovery.path.to_string_lossy().into_owned();
    commit(state, save, |s| {
        let r = rotation_mut(s);
        r.capability_grant = capability_grant;
        r.root_grant = hex(&root_grant);
        r.create_request = create_request;
        r.root_grant_request = root_grant_request;
        r.ack_request = ack_request;
        r.recovery_requests = recovery_requests;
        r.recovery_ack_requests = recovery_ack_requests;
        r.activate_request = activate_request;
        r.recovery_bundle_sha256 = hex(&sha);
        r.recovery_path = path;
        r.step = 0;
    })
}

/// Saves that the run's `step` is the next one to send.
fn answered(
    state: &mut BootstrapState,
    save: &mut impl FnMut(&BootstrapState) -> Result<()>,
    step: usize,
) -> Result<()> {
    let step = u32::try_from(step).map_err(|_| corrupt())?;
    commit(state, save, |s| rotation_mut(s).step = step)?;
    #[cfg(test)]
    if CRASH_AFTER_STEP.with(std::cell::Cell::get) == step - 1 {
        CRASH_AFTER_STEP.with(|c| c.set(u32::MAX));
        return Err(code("fleet.unreachableCustody"));
    }
    Ok(())
}

/// RR step 5: the saved run's requests in order from its saved step, each
/// checked by the reply that answers it and saved as answered before the
/// next is sent.
#[allow(clippy::too_many_arguments)]
async fn send(
    client: &FleetClient,
    access: &str,
    cx: &Context16,
    own_pk: &[u8; 32],
    hpke_secret: &[u8],
    new_trk: &[u8; 32],
    recovery: &RecoveryExport<'_>,
    state: &mut BootstrapState,
    save: &mut impl FnMut(&BootstrapState) -> Result<()>,
) -> Result<()> {
    let r = state.root_rotation.clone().ok_or_else(corrupt)?;
    let n = r.recovery_requests.len();
    if r.recovery_ack_requests.len() != n {
        return Err(corrupt());
    }
    let tenant = hex(&cx.tenant);
    let from = usize::try_from(r.step).map_err(|_| corrupt())?;
    let (create, create_bytes) = saved(&r.create_request)?;
    let target = TenantRootGenerationCreateV2::parse(&create.canonical_payload_bytes)
        .map_err(|_| corrupt())?
        .target;
    let generation = target.root_generation;
    let (filing_request, filing_bytes) = saved(&r.root_grant_request)?;
    let filing = TenantRootGrantCreateV2::parse(&filing_request.canonical_payload_bytes)
        .map_err(|_| corrupt())?;
    let replay = hex(&filing.grant.replay_id);
    let previous = generation.checked_sub(1).ok_or_else(corrupt)?;

    if from == 0 {
        let grant = unhex_vec(&r.capability_grant)?;
        if client.file_capability_grant(access, &grant).await? != grant {
            return Err(mismatch());
        }
        answered(state, save, 1)?;
    }
    if from <= 1 {
        let stored = match client
            .create_root_generation(access, &tenant, &create_bytes)
            .await
        {
            // Another PREPARING root (a lost run's, Q-24): the operator
            // discards it (`root discard-preparing`), then this run resumes.
            Err(e) if refused_with(&e, 409, Some("ROOT_GENERATION_MISMATCH")) => {
                return Err(code("fleet.rootRotationStuck"));
            }
            stored => stored?,
        };
        let created = TenantRootGenerationCreatedV2::parse(&stored_payload(
            &stored,
            &create,
            RECORD_TYPE_ROOT_GENERATION_CREATED,
        )?)
        .map_err(|_| mismatch())?;
        let rotates = matches!(created.mode, RootGenerationMode::Rotation {
            previous_root_generation, ..
        } if previous_root_generation == previous);
        if created.target != target || !rotates {
            return Err(mismatch());
        }
        eprintln!("[root-rotation] generation {generation} PREPARING");
        answered(state, save, 2)?;
    }
    if from <= 2 {
        let stored = client
            .file_root_grant(access, &tenant, generation, &filing_bytes)
            .await?;
        let created = TenantRootGrantCreatedV2::parse(&stored_payload(
            &stored,
            &filing_request,
            RECORD_TYPE_ROOT_GRANT_CREATED,
        )?)
        .map_err(|_| mismatch())?;
        if created.grant != filing.grant {
            return Err(mismatch());
        }
        answered(state, save, 3)?;
    }
    if from <= 3 {
        // The grant reads back as exactly what was filed, live, and opens to
        // the new TRK.
        let read = client
            .read_root_grant(access, &tenant, generation, &replay)
            .await?;
        let descriptor =
            TenantRootGrantDescriptorV2::parse(&read, own_pk).map_err(|_| mismatch())?;
        let opens = match descriptor.record().payload() {
            Payload::TenantRootKeyGrant(g) => g
                .open_trk(hpke_secret)
                .is_ok_and(|opened| *opened == *new_trk),
            _ => false,
        };
        let live = matches!(
            descriptor.grant_state(),
            RootGrantState::PendingAck | RootGrantState::Acknowledged
        ) && matches!(
            descriptor.generation_state(),
            RootGenerationState::Preparing
        );
        if descriptor.record().record().exact_signed_container_bytes()
            != filing.exact_signed_grant_container_bytes
            || !opens
            || !live
        {
            bail!(crate::errcode::code("fleet.custodyGrantMismatch"));
        }
        let (request, bytes) = saved(&r.ack_request)?;
        let stored = client
            .ack_root_grant(access, &tenant, generation, &replay, &bytes)
            .await?;
        let acked = TenantRootGrantAckedV2::parse(&stored_payload(
            &stored,
            &request,
            RECORD_TYPE_ROOT_GRANT_ACKED,
        )?)
        .map_err(|_| mismatch())?;
        if acked.grant != filing.grant {
            return Err(mismatch());
        }
        answered(state, save, 4)?;
    }
    for i in 0..n {
        let (file_step, ack_step) = (4 + 2 * i, 5 + 2 * i);
        let (request, bytes) = saved(&r.recovery_requests[i])?;
        let grant = FleetKeyGrantCreateV2::parse(&request.canonical_payload_bytes)
            .map_err(|_| corrupt())?
            .grant;
        let fleet = hex(&grant.generation.fleet_id);
        let fleet_generation = grant.generation.generation;
        if from <= file_step {
            let stored = client
                .file_fleet_grant(access, &fleet, fleet_generation, &bytes)
                .await?;
            let created = FleetKeyGrantCreatedV2::parse(&stored_payload(
                &stored,
                &request,
                RECORD_TYPE_FLEET_GRANT_CREATED,
            )?)
            .map_err(|_| mismatch())?;
            if created.grant != grant {
                return Err(mismatch());
            }
            answered(state, save, file_step + 1)?;
        }
        if from <= ack_step {
            let (request, bytes) = saved(&r.recovery_ack_requests[i])?;
            let stored = client
                .ack_fleet_grant(access, &fleet, fleet_generation, &bytes)
                .await?;
            let acked = FleetKeyGrantAckedV2::parse(&stored_payload(
                &stored,
                &request,
                RECORD_TYPE_FLEET_GRANT_ACKED,
            )?)
            .map_err(|_| mismatch())?;
            if acked.grant != grant {
                return Err(mismatch());
            }
            answered(state, save, ack_step + 1)?;
        }
    }

    let last = 4 + 2 * n;
    if from <= last {
        // Activation acknowledges the device holds the pinned bundle (L819).
        check_bundle(recovery, &target.recovery_bundle_sha256, new_trk)?;
        let (request, bytes) = saved(&r.activate_request)?;
        let stored = match client
            .activate_root_generation(access, &tenant, generation, &bytes)
            .await
        {
            // D-5: a fleet generation (a stuck PREPARING one) has no
            // recovery grant under the new root; the run waits for its discard.
            Err(e) if refused_with(&e, 409, Some("ROOT_GENERATION_MISMATCH")) => {
                return Err(code("fleet.rootRotationWaitsForFleetDiscard"));
            }
            // A quarantined fleet grant refuses the whole D-5 check.
            Err(e) if refused_with(&e, 422, Some("AUTH_CLAIM_COLUMN_MISMATCH")) => {
                return Err(code("fleet.rootRotationBlockedByQuarantine"));
            }
            stored => stored?,
        };
        let activated = TenantRootGenerationActivatedV2::parse(&stored_payload(
            &stored,
            &request,
            RECORD_TYPE_ROOT_GENERATION_ACTIVATED,
        )?)
        .map_err(|_| mismatch())?;
        let follows = activated
            .previous
            .is_some_and(|p| p.root_generation == previous);
        if activated.target != target || !follows {
            return Err(mismatch());
        }
        eprintln!("[root-rotation] generation {generation} ACTIVE");
        answered(state, save, last + 1)?;
    }
    Ok(())
}

/// Whether `e`, the failure of the step the run saved as next, shows that
/// `N + 1` was discarded by the operator (D2): before the root grant was
/// filed, the server refuses it because no PREPARING generation is there, or
/// a replay of it no longer finds its row; after, the grant no longer reads
/// back.
async fn discarded(
    client: &FleetClient,
    access: &str,
    state: &BootstrapState,
    e: &anyhow::Error,
) -> Result<bool> {
    let Some(r) = state.root_rotation.as_ref().filter(|r| r.step >= 2) else {
        return Ok(false);
    };
    if r.step == 2 {
        return Ok(refused_with(e, 409, Some("ROOT_GENERATION_MISMATCH"))
            || refused_with(e, 422, Some("MUTATION_RESPONSE_MISMATCH")));
    }
    // A moved or replaced bundle stops the run before activation, locally:
    // the server is asked too, so a discarded run still ends.
    if !refused_for_good(e)
        && !crate::errcode::has_code(&e.to_string(), "fleet.recoveryBundleChanged")
    {
        return Ok(false);
    }
    let (request, _) = saved(&r.root_grant_request)?;
    let filing =
        TenantRootGrantCreateV2::parse(&request.canonical_payload_bytes).map_err(|_| corrupt())?;
    let read = client
        .read_root_grant(
            access,
            &state.tenant_id,
            r.generation,
            &hex(&filing.grant.replay_id),
        )
        .await;
    Ok(matches!(read, Err(e) if refused_with(&e, 404, None)))
}

/// Root key rotation (sequence RR) over this root custodian's session
/// `access`, under the custody lock the caller holds, after its renewal
/// step. A run in progress resumes at its saved step with its saved bytes;
/// otherwise RR step 1 refusals apply, then a new run is started from the
/// ACTIVE root `N`. `local_keys` is every verified key of the tenant fleet
/// this device holds; `recovery` is where the new bundle goes (a resumed run
/// passes the path it saved). `Ok` means `N + 1` is ACTIVE and its
/// `RotationGrant` is this device's current root grant.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn rotate_root(
    client: &FleetClient,
    access: &str,
    me: &RenewingDevice<'_>,
    vault: &dyn TrkStore,
    ledger: &mut Ledger<'_>,
    custody: &FleetCustodyState,
    local_keys: &[(u64, Zeroizing<[u8; 32]>)],
    recovery: &RecoveryExport<'_>,
    local_now: u64,
    state: &mut BootstrapState,
    save: &mut impl FnMut(&BootstrapState) -> Result<()>,
) -> Result<()> {
    if !state.activated {
        return Err(code("fleet.notCustodian"));
    }
    crate::fleet_custody::refuse_handed_over(custody)?;
    // A finished run stopped before its key was released finishes that.
    if state
        .root_rotation
        .as_ref()
        .is_some_and(|r| r.done && !r.trk_nonce.is_empty())
    {
        return release_trk(vault, state, save);
    }
    let cx = renewal_context(state, me)?;
    let id = client.server_identity(access).await?;
    let instance =
        decode_hex16(&id.server_instance_id, "server_instance_id").map_err(|_| mismatch())?;
    let epoch = u64::try_from(id.restore_epoch).map_err(|_| mismatch())?;
    if instance != cx.instance || epoch != cx.epoch {
        return Err(code("fleet.custodyServerChanged"));
    }
    let (current, _, _) = current_root_grant(state, me.signer)?;
    let (hpke_secret, _) = derive_keypair(me.hpke_seed);
    let fresh = !unfinished(state);
    if fresh {
        refuse_start(state, custody)?;
    }
    // Steps 1 and 2 refuse before anything is saved or filed; a run whose
    // requests are not saved yet reads the evidence again.
    let retained = if fresh
        || state
            .root_rotation
            .as_ref()
            .is_some_and(|r| r.create_request.is_empty())
    {
        // Root N's bundle is the only one that restores until N + 1 activates.
        let current_bundle = std::path::Path::new(&state.recovery_path);
        let same = |a: &std::path::Path, b: &std::path::Path| {
            a == b
                || matches!((std::fs::canonicalize(a), std::fs::canonicalize(b)), (Ok(a), Ok(b)) if a == b)
        };
        if !state.recovery_path.is_empty() && same(recovery.path, current_bundle) {
            return Err(code("fleet.rootRotationBundlePathInUse"));
        }
        let old_trk = current.open_trk(&hpke_secret).map_err(|_| corrupt())?;
        Some(
            retained_keys(
                client, access, ledger, &cx, &current, &old_trk, local_keys, local_now,
            )
            .await?,
        )
    } else {
        None
    };
    if fresh {
        let generation = current
            .root_generation
            .checked_add(1)
            .ok_or_else(mismatch)?;
        commit(state, save, |s| {
            s.root_rotation = Some(RootRotation {
                generation,
                ..Default::default()
            })
        })?;
        eprintln!(
            "[root-rotation] start: generation {} to {generation}",
            current.root_generation
        );
    }
    let generation = state.root_rotation.as_ref().ok_or_else(corrupt)?.generation;
    if current.root_generation.checked_add(1) != Some(generation) {
        return Err(corrupt());
    }
    let own = me.signer.verifying_key().to_bytes();
    let new_trk = hold_trk(vault, &own, &hpke_secret, state, save)?;
    if let Some(retained) = retained {
        build(
            &cx, me, &current, &new_trk, retained, recovery, local_now, state, save,
        )?;
    }

    let sent = send(
        client,
        access,
        &cx,
        &own,
        &hpke_secret,
        &new_trk,
        recovery,
        state,
        save,
    )
    .await;
    if let Err(e) = sent {
        if discarded(client, access, state, &e).await? {
            // One save ends the run: a crash before it resumes into the
            // same discard, its TRK reopened from the RotationGrant.
            forget_trk(vault, state)?;
            commit(state, save, |s| s.root_rotation = None)?;
            eprintln!("[root-rotation] generation {generation} was discarded");
            return Err(code("fleet.rootRotationDiscarded"));
        }
        return Err(e);
    }

    // 6. One save makes the RotationGrant the current root grant, with the
    // new bundle and the fleet rotation it asks for; then the stored copy of
    // the new TRK goes.
    let r = state.root_rotation.clone().ok_or_else(corrupt)?;
    let issuer = hex(me.signer.verifying_key().as_bytes());
    commit(state, save, |s| {
        s.root_grant = r.root_grant.clone();
        s.root_grant_issuer = issuer;
        s.recovery_bundle_sha256 = r.recovery_bundle_sha256.clone();
        s.recovery_path = r.recovery_path.clone();
        s.fleet_rotation_due_after_root = Some(r.generation);
        rotation_mut(s).done = true;
    })?;
    release_trk(vault, state, save)
}

/// D8: a fleet rotation whose `RecoveryGrant`, signed by `issuer`, is under
/// the root generation a root rotation activated ends that prompt.
pub(crate) fn fleet_rotated(
    recovery_grant: &[u8],
    issuer: &[u8; 32],
    state: &mut BootstrapState,
    save: &mut impl FnMut(&BootstrapState) -> Result<()>,
) -> Result<()> {
    let Some(due) = state.fleet_rotation_due_after_root else {
        return Ok(());
    };
    let under = AuthorizationRecord::parse(recovery_grant)
        .and_then(|r| r.verify_signature(issuer))
        .ok()
        .and_then(|v| match v.payload() {
            Payload::RecoveryGrant(g) => Some(g.recipient_root_generation),
            _ => None,
        });
    if under.is_some_and(|g| g >= due) {
        commit(state, save, |s| s.fleet_rotation_due_after_root = None)?;
    }
    Ok(())
}
