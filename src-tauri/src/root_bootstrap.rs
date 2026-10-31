//! First-device custody bootstrap (ADR 0001 D1 and S6; ADR 0002 D-5).
//!
//! The first device of a tenant becomes its root custodian. Once the operator
//! has confirmed it (`tenant confirm-first-device`), the device:
//!
//! 1. approves itself (D1);
//! 2. creates the tenant root key (TRK) and seals it to itself in the first
//!    root self-grant;
//! 3. exports the recovery bundle, re-reads it and checks it opens;
//! 4. files root generation 0, which pins the bundle's hash;
//! 5. reads the grant back, acknowledges it and activates the generation.
//!
//! Every request is built once and kept, as exact bytes, in the bootstrap
//! state before it leaves the device. A retry after a crash or a lost reply
//! resends the same bytes, and the server answers a replay with its stored
//! response. The TRK is stored before anything that names it is sent, so the
//! key never exists only on the server. It lives in the credential store
//! (OS store, else the key file) under a stable reference; the state keeps
//! that reference and never the key. Every reply is checked against the
//! request it answers before the next step runs.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use shardx_core::approval_receipt::{device_approve_request_hash, DeviceApprovalReceiptV2};
use shardx_core::authz_record::{
    build_record, ApprovalScopeKind, AuthorizationRecord, CommonFields, DeviceApprovalV2, Payload,
    RootGrantVariant, TenantRootKeyGrantV2, DOMAIN_DEVICE_APPROVAL, DOMAIN_TENANT_ROOT_KEY_GRANT,
};
use shardx_core::grants::{derive_keypair, seal_trk};
use shardx_core::keys::{fill_random, hpke_key_id, root_key_id, signing_key_id};
use shardx_core::mutation::{
    root_custodian_grant_set_hash, EmbeddedSelfGrant, IdempotentMutationRequestV2,
    IdempotentStoredResponseV2, OperationKind, RootGenerationMode, RootGenerationState,
    RootGenerationTarget, RootGrantRef, RootGrantState, TenantRootGenerationActivateV2,
    TenantRootGenerationActivatedV2, TenantRootGenerationCreateV2, TenantRootGenerationCreatedV2,
    TenantRootGrantAckV2, TenantRootGrantAckedV2, TenantRootGrantDescriptorV2,
    RECORD_TYPE_ROOT_GENERATION_ACTIVATED, RECORD_TYPE_ROOT_GENERATION_CREATED,
    RECORD_TYPE_ROOT_GRANT_ACKED,
};
use shardx_core::recovery_bundle::{self as rb, RecoveryBundlePlaintextV2};
use shardx_core::signing::Ed25519SigningKey;
use shardx_core::trust_chain::{Binding, Evidence, TrustChain};

use crate::fleet_client::{decode_hex, decode_hex16, hex, AccountLogin, FleetClient};

const DAY_MS: u64 = 86_400_000;
/// The approval and the self-grant run a year; renewal comes with the
/// custodian ledger (W6).
const VALIDITY_MS: u64 = 365 * DAY_MS;
/// Backdated so a server clock slightly behind this one accepts it.
const CLOCK_SKEW_MS: u64 = 60_000;
const _: () = assert!(VALIDITY_MS <= shardx_core::approval_receipt::MAX_DEVICE_APPROVAL_TTL_MS);

/// Where the TRK lives while the bootstrap runs, under the reference
/// [`trk_ref`] names.
pub trait TrkStore: Sync {
    fn store(&self, credential_ref: &str, key: &[u8; 32]) -> Result<()>;
    fn load(&self, credential_ref: &str) -> Result<Zeroizing<[u8; 32]>>;
    fn forget(&self, credential_ref: &str) -> Result<()>;
}

/// The launcher's credential store: the OS store, else the open key file.
pub struct CredentialTrkStore;

impl TrkStore for CredentialTrkStore {
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

/// What the bootstrap keeps between attempts, hex-encoded, written before
/// each request leaves the device. The TRK is not among it: only the
/// reference it is stored under.
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct BootstrapState {
    #[serde(default)]
    pub tenant_id: String,
    #[serde(default)]
    pub device_id: String,
    #[serde(default)]
    pub server_instance_id: String,
    #[serde(default)]
    pub restore_epoch: u64,
    /// The exact D1 approval container.
    #[serde(default)]
    pub approval: String,
    /// Names this run's TRK: saved before the key is stored, it makes the
    /// reference unique, so a key an abandoned run left is never picked up.
    #[serde(default)]
    pub trk_nonce: String,
    /// The credential reference of the TRK, from its creation until the
    /// generation is active and the key is forgotten.
    #[serde(default)]
    pub trk_ref: String,
    /// A TRK that an earlier launcher wrote here in the clear. It is read to
    /// be moved into the credential store and never written back.
    #[serde(default, rename = "trk", skip_serializing)]
    pub legacy_trk: Zeroizing<String>,
    /// The exact first root self-grant container.
    #[serde(default)]
    pub self_grant: String,
    #[serde(default)]
    pub recovery_bundle_sha256: String,
    /// Where that bundle was written: activation checks it is still there.
    #[serde(default)]
    pub recovery_path: String,
    #[serde(default)]
    pub create_request: String,
    #[serde(default)]
    pub ack_request: String,
    #[serde(default)]
    pub activate_request: String,
    #[serde(default)]
    pub activated: bool,
    /// The bootstrap anchor `A0` the server's trust evidence verified to:
    /// this device's own signing key ID.
    #[serde(default)]
    pub anchor: String,
}

impl std::fmt::Debug for BootstrapState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapState")
            .field("tenant_id", &self.tenant_id)
            .field("device_id", &self.device_id)
            .field("trk_ref", &self.trk_ref)
            .field("legacy_trk", &"<redacted>")
            .field("activated", &self.activated)
            .finish_non_exhaustive()
    }
}

/// The enrolled device that bootstraps custody, and the account it acts as.
pub struct BootstrapDevice<'a> {
    pub login: AccountLogin<'a>,
    pub device_id: &'a str,
    pub account_id: &'a str,
    pub signer: &'a Ed25519SigningKey,
    pub hpke_seed: &'a [u8; 32],
    pub trk_store: &'a dyn TrkStore,
}

/// Where the recovery bundle goes, and the passphrase it is sealed under.
pub struct RecoveryExport<'a> {
    pub path: &'a Path,
    pub passphrase: &'a str,
}

fn mismatch() -> anyhow::Error {
    anyhow!(crate::errcode::code("fleet.custodyReplyMismatch"))
}

fn corrupt() -> anyhow::Error {
    anyhow!(crate::errcode::code("fleet.custodyStateCorrupt"))
}

/// A saved state field: anything that does not decode is a damaged file.
fn unhex<const N: usize>(s: &str) -> Result<[u8; N]> {
    unhex_vec(s)?.try_into().map_err(|_| corrupt())
}

fn unhex_vec(s: &str) -> Result<Vec<u8>> {
    decode_hex(s).ok_or_else(corrupt)
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    fill_random(&mut out).map_err(|_| anyhow!(crate::errcode::code("fleet.custodyEntropy")))?;
    Ok(out)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The facts every built record and request names.
struct Context16 {
    tenant: [u8; 16],
    instance: [u8; 16],
    epoch: u64,
    account: [u8; 16],
    device: [u8; 16],
    signing_key_id: [u8; 32],
    hpke_key_id: [u8; 32],
}

impl Context16 {
    fn common(&self, replay_id: [u8; 16], now: u64) -> CommonFields {
        let start = now.saturating_sub(CLOCK_SKEW_MS);
        CommonFields {
            replay_id,
            tenant_id: self.tenant,
            issued_at_ms: start,
            not_before_ms: start,
            not_after_ms: start + VALIDITY_MS,
            server_instance_id: self.instance,
            restore_epoch: self.epoch,
        }
    }

    fn request(&self, kind: OperationKind, payload: Vec<u8>) -> Result<Vec<u8>> {
        Ok(IdempotentMutationRequestV2 {
            operation_kind: kind,
            idempotency_key: random()?,
            canonical_payload_bytes: payload,
            client_request_nonce: random()?,
            server_instance_id: self.instance,
            restore_epoch: self.epoch,
        }
        .encode())
    }
}

/// The D1 self-approval: this device, tenant-wide.
fn self_approval(cx: &Context16, signer: &Ed25519SigningKey, now: u64) -> Result<Vec<u8>> {
    let payload = DeviceApprovalV2 {
        common: cx.common(random()?, now),
        subject_account_id: cx.account,
        subject_device_id: cx.device,
        subject_signing_key_id: cx.signing_key_id,
        subject_hpke_key_id: cx.hpke_key_id,
        approval_scope_kind: ApprovalScopeKind::Tenant,
        approval_scope_id: cx.tenant,
    }
    .encode();
    Ok(build_record(signer, DOMAIN_DEVICE_APPROVAL, &payload))
}

/// The first root self-grant of `trk`, sealed to this device's HPKE key.
fn self_grant(
    cx: &Context16,
    signer: &Ed25519SigningKey,
    hpke_public_key: &[u8],
    trk: &[u8; 32],
    approval_replay_id: [u8; 16],
    now: u64,
) -> Result<Vec<u8>> {
    let mut g = TenantRootKeyGrantV2 {
        common: cx.common(random()?, now),
        variant: RootGrantVariant::FirstRootSelfGrant,
        root_key_id: root_key_id(trk),
        root_generation: 0,
        subject_account_id: cx.account,
        subject_device_id: cx.device,
        subject_signing_key_id: cx.signing_key_id,
        recipient_hpke_key_id: cx.hpke_key_id,
        subject_device_approval_replay_id: approval_replay_id,
        hpke_encapped_key_bytes: [0; 32],
        hpke_wrapped_trk_bytes: [0; 48],
    };
    let sealed = seal_trk(hpke_public_key, &g.scope(), trk)
        .map_err(|_| anyhow!(crate::errcode::code("fleet.custodySealFailed")))?;
    g.hpke_encapped_key_bytes = sealed
        .encapped_key_bytes
        .try_into()
        .map_err(|_| anyhow!(crate::errcode::code("fleet.custodySealFailed")))?;
    g.hpke_wrapped_trk_bytes = sealed
        .ciphertext_bytes
        .try_into()
        .map_err(|_| anyhow!(crate::errcode::code("fleet.custodySealFailed")))?;
    Ok(build_record(
        signer,
        DOMAIN_TENANT_ROOT_KEY_GRANT,
        &g.encode(),
    ))
}

/// The self-grant as this device filed it, verified under its own key.
fn own_grant(
    container: &[u8],
    signer: &Ed25519SigningKey,
) -> Result<(TenantRootKeyGrantV2, RootGrantRef)> {
    let v = AuthorizationRecord::parse(container)
        .and_then(|r| r.verify_signature(signer.verifying_key().as_bytes()))
        .map_err(|_| anyhow!(crate::errcode::code("fleet.custodyStateCorrupt")))?;
    let Payload::TenantRootKeyGrant(g) = v.payload() else {
        bail!(crate::errcode::code("fleet.custodyStateCorrupt"));
    };
    let grant_ref = RootGrantRef {
        tenant_id: g.common.tenant_id,
        server_instance_id: g.common.server_instance_id,
        restore_epoch: g.common.restore_epoch,
        root_generation: g.root_generation,
        root_key_id: g.root_key_id,
        replay_id: g.common.replay_id,
        signed_container_hash: *v.record().signed_container_hash(),
        exact_signed_container_bytes_sha256: *v.record().exact_signed_container_bytes_sha256(),
    };
    Ok((g.clone(), grant_ref))
}

/// The D1 receipt must answer exactly this device's approval of itself, as
/// the first device: it consumes the operator's confirmation.
fn check_receipt(
    receipt: &[u8],
    cx: &Context16,
    approval: &[u8],
    approval_replay: [u8; 16],
) -> Result<()> {
    let r = DeviceApprovalReceiptV2::parse(receipt).map_err(|_| mismatch())?;
    let expected_hash = device_approve_request_hash(
        &cx.instance,
        cx.epoch,
        &cx.tenant,
        &cx.account,
        &cx.device,
        &cx.device,
        approval,
    );
    let answers = r.request_hash == expected_hash
        && r.server_instance_id == cx.instance
        && r.restore_epoch == cx.epoch
        && r.tenant_id == cx.tenant
        && r.actor_account_id == cx.account
        && r.actor_device_id == cx.device
        && r.subject_device_id == cx.device
        && r.approval_replay_id == approval_replay
        && r.confirmation_id.is_some();
    if !answers {
        return Err(mismatch());
    }
    Ok(())
}

/// The payload of a stored response, once it answers exactly `request` with
/// a `record_type` record.
fn stored_payload(
    stored: &[u8],
    request: &IdempotentMutationRequestV2,
    record_type: &str,
) -> Result<Vec<u8>> {
    let s = IdempotentStoredResponseV2::parse(stored).map_err(|_| mismatch())?;
    let answers = s.operation_kind == request.operation_kind
        && s.idempotency_key == request.idempotency_key
        && s.exact_request_hash == request.canonical_request_hash()
        && s.server_instance_id == request.server_instance_id
        && s.restore_epoch == request.restore_epoch
        && s.response_record_type == record_type;
    if !answers {
        return Err(mismatch());
    }
    Ok(s.canonical_response_payload_bytes)
}

/// Writes the bundle, re-reads it from its final path and checks it opens
/// (L819, L1387). Returns the hash the create request pins.
fn export_recovery_bundle(
    cx: &Context16,
    trk: &[u8; 32],
    recovery: &RecoveryExport<'_>,
    now: u64,
) -> Result<[u8; 32]> {
    let failed = || crate::errcode::code("fleet.recoveryExportFailed");
    let plaintext = RecoveryBundlePlaintextV2 {
        trk: (*trk).into(),
        bootstrap_anchor_signing_key_id: cx.signing_key_id,
        retained_fkeks: Vec::new(),
    };
    let (header, file) = rb::seal(
        cx.tenant,
        cx.instance,
        0,
        now,
        &plaintext,
        recovery.passphrase,
    )
    .map_err(|e| anyhow!(e).context(failed()))?;
    crate::durable::write_private(recovery.path, &file).with_context(failed)?;
    let reread = std::fs::read(recovery.path).with_context(failed)?;
    rb::verify_export(&reread, recovery.passphrase, &header)
        .map_err(|e| anyhow!(e).context(failed()))
}

/// The bundle at `recovery.path` is the pinned one and still opens to `trk`.
fn check_bundle(recovery: &RecoveryExport<'_>, pinned: &[u8; 32], trk: &[u8; 32]) -> Result<()> {
    let changed = || anyhow!(crate::errcode::code("fleet.recoveryBundleChanged"));
    let file = std::fs::read(recovery.path).map_err(|_| changed())?;
    if rb::recovery_bundle_sha256(&file) != *pinned {
        return Err(changed());
    }
    match rb::open(&file, recovery.passphrase) {
        Ok((_, plaintext)) if *plaintext.trk == *trk => Ok(()),
        _ => Err(changed()),
    }
}

/// Applies `change` to a copy of `state`, saves the copy, and only then
/// replaces `state`: what the caller holds is always what is on disk.
fn commit(
    state: &mut BootstrapState,
    save: &mut impl FnMut(&BootstrapState) -> Result<()>,
    change: impl FnOnce(&mut BootstrapState),
) -> Result<()> {
    let mut next = state.clone();
    change(&mut next);
    save(&next)?;
    *state = next;
    Ok(())
}

/// A run nonce: 16 random bytes, lower-case hex.
fn nonce_ok(nonce: &str) -> bool {
    nonce.len() == 32
        && nonce
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The reference the TRK of one run of `tenant_hex` is stored under.
fn trk_ref(tenant_hex: &str, nonce: &str) -> String {
    format!("tenant-root.{}.{nonce}", tenant_hex.to_ascii_lowercase())
}

/// The reference the state names, once it is the one this tenant's run stored
/// its TRK under: a saved file that points at any other credential is
/// damaged, and must not make the bootstrap read or delete it.
fn own_trk_ref(state: &BootstrapState) -> Result<String> {
    let name = trk_ref(&state.tenant_id, &state.trk_nonce);
    if nonce_ok(&state.trk_nonce) && state.trk_ref == name {
        Ok(name)
    } else {
        Err(corrupt())
    }
}

/// This run's reference. The nonce is saved first: whatever is stored under
/// the reference afterwards belongs to this run.
fn run_ref(
    state: &mut BootstrapState,
    save: &mut impl FnMut(&BootstrapState) -> Result<()>,
) -> Result<String> {
    if state.trk_nonce.is_empty() {
        let nonce = hex(&random::<16>()?);
        commit(state, save, |s| s.trk_nonce = nonce)?;
    }
    if !nonce_ok(&state.trk_nonce) {
        return Err(corrupt());
    }
    Ok(trk_ref(&state.tenant_id, &state.trk_nonce))
}

/// A hex secret, decoded straight into memory that is wiped on drop.
fn unhex_secret(s: &str) -> Result<Zeroizing<[u8; 32]>> {
    let digits = s.as_bytes();
    if digits.len() != 64 {
        return Err(corrupt());
    }
    let mut out = Zeroizing::new([0u8; 32]);
    for (byte, pair) in out.iter_mut().zip(digits.chunks(2)) {
        let digit = |c: u8| (c as char).to_digit(16).ok_or_else(corrupt);
        *byte = (digit(pair[0])? * 16 + digit(pair[1])?) as u8;
    }
    Ok(out)
}

/// The TRK the state names, from the credential store. A locked or
/// unavailable store, or a missing key, stops the run with its credential
/// error: the key is never made up again.
fn load_trk(vault: &dyn TrkStore, state: &BootstrapState) -> Result<Zeroizing<[u8; 32]>> {
    vault.load(&own_trk_ref(state)?)
}

fn is_missing(e: &anyhow::Error) -> bool {
    crate::errcode::has_code(&e.to_string(), "credential.missing")
}

/// Stores a new TRK and only then saves its reference, so the key is held
/// before anything names it. A key under this run's reference, left by a run
/// that stopped between the two, was named by nothing yet and is reused, not
/// overwritten.
fn create_trk(
    vault: &dyn TrkStore,
    state: &mut BootstrapState,
    save: &mut impl FnMut(&BootstrapState) -> Result<()>,
) -> Result<()> {
    let name = run_ref(state, save)?;
    match vault.load(&name) {
        Ok(_) => {}
        Err(e) if is_missing(&e) => vault.store(&name, &Zeroizing::new(random::<32>()?))?,
        Err(e) => return Err(e),
    }
    commit(state, save, |s| s.trk_ref = name)
}

/// Deletes the TRK from the credential store, then drops its reference. The
/// reference stays until the key is gone, so a store that refuses is retried.
fn release_trk(
    vault: &dyn TrkStore,
    state: &mut BootstrapState,
    save: &mut impl FnMut(&BootstrapState) -> Result<()>,
) -> Result<()> {
    if state.trk_ref.is_empty() {
        return Ok(());
    }
    vault.forget(&own_trk_ref(state)?)?;
    commit(state, save, |s| {
        s.trk_ref.clear();
        s.trk_nonce.clear();
    })
}

/// Marks the generation active and saves that first. Only then is the stored
/// TRK forgotten: a crash between the two resumes with the key still there,
/// where the other order would leave a state that must make a second TRK.
fn finish_activation(
    vault: &dyn TrkStore,
    state: &mut BootstrapState,
    save: &mut impl FnMut(&BootstrapState) -> Result<()>,
    anchor: String,
) -> Result<()> {
    commit(state, save, |s| {
        s.anchor = anchor;
        s.activated = true;
    })?;
    release_trk(vault, state, save)
}

/// Deals with a TRK that an earlier launcher saved in the clear.
///
/// With no self-grant, recovery bundle or create request saved, nothing
/// outside this device ever named that key: it is dropped, and the run makes a
/// fresh one in the store. Otherwise it moves into the store under a
/// reference of this run. A reference already set, or a different key already
/// held there, is a damaged state and is never overwritten.
///
/// Nothing is saved until the store holds the key: the nonce is only made in
/// memory (any save would drop the legacy key from the file), and one commit
/// then clears the legacy key and sets the nonce and reference together. If
/// the store refuses, or the run stops before that commit, the old file still
/// has the key, and a rerun reuses the copy already stored under that nonce.
fn migrate_legacy_trk(
    vault: &dyn TrkStore,
    state: &mut BootstrapState,
    save: &mut impl FnMut(&BootstrapState) -> Result<()>,
) -> Result<()> {
    if state.legacy_trk.is_empty() {
        return Ok(());
    }
    if state.tenant_id.is_empty() || !state.trk_ref.is_empty() {
        return Err(corrupt());
    }
    let key = unhex_secret(&state.legacy_trk)?;
    if state.self_grant.is_empty()
        && state.recovery_bundle_sha256.is_empty()
        && state.create_request.is_empty()
    {
        return commit(state, save, |s| s.legacy_trk.zeroize());
    }
    // Derived from the public root key ID, so a rerun after a crash before the
    // commit finds the same reference and the same key instead of a second copy.
    let nonce = if state.trk_nonce.is_empty() {
        hex(&root_key_id(&key)[..16])
    } else {
        state.trk_nonce.clone()
    };
    if !nonce_ok(&nonce) {
        return Err(corrupt());
    }
    let name = trk_ref(&state.tenant_id, &nonce);
    match vault.load(&name) {
        Ok(held) if *held == *key => {}
        Ok(_) => return Err(corrupt()),
        Err(e) if is_missing(&e) => vault.store(&name, &key)?,
        Err(e) => return Err(e),
    }
    commit(state, save, |s| {
        s.legacy_trk.zeroize();
        s.trk_nonce = nonce;
        s.trk_ref = name;
    })
}

/// Runs, or resumes, the bootstrap. `save` persists `state`; every step that
/// builds new bytes saves them before sending, a failed save stops the run,
/// and `state` only ever holds what `save` accepted.
pub async fn bootstrap_root(
    client: &FleetClient,
    device: &BootstrapDevice<'_>,
    recovery: &RecoveryExport<'_>,
    state: &mut BootstrapState,
    save: &mut impl FnMut(&BootstrapState) -> Result<()>,
) -> Result<()> {
    let tenant_hex = device.login.tenant_id;
    if !state.tenant_id.is_empty()
        && (state.tenant_id != tenant_hex || state.device_id != device.device_id)
    {
        bail!(crate::errcode::code("fleet.custodyOtherDevice"));
    }
    migrate_legacy_trk(device.trk_store, state, save)?;
    if state.activated {
        // An activation that stopped before the key was forgotten finishes it.
        return release_trk(device.trk_store, state, save);
    }
    let tenant = decode_hex16(tenant_hex, "tenant_id")?;
    let account = decode_hex16(device.account_id, "account_id")?;
    let device_id = decode_hex16(device.device_id, "device_id")?;

    let id = client.server_identity().await?;
    let instance =
        decode_hex16(&id.server_instance_id, "server_instance_id").map_err(|_| mismatch())?;
    let epoch = u64::try_from(id.restore_epoch).map_err(|_| mismatch())?;
    if state.server_instance_id.is_empty() {
        commit(state, save, |s| {
            s.tenant_id = tenant_hex.to_string();
            s.device_id = device.device_id.to_string();
            s.server_instance_id = hex(&instance);
            s.restore_epoch = epoch;
        })?;
    } else if state.server_instance_id != hex(&instance) || state.restore_epoch != epoch {
        // Every saved request names the old instance or epoch, so none can
        // be replayed. Before the create nothing is pinned and the state may
        // be discarded; after it, the tenant's custody needs recovery.
        bail!(crate::errcode::code("fleet.custodyServerChanged"));
    }

    let (hpke_secret, hpke_public) = derive_keypair(device.hpke_seed);
    let cx = Context16 {
        tenant,
        instance,
        epoch,
        account,
        device: device_id,
        signing_key_id: signing_key_id(device.signer.verifying_key().as_bytes()),
        hpke_key_id: hpke_key_id(&hpke_public),
    };
    let session = client
        .open_device_session(
            &device.login,
            device.device_id,
            device.signer,
            device.hpke_seed,
        )
        .await?;
    let access = session.access_token.as_str();
    let run = Run {
        client,
        device,
        recovery,
        cx: &cx,
        access,
        hpke_secret: &hpke_secret,
        hpke_public: &hpke_public,
    };
    let result = run.steps(state, save).await;
    client.end_session(access).await;
    result
}

struct Run<'a> {
    client: &'a FleetClient,
    device: &'a BootstrapDevice<'a>,
    recovery: &'a RecoveryExport<'a>,
    cx: &'a Context16,
    access: &'a str,
    hpke_secret: &'a [u8],
    hpke_public: &'a [u8],
}

impl Run<'_> {
    async fn steps(
        &self,
        state: &mut BootstrapState,
        save: &mut impl FnMut(&BootstrapState) -> Result<()>,
    ) -> Result<()> {
        let (cx, signer, tenant_hex, access) = (
            self.cx,
            self.device.signer,
            self.device.login.tenant_id,
            self.access,
        );
        let now = now_ms();

        // 1. D1. A retry resends the same approval and gets the stored receipt.
        if state.approval.is_empty() {
            let approval = hex(&self_approval(cx, signer, now)?);
            commit(state, save, |s| s.approval = approval)?;
        }
        let approval = unhex_vec(&state.approval)?;
        let approval_replay = match AuthorizationRecord::parse(&approval)
            .and_then(|r| r.verify_signature(signer.verifying_key().as_bytes()))
            .map(|v| v.payload().clone())
        {
            Ok(Payload::DeviceApproval(a)) => a.common.replay_id,
            _ => return Err(corrupt()),
        };
        let receipt = self
            .client
            .approve_device(access, self.device.device_id, &approval)
            .await?;
        check_receipt(&receipt, cx, &approval, approval_replay)?;

        // 2. The TRK is stored before anything names it.
        if state.trk_ref.is_empty() {
            create_trk(self.device.trk_store, state, save)?;
        }
        let trk = load_trk(self.device.trk_store, state)?;
        if state.self_grant.is_empty() {
            let grant = hex(&self_grant(
                cx,
                signer,
                self.hpke_public,
                &trk,
                approval_replay,
                now,
            )?);
            commit(state, save, |s| s.self_grant = grant)?;
        }
        let container = unhex_vec(&state.self_grant)?;
        let (grant, grant_ref) = own_grant(&container, signer)?;
        if grant.root_key_id != root_key_id(&trk) {
            return Err(corrupt());
        }

        // 3. The bundle, saved on its own: an export the server has not yet
        // seen is reused while it is still there and opens, else replaced.
        if state.create_request.is_empty() {
            let reusable = !state.recovery_bundle_sha256.is_empty()
                && check_bundle(self.recovery, &unhex(&state.recovery_bundle_sha256)?, &trk)
                    .is_ok();
            if !reusable {
                let sha = hex(&export_recovery_bundle(cx, &trk, self.recovery, now)?);
                let path = self.recovery.path.to_string_lossy().into_owned();
                commit(state, save, |s| {
                    s.recovery_bundle_sha256 = sha;
                    s.recovery_path = path;
                })?;
            }
            // 4. The create pins the bundle's hash.
            let hash = grant_ref.signed_container_hash;
            let create = TenantRootGenerationCreateV2 {
                target: RootGenerationTarget {
                    tenant_id: cx.tenant,
                    server_instance_id: cx.instance,
                    restore_epoch: cx.epoch,
                    root_key_id: grant.root_key_id,
                    root_generation: 0,
                    required_custodian_grant_count: 1,
                    required_custodian_grant_set_hash: root_custodian_grant_set_hash(&[hash])
                        .ok_or_else(mismatch)?,
                    recovery_bundle_sha256: unhex(&state.recovery_bundle_sha256)?,
                },
                mode: RootGenerationMode::Bootstrap(EmbeddedSelfGrant {
                    container_bytes: container.clone(),
                    signed_container_hash: hash,
                }),
            };
            let request = hex(&cx.request(OperationKind::RootGenerationCreate, create.encode())?);
            commit(state, save, |s| s.create_request = request)?;
        }
        let create = IdempotentMutationRequestV2::parse(&unhex_vec(&state.create_request)?)
            .map_err(|_| corrupt())?;
        let target = TenantRootGenerationCreateV2::parse(&create.canonical_payload_bytes)
            .map_err(|_| corrupt())?
            .target;
        let stored = self
            .client
            .create_root_generation(access, tenant_hex, &create.encode())
            .await?;
        let created = TenantRootGenerationCreatedV2::parse(&stored_payload(
            &stored,
            &create,
            RECORD_TYPE_ROOT_GENERATION_CREATED,
        )?)
        .map_err(|_| mismatch())?;
        let names_our_grant = matches!(&created.mode, RootGenerationMode::Bootstrap(id)
            if id.replay_id == grant_ref.replay_id
                && id.signed_container_hash == grant_ref.signed_container_hash
                && id.container_bytes_sha256 == grant_ref.exact_signed_container_bytes_sha256);
        if created.target != target || !names_our_grant {
            return Err(mismatch());
        }

        // 5. The grant reads back as exactly what was filed, live, and opens
        // to the TRK.
        let replay_hex = hex(&grant_ref.replay_id);
        let descriptor = self
            .client
            .read_root_grant(access, tenant_hex, 0, &replay_hex)
            .await?;
        let descriptor =
            TenantRootGrantDescriptorV2::parse(&descriptor, signer.verifying_key().as_bytes())
                .map_err(|_| mismatch())?;
        let opens = match descriptor.record().payload() {
            Payload::TenantRootKeyGrant(g) => g
                .open_trk(self.hpke_secret)
                .is_ok_and(|opened| *opened == *trk),
            _ => false,
        };
        let live = matches!(
            descriptor.grant_state(),
            RootGrantState::PendingAck | RootGrantState::Acknowledged
        ) && matches!(
            descriptor.generation_state(),
            RootGenerationState::Preparing | RootGenerationState::Active
        );
        if descriptor.record().record().exact_signed_container_bytes() != container
            || !opens
            || !live
        {
            bail!(crate::errcode::code("fleet.custodyGrantMismatch"));
        }

        if state.ack_request.is_empty() {
            let ack = TenantRootGrantAckV2 {
                grant: grant_ref.clone(),
            };
            let request = hex(&cx.request(OperationKind::RootGrantAck, ack.encode())?);
            commit(state, save, |s| s.ack_request = request)?;
        }
        let ack = IdempotentMutationRequestV2::parse(&unhex_vec(&state.ack_request)?)
            .map_err(|_| corrupt())?;
        let stored = self
            .client
            .ack_root_grant(access, tenant_hex, 0, &replay_hex, &ack.encode())
            .await?;
        let acked = TenantRootGrantAckedV2::parse(&stored_payload(
            &stored,
            &ack,
            RECORD_TYPE_ROOT_GRANT_ACKED,
        )?)
        .map_err(|_| mismatch())?;
        if acked.grant != grant_ref {
            return Err(mismatch());
        }

        // 6. Activation acknowledges that the device holds the pinned bundle
        // (L819), so the file must still be that bundle and open.
        check_bundle(self.recovery, &target.recovery_bundle_sha256, &trk)?;
        if state.activate_request.is_empty() {
            let activate = TenantRootGenerationActivateV2 {
                target: target.clone(),
                previous: None,
            };
            let request =
                hex(&cx.request(OperationKind::RootGenerationActivate, activate.encode())?);
            commit(state, save, |s| s.activate_request = request)?;
        }
        let activate = IdempotentMutationRequestV2::parse(&unhex_vec(&state.activate_request)?)
            .map_err(|_| corrupt())?;
        let stored = self
            .client
            .activate_root_generation(access, tenant_hex, 0, &activate.encode())
            .await?;
        let activated = TenantRootGenerationActivatedV2::parse(&stored_payload(
            &stored,
            &activate,
            RECORD_TYPE_ROOT_GENERATION_ACTIVATED,
        )?)
        .map_err(|_| mismatch())?;
        if activated.target != target || activated.previous.is_some() {
            return Err(mismatch());
        }

        // 7. The trust evidence the server now serves must verify on its own,
        // rooted at this device: it is the anchor every later device pins,
        // and a custodian now.
        let refused = || anyhow!(crate::errcode::code("fleet.trustEvidenceRefused"));
        let pages = self.client.trust_evidence(access, tenant_hex).await?;
        let binding = Binding {
            server_instance_id: cx.instance,
            tenant_id: cx.tenant,
        };
        let evidence = Evidence::collect(&binding, &pages).map_err(|_| refused())?;
        let chain =
            TrustChain::evaluate(evidence, Some(&cx.signing_key_id)).map_err(|_| refused())?;
        if !chain.custodian_now(&cx.signing_key_id, now_ms()) {
            return Err(refused());
        }
        // The device reopens its self-grant with its HPKE key, and the
        // recovery bundle holds the TRK: the stored copy is no longer needed.
        finish_activation(self.device.trk_store, state, save, hex(chain.anchor()))
    }
}

/// Set while a bootstrap runs in this process. The single-instance plugin
/// keeps the launcher to one process, so this is the only writer.
static RUNNING: AtomicBool = AtomicBool::new(false);

struct Running;

impl Drop for Running {
    fn drop(&mut self) {
        RUNNING.store(false, Ordering::SeqCst);
    }
}

/// Runs the bootstrap from the saved state on disk, one run at a time: a
/// second run while one is going is refused rather than queued, so two runs
/// never build different requests from the same empty state. Once a bundle
/// was written, a resumed run keeps its path and ignores `recovery_path`.
pub async fn run(
    client: &FleetClient,
    device: &BootstrapDevice<'_>,
    recovery_path: &Path,
    passphrase: &str,
) -> Result<BootstrapStatus> {
    if RUNNING.swap(true, Ordering::SeqCst) {
        bail!(crate::errcode::code("fleet.custodyBusy"));
    }
    let _running = Running;
    let mut state = load()?;
    let saved = std::path::PathBuf::from(&state.recovery_path);
    let recovery = RecoveryExport {
        path: if state.recovery_path.is_empty() {
            recovery_path
        } else {
            &saved
        },
        passphrase,
    };
    // A bootstrap returns Ok only once the generation is active.
    bootstrap_root(client, device, &recovery, &mut state, &mut |s| save(s)).await?;
    keep_records(client.base_url(), &state)?;
    Ok(BootstrapStatus::of(&state))
}

/// Files the activated generation 0, its self-grant and this device's
/// approval in the team database (plan L1510-L1744). Each run after
/// activation files what is missing and refuses a row that changed.
fn keep_records(server_url: &str, state: &BootstrapState) -> Result<()> {
    let mut db = crate::team::db::Db::open()?;
    let tx = db.conn.transaction()?;
    crate::team::records::keep_root_bootstrap(
        &tx,
        server_url,
        &unhex_vec(&state.approval)?,
        &unhex_vec(&state.self_grant)?,
        &unhex(&state.recovery_bundle_sha256)?,
        now_ms(),
    )?;
    tx.commit()?;
    Ok(())
}

/// How far the bootstrap got, for the UI: nothing of the state's secrets.
#[derive(Serialize, Debug, PartialEq)]
pub struct BootstrapStatus {
    /// Some step ran, so a new attempt resumes rather than starts over.
    pub started: bool,
    pub activated: bool,
    /// Where the recovery bundle was written, once it was.
    pub recovery_path: String,
    /// The bootstrap anchor, once the trust evidence verified to it.
    pub anchor: String,
}

impl BootstrapStatus {
    fn of(state: &BootstrapState) -> Self {
        Self {
            started: !state.tenant_id.is_empty(),
            activated: state.activated,
            recovery_path: state.recovery_path.clone(),
            anchor: state.anchor.clone(),
        }
    }
}

/// The saved bootstrap's progress.
pub fn status() -> Result<BootstrapStatus> {
    Ok(BootstrapStatus::of(&load()?))
}

/// Loads the bootstrap state; none yet is the empty state.
pub fn load() -> Result<BootstrapState> {
    let path = crate::store::custody_bootstrap_path()?;
    if !path.exists() {
        return Ok(BootstrapState::default());
    }
    let body = Zeroizing::new(std::fs::read_to_string(&path)?);
    serde_json::from_str(&body).map_err(|_| corrupt())
}

/// Saves the bootstrap state durably: a torn write or a power cut must not
/// lose a request the server may already hold.
pub fn save(state: &BootstrapState) -> Result<()> {
    let path = crate::store::custody_bootstrap_path()?;
    crate::durable::write_private(&path, serde_json::to_string_pretty(state)?.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use shardx_core::recovery_bundle::{open, recovery_bundle_sha256};

    fn signer() -> Ed25519SigningKey {
        Ed25519SigningKey::from_bytes(&[3; 32])
    }

    fn cx() -> Context16 {
        Context16 {
            tenant: [1; 16],
            instance: [2; 16],
            epoch: 0,
            account: [4; 16],
            device: [5; 16],
            signing_key_id: signing_key_id(signer().verifying_key().as_bytes()),
            hpke_key_id: [6; 32],
        }
    }

    fn approval_of(container: &[u8]) -> DeviceApprovalV2 {
        let v = AuthorizationRecord::parse(container)
            .and_then(|r| r.verify_signature(signer().verifying_key().as_bytes()))
            .unwrap();
        let Payload::DeviceApproval(a) = v.payload() else {
            panic!("an approval")
        };
        a.clone()
    }

    /// After activation, every `run` files generation 0, the self-grant and
    /// the approval in the team database without reaching the server, and
    /// they reload exactly; a second run changes nothing.
    #[test]
    fn an_activated_run_keeps_the_root_records_and_they_reload_exactly() {
        use crate::team::records::{load, ROOT_GRANTS, SIGNED};
        let _config = crate::store::config_root_test_lock()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().unwrap();
        crate::store::set_config_root(Some(dir.path().to_path_buf()));
        let seed = [7; 32];
        let (_, pk) = derive_keypair(&seed);
        let cx = Context16 {
            hpke_key_id: hpke_key_id(&pk),
            ..cx()
        };
        let now = 1_800_000_000_000;
        let approval = self_approval(&cx, &signer(), now).unwrap();
        let replay = approval_of(&approval).common.replay_id;
        let grant = self_grant(&cx, &signer(), &pk, &[9; 32], replay, now).unwrap();
        save(&BootstrapState {
            tenant_id: hex(&cx.tenant),
            device_id: hex(&cx.device),
            server_instance_id: hex(&cx.instance),
            approval: hex(&approval),
            self_grant: hex(&grant),
            recovery_bundle_sha256: hex(&[8; 32]),
            activated: true,
            anchor: hex(&cx.signing_key_id),
            ..Default::default()
        })
        .unwrap();
        // Nothing listens here: an activated run never calls the server.
        let client = FleetClient::new("http://127.0.0.1:9", "t").unwrap();
        let (tenant, device_id, account) = (hex(&cx.tenant), hex(&cx.device), hex(&cx.account));
        let signer = signer();
        let device = BootstrapDevice {
            login: AccountLogin {
                tenant_id: &tenant,
                username: "u",
                password: "p",
            },
            device_id: &device_id,
            account_id: &account,
            signer: &signer,
            hpke_seed: &seed,
            trk_store: &CredentialTrkStore,
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        for _ in 0..2 {
            let status = rt.block_on(run(&client, &device, Path::new("unused"), "pass"));
            assert!(status.unwrap().activated);
        }
        let db = crate::team::db::Db::open();
        crate::store::set_config_root(None);
        let db = db.unwrap();
        let hash = |c: &[u8]| {
            *AuthorizationRecord::parse(c)
                .unwrap()
                .signed_container_hash()
        };
        assert_eq!(load(&db.conn, ROOT_GRANTS, &hash(&grant)).unwrap(), grant);
        assert_eq!(load(&db.conn, SIGNED, &hash(&approval)).unwrap(), approval);
        let generation: (i64, String, String, Vec<u8>, i64, Vec<u8>, i64) = db
            .conn
            .query_row(
                "SELECT root_generation, root_key_id, state, recovery_bundle_sha256,
                   required_custodian_grant_count, required_custodian_grant_set_hash,
                   (SELECT count(*) FROM tenant_root_key_generations)
                 FROM tenant_root_key_generations",
                [],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                },
            )
            .unwrap();
        let set = root_custodian_grant_set_hash(&[hash(&grant)]).unwrap();
        assert_eq!(
            generation,
            (
                0,
                hex(&root_key_id(&[9; 32])),
                "ACTIVE".into(),
                vec![8; 32],
                1,
                set.to_vec(),
                1
            )
        );
    }

    #[test]
    fn the_self_approval_names_this_device_tenant_wide_for_a_year() {
        let now = 1_800_000_000_000;
        let a = approval_of(&self_approval(&cx(), &signer(), now).unwrap());
        assert_eq!(
            (
                a.subject_device_id,
                a.subject_account_id,
                a.approval_scope_id
            ),
            ([5; 16], [4; 16], [1; 16])
        );
        assert_eq!(a.approval_scope_kind, ApprovalScopeKind::Tenant);
        assert_eq!(a.subject_signing_key_id, cx().signing_key_id);
        assert_eq!(a.common.not_before_ms, now - CLOCK_SKEW_MS);
        assert_eq!(a.common.not_after_ms - a.common.not_before_ms, VALIDITY_MS);
    }

    #[test]
    fn the_self_grant_seals_the_trk_to_this_device_and_links_the_approval() {
        let seed = [7; 32];
        let (sk, pk) = derive_keypair(&seed);
        let cx = Context16 {
            hpke_key_id: hpke_key_id(&pk),
            ..cx()
        };
        let trk = [9; 32];
        let container = self_grant(&cx, &signer(), &pk, &trk, [8; 16], 1_800_000_000_000).unwrap();
        let (g, grant_ref) = own_grant(&container, &signer()).unwrap();
        assert_eq!(g.variant, RootGrantVariant::FirstRootSelfGrant);
        assert_eq!((g.root_generation, g.root_key_id), (0, root_key_id(&trk)));
        assert_eq!(g.subject_device_approval_replay_id, [8; 16]);
        assert_eq!(*g.open_trk(&sk).unwrap(), trk);
        assert_eq!(grant_ref.replay_id, g.common.replay_id);
        // Another key's signature over the same bytes is not this device's grant.
        assert!(own_grant(&container, &Ed25519SigningKey::from_bytes(&[4; 32])).is_err());
    }

    fn request() -> IdempotentMutationRequestV2 {
        IdempotentMutationRequestV2::parse(
            &cx()
                .request(OperationKind::RootGrantAck, vec![0xa0])
                .unwrap(),
        )
        .unwrap()
    }

    fn stored(req: &IdempotentMutationRequestV2) -> IdempotentStoredResponseV2 {
        IdempotentStoredResponseV2 {
            operation_kind: req.operation_kind,
            idempotency_key: req.idempotency_key,
            exact_request_hash: req.canonical_request_hash(),
            response_record_type: RECORD_TYPE_ROOT_GRANT_ACKED.into(),
            canonical_response_payload_bytes: vec![0xa1, 0x61, 0x61, 0x01],
            server_instance_id: req.server_instance_id,
            restore_epoch: req.restore_epoch,
            committed_at_ms: 1,
            receipt_id: [0; 16],
        }
    }

    #[test]
    fn a_stored_response_counts_only_when_it_answers_this_exact_request() {
        let req = request();
        let read = |s: &IdempotentStoredResponseV2| {
            stored_payload(&s.encode(), &req, RECORD_TYPE_ROOT_GRANT_ACKED)
        };
        assert_eq!(read(&stored(&req)).unwrap(), vec![0xa1, 0x61, 0x61, 0x01]);
        type Edit = fn(&mut IdempotentStoredResponseV2);
        let edits: [Edit; 6] = [
            |s| s.operation_kind = OperationKind::RootGenerationActivate,
            |s| s.idempotency_key[0] ^= 1,
            |s| s.exact_request_hash[0] ^= 1,
            |s| s.server_instance_id[0] ^= 1,
            |s| s.restore_epoch += 1,
            |s| s.response_record_type = RECORD_TYPE_ROOT_GENERATION_ACTIVATED.into(),
        ];
        for edit in edits {
            let mut s = stored(&req);
            edit(&mut s);
            assert!(read(&s).is_err());
        }
        assert!(stored_payload(b"not a response", &req, RECORD_TYPE_ROOT_GRANT_ACKED).is_err());
    }

    #[test]
    fn a_receipt_counts_only_for_this_devices_own_approval() {
        let cx = cx();
        let approval = self_approval(&cx, &signer(), 1_800_000_000_000).unwrap();
        let replay = approval_of(&approval).common.replay_id;
        let receipt = || DeviceApprovalReceiptV2 {
            server_instance_id: cx.instance,
            restore_epoch: cx.epoch,
            tenant_id: cx.tenant,
            actor_account_id: cx.account,
            actor_device_id: cx.device,
            subject_device_id: cx.device,
            approval_replay_id: replay,
            request_hash: device_approve_request_hash(
                &cx.instance,
                cx.epoch,
                &cx.tenant,
                &cx.account,
                &cx.device,
                &cx.device,
                &approval,
            ),
            approval_payload_sha256: [0; 32],
            approval_signed_container_hash: [0; 32],
            approval_outer_sha256: [0; 32],
            confirmation_id: Some([0; 16]),
            committed_at_ms: 1,
        };
        assert!(check_receipt(&receipt().encode(), &cx, &approval, replay).is_ok());
        type Edit = fn(&mut DeviceApprovalReceiptV2);
        let edits: [Edit; 9] = [
            |r| r.request_hash[0] ^= 1,
            |r| r.subject_device_id[0] ^= 1,
            |r| r.approval_replay_id[0] ^= 1,
            |r| r.server_instance_id[0] ^= 1,
            |r| r.restore_epoch += 1,
            |r| r.tenant_id[0] ^= 1,
            |r| r.actor_account_id[0] ^= 1,
            |r| r.actor_device_id[0] ^= 1,
            |r| r.confirmation_id = None,
        ];
        for edit in edits {
            let mut r = receipt();
            edit(&mut r);
            assert!(check_receipt(&r.encode(), &cx, &approval, replay).is_err());
        }
    }

    #[test]
    fn the_recovery_export_is_read_back_and_its_pinned_hash_returned() {
        let dir = std::env::temp_dir().join(format!("shardx-bootstrap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("recovery.bundle");
        let trk = [9; 32];
        let export = RecoveryExport {
            path: &path,
            passphrase: "correct horse battery",
        };
        let pinned = export_recovery_bundle(&cx(), &trk, &export, 1_800_000_000_000).unwrap();
        let file = std::fs::read(&path).unwrap();
        assert_eq!(pinned, recovery_bundle_sha256(&file));
        let (header, plaintext) = open(&file, "correct horse battery").unwrap();
        assert_eq!(*plaintext.trk, trk);
        assert_eq!(
            plaintext.bootstrap_anchor_signing_key_id,
            cx().signing_key_id
        );
        assert_eq!((header.tenant_id, header.root_generation), ([1; 16], 0));
        assert!(!dir.join("recovery.bundle.tmp").exists());

        // The pinned bundle checks out; a changed or missing one does not.
        assert!(check_bundle(&export, &pinned, &trk).is_ok());
        assert!(check_bundle(&export, &pinned, &[8; 32]).is_err());
        let wrong = RecoveryExport {
            passphrase: "correct horse batterz",
            ..export
        };
        assert!(check_bundle(&wrong, &pinned, &trk).is_err());
        std::fs::write(&path, b"replaced").unwrap();
        assert!(check_bundle(&export, &pinned, &trk).is_err());
        std::fs::remove_file(&path).unwrap();
        assert!(check_bundle(&export, &pinned, &trk).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failed_save_leaves_the_callers_state_as_it_was() {
        let mut state = BootstrapState::default();
        let mut refuse = |_: &BootstrapState| -> Result<()> { anyhow::bail!("disk full") };
        assert!(commit(&mut state, &mut refuse, |s| s.trk_ref = "ab".into()).is_err());
        assert!(state.trk_ref.is_empty());
        let mut saved = Vec::new();
        let mut accept = |s: &BootstrapState| -> Result<()> {
            saved.push(s.trk_ref.clone());
            Ok(())
        };
        commit(&mut state, &mut accept, |s| s.trk_ref = "ab".into()).unwrap();
        assert_eq!(
            (state.trk_ref.as_str(), saved),
            ("ab", vec!["ab".to_string()])
        );
    }

    #[test]
    fn the_saved_state_never_prints_the_legacy_trk() {
        let s = BootstrapState {
            legacy_trk: "ab".repeat(32).into(),
            ..Default::default()
        };
        assert!(!format!("{s:?}").contains("abab"));
    }

    /// A legacy cleartext TRK is wiped on drop (G2-47), read from an old file,
    /// and never serialized again.
    #[test]
    fn the_legacy_trk_zeroizes_on_drop_and_is_read_but_never_written() {
        let s = BootstrapState {
            legacy_trk: "ab".repeat(32).into(),
            ..Default::default()
        };
        let _: &dyn zeroize::ZeroizeOnDrop = &s.legacy_trk;
        assert!(serde_json::to_value(&s).unwrap().get("trk").is_none());
        let back: BootstrapState =
            serde_json::from_value(serde_json::json!({ "trk": "ab".repeat(32) })).unwrap();
        assert_eq!(back.legacy_trk.as_str(), "ab".repeat(32));
    }

    // ---- G2-63: the TRK lives in the credential store, never in the file.

    /// A config root of its own, held for the test, with the credential
    /// seams put back when it ends.
    struct Rooted {
        _guard: std::sync::MutexGuard<'static, ()>,
        _dir: tempfile::TempDir,
    }

    impl Drop for Rooted {
        fn drop(&mut self) {
            crate::credential::OS_STORE_DOWN.with(|d| d.set(false));
            crate::key_file::close();
            crate::store::set_config_root(None);
        }
    }

    fn rooted() -> Rooted {
        let guard = crate::store::config_root_test_lock()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().unwrap();
        crate::store::set_config_root(Some(dir.path().to_path_buf()));
        // The mock store outlives the test: tests that name tenant 1 start clean.
        crate::credential::forget(&name_of(1)).unwrap();
        Rooted {
            _guard: guard,
            _dir: dir,
        }
    }

    fn tenant_of(n: u8) -> String {
        hex(&[n; 16])
    }

    /// The run nonce the tests start from, as if it were saved already.
    const NONCE: &str = "00112233445566778899aabbccddeeff";

    fn name_of(n: u8) -> String {
        format!("tenant-root.{}.{NONCE}", tenant_of(n))
    }

    fn state_of(n: u8) -> BootstrapState {
        BootstrapState {
            tenant_id: tenant_of(n),
            device_id: hex(&[5; 16]),
            trk_nonce: NONCE.into(),
            ..Default::default()
        }
    }

    fn file_path() -> std::path::PathBuf {
        crate::store::custody_bootstrap_path().unwrap()
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// The old file format, as an earlier launcher wrote it: the TRK in hex.
    fn write_legacy_file(n: u8, trk: &[u8; 32], self_grant: &str, with_nonce: bool) {
        let mut json = serde_json::to_value(BootstrapState {
            approval: "abcd".into(),
            self_grant: self_grant.into(),
            ..state_of(n)
        })
        .unwrap();
        json["trk"] = hex(trk).into();
        if !with_nonce {
            json.as_object_mut().unwrap().remove("trk_nonce");
        }
        std::fs::write(file_path(), serde_json::to_vec_pretty(&json).unwrap()).unwrap();
    }

    /// `bootstrap_root` for tenant `[1; 16]` against a server nobody runs: it
    /// returns at once for an activated state and fails at the first server
    /// call for any other.
    fn run_offline(state: &mut BootstrapState) -> Result<()> {
        let (tenant, device_id, account) = (tenant_of(1), hex(&[5; 16]), hex(&[4; 16]));
        let (signer, seed) = (signer(), [7; 32]);
        let device = BootstrapDevice {
            login: AccountLogin {
                tenant_id: &tenant,
                username: "u",
                password: "p",
            },
            device_id: &device_id,
            account_id: &account,
            signer: &signer,
            hpke_seed: &seed,
            trk_store: &CredentialTrkStore,
        };
        let recovery = RecoveryExport {
            path: Path::new("unused"),
            passphrase: "pass",
        };
        let client = FleetClient::new("http://127.0.0.1:9", "t").unwrap();
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(bootstrap_root(
                &client,
                &device,
                &recovery,
                state,
                &mut |s| save(s),
            ))
    }

    #[test]
    fn the_trk_is_stored_and_the_saved_state_holds_only_its_reference() {
        let _root = rooted();
        let mut state = state_of(0x61);
        create_trk(&CredentialTrkStore, &mut state, &mut |s| save(s)).unwrap();
        assert_eq!(state.trk_ref, name_of(0x61));
        let trk = load_trk(&CredentialTrkStore, &state).unwrap();
        assert_eq!(*trk, *crate::credential::load(&name_of(0x61)).unwrap());
        assert_ne!(*trk, [0; 32]);
        let file = std::fs::read(file_path()).unwrap();
        assert!(contains(&file, name_of(0x61).as_bytes()));
        assert!(!contains(&file, hex(&*trk).as_bytes()), "the hex");
        assert!(!contains(&file, hex(&*trk).to_uppercase().as_bytes()));
        assert!(!contains(&file, &*trk), "the raw bytes");
        let json: serde_json::Value = serde_json::from_slice(&file).unwrap();
        assert!(json.get("trk").is_none(), "{json}");
        assert_eq!(load().unwrap().trk_ref, name_of(0x61));
    }

    /// Crash point: the key is stored, the reference is not yet saved.
    #[test]
    fn a_crash_between_storing_and_saving_the_key_resumes_with_the_same_key() {
        let _root = rooted();
        let mut state = state_of(0x62);
        let mut refuse = |_: &BootstrapState| -> Result<()> { anyhow::bail!("disk full") };
        assert!(create_trk(&CredentialTrkStore, &mut state, &mut refuse).is_err());
        assert!(state.trk_ref.is_empty());
        let stored = crate::credential::load(&name_of(0x62)).unwrap();
        create_trk(&CredentialTrkStore, &mut state, &mut |s| save(s)).unwrap();
        assert_eq!(*load_trk(&CredentialTrkStore, &state).unwrap(), *stored);
    }

    /// Crash point: the reference is saved, so a resume loads the same key
    /// and `create_trk` is not run again.
    #[test]
    fn a_resume_loads_the_stored_key_and_a_missing_one_is_not_made_up_again() {
        let _root = rooted();
        let mut state = state_of(0x63);
        create_trk(&CredentialTrkStore, &mut state, &mut |s| save(s)).unwrap();
        let first = load_trk(&CredentialTrkStore, &state).unwrap();
        let resumed = load().unwrap();
        assert_eq!(*load_trk(&CredentialTrkStore, &resumed).unwrap(), *first);
        crate::credential::forget(&name_of(0x63)).unwrap();
        let err = load_trk(&CredentialTrkStore, &resumed).unwrap_err();
        assert!(err.to_string().contains("credential.missing"), "{err}");
    }

    #[test]
    fn a_locked_or_unavailable_store_stops_every_trk_step_and_writes_nothing() {
        let _root = rooted();
        let mut saves = 0;
        let mut count = |_: &BootstrapState| -> Result<()> {
            saves += 1;
            Ok(())
        };
        let mut state = state_of(0x64);
        let name = name_of(0x64);

        crate::credential::fail_next_call(&name);
        let err = create_trk(&CredentialTrkStore, &mut state, &mut count).unwrap_err();
        assert!(err.to_string().contains("credential.unavailable"), "{err}");
        crate::credential::OS_STORE_DOWN.with(|d| d.set(true));
        let err = create_trk(&CredentialTrkStore, &mut state, &mut count).unwrap_err();
        assert!(err.to_string().contains("credential.unavailable"), "{err}");
        crate::credential::OS_STORE_DOWN.with(|d| d.set(false));
        assert!(state.trk_ref.is_empty());
        assert!(crate::credential::load(&name).is_err(), "no key was made");

        // With the key held, a store that stops answering fails a load and a
        // release, and the reference stays.
        crate::credential::store(&name, &[0x64; 32]).unwrap();
        state.trk_ref = name.clone();
        crate::credential::fail_next_call(&name);
        let err = load_trk(&CredentialTrkStore, &state).unwrap_err();
        assert!(err.to_string().contains("credential.unavailable"), "{err}");
        crate::credential::fail_next_call(&name);
        assert!(release_trk(&CredentialTrkStore, &mut state, &mut count).is_err());
        assert_eq!(state.trk_ref, name);
        assert_eq!(*crate::credential::load(&name).unwrap(), [0x64; 32]);

        // A key file that exists and is not open is locked, not absent.
        crate::credential::OS_STORE_DOWN.with(|d| d.set(true));
        crate::key_file::create("g2-63 test passphrase").unwrap();
        crate::key_file::close();
        let err = create_trk(&CredentialTrkStore, &mut state_of(0x68), &mut count).unwrap_err();
        assert!(err.to_string().contains("credential.locked"), "{err}");
        crate::credential::OS_STORE_DOWN.with(|d| d.set(false));

        assert_eq!(saves, 0, "nothing was saved");
        assert!(!file_path().exists(), "nothing was written");
    }

    #[test]
    fn a_reference_to_another_credential_is_refused_and_that_credential_is_kept() {
        let _root = rooted();
        crate::credential::store("device-signing.g2-63", &[5; 32]).unwrap();
        let mut state = state_of(0x65);
        state.trk_ref = "device-signing.g2-63".into();
        let err = load_trk(&CredentialTrkStore, &state).unwrap_err();
        assert!(
            err.to_string().contains("fleet.custodyStateCorrupt"),
            "{err}"
        );
        assert!(release_trk(&CredentialTrkStore, &mut state, &mut |_| Ok(())).is_err());
        assert_eq!(
            *crate::credential::load("device-signing.g2-63").unwrap(),
            [5; 32]
        );
    }

    #[test]
    fn releasing_forgets_the_key_and_drops_the_reference() {
        let _root = rooted();
        let mut state = state_of(0x66);
        create_trk(&CredentialTrkStore, &mut state, &mut |s| save(s)).unwrap();
        release_trk(&CredentialTrkStore, &mut state, &mut |s| save(s)).unwrap();
        assert!(state.trk_ref.is_empty() && load().unwrap().trk_ref.is_empty());
        assert!(state.trk_nonce.is_empty(), "the run is over");
        let err = crate::credential::load(&name_of(0x66)).unwrap_err();
        assert!(err.to_string().contains("credential.missing"), "{err}");
    }

    /// Crash point: the generation is active but the key is not yet forgotten,
    /// or the store refused the delete. The next run finishes it.
    #[test]
    fn an_activated_run_forgets_a_key_that_an_earlier_run_left() {
        let _root = rooted();
        let name = name_of(1);
        crate::credential::store(&name, &[1; 32]).unwrap();
        let mut state = BootstrapState {
            activated: true,
            trk_ref: name.clone(),
            ..state_of(1)
        };
        crate::credential::fail_next_call(&name);
        let err = run_offline(&mut state).unwrap_err();
        assert!(err.to_string().contains("credential.unavailable"), "{err}");
        assert_eq!(state.trk_ref, name, "kept until the key is gone");
        run_offline(&mut state).unwrap();
        assert!(state.trk_ref.is_empty() && load().unwrap().trk_ref.is_empty());
        assert!(crate::credential::load(&name).is_err());
        run_offline(&mut state).unwrap();
    }

    #[test]
    fn a_legacy_cleartext_trk_moves_into_the_store_and_the_file_is_rewritten_without_it() {
        let _root = rooted();
        let key = [0xa7; 32];
        write_legacy_file(1, &key, "ab", false);
        let mut state = load().unwrap();
        assert_eq!(state.legacy_trk.as_str(), hex(&key));
        assert!(
            state.trk_nonce.is_empty(),
            "a real legacy file has no nonce"
        );
        // The server is down: the run stops there, after the migration.
        assert!(run_offline(&mut state).is_err());
        assert!(state.legacy_trk.is_empty());
        assert_eq!(state.trk_ref, own_trk_ref(&state).unwrap());
        assert_eq!(*crate::credential::load(&state.trk_ref).unwrap(), key);
        let file = std::fs::read(file_path()).unwrap();
        assert!(!contains(&file, hex(&key).as_bytes()), "the hex");
        assert!(!contains(&file, &key), "the raw bytes");
        let json: serde_json::Value = serde_json::from_slice(&file).unwrap();
        assert!(json.get("trk").is_none(), "{json}");
        let reloaded = load().unwrap();
        assert_eq!(
            (reloaded.trk_ref.as_str(), reloaded.approval.as_str()),
            (state.trk_ref.as_str(), "abcd")
        );
        assert_eq!(*load_trk(&CredentialTrkStore, &reloaded).unwrap(), key);
    }

    #[test]
    fn a_store_that_refuses_the_legacy_trk_leaves_the_file_untouched_and_fails_closed() {
        let _root = rooted();
        let key = [0xb8; 32];
        write_legacy_file(1, &key, "ab", true);
        let before = std::fs::read(file_path()).unwrap();
        let mut state = load().unwrap();
        crate::credential::fail_next_call(&name_of(1));
        let err = run_offline(&mut state).unwrap_err();
        assert!(err.to_string().contains("credential.unavailable"), "{err}");
        assert_eq!(std::fs::read(file_path()).unwrap(), before, "untouched");
        assert_eq!(state.legacy_trk.as_str(), hex(&key));
        assert!(state.trk_ref.is_empty());
        assert!(crate::credential::load(&name_of(1)).is_err());
        // The store answers again: the same file migrates, the key is not lost.
        let mut state = load().unwrap();
        assert!(run_offline(&mut state).is_err());
        assert_eq!(*crate::credential::load(&name_of(1)).unwrap(), key);
        let after = std::fs::read(file_path()).unwrap();
        assert!(!contains(&after, hex(&key).as_bytes()));
    }

    #[test]
    fn a_legacy_file_that_names_no_tenant_or_holds_no_key_is_refused() {
        let _root = rooted();
        let mut state = BootstrapState {
            legacy_trk: "ab".repeat(32).into(),
            ..Default::default()
        };
        let no_save = &mut |_: &BootstrapState| -> Result<()> { panic!("saved") };
        assert!(migrate_legacy_trk(&CredentialTrkStore, &mut state, no_save).is_err());
        state.tenant_id = tenant_of(0x67);
        state.legacy_trk = "zz".repeat(32).into();
        assert!(migrate_legacy_trk(&CredentialTrkStore, &mut state, no_save).is_err());
        assert!(crate::credential::load(&name_of(0x67)).is_err());
    }

    /// A store that reads "missing" but refuses every write, as a locked key
    /// file does once the OS store is gone.
    struct RefusesWrites;

    impl TrkStore for RefusesWrites {
        fn store(&self, _: &str, _: &[u8; 32]) -> Result<()> {
            Err(anyhow!(crate::errcode::code("credential.locked")))
        }
        fn load(&self, _: &str) -> Result<Zeroizing<[u8; 32]>> {
            Err(anyhow!(crate::errcode::code("credential.missing")))
        }
        fn forget(&self, _: &str) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_store_that_refuses_a_new_key_leaves_no_reference_and_no_file() {
        let _root = rooted();
        let mut state = state_of(0x69);
        let no_save = &mut |_: &BootstrapState| -> Result<()> { panic!("saved") };
        let err = create_trk(&RefusesWrites, &mut state, no_save).unwrap_err();
        assert!(err.to_string().contains("credential.locked"), "{err}");
        assert!(state.trk_ref.is_empty() && !file_path().exists());
    }

    /// Crash point: the generation is active in memory but the save of that
    /// fails. The key must still be in the store and the reference still
    /// saved, so a rerun finishes with the same key.
    #[test]
    fn the_activation_is_saved_before_the_key_is_forgotten() {
        let _root = rooted();
        let mut state = state_of(0x6f);
        create_trk(&CredentialTrkStore, &mut state, &mut |s| save(s)).unwrap();
        let key = load_trk(&CredentialTrkStore, &state).unwrap();
        let mut refuse = |s: &BootstrapState| -> Result<()> {
            if s.activated {
                anyhow::bail!("disk full");
            }
            save(s)
        };
        let err = finish_activation(&CredentialTrkStore, &mut state, &mut refuse, "aa".into())
            .unwrap_err();
        assert!(err.to_string().contains("disk full"), "{err}");
        assert!(!state.activated && state.trk_ref == name_of(0x6f));
        assert_eq!(
            *crate::credential::load(&name_of(0x6f)).unwrap(),
            *key,
            "the key is still stored"
        );
        let on_disk = load().unwrap();
        assert!(!on_disk.activated && on_disk.trk_ref == name_of(0x6f));
        // The rerun finishes: active, key forgotten.
        finish_activation(
            &CredentialTrkStore,
            &mut state,
            &mut |s| save(s),
            "aa".into(),
        )
        .unwrap();
        assert!(state.activated && state.trk_ref.is_empty());
        assert!(crate::credential::load(&name_of(0x6f)).is_err());
        let on_disk = load().unwrap();
        assert!(on_disk.activated && on_disk.trk_ref.is_empty());
    }

    #[test]
    fn a_new_run_never_reuses_a_key_an_abandoned_run_left() {
        let _root = rooted();
        let stale = format!("tenant-root.{}.{}", tenant_of(0x6a), "f".repeat(32));
        crate::credential::store(&stale, &[9; 32]).unwrap();
        let fresh = || BootstrapState {
            tenant_id: tenant_of(0x6a),
            ..Default::default()
        };
        let mut first = fresh();
        create_trk(&CredentialTrkStore, &mut first, &mut |s| save(s)).unwrap();
        let mut second = fresh();
        create_trk(&CredentialTrkStore, &mut second, &mut |s| save(s)).unwrap();
        assert!(nonce_ok(&first.trk_nonce) && nonce_ok(&second.trk_nonce));
        assert_ne!(first.trk_nonce, second.trk_nonce);
        assert_eq!(first.trk_ref, own_trk_ref(&first).unwrap());
        assert_ne!(first.trk_ref, stale);
        assert_ne!(*load_trk(&CredentialTrkStore, &first).unwrap(), [9; 32]);
        assert_ne!(
            *load_trk(&CredentialTrkStore, &second).unwrap(),
            *load_trk(&CredentialTrkStore, &first).unwrap()
        );
        assert_eq!(*crate::credential::load(&stale).unwrap(), [9; 32]);
    }

    #[test]
    fn the_run_nonce_is_saved_before_the_key_is_stored() {
        let _root = rooted();
        let mut state = BootstrapState {
            tenant_id: tenant_of(0x6b),
            ..Default::default()
        };
        let mut seen = Vec::new();
        let mut watch = |s: &BootstrapState| -> Result<()> {
            let stored = !s.trk_nonce.is_empty()
                && crate::credential::load(&trk_ref(&s.tenant_id, &s.trk_nonce)).is_ok();
            seen.push((!s.trk_nonce.is_empty(), !s.trk_ref.is_empty(), stored));
            Ok(())
        };
        create_trk(&CredentialTrkStore, &mut state, &mut watch).unwrap();
        // First save: the nonce, no key yet. Second: the key and its reference.
        assert_eq!(seen, [(true, false, false), (true, true, true)]);
    }

    #[test]
    fn a_reference_for_another_tenant_or_with_a_malformed_nonce_is_refused() {
        let _root = rooted();
        let other = format!("tenant-root.{}.{NONCE}", tenant_of(0x6d));
        crate::credential::store(&other, &[3; 32]).unwrap();
        let mut state = state_of(0x6c);
        state.trk_ref = other.clone();
        let err = load_trk(&CredentialTrkStore, &state).unwrap_err();
        assert!(
            err.to_string().contains("fleet.custodyStateCorrupt"),
            "{err}"
        );
        assert!(release_trk(&CredentialTrkStore, &mut state, &mut |_| Ok(())).is_err());
        assert_eq!(*crate::credential::load(&other).unwrap(), [3; 32]);
        for bad in [
            "",
            "short",
            "00112233445566778899AABBCCDDEEFF",
            "../../device-signing.x/0000000000",
            "0011223344556677889900112233445566",
        ] {
            let mut state = state_of(0x6c);
            state.trk_nonce = bad.into();
            state.trk_ref = trk_ref(&state.tenant_id, bad);
            assert!(own_trk_ref(&state).is_err(), "{bad:?}");
            assert!(run_ref(&mut state, &mut |_| Ok(())).is_err() == !bad.is_empty());
        }
    }

    #[test]
    fn a_legacy_trk_is_refused_when_a_reference_is_already_set() {
        let _root = rooted();
        let key = [0x31; 32];
        let mut state = BootstrapState {
            legacy_trk: hex(&key).into(),
            self_grant: "ab".into(),
            trk_ref: name_of(0x70),
            ..state_of(0x70)
        };
        let no_save = &mut |_: &BootstrapState| -> Result<()> { panic!("saved") };
        let err = migrate_legacy_trk(&CredentialTrkStore, &mut state, no_save).unwrap_err();
        assert!(
            err.to_string().contains("fleet.custodyStateCorrupt"),
            "{err}"
        );
        assert!(crate::credential::load(&name_of(0x70)).is_err());
    }

    #[test]
    fn a_legacy_trk_the_store_already_holds_is_only_dropped() {
        let _root = rooted();
        let key = [0x32; 32];
        crate::credential::store(&name_of(0x71), &key).unwrap();
        let mut state = BootstrapState {
            legacy_trk: hex(&key).into(),
            self_grant: "ab".into(),
            ..state_of(0x71)
        };
        migrate_legacy_trk(&CredentialTrkStore, &mut state, &mut |s| save(s)).unwrap();
        assert!(state.legacy_trk.is_empty() && state.trk_ref == name_of(0x71));
        assert_eq!(*crate::credential::load(&name_of(0x71)).unwrap(), key);
        assert!(!contains(
            &std::fs::read(file_path()).unwrap(),
            hex(&key).as_bytes()
        ));
    }

    #[test]
    fn a_legacy_trk_never_overwrites_a_different_stored_key() {
        let _root = rooted();
        crate::credential::store(&name_of(0x72), &[0x41; 32]).unwrap();
        let mut state = BootstrapState {
            legacy_trk: hex(&[0x42; 32]).into(),
            self_grant: "ab".into(),
            ..state_of(0x72)
        };
        let no_save = &mut |_: &BootstrapState| -> Result<()> { panic!("saved") };
        let err = migrate_legacy_trk(&CredentialTrkStore, &mut state, no_save).unwrap_err();
        assert!(
            err.to_string().contains("fleet.custodyStateCorrupt"),
            "{err}"
        );
        assert_eq!(
            *crate::credential::load(&name_of(0x72)).unwrap(),
            [0x41; 32]
        );
        assert_eq!(state.legacy_trk.as_str(), hex(&[0x42; 32]));
    }

    /// A launcher that stopped before it saved a self-grant: no other party
    /// ever saw its key, so the key is dropped, not carried over.
    #[test]
    fn a_legacy_trk_nobody_has_seen_is_dropped_and_a_fresh_one_is_made() {
        let _root = rooted();
        let key = [0xc3; 32];
        write_legacy_file(1, &key, "", true);
        let mut state = load().unwrap();
        // The server is down: the run stops there, after the migration.
        assert!(run_offline(&mut state).is_err());
        assert!(state.legacy_trk.is_empty() && state.trk_ref.is_empty());
        assert!(
            crate::credential::load(&name_of(1)).is_err(),
            "not migrated"
        );
        let file = std::fs::read(file_path()).unwrap();
        assert!(!contains(&file, hex(&key).as_bytes()) && !contains(&file, &key));
        create_trk(&CredentialTrkStore, &mut state, &mut |s| save(s)).unwrap();
        assert_ne!(*load_trk(&CredentialTrkStore, &state).unwrap(), key);

        // A hand-edited file that still shows a recovery bundle or a create
        // request is not "unseen": the key moves to the store instead.
        type Edit = fn(&mut BootstrapState);
        let edits: [Edit; 2] = [
            |s| s.recovery_bundle_sha256 = "ab".repeat(32),
            |s| s.create_request = "ab".into(),
        ];
        for (n, edit) in (0x74..).zip(edits) {
            let mut state = BootstrapState {
                legacy_trk: hex(&key).into(),
                ..state_of(n)
            };
            edit(&mut state);
            migrate_legacy_trk(&CredentialTrkStore, &mut state, &mut |s| save(s)).unwrap();
            assert!(state.legacy_trk.is_empty() && state.trk_ref == name_of(n));
            assert_eq!(*crate::credential::load(&name_of(n)).unwrap(), key);
        }
    }

    /// A real legacy file has no nonce. The store refusing the key, or the
    /// run stopping between the store and the commit, must leave the key in
    /// the file: any save drops it.
    #[test]
    fn a_nonce_less_legacy_trk_stays_in_the_file_until_the_store_holds_it() {
        let _root = rooted();
        let key = [0xd4; 32];
        write_legacy_file(1, &key, "ab", false);
        let before = std::fs::read(file_path()).unwrap();
        let has_key = |file: &[u8]| contains(file, hex(&key).as_bytes());
        assert!(has_key(&before));

        // The store is down: a credential error, and the file is as it was.
        crate::credential::OS_STORE_DOWN.with(|d| d.set(true));
        let mut state = load().unwrap();
        let err = run_offline(&mut state).unwrap_err();
        assert!(err.to_string().contains("credential.unavailable"), "{err}");
        crate::credential::OS_STORE_DOWN.with(|d| d.set(false));
        assert_eq!(std::fs::read(file_path()).unwrap(), before, "untouched");
        assert!(state.trk_nonce.is_empty() && state.trk_ref.is_empty());
        assert_eq!(state.legacy_trk.as_str(), hex(&key));

        // The store takes the key, then the save fails: the file still has it.
        let mut state = load().unwrap();
        let mut refuse = |_: &BootstrapState| -> Result<()> { anyhow::bail!("disk full") };
        let err = migrate_legacy_trk(&CredentialTrkStore, &mut state, &mut refuse).unwrap_err();
        assert!(err.to_string().contains("disk full"), "{err}");
        assert_eq!(std::fs::read(file_path()).unwrap(), before, "untouched");
        assert!(state.trk_nonce.is_empty() && state.trk_ref.is_empty());

        // The rerun finishes with the same TRK.
        let mut state = load().unwrap();
        migrate_legacy_trk(&CredentialTrkStore, &mut state, &mut |s| save(s)).unwrap();
        assert_eq!(*load_trk(&CredentialTrkStore, &state).unwrap(), key);
        let after = std::fs::read(file_path()).unwrap();
        assert!(!has_key(&after) && !contains(&after, &key));
        let reloaded = load().unwrap();
        assert_eq!(reloaded.trk_ref, own_trk_ref(&reloaded).unwrap());
        assert_eq!(*load_trk(&CredentialTrkStore, &reloaded).unwrap(), key);
        // The rerun reused the reference the failed run stored under: no second copy.
        assert_eq!(reloaded.trk_nonce, hex(&root_key_id(&key)[..16]));
    }

    #[test]
    fn a_hex_secret_decodes_into_32_bytes_or_is_refused() {
        let key: Vec<u8> = (0..32).collect();
        assert_eq!(unhex_secret(&hex(&key)).unwrap()[..], key[..]);
        assert_eq!(
            unhex_secret(&hex(&key).to_uppercase()).unwrap()[..],
            key[..]
        );
        for bad in [
            "",
            "ab",
            &"ab".repeat(33),
            &"zz".repeat(32),
            &"+1".repeat(32),
        ] {
            assert!(unhex_secret(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_legacy_trk_with_a_malformed_nonce_is_refused_before_anything_is_stored() {
        let _root = rooted();
        let mut state = BootstrapState {
            legacy_trk: hex(&[0x51; 32]).into(),
            self_grant: "ab".into(),
            trk_nonce: "../device-signing.x".into(),
            ..state_of(0x76)
        };
        let no_save = &mut |_: &BootstrapState| -> Result<()> { panic!("saved") };
        let err = migrate_legacy_trk(&CredentialTrkStore, &mut state, no_save).unwrap_err();
        assert!(
            err.to_string().contains("fleet.custodyStateCorrupt"),
            "{err}"
        );
        assert_eq!(state.legacy_trk.as_str(), hex(&[0x51; 32]));
    }
}
