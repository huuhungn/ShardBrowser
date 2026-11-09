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
use shardx_core::recovery_bundle::{
    self as rb, RecoveryBundlePlaintextV2, RetainedFkek, RootCustodian,
};
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
    /// this device's own signing key ID, or the pinned one of the tenant
    /// whose custody this device received (ADR 0002 Q-52).
    #[serde(default)]
    pub anchor: String,
    /// The exact current root grant container, once a renewal or a hand-over
    /// replaced the first self-grant (Q-52); empty while the first self-grant
    /// is current.
    #[serde(default)]
    pub root_grant: String,
    /// The Ed25519 public key that signed `root_grant`.
    #[serde(default)]
    pub root_grant_issuer: String,
    /// Root self-renewal (v2.10 4.R, ADR 0002 Q-55): the run in progress, or
    /// the last one finished.
    #[serde(default)]
    pub renewal: Option<Renewal>,
}

/// One root self-renewal: every record and request, hex, built once and
/// saved before the first is sent, so a resumed run resends the same bytes.
/// No key is among it.
#[derive(Default, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Renewal {
    #[serde(default)]
    pub capability_grants: Vec<String>,
    #[serde(default)]
    pub approval: String,
    /// The `ExistingRootGrant` of the ACTIVE root to this device.
    #[serde(default)]
    pub root_grant: String,
    #[serde(default)]
    pub root_grant_request: String,
    #[serde(default)]
    pub ack_request: String,
    /// Files this device's grant of fleet generation `generation`; empty
    /// while the fleet had no ACTIVE generation.
    #[serde(default)]
    pub device_grant_request: String,
    #[serde(default)]
    pub device_ack_request: String,
    #[serde(default)]
    pub generation: u64,
    /// The next step to send, saved once the one before it is answered: the
    /// capability grants one by one, then the approval, the root grant, its
    /// ack, the device grant, its ack and the collect.
    #[serde(default)]
    pub step: u8,
    /// Every step was answered and the new records are the current ones.
    #[serde(default)]
    pub done: bool,
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

pub(crate) fn mismatch() -> anyhow::Error {
    anyhow!(crate::errcode::code("fleet.custodyReplyMismatch"))
}

pub(crate) fn corrupt() -> anyhow::Error {
    anyhow!(crate::errcode::code("fleet.custodyStateCorrupt"))
}

/// A saved state field: anything that does not decode is a damaged file.
fn unhex<const N: usize>(s: &str) -> Result<[u8; N]> {
    unhex_vec(s)?.try_into().map_err(|_| corrupt())
}

pub(crate) fn unhex_vec(s: &str) -> Result<Vec<u8>> {
    decode_hex(s).ok_or_else(corrupt)
}

pub(crate) fn random<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    fill_random(&mut out).map_err(|_| anyhow!(crate::errcode::code("fleet.custodyEntropy")))?;
    Ok(out)
}

pub(crate) fn now_ms() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    #[cfg(test)]
    let now = now.saturating_sub(tests::CLOCK_BACK_MS.with(std::cell::Cell::get));
    now
}

/// The facts every built record and request names.
pub(crate) struct Context16 {
    pub(crate) tenant: [u8; 16],
    pub(crate) instance: [u8; 16],
    pub(crate) epoch: u64,
    pub(crate) account: [u8; 16],
    pub(crate) device: [u8; 16],
    pub(crate) signing_key_id: [u8; 32],
    pub(crate) hpke_key_id: [u8; 32],
}

impl Context16 {
    pub(crate) fn common(&self, replay_id: [u8; 16], now: u64) -> CommonFields {
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

    pub(crate) fn request(&self, kind: OperationKind, payload: Vec<u8>) -> Result<Vec<u8>> {
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
pub(crate) fn self_grant(
    cx: &Context16,
    signer: &Ed25519SigningKey,
    hpke_public_key: &[u8],
    trk: &[u8; 32],
    approval_replay_id: [u8; 16],
    now: u64,
) -> Result<Vec<u8>> {
    let g = TenantRootKeyGrantV2 {
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
    sealed_root_grant(signer, hpke_public_key, trk, g)
}

/// `g` with `trk` sealed to `hpke_public_key`, signed by `signer`.
fn sealed_root_grant(
    signer: &Ed25519SigningKey,
    hpke_public_key: &[u8],
    trk: &[u8; 32],
    mut g: TenantRootKeyGrantV2,
) -> Result<Vec<u8>> {
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
pub(crate) fn own_grant(
    container: &[u8],
    signer: &Ed25519SigningKey,
) -> Result<(TenantRootKeyGrantV2, RootGrantRef)> {
    verified_root_grant(container, signer.verifying_key().as_bytes())
}

/// A root grant verified under its issuer's public key `issuer`.
pub(crate) fn verified_root_grant(
    container: &[u8],
    issuer: &[u8; 32],
) -> Result<(TenantRootKeyGrantV2, RootGrantRef)> {
    let v = AuthorizationRecord::parse(container)
        .and_then(|r| r.verify_signature(issuer))
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

/// This device's current root grant (ADR 0002 Q-52): the first self-grant
/// until a renewal or a hand-over saved another in `root_grant`. Returns it
/// with its exact container and its issuer's public key, once it verifies
/// under that key and names this device's own signing key.
pub(crate) fn current_root_grant(
    state: &BootstrapState,
    signer: &Ed25519SigningKey,
) -> Result<(TenantRootKeyGrantV2, Vec<u8>, [u8; 32])> {
    let own = signer.verifying_key().to_bytes();
    if state.root_grant.is_empty() {
        let container = unhex_vec(&state.self_grant)?;
        let (grant, _) = verified_root_grant(&container, &own)?;
        return Ok((grant, container, own));
    }
    let container = unhex_vec(&state.root_grant)?;
    let issuer = unhex(&state.root_grant_issuer)?;
    let (grant, _) = verified_root_grant(&container, &issuer)?;
    if grant.subject_signing_key_id != signing_key_id(&own) {
        return Err(corrupt());
    }
    Ok((grant, container, issuer))
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
pub(crate) fn stored_payload(
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

/// Writes the bundle (v3: it carries this device as the root custodian, with
/// both key seeds and its first self-grant, and `retained_fkeks`) once its
/// sealed bytes open (L819, L1387), then re-reads exactly those bytes from its
/// final path. Returns the hash the create request pins.
#[allow(clippy::too_many_arguments)]
fn export_recovery_bundle(
    cx: &Context16,
    trk: &[u8; 32],
    signer: &Ed25519SigningKey,
    hpke_seed: &[u8; 32],
    self_grant: &[u8],
    retained_fkeks: Vec<RetainedFkek>,
    recovery: &RecoveryExport<'_>,
    now: u64,
) -> Result<[u8; 32]> {
    let plaintext = RecoveryBundlePlaintextV2 {
        trk: (*trk).into(),
        bootstrap_anchor_signing_key_id: cx.signing_key_id,
        retained_fkeks,
        root_custodian: Some(RootCustodian {
            account_id: cx.account,
            device_id: cx.device,
            signing_key_seed: signer.to_bytes().into(),
            hpke_key_seed: (*hpke_seed).into(),
            root_grant: self_grant.to_vec(),
            root_grant_issuer: None,
        }),
    };
    write_bundle((cx.tenant, cx.instance, 0), &plaintext, recovery, now)
}

/// Seals `plaintext` under a header naming `(tenant, instance, root
/// generation)` and writes it once its sealed bytes open, then re-reads
/// exactly those bytes from its final path. Returns the pinned hash.
fn write_bundle(
    (tenant, instance, root_generation): ([u8; 16], [u8; 16], u64),
    plaintext: &RecoveryBundlePlaintextV2,
    recovery: &RecoveryExport<'_>,
    now: u64,
) -> Result<[u8; 32]> {
    let failed = || crate::errcode::code("fleet.recoveryExportFailed");
    let (header, file) = rb::seal(
        tenant,
        instance,
        root_generation,
        now,
        plaintext,
        recovery.passphrase,
    )
    .map_err(|e| anyhow!(e).context(failed()))?;
    // Verified before the write, so a bundle that does not open never
    // replaces an older one at the path; the reread must be those bytes.
    let pinned = rb::verify_export(&file, recovery.passphrase, &header)
        .map_err(|e| anyhow!(e).context(failed()))?;
    crate::durable::write_private(recovery.path, &file).with_context(failed)?;
    if std::fs::read(recovery.path).with_context(failed)? != file {
        bail!(failed());
    }
    Ok(pinned)
}

/// The bundle at `recovery.path` is the pinned one and still opens to `trk`.
/// A 2.7.x (v2) bundle passes: activation accepts the one it pinned.
fn check_bundle(
    recovery: &RecoveryExport<'_>,
    pinned: &[u8; 32],
    trk: &[u8; 32],
) -> Result<RecoveryBundlePlaintextV2> {
    let changed = || anyhow!(crate::errcode::code("fleet.recoveryBundleChanged"));
    let file = std::fs::read(recovery.path).map_err(|_| changed())?;
    if rb::recovery_bundle_sha256(&file) != *pinned {
        return Err(changed());
    }
    match rb::open(&file, recovery.passphrase) {
        Ok((_, plaintext)) if *plaintext.trk == *trk => Ok(plaintext),
        _ => Err(changed()),
    }
}

/// Step 3 reuses a saved bundle the server has not yet seen only while it
/// passes [`check_bundle`] and carries this device, with the saved self-grant,
/// as the root custodian; a v2 one cannot restore the team, so it is exported
/// again.
fn reusable_bundle(
    recovery: &RecoveryExport<'_>,
    state: &BootstrapState,
    trk: &[u8; 32],
    device: &[u8; 16],
    self_grant: &[u8],
) -> Result<bool> {
    if state.recovery_bundle_sha256.is_empty() {
        return Ok(false);
    }
    Ok(
        check_bundle(recovery, &unhex(&state.recovery_bundle_sha256)?, trk).is_ok_and(|pt| {
            pt.root_custodian
                .is_some_and(|c| c.device_id == *device && c.root_grant == self_grant)
        }),
    )
}

/// Applies `change` to a copy of `state`, saves the copy, and only then
/// replaces `state`: what the caller holds is always what is on disk.
pub(crate) fn commit<S: Clone>(
    state: &mut S,
    save: &mut impl FnMut(&S) -> Result<()>,
    change: impl FnOnce(&mut S),
) -> Result<()> {
    let mut next = state.clone();
    change(&mut next);
    save(&next)?;
    *state = next;
    Ok(())
}

/// A run nonce: 16 random bytes, lower-case hex.
pub(crate) fn nonce_ok(nonce: &str) -> bool {
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

pub(crate) fn is_missing(e: &anyhow::Error) -> bool {
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

    // A pending device's session reads the identity: no v1 token is needed.
    let session = client
        .open_device_session(
            &device.login,
            device.device_id,
            device.signer,
            device.hpke_seed,
        )
        .await?;
    let access = session.access_token.as_str();
    let result = async {
        let id = client.server_identity(access).await?;
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
        let run = Run {
            client,
            device,
            recovery,
            cx: &cx,
            access,
            hpke_secret: &hpke_secret,
            hpke_public: &hpke_public,
        };
        run.steps(state, save).await
    }
    .await;
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
        // seen is reused while it is still there, opens and names this device
        // as root custodian, else replaced.
        if state.create_request.is_empty() {
            if !reusable_bundle(self.recovery, state, &trk, &cx.device, &container)? {
                let sha = hex(&export_recovery_bundle(
                    cx,
                    &trk,
                    signer,
                    self.device.hpke_seed,
                    &container,
                    Vec::new(),
                    self.recovery,
                    now,
                )?);
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
    // Generation 0's records; a custodian that received custody has none.
    if state.root_grant.is_empty() {
        keep_records(client.base_url(), &state)?;
    }
    Ok(BootstrapStatus::of(&state))
}

/// Exports the recovery bundle again (v0.2.2b plan, section 4.X) over this
/// root custodian's device session `access`. `fkeks` is every verified fleet
/// key of `fleet_hex` this device holds: the fleet's ACTIVE generation must be
/// among them. The current root grant (Q-52) must read back acknowledged
/// under an ACTIVE root generation and open to the TRK. The bundle names that
/// grant's server instance and root generation and the saved anchor; it is v3
/// while the first self-grant is current, v4 otherwise (Q-53). Nothing is
/// filed and no state file changes.
#[allow(clippy::too_many_arguments)]
pub async fn export_again(
    client: &FleetClient,
    access: &str,
    fleet_hex: &str,
    signer: &Ed25519SigningKey,
    hpke_seed: &[u8; 32],
    fkeks: Vec<(u64, Zeroizing<[u8; 32]>)>,
    recovery: &RecoveryExport<'_>,
) -> Result<String> {
    crate::fleet_custody::refuse_handed_over(&crate::fleet_custody::load()?)?;
    let state = load()?;
    let (grant, container, issuer) = current_root_grant(&state, signer)?;
    let exported = root_grant_sha256(&state);
    let tenant_hex = hex(&grant.common.tenant_id);
    let active = client
        .active_fleet_generation(access, &tenant_hex, fleet_hex)
        .await?;
    if !active.is_some_and(|g| fkeks.iter().any(|(held, _)| *held == g)) {
        bail!(crate::errcode::code("fleet.recoveryExportNeedsFleetKey"));
    }
    let (hpke_secret, _) = derive_keypair(hpke_seed);
    let trk = grant
        .open_trk(&hpke_secret)
        .map_err(|_| anyhow!(crate::errcode::code("fleet.custodyGrantMismatch")))?;
    crate::recovery_import::check_root_grant(
        client,
        access,
        &tenant_hex,
        &container,
        &issuer,
        &hpke_secret,
        &trk,
    )
    .await?;
    let fleet_id = decode_hex16(fleet_hex, "fleet_id")?;
    let retained = fkeks
        .into_iter()
        .map(|(generation, fkek)| RetainedFkek {
            fleet_id,
            generation,
            fkek,
        })
        .collect();
    let plaintext = RecoveryBundlePlaintextV2 {
        trk,
        bootstrap_anchor_signing_key_id: unhex(&state.anchor)?,
        retained_fkeks: retained,
        root_custodian: Some(RootCustodian {
            account_id: grant.subject_account_id,
            device_id: grant.subject_device_id,
            signing_key_seed: signer.to_bytes().into(),
            hpke_key_seed: (*hpke_seed).into(),
            root_grant: container,
            root_grant_issuer: (!state.root_grant.is_empty()).then_some(issuer),
        }),
    };
    let header = (
        grant.common.tenant_id,
        grant.common.server_instance_id,
        grant.root_generation,
    );
    write_bundle(header, &plaintext, recovery, now_ms())?;
    Ok(exported)
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
    /// The started state names this device of the saved tenant, or
    /// `team.json` does not read to say otherwise: the UI treats only this
    /// as a root custodian, as Reset refuses only it.
    pub this_device: bool,
    pub activated: bool,
    /// Where the recovery bundle was written, once it was.
    pub recovery_path: String,
    /// The bootstrap anchor, once the trust evidence verified to it.
    pub anchor: String,
    /// The recovery fingerprint (ADR 0002 D-5), the activated root's
    /// `root_key_id` in hex: empty before activation or when the self-grant
    /// does not read under this device's key.
    pub root_key_id: String,
    /// When this root custodian's earliest own record reaches half its life
    /// and the next custodian command or sync renews them (4.R).
    pub renewal_due_ms: Option<u64>,
    /// When the earliest of those records ends.
    pub custody_ends_ms: Option<u64>,
    /// When this device's signing key stops counting as a custodian's
    /// (`MAX_CUSTODIAN_KEY_AGE_MS`); only a hand-over moves custody past it.
    pub key_age_ends_ms: Option<u64>,
}

impl BootstrapStatus {
    fn of(state: &BootstrapState) -> Self {
        let (renewal_due_ms, custody_ends_ms, key_age_ends_ms) = renewal_times(state);
        Self {
            started: !state.tenant_id.is_empty(),
            this_device: !state.tenant_id.is_empty()
                && crate::team_config::load().map_or(true, |c| {
                    state.tenant_id.eq_ignore_ascii_case(&c.tenant_id)
                        && state.device_id.eq_ignore_ascii_case(&c.device_id)
                }),
            activated: state.activated,
            recovery_path: state.recovery_path.clone(),
            anchor: state.anchor.clone(),
            root_key_id: root_key_id_of(state),
            renewal_due_ms,
            custody_ends_ms,
            key_age_ends_ms,
        }
    }
}

/// [`BootstrapStatus`]'s renewal due time, custody end and key age end,
/// from the records saved here; none before activation.
fn renewal_times(state: &BootstrapState) -> (Option<u64>, Option<u64>, Option<u64>) {
    let own = crate::team_config::load().and_then(|c| c.signing_key());
    let (true, Ok(own)) = (state.activated, own) else {
        return (None, None, None);
    };
    let own = own.verifying_key().to_bytes();
    let grants = crate::fleet_custody::load()
        .map(|c| c.capability_grants)
        .unwrap_or_default();
    let windows = own_windows(state, &own, &grants, own_device_grant(state).as_deref());
    let age = shardx_core::trust_chain::MAX_CUSTODIAN_KEY_AGE_MS;
    (
        renewal_due_ms(&windows),
        windows.iter().map(|w| w.1).min(),
        first_not_before(state, &own).map(|nb| nb + age),
    )
}

/// The `root_key_id` of `state`'s current root grant ([`current_root_grant`]);
/// empty when not activated or when it or this device's key does not read.
fn root_key_id_of(state: &BootstrapState) -> String {
    if !state.activated {
        return String::new();
    }
    crate::team_config::load()
        .and_then(|c| c.signing_key())
        .and_then(|signer| current_root_grant(state, &signer))
        .map(|(g, _, _)| hex(&g.root_key_id))
        .unwrap_or_default()
}

/// The saved bootstrap's progress.
pub fn status() -> Result<BootstrapStatus> {
    Ok(BootstrapStatus::of(&load()?))
}

/// Loads the bootstrap state; none yet is the empty state. A file whose
/// existence cannot be checked is an error, never no root state.
pub fn load() -> Result<BootstrapState> {
    let path = crate::store::custody_bootstrap_path()?;
    if !path.try_exists()? {
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

// ---- Root self-renewal (v2.10 4.R, ADR 0002 Q-55) ----

/// The approval and root grant a renewal files run exactly the server's cap
/// (ADR 0002 D-6; the server refuses anything longer), so members offline
/// for months still see a custodian; capability and device grants run a
/// year.
pub(crate) const RENEWED_VALIDITY_MS: u64 = 730 * DAY_MS;
const _: () =
    assert!(RENEWED_VALIDITY_MS == shardx_core::approval_receipt::MAX_DEVICE_APPROVAL_TTL_MS);

/// What one renewal step did.
#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RenewalOutcome {
    /// This device holds no activated root state of its tenant.
    NotCustodian,
    /// This custodian handed its custody over (4.H): it never renews.
    HandedOver,
    /// Another custody command holds the lock; the next one renews.
    Busy,
    NotDue,
    Renewed,
}

/// The root custodian that renews, and its keys.
pub(crate) struct RenewingDevice<'a> {
    pub(crate) account_id: &'a str,
    pub(crate) signer: &'a Ed25519SigningKey,
    pub(crate) hpke_seed: &'a [u8; 32],
}

/// `(not_before_ms, not_after_ms)` of a saved container signed by `issuer`.
/// One that does not verify is left out: it is checked where it is used.
fn window_of(container: &[u8], issuer: &[u8; 32]) -> Option<(u64, u64)> {
    let v = AuthorizationRecord::parse(container)
        .and_then(|r| r.verify_signature(issuer))
        .ok()?;
    let c = v.payload().common();
    Some((c.not_before_ms, c.not_after_ms))
}

/// The issuer of `state`'s current root grant: its saved issuer, else this
/// device (`own`, its public key) for the first self-grant.
fn root_issuer(state: &BootstrapState, own: &[u8; 32]) -> Option<[u8; 32]> {
    if state.root_grant.is_empty() {
        Some(*own)
    } else {
        unhex(&state.root_grant_issuer).ok()
    }
}

/// The windows of this custodian's own records as saved here, each verified
/// under its issuer: its current root grant, its approval, its capability
/// grants (a finished renewal's, else `custody_grants`, Create fleet key's)
/// and `device_grant`, its kept grant of the newest fleet generation when
/// this device (`own`, its public key) issued it. A record not saved here (an
/// import keeps no approval or capability grants) is left out.
pub(crate) fn own_windows(
    state: &BootstrapState,
    own: &[u8; 32],
    custody_grants: &[String],
    device_grant: Option<&[u8]>,
) -> Vec<(u64, u64)> {
    let root = if state.root_grant.is_empty() {
        &state.self_grant
    } else {
        &state.root_grant
    };
    let grants = match state.renewal.as_ref().filter(|r| r.done) {
        Some(r) => r.capability_grants.as_slice(),
        None => custody_grants,
    };
    let root = decode_hex(root).zip(root_issuer(state, own));
    let mine = std::iter::once(&state.approval)
        .chain(grants)
        .filter_map(|h| decode_hex(h))
        .chain(device_grant.map(<[u8]>::to_vec))
        .map(|c| (c, *own));
    root.into_iter()
        .chain(mine)
        .filter_map(|(c, issuer)| window_of(&c, &issuer))
        .collect()
}

/// When the earliest of `windows` reaches half its life (4.R).
pub(crate) fn renewal_due_ms(windows: &[(u64, u64)]) -> Option<u64> {
    windows
        .iter()
        .map(|&(nb, na)| nb + na.saturating_sub(nb) / 2)
        .min()
}

/// SHA-256 of `state`'s current root grant as saved, lower-case hex; empty
/// when none is saved.
pub(crate) fn root_grant_sha256(state: &BootstrapState) -> String {
    use sha2::{Digest, Sha256};
    let root = if state.root_grant.is_empty() {
        &state.self_grant
    } else {
        &state.root_grant
    };
    decode_hex(root)
        .map(|c| hex(&Sha256::digest(c)))
        .unwrap_or_default()
}

/// A finished renewal replaced the root grant of the recovery bundle last
/// exported, whose [`root_grant_sha256`] is `exported`.
pub(crate) fn renewal_unexported(state: &BootstrapState, exported: &str) -> bool {
    state.renewal.as_ref().is_some_and(|r| r.done) && root_grant_sha256(state) != exported
}

fn due(windows: &[(u64, u64)], t: u64) -> bool {
    renewal_due_ms(windows).is_some_and(|d| t >= d)
}

/// The earliest `not_before_ms` of this custodian's root grants: those saved
/// here, and the trust ledger's cached first one, which is all a custodian
/// imported from a bundle exported after a renewal knows of the earlier ones.
/// A ledger that does not exist is not created.
fn first_not_before(state: &BootstrapState, own: &[u8; 32]) -> Option<u64> {
    let first = decode_hex(&state.self_grant).and_then(|c| window_of(&c, own));
    let current = decode_hex(&state.root_grant)
        .zip(unhex(&state.root_grant_issuer).ok())
        .and_then(|(c, issuer)| window_of(&c, &issuer));
    let ledger = || -> Option<u64> {
        let (binding, _) = pin_of(state).ok()?;
        if !crate::team::db::Db::path().ok()?.try_exists().ok()? {
            return None;
        }
        let db = crate::team::db::Db::open().ok()?;
        crate::team::ledger::first_not_before(&db, &binding, &signing_key_id(own)).ok()?
    };
    first
        .into_iter()
        .chain(current)
        .map(|w| w.0)
        .chain(ledger())
        .min()
}

/// The pin `state` names: its binding and anchor.
fn pin_of(state: &BootstrapState) -> Result<(Binding, [u8; 32])> {
    Ok((
        Binding {
            server_instance_id: decode_hex16(&state.server_instance_id, "server_instance_id")?,
            tenant_id: decode_hex16(&state.tenant_id, "tenant_id")?,
        },
        unhex(&state.anchor)?,
    ))
}

/// The grant of the newest fleet generation the trust ledger kept for this
/// custodian (G2-35), if any. A ledger that does not exist is not created.
pub(crate) fn own_device_grant(state: &BootstrapState) -> Option<Vec<u8>> {
    let (binding, anchor) = pin_of(state).ok()?;
    if !crate::team::db::Db::path().ok()?.try_exists().ok()? {
        return None;
    }
    let db = crate::team::db::Db::open().ok()?;
    let fleet = binding.tenant_id;
    let generation = crate::team::ledger::highest_generation(&db, &binding, &fleet).ok()??;
    let kept = crate::team::ledger::fleet_key_grant(&db, &binding, &anchor, &fleet, generation);
    kept.ok()?.map(|(container, _)| container)
}

/// The facts this custodian's renewed records name.
fn renewal_context(state: &BootstrapState, me: &RenewingDevice<'_>) -> Result<Context16> {
    let (_, hpke_public) = derive_keypair(me.hpke_seed);
    Ok(Context16 {
        tenant: decode_hex16(&state.tenant_id, "tenant_id")?,
        instance: decode_hex16(&state.server_instance_id, "server_instance_id")?,
        epoch: state.restore_epoch,
        account: decode_hex16(me.account_id, "account_id")?,
        device: decode_hex16(&state.device_id, "device_id")?,
        signing_key_id: signing_key_id(me.signer.verifying_key().as_bytes()),
        hpke_key_id: hpke_key_id(&hpke_public),
    })
}

/// 4.R: every record of one renewal at server time `t`, in the order they
/// are sent: the six capability grants (a year), the tenant self-approval
/// and the `ExistingRootGrant` of the ACTIVE root linking it (exactly 730
/// days), its ack, and this device's grant of the fleet's ACTIVE generation
/// (a year) with its ack. Each starts at `t`.
async fn build_renewal(
    client: &FleetClient,
    access: &str,
    cx: &Context16,
    me: &RenewingDevice<'_>,
    state: &BootstrapState,
    t: u64,
    fleet_key: &impl Fn(u64) -> Result<Zeroizing<[u8; 32]>>,
) -> Result<Renewal> {
    use shardx_core::authz_record::GrantSubject;
    use shardx_core::fleet_lifecycle::{FleetKeyGrantAckV2, FleetKeyGrantCreateV2};
    use shardx_core::mutation::TenantRootGrantCreateV2;
    // `common` backdates by the skew: built at `start`, records begin at `t`.
    let start = t + CLOCK_SKEW_MS;
    let long = || -> Result<CommonFields> {
        let mut common = cx.common(random()?, start);
        common.not_after_ms = common.not_before_ms + RENEWED_VALIDITY_MS;
        Ok(common)
    };
    let (hpke_secret, hpke_public) = derive_keypair(me.hpke_seed);
    let hpke_pk: [u8; 32] = hpke_public.clone().try_into().map_err(|_| corrupt())?;
    let subject = GrantSubject::Device {
        account_id: cx.account,
        device_id: cx.device,
        signing_key_id: cx.signing_key_id,
        hpke_key_id: cx.hpke_key_id,
    };
    let own = crate::fleet_custody::own_grants(cx, cx.tenant);
    let capability_grants =
        crate::fleet_custody::capability_grants(cx, me.signer, &subject, own, start)?;

    let approval = DeviceApprovalV2 {
        common: long()?,
        subject_account_id: cx.account,
        subject_device_id: cx.device,
        subject_signing_key_id: cx.signing_key_id,
        subject_hpke_key_id: cx.hpke_key_id,
        approval_scope_kind: ApprovalScopeKind::Tenant,
        approval_scope_id: cx.tenant,
    };
    let approval_replay = approval.common.replay_id;
    let approval = build_record(me.signer, DOMAIN_DEVICE_APPROVAL, &approval.encode());

    let (current, _, _) = current_root_grant(state, me.signer)?;
    let trk = current.open_trk(&hpke_secret).map_err(|_| corrupt())?;
    let grant = TenantRootKeyGrantV2 {
        common: long()?,
        variant: RootGrantVariant::ExistingRootGrant,
        root_key_id: current.root_key_id,
        root_generation: current.root_generation,
        subject_account_id: cx.account,
        subject_device_id: cx.device,
        subject_signing_key_id: cx.signing_key_id,
        recipient_hpke_key_id: cx.hpke_key_id,
        subject_device_approval_replay_id: approval_replay,
        hpke_encapped_key_bytes: [0; 32],
        hpke_wrapped_trk_bytes: [0; 48],
    };
    let root_grant = sealed_root_grant(me.signer, &hpke_public, &trk, grant)?;
    let (_, grant_ref) = verified_root_grant(&root_grant, me.signer.verifying_key().as_bytes())?;
    let filing = TenantRootGrantCreateV2 {
        grant: grant_ref.clone(),
        exact_signed_grant_container_bytes: root_grant.clone(),
    };
    let root_grant_request = cx.request(OperationKind::RootGrantCreate, filing.encode())?;
    let ack_request = cx.request(
        OperationKind::RootGrantAck,
        TenantRootGrantAckV2 { grant: grant_ref }.encode(),
    )?;

    let fleet = hex(&cx.tenant);
    let mut run = Renewal {
        capability_grants,
        approval: hex(&approval),
        root_grant: hex(&root_grant),
        root_grant_request: hex(&root_grant_request),
        ack_request: hex(&ack_request),
        ..Default::default()
    };
    if let Some(generation) = client
        .active_fleet_generation(access, &fleet, &fleet)
        .await?
    {
        let fkek = fleet_key(generation)?;
        let keys = (cx.signing_key_id, cx.hpke_key_id, hpke_pk);
        let filing = crate::fleet_custody::member_grant(
            cx,
            me.signer,
            (cx.account, cx.device),
            keys,
            &fkek,
            generation,
            start,
        )?;
        let (request, _) = saved(&filing)?;
        let grant = FleetKeyGrantCreateV2::parse(&request.canonical_payload_bytes)
            .map_err(|_| corrupt())?
            .grant;
        let ack = cx.request(
            OperationKind::FleetGrantAck,
            FleetKeyGrantAckV2 { grant }.encode(),
        )?;
        run.device_grant_request = filing;
        run.device_ack_request = hex(&ack);
        run.generation = generation;
    }
    Ok(run)
}

/// The replay ID of the saved record `container`, signed by `issuer`.
fn saved_replay(container: &[u8], issuer: &[u8; 32]) -> Result<[u8; 16]> {
    AuthorizationRecord::parse(container)
        .and_then(|r| r.verify_signature(issuer))
        .map(|v| v.payload().common().replay_id)
        .map_err(|_| corrupt())
}

/// The saved request `saved` and its exact bytes.
fn saved(saved: &str) -> Result<(IdempotentMutationRequestV2, Vec<u8>)> {
    let bytes = unhex_vec(saved)?;
    let request = IdempotentMutationRequestV2::parse(&bytes).map_err(|_| corrupt())?;
    Ok((request, bytes))
}

/// `run`'s own records are past half their life at `t`: the next renewal is
/// due, and a grant not yet sent has ended or soon will.
fn run_stale(run: &Renewal, own: &[u8; 32], t: u64) -> bool {
    let windows: Vec<_> = run
        .capability_grants
        .iter()
        .chain([&run.approval, &run.root_grant])
        .filter_map(|h| decode_hex(h))
        .filter_map(|c| window_of(&c, own))
        .collect();
    due(&windows, t)
}

/// Saves that the saved run's `step` is the next one to send.
fn answered(
    state: &mut BootstrapState,
    save: &mut impl FnMut(&BootstrapState) -> Result<()>,
    step: usize,
) -> Result<()> {
    let step = u8::try_from(step).map_err(|_| corrupt())?;
    commit(state, save, |s| {
        if let Some(r) = s.renewal.as_mut() {
            r.step = step;
        }
    })
}

/// Sends the saved run's records in order from its saved `step`, each
/// checked against the reply that answers it and saved as answered before
/// the next is sent, then `collect`s this device's new grant of
/// `run.generation`. A rotation since the run was built granted this device
/// the newer ACTIVE generation, so the device grant of the retired one is
/// left out; so is one of a `stale` run, whose root grant was acked.
#[allow(clippy::too_many_arguments)]
async fn send_renewal(
    client: &FleetClient,
    access: &str,
    cx: &Context16,
    own: &[u8; 32],
    stale: bool,
    state: &mut BootstrapState,
    save: &mut impl FnMut(&BootstrapState) -> Result<()>,
    collect: impl AsyncFnOnce(u64) -> Result<()>,
) -> Result<()> {
    use shardx_core::fleet_lifecycle::{
        FleetKeyGrantAckedV2, FleetKeyGrantCreateV2, FleetKeyGrantCreatedV2,
        RECORD_TYPE_FLEET_GRANT_ACKED, RECORD_TYPE_FLEET_GRANT_CREATED,
    };
    use shardx_core::mutation::{
        TenantRootGrantCreateV2, TenantRootGrantCreatedV2, RECORD_TYPE_ROOT_GRANT_CREATED,
    };
    let run = state.renewal.clone().ok_or_else(corrupt)?;
    let (n, from) = (run.capability_grants.len(), usize::from(run.step));
    for (i, grant) in run.capability_grants.iter().enumerate().skip(from) {
        let grant = unhex_vec(grant)?;
        if client.file_capability_grant(access, &grant).await? != grant {
            return Err(mismatch());
        }
        answered(state, save, i + 1)?;
    }

    if from <= n {
        let approval = unhex_vec(&run.approval)?;
        let replay = saved_replay(&approval, own)?;
        let receipt = client
            .approve_device(access, &hex(&cx.device), &approval)
            .await?;
        let r = DeviceApprovalReceiptV2::parse(&receipt).map_err(|_| mismatch())?;
        let hash = device_approve_request_hash(
            &cx.instance,
            cx.epoch,
            &cx.tenant,
            &cx.account,
            &cx.device,
            &cx.device,
            &approval,
        );
        if r.request_hash != hash
            || (r.server_instance_id, r.restore_epoch, r.tenant_id)
                != (cx.instance, cx.epoch, cx.tenant)
            || (r.actor_account_id, r.actor_device_id) != (cx.account, cx.device)
            || (r.subject_device_id, r.approval_replay_id) != (cx.device, replay)
        {
            return Err(mismatch());
        }
        answered(state, save, n + 1)?;
    }

    let tenant = hex(&cx.tenant);
    let (request, bytes) = saved(&run.root_grant_request)?;
    let filing =
        TenantRootGrantCreateV2::parse(&request.canonical_payload_bytes).map_err(|_| corrupt())?;
    let generation = filing.grant.root_generation;
    if from <= n + 1 {
        let stored = client
            .file_root_grant(access, &tenant, generation, &bytes)
            .await?;
        let created = TenantRootGrantCreatedV2::parse(&stored_payload(
            &stored,
            &request,
            RECORD_TYPE_ROOT_GRANT_CREATED,
        )?)
        .map_err(|_| mismatch())?;
        if created.grant != filing.grant {
            return Err(mismatch());
        }
        answered(state, save, n + 2)?;
    }
    if from <= n + 2 {
        let (request, bytes) = saved(&run.ack_request)?;
        let replay = hex(&filing.grant.replay_id);
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
        answered(state, save, n + 3)?;
    }

    if stale
        || run.device_grant_request.is_empty()
        || client
            .active_fleet_generation(access, &tenant, &tenant)
            .await?
            != Some(run.generation)
    {
        return Ok(());
    }
    let (request, bytes) = saved(&run.device_grant_request)?;
    let grant = FleetKeyGrantCreateV2::parse(&request.canonical_payload_bytes)
        .map_err(|_| corrupt())?
        .grant;
    if from <= n + 3 {
        let stored = client
            .file_fleet_grant(access, &tenant, run.generation, &bytes)
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
        answered(state, save, n + 4)?;
    }
    if from <= n + 4 {
        let (request, bytes) = saved(&run.device_ack_request)?;
        let stored = client
            .ack_fleet_grant(access, &tenant, run.generation, &bytes)
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
        answered(state, save, n + 5)?;
    }
    collect(run.generation).await
}

/// 4.R's lapse rule: `pages`, evaluated to the saved anchor, no longer count
/// this device's key as a custodian at the server's time `server_now`. Pages
/// that do not verify prove nothing.
fn lapsed(
    state: &BootstrapState,
    pages: &[shardx_core::trust_evidence::TenantTrustEvidencePageV2],
    key: &[u8; 32],
    server_now: u64,
) -> bool {
    let Ok((binding, anchor)) = pin_of(state) else {
        return false;
    };
    Evidence::collect(&binding, pages)
        .ok()
        .and_then(|e| TrustChain::evaluate(e, Some(&anchor)).ok())
        .is_some_and(|chain| !chain.custodian_now(key, server_now))
}

/// Root self-renewal (4.R) over this custodian's session `access`, under the
/// custody lock the caller holds. A run in progress is resumed with its
/// saved bytes at its saved step; once past half its own life it is built
/// again if its root grant was never sent, else finished without its device
/// grant. Otherwise nothing is asked of the server unless one of this
/// custodian's own records ([`own_windows`]) reaches half its life at the
/// local clock less the skew; then the server's time `T = min(local,
/// server_now_ms) - CLOCK_SKEW_MS`, from fresh trust evidence, decides, and
/// a due renewal is built at `T` and saved before anything is sent.
/// `fleet_key` gives the verified key of a fleet generation; `collect` keeps
/// this device's new grant of one. Once every step is answered the new root
/// grant and approval become the current ones. A 403 is a lapse
/// (`fleet.custodyLapsed`) only when the evidence no longer counts this
/// device as a custodian at the server's time; any other error is returned
/// as it is.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn renew(
    client: &FleetClient,
    access: &str,
    me: &RenewingDevice<'_>,
    custody: &crate::fleet_custody::FleetCustodyState,
    device_grant: Option<&[u8]>,
    local_now: u64,
    fleet_key: impl Fn(u64) -> Result<Zeroizing<[u8; 32]>>,
    collect: impl AsyncFnOnce(u64) -> Result<()>,
    state: &mut BootstrapState,
    save: &mut impl FnMut(&BootstrapState) -> Result<()>,
) -> Result<RenewalOutcome> {
    if crate::fleet_custody::refuse_handed_over(custody).is_err() {
        return Ok(RenewalOutcome::HandedOver);
    }
    let resuming = state.renewal.as_ref().is_some_and(|r| !r.done);
    let own = me.signer.verifying_key().to_bytes();
    let windows = own_windows(state, &own, &custody.capability_grants, device_grant);
    #[cfg(test)]
    let forced = tests::RENEWAL_DUE.with(std::cell::Cell::get);
    #[cfg(not(test))]
    let forced = false;
    let due = |t: u64| forced || due(&windows, t);
    if !resuming && !due(local_now.saturating_sub(CLOCK_SKEW_MS)) {
        return Ok(RenewalOutcome::NotDue);
    }
    let cx = renewal_context(state, me)?;
    let pages = client.trust_evidence(access, &hex(&cx.tenant)).await?;
    let server_now = pages.iter().map(|p| p.server_now_ms).max().unwrap_or(0);
    // Without the server's time nothing is due, sent or lapsed.
    if server_now == 0 {
        return Err(mismatch());
    }
    let t = local_now.min(server_now).saturating_sub(CLOCK_SKEW_MS);
    let open = state.renewal.as_ref().filter(|r| !r.done);
    let stale = open.is_some_and(|r| run_stale(r, &own, t));
    // A stale run whose root grant was never sent is built again.
    let rebuild = stale && open.is_some_and(|r| usize::from(r.step) <= r.capability_grants.len());
    if !resuming || rebuild {
        if !due(t) {
            return Ok(RenewalOutcome::NotDue);
        }
        let run = build_renewal(client, access, &cx, me, state, t, &fleet_key).await?;
        commit(state, save, |s| s.renewal = Some(run))?;
        eprintln!("[renewal] built at server time {t}");
    }
    let skip_device_grant = stale && !rebuild;
    let sent = send_renewal(
        client,
        access,
        &cx,
        &own,
        skip_device_grant,
        state,
        save,
        collect,
    );
    if let Err(e) = sent.await {
        if crate::fleet_custody::refused_with(&e, 403, None)
            && lapsed(state, &pages, &cx.signing_key_id, server_now)
        {
            eprintln!("[renewal] lapsed at server time {server_now}");
            bail!(crate::errcode::code("fleet.custodyLapsed"));
        }
        return Err(e);
    }
    let run = state.renewal.clone().ok_or_else(corrupt)?;
    let issuer = hex(me.signer.verifying_key().as_bytes());
    commit(state, save, |s| {
        s.root_grant = run.root_grant.clone();
        s.root_grant_issuer = issuer;
        s.approval = run.approval.clone();
        if let Some(r) = s.renewal.as_mut() {
            r.done = true;
        }
    })?;
    eprintln!("[renewal] renewed (fleet generation {})", run.generation);
    Ok(RenewalOutcome::Renewed)
}

#[cfg(test)]
pub(crate) mod tests {
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

    /// The test HPKE seed (never a real device's).
    const HPKE_SEED: [u8; 32] = [7; 32];

    /// `cx` with this device's real HPKE key ID, and its first self-grant of
    /// `trk`.
    fn custodian_cx(device: [u8; 16], trk: &[u8; 32]) -> (Context16, Vec<u8>) {
        let (_, pk) = derive_keypair(&HPKE_SEED);
        let cx = Context16 {
            device,
            hpke_key_id: hpke_key_id(&pk),
            ..cx()
        };
        let grant = self_grant(&cx, &signer(), &pk, trk, [0x33; 16], 1_800_000_000_000).unwrap();
        (cx, grant)
    }

    fn export_v3(
        cx: &Context16,
        trk: &[u8; 32],
        grant: &[u8],
        export: &RecoveryExport<'_>,
    ) -> [u8; 32] {
        export_recovery_bundle(
            cx,
            trk,
            &signer(),
            &HPKE_SEED,
            grant,
            Vec::new(),
            export,
            1_800_000_000_000,
        )
        .unwrap()
    }

    /// S3: an export whose file cannot be written and read back, or that does
    /// not open as a bundle of this root custodian, is refused.
    #[test]
    fn an_export_that_cannot_read_back_or_open_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let trk = [9; 32];
        let (cx, grant) = custodian_cx([5; 16], &trk);
        let refused = |path: &Path, grant: &[u8]| {
            let export = RecoveryExport {
                path,
                passphrase: "correct horse battery",
            };
            let err = export_recovery_bundle(
                &cx,
                &trk,
                &signer(),
                &HPKE_SEED,
                grant,
                Vec::new(),
                &export,
                1_800_000_000_000,
            )
            .unwrap_err();
            assert!(
                crate::errcode::has_code(&format!("{err:#}"), "fleet.recoveryExportFailed"),
                "{err:#}"
            );
        };
        // Its folder is missing, or the path is a folder: nothing to read back.
        let missing = dir.path().join("gone").join("recovery.bundle");
        refused(&missing, &grant);
        assert!(!missing.exists());
        refused(dir.path(), &grant);
        // A self-grant of another device: the sealed bytes do not open as this
        // root custodian's bundle, so an older bundle at the path is kept.
        let (_, other) = custodian_cx([0x0e; 16], &trk);
        let older = dir.path().join("recovery.bundle");
        std::fs::write(&older, b"an older bundle").unwrap();
        refused(&older, &other);
        assert_eq!(std::fs::read(&older).unwrap(), b"an older bundle");
    }

    #[test]
    fn a_rejected_export_preserves_an_openable_older_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recovery.bundle");
        let recovery = RecoveryExport {
            path: &path,
            passphrase: "fixture passphrase",
        };
        let trk = [9; 32];
        let (cx, good) = custodian_cx([5; 16], &trk);
        export_v3(&cx, &trk, &good, &recovery);
        let before = std::fs::read(&path).unwrap();
        assert!(rb::open(&before, recovery.passphrase).is_ok());
        let (_, wrong) = custodian_cx([0x0e; 16], &trk);
        let result = export_recovery_bundle(
            &cx,
            &trk,
            &signer(),
            &HPKE_SEED,
            &wrong,
            Vec::new(),
            &recovery,
            1_800_000_000_000,
        );
        assert!(result.is_err());
        let after = std::fs::read(&path).unwrap();
        assert!(after == before, "the good bundle was replaced");
        assert!(rb::open(&after, recovery.passphrase).is_ok());
    }

    /// S3: a verified key of generation 0 while the server reports generation
    /// 1 ACTIVE is refused before the root grant is read; with generation 0
    /// ACTIVE the export goes on to that read.
    #[test]
    fn an_export_without_the_active_generations_key_is_refused() {
        use crate::fleet_custody::tests::{mock, runtime};
        let _lock = crate::store::config_root_test_lock()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().unwrap();
        crate::store::set_config_root(Some(dir.path().to_path_buf()));
        let (_, grant) = custodian_cx([5; 16], &[9; 32]);
        save(&BootstrapState {
            self_grant: hex(&grant),
            ..Default::default()
        })
        .unwrap();
        let path = dir.path().join("again.bundle");
        let export = RecoveryExport {
            path: &path,
            passphrase: "correct horse battery",
        };
        let fleet = hex(&[1; 16]);
        let rt = runtime();
        let attempt = |active: u64| {
            let body = format!("{{\"generation\":{active}}}").into_bytes();
            let (client, seen) =
                rt.block_on(mock(std::sync::Arc::new(move |call: &str, _: &[u8]| {
                    if call.ends_with("/key-generation") {
                        (200, body.clone())
                    } else {
                        (404, Vec::new())
                    }
                })));
            let err = rt
                .block_on(export_again(
                    &client,
                    "access",
                    &fleet,
                    &signer(),
                    &HPKE_SEED,
                    vec![(0, Zeroizing::new([0x44; 32]))],
                    &export,
                ))
                .unwrap_err()
                .to_string();
            let calls = seen.lock().unwrap().len();
            (err, calls)
        };
        let (err, calls) = attempt(1);
        let (onward, _) = attempt(0);
        crate::store::set_config_root(None);
        assert!(
            crate::errcode::has_code(&err, "fleet.recoveryExportNeedsFleetKey"),
            "{err}"
        );
        assert_eq!(calls, 1, "only the ACTIVE generation was read");
        assert!(
            crate::errcode::has_code(&onward, "recovery.rootGrantMissing"),
            "{onward}"
        );
        assert!(!path.exists());
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
        let (cx, grant) = custodian_cx([5; 16], &trk);
        let pinned = export_v3(&cx, &trk, &grant, &export);
        let file = std::fs::read(&path).unwrap();
        assert_eq!(pinned, recovery_bundle_sha256(&file));
        let (header, plaintext) = open(&file, "correct horse battery").unwrap();
        assert_eq!(*plaintext.trk, trk);
        assert_eq!(plaintext.bootstrap_anchor_signing_key_id, cx.signing_key_id);
        assert_eq!((header.tenant_id, header.root_generation), ([1; 16], 0));
        // v3: it carries this device as the root custodian.
        let custodian = plaintext.root_custodian.as_ref().unwrap();
        assert_eq!(
            (custodian.account_id, custodian.device_id),
            (cx.account, cx.device)
        );
        assert_eq!(*custodian.signing_key_seed, signer().to_bytes());
        assert_eq!(*custodian.hpke_key_seed, HPKE_SEED);
        assert_eq!(custodian.root_grant, grant);
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

    /// A 2.7.x bundle sealed with no custodian, as that launcher's step 3
    /// wrote it.
    fn write_v2(cx: &Context16, trk: &[u8; 32], export: &RecoveryExport<'_>) -> [u8; 32] {
        let plaintext = RecoveryBundlePlaintextV2 {
            trk: (*trk).into(),
            bootstrap_anchor_signing_key_id: cx.signing_key_id,
            retained_fkeks: Vec::new(),
            root_custodian: None,
        };
        let (_, file) =
            rb::seal(cx.tenant, cx.instance, 0, 1, &plaintext, export.passphrase).unwrap();
        std::fs::write(export.path, &file).unwrap();
        recovery_bundle_sha256(&file)
    }

    /// Resume before the create request: a v2 bundle on disk (from 2.7.x) is
    /// not reused but exported again as v3, and only a v3 bundle naming this
    /// device is reused.
    #[test]
    fn a_v2_bundle_saved_before_the_create_is_replaced_by_a_v3_export() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recovery.bundle");
        let export = RecoveryExport {
            path: &path,
            passphrase: "correct horse battery",
        };
        let trk = [9; 32];
        let (cx, grant) = custodian_cx([5; 16], &trk);
        let mut state = BootstrapState {
            recovery_bundle_sha256: hex(&write_v2(&cx, &trk, &export)),
            ..Default::default()
        };
        assert!(check_bundle(
            &export,
            &unhex(&state.recovery_bundle_sha256).unwrap(),
            &trk
        )
        .is_ok());
        assert!(!reusable_bundle(&export, &state, &trk, &cx.device, &grant).unwrap());

        state.recovery_bundle_sha256 = hex(&export_v3(&cx, &trk, &grant, &export));
        assert!(reusable_bundle(&export, &state, &trk, &cx.device, &grant).unwrap());
        assert!(!reusable_bundle(&export, &state, &trk, &[0x0e; 16], &grant).unwrap());
        // Another self-grant of this device (a fresh replay ID) is not the
        // saved one: exported again.
        let (_, newer) = custodian_cx([5; 16], &trk);
        assert_ne!(newer, grant);
        assert!(!reusable_bundle(&export, &state, &trk, &cx.device, &newer).unwrap());

        // A v3 bundle of another device is exported again too.
        let (other, other_grant) = custodian_cx([0x0e; 16], &trk);
        state.recovery_bundle_sha256 = hex(&export_v3(&other, &trk, &other_grant, &export));
        assert!(!reusable_bundle(&export, &state, &trk, &cx.device, &grant).unwrap());
        // Nothing saved yet: nothing to reuse.
        let empty = BootstrapState::default();
        assert!(!reusable_bundle(&export, &empty, &trk, &cx.device, &grant).unwrap());
    }

    /// Resume after the create request: activation checks the bundle the
    /// create pinned, and a pinned v2 bundle still passes.
    #[test]
    fn activation_accepts_the_v2_bundle_a_2_7_create_pinned() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recovery.bundle");
        let export = RecoveryExport {
            path: &path,
            passphrase: "correct horse battery",
        };
        let trk = [9; 32];
        let pinned = write_v2(&cx(), &trk, &export);
        let plaintext = check_bundle(&export, &pinned, &trk).unwrap();
        assert!(plaintext.root_custodian.is_none());
        assert!(check_bundle(&export, &pinned, &[8; 32]).is_err());
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

    /// An `ExistingRootGrant` of `trk` as root `generation` from `issuer`
    /// to the device `cx` names, sealed to `hpke_public` and linked to the
    /// approval `approval_replay_id`.
    pub(crate) fn existing_grant(
        issuer: &Ed25519SigningKey,
        cx: &Context16,
        hpke_public: &[u8],
        trk: &[u8; 32],
        generation: u64,
        approval_replay_id: [u8; 16],
        now: u64,
    ) -> Vec<u8> {
        let mut g = TenantRootKeyGrantV2 {
            common: cx.common(random().unwrap(), now),
            variant: RootGrantVariant::ExistingRootGrant,
            root_key_id: root_key_id(trk),
            root_generation: generation,
            subject_account_id: cx.account,
            subject_device_id: cx.device,
            subject_signing_key_id: cx.signing_key_id,
            recipient_hpke_key_id: cx.hpke_key_id,
            subject_device_approval_replay_id: approval_replay_id,
            hpke_encapped_key_bytes: [0; 32],
            hpke_wrapped_trk_bytes: [0; 48],
        };
        let sealed = seal_trk(hpke_public, &g.scope(), trk).unwrap();
        g.hpke_encapped_key_bytes = sealed.encapped_key_bytes.try_into().unwrap();
        g.hpke_wrapped_trk_bytes = sealed.ciphertext_bytes.try_into().unwrap();
        build_record(issuer, DOMAIN_TENANT_ROOT_KEY_GRANT, &g.encode())
    }

    /// The anchor `A0` that appointed this test device (test key only).
    fn a0() -> Ed25519SigningKey {
        Ed25519SigningKey::from_bytes(&[0xa0; 32])
    }

    /// A root state whose current grant is `A0`'s `ExistingRootGrant` of
    /// `TRK` as root `generation` to this device, anchored at `A0`.
    fn appointed_state(generation: u64) -> (BootstrapState, Vec<u8>) {
        let (cx, _) = custodian_cx([5; 16], &[9; 32]);
        let (_, pk) = derive_keypair(&HPKE_SEED);
        let grant = existing_grant(&a0(), &cx, &pk, &[9; 32], generation, [0x34; 16], now_ms());
        let state = BootstrapState {
            tenant_id: hex(&cx.tenant),
            device_id: hex(&cx.device),
            server_instance_id: hex(&cx.instance),
            activated: true,
            anchor: hex(&signing_key_id(a0().verifying_key().as_bytes())),
            root_grant: hex(&grant),
            root_grant_issuer: hex(&a0().verifying_key().to_bytes()),
            ..Default::default()
        };
        (state, grant)
    }

    /// Q-52: the first self-grant until another grant replaced it; that one
    /// only while it verifies under its saved issuer and names this device's
    /// own signing key.
    #[test]
    fn the_current_root_grant_refuses_a_grant_to_another_key() {
        let (_, first) = custodian_cx([5; 16], &[9; 32]);
        let initial = BootstrapState {
            self_grant: hex(&first),
            ..Default::default()
        };
        let (grant, container, issuer) = current_root_grant(&initial, &signer()).unwrap();
        assert_eq!(
            (grant.root_generation, container, issuer),
            (0, first.clone(), signer().verifying_key().to_bytes())
        );

        let (mut state, appointed) = appointed_state(1);
        state.self_grant = hex(&first);
        let (grant, container, issuer) = current_root_grant(&state, &signer()).unwrap();
        assert_eq!(
            (grant.root_generation, container, issuer),
            (1, appointed, a0().verifying_key().to_bytes())
        );

        // A grant to another device's key, or under a key that did not sign
        // it, is refused.
        let other = Ed25519SigningKey::from_bytes(&[0x0e; 32]);
        assert!(current_root_grant(&state, &other).is_err());
        let forged = BootstrapState {
            root_grant_issuer: hex(&other.verifying_key().to_bytes()),
            ..state.clone()
        };
        assert!(current_root_grant(&forged, &signer()).is_err());
        let damaged = BootstrapState {
            root_grant_issuer: "ab".into(),
            ..state
        };
        assert!(current_root_grant(&damaged, &signer()).is_err());
    }

    /// Exports again from `state` against a server that lists generation 0
    /// ACTIVE and reads `grant` back acknowledged from `issuer`; returns the
    /// opened bundle.
    fn export_again_from(
        state: &BootstrapState,
        grant: &[u8],
        issuer: &Ed25519SigningKey,
    ) -> (rb::RecoveryBundleHeaderV2, RecoveryBundlePlaintextV2) {
        use crate::fleet_custody::tests::{mock, runtime};
        use shardx_core::mutation::{RootGenerationState, RootGrantState};
        let _lock = crate::store::config_root_test_lock()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().unwrap();
        crate::store::set_config_root(Some(dir.path().to_path_buf()));
        save(state).unwrap();
        let record = AuthorizationRecord::parse(grant)
            .unwrap()
            .verify_signature(issuer.verifying_key().as_bytes())
            .unwrap();
        let descriptor = TenantRootGrantDescriptorV2::new(
            record,
            RootGrantState::Acknowledged,
            RootGenerationState::Active,
        )
        .unwrap()
        .encode();
        let rt = runtime();
        let (client, _) = rt.block_on(mock(std::sync::Arc::new(move |call: &str, _: &[u8]| {
            if call.ends_with("/key-generation") {
                (200, br#"{"generation":0}"#.to_vec())
            } else if call.contains("/root-key-generations/") {
                (200, descriptor.clone())
            } else {
                (404, Vec::new())
            }
        })));
        let path = dir.path().join("again.bundle");
        let export = RecoveryExport {
            path: &path,
            passphrase: "correct horse battery",
        };
        let result = rt.block_on(export_again(
            &client,
            "access",
            &hex(&[1; 16]),
            &signer(),
            &HPKE_SEED,
            vec![(0, Zeroizing::new([0x44; 32]))],
            &export,
        ));
        let file = std::fs::read(&path);
        crate::store::set_config_root(None);
        assert_eq!(
            result.unwrap(),
            root_grant_sha256(state),
            "the exported grant"
        );
        open(&file.unwrap(), "correct horse battery").unwrap()
    }

    /// Q-52: the header's root generation is the current grant's, so a
    /// custodian of root generation 1 exports.
    #[test]
    fn export_again_succeeds_for_a_custodian_of_root_generation_1() {
        let (state, grant) = appointed_state(1);
        let (header, plaintext) = export_again_from(&state, &grant, &a0());
        assert_eq!(header.root_generation, 1);
        let custodian = plaintext.root_custodian.unwrap();
        assert_eq!(custodian.root_grant, grant);
        assert_eq!(
            custodian.root_grant_issuer,
            Some(a0().verifying_key().to_bytes())
        );
    }

    /// Q-52: a custodian that is not the anchor names the saved anchor `A0`,
    /// not its own key.
    #[test]
    fn the_v4_bundle_names_the_saved_anchor_not_the_custodian() {
        let (state, grant) = appointed_state(0);
        let (_, plaintext) = export_again_from(&state, &grant, &a0());
        let a0_id = signing_key_id(a0().verifying_key().as_bytes());
        assert_eq!(plaintext.bootstrap_anchor_signing_key_id, a0_id);
        assert_ne!(a0_id, cx().signing_key_id);
        let custodian = plaintext.root_custodian.unwrap();
        assert_eq!(*custodian.signing_key_seed, signer().to_bytes());
        assert_eq!(custodian.device_id, [5; 16]);
    }

    /// Q-53 (D3): while the first self-grant is current, export writes v3
    /// for 2.9.x to read.
    #[test]
    fn export_writes_v3_while_the_first_self_grant_is_current() {
        let (cx, first) = custodian_cx([5; 16], &[9; 32]);
        let state = BootstrapState {
            self_grant: hex(&first),
            anchor: hex(&cx.signing_key_id),
            ..Default::default()
        };
        let (header, plaintext) = export_again_from(&state, &first, &signer());
        assert_eq!(header.root_generation, 0);
        assert_eq!(plaintext.bootstrap_anchor_signing_key_id, cx.signing_key_id);
        let custodian = plaintext.root_custodian.unwrap();
        assert_eq!(custodian.root_grant_issuer, None);
        assert_eq!(custodian.root_grant, first);
    }

    /// Neither the debug print nor the status shows the current grant.
    #[test]
    fn a_root_state_with_a_current_grant_never_prints_it() {
        let (state, grant) = appointed_state(1);
        let printed = format!("{state:?}");
        let status = serde_json::to_string(&BootstrapStatus::of(&state)).unwrap();
        for shown in [printed, status] {
            assert!(!shown.contains(&hex(&grant)), "{shown}");
            assert!(!shown.contains(&state.root_grant_issuer), "{shown}");
        }
    }

    /// An activated custodian whose current grant replaced the first
    /// self-grant files no bootstrap records: those are generation 0's.
    #[test]
    fn an_activated_run_with_a_current_root_grant_keeps_no_bootstrap_records() {
        let _lock = crate::store::config_root_test_lock()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().unwrap();
        crate::store::set_config_root(Some(dir.path().to_path_buf()));
        let (state, _) = appointed_state(0);
        save(&state).unwrap();
        let client = FleetClient::new("http://127.0.0.1:9", "t").unwrap();
        let (tenant, device_id, account) = (
            state.tenant_id.clone(),
            state.device_id.clone(),
            hex(&cx().account),
        );
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
            hpke_seed: &HPKE_SEED,
            trk_store: &CredentialTrkStore,
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        let status = rt.block_on(run(&client, &device, Path::new("unused"), "pass"));
        let db = crate::team::db::Db::path().unwrap();
        crate::store::set_config_root(None);
        assert!(status.unwrap().activated);
        assert!(!db.exists(), "no team database was written");
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

    // ---- Root self-renewal (v2.10 4.R) ----

    use std::sync::{Arc, Mutex};

    thread_local! {
        /// How far this thread's launcher clock ([`now_ms`]) runs behind the
        /// real one: a real-server test backdates the records it builds.
        pub(crate) static CLOCK_BACK_MS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
        /// Makes this thread's renewal steps due whatever the records say,
        /// for a real-server journey whose records are all new.
        pub(crate) static RENEWAL_DUE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// When the renewal fixture's first records begin.
    pub(crate) const START: u64 = 1_800_000_000_000;
    pub(crate) const DAY: u64 = DAY_MS;
    const FKEK: [u8; 32] = [0x5a; 32];

    /// What the renewal server is told, and holds.
    pub(crate) struct RenewalServer {
        /// Its clock, as every evidence page states it.
        pub(crate) now: u64,
        pub(crate) active: Option<u64>,
        /// The first call containing the text is answered with the status.
        pub(crate) refuse: Option<(&'static str, u16)>,
        /// The containers its trust evidence serves.
        pub(crate) evidence: Vec<Vec<u8>>,
    }

    /// A root custodian whose own records, as the bootstrap and Create fleet
    /// key build them, began at `START` and run a year, against a mock server.
    pub(crate) struct Renewing {
        pub(crate) state: BootstrapState,
        pub(crate) custody: crate::fleet_custody::FleetCustodyState,
        pub(crate) server: Arc<Mutex<RenewalServer>>,
        pub(crate) client: FleetClient,
        pub(crate) seen: crate::fleet_custody::tests::Seen,
        pub(crate) collected: Arc<Mutex<Vec<u64>>>,
        pub(crate) saves: usize,
    }

    fn me_subject(cx: &Context16) -> shardx_core::authz_record::GrantSubject {
        shardx_core::authz_record::GrantSubject::Device {
            account_id: cx.account,
            device_id: cx.device,
            signing_key_id: cx.signing_key_id,
            hpke_key_id: cx.hpke_key_id,
        }
    }

    fn renewal_reply(server: Arc<Mutex<RenewalServer>>) -> Arc<crate::fleet_custody::tests::Reply> {
        use crate::fleet_custody::tests::stored;
        use shardx_core::fleet_lifecycle::*;
        use shardx_core::mutation::*;
        Arc::new(move |call: &str, body: &[u8]| {
            let mut s = server.lock().unwrap();
            if let Some((_, status)) = s.refuse.filter(|(t, _)| call.contains(t)) {
                s.refuse = None;
                return (status, br#"{"code":"REFUSED"}"#.to_vec());
            }
            let (cx, _) = custodian_cx([5; 16], &[9; 32]);
            let post = call.starts_with("POST ");
            // The server refuses a capability or fleet grant that has ended.
            let ended = |container: &[u8]| window(container).1 <= s.now;
            let refused = || (403, br#"{"code":"EXPIRED"}"#.to_vec());
            match call {
                c if c.contains("/trust-evidence") => {
                    let page = shardx_core::trust_evidence::TenantTrustEvidencePageV2 {
                        server_instance_id: cx.instance,
                        tenant_id: cx.tenant,
                        server_now_ms: s.now,
                        page_index: 0,
                        next_cursor: Vec::new(),
                        signing_public_keys: vec![signer().verifying_key().to_bytes()],
                        containers: s.evidence.clone(),
                        revocations: Vec::new(),
                        device_revocations: Vec::new(),
                    };
                    (200, page.encode())
                }
                c if c.ends_with("/key-generation") => match s.active {
                    Some(g) => (200, format!(r#"{{"generation":{g}}}"#).into_bytes()),
                    None => (200, b"null".to_vec()),
                },
                "POST /v2/capability-grants" if ended(body) => refused(),
                "POST /v2/capability-grants" => (201, body.to_vec()),
                c if post && c.ends_with("/approve") => {
                    let a = approval_of(body);
                    let receipt = DeviceApprovalReceiptV2 {
                        server_instance_id: cx.instance,
                        restore_epoch: 0,
                        tenant_id: cx.tenant,
                        actor_account_id: cx.account,
                        actor_device_id: cx.device,
                        subject_device_id: a.subject_device_id,
                        approval_replay_id: a.common.replay_id,
                        request_hash: device_approve_request_hash(
                            &cx.instance,
                            0,
                            &cx.tenant,
                            &cx.account,
                            &cx.device,
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
                c if post && c.contains("/root-key-generations/") && c.ends_with("/grants") => {
                    let reply = stored(body, RECORD_TYPE_ROOT_GRANT_CREATED, |p| {
                        TenantRootGrantCreatedV2 {
                            grant: TenantRootGrantCreateV2::parse(p).unwrap().grant,
                            grant_variant: "ExistingRootGrant",
                            subject_device_id: cx.device,
                            recipient_hpke_key_id: cx.hpke_key_id,
                            created_at_ms: 1,
                        }
                        .encode()
                    });
                    (201, reply)
                }
                c if post && c.contains("/root-key-generations/") && c.ends_with("/ack") => {
                    let reply = stored(body, RECORD_TYPE_ROOT_GRANT_ACKED, |p| {
                        TenantRootGrantAckedV2 {
                            grant: TenantRootGrantAckV2::parse(p).unwrap().grant,
                            acked_at_ms: 1,
                        }
                        .encode()
                    });
                    (201, reply)
                }
                c if post && c.starts_with("POST /v2/fleets/") && c.ends_with("/grants") => {
                    let request = IdempotentMutationRequestV2::parse(body).unwrap();
                    let filing =
                        FleetKeyGrantCreateV2::parse(&request.canonical_payload_bytes).unwrap();
                    if ended(&filing.exact_signed_grant_container_bytes) {
                        return refused();
                    }
                    let reply = stored(body, RECORD_TYPE_FLEET_GRANT_CREATED, |p| {
                        FleetKeyGrantCreatedV2 {
                            grant: FleetKeyGrantCreateV2::parse(p).unwrap().grant,
                            target: FleetGrantTarget::Device {
                                subject_device_id: cx.device,
                            },
                            created_at_ms: 1,
                        }
                        .encode()
                    });
                    (201, reply)
                }
                c if post && c.starts_with("POST /v2/fleets/") && c.ends_with("/ack") => {
                    let reply = stored(body, RECORD_TYPE_FLEET_GRANT_ACKED, |p| {
                        FleetKeyGrantAckedV2 {
                            grant: FleetKeyGrantAckV2::parse(p).unwrap().grant,
                            acked_at_ms: 1,
                        }
                        .encode()
                    });
                    (201, reply)
                }
                _ => (500, Vec::new()),
            }
        })
    }

    /// The renewal fixture on `rt`; the server's clock reads `server_now`.
    pub(crate) fn renewal_fixture(rt: &tokio::runtime::Runtime, server_now: u64) -> Renewing {
        let (cx, _) = custodian_cx([5; 16], &[9; 32]);
        let (_, pk) = derive_keypair(&HPKE_SEED);
        // `common` backdates by the skew: built here, they begin at `START`.
        let built = START + CLOCK_SKEW_MS;
        let approval = self_approval(&cx, &signer(), built).unwrap();
        let replay = approval_of(&approval).common.replay_id;
        let grant = self_grant(&cx, &signer(), &pk, &[9; 32], replay, built).unwrap();
        let own = crate::fleet_custody::own_grants(&cx, cx.tenant);
        let grants =
            crate::fleet_custody::capability_grants(&cx, &signer(), &me_subject(&cx), own, built)
                .unwrap();
        let state = BootstrapState {
            tenant_id: hex(&cx.tenant),
            device_id: hex(&cx.device),
            server_instance_id: hex(&cx.instance),
            approval: hex(&approval),
            self_grant: hex(&grant),
            activated: true,
            anchor: hex(&cx.signing_key_id),
            ..Default::default()
        };
        let custody = crate::fleet_custody::FleetCustodyState {
            tenant_id: hex(&cx.tenant),
            device_id: hex(&cx.device),
            server_instance_id: hex(&cx.instance),
            capability_grants: grants.clone(),
            ..Default::default()
        };
        let mut evidence = vec![approval, grant];
        evidence.extend(grants.iter().map(|g| unhex_vec(g).unwrap()));
        let server = Arc::new(Mutex::new(RenewalServer {
            now: server_now,
            active: Some(0),
            refuse: None,
            evidence,
        }));
        let (client, seen) = rt.block_on(crate::fleet_custody::tests::mock(renewal_reply(
            server.clone(),
        )));
        Renewing {
            state,
            custody,
            server,
            client,
            seen,
            collected: Arc::default(),
            saves: 0,
        }
    }

    impl Renewing {
        /// One renewal step at the local clock `local_now`.
        pub(crate) async fn renew_at(&mut self, local_now: u64) -> Result<RenewalOutcome> {
            let (signer, account) = (signer(), hex(&[4; 16]));
            let me = RenewingDevice {
                account_id: &account,
                signer: &signer,
                hpke_seed: &HPKE_SEED,
            };
            let collected = self.collected.clone();
            let saves = &mut self.saves;
            renew(
                &self.client,
                "access",
                &me,
                &self.custody,
                None,
                local_now,
                |_| Ok(Zeroizing::new(FKEK)),
                async move |g| {
                    collected.lock().unwrap().push(g);
                    Ok(())
                },
                &mut self.state,
                &mut |_| {
                    *saves += 1;
                    Ok(())
                },
            )
            .await
        }

        /// Every POST so far, with its body.
        pub(crate) fn posts(&self) -> Vec<(String, Vec<u8>)> {
            self.seen
                .lock()
                .unwrap()
                .iter()
                .filter(|(c, _)| c.starts_with("POST "))
                .cloned()
                .collect()
        }

        /// The finished or saved renewal.
        fn run(&self) -> Renewal {
            self.state.renewal.clone().expect("a renewal")
        }

        /// The containers the renewal holds, for evidence.
        fn renewed_records(&self) -> Vec<Vec<u8>> {
            let r = self.run();
            let mut out = vec![
                unhex_vec(&r.approval).unwrap(),
                unhex_vec(&r.root_grant).unwrap(),
            ];
            out.extend(r.capability_grants.iter().map(|g| unhex_vec(g).unwrap()));
            out
        }
    }

    /// The window of a container this device signed.
    fn window(container: &[u8]) -> (u64, u64) {
        window_of(container, signer().verifying_key().as_bytes()).expect("own record")
    }

    /// The containers a saved request files.
    fn filed_container(saved: &str) -> Vec<u8> {
        let (request, _) = super::saved(saved).unwrap();
        shardx_core::fleet_lifecycle::FleetKeyGrantCreateV2::parse(&request.canonical_payload_bytes)
            .unwrap()
            .exact_signed_grant_container_bytes
    }

    fn short(call: &str) -> String {
        let path = call.trim_start_matches("POST ");
        let parts: Vec<&str> = path.split('/').collect();
        match parts.as_slice() {
            [.., "capability-grants"] => "capability".into(),
            [.., "approve"] => "approve".into(),
            [.., "root-key-generations", _, "grants"] => "root grant".into(),
            [.., "root-key-generations", _, "grants", _, "ack"] => "root ack".into(),
            [.., "key-generations", _, "grants"] => "device grant".into(),
            [.., "key-generations", _, "ack"] => "device ack".into(),
            _ => call.into(),
        }
    }

    /// 4.R: a custodian past half its records' life renews them in D-6
    /// order (capability grants, self-approval, `ExistingRootGrant`, its
    /// ack, the device grant of the ACTIVE generation, its ack, the verified
    /// collect), and only then makes the new records current.
    #[test]
    fn a_due_custodian_renews_capabilities_approval_root_grant_and_device_grant_in_order() {
        let rt = crate::fleet_custody::tests::runtime();
        let now = START + 200 * DAY;
        let mut f = renewal_fixture(&rt, now);
        let first = f.state.clone();
        assert_eq!(
            rt.block_on(f.renew_at(now)).unwrap(),
            RenewalOutcome::Renewed
        );
        let order: Vec<String> = f.posts().iter().map(|(c, _)| short(c)).collect();
        let mut want = vec!["capability".to_string(); 6];
        want.extend(
            [
                "approve",
                "root grant",
                "root ack",
                "device grant",
                "device ack",
            ]
            .map(String::from),
        );
        assert_eq!(order, want);
        assert_eq!(*f.collected.lock().unwrap(), vec![0], "the collect of N");

        let run = f.run();
        assert!(run.done);
        assert_eq!(f.state.root_grant, run.root_grant);
        assert_eq!(f.state.approval, run.approval);
        assert_eq!(
            f.state.root_grant_issuer,
            hex(signer().verifying_key().as_bytes())
        );
        assert_eq!(f.state.self_grant, first.self_grant, "kept beside it");
        let (grant, _, issuer) = current_root_grant(&f.state, &signer()).unwrap();
        assert_eq!(grant.variant, RootGrantVariant::ExistingRootGrant);
        assert_eq!(issuer, signer().verifying_key().to_bytes());
        let (old, _, _) = current_root_grant(&first, &signer()).unwrap();
        assert_eq!(
            (grant.root_key_id, grant.root_generation),
            (old.root_key_id, old.root_generation)
        );
        let approval = approval_of(&unhex_vec(&run.approval).unwrap());
        assert_eq!(
            grant.subject_device_approval_replay_id,
            approval.common.replay_id
        );
        let (sk, _) = derive_keypair(&HPKE_SEED);
        assert_eq!(*grant.open_trk(&sk).unwrap(), [9; 32], "the same TRK");
    }

    /// A-MF5: the records start at `min(local, server) - CLOCK_SKEW_MS`, so
    /// a local clock ahead of the server's never dates them into the future.
    #[test]
    fn a_renewal_takes_its_times_from_the_servers_clock() {
        let rt = crate::fleet_custody::tests::runtime();
        let server = START + 200 * DAY;
        for local in [server + 10 * DAY, server - DAY] {
            let mut f = renewal_fixture(&rt, server);
            assert_eq!(
                rt.block_on(f.renew_at(local)).unwrap(),
                RenewalOutcome::Renewed
            );
            let t = local.min(server) - CLOCK_SKEW_MS;
            let run = f.run();
            for record in f.renewed_records() {
                assert_eq!(window(&record).0, t);
            }
            assert_eq!(window(&filed_container(&run.device_grant_request)).0, t);
        }
        // Due by the local clock only: the server's says not yet.
        let mut f = renewal_fixture(&rt, START + 100 * DAY);
        assert_eq!(
            rt.block_on(f.renew_at(START + 300 * DAY)).unwrap(),
            RenewalOutcome::NotDue
        );
        assert!(f.posts().is_empty());
        assert!(f.state.renewal.is_none());
    }

    /// A-MF5: a local clock past the records' end proves no lapse: the
    /// server's time decides, and a refusal is returned as it is.
    #[test]
    fn a_fast_local_clock_never_declares_a_lapse() {
        let rt = crate::fleet_custody::tests::runtime();
        let mut f = renewal_fixture(&rt, START + 200 * DAY);
        f.server.lock().unwrap().refuse = Some(("/capability-grants", 403));
        let err = rt
            .block_on(f.renew_at(START + 900 * DAY))
            .unwrap_err()
            .to_string();
        assert!(!err.contains("fleet.custodyLapsed"), "{err}");
        assert!(err.contains("status=403"), "{err}");
    }

    /// 4.R: a lapse needs both: the chain evaluated at the server's time no
    /// longer counts this device, and the server refused with 403.
    #[test]
    fn a_lapse_is_declared_only_when_the_chain_at_server_time_and_a_403_agree() {
        let rt = crate::fleet_custody::tests::runtime();
        let ended = START + 400 * DAY;
        let lapse = |status: u16| {
            let mut f = renewal_fixture(&rt, ended);
            f.server.lock().unwrap().refuse = Some(("/capability-grants", status));
            rt.block_on(f.renew_at(ended)).unwrap_err().to_string()
        };
        assert!(lapse(403).contains("fleet.custodyLapsed"), "{}", lapse(403));
        let other = lapse(500);
        assert!(!other.contains("fleet.custodyLapsed"), "{other}");
        assert!(other.contains("status=500"), "{other}");
        // Before the end, the chain still counts this device.
        let mut f = renewal_fixture(&rt, START + 200 * DAY);
        f.server.lock().unwrap().refuse = Some(("/capability-grants", 403));
        let refused = rt.block_on(f.renew_at(START + 200 * DAY)).unwrap_err();
        assert!(
            !refused.to_string().contains("fleet.custodyLapsed"),
            "{refused}"
        );
    }

    /// 4.R: while the chain still counts this device at the server's time, a
    /// 403 is the server's own refusal, returned unchanged.
    #[test]
    fn a_403_before_the_records_end_is_returned_unchanged() {
        let rt = crate::fleet_custody::tests::runtime();
        let now = START + 200 * DAY;
        let mut f = renewal_fixture(&rt, now);
        f.server.lock().unwrap().refuse = Some(("/root-key-generations/", 403));
        let err = rt.block_on(f.renew_at(now)).unwrap_err().to_string();
        assert!(!err.contains("fleet.custodyLapsed"), "{err}");
        assert!(
            err.contains("fleet.refusedCustody") && err.contains("status=403"),
            "{err}"
        );
        assert!(!f.run().done, "the run stays saved for a resume");
    }

    /// A-MF6: the renewed approval and root grant run 730 days, the
    /// capability and device grants 365.
    #[test]
    fn renewed_custody_records_run_730_days() {
        let rt = crate::fleet_custody::tests::runtime();
        let now = START + 200 * DAY;
        let mut f = renewal_fixture(&rt, now);
        rt.block_on(f.renew_at(now)).unwrap();
        let run = f.run();
        let span = |c: &[u8]| {
            let (nb, na) = window(c);
            na - nb
        };
        assert_eq!(span(&unhex_vec(&run.approval).unwrap()), 730 * DAY);
        assert_eq!(span(&unhex_vec(&run.root_grant).unwrap()), 730 * DAY);
        assert_eq!(run.capability_grants.len(), 6);
        for g in &run.capability_grants {
            assert_eq!(span(&unhex_vec(g).unwrap()), 365 * DAY);
        }
        assert_eq!(span(&filed_container(&run.device_grant_request)), 365 * DAY);
    }

    /// 4.R: 730 days is exactly the server's cap for an approval and a root
    /// grant (`MAX_DEVICE_APPROVAL_TTL_MS`); one millisecond more is refused.
    #[test]
    fn a_730_day_renewal_window_is_exactly_the_server_cap() {
        assert_eq!(RENEWED_VALIDITY_MS, 63_072_000_000);
        assert_eq!(
            RENEWED_VALIDITY_MS,
            shardx_core::approval_receipt::MAX_DEVICE_APPROVAL_TTL_MS
        );
    }

    /// Plan pre-mortem 5: the renewed grant counts from `T`, inside the old
    /// window, so the chain counts this device across the old end.
    #[test]
    fn a_renewal_crosses_the_old_expiry_with_no_gap() {
        let rt = crate::fleet_custody::tests::runtime();
        let now = START + 200 * DAY;
        let mut f = renewal_fixture(&rt, now);
        rt.block_on(f.renew_at(now)).unwrap();
        let old_end = window(&unhex_vec(&f.state.self_grant).unwrap()).1;
        let mut evidence = f.server.lock().unwrap().evidence.clone();
        evidence.extend(f.renewed_records());
        let (cx, _) = custodian_cx([5; 16], &[9; 32]);
        let page = shardx_core::trust_evidence::TenantTrustEvidencePageV2 {
            server_instance_id: cx.instance,
            tenant_id: cx.tenant,
            server_now_ms: now,
            page_index: 0,
            next_cursor: Vec::new(),
            signing_public_keys: vec![signer().verifying_key().to_bytes()],
            containers: evidence,
            revocations: Vec::new(),
            device_revocations: Vec::new(),
        };
        let binding = Binding {
            server_instance_id: cx.instance,
            tenant_id: cx.tenant,
        };
        let chain = TrustChain::evaluate(
            Evidence::collect(&binding, &[page]).unwrap(),
            Some(&cx.signing_key_id),
        )
        .unwrap();
        let t = now - CLOCK_SKEW_MS;
        for at in [t, old_end - 1, old_end, old_end + DAY, t + 729 * DAY] {
            assert!(chain.custodian_at(&cx.signing_key_id, at), "at {at}");
        }
        assert!(!chain.custodian_at(&cx.signing_key_id, t + 730 * DAY));
    }

    /// Each request is built once and saved before the first is sent: a run
    /// that stopped resumes, even before it is due, at the step that was not
    /// answered, resending the same bytes.
    #[test]
    fn renewal_resumes_each_step_with_byte_identical_requests() {
        let rt = crate::fleet_custody::tests::runtime();
        let now = START + 200 * DAY;
        let mut f = renewal_fixture(&rt, now);
        f.server.lock().unwrap().refuse = Some(("/ack", 503));
        assert!(rt.block_on(f.renew_at(now)).is_err());
        let saved = f.run();
        assert!(!saved.done);
        let first = f.posts();
        assert_eq!(short(&first.last().unwrap().0), "root ack");
        f.seen.lock().unwrap().clear();

        // Resumed later, and at a clock that would not be due.
        assert_eq!(
            rt.block_on(f.renew_at(START)).unwrap(),
            RenewalOutcome::Renewed
        );
        let second = f.posts();
        let order: Vec<String> = second.iter().map(|(c, _)| short(c)).collect();
        assert_eq!(order, ["root ack", "device grant", "device ack"]);
        assert_eq!(first.last(), second.first(), "byte-identical resend");
        assert_eq!(
            Renewal {
                done: true,
                step: 11,
                ..saved
            },
            f.run(),
            "nothing rebuilt"
        );
    }

    /// One root grant per renewal: a resume goes on after the answered one,
    /// and a finished renewal is not due again.
    #[test]
    fn a_renewal_never_files_two_root_grants() {
        let rt = crate::fleet_custody::tests::runtime();
        let now = START + 200 * DAY;
        let mut f = renewal_fixture(&rt, now);
        f.server.lock().unwrap().refuse = Some(("/key-generations/0/grants", 503));
        assert!(rt.block_on(f.renew_at(now)).is_err());
        rt.block_on(f.renew_at(now)).unwrap();
        for later in [now, now + DAY, now + 100 * DAY] {
            assert_eq!(
                rt.block_on(f.renew_at(later)).unwrap(),
                RenewalOutcome::NotDue
            );
        }
        let sent: Vec<Vec<u8>> = f
            .posts()
            .into_iter()
            .filter(|(c, _)| short(c) == "root grant")
            .map(|(_, body)| body)
            .collect();
        assert_eq!(sent.len(), 1, "filed once, never resent");
    }

    /// A run that stopped before its root grant was sent and then sat past
    /// half its own life is dropped and built again at the server's time,
    /// never resent with records that have ended.
    #[test]
    fn a_stale_unsent_renewal_is_rebuilt() {
        let rt = crate::fleet_custody::tests::runtime();
        let now = START + 200 * DAY;
        let mut f = renewal_fixture(&rt, now);
        f.server.lock().unwrap().refuse = Some(("/capability-grants", 503));
        assert!(rt.block_on(f.renew_at(now)).is_err());
        let stale = f.run();
        f.seen.lock().unwrap().clear();

        let later = now + 400 * DAY;
        f.server.lock().unwrap().now = later;
        assert_eq!(
            rt.block_on(f.renew_at(later)).unwrap(),
            RenewalOutcome::Renewed
        );
        let run = f.run();
        assert_ne!(run.capability_grants, stale.capability_grants, "rebuilt");
        assert_eq!(
            window(&unhex_vec(&run.root_grant).unwrap()).0,
            later - CLOCK_SKEW_MS
        );
        let roots: Vec<_> = f
            .posts()
            .into_iter()
            .filter(|(c, _)| short(c) == "root grant")
            .map(|(_, body)| body)
            .collect();
        assert_eq!(roots.len(), 1, "one root grant");
        assert_eq!(roots[0], saved(&run.root_grant_request).unwrap().1);
    }

    /// A run whose root grant was acked and then sat past half its own life
    /// finishes without its device grant, which has ended or soon will: the
    /// next renewal is due at once and grants the device again.
    #[test]
    fn a_renewal_past_its_root_ack_completes_without_its_expired_device_grant() {
        let rt = crate::fleet_custody::tests::runtime();
        let now = START + 200 * DAY;
        let mut f = renewal_fixture(&rt, now);
        f.server.lock().unwrap().refuse = Some(("/key-generations/0/grants", 503));
        assert!(rt.block_on(f.renew_at(now)).is_err());
        let saved = f.run();
        f.seen.lock().unwrap().clear();

        let later = now + 400 * DAY;
        f.server.lock().unwrap().now = later;
        assert_eq!(
            rt.block_on(f.renew_at(later)).unwrap(),
            RenewalOutcome::Renewed
        );
        assert!(f.posts().is_empty(), "{:?}", f.posts());
        assert!(f.collected.lock().unwrap().is_empty());
        let run = f.run();
        assert!(run.done);
        assert_eq!(run.root_grant, saved.root_grant, "nothing rebuilt");
        assert_eq!(f.state.root_grant, saved.root_grant);
    }

    /// A trust-evidence reply without the server's time proves nothing: no
    /// request is sent and a refusal is never read as a lapse.
    #[test]
    fn a_reply_without_the_servers_time_is_never_a_lapse() {
        let rt = crate::fleet_custody::tests::runtime();
        let now = START + 200 * DAY;
        let mut f = renewal_fixture(&rt, now);
        f.server.lock().unwrap().refuse = Some(("/capability-grants", 503));
        assert!(rt.block_on(f.renew_at(now)).is_err());
        f.seen.lock().unwrap().clear();

        f.server.lock().unwrap().now = 0;
        f.server.lock().unwrap().refuse = Some(("/capability-grants", 403));
        let err = rt.block_on(f.renew_at(now)).unwrap_err().to_string();
        assert!(!err.contains("fleet.custodyLapsed"), "{err}");
        assert!(err.contains("fleet.custodyReplyMismatch"), "{err}");
        assert!(f.posts().is_empty(), "{:?}", f.posts());
    }

    /// 4.H: a custodian that handed its custody over never renews.
    #[test]
    fn a_handed_over_root_never_renews() {
        let rt = crate::fleet_custody::tests::runtime();
        let now = START + 300 * DAY;
        let mut f = renewal_fixture(&rt, now);
        f.custody.handed_over_to = hex(&[0x99; 16]);
        assert_eq!(
            rt.block_on(f.renew_at(now)).unwrap(),
            RenewalOutcome::HandedOver
        );
        assert!(f.seen.lock().unwrap().is_empty());
        assert!(f.state.renewal.is_none());
    }

    /// D9: on sync the renewal never waits for the custody lock: while
    /// another custody command holds it, the step is skipped, with no
    /// request and nothing read.
    #[test]
    fn a_busy_custody_lock_skips_the_renewal() {
        let _lock = crate::store::config_root_test_lock()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let rt = crate::fleet_custody::tests::runtime();
        let held = crate::fleet_custody::begin().unwrap();
        // Nothing listens here.
        let client = FleetClient::new("http://127.0.0.1:9", "t").unwrap();
        let c = crate::team_config::TeamConfig::default();
        let outcome = rt.block_on(crate::renew_quietly(&client, &c, "access"));
        drop(held);
        assert_eq!(outcome.unwrap(), RenewalOutcome::Busy);
    }

    /// F23, a known limitation: a member offline past the old root grant's
    /// end holds the custodian lapsed, so a renewal it first sees afterwards
    /// never counts there, though it was issued in time. A member that saw
    /// the renewal before the old end keeps the custodian.
    #[test]
    fn a_member_offline_past_the_old_root_grant_end_refuses_the_self_renewal() {
        use crate::team::{db::Db, ledger};
        let rt = crate::fleet_custody::tests::runtime();
        let renewed_at = START + 200 * DAY;
        let mut f = renewal_fixture(&rt, renewed_at);
        rt.block_on(f.renew_at(renewed_at)).unwrap();
        let old = f.server.lock().unwrap().evidence.clone();
        let mut both = old.clone();
        both.extend(f.renewed_records());
        let (cx, _) = custodian_cx([5; 16], &[9; 32]);
        let binding = Binding {
            server_instance_id: cx.instance,
            tenant_id: cx.tenant,
        };
        let page = |containers: Vec<Vec<u8>>, now: u64| {
            shardx_core::trust_evidence::TenantTrustEvidencePageV2 {
                server_instance_id: cx.instance,
                tenant_id: cx.tenant,
                server_now_ms: now,
                page_index: 0,
                next_cursor: Vec::new(),
                signing_public_keys: vec![signer().verifying_key().to_bytes()],
                containers,
                revocations: Vec::new(),
                device_revocations: Vec::new(),
            }
        };
        let anchor = cx.signing_key_id;
        // A member's ledger: what it saw at `first`, then all at `back`.
        let member = |back: u64| {
            let dir = tempfile::tempdir().unwrap();
            let mut db = Db::open_at(&dir.path().join("m.db")).unwrap();
            ledger::pin_anchor(&db, &binding, &anchor, ledger::JOIN, START).unwrap();
            for (containers, now) in [(old.clone(), START + DAY), (both.clone(), back)] {
                let pages = [page(containers, now)];
                let (seen, chain) = ledger::evaluate(&db, &binding, &anchor, &pages, now)
                    .unwrap()
                    .expect("verifies");
                ledger::record(&mut db, &binding, &seen, &chain, None, false, now).unwrap();
            }
            let pages = [page(both.clone(), START + 400 * DAY)];
            let (_, chain) = ledger::evaluate(&db, &binding, &anchor, &pages, START + 400 * DAY)
                .unwrap()
                .unwrap();
            chain.custodian_now(&anchor, START + 400 * DAY)
        };
        assert!(!member(START + 380 * DAY), "offline past the old end");
        assert!(member(START + 250 * DAY), "back before the old end");
    }

    /// After a renewal Export again writes a v4 bundle with the renewed,
    /// self-issued grant, after the import's own root grant check (step 5)
    /// passed on it, and the bundle opens. The chain an import evaluates is
    /// `a_renewal_crosses_the_old_expiry_with_no_gap`'s.
    #[test]
    fn a_renewal_exports_a_v4_bundle_whose_grant_passes_the_import_root_grant_check() {
        let rt = crate::fleet_custody::tests::runtime();
        let now = START + 200 * DAY;
        let mut f = renewal_fixture(&rt, now);
        rt.block_on(f.renew_at(now)).unwrap();
        let grant = unhex_vec(&f.state.root_grant).unwrap();
        let (header, plaintext) = export_again_from(&f.state, &grant, &signer());
        assert_eq!(header.root_generation, 0);
        let custodian = plaintext.root_custodian.unwrap();
        assert_eq!(custodian.root_grant, grant);
        assert_eq!(
            custodian.root_grant_issuer,
            Some(signer().verifying_key().to_bytes())
        );
        assert_eq!(
            plaintext.bootstrap_anchor_signing_key_id,
            custodian_cx([5; 16], &[9; 32]).0.signing_key_id
        );
    }

    /// A custodian imported from a bundle exported after a renewal keeps only
    /// the renewed grant; its key age still counts from the first root grant,
    /// which the trust ledger remembers.
    #[test]
    fn an_imported_custodian_counts_its_key_age_from_the_ledgers_first_grant() {
        use crate::team::{db::Db, ledger};
        let _lock = crate::store::config_root_test_lock()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().unwrap();
        crate::store::set_config_root(Some(dir.path().to_path_buf()));
        let rt = crate::fleet_custody::tests::runtime();
        let now = START + 200 * DAY;
        let mut f = renewal_fixture(&rt, now);
        rt.block_on(f.renew_at(now)).unwrap();
        let imported = BootstrapState {
            self_grant: String::new(),
            renewal: None,
            ..f.state.clone()
        };
        let own = signer().verifying_key().to_bytes();
        let renewed = first_not_before(&imported, &own);

        let mut evidence = f.server.lock().unwrap().evidence.clone();
        evidence.extend(f.renewed_records());
        let (cx, _) = custodian_cx([5; 16], &[9; 32]);
        let (binding, anchor) = pin_of(&imported).unwrap();
        let page = shardx_core::trust_evidence::TenantTrustEvidencePageV2 {
            server_instance_id: cx.instance,
            tenant_id: cx.tenant,
            server_now_ms: now,
            page_index: 0,
            next_cursor: Vec::new(),
            signing_public_keys: vec![own],
            containers: evidence,
            revocations: Vec::new(),
            device_revocations: Vec::new(),
        };
        let mut db = Db::open().unwrap();
        ledger::pin_anchor(&db, &binding, &anchor, ledger::BOOTSTRAP, now).unwrap();
        let (seen, chain) = ledger::evaluate(&db, &binding, &anchor, &[page], now)
            .unwrap()
            .expect("verifies");
        ledger::record(&mut db, &binding, &seen, &chain, None, false, now).unwrap();
        drop(db);
        let counted = first_not_before(&imported, &own);
        crate::store::set_config_root(None);
        assert_eq!(
            renewed,
            Some(now - CLOCK_SKEW_MS),
            "the renewed grant alone"
        );
        assert_eq!(counted, Some(START), "the ledger's first grant");
    }

    /// No key is among the renewal state: not the seeds, the TRK or the
    /// fleet key.
    #[test]
    fn the_renewal_state_holds_no_key_bytes() {
        let rt = crate::fleet_custody::tests::runtime();
        let now = START + 200 * DAY;
        let mut f = renewal_fixture(&rt, now);
        f.server.lock().unwrap().refuse = Some(("/ack", 503));
        let _ = rt.block_on(f.renew_at(now));
        let mid = serde_json::to_string(&f.state).unwrap();
        rt.block_on(f.renew_at(now)).unwrap();
        let done = serde_json::to_string(&f.state).unwrap();
        for text in [mid, done] {
            for secret in [signer().to_bytes(), HPKE_SEED, [9; 32], FKEK] {
                assert!(!text.contains(&hex(&secret)), "a key in the state");
            }
            assert!(text.contains("\"renewal\""));
        }
    }
}
