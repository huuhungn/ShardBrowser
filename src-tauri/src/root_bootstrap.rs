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
//! response. The TRK is saved before anything that names it is sent, so the
//! key never exists only on the server. Every reply is checked against the
//! request it answers before the next step runs.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

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

/// What the bootstrap keeps between attempts, hex-encoded, written before
/// each request leaves the device.
// shortcut: while the bootstrap runs, the TRK sits in this file in the clear
// (owner-only on Unix) and in plain `String`s that are not zeroized. It is
// cleared once the generation is active: the device reopens its self-grant
// with its HPKE key, and the recovery bundle holds it. Keeping it in the OS
// store instead waits for the fallback key file (G2-48).
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
    #[serde(default)]
    pub trk: String,
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
            .field("trk", &"<redacted>")
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

/// Writes `bytes` over `path` so a crash leaves the old file or the new one:
/// a synced sibling `<path>.tmp`, owner-only on Unix, renamed into place.
pub(crate) fn write_durably(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = std::path::PathBuf::from(tmp);
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    crate::fleet_keys::restrict(&tmp);
    std::fs::rename(&tmp, path)?;
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
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
    write_durably(recovery.path, &file).with_context(failed)?;
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
    if state.activated {
        return Ok(());
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

        // 2. The TRK is saved before anything names it.
        if state.trk.is_empty() {
            let trk = hex(&random::<32>()?);
            commit(state, save, |s| s.trk = trk)?;
        }
        let trk: [u8; 32] = unhex(&state.trk)?;
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
                .is_ok_and(|opened| *opened == trk),
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
        let anchor = hex(chain.anchor());
        commit(state, save, |s| {
            s.anchor = anchor;
            s.activated = true;
            s.trk.clear();
        })
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
    let result = bootstrap_root(client, device, &recovery, &mut state, &mut |s| save(s)).await;
    result.map(|()| BootstrapStatus::of(&state))
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
    let body = std::fs::read_to_string(&path)?;
    serde_json::from_str(&body).map_err(|_| corrupt())
}

/// Saves the bootstrap state durably: a torn write or a power cut must not
/// lose the TRK or a request the server may already hold.
pub fn save(state: &BootstrapState) -> Result<()> {
    let path = crate::store::custody_bootstrap_path()?;
    write_durably(&path, serde_json::to_string_pretty(state)?.as_bytes())?;
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
        assert!(commit(&mut state, &mut refuse, |s| s.trk = "ab".into()).is_err());
        assert!(state.trk.is_empty());
        let mut saved = Vec::new();
        let mut accept = |s: &BootstrapState| -> Result<()> {
            saved.push(s.trk.clone());
            Ok(())
        };
        commit(&mut state, &mut accept, |s| s.trk = "ab".into()).unwrap();
        assert_eq!((state.trk.as_str(), saved), ("ab", vec!["ab".to_string()]));
    }

    #[test]
    fn a_durable_write_replaces_the_file_and_leaves_no_temporary() {
        let dir = std::env::temp_dir().join(format!("shardx-durable-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        write_durably(&path, b"one").unwrap();
        write_durably(&path, b"two").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
        assert!(!dir.join("state.json.tmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_saved_state_never_prints_the_trk() {
        let s = BootstrapState {
            trk: "ab".repeat(32),
            ..Default::default()
        };
        assert!(!format!("{s:?}").contains("abab"));
    }
}
