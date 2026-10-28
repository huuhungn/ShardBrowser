//! Exact `RestoreEpochTransitionV2`, `RestoreEpochLeafV2` and
//! `RestoreEpochInclusionProofV2` codecs (plan 5.6.3 L667-L749, L374; ADR 0002
//! D-1 and the D-2 issuer matrix L724).
//!
//! A transition is tenant scoped over the server-global epoch: a root custodian
//! of the tenant signs the root of the sorted `(tenant_id, profile_id)` leaf set,
//! and each binding is unquarantined only by an inclusion proof of its own leaf
//! against that signed root. The tree math lives in [`crate::envelope`]; this
//! module owns the closed wire maps around it.
//!
//! The transition has its own TBS and container labels (L745, L748), so it is
//! not a [`crate::authz_record`] payload and no authorization signature can be
//! replayed as one. A parsed transition is only well formed: whether its signer
//! is an active `root.custody` holder of `tenant_id` is the caller's lookup.

use ed25519_dalek::{Signer, SigningKey};

use crate::authz_record::{Fields, RecordError};
use crate::canonical::{self as c, Value};
use crate::envelope::{
    self as ev, leaf_hash, merkle_proof_steps, merkle_root, restore_epoch_leaf_bytes, EpochLeaf,
    MerkleError, ProofError, ProofStep, DIR_SIBLING_LEFT, DIR_SIBLING_RIGHT, DIR_UNARY_PROMOTE,
};
use crate::keys::signing_key_id;
use crate::signing::{self, ED25519_SIG_LEN, SIGNATURE_SUITE_ID_ED25519, SIGNATURE_VERSION};

pub const DOMAIN_RESTORE_EPOCH_LEAF: &str = "shardx.restore-epoch.profile-head-leaf.v2";
pub const DOMAIN_RESTORE_EPOCH_INCLUSION_PROOF: &str = "shardx.restore-epoch.inclusion-proof.v2";
pub const DOMAIN_RESTORE_EPOCH_TRANSITION_PAYLOAD: &str =
    "shardx.restore-epoch.transition-payload.v2";
pub const DOMAIN_RESTORE_EPOCH_SIGNED_TRANSITION_CONTAINER: &str =
    "shardx.restore-epoch.signed-transition-container.v2";
/// The one mapping codec (L689): sorted leaves under the L684-L685 tree.
pub const MAPPING_CODEC: &str = "PROFILE_HEAD_SET_MERKLE_V2";

const VERSION: u16 = 2;
/// L742: `canonical_transition_payload_bytes:Bytes(1,131072)`.
const MAX_TRANSITION_PAYLOAD_BYTES: usize = 131_072;
const MAX_SIGNATURE_BYTES: usize = 4096;
/// Both byte fields at their caps plus room for the other nine fields, checked
/// before decoding so an oversized body is refused without being parsed.
pub const MAX_SIGNED_TRANSITION_BYTES: usize =
    MAX_TRANSITION_PAYLOAD_BYTES + MAX_SIGNATURE_BYTES + 1024;
/// L708: `canonical_leaf_bytes:Bytes(1,1024)`.
const MAX_LEAF_BYTES: usize = 1024;
/// L710: `steps` length `0..20`, enough for `MAX_RESTORE_EPOCH_LEAVES_V2`.
pub const MAX_PROOF_STEPS: usize = 20;
/// The leaf and every step at their caps plus room for the fixed fields.
pub const MAX_PROOF_BYTES: usize = MAX_LEAF_BYTES + MAX_PROOF_STEPS * 64 + 1024;

type Result<T> = std::result::Result<T, RecordError>;

// ------------------------------------------------------ RestoreEpochLeafV2 ---

/// One profile's `previous -> new` signed head under a transition (L669-L674).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreEpochLeafV2 {
    pub tenant_id: [u8; 16],
    pub profile_id: [u8; 16],
    pub previous_signed_head_hash: [u8; 32],
    pub new_signed_head_hash: [u8; 32],
}

impl RestoreEpochLeafV2 {
    pub fn parse(exact: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("RestoreEpochLeafV2", exact)?;
        f.exact_text("domain", DOMAIN_RESTORE_EPOCH_LEAF)?;
        if f.u16("version")? != VERSION {
            return Err(RecordError::BadValue("version"));
        }
        let leaf = Self {
            tenant_id: f.fixed("tenant_id")?,
            profile_id: f.fixed("profile_id")?,
            previous_signed_head_hash: f.fixed("previous_signed_head_hash")?,
            new_signed_head_hash: f.fixed("new_signed_head_hash")?,
        };
        f.finish()?;
        // L672-L674: a profile without a pinned previous head is not covered,
        // and must not be smuggled in as a zero hash.
        if leaf.previous_signed_head_hash == [0; 32] {
            return Err(RecordError::BadValue("previous_signed_head_hash"));
        }
        Ok(leaf)
    }

    pub fn encode(&self) -> Vec<u8> {
        restore_epoch_leaf_bytes(
            &self.tenant_id,
            &self.profile_id,
            &self.previous_signed_head_hash,
            &self.new_signed_head_hash,
        )
    }

    /// L676 `leaf_hash` over the exact leaf bytes.
    pub fn hash(&self) -> [u8; 32] {
        leaf_hash(&self.encode())
    }

    fn epoch_leaf(&self) -> EpochLeaf {
        (self.tenant_id, self.profile_id, self.encode())
    }
}

/// `profile_head_mapping_root` of `tenant_id`'s leaf set. Empty, oversized,
/// duplicate, unsorted and cross-tenant sets, and leaves without a previous
/// head, are refused (L676-L680, L1112), never normalized.
pub fn mapping_root(
    tenant_id: &[u8; 16],
    leaves: &[RestoreEpochLeafV2],
) -> std::result::Result<[u8; 32], MerkleError> {
    for l in leaves {
        if &l.tenant_id != tenant_id {
            return Err(MerkleError::ForeignTenant);
        }
        if l.previous_signed_head_hash == [0; 32] {
            return Err(MerkleError::ZeroPreviousHead);
        }
    }
    let leaves: Vec<EpochLeaf> = leaves.iter().map(RestoreEpochLeafV2::epoch_leaf).collect();
    merkle_root(&leaves)
}

// ------------------------------------------------ RestoreEpochTransitionV2 ---

/// L729 `reason_code`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreReason {
    OperatorRestore,
    DisasterRecovery,
    VerifiedBackupRollback,
}

impl RestoreReason {
    pub const ALL: [Self; 3] = [
        Self::OperatorRestore,
        Self::DisasterRecovery,
        Self::VerifiedBackupRollback,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::OperatorRestore => "operator_restore",
            Self::DisasterRecovery => "disaster_recovery",
            Self::VerifiedBackupRollback => "verified_backup_rollback",
        }
    }
}

/// The signed payload (L719-L735), keyed
/// `(server_instance_id, tenant_id, previous_epoch, new_epoch)` (L374).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreEpochTransitionV2 {
    pub transition_replay_id: [u8; 16],
    pub server_instance_id: [u8; 16],
    pub tenant_id: [u8; 16],
    pub previous_epoch: u64,
    pub new_epoch: u64,
    pub mapping_count: u64,
    pub profile_head_mapping_root: [u8; 32],
    pub reason_code: RestoreReason,
    pub approver_account_id: [u8; 16],
    pub approver_device_id: [u8; 16],
    pub approver_signing_key_id: [u8; 32],
    pub issued_at_ms: u64,
    pub nonce: [u8; 16],
}

impl RestoreEpochTransitionV2 {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("RestoreEpochTransitionV2", payload)?;
        f.exact_text("domain", DOMAIN_RESTORE_EPOCH_TRANSITION_PAYLOAD)?;
        if f.u16("version")? != VERSION {
            return Err(RecordError::BadValue("version"));
        }
        let transition_replay_id = f.fixed("transition_replay_id")?;
        let server_instance_id = f.fixed("server_instance_id")?;
        let tenant_id = f.fixed("tenant_id")?;
        let previous_epoch = f.uint("previous_epoch")?;
        let new_epoch = f.uint("new_epoch")?;
        f.exact_text("mapping_codec", MAPPING_CODEC)?;
        let mapping_count = f.uint("mapping_count")?;
        let profile_head_mapping_root = f.fixed("profile_head_mapping_root")?;
        let reason = f.text("reason_code")?;
        let reason_code = RestoreReason::ALL
            .into_iter()
            .find(|r| r.as_str() == reason)
            .ok_or(RecordError::BadValue("reason_code"))?;
        let approver_account_id = f.fixed("approver_account_id")?;
        let approver_device_id = f.fixed("approver_device_id")?;
        let approver_signing_key_id = f.fixed("approver_signing_key_id")?;
        let issued_at_ms = f.uint("issued_at_ms")?;
        let nonce = f.fixed("nonce")?;
        f.finish()?;
        check_epochs_and_count(previous_epoch, new_epoch, mapping_count, "mapping_count")?;
        Ok(Self {
            transition_replay_id,
            server_instance_id,
            tenant_id,
            previous_epoch,
            new_epoch,
            mapping_count,
            profile_head_mapping_root,
            reason_code,
            approver_account_id,
            approver_device_id,
            approver_signing_key_id,
            issued_at_ms,
            nonce,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        c::encode(&c::m(vec![
            ("domain", c::t(DOMAIN_RESTORE_EPOCH_TRANSITION_PAYLOAD)),
            ("version", c::u(VERSION.into())),
            ("transition_replay_id", c::b(&self.transition_replay_id)),
            ("server_instance_id", c::b(&self.server_instance_id)),
            ("tenant_id", c::b(&self.tenant_id)),
            ("previous_epoch", c::u(self.previous_epoch)),
            ("new_epoch", c::u(self.new_epoch)),
            ("mapping_codec", c::t(MAPPING_CODEC)),
            ("mapping_count", c::u(self.mapping_count)),
            (
                "profile_head_mapping_root",
                c::b(&self.profile_head_mapping_root),
            ),
            ("reason_code", c::t(self.reason_code.as_str())),
            ("approver_account_id", c::b(&self.approver_account_id)),
            ("approver_device_id", c::b(&self.approver_device_id)),
            (
                "approver_signing_key_id",
                c::b(&self.approver_signing_key_id),
            ),
            ("issued_at_ms", c::u(self.issued_at_ms)),
            ("nonce", c::b(&self.nonce)),
        ]))
    }
}

/// L726 and L705-L706: `new_epoch > previous_epoch`, and a leaf count in
/// `1..=MAX_RESTORE_EPOCH_LEAVES_V2` (no empty transition, L680).
fn check_epochs_and_count(
    previous_epoch: u64,
    new_epoch: u64,
    count: u64,
    count_field: &'static str,
) -> Result<()> {
    if new_epoch <= previous_epoch {
        return Err(RecordError::BadValue("new_epoch"));
    }
    if count == 0 || count > c::MAX_RESTORE_EPOCH_LEAVES_V2 {
        return Err(RecordError::BadValue(count_field));
    }
    Ok(())
}

// ------------------------------------------- SignedRestoreEpochTransitionV2 ---

/// The nine TBS fields of L737-L744, before `signature_bytes`.
fn tbs_fields(
    payload_bytes: &[u8],
    payload_sha256: &[u8; 32],
    approver_signing_key_id: &[u8; 32],
) -> Vec<(&'static str, Value)> {
    vec![
        (
            "container_domain",
            c::t(DOMAIN_RESTORE_EPOCH_SIGNED_TRANSITION_CONTAINER),
        ),
        ("container_version", c::u(VERSION.into())),
        (
            "payload_domain",
            c::t(DOMAIN_RESTORE_EPOCH_TRANSITION_PAYLOAD),
        ),
        ("payload_version", c::u(VERSION.into())),
        ("canonical_transition_payload_bytes", c::b(payload_bytes)),
        ("transition_payload_sha256", c::b(payload_sha256)),
        (
            "signature_suite_id",
            c::u(SIGNATURE_SUITE_ID_ED25519.into()),
        ),
        ("signature_version", c::u(SIGNATURE_VERSION.into())),
        ("approver_signing_key_id", c::b(approver_signing_key_id)),
    ]
}

/// L745: label + `u32be(len(tbs))` + exact TBS bytes.
fn signing_input(tbs_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(c::L_RESTORE_EPOCH_TRANSITION_TBS.len() + 4 + tbs_bytes.len());
    out.extend_from_slice(c::L_RESTORE_EPOCH_TRANSITION_TBS.as_bytes());
    out.extend_from_slice(&(tbs_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(tbs_bytes);
    out
}

/// Signs `payload` into exact `SignedRestoreEpochTransitionV2` bytes. The
/// container names the signer's own key, so a payload naming another approver
/// key builds bytes that [`SignedRestoreEpochTransitionV2::parse`] refuses.
pub fn build_signed_transition(sk: &SigningKey, payload: &RestoreEpochTransitionV2) -> Vec<u8> {
    let payload_bytes = payload.encode();
    let key_id = signing_key_id(sk.verifying_key().as_bytes());
    let mut fields = tbs_fields(&payload_bytes, &c::sha256(&payload_bytes), &key_id);
    let tbs = c::encode(&c::m(fields.clone()));
    let signature = sk.sign(&signing_input(&tbs)).to_bytes();
    fields.push(("signature_bytes", c::b(&signature)));
    let core = c::encode(&c::m(fields.clone()));
    let hash = c::domain_hash(c::L_RESTORE_EPOCH_TRANSITION_CONTAINER, &core);
    fields.push(("signed_transition_container_hash", c::b(&hash)));
    c::encode(&c::m(fields))
}

/// A `SignedRestoreEpochTransitionV2` whose bytes, hashes, suite and payload
/// were checked. The payload is reachable only through
/// [`SignedRestoreEpochTransitionV2::verify_signature`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRestoreEpochTransitionV2 {
    canonical_transition_payload_bytes: Vec<u8>,
    transition_payload_sha256: [u8; 32],
    approver_signing_key_id: [u8; 32],
    signature_bytes: Vec<u8>,
    signed_transition_container_hash: [u8; 32],
    exact_signed_transition_bytes: Vec<u8>,
    exact_signed_transition_bytes_sha256: [u8; 32],
    tbs_bytes: Vec<u8>,
    payload: RestoreEpochTransitionV2,
}

/// A transition whose signature verified under the key the caller supplied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTransition {
    container: SignedRestoreEpochTransitionV2,
}

impl VerifiedTransition {
    pub fn container(&self) -> &SignedRestoreEpochTransitionV2 {
        &self.container
    }

    pub fn payload(&self) -> &RestoreEpochTransitionV2 {
        &self.container.payload
    }
}

impl SignedRestoreEpochTransitionV2 {
    /// Parses exact container bytes, recomputing every hash and requiring the
    /// container signer key to equal the payload's `approver_signing_key_id`
    /// (L749). Newer versions and suites are `SCHEMA_UNSUPPORTED`.
    pub fn parse(exact: &[u8]) -> Result<Self> {
        const MAP: &str = "SignedRestoreEpochTransitionV2";
        if exact.len() > MAX_SIGNED_TRANSITION_BYTES {
            return Err(RecordError::BadField {
                map: MAP,
                field: "exact_signed_transition_bytes",
            });
        }
        let mut f = Fields::decode(MAP, exact)?;
        f.exact_text(
            "container_domain",
            DOMAIN_RESTORE_EPOCH_SIGNED_TRANSITION_CONTAINER,
        )?;
        for field in ["container_version", "payload_version"] {
            let v = f.u16(field)?;
            if v != VERSION {
                return Err(RecordError::Unsupported {
                    field,
                    id: v.into(),
                });
            }
        }
        f.exact_text("payload_domain", DOMAIN_RESTORE_EPOCH_TRANSITION_PAYLOAD)?;
        let payload_bytes = f.bytes(
            "canonical_transition_payload_bytes",
            1,
            MAX_TRANSITION_PAYLOAD_BYTES,
        )?;
        let payload_sha256 = f.fixed::<32>("transition_payload_sha256")?;
        for (field, expected) in [
            ("signature_suite_id", SIGNATURE_SUITE_ID_ED25519),
            ("signature_version", SIGNATURE_VERSION),
        ] {
            let v = f.u16(field)?;
            if v != expected {
                return Err(RecordError::Unsupported {
                    field,
                    id: v.into(),
                });
            }
        }
        let approver_signing_key_id = f.fixed::<32>("approver_signing_key_id")?;
        let signature_bytes = f.bytes("signature_bytes", 1, MAX_SIGNATURE_BYTES)?;
        let container_hash = f.fixed::<32>("signed_transition_container_hash")?;
        f.finish()?;

        if signature_bytes.len() != ED25519_SIG_LEN {
            return Err(RecordError::BadField {
                map: MAP,
                field: "signature_bytes",
            });
        }
        if c::sha256(&payload_bytes) != payload_sha256 {
            return Err(RecordError::PayloadHashMismatch);
        }
        let mut core = tbs_fields(&payload_bytes, &payload_sha256, &approver_signing_key_id);
        let tbs_bytes = c::encode(&c::m(core.clone()));
        core.push(("signature_bytes", c::b(&signature_bytes)));
        let core_bytes = c::encode(&c::m(core));
        if c::domain_hash(c::L_RESTORE_EPOCH_TRANSITION_CONTAINER, &core_bytes) != container_hash {
            return Err(RecordError::ContainerHashMismatch);
        }

        let payload = RestoreEpochTransitionV2::parse(&payload_bytes)?;
        if payload.approver_signing_key_id != approver_signing_key_id {
            return Err(RecordError::BadValue("approver_signing_key_id"));
        }
        Ok(Self {
            canonical_transition_payload_bytes: payload_bytes,
            transition_payload_sha256: payload_sha256,
            approver_signing_key_id,
            signature_bytes,
            signed_transition_container_hash: container_hash,
            exact_signed_transition_bytes: exact.to_vec(),
            exact_signed_transition_bytes_sha256: c::sha256(exact),
            tbs_bytes,
            payload,
        })
    }

    /// Checks the signature under the approver key the caller looked up. The
    /// caller owns the D-2 rule (ADR 0002 L724, plan L733): the key is an active
    /// `root.custody` signer of the same tenant.
    pub fn verify_signature(self, approver_public_key: &[u8; 32]) -> Result<VerifiedTransition> {
        if signing_key_id(approver_public_key) != self.approver_signing_key_id {
            return Err(RecordError::IssuerKeyMismatch);
        }
        signing::verify_message_strict(
            approver_public_key,
            &signing_input(&self.tbs_bytes),
            &self.signature_bytes,
        )
        .map_err(|_| RecordError::Signature)?;
        Ok(VerifiedTransition { container: self })
    }

    pub fn canonical_transition_payload_bytes(&self) -> &[u8] {
        &self.canonical_transition_payload_bytes
    }

    pub fn transition_payload_sha256(&self) -> &[u8; 32] {
        &self.transition_payload_sha256
    }

    pub fn approver_signing_key_id(&self) -> &[u8; 32] {
        &self.approver_signing_key_id
    }

    pub fn signature_bytes(&self) -> &[u8] {
        &self.signature_bytes
    }

    pub fn signed_transition_container_hash(&self) -> &[u8; 32] {
        &self.signed_transition_container_hash
    }

    pub fn exact_signed_transition_bytes(&self) -> &[u8] {
        &self.exact_signed_transition_bytes
    }

    pub fn exact_signed_transition_bytes_sha256(&self) -> &[u8; 32] {
        &self.exact_signed_transition_bytes_sha256
    }

    pub fn tbs_bytes(&self) -> &[u8] {
        &self.tbs_bytes
    }
}

// ------------------------------------------- RestoreEpochInclusionProofV2 ---

/// One binding's inclusion proof (L691-L715). Its tenant and profile are the
/// leaf's; the parser refuses a proof whose header names others.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreEpochInclusionProofV2 {
    pub server_instance_id: [u8; 16],
    pub previous_epoch: u64,
    pub new_epoch: u64,
    pub leaf_index: u64,
    pub leaf_count: u64,
    pub leaf: RestoreEpochLeafV2,
    pub expected_root: [u8; 32],
    pub steps: Vec<ProofStep>,
}

impl RestoreEpochInclusionProofV2 {
    /// The proof of `leaves[leaf_index]` under `transition`. The leaf set is
    /// checked as [`mapping_root`] checks it and must be the one `transition`
    /// commits to; `leaf_index` must be in range.
    pub fn build(
        transition: &RestoreEpochTransitionV2,
        leaves: &[RestoreEpochLeafV2],
        leaf_index: usize,
    ) -> std::result::Result<Self, MerkleError> {
        let root = mapping_root(&transition.tenant_id, leaves)?;
        if leaf_index >= leaves.len() {
            return Err(MerkleError::IndexOutOfRange);
        }
        if leaves.len() as u64 != transition.mapping_count
            || root != transition.profile_head_mapping_root
        {
            return Err(MerkleError::NotTheTransition);
        }
        let epoch_leaves: Vec<EpochLeaf> =
            leaves.iter().map(RestoreEpochLeafV2::epoch_leaf).collect();
        Ok(Self {
            server_instance_id: transition.server_instance_id,
            previous_epoch: transition.previous_epoch,
            new_epoch: transition.new_epoch,
            leaf_index: leaf_index as u64,
            leaf_count: leaves.len() as u64,
            leaf: leaves[leaf_index].clone(),
            expected_root: root,
            steps: merkle_proof_steps(&epoch_leaves, leaf_index),
        })
    }

    pub fn parse(exact: &[u8]) -> Result<Self> {
        const MAP: &str = "RestoreEpochInclusionProofV2";
        if exact.len() > MAX_PROOF_BYTES {
            return Err(RecordError::BadField {
                map: MAP,
                field: "exact_proof_bytes",
            });
        }
        let mut f = Fields::decode(MAP, exact)?;
        f.exact_text("domain", DOMAIN_RESTORE_EPOCH_INCLUSION_PROOF)?;
        if f.u16("version")? != VERSION {
            return Err(RecordError::BadValue("version"));
        }
        let server_instance_id = f.fixed("server_instance_id")?;
        let tenant_id: [u8; 16] = f.fixed("tenant_id")?;
        let profile_id: [u8; 16] = f.fixed("profile_id")?;
        let previous_epoch = f.uint("previous_epoch")?;
        let new_epoch = f.uint("new_epoch")?;
        f.exact_text("mapping_codec", MAPPING_CODEC)?;
        let leaf_index = f.uint("leaf_index")?;
        let leaf_count = f.uint("leaf_count")?;
        let leaf_bytes = f.bytes("canonical_leaf_bytes", 1, MAX_LEAF_BYTES)?;
        let claimed_leaf_hash: [u8; 32] = f.fixed("leaf_hash")?;
        let expected_root = f.fixed("expected_root")?;
        let items = match f.req("steps")? {
            Value::Array(items) if items.len() <= MAX_PROOF_STEPS => items,
            _ => return Err(f.bad("steps")),
        };
        f.finish()?;
        check_epochs_and_count(previous_epoch, new_epoch, leaf_count, "leaf_count")?;
        if leaf_index >= leaf_count {
            return Err(RecordError::BadValue("leaf_index"));
        }
        let leaf = RestoreEpochLeafV2::parse(&leaf_bytes)?;
        if leaf.tenant_id != tenant_id {
            return Err(RecordError::BadValue("tenant_id"));
        }
        if leaf.profile_id != profile_id {
            return Err(RecordError::BadValue("profile_id"));
        }
        if leaf_hash(&leaf_bytes) != claimed_leaf_hash {
            return Err(RecordError::BadValue("leaf_hash"));
        }
        let steps = items
            .into_iter()
            .map(parse_step)
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            server_instance_id,
            previous_epoch,
            new_epoch,
            leaf_index,
            leaf_count,
            leaf,
            expected_root,
            steps,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let leaf_bytes = self.leaf.encode();
        let steps = self
            .steps
            .iter()
            .map(|(direction, sibling)| {
                let mut step = vec![("direction", c::u(*direction))];
                if let Some(s) = sibling {
                    step.push(("sibling_hash", c::b(s)));
                }
                c::m(step)
            })
            .collect();
        c::encode(&c::m(vec![
            ("domain", c::t(DOMAIN_RESTORE_EPOCH_INCLUSION_PROOF)),
            ("version", c::u(VERSION.into())),
            ("server_instance_id", c::b(&self.server_instance_id)),
            ("tenant_id", c::b(&self.leaf.tenant_id)),
            ("profile_id", c::b(&self.leaf.profile_id)),
            ("previous_epoch", c::u(self.previous_epoch)),
            ("new_epoch", c::u(self.new_epoch)),
            ("mapping_codec", c::t(MAPPING_CODEC)),
            ("leaf_index", c::u(self.leaf_index)),
            ("leaf_count", c::u(self.leaf_count)),
            ("canonical_leaf_bytes", c::b(&leaf_bytes)),
            ("leaf_hash", c::b(&leaf_hash(&leaf_bytes))),
            ("expected_root", c::b(&self.expected_root)),
            ("steps", Value::Array(steps)),
        ]))
    }

    /// L713 `proof_sha256` over the exact (canonical) proof bytes.
    pub fn proof_sha256(&self) -> [u8; 32] {
        c::domain_hash(c::L_RESTORE_EPOCH_PROOF, &self.encode())
    }
}

/// L691-L694 `MerkleProofStepV2`: a sibling for directions 0 and 1, none for 2.
fn parse_step(v: Value) -> Result<ProofStep> {
    let mut f = Fields::open("MerkleProofStepV2", v)?;
    let direction = u64::from(f.u16("direction")?);
    let sibling = f.opt_fixed::<32>("sibling_hash")?;
    f.finish()?;
    match (direction, sibling) {
        (DIR_SIBLING_LEFT | DIR_SIBLING_RIGHT, Some(_)) | (DIR_UNARY_PROMOTE, None) => {
            Ok((direction, sibling))
        }
        (DIR_SIBLING_LEFT | DIR_SIBLING_RIGHT, None) => Err(RecordError::MissingField {
            map: "MerkleProofStepV2",
            field: "sibling_hash",
        }),
        (DIR_UNARY_PROMOTE, Some(_)) => Err(RecordError::BadValue("sibling_hash")),
        _ => Err(RecordError::BadValue("direction")),
    }
}

// ------------------------------------------------------- verify_inclusion ---

/// Why a proof does not unquarantine a binding (plan L1237).
#[derive(Debug, PartialEq, Eq)]
pub enum InclusionError {
    /// The leaf belongs to another tenant than the signed transition.
    CrossTenant,
    /// A proof field differs from the signed transition or the asked binding.
    Mismatch(&'static str),
    /// The path does not rebuild the signed root by the exact derived shape.
    Proof(ProofError),
}

impl InclusionError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::CrossTenant => "RESTORE_EPOCH_CROSS_TENANT",
            Self::Mismatch(_) | Self::Proof(_) => "RESTORE_EPOCH_TRANSITION_INVALID",
        }
    }
}

impl std::fmt::Display for InclusionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CrossTenant => write!(f, "inclusion proof is for another tenant"),
            Self::Mismatch(field) => {
                write!(f, "inclusion proof {field} differs from the transition")
            }
            Self::Proof(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for InclusionError {}

/// Verifies that `proof` proves `profile_id`'s leaf under the signed
/// `transition` (L711-L713): same instance, tenant, epochs, count and root,
/// then the exact path shape of [`ev::verify_proof`]. On success the caller
/// still compares `proof.leaf`'s heads with the binding's pinned head.
pub fn verify_inclusion(
    transition: &VerifiedTransition,
    proof: &RestoreEpochInclusionProofV2,
    profile_id: &[u8; 16],
) -> std::result::Result<(), InclusionError> {
    let t = transition.payload();
    if proof.leaf.tenant_id != t.tenant_id {
        return Err(InclusionError::CrossTenant);
    }
    for (field, equal) in [
        ("profile_id", &proof.leaf.profile_id == profile_id),
        (
            "server_instance_id",
            proof.server_instance_id == t.server_instance_id,
        ),
        ("previous_epoch", proof.previous_epoch == t.previous_epoch),
        ("new_epoch", proof.new_epoch == t.new_epoch),
        ("leaf_count", proof.leaf_count == t.mapping_count),
        (
            "expected_root",
            proof.expected_root == t.profile_head_mapping_root,
        ),
    ] {
        if !equal {
            return Err(InclusionError::Mismatch(field));
        }
    }
    ev::verify_proof(
        proof.leaf_index,
        proof.leaf_count,
        &proof.leaf.hash(),
        &proof.steps,
        &t.profile_head_mapping_root,
    )
    .map_err(InclusionError::Proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// The fixture generator shared by the G2 vectors (see `envelope` tests).
    fn fx<const N: usize>(label: &str) -> [u8; N] {
        use sha2::{Digest, Sha256};
        let mut out = [0u8; N];
        let (mut filled, mut counter) = (0, 0u32);
        while filled < N {
            let mut h = Sha256::new();
            h.update(b"SHARDX-G2-SPIKE-FIXTURE\0");
            h.update(label.as_bytes());
            h.update(counter.to_be_bytes());
            let block: [u8; 32] = h.finalize().into();
            let take = (N - filled).min(32);
            out[filled..filled + take].copy_from_slice(&block[..take]);
            filled += take;
            counter += 1;
        }
        out
    }

    fn custodian() -> SigningKey {
        SigningKey::from_bytes(&fx::<32>("root-custodian-signing-key"))
    }

    /// The envelope tests' G2 leaf fixture (`g2_leaves`), sorted.
    fn leaves(tenant: &str, n: u8) -> Vec<RestoreEpochLeafV2> {
        let mut l: Vec<RestoreEpochLeafV2> = (1..=n)
            .map(|i| RestoreEpochLeafV2 {
                tenant_id: fx(tenant),
                profile_id: fx(&format!("profile-{i}")),
                previous_signed_head_hash: fx(&format!("prev-head-{i}")),
                new_signed_head_hash: fx(&format!("new-head-{i}")),
            })
            .collect();
        l.sort_by_key(|x| (x.tenant_id, x.profile_id));
        l
    }

    fn transition(tenant: &str, l: &[RestoreEpochLeafV2]) -> RestoreEpochTransitionV2 {
        RestoreEpochTransitionV2 {
            transition_replay_id: fx("transition-replay"),
            server_instance_id: fx("server-1"),
            tenant_id: fx(tenant),
            previous_epoch: 7,
            new_epoch: 8,
            mapping_count: l.len() as u64,
            profile_head_mapping_root: mapping_root(&fx(tenant), l).unwrap(),
            reason_code: RestoreReason::OperatorRestore,
            approver_account_id: fx("approver-account"),
            approver_device_id: fx("approver-device"),
            approver_signing_key_id: signing_key_id(custodian().verifying_key().as_bytes()),
            issued_at_ms: 1_756_000_000_000,
            nonce: fx("transition-nonce"),
        }
    }

    fn verified(t: &RestoreEpochTransitionV2) -> VerifiedTransition {
        let sk = custodian();
        SignedRestoreEpochTransitionV2::parse(&build_signed_transition(&sk, t))
            .unwrap()
            .verify_signature(sk.verifying_key().as_bytes())
            .unwrap()
    }

    fn edit_map(bytes: &[u8], edit: impl FnOnce(&mut Vec<(String, Value)>)) -> Vec<u8> {
        let Value::Map(mut entries) = c::decode(bytes).unwrap() else {
            panic!("not a map")
        };
        edit(&mut entries);
        c::encode(&Value::Map(entries))
    }

    fn set(entries: &mut Vec<(String, Value)>, key: &str, v: Value) {
        entries.retain(|(k, _)| k != key);
        entries.push((key.to_string(), v));
    }

    fn with(bytes: &[u8], key: &str, v: Value) -> Vec<u8> {
        edit_map(bytes, |e| set(e, key, v))
    }

    fn without(bytes: &[u8], key: &str) -> Vec<u8> {
        edit_map(bytes, |e| e.retain(|(k, _)| k != key))
    }

    // ------------------------------------------------------ golden vectors --

    /// Regression vectors pinned at this commit (plan L751-L753). The n=1/2/3
    /// roots equal the G2-pinned roots in `envelope`.
    #[test]
    fn golden_vectors() {
        let roots: Vec<String> = (1..=3)
            .map(|n| hex(&mapping_root(&fx("tenant-a"), &leaves("tenant-a", n)).unwrap()))
            .collect();
        assert_eq!(
            roots,
            [
                "49a633fcc5d872970885e5098c3100cfe5dbc4aa8ff6e3fbf7ebb9b93db87414",
                "9f6dc107e60b21f765dcfc393c2f9f247febdfd75517a180e9036dd7b75cec48",
                "1d89cd4e233fac8d84df6c8039bd0084bc331e53a9233fd1643a4e3f59a0ce5f",
            ]
        );

        let l = leaves("tenant-a", 3);
        assert_eq!(hex(&l[0].encode()), "a666646f6d61696e78297368617264782e726573746f72652d65706f63682e70726f66696c652d686561642d6c6561662e76326776657273696f6e026974656e616e745f69645013803ee0a88ccb229d0c890aa636db586a70726f66696c655f69645024049c3fadbc5b230d7011dc6e281c45746e65775f7369676e65645f686561645f686173685820d8e60a273faa5347a4ba5e77fb5bc587fdd44c9df14a413b8ddb695f7626dd96781970726576696f75735f7369676e65645f686561645f68617368582065a6fa964e754ec80345f90d5eeba7147822b6d09de12b9374961b26f13c4841");
        assert_eq!(
            hex(&l[0].hash()),
            "49a633fcc5d872970885e5098c3100cfe5dbc4aa8ff6e3fbf7ebb9b93db87414"
        );

        let t = transition("tenant-a", &l);
        assert_eq!(
            hex(&c::sha256(&t.encode())),
            "d493d12306c3786d6ec6a5e80222b2676c61cbe18c05a7883e43b7d787093df4"
        );
        let v = verified(&t);
        assert_eq!(
            hex(v.container().signed_transition_container_hash()),
            "6f06f10b668b83d4e8d07beb2ca896e966cc2c69b3303362fb1895f4b497df4d"
        );
        assert_eq!(
            hex(v.container().exact_signed_transition_bytes_sha256()),
            "6ff77b1b9399bdd51309841e49a201d2181114d32810c4e20234bcb7da6c805b"
        );

        // n=3 covers both sibling directions and the unary promote.
        let built: Vec<_> = (0..3)
            .map(|i| RestoreEpochInclusionProofV2::build(&t, &l, i).unwrap())
            .collect();
        let directions: Vec<Vec<u64>> = built
            .iter()
            .map(|p| p.steps.iter().map(|s| s.0).collect())
            .collect();
        assert_eq!(directions, [vec![1, 1], vec![0, 1], vec![2, 0]]);
        let proofs: Vec<String> = built.iter().map(|p| hex(&p.proof_sha256())).collect();
        assert_eq!(
            proofs,
            [
                "5f9fd5114aea062488f4fc892dc82920cf1be32765a9b01a8c2ad9baa0f5cbe9",
                "6b5a51f746d5185bad449f14d2d1784201c85402bd6f51a7294523d44c68a3ab",
                "8be8649c6947d34df6b50bb5a31c5ffdb404f78eb5d4833932b189633578ec29"
            ]
        );
    }

    // ---------------------------------------------------------- transition --

    #[test]
    fn transition_roundtrips_and_verifies() {
        let l = leaves("tenant-a", 3);
        let t = transition("tenant-a", &l);
        assert_eq!(RestoreEpochTransitionV2::parse(&t.encode()), Ok(t.clone()));
        for reason in RestoreReason::ALL {
            let mut other = t.clone();
            other.reason_code = reason;
            assert_eq!(RestoreEpochTransitionV2::parse(&other.encode()), Ok(other));
        }
        let sk = custodian();
        let exact = build_signed_transition(&sk, &t);
        let parsed = SignedRestoreEpochTransitionV2::parse(&exact).unwrap();
        assert_eq!(parsed.exact_signed_transition_bytes(), exact);
        assert_eq!(parsed.canonical_transition_payload_bytes(), t.encode());
        assert_eq!(parsed.approver_signing_key_id(), &t.approver_signing_key_id);
        let v = parsed
            .verify_signature(sk.verifying_key().as_bytes())
            .unwrap();
        assert_eq!(v.payload(), &t);
    }

    #[test]
    fn transition_payload_refuses_every_contract_violation() {
        let t = transition("tenant-a", &leaves("tenant-a", 3));
        let good = t.encode();
        let parse = |b: &[u8]| RestoreEpochTransitionV2::parse(b);

        assert!(matches!(
            parse(&with(&good, "extra", c::u(1))),
            Err(RecordError::UnknownField { .. })
        ));
        let Value::Map(fields) = c::decode(&good).unwrap() else {
            unreachable!()
        };
        for (key, _) in &fields {
            assert!(
                matches!(
                    parse(&without(&good, key)),
                    Err(RecordError::MissingField { .. })
                ),
                "{key}"
            );
        }
        for (key, v, err) in [
            ("domain", c::t("shardx.other.v2"), "domain"),
            ("version", c::u(3), "version"),
            ("mapping_codec", c::t("SORTED_LIST_V2"), "mapping_codec"),
            ("reason_code", c::t("rollback"), "reason_code"),
            ("new_epoch", c::u(7), "new_epoch"),
            ("new_epoch", c::u(6), "new_epoch"),
            ("mapping_count", c::u(0), "mapping_count"),
            ("mapping_count", c::u(1_000_001), "mapping_count"),
        ] {
            assert_eq!(
                parse(&with(&good, key, v)),
                Err(RecordError::BadValue(err)),
                "{key}"
            );
        }
        assert!(parse(&with(&good, "mapping_count", c::u(1_000_000))).is_ok());
        for (key, len) in [
            ("transition_replay_id", 15),
            ("server_instance_id", 17),
            ("tenant_id", 15),
            ("profile_head_mapping_root", 31),
            ("approver_account_id", 15),
            ("approver_device_id", 15),
            ("approver_signing_key_id", 33),
            ("nonce", 15),
        ] {
            assert!(
                matches!(
                    parse(&with(&good, key, c::b(&vec![1u8; len]))),
                    Err(RecordError::BadField { .. })
                ),
                "{key}"
            );
        }
        // Integers outside the SQLite domain never reach the epoch rule.
        assert_eq!(
            parse(&with(&good, "new_epoch", c::u(1 << 63)))
                .unwrap_err()
                .code(),
            "WIRE_INTEGER_OUT_OF_RANGE"
        );
    }

    #[test]
    fn signed_transition_refuses_every_container_defect() {
        let sk = custodian();
        let t = transition("tenant-a", &leaves("tenant-a", 3));
        let good = build_signed_transition(&sk, &t);
        let parse = |b: &[u8]| SignedRestoreEpochTransitionV2::parse(b);

        assert!(matches!(
            parse(&with(&good, "extra", c::u(1))),
            Err(RecordError::UnknownField { .. })
        ));
        assert!(matches!(
            parse(&without(&good, "transition_payload_sha256")),
            Err(RecordError::MissingField { .. })
        ));
        for key in ["container_domain", "payload_domain"] {
            assert_eq!(
                parse(&with(
                    &good,
                    key,
                    c::t(crate::authz_record::CONTAINER_DOMAIN)
                )),
                Err(RecordError::BadValue(key))
            );
        }
        for (field, v) in [
            ("container_version", 3),
            ("payload_version", 3),
            ("signature_suite_id", 2),
            ("signature_version", 2),
        ] {
            assert_eq!(
                parse(&with(&good, field, c::u(v))),
                Err(RecordError::Unsupported { field, id: v }),
                "{field}"
            );
        }
        assert_eq!(
            parse(&with(
                &good,
                "extra",
                c::b(&vec![0u8; MAX_SIGNED_TRANSITION_BYTES])
            )),
            Err(RecordError::BadField {
                map: "SignedRestoreEpochTransitionV2",
                field: "exact_signed_transition_bytes",
            })
        );
        assert_eq!(
            parse(&with(&good, "signature_bytes", c::b(&[1u8; 63]))),
            Err(RecordError::BadField {
                map: "SignedRestoreEpochTransitionV2",
                field: "signature_bytes",
            })
        );
        assert_eq!(
            parse(&with(&good, "transition_payload_sha256", c::b(&[0u8; 32]))),
            Err(RecordError::PayloadHashMismatch)
        );
        assert_eq!(
            parse(&with(
                &good,
                "signed_transition_container_hash",
                c::b(&[0u8; 32])
            )),
            Err(RecordError::ContainerHashMismatch)
        );
        // L749: the container signer must be the payload's approver key.
        let mut other = t.clone();
        other.approver_signing_key_id = fx("another-key");
        assert_eq!(
            parse(&build_signed_transition(&sk, &other)),
            Err(RecordError::BadValue("approver_signing_key_id"))
        );
        // The payload is parsed by its closed schema inside the container.
        let mut bad = t.clone();
        bad.mapping_count = 0;
        assert_eq!(
            parse(&build_signed_transition(&sk, &bad)),
            Err(RecordError::BadValue("mapping_count"))
        );
    }

    #[test]
    fn transition_signature_binds_key_bytes_and_label() {
        let sk = custodian();
        let t = transition("tenant-a", &leaves("tenant-a", 3));
        let exact = build_signed_transition(&sk, &t);
        let parsed = || SignedRestoreEpochTransitionV2::parse(&exact).unwrap();

        let stranger = SigningKey::from_bytes(&fx::<32>("stranger"));
        assert_eq!(
            parsed().verify_signature(stranger.verifying_key().as_bytes()),
            Err(RecordError::IssuerKeyMismatch)
        );

        // A signature over the same TBS under the authorization label (or any
        // other byte string) is refused: the transition label is part of the
        // signed message.
        let p = parsed();
        let resign = |sig: &[u8]| {
            let mut fields = tbs_fields(
                p.canonical_transition_payload_bytes(),
                p.transition_payload_sha256(),
                p.approver_signing_key_id(),
            );
            fields.push(("signature_bytes", c::b(sig)));
            let core = c::encode(&c::m(fields.clone()));
            let hash = c::domain_hash(c::L_RESTORE_EPOCH_TRANSITION_CONTAINER, &core);
            fields.push(("signed_transition_container_hash", c::b(&hash)));
            SignedRestoreEpochTransitionV2::parse(&c::encode(&c::m(fields))).unwrap()
        };
        let authz_label_sig = signing::sign_tbs(&sk, p.tbs_bytes());
        assert_eq!(
            resign(&authz_label_sig).verify_signature(sk.verifying_key().as_bytes()),
            Err(RecordError::Signature)
        );
        let mut flipped = p.signature_bytes().to_vec();
        flipped[0] ^= 1;
        assert_eq!(
            resign(&flipped).verify_signature(sk.verifying_key().as_bytes()),
            Err(RecordError::Signature)
        );
    }

    // ---------------------------------------------------------------- leaf --

    #[test]
    fn leaf_roundtrips_and_refuses_contract_violations() {
        let leaf = leaves("tenant-a", 1).remove(0);
        let good = leaf.encode();
        assert_eq!(RestoreEpochLeafV2::parse(&good), Ok(leaf.clone()));
        let parse = |b: &[u8]| RestoreEpochLeafV2::parse(b);
        assert!(matches!(
            parse(&with(&good, "extra", c::u(1))),
            Err(RecordError::UnknownField { .. })
        ));
        for key in [
            "domain",
            "version",
            "tenant_id",
            "profile_id",
            "previous_signed_head_hash",
            "new_signed_head_hash",
        ] {
            assert!(
                matches!(
                    parse(&without(&good, key)),
                    Err(RecordError::MissingField { .. })
                ),
                "{key}"
            );
        }
        assert_eq!(
            parse(&with(
                &good,
                "domain",
                c::t(DOMAIN_RESTORE_EPOCH_INCLUSION_PROOF)
            )),
            Err(RecordError::BadValue("domain"))
        );
        assert_eq!(
            parse(&with(&good, "version", c::u(3))),
            Err(RecordError::BadValue("version"))
        );
        assert_eq!(
            parse(&with(&good, "previous_signed_head_hash", c::b(&[0u8; 32]))),
            Err(RecordError::BadValue("previous_signed_head_hash"))
        );
        assert!(matches!(
            parse(&with(&good, "new_signed_head_hash", c::b(&[1u8; 31]))),
            Err(RecordError::BadField { .. })
        ));
    }

    #[test]
    fn leaf_sets_must_be_non_empty_sorted_and_unique() {
        let a = fx("tenant-a");
        assert_eq!(mapping_root(&a, &[]), Err(MerkleError::EmptyTree));
        let l = leaves("tenant-a", 2);
        assert_eq!(
            mapping_root(&a, &[l[1].clone(), l[0].clone()]),
            Err(MerkleError::UnsortedLeaves)
        );
        assert_eq!(
            mapping_root(&a, &[l[0].clone(), l[0].clone()]),
            Err(MerkleError::DuplicateTuple)
        );
        // Same tuple, different heads: still a duplicate.
        let mut twin = l[0].clone();
        twin.new_signed_head_hash = fx("other-new-head");
        assert_eq!(
            mapping_root(&a, &[l[0].clone(), twin]),
            Err(MerkleError::DuplicateTuple)
        );
        // Every leaf is the transition tenant's, and restores a previous head.
        assert_eq!(
            mapping_root(&fx("tenant-b"), &l),
            Err(MerkleError::ForeignTenant)
        );
        let mut blank = l[1].clone();
        blank.previous_signed_head_hash = [0; 32];
        assert_eq!(
            mapping_root(&a, &[l[0].clone(), blank]),
            Err(MerkleError::ZeroPreviousHead)
        );
        // A proof is built only for the set the transition commits to.
        let t = transition("tenant-a", &l);
        assert_eq!(
            RestoreEpochInclusionProofV2::build(&t, &l, 2),
            Err(MerkleError::IndexOutOfRange)
        );
        assert_eq!(
            RestoreEpochInclusionProofV2::build(&t, &l[..1], 0),
            Err(MerkleError::NotTheTransition)
        );
        let mut miscounted = t.clone();
        miscounted.mapping_count = 3;
        assert_eq!(
            RestoreEpochInclusionProofV2::build(&miscounted, &l, 0),
            Err(MerkleError::NotTheTransition)
        );
        let mut other = l.clone();
        other[1].new_signed_head_hash = fx("other-new-head");
        assert_eq!(
            RestoreEpochInclusionProofV2::build(&t, &other, 0),
            Err(MerkleError::NotTheTransition)
        );
    }

    // --------------------------------------------------------------- proof --

    /// n=1..7 covers single-leaf, even and odd widths at every level.
    #[test]
    fn every_leaf_proves_and_every_tampering_fails() {
        for n in 1..=7u8 {
            let l = leaves("tenant-a", n);
            let t = transition("tenant-a", &l);
            let v = verified(&t);
            for i in 0..l.len() {
                let proof = RestoreEpochInclusionProofV2::build(&t, &l, i).unwrap();
                let parsed = RestoreEpochInclusionProofV2::parse(&proof.encode()).unwrap();
                assert_eq!(parsed, proof);
                let pid = l[i].profile_id;
                assert_eq!(verify_inclusion(&v, &parsed, &pid), Ok(()), "{i} of {n}");

                let fails =
                    |p: &RestoreEpochInclusionProofV2| verify_inclusion(&v, p, &pid).is_err();
                for s in 0..proof.steps.len() {
                    if let (_, Some(sib)) = proof.steps[s] {
                        let mut p = proof.clone();
                        let mut bad = sib;
                        bad[31] ^= 1;
                        p.steps[s].1 = Some(bad);
                        assert!(fails(&p), "sibling {s} of {i}/{n}");
                    }
                    for d in [DIR_SIBLING_LEFT, DIR_SIBLING_RIGHT, DIR_UNARY_PROMOTE] {
                        if d != proof.steps[s].0 {
                            let mut p = proof.clone();
                            p.steps[s].0 = d;
                            assert!(fails(&p), "direction {s} of {i}/{n}");
                        }
                    }
                    let mut dropped = proof.clone();
                    dropped.steps.remove(s);
                    assert!(fails(&dropped), "dropped {s} of {i}/{n}");
                    let mut repeated = proof.clone();
                    repeated.steps.insert(s, proof.steps[s]);
                    assert!(fails(&repeated), "repeated {s} of {i}/{n}");
                }
                let mut extra = proof.clone();
                extra.steps.push((DIR_UNARY_PROMOTE, None));
                assert!(fails(&extra), "extra step {i}/{n}");
                if n > 1 {
                    let mut moved = proof.clone();
                    moved.leaf_index = ((i + 1) % l.len()) as u64;
                    assert!(fails(&moved), "moved {i}/{n}");
                    // Another leaf of the same set, under this leaf's path.
                    let mut swapped = proof.clone();
                    swapped.leaf = l[(i + 1) % l.len()].clone();
                    assert!(
                        verify_inclusion(&v, &swapped, &swapped.leaf.profile_id).is_err(),
                        "swapped {i}/{n}"
                    );
                }
                let mut heads = proof.clone();
                heads.leaf.new_signed_head_hash[0] ^= 1;
                assert!(fails(&heads), "new head {i}/{n}");
            }
        }
    }

    #[test]
    fn a_proof_binds_tenant_profile_instance_epochs_count_and_root() {
        let l = leaves("tenant-a", 3);
        let t = transition("tenant-a", &l);
        let v = verified(&t);
        let proof = RestoreEpochInclusionProofV2::build(&t, &l, 1).unwrap();
        let pid = l[1].profile_id;

        // Tenant B's own well-formed proof does not open tenant A's binding.
        let lb = leaves("tenant-b", 3);
        let tb = transition("tenant-b", &lb);
        let cross = RestoreEpochInclusionProofV2::build(&tb, &lb, 1).unwrap();
        let cross = RestoreEpochInclusionProofV2::parse(&cross.encode()).unwrap();
        let err = verify_inclusion(&v, &cross, &lb[1].profile_id).unwrap_err();
        assert_eq!(err, InclusionError::CrossTenant);
        assert_eq!(err.code(), "RESTORE_EPOCH_CROSS_TENANT");

        assert_eq!(
            verify_inclusion(&v, &proof, &l[0].profile_id),
            Err(InclusionError::Mismatch("profile_id"))
        );
        type Edit = fn(&mut RestoreEpochInclusionProofV2);
        let cases: [(&str, Edit); 5] = [
            ("server_instance_id", |p| p.server_instance_id[0] ^= 1),
            ("previous_epoch", |p| p.previous_epoch = 6),
            ("new_epoch", |p| p.new_epoch = 9),
            ("leaf_count", |p| p.leaf_count = 4),
            ("expected_root", |p| p.expected_root[0] ^= 1),
        ];
        for (field, edit) in cases {
            let mut p = proof.clone();
            edit(&mut p);
            let err = verify_inclusion(&v, &p, &pid).unwrap_err();
            assert_eq!(err, InclusionError::Mismatch(field));
            assert_eq!(err.code(), "RESTORE_EPOCH_TRANSITION_INVALID");
        }
    }

    #[test]
    fn proof_parser_refuses_every_contract_violation() {
        let l = leaves("tenant-a", 3);
        let t = transition("tenant-a", &l);
        // Leaf 2 of 3 is the odd tail: [UnaryPromote, SiblingLeft].
        let good = RestoreEpochInclusionProofV2::build(&t, &l, 2)
            .unwrap()
            .encode();
        let parse = |b: &[u8]| RestoreEpochInclusionProofV2::parse(b);
        assert!(parse(&good).is_ok());

        assert!(matches!(
            parse(&with(&good, "extra", c::u(1))),
            Err(RecordError::UnknownField { .. })
        ));
        let Value::Map(fields) = c::decode(&good).unwrap() else {
            unreachable!()
        };
        for (key, _) in &fields {
            assert!(
                matches!(
                    parse(&without(&good, key)),
                    Err(RecordError::MissingField { .. })
                ),
                "{key}"
            );
        }
        for (key, v, err) in [
            ("domain", c::t(DOMAIN_RESTORE_EPOCH_LEAF), "domain"),
            ("version", c::u(3), "version"),
            ("mapping_codec", c::t("SORTED_LIST_V2"), "mapping_codec"),
            ("new_epoch", c::u(7), "new_epoch"),
            ("leaf_count", c::u(0), "leaf_count"),
            ("leaf_count", c::u(1_000_001), "leaf_count"),
            ("leaf_index", c::u(3), "leaf_index"),
            ("tenant_id", c::b(&fx::<16>("tenant-b")), "tenant_id"),
            ("profile_id", c::b(&l[0].profile_id), "profile_id"),
            ("leaf_hash", c::b(&l[0].hash()), "leaf_hash"),
        ] {
            assert_eq!(
                parse(&with(&good, key, v)),
                Err(RecordError::BadValue(err)),
                "{key}"
            );
        }
        assert_eq!(
            parse(&with(
                &good,
                "canonical_leaf_bytes",
                c::b(&[0u8; MAX_LEAF_BYTES + 1])
            )),
            Err(RecordError::BadField {
                map: "RestoreEpochInclusionProofV2",
                field: "canonical_leaf_bytes",
            })
        );
        assert!(parse(&with(&good, "canonical_leaf_bytes", c::b(&[0xa0]))).is_err());

        let step = |d: u64, sib: Option<[u8; 32]>| {
            let mut s = vec![("direction", c::u(d))];
            if let Some(h) = sib {
                s.push(("sibling_hash", c::b(&h)));
            }
            c::m(s)
        };
        let with_steps = |steps: Vec<Value>| with(&good, "steps", Value::Array(steps));
        let h = l[0].hash();
        assert_eq!(
            parse(&with_steps(vec![step(3, None)])),
            Err(RecordError::BadValue("direction"))
        );
        assert_eq!(
            parse(&with_steps(vec![step(DIR_UNARY_PROMOTE, Some(h))])),
            Err(RecordError::BadValue("sibling_hash"))
        );
        for d in [DIR_SIBLING_LEFT, DIR_SIBLING_RIGHT] {
            assert!(matches!(
                parse(&with_steps(vec![step(d, None)])),
                Err(RecordError::MissingField {
                    field: "sibling_hash",
                    ..
                })
            ));
        }
        let extra_field = c::m(vec![("direction", c::u(2)), ("note", c::u(1))]);
        assert!(matches!(
            parse(&with_steps(vec![extra_field])),
            Err(RecordError::UnknownField { .. })
        ));
        assert!(matches!(
            parse(&with_steps(vec![c::u(2)])),
            Err(RecordError::NotAMap("MerkleProofStepV2"))
        ));
        assert!(parse(&with_steps(vec![
            step(DIR_UNARY_PROMOTE, None);
            MAX_PROOF_STEPS
        ]))
        .is_ok());
        assert_eq!(
            parse(&with_steps(vec![
                step(DIR_UNARY_PROMOTE, None);
                MAX_PROOF_STEPS + 1
            ])),
            Err(RecordError::BadField {
                map: "RestoreEpochInclusionProofV2",
                field: "steps",
            })
        );
        assert_eq!(
            parse(&with(&good, "extra", c::b(&vec![0u8; MAX_PROOF_BYTES]))),
            Err(RecordError::BadField {
                map: "RestoreEpochInclusionProofV2",
                field: "exact_proof_bytes",
            })
        );
    }
}
