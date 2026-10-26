//! Streaming envelope v2: DEK slot, pre-encryption intent, STREAM framing and
//! the restore-epoch Merkle contract.
//!
//! The security of the whole backup format rests on one property — **acyclic
//! commitment direction**:
//!
//! ```text
//!   DekSlotContextV2  (closed: no intent/ciphertext/manifest reference)
//!        |  wrapped under FKEK, context bytes as AAD
//!        v
//!   DekSlotV2 -> dek_slot_sha256
//!        |
//!        v
//!   EnvelopeIntentV2 (commits to the slot; NOT to ciphertext or manifest)
//!        |  intent_hash is the AAD of every frame
//!        v
//!   ciphertext frames -> SignedSnapshotManifestV2 (commits to everything)
//! ```
//!
//! Nothing later is referenced by anything earlier, so no field ever commits to
//! a hash of itself, and a truncated stream can never be presented as complete.
//!
//! Every byte string here was validated by the G2 conformance gate; the golden
//! vectors in the test module are pinned from that gate's report.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;

use crate::canonical::{self as c, Value};
use crate::keys::{
    wrap_dek, KeyError, ARCHIVE_FORMAT_ID_TAR, ARCHIVE_POLICY_ID_PROFILE_SNAPSHOT,
    COMPRESSION_ID_GZIP, DEK_LEN, ENVELOPE_SUITE_ID_CHACHA20POLY1305_STREAM,
    STREAM_NONCE_PREFIX_LEN, WRAP_NONCE_LEN, WRAP_SUITE_ID_CHACHA20POLY1305,
};

/// ChaCha20-Poly1305 IETF nonce length.
pub const STREAM_NONCE_LEN: usize = 12;
/// Frame AAD domain label.
pub const L_ENVELOPE_FRAME: &str = "SHARDX-ENVELOPE-FRAME-V2\0";

// -------------------------------------------------------------- DEK slot ----

/// Everything produced when sealing the single DEK slot.
pub struct SlotMaterial {
    /// Exact canonical `DekSlotContextV2` bytes — also the wrap AAD.
    pub context_bytes: Vec<u8>,
    pub context_hash: [u8; 32],
    /// Exact canonical `DekSlotV2` bytes.
    pub exact_slot_bytes: Vec<u8>,
    pub dek_slot_sha256: [u8; 32],
}

/// Identifiers bound into a DEK slot context.
pub struct SlotIds<'a> {
    pub tenant_id: &'a [u8; 16],
    pub fleet_id: &'a [u8; 16],
    pub profile_id: &'a [u8; 16],
    pub snapshot_id: &'a [u8; 16],
    pub fkek_key_id: &'a [u8; 32],
    pub envelope_context_nonce: &'a [u8; 16],
}

/// Build the single FKEK-wrapped DEK slot.
///
/// The context map is deliberately **closed**: it carries no reference to the
/// intent, the ciphertext or the manifest. That is what keeps the commitment
/// direction acyclic, and it is why a device-membership change cannot mutate a
/// retained one-slot envelope.
pub fn build_dek_slot(
    fkek: &[u8; 32],
    dek: &[u8; DEK_LEN],
    wrap_nonce: &[u8; WRAP_NONCE_LEN],
    ids: &SlotIds<'_>,
    key_generation: u64,
) -> Result<SlotMaterial, KeyError> {
    let context = c::m(vec![
        ("domain", c::t("shardx.envelope.dek-slot-context.v2")),
        ("version", c::u(2)),
        ("slot_index", c::u(0)),
        ("tenant_id", c::b(ids.tenant_id)),
        ("fleet_id", c::b(ids.fleet_id)),
        ("profile_id", c::b(ids.profile_id)),
        ("snapshot_id", c::b(ids.snapshot_id)),
        ("fkek_key_id", c::b(ids.fkek_key_id)),
        ("key_generation", c::u(key_generation)),
        ("wrap_suite_id", c::u(WRAP_SUITE_ID_CHACHA20POLY1305 as u64)),
        ("envelope_context_nonce", c::b(ids.envelope_context_nonce)),
    ]);
    let context_bytes = c::encode(&context);
    let context_hash = c::domain_hash(c::L_DEK_SLOT_CONTEXT, &context_bytes);

    let wrapped = wrap_dek(fkek, wrap_nonce, dek, &context_bytes)?;

    let slot = c::m(vec![
        ("domain", c::t("shardx.envelope.dek-slot.v2")),
        ("version", c::u(2)),
        ("slot_index", c::u(0)),
        ("canonical_dek_slot_context_bytes", c::b(&context_bytes)),
        ("dek_slot_context_hash", c::b(&context_hash)),
        ("wrap_nonce_bytes", c::b(wrap_nonce)),
        ("wrapped_dek_bytes", c::b(&wrapped)),
    ]);
    let exact_slot_bytes = c::encode(&slot);
    let dek_slot_sha256 = c::domain_hash(c::L_DEK_SLOT, &exact_slot_bytes);

    Ok(SlotMaterial {
        context_bytes,
        context_hash,
        exact_slot_bytes,
        dek_slot_sha256,
    })
}

// -------------------------------------------------------- envelope intent ----

pub struct IntentIds {
    pub snapshot_id: [u8; 16],
    pub tenant_id: [u8; 16],
    pub fleet_id: [u8; 16],
    pub profile_id: [u8; 16],
    pub lease_id: [u8; 16],
    pub manifest_replay_id: [u8; 16],
    pub server_instance_id: [u8; 16],
    pub fkek_key_id: [u8; 32],
    pub intended_signer_signing_key_id: [u8; 32],
}

pub struct IntentNumbers {
    pub target_version: u64,
    pub base_version: u64,
    pub fencing_token: u64,
    pub key_generation: u64,
    pub restore_epoch: u64,
    pub frame_plaintext_size: u32,
    pub max_plaintext_size: u64,
    pub max_ciphertext_size: u64,
    pub created_at_ms: u64,
}

pub struct IntentMaterial {
    pub exact_intent_bytes: Vec<u8>,
    pub intent_hash: [u8; 32],
}

#[derive(Debug, PartialEq, Eq)]
pub enum IntentError {
    /// `target_version` must be exactly `base_version + 1`.
    NonSequentialVersion { base: u64, target: u64 },
    /// `previous_signed_head_hash` is omitted (never null) iff `base_version == 0`.
    GenesisHeadMismatch { base_version: u64, has_prev: bool },
    /// A size field outside the plan's bounds (L649-L652).
    OutOfBounds(&'static str),
}

impl std::fmt::Display for IntentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonSequentialVersion { base, target } => write!(
                f,
                "target_version must be base_version+1: base={base} target={target}"
            ),
            Self::GenesisHeadMismatch {
                base_version,
                has_prev,
            } => write!(
                f,
                "previous_signed_head_hash presence ({has_prev}) contradicts base_version ({base_version})"
            ),
            Self::OutOfBounds(field) => write!(f, "{field} is outside its bounds"),
        }
    }
}

impl std::error::Error for IntentError {}

/// Build the pre-encryption `EnvelopeIntentV2`.
///
/// Returns an error rather than panicking on the two structural invariants, so a
/// malformed caller cannot abort a long-running backup.
pub fn build_envelope_intent(
    ids: &IntentIds,
    nums: &IntentNumbers,
    stream_nonce_prefix: &[u8; STREAM_NONCE_PREFIX_LEN],
    previous_signed_head_hash: Option<&[u8; 32]>,
    slot: &SlotMaterial,
) -> Result<IntentMaterial, IntentError> {
    build_intent(
        ids,
        nums,
        ENVELOPE_SUITE_ID_CHACHA20POLY1305_STREAM,
        stream_nonce_prefix,
        previous_signed_head_hash,
        slot,
    )
}

/// The intent for any envelope suite: the suite ID and its nonce prefix are
/// the only fields that differ (`envelope_v2` builds suite 2 with this).
pub(crate) fn build_intent(
    ids: &IntentIds,
    nums: &IntentNumbers,
    envelope_suite_id: u16,
    stream_nonce_prefix: &[u8],
    previous_signed_head_hash: Option<&[u8; 32]>,
    slot: &SlotMaterial,
) -> Result<IntentMaterial, IntentError> {
    if nums.target_version != nums.base_version + 1 {
        return Err(IntentError::NonSequentialVersion {
            base: nums.base_version,
            target: nums.target_version,
        });
    }
    // The optional field is OMITTED (never encoded as null) exactly at genesis.
    if previous_signed_head_hash.is_none() != (nums.base_version == 0) {
        return Err(IntentError::GenesisHeadMismatch {
            base_version: nums.base_version,
            has_prev: previous_signed_head_hash.is_some(),
        });
    }

    let mut fields: Vec<(&str, Value)> = vec![
        ("domain", c::t("shardx.envelope.intent.v2")),
        ("version", c::u(2)),
        ("snapshot_id", c::b(&ids.snapshot_id)),
        ("tenant_id", c::b(&ids.tenant_id)),
        ("fleet_id", c::b(&ids.fleet_id)),
        ("profile_id", c::b(&ids.profile_id)),
        ("lease_id", c::b(&ids.lease_id)),
        ("manifest_replay_id", c::b(&ids.manifest_replay_id)),
        ("target_version", c::u(nums.target_version)),
        ("base_version", c::u(nums.base_version)),
        ("fencing_token", c::u(nums.fencing_token)),
        ("key_generation", c::u(nums.key_generation)),
        ("fkek_key_id", c::b(&ids.fkek_key_id)),
        ("preamble_version", c::u(2)),
        ("envelope_suite_id", c::u(envelope_suite_id as u64)),
        ("wrap_suite_id", c::u(WRAP_SUITE_ID_CHACHA20POLY1305 as u64)),
        ("archive_format_id", c::u(ARCHIVE_FORMAT_ID_TAR as u64)),
        (
            "archive_policy_id",
            c::u(ARCHIVE_POLICY_ID_PROFILE_SNAPSHOT as u64),
        ),
        ("compression_id", c::u(COMPRESSION_ID_GZIP as u64)),
        (
            "frame_plaintext_size",
            c::u(nums.frame_plaintext_size as u64),
        ),
        ("stream_nonce_prefix", c::b(stream_nonce_prefix)),
        ("final_frame_required", Value::Bool(true)),
        ("max_plaintext_size", c::u(nums.max_plaintext_size)),
        ("max_ciphertext_size", c::u(nums.max_ciphertext_size)),
        ("created_at_ms", c::u(nums.created_at_ms)),
        (
            "intended_signer_signing_key_id",
            c::b(&ids.intended_signer_signing_key_id),
        ),
        ("server_instance_id", c::b(&ids.server_instance_id)),
        ("restore_epoch", c::u(nums.restore_epoch)),
        ("dek_slot_context_hash", c::b(&slot.context_hash)),
        ("dek_slot_sha256", c::b(&slot.dek_slot_sha256)),
    ];
    if let Some(prev) = previous_signed_head_hash {
        fields.push(("previous_signed_head_hash", c::b(prev)));
    }

    let exact_intent_bytes = c::encode(&c::m(fields));
    let intent_hash = c::domain_hash(c::L_ENVELOPE_INTENT, &exact_intent_bytes);
    Ok(IntentMaterial {
        exact_intent_bytes,
        intent_hash,
    })
}

// -------------------------------------------------------- STREAM framing ----

/// STREAM nonce = 7-byte per-snapshot prefix ‖ u32be(counter) ‖ final flag.
pub fn stream_nonce(
    prefix: &[u8; STREAM_NONCE_PREFIX_LEN],
    counter: u32,
    is_final: bool,
) -> [u8; STREAM_NONCE_LEN] {
    let mut n = [0u8; STREAM_NONCE_LEN];
    n[..STREAM_NONCE_PREFIX_LEN].copy_from_slice(prefix);
    n[STREAM_NONCE_PREFIX_LEN..STREAM_NONCE_PREFIX_LEN + 4].copy_from_slice(&counter.to_be_bytes());
    n[11] = u8::from(is_final);
    n
}

/// Frame AAD binds the exact `intent_hash`, the counter and the final flag.
///
/// This is what makes truncation, reordering and cross-envelope splicing all
/// fail closed: a frame is only openable at the exact position, in the exact
/// stream, that it was sealed for.
pub fn frame_aad(intent_hash: &[u8; 32], counter: u32, is_final: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(L_ENVELOPE_FRAME.len() + 32 + 4 + 1);
    aad.extend_from_slice(L_ENVELOPE_FRAME.as_bytes());
    aad.extend_from_slice(intent_hash);
    aad.extend_from_slice(&counter.to_be_bytes());
    aad.push(u8::from(is_final));
    aad
}

pub fn seal_frame(
    dek: &[u8; DEK_LEN],
    prefix: &[u8; STREAM_NONCE_PREFIX_LEN],
    intent_hash: &[u8; 32],
    counter: u32,
    is_final: bool,
    plaintext: &[u8],
) -> Result<Vec<u8>, KeyError> {
    let cipher = ChaCha20Poly1305::new(&(*dek).into());
    let nonce = stream_nonce(prefix, counter, is_final);
    cipher
        .encrypt(
            &nonce.into(),
            Payload {
                msg: plaintext,
                aad: &frame_aad(intent_hash, counter, is_final),
            },
        )
        .map_err(|_| KeyError::Aead)
}

pub fn open_frame(
    dek: &[u8; DEK_LEN],
    prefix: &[u8; STREAM_NONCE_PREFIX_LEN],
    intent_hash: &[u8; 32],
    counter: u32,
    is_final: bool,
    ciphertext: &[u8],
) -> Result<Vec<u8>, KeyError> {
    let cipher = ChaCha20Poly1305::new(&(*dek).into());
    let nonce = stream_nonce(prefix, counter, is_final);
    cipher
        .decrypt(
            &nonce.into(),
            Payload {
                msg: ciphertext,
                aad: &frame_aad(intent_hash, counter, is_final),
            },
        )
        .map_err(|_| KeyError::Aead)
}

// ---------------------------------------------- restore-epoch Merkle tree ----

pub fn restore_epoch_leaf_bytes(
    tenant_id: &[u8; 16],
    profile_id: &[u8; 16],
    previous_signed_head_hash: &[u8; 32],
    new_signed_head_hash: &[u8; 32],
) -> Vec<u8> {
    c::encode(&c::m(vec![
        ("domain", c::t("shardx.restore-epoch.profile-head-leaf.v2")),
        ("version", c::u(2)),
        ("tenant_id", c::b(tenant_id)),
        ("profile_id", c::b(profile_id)),
        ("previous_signed_head_hash", c::b(previous_signed_head_hash)),
        ("new_signed_head_hash", c::b(new_signed_head_hash)),
    ]))
}

pub fn leaf_hash(exact_leaf_bytes: &[u8]) -> [u8; 32] {
    c::domain_hash(c::L_RESTORE_EPOCH_LEAF, exact_leaf_bytes)
}

/// Internal node with two children. Distinct label from [`node1`] so a
/// single-child promotion can never be forged as a two-child node.
pub fn node2(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut pre = Vec::with_capacity(L_RESTORE_EPOCH_NODE2_LEN + 64);
    pre.extend_from_slice(c::L_RESTORE_EPOCH_NODE2.as_bytes());
    pre.extend_from_slice(left);
    pre.extend_from_slice(right);
    c::sha256(&pre)
}

/// Odd-node promotion, domain-separated from [`node2`].
pub fn node1(child: &[u8; 32]) -> [u8; 32] {
    let mut pre = Vec::with_capacity(L_RESTORE_EPOCH_NODE1_LEN + 32);
    pre.extend_from_slice(c::L_RESTORE_EPOCH_NODE1.as_bytes());
    pre.extend_from_slice(child);
    c::sha256(&pre)
}

const L_RESTORE_EPOCH_NODE2_LEN: usize = 30;
const L_RESTORE_EPOCH_NODE1_LEN: usize = 30;

/// A restore-epoch leaf: `(tenant_id, profile_id, exact_leaf_bytes)`.
///
/// The tuple key is what the tree's ordering and duplicate rules are enforced
/// on, so it travels with the bytes rather than being re-derived.
pub type EpochLeaf = ([u8; 16], [u8; 16], Vec<u8>);

#[derive(Debug, PartialEq, Eq)]
pub enum MerkleError {
    /// An epoch transition must cover at least one profile head. There is
    /// deliberately no "empty root" constant to forge against.
    EmptyTree,
    TooManyLeaves(u64),
    /// The same `(tenant_id, profile_id)` appeared twice.
    DuplicateTuple,
    /// Leaves must be in ascending raw tuple order.
    UnsortedLeaves,
}

impl std::fmt::Display for MerkleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyTree => write!(f, "restore-epoch transition has no leaves"),
            Self::TooManyLeaves(n) => write!(f, "too many leaves: {n}"),
            Self::DuplicateTuple => write!(f, "duplicate (tenant_id, profile_id) leaf"),
            Self::UnsortedLeaves => write!(f, "leaves are not in ascending tuple order"),
        }
    }
}

impl std::error::Error for MerkleError {}

/// Merkle root over ordered leaves.
///
/// Rejects empty, oversized, duplicate and unsorted inputs rather than
/// normalizing them: a caller that cannot produce a canonical leaf set must not
/// get a root it can present as authoritative.
pub fn merkle_root(leaves: &[EpochLeaf]) -> Result<[u8; 32], MerkleError> {
    if leaves.is_empty() {
        return Err(MerkleError::EmptyTree);
    }
    if leaves.len() as u64 > c::MAX_RESTORE_EPOCH_LEAVES_V2 {
        return Err(MerkleError::TooManyLeaves(leaves.len() as u64));
    }
    for w in leaves.windows(2) {
        match (w[0].0, w[0].1).cmp(&(w[1].0, w[1].1)) {
            std::cmp::Ordering::Equal => return Err(MerkleError::DuplicateTuple),
            std::cmp::Ordering::Greater => return Err(MerkleError::UnsortedLeaves),
            std::cmp::Ordering::Less => {}
        }
    }

    let mut level: Vec<[u8; 32]> = leaves.iter().map(|(_, _, b)| leaf_hash(b)).collect();
    // The root of a single leaf is the leaf hash itself: no unary promote is
    // applied at an empty level.
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i + 1 < level.len() {
            next.push(node2(&level[i], &level[i + 1]));
            i += 2;
        }
        if i < level.len() {
            next.push(node1(&level[i]));
        }
        level = next;
    }
    Ok(level[0])
}

pub const DIR_SIBLING_LEFT: u64 = 0;
pub const DIR_SIBLING_RIGHT: u64 = 1;
pub const DIR_UNARY_PROMOTE: u64 = 2;

/// One inclusion-proof step: a direction plus the sibling it consumes.
/// `UnaryPromote` carries no sibling.
pub type ProofStep = (u64, Option<[u8; 32]>);

/// Build the exact proof step list for `leaf_index`.
pub fn merkle_proof_steps(leaves: &[EpochLeaf], leaf_index: usize) -> Vec<ProofStep> {
    let mut level: Vec<[u8; 32]> = leaves.iter().map(|(_, _, b)| leaf_hash(b)).collect();
    let mut idx = leaf_index;
    let mut steps = Vec::new();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i + 1 < level.len() {
            if idx == i {
                steps.push((DIR_SIBLING_RIGHT, Some(level[i + 1])));
                idx = next.len();
            } else if idx == i + 1 {
                steps.push((DIR_SIBLING_LEFT, Some(level[i])));
                idx = next.len();
            }
            next.push(node2(&level[i], &level[i + 1]));
            i += 2;
        }
        if i < level.len() {
            if idx == i {
                steps.push((DIR_UNARY_PROMOTE, None));
                idx = next.len();
            }
            next.push(node1(&level[i]));
        }
        level = next;
    }
    steps
}

#[derive(Debug, PartialEq, Eq)]
pub enum ProofError {
    DirectionMismatch { level: usize },
    UnaryNotAtOddTail { level: usize },
    MissingSibling,
    UnexpectedSibling,
    StepCountMismatch { expected: usize, got: usize },
    RootMismatch,
    LeafIndexOutOfRange,
    LeafCountOutOfRange,
}

impl std::fmt::Display for ProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DirectionMismatch { level } => {
                write!(f, "proof direction does not match parity at level {level}")
            }
            Self::UnaryNotAtOddTail { level } => {
                write!(f, "unary promote outside the odd tail at level {level}")
            }
            Self::MissingSibling => write!(f, "proof step is missing its sibling"),
            Self::UnexpectedSibling => write!(f, "unary promote carries a sibling"),
            Self::StepCountMismatch { expected, got } => {
                write!(
                    f,
                    "proof step count mismatch: expected {expected}, got {got}"
                )
            }
            Self::RootMismatch => write!(f, "proof does not reconstruct the expected root"),
            Self::LeafIndexOutOfRange => write!(f, "leaf index out of range"),
            Self::LeafCountOutOfRange => write!(f, "leaf count out of range"),
        }
    }
}

impl std::error::Error for ProofError {}

/// Verify an inclusion proof.
///
/// The verifier recomputes the expected parity and level width independently and
/// requires the step list to match exactly — no omitted, extra or repeated step,
/// and no unary promote anywhere but a genuine odd tail.
pub fn verify_proof(
    leaf_index: u64,
    leaf_count: u64,
    leaf_hash_value: &[u8; 32],
    steps: &[ProofStep],
    expected_root: &[u8; 32],
) -> Result<(), ProofError> {
    if leaf_count == 0 || leaf_count > c::MAX_RESTORE_EPOCH_LEAVES_V2 {
        return Err(ProofError::LeafCountOutOfRange);
    }
    if leaf_index >= leaf_count {
        return Err(ProofError::LeafIndexOutOfRange);
    }

    let mut acc = *leaf_hash_value;
    let mut idx = leaf_index as usize;
    let mut width = leaf_count as usize;
    let mut used = 0usize;
    let mut level = 0usize;

    while width > 1 {
        let paired = (width / 2) * 2;
        let step = steps.get(used).ok_or(ProofError::StepCountMismatch {
            expected: used + 1,
            got: steps.len(),
        })?;
        if idx < paired {
            let expect_dir = if idx.is_multiple_of(2) {
                DIR_SIBLING_RIGHT
            } else {
                DIR_SIBLING_LEFT
            };
            if step.0 != expect_dir {
                return Err(ProofError::DirectionMismatch { level });
            }
            let sib = step.1.as_ref().ok_or(ProofError::MissingSibling)?;
            acc = if idx.is_multiple_of(2) {
                node2(&acc, sib)
            } else {
                node2(sib, &acc)
            };
        } else {
            if step.0 != DIR_UNARY_PROMOTE {
                return Err(ProofError::DirectionMismatch { level });
            }
            if idx != width - 1 || width.is_multiple_of(2) {
                return Err(ProofError::UnaryNotAtOddTail { level });
            }
            if step.1.is_some() {
                return Err(ProofError::UnexpectedSibling);
            }
            acc = node1(&acc);
        }
        used += 1;
        idx /= 2;
        width = width.div_ceil(2);
        level += 1;
    }

    if used != steps.len() {
        return Err(ProofError::StepCountMismatch {
            expected: used,
            got: steps.len(),
        });
    }
    if width != 1 || idx != 0 {
        return Err(ProofError::RootMismatch);
    }
    if &acc != expected_root {
        return Err(ProofError::RootMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{root_key_id, signing_key_id};
    use crate::signing::identity_key_id;
    use ed25519_dalek::SigningKey;

    fn hex32(h: &[u8; 32]) -> String {
        h.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn fixture_bytes<const N: usize>(label: &str) -> [u8; N] {
        use sha2::{Digest, Sha256};
        let mut out = [0u8; N];
        let mut counter: u32 = 0;
        let mut filled = 0;
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

    /// The exact G2 fixture from the gate's `build_fixture()`.
    struct Fixture {
        slot: SlotMaterial,
        intent: IntentMaterial,
        dek: [u8; DEK_LEN],
        prefix: [u8; STREAM_NONCE_PREFIX_LEN],
    }

    fn build_g2_fixture(genesis: bool) -> Fixture {
        let fkek: [u8; 32] = fixture_bytes("fkek-gen-1");
        // The gate's genesis probe uses a `-0`-suffixed fixture set throughout.
        let sfx = if genesis { "0" } else { "1" };
        let dek: [u8; DEK_LEN] = fixture_bytes(&format!("dek-snapshot-{sfx}"));
        let wrap_nonce: [u8; WRAP_NONCE_LEN] = fixture_bytes(&format!("wrap-nonce-{sfx}"));
        let prefix: [u8; STREAM_NONCE_PREFIX_LEN] = fixture_bytes(&format!("stream-prefix-{sfx}"));

        let tenant_id: [u8; 16] = fixture_bytes("tenant-a");
        let fleet_id: [u8; 16] = fixture_bytes("fleet-a");
        let profile_id: [u8; 16] = fixture_bytes("profile-a");
        // The gate's genesis probe uses a distinct id set from the versioned one.
        let snapshot_id: [u8; 16] =
            fixture_bytes(if genesis { "snapshot-0" } else { "snapshot-1" });
        let lease_id: [u8; 16] = fixture_bytes(if genesis { "lease-0" } else { "lease-1" });
        let manifest_replay_id: [u8; 16] = fixture_bytes(if genesis {
            "manifest-replay-0"
        } else {
            "manifest-replay-1"
        });
        let server_instance_id: [u8; 16] = fixture_bytes("server-1");
        let envelope_context_nonce: [u8; 16] =
            fixture_bytes(&format!("envelope-context-nonce-{sfx}"));
        let fkek_key_id = root_key_id(&fkek);

        let signer = SigningKey::from_bytes(&fixture_bytes::<32>("snapshot-signer"));
        let signer_key_id = signing_key_id(signer.verifying_key().as_bytes());
        assert_eq!(signer_key_id, identity_key_id(&signer.verifying_key()));

        let slot = build_dek_slot(
            &fkek,
            &dek,
            &wrap_nonce,
            &SlotIds {
                tenant_id: &tenant_id,
                fleet_id: &fleet_id,
                profile_id: &profile_id,
                snapshot_id: &snapshot_id,
                fkek_key_id: &fkek_key_id,
                envelope_context_nonce: &envelope_context_nonce,
            },
            1,
        )
        .expect("slot");

        let prev_head: [u8; 32] = fixture_bytes("previous-signed-head");
        let nums = if genesis {
            IntentNumbers {
                target_version: 1,
                base_version: 0,
                fencing_token: 1,
                key_generation: 1,
                restore_epoch: 7,
                frame_plaintext_size: 65536,
                max_plaintext_size: 4_194_304,
                max_ciphertext_size: 4_259_840,
                created_at_ms: 1_756_000_000_000,
            }
        } else {
            IntentNumbers {
                target_version: 5,
                base_version: 4,
                fencing_token: 42,
                key_generation: 1,
                restore_epoch: 7,
                frame_plaintext_size: 65536,
                max_plaintext_size: 4_194_304,
                max_ciphertext_size: 4_259_840,
                created_at_ms: 1_756_000_000_000,
            }
        };

        let intent = build_envelope_intent(
            &IntentIds {
                snapshot_id,
                tenant_id,
                fleet_id,
                profile_id,
                lease_id,
                manifest_replay_id,
                server_instance_id,
                fkek_key_id,
                intended_signer_signing_key_id: signer_key_id,
            },
            &nums,
            &prefix,
            if genesis { None } else { Some(&prev_head) },
            &slot,
        )
        .expect("intent");

        Fixture {
            slot,
            intent,
            dek,
            prefix,
        }
    }

    // ---------------------------------------------------- golden vectors ----

    /// Pinned from the G2 report, probe `G2-VEC-dek-slot`.
    #[test]
    fn g2_golden_vector_dek_slot() {
        let f = build_g2_fixture(false);
        assert_eq!(
            hex32(&f.slot.dek_slot_sha256),
            "bd97ceab0b5b94b22c074ee5dabe651ad453492de573672ee34bf3ea89f799c7",
            "dek_slot_sha256 diverged from the G2-pinned golden vector"
        );
    }

    /// Pinned from the G2 report, probe `G2-VEC-intent`.
    #[test]
    fn g2_golden_vector_intent() {
        let f = build_g2_fixture(false);
        assert_eq!(
            hex32(&f.intent.intent_hash),
            "4f566bd7074289878e54c50e0e837fffd1bb324e39ad6a4105f16e3602cef239",
            "intent_hash diverged from the G2-pinned golden vector"
        );
    }

    /// Pinned from the G2 report, probe `G2-VEC-intent-genesis`. Proves the
    /// optional head hash is OMITTED, not null, at `base_version == 0`.
    #[test]
    fn g2_golden_vector_intent_genesis() {
        let f = build_g2_fixture(true);
        assert_eq!(
            hex32(&f.intent.intent_hash),
            "255766d2341f02b05eb054cb5aaecf9d3024a1f18bf1c49d293077757153008f",
            "genesis intent_hash diverged from the G2-pinned golden vector"
        );
    }

    /// Pinned from the G2 report, probe `G2-VEC-ciphertext-stream`.
    #[test]
    fn g2_golden_vector_ciphertext_stream() {
        let f = build_g2_fixture(false);
        let ih = f.intent.intent_hash;
        let c0 = seal_frame(&f.dek, &f.prefix, &ih, 0, false, b"plaintext-frame-0-block").unwrap();
        let c1 = seal_frame(&f.dek, &f.prefix, &ih, 1, true, b"plaintext-frame-1-final").unwrap();
        let mut all = c0.clone();
        all.extend_from_slice(&c1);
        assert_eq!(
            hex32(&c::sha256(&all)),
            "95f278dbbb81505a24d38c1082fa7395f651ad1a2aeb049d71442c1443091109",
            "2-frame ciphertext diverged from the G2-pinned golden vector"
        );
    }

    /// Pinned from the G2 report, probes `G2-VEC-merkle-n1/n2/n3`.
    #[test]
    fn g2_golden_vectors_merkle_roots() {
        let roots: Vec<String> = (1..=3)
            .map(|n| {
                let mut leaves = g2_leaves(n);
                leaves.sort_by_key(|x| (x.0, x.1));
                hex32(&merkle_root(&leaves).expect("root"))
            })
            .collect();

        assert_eq!(
            roots[0], "49a633fcc5d872970885e5098c3100cfe5dbc4aa8ff6e3fbf7ebb9b93db87414",
            "n=1 Merkle root diverged from the G2-pinned golden vector"
        );
        assert_eq!(
            roots[1], "9f6dc107e60b21f765dcfc393c2f9f247febdfd75517a180e9036dd7b75cec48",
            "n=2 Merkle root diverged from the G2-pinned golden vector"
        );
        assert_eq!(
            roots[2], "1d89cd4e233fac8d84df6c8039bd0084bc331e53a9233fd1643a4e3f59a0ce5f",
            "n=3 Merkle root diverged from the G2-pinned golden vector"
        );
    }

    // ------------------------------------------------- structural invariants --

    #[test]
    fn slot_and_intent_bytes_are_canonical() {
        let f = build_g2_fixture(false);
        assert!(c::assert_canonical_roundtrip(&f.slot.exact_slot_bytes).is_ok());
        assert!(c::assert_canonical_roundtrip(&f.slot.context_bytes).is_ok());
        assert!(c::assert_canonical_roundtrip(&f.intent.exact_intent_bytes).is_ok());
    }

    /// The core acyclic-commitment property, asserted directly on bytes.
    #[test]
    fn commitment_direction_is_acyclic() {
        let f = build_g2_fixture(false);

        // The closed slot context must not reference the intent.
        assert!(!f
            .slot
            .context_bytes
            .windows(32)
            .any(|w| w == f.intent.intent_hash));
        // The intent must not contain the ciphertext or any manifest hash; it
        // must contain the slot commitments.
        assert!(f
            .intent
            .exact_intent_bytes
            .windows(32)
            .any(|w| w == f.slot.dek_slot_sha256));
        assert!(f
            .intent
            .exact_intent_bytes
            .windows(32)
            .any(|w| w == f.slot.context_hash));
    }

    #[test]
    fn genesis_omits_previous_head_rather_than_encoding_null() {
        let genesis = build_g2_fixture(true);
        let normal = build_g2_fixture(false);
        assert!(!genesis
            .intent
            .exact_intent_bytes
            .windows(25)
            .any(|w| w == b"previous_signed_head_hash"));
        assert!(normal
            .intent
            .exact_intent_bytes
            .windows(25)
            .any(|w| w == b"previous_signed_head_hash"));
        // No null (0xf6) anywhere in the genesis encoding.
        assert!(!genesis.intent.exact_intent_bytes.contains(&0xf6));
    }

    #[test]
    fn intent_rejects_non_sequential_versions() {
        let fkek: [u8; 32] = fixture_bytes("fkek-gen-1");
        let dek: [u8; DEK_LEN] = fixture_bytes("dek-snapshot-1");
        let wrap_nonce: [u8; WRAP_NONCE_LEN] = fixture_bytes("wrap-nonce-1");
        let prefix: [u8; STREAM_NONCE_PREFIX_LEN] = fixture_bytes("stream-prefix-1");
        let id16: [u8; 16] = fixture_bytes("tenant-a");
        let id32: [u8; 32] = fixture_bytes("previous-signed-head");
        let fkek_key_id = root_key_id(&fkek);
        let slot = build_dek_slot(
            &fkek,
            &dek,
            &wrap_nonce,
            &SlotIds {
                tenant_id: &id16,
                fleet_id: &id16,
                profile_id: &id16,
                snapshot_id: &id16,
                fkek_key_id: &fkek_key_id,
                envelope_context_nonce: &id16,
            },
            1,
        )
        .unwrap();

        let ids = IntentIds {
            snapshot_id: id16,
            tenant_id: id16,
            fleet_id: id16,
            profile_id: id16,
            lease_id: id16,
            manifest_replay_id: id16,
            server_instance_id: id16,
            fkek_key_id,
            intended_signer_signing_key_id: id32,
        };
        let mut nums = IntentNumbers {
            target_version: 9,
            base_version: 4,
            fencing_token: 1,
            key_generation: 1,
            restore_epoch: 0,
            frame_plaintext_size: 65536,
            max_plaintext_size: 1024,
            max_ciphertext_size: 2048,
            created_at_ms: 0,
        };
        let err = build_envelope_intent(&ids, &nums, &prefix, Some(&id32), &slot)
            .err()
            .expect("non-sequential versions must fail");
        assert_eq!(
            err,
            IntentError::NonSequentialVersion { base: 4, target: 9 }
        );

        // Genesis with a previous head is rejected.
        nums.base_version = 0;
        nums.target_version = 1;
        let err = build_envelope_intent(&ids, &nums, &prefix, Some(&id32), &slot)
            .err()
            .expect("genesis mismatch must fail");
        assert_eq!(
            err,
            IntentError::GenesisHeadMismatch {
                base_version: 0,
                has_prev: true
            }
        );
    }

    // -------------------------------------------------------- STREAM AEAD ----

    #[test]
    fn frames_roundtrip() {
        let f = build_g2_fixture(false);
        let ih = f.intent.intent_hash;
        let p0 = b"plaintext-frame-0-block";
        let c0 = seal_frame(&f.dek, &f.prefix, &ih, 0, false, p0).unwrap();
        assert_eq!(
            open_frame(&f.dek, &f.prefix, &ih, 0, false, &c0).unwrap(),
            p0
        );
    }

    #[test]
    fn truncation_is_rejected() {
        let f = build_g2_fixture(false);
        let ih = f.intent.intent_hash;
        let c1 = seal_frame(&f.dek, &f.prefix, &ih, 1, true, b"final").unwrap();
        // A FINAL frame cannot be opened as non-final: a truncated stream can
        // never be presented as a complete one.
        assert_eq!(
            open_frame(&f.dek, &f.prefix, &ih, 1, false, &c1),
            Err(KeyError::Aead)
        );
    }

    #[test]
    fn reordering_is_rejected() {
        let f = build_g2_fixture(false);
        let ih = f.intent.intent_hash;
        let c0 = seal_frame(&f.dek, &f.prefix, &ih, 0, false, b"a").unwrap();
        let c1 = seal_frame(&f.dek, &f.prefix, &ih, 1, true, b"b").unwrap();
        assert_eq!(
            open_frame(&f.dek, &f.prefix, &ih, 1, false, &c0),
            Err(KeyError::Aead)
        );
        assert_eq!(
            open_frame(&f.dek, &f.prefix, &ih, 0, false, &c1),
            Err(KeyError::Aead)
        );
    }

    #[test]
    fn wrong_aad_and_wrong_key_fail_closed() {
        let f = build_g2_fixture(false);
        let ih = f.intent.intent_hash;
        let c0 = seal_frame(&f.dek, &f.prefix, &ih, 0, false, b"a").unwrap();

        let mut other = ih;
        other[0] ^= 0xff;
        assert_eq!(
            open_frame(&f.dek, &f.prefix, &other, 0, false, &c0),
            Err(KeyError::Aead)
        );

        let wrong_dek: [u8; DEK_LEN] = fixture_bytes("wrong-dek");
        assert_eq!(
            open_frame(&wrong_dek, &f.prefix, &ih, 0, false, &c0),
            Err(KeyError::Aead)
        );
    }

    /// A frame from one envelope must not open in another, even at the same
    /// position with the same key — the intent hash separates the streams.
    #[test]
    fn cross_envelope_splice_is_rejected() {
        let a = build_g2_fixture(false);
        let b = build_g2_fixture(true); // different intent (genesis)
        assert_ne!(a.intent.intent_hash, b.intent.intent_hash);

        let ca = seal_frame(&a.dek, &a.prefix, &a.intent.intent_hash, 0, false, b"x").unwrap();
        assert_eq!(
            open_frame(&b.dek, &b.prefix, &b.intent.intent_hash, 0, false, &ca),
            Err(KeyError::Aead)
        );
    }

    #[test]
    fn corruption_of_any_ciphertext_byte_fails_closed() {
        let f = build_g2_fixture(false);
        let ih = f.intent.intent_hash;
        let c0 = seal_frame(&f.dek, &f.prefix, &ih, 0, false, b"plaintext-block").unwrap();
        for i in 0..c0.len() {
            let mut bad = c0.clone();
            bad[i] ^= 0x01;
            assert_eq!(
                open_frame(&f.dek, &f.prefix, &ih, 0, false, &bad),
                Err(KeyError::Aead),
                "corrupted byte {i} must fail closed"
            );
        }
    }

    #[test]
    fn stream_nonce_layout_is_exact() {
        let prefix: [u8; STREAM_NONCE_PREFIX_LEN] = fixture_bytes("stream-prefix-1");
        let n = stream_nonce(&prefix, 0x01020304, true);
        assert_eq!(n.len(), STREAM_NONCE_LEN);
        assert_eq!(&n[..7], &prefix[..]);
        assert_eq!(&n[7..11], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(n[11], 1);
        assert_eq!(stream_nonce(&prefix, 0x01020304, false)[11], 0);
    }

    // ------------------------------------------------------------- Merkle ----

    /// The gate's leaf fixture: profiles `1..=n`, tenant `tenant-a`.
    fn g2_leaves(n: u8) -> Vec<EpochLeaf> {
        let tenant: [u8; 16] = fixture_bytes("tenant-a");
        (1..=n)
            .map(|i| {
                let pid: [u8; 16] = fixture_bytes(&format!("profile-{i}"));
                let prev: [u8; 32] = fixture_bytes(&format!("prev-head-{i}"));
                let new: [u8; 32] = fixture_bytes(&format!("new-head-{i}"));
                (
                    tenant,
                    pid,
                    restore_epoch_leaf_bytes(&tenant, &pid, &prev, &new),
                )
            })
            .collect()
    }

    fn sorted_leaves(n: u8) -> Vec<EpochLeaf> {
        let mut l = g2_leaves(n);
        l.sort_by_key(|x| (x.0, x.1));
        l
    }

    #[test]
    fn merkle_empty_tree_is_rejected() {
        // There is no empty-root constant to forge against.
        assert_eq!(merkle_root(&[]), Err(MerkleError::EmptyTree));
    }

    #[test]
    fn merkle_rejects_duplicate_and_unsorted_leaves() {
        let l = sorted_leaves(2);
        let dup = vec![l[0].clone(), l[0].clone()];
        assert_eq!(merkle_root(&dup), Err(MerkleError::DuplicateTuple));

        let unsorted = vec![l[1].clone(), l[0].clone()];
        assert_eq!(merkle_root(&unsorted), Err(MerkleError::UnsortedLeaves));
    }

    #[test]
    fn merkle_single_leaf_root_is_the_leaf_hash() {
        let l = sorted_leaves(1);
        assert_eq!(merkle_root(&l).unwrap(), leaf_hash(&l[0].2));
        // No unary promote is applied at an empty level.
        assert!(merkle_proof_steps(&l, 0).is_empty());
    }

    #[test]
    fn merkle_node_labels_are_domain_separated() {
        let a: [u8; 32] = fixture_bytes("child");
        // A promoted odd node must never be confusable with a binary node over
        // a duplicated child.
        assert_ne!(node1(&a), node2(&a, &a));
        assert_ne!(node1(&a), a);
    }

    #[test]
    fn merkle_proofs_verify_for_every_leaf() {
        for n in 1..=3u8 {
            let l = sorted_leaves(n);
            let root = merkle_root(&l).unwrap();
            for i in 0..l.len() {
                let lh = leaf_hash(&l[i].2);
                let steps = merkle_proof_steps(&l, i);
                assert_eq!(
                    verify_proof(i as u64, n as u64, &lh, &steps, &root),
                    Ok(()),
                    "leaf {i} of {n} must verify"
                );
            }
        }
    }

    /// The odd tail must be promoted with NODE1, never duplicated into NODE2.
    #[test]
    fn merkle_odd_tail_uses_unary_promote() {
        let l = sorted_leaves(3);
        let saw_unary = (0..3).any(|i| {
            merkle_proof_steps(&l, i)
                .iter()
                .any(|(d, s)| *d == DIR_UNARY_PROMOTE && s.is_none())
        });
        assert!(saw_unary, "n=3 must promote its odd tail");
    }

    #[test]
    fn merkle_proof_rejects_wrong_direction_and_extra_steps() {
        let l = sorted_leaves(2);
        let root = merkle_root(&l).unwrap();
        let lh = leaf_hash(&l[0].2);

        let mut bad = merkle_proof_steps(&l, 0);
        bad[0].0 = DIR_SIBLING_LEFT;
        assert_eq!(
            verify_proof(0, 2, &lh, &bad, &root),
            Err(ProofError::DirectionMismatch { level: 0 })
        );

        let mut extra = merkle_proof_steps(&l, 0);
        extra.push((DIR_UNARY_PROMOTE, None));
        assert!(matches!(
            verify_proof(0, 2, &lh, &extra, &root),
            Err(ProofError::StepCountMismatch { .. })
        ));
    }

    #[test]
    fn merkle_proof_rejects_out_of_range_and_wrong_root() {
        let l = sorted_leaves(2);
        let root = merkle_root(&l).unwrap();
        let lh = leaf_hash(&l[0].2);
        let steps = merkle_proof_steps(&l, 0);

        assert_eq!(
            verify_proof(2, 2, &lh, &steps, &root),
            Err(ProofError::LeafIndexOutOfRange)
        );
        assert_eq!(
            verify_proof(0, 0, &lh, &steps, &root),
            Err(ProofError::LeafCountOutOfRange)
        );

        let mut wrong = root;
        wrong[0] ^= 0x01;
        assert_eq!(
            verify_proof(0, 2, &lh, &steps, &wrong),
            Err(ProofError::RootMismatch)
        );
    }

    #[test]
    fn merkle_root_is_order_sensitive() {
        let l = sorted_leaves(2);
        let swapped = vec![l[1].clone(), l[0].clone()];
        // Reversed order is rejected outright rather than silently re-sorted.
        assert_eq!(merkle_root(&swapped), Err(MerkleError::UnsortedLeaves));
    }
}
