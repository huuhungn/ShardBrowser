//! Envelope v2 objects: `SHARDXBK`, suite 2 (ADR 0003, G2-27).
//!
//! ```text
//!   PreambleV2 (64 bytes) | intent_bytes | dek_slot_bytes | FrameRecord+
//!   FrameRecord = kind u8 (0 DATA, 1 FINAL) | counter u32be | ciphertext_len u32be | ciphertext
//! ```
//!
//! Frames are XChaCha20-Poly1305 under RustCrypto STREAM LE31 (`aead-stream`):
//! the nonce is the 20-byte prefix, then `u32le(position | last << 31)`, so no
//! nonce or counter arithmetic lives here. Frame `i` is STREAM position `i`,
//! and its AAD is [`frame_aad`].
//!
//! [`open`] writes no plaintext until the whole object matches the size and
//! hash the verified manifest names, and the preamble, intent and slot all
//! check out. Plaintext then goes only to the caller's staging sink, which the
//! caller promotes after `Ok` and discards on any error.

use std::io::{Read, Seek, SeekFrom, Write};

use aead_stream::aead::Payload;
use aead_stream::{DecryptorLE31, EncryptorLE31};
use chacha20poly1305::XChaCha20Poly1305;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::authz_record::{Fields, RecordError};
use crate::canonical::{self as c, Value};
use crate::envelope::{
    build_intent, frame_aad, IntentError, IntentIds, IntentMaterial, IntentNumbers, SlotMaterial,
};
use crate::keys::{
    unwrap_dek, AEAD_TAG_LEN, ARCHIVE_FORMAT_ID_TAR, ARCHIVE_POLICY_ID_PROFILE_SNAPSHOT,
    COMPRESSION_ID_GZIP, DEK_LEN, ENVELOPE_SUITE_ID_XCHACHA20POLY1305_STREAM_LE31 as SUITE_ID,
    WRAP_NONCE_LEN, WRAP_SUITE_ID_CHACHA20POLY1305,
};

pub const MAGIC: [u8; 8] = *b"SHARDXBK";
pub const ENVELOPE_VERSION: u16 = 2;
pub const PREAMBLE_LEN: usize = 64;
/// XChaCha20's 24-byte nonce less the 4 bytes STREAM LE31 appends.
pub const STREAM_NONCE_PREFIX_LEN: usize = 20;
/// What a writer uses; readers accept the whole range below.
pub const DEFAULT_FRAME_PLAINTEXT_SIZE: u32 = 1 << 20;
pub const MIN_FRAME_PLAINTEXT_SIZE: u32 = 1 << 16;
pub const MAX_FRAME_PLAINTEXT_SIZE: u32 = 1 << 22;
pub const MAX_INTENT_LEN: u32 = 65_536;
pub const MAX_DEK_SLOT_LEN: u32 = 16_384;
/// The plan's cap on both the plaintext and the stored object (L649-L652).
pub const MAX_OBJECT_SIZE: u64 = 536_870_912;
pub const L_ENVELOPE_PREAMBLE: &str = "SHARDX-ENVELOPE-PREAMBLE-V2\0";
pub const KIND_DATA: u8 = 0;
pub const KIND_FINAL: u8 = 1;

const TAG_LEN: usize = 16;
const FRAME_HEADER_LEN: u64 = 9;

#[derive(Debug)]
pub enum EnvelopeError {
    /// A structural rule of the object failed; the text names the rule.
    Malformed(&'static str),
    /// The object, or a part of it, is not what the manifest or the preamble
    /// commits to.
    Mismatch(&'static str),
    /// The intent, slot or slot context is not its exact closed map.
    Record(RecordError),
    /// The DEK did not unwrap under the given FKEK.
    KeyUnwrap,
    /// A frame failed authentication.
    Aead,
    Io(std::io::Error),
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(rule) => write!(f, "malformed envelope: {rule}"),
            Self::Mismatch(what) => write!(f, "envelope does not match its binding: {what}"),
            Self::Record(e) => write!(f, "malformed envelope record: {e}"),
            Self::KeyUnwrap => write!(f, "the DEK did not unwrap"),
            Self::Aead => write!(f, "a frame failed authentication"),
            Self::Io(e) => write!(f, "envelope I/O: {e}"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

impl From<std::io::Error> for EnvelopeError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<RecordError> for EnvelopeError {
    fn from(e: RecordError) -> Self {
        Self::Record(e)
    }
}

// --------------------------------------------------------------- preamble ----

/// The variable fields of `PreambleV2`; the rest are fixed by the format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preamble {
    pub intent_len: u32,
    pub dek_slot_len: u32,
    pub frame_plaintext_size: u32,
    pub intent_sha256: [u8; 32],
}

impl Preamble {
    pub fn encode(&self) -> [u8; PREAMBLE_LEN] {
        let mut p = [0u8; PREAMBLE_LEN];
        p[0..8].copy_from_slice(&MAGIC);
        p[8..10].copy_from_slice(&ENVELOPE_VERSION.to_be_bytes());
        p[10..12].copy_from_slice(&(PREAMBLE_LEN as u16).to_be_bytes());
        p[12..14].copy_from_slice(&SUITE_ID.to_be_bytes());
        // 14..16: flags, no bits defined. 28..32: reserved, zero.
        p[16..20].copy_from_slice(&self.intent_len.to_be_bytes());
        p[20..24].copy_from_slice(&self.dek_slot_len.to_be_bytes());
        p[24..28].copy_from_slice(&self.frame_plaintext_size.to_be_bytes());
        p[32..64].copy_from_slice(&self.intent_sha256);
        p
    }

    /// Every fixed field and bound, checked before anything is allocated.
    pub fn parse(p: &[u8; PREAMBLE_LEN]) -> Result<Self, EnvelopeError> {
        let u16_at = |i: usize| u16::from_be_bytes([p[i], p[i + 1]]);
        let u32_at = |i: usize| u32::from_be_bytes([p[i], p[i + 1], p[i + 2], p[i + 3]]);
        let rule = |ok: bool, name| {
            if ok {
                Ok(())
            } else {
                Err(EnvelopeError::Malformed(name))
            }
        };
        rule(p[0..8] == MAGIC, "magic")?;
        rule(u16_at(8) == ENVELOPE_VERSION, "envelope_version")?;
        rule(u16_at(10) as usize == PREAMBLE_LEN, "preamble_length")?;
        rule(u16_at(12) == SUITE_ID, "suite_id")?;
        rule(u16_at(14) == 0, "flags")?;
        rule(u32_at(28) == 0, "reserved")?;
        let intent_len = u32_at(16);
        rule((1..=MAX_INTENT_LEN).contains(&intent_len), "intent_len")?;
        let dek_slot_len = u32_at(20);
        rule(
            (1..=MAX_DEK_SLOT_LEN).contains(&dek_slot_len),
            "dek_slot_len",
        )?;
        let frame_plaintext_size = u32_at(24);
        rule(frame_size_ok(frame_plaintext_size), "frame_plaintext_size")?;
        let mut intent_sha256 = [0u8; 32];
        intent_sha256.copy_from_slice(&p[32..64]);
        Ok(Self {
            intent_len,
            dek_slot_len,
            frame_plaintext_size,
            intent_sha256,
        })
    }
}

/// `preamble_sha256`, the manifest's commitment to the 64 preamble bytes.
pub fn preamble_sha256(preamble: &[u8; PREAMBLE_LEN]) -> [u8; 32] {
    c::domain_hash(L_ENVELOPE_PREAMBLE, preamble)
}

fn frame_size_ok(size: u32) -> bool {
    (MIN_FRAME_PLAINTEXT_SIZE..=MAX_FRAME_PLAINTEXT_SIZE).contains(&size)
}

// ----------------------------------------------------------------- intent ----

/// `EnvelopeIntentV2` for suite 2, refusing sizes outside the plan's bounds.
pub fn build_intent_v2(
    ids: &IntentIds,
    nums: &IntentNumbers,
    stream_nonce_prefix: &[u8; STREAM_NONCE_PREFIX_LEN],
    previous_signed_head_hash: Option<&[u8; 32]>,
    slot: &SlotMaterial,
) -> Result<IntentMaterial, IntentError> {
    if !frame_size_ok(nums.frame_plaintext_size) {
        return Err(IntentError::OutOfBounds("frame_plaintext_size"));
    }
    for (name, value) in [
        ("max_plaintext_size", nums.max_plaintext_size),
        ("max_ciphertext_size", nums.max_ciphertext_size),
    ] {
        if !(1..=MAX_OBJECT_SIZE).contains(&value) {
            return Err(IntentError::OutOfBounds(name));
        }
    }
    build_intent(
        ids,
        nums,
        SUITE_ID,
        stream_nonce_prefix,
        previous_signed_head_hash,
        slot,
    )
}

// ------------------------------------------------------------ closed maps ----

/// `wrapped_dek_bytes` under `wrap_suite_id` 1: the DEK and its tag (ADR 0002
/// registry table: nonce 12, wrapped DEK 48, inside the plan's L628-L629 bounds).
const WRAPPED_DEK_LEN: usize = DEK_LEN + AEAD_TAG_LEN;
/// `canonical_dek_slot_context_bytes` is `Bytes(1,4096)` (plan L626).
const MAX_DEK_SLOT_CONTEXT_LEN: usize = 4096;

/// A `U16` with one valid value (`version`, `slot_index`, `preamble_version`).
fn exact_u16(f: &mut Fields, field: &'static str, want: u16) -> Result<(), RecordError> {
    if f.u16(field)? == want {
        Ok(())
    } else {
        Err(RecordError::BadValue(field))
    }
}

/// A registry ID that G2 pins to one value (ADR 0002 registry table).
fn registry_id(f: &mut Fields, field: &'static str, pinned: u16) -> Result<(), RecordError> {
    let id = f.u16(field)?;
    if id == pinned {
        Ok(())
    } else {
        Err(RecordError::Unsupported {
            field,
            id: id.into(),
        })
    }
}

/// `DekSlotContextV2` (plan L601-L617). `domain`, `version`, `wrap_suite_id`
/// and `slot_index` have one valid value each, so only the IDs are kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DekSlotContextV2 {
    pub snapshot_id: [u8; 16],
    pub tenant_id: [u8; 16],
    pub fleet_id: [u8; 16],
    pub profile_id: [u8; 16],
    pub fkek_key_id: [u8; 32],
    pub key_generation: u64,
    pub envelope_context_nonce: [u8; 16],
}

impl DekSlotContextV2 {
    /// Parses exact context bytes: canonical, closed, registry-pinned.
    pub fn parse(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut f = Fields::decode("DekSlotContextV2", bytes)?;
        f.exact_text("domain", "shardx.envelope.dek-slot-context.v2")?;
        exact_u16(&mut f, "version", 2)?;
        let snapshot_id = f.fixed("snapshot_id")?;
        let tenant_id = f.fixed("tenant_id")?;
        let fleet_id = f.fixed("fleet_id")?;
        let profile_id = f.fixed("profile_id")?;
        let fkek_key_id = f.fixed("fkek_key_id")?;
        let key_generation = f.uint("key_generation")?;
        registry_id(&mut f, "wrap_suite_id", WRAP_SUITE_ID_CHACHA20POLY1305)?;
        exact_u16(&mut f, "slot_index", 0)?;
        let envelope_context_nonce = f.fixed("envelope_context_nonce")?;
        f.finish()?;
        Ok(Self {
            snapshot_id,
            tenant_id,
            fleet_id,
            profile_id,
            fkek_key_id,
            key_generation,
            envelope_context_nonce,
        })
    }
}

/// `DekSlotV2` (plan L619-L635), the one slot of a v2 envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DekSlotV2 {
    pub context: DekSlotContextV2,
    /// The exact context bytes, which are the DEK-wrap AAD (plan L616).
    pub canonical_dek_slot_context_bytes: Vec<u8>,
    pub dek_slot_context_hash: [u8; 32],
    pub wrap_nonce_bytes: [u8; WRAP_NONCE_LEN],
    pub wrapped_dek_bytes: [u8; WRAPPED_DEK_LEN],
}

impl DekSlotV2 {
    /// Plan L631-L632: decode the context as its own closed canonical map,
    /// then recompute its hash. The outer and inner `slot_index` are both
    /// pinned to 0, so they are equal without a separate comparison.
    pub fn parse(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut f = Fields::decode("DekSlotV2", bytes)?;
        f.exact_text("domain", "shardx.envelope.dek-slot.v2")?;
        exact_u16(&mut f, "version", 2)?;
        exact_u16(&mut f, "slot_index", 0)?;
        let context_bytes = f.bytes(
            "canonical_dek_slot_context_bytes",
            1,
            MAX_DEK_SLOT_CONTEXT_LEN,
        )?;
        let context = DekSlotContextV2::parse(&context_bytes)?;
        let dek_slot_context_hash = f.fixed("dek_slot_context_hash")?;
        if dek_slot_context_hash != c::domain_hash(c::L_DEK_SLOT_CONTEXT, &context_bytes) {
            return Err(RecordError::BadValue("dek_slot_context_hash"));
        }
        // The context pins wrap_suite_id 1, which fixes both lengths.
        let wrap_nonce_bytes = f.fixed("wrap_nonce_bytes")?;
        let wrapped_dek_bytes = f.fixed("wrapped_dek_bytes")?;
        f.finish()?;
        Ok(Self {
            context,
            canonical_dek_slot_context_bytes: context_bytes,
            dek_slot_context_hash,
            wrap_nonce_bytes,
            wrapped_dek_bytes,
        })
    }
}

/// `EnvelopeIntentV2` of a suite 2 object (plan L637-L665).
///
/// `domain`, `version`, `preamble_version`, `final_frame_required` and the
/// five registry IDs have one valid value each and are not kept. A later
/// manifest check compares these fields one for one, and its `intent_hash`
/// with [`EnvelopeIntentV2::hash`] of the same exact bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeIntentV2 {
    pub snapshot_id: [u8; 16],
    pub tenant_id: [u8; 16],
    pub fleet_id: [u8; 16],
    pub profile_id: [u8; 16],
    pub lease_id: [u8; 16],
    pub manifest_replay_id: [u8; 16],
    pub target_version: u64,
    pub base_version: u64,
    pub fencing_token: u64,
    pub key_generation: u64,
    pub fkek_key_id: [u8; 32],
    pub frame_plaintext_size: u32,
    pub stream_nonce_prefix: [u8; STREAM_NONCE_PREFIX_LEN],
    pub max_plaintext_size: u64,
    pub max_ciphertext_size: u64,
    pub created_at_ms: u64,
    /// Omitted exactly at genesis, `base_version == 0` (plan L654).
    pub previous_signed_head_hash: Option<[u8; 32]>,
    pub intended_signer_signing_key_id: [u8; 32],
    pub server_instance_id: [u8; 16],
    pub restore_epoch: u64,
    pub dek_slot_context_hash: [u8; 32],
    pub dek_slot_sha256: [u8; 32],
}

impl EnvelopeIntentV2 {
    /// Parses exact intent bytes: canonical, closed, bounded, registry-pinned,
    /// with the version and genesis invariants of plan L645 and L654.
    pub fn parse(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut f = Fields::decode("EnvelopeIntentV2", bytes)?;
        f.exact_text("domain", "shardx.envelope.intent.v2")?;
        exact_u16(&mut f, "version", 2)?;
        let snapshot_id = f.fixed("snapshot_id")?;
        let tenant_id = f.fixed("tenant_id")?;
        let fleet_id = f.fixed("fleet_id")?;
        let profile_id = f.fixed("profile_id")?;
        let lease_id = f.fixed("lease_id")?;
        let manifest_replay_id = f.fixed("manifest_replay_id")?;
        let target_version = f.uint("target_version")?;
        let base_version = f.uint("base_version")?;
        let fencing_token = f.uint("fencing_token")?;
        let key_generation = f.uint("key_generation")?;
        let fkek_key_id = f.fixed("fkek_key_id")?;
        exact_u16(&mut f, "preamble_version", 2)?;
        registry_id(&mut f, "envelope_suite_id", SUITE_ID)?;
        registry_id(&mut f, "wrap_suite_id", WRAP_SUITE_ID_CHACHA20POLY1305)?;
        registry_id(&mut f, "archive_format_id", ARCHIVE_FORMAT_ID_TAR)?;
        registry_id(
            &mut f,
            "archive_policy_id",
            ARCHIVE_POLICY_ID_PROFILE_SNAPSHOT,
        )?;
        registry_id(&mut f, "compression_id", COMPRESSION_ID_GZIP)?;
        let frame_plaintext_size = u32::try_from(f.uint("frame_plaintext_size")?)
            .ok()
            .filter(|s| frame_size_ok(*s))
            .ok_or(RecordError::BadValue("frame_plaintext_size"))?;
        // Suite 2 pins the prefix to 20 bytes inside the plan's Bytes(1,64).
        let stream_nonce_prefix = f.fixed("stream_nonce_prefix")?;
        if f.req("final_frame_required")? != Value::Bool(true) {
            return Err(RecordError::BadValue("final_frame_required"));
        }
        let max_plaintext_size = f.uint("max_plaintext_size")?;
        let max_ciphertext_size = f.uint("max_ciphertext_size")?;
        for (name, value) in [
            ("max_plaintext_size", max_plaintext_size),
            ("max_ciphertext_size", max_ciphertext_size),
        ] {
            if !(1..=MAX_OBJECT_SIZE).contains(&value) {
                return Err(RecordError::BadValue(name));
            }
        }
        let created_at_ms = f.uint("created_at_ms")?;
        let previous_signed_head_hash = f.opt_fixed("previous_signed_head_hash")?;
        let intended_signer_signing_key_id = f.fixed("intended_signer_signing_key_id")?;
        let server_instance_id = f.fixed("server_instance_id")?;
        let restore_epoch = f.uint("restore_epoch")?;
        let dek_slot_context_hash = f.fixed("dek_slot_context_hash")?;
        let dek_slot_sha256 = f.fixed("dek_slot_sha256")?;
        f.finish()?;
        // The decoder caps every integer at i64::MAX, so this cannot overflow.
        if target_version != base_version + 1 {
            return Err(RecordError::BadValue("target_version"));
        }
        if previous_signed_head_hash.is_some() != (base_version != 0) {
            return Err(RecordError::BadValue("previous_signed_head_hash"));
        }
        Ok(Self {
            snapshot_id,
            tenant_id,
            fleet_id,
            profile_id,
            lease_id,
            manifest_replay_id,
            target_version,
            base_version,
            fencing_token,
            key_generation,
            fkek_key_id,
            frame_plaintext_size,
            stream_nonce_prefix,
            max_plaintext_size,
            max_ciphertext_size,
            created_at_ms,
            previous_signed_head_hash,
            intended_signer_signing_key_id,
            server_instance_id,
            restore_epoch,
            dek_slot_context_hash,
            dek_slot_sha256,
        })
    }

    /// `intent_hash` of exact intent bytes (plan L660-L661).
    pub fn hash(exact_intent_bytes: &[u8]) -> [u8; 32] {
        c::domain_hash(c::L_ENVELOPE_INTENT, exact_intent_bytes)
    }
}

/// The one slot, bound one for one to the intent before any unwrap (plan
/// L631-L632, L1334-L1335). `wrap_suite_id` is pinned to 1 in both maps, so
/// it is equal without a comparison.
fn bind_slot(slot_bytes: &[u8], intent: &EnvelopeIntentV2) -> Result<DekSlotV2, EnvelopeError> {
    if c::domain_hash(c::L_DEK_SLOT, slot_bytes) != intent.dek_slot_sha256 {
        return Err(EnvelopeError::Mismatch("dek_slot_sha256"));
    }
    let slot = DekSlotV2::parse(slot_bytes)?;
    let cx = &slot.context;
    for (field, equal) in [
        (
            "dek_slot_context_hash",
            slot.dek_slot_context_hash == intent.dek_slot_context_hash,
        ),
        ("snapshot_id", cx.snapshot_id == intent.snapshot_id),
        ("tenant_id", cx.tenant_id == intent.tenant_id),
        ("fleet_id", cx.fleet_id == intent.fleet_id),
        ("profile_id", cx.profile_id == intent.profile_id),
        ("fkek_key_id", cx.fkek_key_id == intent.fkek_key_id),
        ("key_generation", cx.key_generation == intent.key_generation),
    ] {
        if !equal {
            return Err(EnvelopeError::Mismatch(field));
        }
    }
    Ok(slot)
}

// ------------------------------------------------------------------- seal ----

/// What the manifest commits to about a sealed object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectDigest {
    /// Plain SHA-256 of the whole object.
    pub ciphertext_sha256: [u8; 32],
    pub ciphertext_size: u64,
    pub preamble_sha256: [u8; 32],
    pub frame_count: u32,
    pub plaintext_len: u64,
}

struct Hashing<'w, W: Write> {
    inner: &'w mut W,
    hasher: Sha256,
    len: u64,
}

impl<W: Write> Hashing<'_, W> {
    fn put(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.inner.write_all(bytes)?;
        self.hasher.update(bytes);
        self.len += bytes.len() as u64;
        Ok(())
    }
}

/// Up to `n` bytes from `r`; fewer only at end of input.
fn read_up_to(r: &mut impl Read, n: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(n);
    r.take(n as u64).read_to_end(&mut buf)?;
    Ok(buf)
}

/// Seal `input` into a suite 2 object written to `out`. The intent must come
/// from [`build_intent_v2`] for this `slot`; its frame size, nonce prefix and
/// caps are the ones used. A partial `out` on error must be discarded.
pub fn seal(
    input: &mut impl Read,
    out: &mut impl Write,
    dek: &[u8; DEK_LEN],
    intent: &IntentMaterial,
    slot: &SlotMaterial,
) -> Result<ObjectDigest, EnvelopeError> {
    if EnvelopeIntentV2::hash(&intent.exact_intent_bytes) != intent.intent_hash {
        return Err(EnvelopeError::Mismatch("intent_hash"));
    }
    let view = EnvelopeIntentV2::parse(&intent.exact_intent_bytes)?;
    bind_slot(&slot.exact_slot_bytes, &view)?;
    let len_in = |bytes: &[u8], max: u32, name| {
        u32::try_from(bytes.len())
            .ok()
            .filter(|n| (1..=max).contains(n))
            .ok_or(EnvelopeError::Malformed(name))
    };
    let preamble = Preamble {
        intent_len: len_in(&intent.exact_intent_bytes, MAX_INTENT_LEN, "intent_len")?,
        dek_slot_len: len_in(&slot.exact_slot_bytes, MAX_DEK_SLOT_LEN, "dek_slot_len")?,
        frame_plaintext_size: view.frame_plaintext_size,
        intent_sha256: intent.intent_hash,
    }
    .encode();

    let mut w = Hashing {
        inner: out,
        hasher: Sha256::new(),
        len: 0,
    };
    w.put(&preamble)?;
    w.put(&intent.exact_intent_bytes)?;
    w.put(&slot.exact_slot_bytes)?;

    let size = view.frame_plaintext_size as usize;
    let mut encryptor = Some(EncryptorLE31::<XChaCha20Poly1305>::new(
        &(*dek).into(),
        &view.stream_nonce_prefix.into(),
    ));
    let mut current = read_up_to(input, size)?;
    if current.is_empty() {
        return Err(EnvelopeError::Malformed("plaintext is empty"));
    }
    let mut counter: u32 = 0;
    let mut plaintext_len: u64 = 0;
    loop {
        // A full frame may still be the last: read ahead to know.
        let next = if current.len() == size {
            read_up_to(input, size)?
        } else {
            Vec::new()
        };
        let is_final = next.is_empty();
        plaintext_len += current.len() as u64;
        if plaintext_len > view.max_plaintext_size {
            return Err(EnvelopeError::Malformed(
                "plaintext exceeds max_plaintext_size",
            ));
        }
        let aad = frame_aad(&intent.intent_hash, counter, is_final);
        let payload = Payload {
            msg: &current,
            aad: &aad,
        };
        let ciphertext = match (is_final, encryptor.as_mut()) {
            (false, Some(e)) => e.encrypt_next(payload),
            _ => encryptor
                .take()
                .expect("the FINAL frame is sealed once")
                .encrypt_last(payload),
        }
        .map_err(|_| EnvelopeError::Aead)?;
        if w.len + FRAME_HEADER_LEN + ciphertext.len() as u64 > view.max_ciphertext_size {
            return Err(EnvelopeError::Malformed(
                "object exceeds max_ciphertext_size",
            ));
        }
        w.put(&[if is_final { KIND_FINAL } else { KIND_DATA }])?;
        w.put(&counter.to_be_bytes())?;
        w.put(&(ciphertext.len() as u32).to_be_bytes())?;
        w.put(&ciphertext)?;
        if is_final {
            break;
        }
        // Bounded: max_plaintext_size / 64 KiB frames is at most 8192.
        counter += 1;
        current = next;
    }
    w.inner.flush()?;
    Ok(ObjectDigest {
        ciphertext_sha256: w.hasher.finalize().into(),
        ciphertext_size: w.len,
        preamble_sha256: preamble_sha256(&preamble),
        frame_count: counter + 1,
        plaintext_len,
    })
}

// ------------------------------------------------------------------- open ----

/// The snapshot the manifest and upload name; the intent must name exactly
/// it before the DEK is unwrapped (plan L1335).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Scope {
    pub snapshot_id: [u8; 16],
    pub tenant_id: [u8; 16],
    pub fleet_id: [u8; 16],
    pub profile_id: [u8; 16],
    pub target_version: u64,
    pub key_generation: u64,
}

impl Scope {
    pub fn of(i: &EnvelopeIntentV2) -> Self {
        Self {
            snapshot_id: i.snapshot_id,
            tenant_id: i.tenant_id,
            fleet_id: i.fleet_id,
            profile_id: i.profile_id,
            target_version: i.target_version,
            key_generation: i.key_generation,
        }
    }

    fn first_difference(&self, other: &Self) -> Option<&'static str> {
        [
            ("snapshot_id", self.snapshot_id == other.snapshot_id),
            ("tenant_id", self.tenant_id == other.tenant_id),
            ("fleet_id", self.fleet_id == other.fleet_id),
            ("profile_id", self.profile_id == other.profile_id),
            (
                "target_version",
                self.target_version == other.target_version,
            ),
            (
                "key_generation",
                self.key_generation == other.key_generation,
            ),
        ]
        .into_iter()
        .find_map(|(field, equal)| (!equal).then_some(field))
    }
}

/// What the verified `SignedSnapshotManifestV2` says the object must be.
pub struct Expected<'a> {
    pub ciphertext_sha256: &'a [u8; 32],
    pub ciphertext_size: u64,
    pub preamble_sha256: &'a [u8; 32],
    pub intent_hash: &'a [u8; 32],
    pub dek_slot_sha256: &'a [u8; 32],
    pub scope: &'a Scope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenOutcome {
    pub frame_count: u32,
    pub plaintext_len: u64,
}

fn read_exact_or(
    r: &mut impl Read,
    buf: &mut [u8],
    rule: &'static str,
) -> Result<(), EnvelopeError> {
    r.read_exact(buf).map_err(|e| match e.kind() {
        std::io::ErrorKind::UnexpectedEof => EnvelopeError::Malformed(rule),
        _ => EnvelopeError::Io(e),
    })
}

fn read_vec(r: &mut impl Read, len: usize, rule: &'static str) -> Result<Vec<u8>, EnvelopeError> {
    let mut buf = vec![0u8; len];
    read_exact_or(r, &mut buf, rule)?;
    Ok(buf)
}

/// Open a downloaded object (ADR 0003 reader steps 3-7) into `out`.
///
/// Pass 1 hashes the whole object; pass 2 reads the same file again, never a
/// second download. Plaintext reaches `out` only after the object, preamble,
/// intent and slot all match `expected`, and the caller promotes `out` only on
/// `Ok`: a frame that fails later leaves `out` partly written, for the caller
/// to discard.
pub fn open<R: Read + Seek>(
    object: &mut R,
    out: &mut impl Write,
    fkek: &[u8; 32],
    expected: &Expected<'_>,
) -> Result<OpenOutcome, EnvelopeError> {
    // Pass 1: the exact object the manifest names, before reading any field.
    if expected.ciphertext_size > MAX_OBJECT_SIZE {
        return Err(EnvelopeError::Malformed("object exceeds the size cap"));
    }
    object.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let len = std::io::copy(
        &mut (&mut *object).take(expected.ciphertext_size + 1),
        &mut hasher,
    )?;
    if len != expected.ciphertext_size {
        return Err(EnvelopeError::Mismatch("ciphertext_size"));
    }
    if <[u8; 32]>::from(hasher.finalize()) != *expected.ciphertext_sha256 {
        return Err(EnvelopeError::Mismatch("ciphertext_sha256"));
    }

    // Pass 2.
    object.seek(SeekFrom::Start(0))?;
    let mut preamble = [0u8; PREAMBLE_LEN];
    read_exact_or(object, &mut preamble, "preamble")?;
    let pre = Preamble::parse(&preamble)?;
    if preamble_sha256(&preamble) != *expected.preamble_sha256 {
        return Err(EnvelopeError::Mismatch("preamble_sha256"));
    }
    let intent_bytes = read_vec(object, pre.intent_len as usize, "intent")?;
    let intent_hash = EnvelopeIntentV2::hash(&intent_bytes);
    if intent_hash != pre.intent_sha256 {
        return Err(EnvelopeError::Mismatch("intent_sha256"));
    }
    if intent_hash != *expected.intent_hash {
        return Err(EnvelopeError::Mismatch("intent_hash"));
    }
    let view = EnvelopeIntentV2::parse(&intent_bytes)?;
    if let Some(field) = Scope::of(&view).first_difference(expected.scope) {
        return Err(EnvelopeError::Mismatch(field));
    }
    if view.frame_plaintext_size != pre.frame_plaintext_size {
        return Err(EnvelopeError::Mismatch("frame_plaintext_size"));
    }
    if expected.ciphertext_size > view.max_ciphertext_size {
        return Err(EnvelopeError::Malformed(
            "object exceeds max_ciphertext_size",
        ));
    }
    let slot_bytes = read_vec(object, pre.dek_slot_len as usize, "dek slot")?;
    if c::domain_hash(c::L_DEK_SLOT, &slot_bytes) != *expected.dek_slot_sha256 {
        return Err(EnvelopeError::Mismatch("dek_slot_sha256"));
    }
    let slot = bind_slot(&slot_bytes, &view)?;
    let dek = unwrap_dek(
        fkek,
        &slot.wrap_nonce_bytes,
        &slot.wrapped_dek_bytes,
        &slot.canonical_dek_slot_context_bytes,
    )
    .map_err(|_| EnvelopeError::KeyUnwrap)?;

    let size = pre.frame_plaintext_size as usize;
    let max_frames = view.max_plaintext_size.div_ceil(size as u64);
    let mut decryptor = Some(DecryptorLE31::<XChaCha20Poly1305>::new(
        &(*dek).into(),
        &view.stream_nonce_prefix.into(),
    ));
    let mut counter: u32 = 0;
    let mut plaintext_len: u64 = 0;
    loop {
        let mut head = [0u8; FRAME_HEADER_LEN as usize];
        read_exact_or(object, &mut head, "missing FINAL frame")?;
        let is_final = match head[0] {
            KIND_DATA => false,
            KIND_FINAL => true,
            _ => return Err(EnvelopeError::Malformed("frame kind")),
        };
        let frame_counter = u32::from_be_bytes([head[1], head[2], head[3], head[4]]);
        if frame_counter != counter {
            return Err(EnvelopeError::Malformed("frame counter"));
        }
        if u64::from(counter) >= max_frames {
            return Err(EnvelopeError::Malformed(
                "frame counter beyond max_plaintext_size",
            ));
        }
        let ciphertext_len = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) as usize;
        if is_final && !(TAG_LEN + 1..=size + TAG_LEN).contains(&ciphertext_len) {
            return Err(EnvelopeError::Malformed("FINAL frame length"));
        }
        if !is_final && ciphertext_len != size + TAG_LEN {
            return Err(EnvelopeError::Malformed("DATA frame length"));
        }
        let ciphertext = read_vec(object, ciphertext_len, "frame ciphertext")?;
        let aad = frame_aad(&intent_hash, counter, is_final);
        let payload = Payload {
            msg: &ciphertext,
            aad: &aad,
        };
        let plaintext = Zeroizing::new(
            match (is_final, decryptor.as_mut()) {
                (false, Some(d)) => d.decrypt_next(payload),
                _ => decryptor
                    .take()
                    .expect("the FINAL frame is opened once")
                    .decrypt_last(payload),
            }
            .map_err(|_| EnvelopeError::Aead)?,
        );
        plaintext_len += plaintext.len() as u64;
        if plaintext_len > view.max_plaintext_size {
            return Err(EnvelopeError::Malformed(
                "plaintext exceeds max_plaintext_size",
            ));
        }
        out.write_all(&plaintext)?;
        if is_final {
            break;
        }
        counter += 1;
    }
    // Anything after FINAL, a DATA frame included, is refused.
    if object.read(&mut [0u8; 1])? != 0 {
        return Err(EnvelopeError::Malformed("bytes after the FINAL frame"));
    }
    out.flush()?;
    Ok(OpenOutcome {
        frame_count: counter + 1,
        plaintext_len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{build_dek_slot, build_envelope_intent, SlotIds};
    use aead_stream::{NewStream, StreamLE31, StreamPrimitive};
    use chacha20poly1305::aead::{Aead, KeyInit};
    use std::io::Cursor;

    const FRAME: u32 = MIN_FRAME_PLAINTEXT_SIZE;
    const FKEK: [u8; 32] = [0x11; 32];
    const DEK: [u8; 32] = [0x22; 32];
    const PREFIX: [u8; STREAM_NONCE_PREFIX_LEN] = [0x44; STREAM_NONCE_PREFIX_LEN];

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    struct Fixture {
        slot: SlotMaterial,
        intent: IntentMaterial,
    }

    fn ids() -> IntentIds {
        IntentIds {
            snapshot_id: [4; 16],
            tenant_id: [1; 16],
            fleet_id: [2; 16],
            profile_id: [3; 16],
            lease_id: [7; 16],
            manifest_replay_id: [8; 16],
            server_instance_id: [9; 16],
            fkek_key_id: [5; 32],
            intended_signer_signing_key_id: [10; 32],
        }
    }

    fn nums(frame: u32, max_plaintext_size: u64) -> IntentNumbers {
        IntentNumbers {
            target_version: 1,
            base_version: 0,
            fencing_token: 1,
            key_generation: 1,
            restore_epoch: 0,
            frame_plaintext_size: frame,
            max_plaintext_size,
            max_ciphertext_size: MAX_OBJECT_SIZE,
            created_at_ms: 1_767_225_600_000,
        }
    }

    fn slot() -> SlotMaterial {
        build_dek_slot(
            &FKEK,
            &DEK,
            &[0x33; WRAP_NONCE_LEN],
            &SlotIds {
                tenant_id: &[1; 16],
                fleet_id: &[2; 16],
                profile_id: &[3; 16],
                snapshot_id: &[4; 16],
                fkek_key_id: &[5; 32],
                envelope_context_nonce: &[6; 16],
            },
            1,
        )
        .unwrap()
    }

    fn fixture_with(max_plaintext_size: u64) -> Fixture {
        let slot = slot();
        let intent = build_intent_v2(
            &ids(),
            &nums(FRAME, max_plaintext_size),
            &PREFIX,
            None,
            &slot,
        )
        .unwrap();
        Fixture { slot, intent }
    }

    fn fixture() -> Fixture {
        fixture_with(MAX_OBJECT_SIZE)
    }

    fn plaintext(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 31 + 7) as u8).collect()
    }

    fn seal_vec(f: &Fixture, pt: &[u8]) -> (Vec<u8>, ObjectDigest) {
        let mut out = Vec::new();
        let digest = seal(&mut Cursor::new(pt), &mut out, &DEK, &f.intent, &f.slot).unwrap();
        (out, digest)
    }

    /// The manifest fields for `object` as it is, so a crafted object gets
    /// past pass 1 and the rule under test is the one that fires.
    struct Exp {
        sha: [u8; 32],
        size: u64,
        pre: [u8; 32],
        intent: [u8; 32],
        slot: [u8; 32],
        scope: Scope,
    }

    /// The scope `intent` names, or none when it does not parse (the parse
    /// refusal then fires first).
    fn scope_of(intent: &[u8]) -> Scope {
        EnvelopeIntentV2::parse(intent)
            .map(|i| Scope::of(&i))
            .unwrap_or_default()
    }

    fn exp_for(f: &Fixture, object: &[u8]) -> Exp {
        Exp {
            sha: c::sha256(object),
            size: object.len() as u64,
            pre: preamble_sha256(object[..PREAMBLE_LEN].try_into().unwrap()),
            intent: f.intent.intent_hash,
            slot: f.slot.dek_slot_sha256,
            scope: scope_of(&f.intent.exact_intent_bytes),
        }
    }

    fn open_with(
        object: &[u8],
        fkek: &[u8; 32],
        e: &Exp,
    ) -> (Result<OpenOutcome, EnvelopeError>, Vec<u8>) {
        let mut out = Vec::new();
        let result = open(
            &mut Cursor::new(object),
            &mut out,
            fkek,
            &Expected {
                ciphertext_sha256: &e.sha,
                ciphertext_size: e.size,
                preamble_sha256: &e.pre,
                intent_hash: &e.intent,
                dek_slot_sha256: &e.slot,
                scope: &e.scope,
            },
        );
        (result, out)
    }

    fn rule_of(r: Result<OpenOutcome, EnvelopeError>) -> String {
        match r {
            Err(EnvelopeError::Malformed(s)) => format!("malformed {s}"),
            Err(EnvelopeError::Mismatch(s)) => format!("mismatch {s}"),
            other => format!("{other:?}"),
        }
    }

    // ------------------------------------------------------- provider ----

    /// draft-irtf-cfrg-xchacha-03, A.3.1 (AEAD_XChaCha20_Poly1305).
    #[test]
    fn xchacha20poly1305_matches_the_draft_vector() {
        let pt = unhex(concat!(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c6173",
            "73206f66202739393a204966204920636f756c64206f6666657220796f75206f",
            "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73",
            "637265656e20776f756c642062652069742e"
        ));
        let aad = unhex("50515253c0c1c2c3c4c5c6c7");
        let key: [u8; 32] =
            unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
                .try_into()
                .unwrap();
        let nonce: [u8; 24] = unhex("404142434445464748494a4b4c4d4e4f5051525354555657")
            .try_into()
            .unwrap();
        let ct = XChaCha20Poly1305::new(&key.into())
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: &pt,
                    aad: &aad,
                },
            )
            .unwrap();
        assert_eq!(
            hex(&ct),
            concat!(
                "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb",
                "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452",
                "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9",
                "21f9664c97637da9768812f615c68b13b52e",
                "c0875924c1c7987947deafd8780acf49"
            )
        );
    }

    /// Frame records of a sealed object: (kind, counter, ciphertext).
    fn frames(f: &Fixture, object: &[u8]) -> Vec<(u8, u32, Vec<u8>)> {
        let mut at =
            PREAMBLE_LEN + f.intent.exact_intent_bytes.len() + f.slot.exact_slot_bytes.len();
        let mut out = Vec::new();
        while at < object.len() {
            let len = u32::from_be_bytes(object[at + 5..at + 9].try_into().unwrap()) as usize;
            let counter = u32::from_be_bytes(object[at + 1..at + 5].try_into().unwrap());
            out.push((object[at], counter, object[at + 9..at + 9 + len].to_vec()));
            at += 9 + len;
        }
        out
    }

    /// Each frame opens with a raw XChaCha20-Poly1305 under the 24-byte nonce
    /// prefix ‖ u32le(position | last << 31): the provider does nothing else.
    #[test]
    fn each_frame_opens_with_raw_xchacha_and_the_le31_nonce() {
        let f = fixture();
        let pt = plaintext(2 * FRAME as usize + 1);
        let (object, _) = seal_vec(&f, &pt);
        let fr = frames(&f, &object);
        assert_eq!(fr.len(), 3);
        let aead = XChaCha20Poly1305::new(&DEK.into());
        let tails = ["00000000", "01000000", "02000080"];
        for (i, (kind, counter, ct)) in fr.iter().enumerate() {
            let last = i == 2;
            assert_eq!((*kind, *counter), (u8::from(last), i as u32));
            let nonce: [u8; 24] = [PREFIX.as_slice(), &unhex(tails[i])]
                .concat()
                .try_into()
                .unwrap();
            let aad = frame_aad(&f.intent.intent_hash, i as u32, last);
            assert_eq!(
                aad.len(),
                62,
                "label 25 + intent hash 32 + counter 4 + kind 1"
            );
            let opened = aead
                .decrypt(&nonce.into(), Payload { msg: ct, aad: &aad })
                .unwrap();
            let start = i * FRAME as usize;
            assert_eq!(opened, pt[start..(start + FRAME as usize).min(pt.len())]);
        }
        // FINAL at position 0 sets the top bit of the same counter word.
        let p = StreamLE31::<XChaCha20Poly1305>::new(&DEK.into(), &PREFIX.into());
        let aad = frame_aad(&f.intent.intent_hash, 0, true);
        let ct = p
            .encrypt(
                0,
                true,
                Payload {
                    msg: b"x",
                    aad: &aad,
                },
            )
            .unwrap();
        let nonce: [u8; 24] = [PREFIX.as_slice(), &unhex("00000080")]
            .concat()
            .try_into()
            .unwrap();
        assert_eq!(
            aead.decrypt(
                &nonce.into(),
                Payload {
                    msg: &ct,
                    aad: &aad
                }
            )
            .unwrap(),
            b"x"
        );
    }

    /// The provider refuses a position past its counter maximum, 0x7fff_ffff.
    #[test]
    fn the_stream_counter_stops_at_the_provider_maximum() {
        let p = StreamLE31::<XChaCha20Poly1305>::new(&DEK.into(), &PREFIX.into());
        let msg = Payload {
            msg: b"x",
            aad: b"",
        };
        assert!(p.encrypt(0x7fff_ffff, true, msg).is_ok());
        let msg = Payload {
            msg: b"x",
            aad: b"",
        };
        assert!(p.encrypt(0x8000_0000, false, msg).is_err());
    }

    // ------------------------------------------------------ round trip ----

    #[test]
    fn objects_round_trip_at_the_frame_boundaries() {
        let f = fixture();
        for (n, frames_expected, final_len) in [
            (1usize, 1u32, 1usize),
            (FRAME as usize + 1, 2, 1),
            (2 * FRAME as usize, 2, FRAME as usize),
        ] {
            let pt = plaintext(n);
            let (object, digest) = seal_vec(&f, &pt);
            assert_eq!(digest.frame_count, frames_expected);
            assert_eq!(digest.plaintext_len, n as u64);
            assert_eq!(digest.ciphertext_size, object.len() as u64);
            let last = frames(&f, &object).pop().unwrap();
            assert_eq!(last.0, KIND_FINAL);
            assert_eq!(
                last.2.len(),
                final_len + TAG_LEN,
                "a full multiple ends in a full FINAL"
            );
            let (r, out) = open_with(&object, &FKEK, &exp_for(&f, &object));
            assert_eq!(
                r.unwrap(),
                OpenOutcome {
                    frame_count: frames_expected,
                    plaintext_len: n as u64
                }
            );
            assert_eq!(out, pt);
        }
    }

    /// Pinned bytes: a change to any field, hash or provider shows here.
    #[test]
    fn golden_objects() {
        let f = fixture();
        let (one, d1) = seal_vec(&f, &plaintext(1));
        assert_eq!(hex(&one[..PREAMBLE_LEN]), GOLDEN_PREAMBLE_P1);
        assert_eq!(hex(&d1.preamble_sha256), GOLDEN_PREAMBLE_SHA256_P1);
        assert_eq!(hex(&f.intent.intent_hash), GOLDEN_INTENT_HASH);
        assert_eq!(hex(&f.slot.dek_slot_sha256), GOLDEN_DEK_SLOT_SHA256);
        for (n, want) in [
            (1usize, GOLDEN_OBJECT_SHA256_P1),
            (FRAME as usize + 1, GOLDEN_OBJECT_SHA256_FRAME_PLUS_1),
            (2 * FRAME as usize, GOLDEN_OBJECT_SHA256_2_FRAMES),
        ] {
            let (object, d) = seal_vec(&f, &plaintext(n));
            assert_eq!(hex(&d.ciphertext_sha256), want, "P = {n}");
            assert_eq!(d.ciphertext_sha256, c::sha256(&object));
        }
    }

    const GOLDEN_PREAMBLE_P1: &str = "534841524458424b00020040000200000000032e0000021e00010000000000003a0cbba1f2ad7f10f16e869b52a439a830c68bda8d25d17e99f00ce5c1f0d6df";
    const GOLDEN_PREAMBLE_SHA256_P1: &str =
        "4fc72d4836d4506d40c894c96ef19bda7aa21f217ffdbb2201de5b5d32017edb";
    const GOLDEN_INTENT_HASH: &str =
        "3a0cbba1f2ad7f10f16e869b52a439a830c68bda8d25d17e99f00ce5c1f0d6df";
    const GOLDEN_DEK_SLOT_SHA256: &str =
        "156c33ac75533be0d70328ea884ce422e18ce29a6165dc90f4decee30e6aa41d";
    const GOLDEN_OBJECT_SHA256_P1: &str =
        "c96edaa56252f2cc8922841e37776bce0e5ad100c2a9c20f8329d805e0f2bdf2";
    const GOLDEN_OBJECT_SHA256_FRAME_PLUS_1: &str =
        "1d151c4bd393a45ad410838ed3ca263502c8056d5976ab8eb6b0b3b6e25c7d46";
    const GOLDEN_OBJECT_SHA256_2_FRAMES: &str =
        "0db47c8466c8c370eb3c340b777a65b8434148e1de6441c84d89fb1888eb8fdc";

    // --------------------------------------------------- the preamble ----

    #[test]
    fn every_preamble_rule_is_enforced() {
        let f = fixture();
        let (good, _) = seal_vec(&f, &plaintext(10));
        let set = |at: usize, bytes: &[u8]| {
            let mut o = good.clone();
            o[at..at + bytes.len()].copy_from_slice(bytes);
            o
        };
        let cases: Vec<(&str, Vec<u8>, &str)> = vec![
            ("legacy magic", set(0, b"SHRDXBK2"), "malformed magic"),
            (
                "version 1",
                set(8, &1u16.to_be_bytes()),
                "malformed envelope_version",
            ),
            (
                "length 63",
                set(10, &63u16.to_be_bytes()),
                "malformed preamble_length",
            ),
            (
                "suite 1",
                set(12, &1u16.to_be_bytes()),
                "malformed suite_id",
            ),
            (
                "suite 3",
                set(12, &3u16.to_be_bytes()),
                "malformed suite_id",
            ),
            (
                "flag bit 0",
                set(14, &1u16.to_be_bytes()),
                "malformed flags",
            ),
            (
                "flag bit 15",
                set(14, &0x8000u16.to_be_bytes()),
                "malformed flags",
            ),
            (
                "reserved 1",
                set(28, &1u32.to_be_bytes()),
                "malformed reserved",
            ),
            (
                "intent_len 0",
                set(16, &0u32.to_be_bytes()),
                "malformed intent_len",
            ),
            (
                "intent_len 65537",
                set(16, &65_537u32.to_be_bytes()),
                "malformed intent_len",
            ),
            (
                "dek_slot_len 0",
                set(20, &0u32.to_be_bytes()),
                "malformed dek_slot_len",
            ),
            (
                "dek_slot_len 16385",
                set(20, &16_385u32.to_be_bytes()),
                "malformed dek_slot_len",
            ),
            (
                "frame below range",
                set(24, &65_535u32.to_be_bytes()),
                "malformed frame_plaintext_size",
            ),
            (
                "frame above range",
                set(24, &4_194_305u32.to_be_bytes()),
                "malformed frame_plaintext_size",
            ),
            (
                "frame disagrees with intent",
                set(24, &131_072u32.to_be_bytes()),
                "mismatch frame_plaintext_size",
            ),
            (
                "intent_sha256 flip",
                set(40, &[good[40] ^ 1]),
                "mismatch intent_sha256",
            ),
        ];
        for (name, object, want) in cases {
            let (r, out) = open_with(&object, &FKEK, &exp_for(&f, &object));
            assert_eq!(rule_of(r), want, "{name}");
            assert!(out.is_empty(), "{name}: no plaintext");
        }
        // A preamble the manifest did not commit to.
        let mut e = exp_for(&f, &good);
        e.pre[0] ^= 1;
        assert_eq!(
            rule_of(open_with(&good, &FKEK, &e).0),
            "mismatch preamble_sha256"
        );
    }

    // ----------------------------------------------------- the frames ----

    /// An object with this fixture's prologue and the given frame records,
    /// each sealed at STREAM `position` with `last`, under the AAD of
    /// (`counter`, `kind == FINAL`), unless the plaintext is `None` (raw
    /// ciphertext bytes then) or the length is overridden.
    struct Rec {
        kind: u8,
        counter: u32,
        position: u32,
        last: bool,
        pt: Vec<u8>,
        len: Option<u32>,
    }

    fn rec(kind: u8, counter: u32, pt: Vec<u8>) -> Rec {
        Rec {
            kind,
            counter,
            position: counter,
            last: kind == KIND_FINAL,
            pt,
            len: None,
        }
    }

    fn crafted(f: &Fixture, recs: &[Rec]) -> Vec<u8> {
        let (good, _) = seal_vec(f, &plaintext(1));
        let prologue =
            PREAMBLE_LEN + f.intent.exact_intent_bytes.len() + f.slot.exact_slot_bytes.len();
        let mut o = good[..prologue].to_vec();
        let p = StreamLE31::<XChaCha20Poly1305>::new(&DEK.into(), &PREFIX.into());
        for r in recs {
            let aad = frame_aad(&f.intent.intent_hash, r.counter, r.kind == KIND_FINAL);
            let ct = p
                .encrypt(
                    r.position,
                    r.last,
                    Payload {
                        msg: &r.pt,
                        aad: &aad,
                    },
                )
                .unwrap();
            o.push(r.kind);
            o.extend_from_slice(&r.counter.to_be_bytes());
            o.extend_from_slice(&r.len.unwrap_or(ct.len() as u32).to_be_bytes());
            o.extend_from_slice(&ct);
        }
        o
    }

    #[test]
    fn every_frame_rule_is_enforced() {
        let f = fixture();
        let full = || plaintext(FRAME as usize);
        let cases: Vec<(&str, Vec<Rec>, &str)> = vec![
            (
                "kind 2",
                vec![rec(2, 0, plaintext(5))],
                "malformed frame kind",
            ),
            (
                "counter starts at 1",
                vec![rec(KIND_FINAL, 1, plaintext(5))],
                "malformed frame counter",
            ),
            (
                "counter skipped",
                vec![rec(KIND_DATA, 0, full()), rec(KIND_FINAL, 2, plaintext(5))],
                "malformed frame counter",
            ),
            (
                "counter repeated",
                vec![rec(KIND_DATA, 0, full()), rec(KIND_FINAL, 0, plaintext(5))],
                "malformed frame counter",
            ),
            (
                "counter at the provider maximum",
                vec![rec(KIND_FINAL, 0x7fff_ffff, plaintext(5))],
                "malformed frame counter",
            ),
            (
                "DATA after FINAL",
                vec![rec(KIND_FINAL, 0, plaintext(5)), rec(KIND_DATA, 1, full())],
                "malformed bytes after the FINAL frame",
            ),
            (
                "missing FINAL",
                vec![rec(KIND_DATA, 0, full())],
                "malformed missing FINAL frame",
            ),
            (
                "empty FINAL",
                vec![rec(KIND_FINAL, 0, Vec::new())],
                "malformed FINAL frame length",
            ),
            (
                "short DATA",
                vec![
                    rec(KIND_DATA, 0, plaintext(FRAME as usize - 1)),
                    rec(KIND_FINAL, 1, plaintext(5)),
                ],
                "malformed DATA frame length",
            ),
            (
                "oversized ciphertext_len",
                vec![Rec {
                    len: Some(FRAME + TAG_LEN as u32 + 1),
                    ..rec(KIND_FINAL, 0, plaintext(5))
                }],
                "malformed FINAL frame length",
            ),
            (
                "DATA sealed as last",
                vec![
                    Rec {
                        last: true,
                        ..rec(KIND_DATA, 0, full())
                    },
                    rec(KIND_FINAL, 1, plaintext(5)),
                ],
                "Err(Aead)",
            ),
            (
                "frame from another position",
                vec![Rec {
                    position: 3,
                    ..rec(KIND_FINAL, 0, plaintext(5))
                }],
                "Err(Aead)",
            ),
        ];
        for (name, recs, want) in cases {
            let object = crafted(&f, &recs);
            let (r, _) = open_with(&object, &FKEK, &exp_for(&f, &object));
            assert_eq!(rule_of(r), want, "{name}");
        }

        // A trailing byte after a valid FINAL.
        let mut object = crafted(&f, &[rec(KIND_FINAL, 0, plaintext(5))]);
        object.push(0);
        let (r, _) = open_with(&object, &FKEK, &exp_for(&f, &object));
        assert_eq!(rule_of(r), "malformed bytes after the FINAL frame");

        // The intent caps the frame count before any AEAD call.
        let small = fixture_with(FRAME as u64);
        let object = crafted(
            &small,
            &[rec(KIND_DATA, 0, full()), rec(KIND_FINAL, 1, plaintext(5))],
        );
        let (r, _) = open_with(&object, &FKEK, &exp_for(&small, &object));
        assert_eq!(
            rule_of(r),
            "malformed frame counter beyond max_plaintext_size"
        );

        // One flipped ciphertext bit.
        let (mut object, _) = seal_vec(&f, &plaintext(10));
        *object.last_mut().unwrap() ^= 1;
        let (r, _) = open_with(&object, &FKEK, &exp_for(&f, &object));
        assert_eq!(rule_of(r), "Err(Aead)");
    }

    // ----------------------------------------- object and release order ----

    /// Flip the last byte: refused on the object hash, before the preamble is
    /// read or the DEK unwrapped (a wrong FKEK is not even reported), and no
    /// byte reaches staging.
    #[test]
    fn nothing_is_read_or_written_before_the_object_hash_matches() {
        let f = fixture();
        let (good, d) = seal_vec(&f, &plaintext(FRAME as usize + 1));
        let e = exp_for(&f, &good);
        assert_eq!(e.sha, d.ciphertext_sha256);
        let mut flipped = good.clone();
        *flipped.last_mut().unwrap() ^= 1;
        for fkek in [FKEK, [0x99; 32]] {
            let (r, out) = open_with(&flipped, &fkek, &e);
            assert_eq!(rule_of(r), "mismatch ciphertext_sha256");
            assert!(out.is_empty());
        }
        let mut longer = good.clone();
        longer.push(0);
        assert_eq!(
            rule_of(open_with(&longer, &FKEK, &e).0),
            "mismatch ciphertext_size"
        );
        assert_eq!(
            rule_of(open_with(&good[..good.len() - 1], &FKEK, &e).0),
            "mismatch ciphertext_size"
        );
        let too_big = Exp {
            size: MAX_OBJECT_SIZE + 1,
            ..exp_for(&f, &good)
        };
        assert_eq!(
            rule_of(open_with(&good, &FKEK, &too_big).0),
            "malformed object exceeds the size cap"
        );
        // The intent must name exactly the snapshot the manifest names.
        let named = exp_for(&f, &good).scope;
        for (field, scope) in [
            (
                "snapshot_id",
                Scope {
                    snapshot_id: [0xee; 16],
                    ..named
                },
            ),
            (
                "tenant_id",
                Scope {
                    tenant_id: [0xee; 16],
                    ..named
                },
            ),
            (
                "fleet_id",
                Scope {
                    fleet_id: [0xee; 16],
                    ..named
                },
            ),
            (
                "profile_id",
                Scope {
                    profile_id: [0xee; 16],
                    ..named
                },
            ),
            (
                "target_version",
                Scope {
                    target_version: named.target_version + 1,
                    ..named
                },
            ),
            (
                "key_generation",
                Scope {
                    key_generation: named.key_generation + 1,
                    ..named
                },
            ),
        ] {
            let e = Exp {
                scope,
                ..exp_for(&f, &good)
            };
            let (result, out) = open_with(&good, &FKEK, &e);
            assert_eq!(rule_of(result), format!("mismatch {field}"));
            assert!(out.is_empty());
        }
    }

    #[test]
    fn the_intent_and_slot_must_be_the_ones_the_manifest_names() {
        let f = fixture();
        let (good, _) = seal_vec(&f, &plaintext(10));
        let mut e = exp_for(&f, &good);
        e.intent[0] ^= 1;
        assert_eq!(
            rule_of(open_with(&good, &FKEK, &e).0),
            "mismatch intent_hash"
        );
        let mut e = exp_for(&f, &good);
        e.slot[0] ^= 1;
        assert_eq!(
            rule_of(open_with(&good, &FKEK, &e).0),
            "mismatch dek_slot_sha256"
        );
        let (r, out) = open_with(&good, &[0x99; 32], &exp_for(&f, &good));
        assert_eq!(rule_of(r), "Err(KeyUnwrap)");
        assert!(out.is_empty());
    }

    // ------------------------------------------------------- the writer ----

    #[test]
    fn the_intent_bounds_are_the_plans() {
        let s = slot();
        for (frame, max, field) in [
            (65_535, MAX_OBJECT_SIZE, "frame_plaintext_size"),
            (4_194_305, MAX_OBJECT_SIZE, "frame_plaintext_size"),
            (FRAME, 0, "max_plaintext_size"),
            (FRAME, MAX_OBJECT_SIZE + 1, "max_plaintext_size"),
        ] {
            let r = build_intent_v2(&ids(), &nums(frame, max), &PREFIX, None, &s);
            assert_eq!(r.err(), Some(IntentError::OutOfBounds(field)));
        }
        assert!(build_intent_v2(
            &ids(),
            &nums(DEFAULT_FRAME_PLAINTEXT_SIZE, 1),
            &PREFIX,
            None,
            &s
        )
        .is_ok());
    }

    #[test]
    fn the_writer_refuses_what_a_reader_would() {
        let f = fixture();
        let mut out = Vec::new();
        let r = seal(
            &mut Cursor::new(Vec::new()),
            &mut out,
            &DEK,
            &f.intent,
            &f.slot,
        );
        assert!(matches!(
            r,
            Err(EnvelopeError::Malformed("plaintext is empty"))
        ));

        // An intent whose hash is stale would seal an object nobody can open.
        let stale = IntentMaterial {
            exact_intent_bytes: f.intent.exact_intent_bytes.clone(),
            intent_hash: [0x5a; 32],
        };
        let r = seal(
            &mut Cursor::new(plaintext(10)),
            &mut Vec::new(),
            &DEK,
            &stale,
            &f.slot,
        );
        assert!(matches!(r, Err(EnvelopeError::Mismatch("intent_hash"))));

        // A suite 1 intent (the shipped body) never goes into a SHARDXBK object.
        let legacy = build_envelope_intent(
            &ids(),
            &nums(FRAME, MAX_OBJECT_SIZE),
            &[0x44; 7],
            None,
            &f.slot,
        )
        .unwrap();
        let r = seal(
            &mut Cursor::new(plaintext(5)),
            &mut Vec::new(),
            &DEK,
            &legacy,
            &f.slot,
        );
        assert!(matches!(
            r,
            Err(EnvelopeError::Record(RecordError::Unsupported {
                field: "envelope_suite_id",
                id: 1
            }))
        ));

        // Over the intent's plaintext cap.
        let small = fixture_with(FRAME as u64);
        let r = seal(
            &mut Cursor::new(plaintext(FRAME as usize + 1)),
            &mut Vec::new(),
            &DEK,
            &small.intent,
            &small.slot,
        );
        assert!(matches!(
            r,
            Err(EnvelopeError::Malformed(
                "plaintext exceeds max_plaintext_size"
            ))
        ));

        // A slot that is not the intent's.
        let other = build_dek_slot(
            &FKEK,
            &DEK,
            &[0x34; WRAP_NONCE_LEN],
            &SlotIds {
                tenant_id: &[1; 16],
                fleet_id: &[2; 16],
                profile_id: &[3; 16],
                snapshot_id: &[4; 16],
                fkek_key_id: &[5; 32],
                envelope_context_nonce: &[6; 16],
            },
            1,
        )
        .unwrap();
        let r = seal(
            &mut Cursor::new(plaintext(5)),
            &mut Vec::new(),
            &DEK,
            &f.intent,
            &other,
        );
        assert!(matches!(r, Err(EnvelopeError::Mismatch("dek_slot_sha256"))));
    }

    // ---------------------------------------------------- closed maps ----

    /// `bytes` decoded, edited as a map and re-encoded canonically.
    fn edit(bytes: &[u8], change: impl FnOnce(&mut Vec<(String, Value)>)) -> Vec<u8> {
        let Value::Map(mut entries) = c::decode(bytes).unwrap() else {
            panic!("not a map")
        };
        change(&mut entries);
        c::encode(&Value::Map(entries))
    }

    fn set(bytes: &[u8], name: &str, value: Value) -> Vec<u8> {
        edit(bytes, |e| {
            e.iter_mut().find(|(k, _)| k == name).expect("field").1 = value;
        })
    }

    fn versioned_intent(slot: &SlotMaterial) -> IntentMaterial {
        let mut n = nums(FRAME, MAX_OBJECT_SIZE);
        n.base_version = 4;
        n.target_version = 5;
        build_intent_v2(&ids(), &n, &PREFIX, Some(&[0x55; 32]), slot).unwrap()
    }

    /// Every field missing in turn, an unknown and a duplicate field, and an
    /// overlong `version`: the rules every closed canonical map shares.
    fn closed_map_rules<T: std::fmt::Debug>(
        map: &'static str,
        good: &[u8],
        parse: fn(&[u8]) -> Result<T, RecordError>,
    ) {
        parse(good).unwrap();
        let Value::Map(entries) = c::decode(good).unwrap() else {
            panic!("not a map")
        };
        for (name, _) in &entries {
            let r = parse(&edit(good, |e| e.retain(|(k, _)| k != name)));
            assert!(
                matches!(&r, Err(RecordError::MissingField { map: m, field }) if *m == map && field == name),
                "{map} without {name}: {r:?}"
            );
        }
        let extra = edit(good, |e| e.push(("extra".into(), c::u(0))));
        assert_eq!(
            parse(&extra).err(),
            Some(RecordError::UnknownField {
                map,
                field: "extra".into()
            })
        );
        // The encoder merges equal keys, so the repeat is spliced in by hand.
        let count = |n: usize| -> Vec<u8> {
            if n < 24 {
                vec![0xa0 | n as u8]
            } else {
                vec![0xb8, n as u8]
            }
        };
        let (k, v) = &entries[0];
        let mut twice = count(entries.len() + 1);
        twice.extend(c::encode(&c::t(k)));
        twice.extend(c::encode(v));
        twice.extend_from_slice(&good[count(entries.len()).len()..]);
        assert_eq!(
            parse(&twice).err(),
            Some(RecordError::Cbor(c::CborError::DuplicateKey(
                entries[0].0.clone()
            )))
        );
        let key: Vec<u8> = [&[0x67u8][..], b"version", &[0x02]].concat();
        let at = good
            .windows(key.len())
            .position(|w| w == key)
            .expect("version");
        let mut overlong = good[..at + 8].to_vec();
        overlong.extend_from_slice(&[0x18, 0x02]);
        overlong.extend_from_slice(&good[at + 9..]);
        assert_eq!(
            parse(&overlong).err(),
            Some(RecordError::Cbor(c::CborError::OverlongInteger))
        );
    }

    fn bad_field(map: &'static str, field: &'static str) -> Option<RecordError> {
        Some(RecordError::BadField { map, field })
    }

    fn unsupported(field: &'static str, id: u64) -> Option<RecordError> {
        Some(RecordError::Unsupported { field, id })
    }

    #[test]
    fn the_closed_maps_parse_what_the_builders_write() {
        let f = fixture();
        let cx = DekSlotContextV2::parse(&f.slot.context_bytes).unwrap();
        assert_eq!(
            cx,
            DekSlotContextV2 {
                snapshot_id: [4; 16],
                tenant_id: [1; 16],
                fleet_id: [2; 16],
                profile_id: [3; 16],
                fkek_key_id: [5; 32],
                key_generation: 1,
                envelope_context_nonce: [6; 16],
            }
        );
        let s = DekSlotV2::parse(&f.slot.exact_slot_bytes).unwrap();
        assert_eq!(s.context, cx);
        assert_eq!(s.canonical_dek_slot_context_bytes, f.slot.context_bytes);
        assert_eq!(s.dek_slot_context_hash, f.slot.context_hash);
        assert_eq!(s.wrap_nonce_bytes, [0x33; WRAP_NONCE_LEN]);
        let dek = unwrap_dek(
            &FKEK,
            &s.wrap_nonce_bytes,
            &s.wrapped_dek_bytes,
            &s.canonical_dek_slot_context_bytes,
        )
        .unwrap();
        assert_eq!(*dek, DEK);

        let i = EnvelopeIntentV2::parse(&f.intent.exact_intent_bytes).unwrap();
        assert_eq!(
            i,
            EnvelopeIntentV2 {
                snapshot_id: [4; 16],
                tenant_id: [1; 16],
                fleet_id: [2; 16],
                profile_id: [3; 16],
                lease_id: [7; 16],
                manifest_replay_id: [8; 16],
                target_version: 1,
                base_version: 0,
                fencing_token: 1,
                key_generation: 1,
                fkek_key_id: [5; 32],
                frame_plaintext_size: FRAME,
                stream_nonce_prefix: PREFIX,
                max_plaintext_size: MAX_OBJECT_SIZE,
                max_ciphertext_size: MAX_OBJECT_SIZE,
                created_at_ms: 1_767_225_600_000,
                previous_signed_head_hash: None,
                intended_signer_signing_key_id: [10; 32],
                server_instance_id: [9; 16],
                restore_epoch: 0,
                dek_slot_context_hash: f.slot.context_hash,
                dek_slot_sha256: f.slot.dek_slot_sha256,
            }
        );
        assert_eq!(
            EnvelopeIntentV2::hash(&f.intent.exact_intent_bytes),
            f.intent.intent_hash
        );
        let v = EnvelopeIntentV2::parse(&versioned_intent(&f.slot).exact_intent_bytes).unwrap();
        assert_eq!(
            (
                v.base_version,
                v.target_version,
                v.previous_signed_head_hash
            ),
            (4, 5, Some([0x55; 32]))
        );
    }

    #[test]
    fn every_dek_slot_context_rule_is_enforced() {
        const M: &str = "DekSlotContextV2";
        let good = slot().context_bytes;
        closed_map_rules(M, &good, DekSlotContextV2::parse);
        let p = |b: Vec<u8>| DekSlotContextV2::parse(&b).err();
        assert_eq!(
            p(set(&good, "domain", c::t("shardx.envelope.dek-slot.v2"))),
            Some(RecordError::BadValue("domain"))
        );
        assert_eq!(p(set(&good, "domain", c::u(0))), bad_field(M, "domain"));
        assert_eq!(
            p(set(&good, "version", c::u(3))),
            Some(RecordError::BadValue("version"))
        );
        assert_eq!(
            p(set(&good, "version", c::u(65_538))),
            bad_field(M, "version")
        );
        assert_eq!(
            p(set(&good, "slot_index", c::u(1))),
            Some(RecordError::BadValue("slot_index"))
        );
        assert_eq!(
            p(set(&good, "wrap_suite_id", c::u(2))),
            unsupported("wrap_suite_id", 2)
        );
        for (name, len) in [
            ("snapshot_id", 16),
            ("tenant_id", 16),
            ("fleet_id", 16),
            ("profile_id", 16),
            ("fkek_key_id", 32),
            ("envelope_context_nonce", 16),
        ] {
            for wrong in [len - 1, len + 1] {
                assert_eq!(
                    p(set(&good, name, c::b(&vec![0; wrong]))),
                    bad_field(M, name)
                );
            }
            assert_eq!(p(set(&good, name, c::u(0))), bad_field(M, name));
        }
        assert_eq!(
            p(set(&good, "key_generation", c::u(1 << 63))),
            Some(RecordError::Cbor(c::CborError::IntegerOutOfSqliteDomain(
                1 << 63
            )))
        );
        let top = DekSlotContextV2::parse(&set(&good, "key_generation", c::u(i64::MAX as u64)));
        assert_eq!(top.unwrap().key_generation, i64::MAX as u64);
    }

    /// A slot whose stored context hash is recomputed for `context`.
    fn slot_around(context: &[u8]) -> Vec<u8> {
        let s = set(
            &slot().exact_slot_bytes,
            "canonical_dek_slot_context_bytes",
            c::b(context),
        );
        set(
            &s,
            "dek_slot_context_hash",
            c::b(&c::domain_hash(c::L_DEK_SLOT_CONTEXT, context)),
        )
    }

    #[test]
    fn every_dek_slot_rule_is_enforced() {
        const M: &str = "DekSlotV2";
        const CX: &str = "canonical_dek_slot_context_bytes";
        let good = slot().exact_slot_bytes;
        closed_map_rules(M, &good, DekSlotV2::parse);
        let p = |b: Vec<u8>| DekSlotV2::parse(&b).err();
        assert_eq!(
            p(set(
                &good,
                "domain",
                c::t("shardx.envelope.dek-slot-context.v2")
            )),
            Some(RecordError::BadValue("domain"))
        );
        assert_eq!(
            p(set(&good, "version", c::u(3))),
            Some(RecordError::BadValue("version"))
        );
        assert_eq!(
            p(set(&good, "slot_index", c::u(1))),
            Some(RecordError::BadValue("slot_index"))
        );

        // The context bound, Bytes(1,4096), is checked before decoding it.
        assert_eq!(p(slot_around(&[])), bad_field(M, CX));
        assert_eq!(p(slot_around(&[0; 4097])), bad_field(M, CX));
        assert_eq!(
            p(slot_around(&[0; 4096])),
            Some(RecordError::Cbor(c::CborError::TrailingBytes(4095)))
        );
        assert_eq!(
            p(slot_around(&[0])),
            Some(RecordError::NotAMap("DekSlotContextV2"))
        );
        assert_eq!(p(set(&good, CX, c::u(0))), bad_field(M, CX));

        // The context is its own closed canonical map.
        let cx = slot().context_bytes;
        let extra = edit(&cx, |e| e.push(("extra".into(), c::u(0))));
        assert_eq!(
            p(slot_around(&extra)),
            Some(RecordError::UnknownField {
                map: "DekSlotContextV2",
                field: "extra".into()
            })
        );
        let mut overlong = cx.clone();
        let at = cx.windows(8).position(|w| w == b"\x67version").unwrap();
        overlong.splice(at + 8..at + 9, [0x18, 0x02]);
        assert_eq!(
            p(slot_around(&overlong)),
            Some(RecordError::Cbor(c::CborError::OverlongInteger))
        );

        // The stored context hash is recomputed, not trusted.
        let mut flipped = slot().context_hash;
        flipped[0] ^= 1;
        assert_eq!(
            p(set(&good, "dek_slot_context_hash", c::b(&flipped))),
            Some(RecordError::BadValue("dek_slot_context_hash"))
        );
        let other_tenant = set(&cx, "tenant_id", c::b(&[0xee; 16]));
        assert_eq!(
            p(set(&good, CX, c::b(&other_tenant))),
            Some(RecordError::BadValue("dek_slot_context_hash"))
        );
        assert!(DekSlotV2::parse(&slot_around(&other_tenant)).is_ok());

        // Suite 1 fixes a 12-byte nonce and a 48-byte wrapped DEK.
        for (name, len) in [
            ("dek_slot_context_hash", 32),
            ("wrap_nonce_bytes", WRAP_NONCE_LEN),
            ("wrapped_dek_bytes", WRAPPED_DEK_LEN),
        ] {
            for wrong in [len - 1, len + 1] {
                assert_eq!(
                    p(set(&good, name, c::b(&vec![0; wrong]))),
                    bad_field(M, name)
                );
            }
        }
    }

    #[test]
    fn every_envelope_intent_rule_is_enforced() {
        const M: &str = "EnvelopeIntentV2";
        let s = slot();
        let good = fixture().intent.exact_intent_bytes;
        let versioned = versioned_intent(&s).exact_intent_bytes;
        closed_map_rules(M, &good, EnvelopeIntentV2::parse);
        let p = |b: Vec<u8>| EnvelopeIntentV2::parse(&b).err();
        let bad = |field| Some(RecordError::BadValue(field));
        let ok = |b: Vec<u8>| EnvelopeIntentV2::parse(&b).unwrap();

        assert_eq!(
            p(set(&good, "domain", c::t("shardx.envelope.dek-slot.v2"))),
            bad("domain")
        );
        assert_eq!(p(set(&good, "version", c::u(3))), bad("version"));
        assert_eq!(
            p(set(&good, "preamble_version", c::u(1))),
            bad("preamble_version")
        );

        // Registry values on read (ADR 0002 registry table).
        for (name, wrong) in [
            ("envelope_suite_id", 1),
            ("envelope_suite_id", 3),
            ("wrap_suite_id", 2),
            ("archive_format_id", 2),
            ("archive_policy_id", 2),
            ("compression_id", 0),
        ] {
            assert_eq!(p(set(&good, name, c::u(wrong))), unsupported(name, wrong));
        }
        assert_eq!(
            p(set(&good, "compression_id", c::u(65_537))),
            bad_field(M, "compression_id")
        );

        // Bounds (plan L649-L652), both edges.
        let frame = "frame_plaintext_size";
        for wrong in [65_535, 4_194_305, (1 << 32) + 65_536] {
            assert_eq!(p(set(&good, frame, c::u(wrong))), bad(frame));
        }
        for edge in [65_536, 4_194_304] {
            assert_eq!(
                ok(set(&good, frame, c::u(edge))).frame_plaintext_size as u64,
                edge
            );
        }
        for name in ["max_plaintext_size", "max_ciphertext_size"] {
            for wrong in [0, MAX_OBJECT_SIZE + 1] {
                assert_eq!(p(set(&good, name, c::u(wrong))), bad(name));
            }
            for edge in [1, MAX_OBJECT_SIZE] {
                assert!(EnvelopeIntentV2::parse(&set(&good, name, c::u(edge))).is_ok());
            }
        }
        for wrong in [STREAM_NONCE_PREFIX_LEN - 1, STREAM_NONCE_PREFIX_LEN + 1] {
            assert_eq!(
                p(set(&good, "stream_nonce_prefix", c::b(&vec![0; wrong]))),
                bad_field(M, "stream_nonce_prefix")
            );
        }
        for wrong in [Value::Bool(false), c::u(1)] {
            assert_eq!(
                p(set(&good, "final_frame_required", wrong)),
                bad("final_frame_required")
            );
        }
        assert_eq!(
            p(set(&good, "restore_epoch", c::u(1 << 63))),
            Some(RecordError::Cbor(c::CborError::IntegerOutOfSqliteDomain(
                1 << 63
            )))
        );

        // Scope IDs and hashes are exact-length byte strings.
        for (name, len) in [
            ("snapshot_id", 16),
            ("tenant_id", 16),
            ("fleet_id", 16),
            ("profile_id", 16),
            ("lease_id", 16),
            ("manifest_replay_id", 16),
            ("server_instance_id", 16),
            ("fkek_key_id", 32),
            ("intended_signer_signing_key_id", 32),
            ("dek_slot_context_hash", 32),
            ("dek_slot_sha256", 32),
        ] {
            for wrong in [len - 1, len + 1] {
                assert_eq!(
                    p(set(&good, name, c::b(&vec![0; wrong]))),
                    bad_field(M, name)
                );
            }
            assert_eq!(p(set(&good, name, c::t("x"))), bad_field(M, name));
        }

        // target_version = base_version + 1 (plan L645).
        let target = "target_version";
        assert_eq!(p(set(&good, target, c::u(0))), bad(target));
        assert_eq!(p(set(&good, target, c::u(2))), bad(target));
        assert_eq!(p(set(&versioned, target, c::u(4))), bad(target));
        assert_eq!(p(set(&versioned, target, c::u(6))), bad(target));
        let top = set(&versioned, "base_version", c::u(i64::MAX as u64));
        assert_eq!(p(set(&top, target, c::u(i64::MAX as u64))), bad(target));

        // previous_signed_head_hash is omitted iff base_version = 0 (plan L654).
        let prev = "previous_signed_head_hash";
        let with_prev = edit(&good, |e| e.push((prev.into(), c::b(&[0x55; 32]))));
        assert_eq!(p(with_prev), bad(prev));
        let without_prev = edit(&versioned, |e| e.retain(|(k, _)| k != prev));
        assert_eq!(p(without_prev), bad(prev));
        assert_eq!(
            p(set(&versioned, prev, c::b(&[0x55; 31]))),
            bad_field(M, prev)
        );
        let rebased = set(&set(&versioned, "base_version", c::u(1)), target, c::u(2));
        assert_eq!(ok(rebased).base_version, 1);
    }

    /// An object around `intent` and `slot` whose every hash agrees, so only
    /// the closed-map and equality rules can refuse it.
    fn object_around(intent: &[u8], slot: &[u8]) -> (Vec<u8>, Exp) {
        let ih = EnvelopeIntentV2::hash(intent);
        let mut o = Preamble {
            intent_len: intent.len() as u32,
            dek_slot_len: slot.len() as u32,
            frame_plaintext_size: FRAME,
            intent_sha256: ih,
        }
        .encode()
        .to_vec();
        o.extend_from_slice(intent);
        o.extend_from_slice(slot);
        let ct = StreamLE31::<XChaCha20Poly1305>::new(&DEK.into(), &PREFIX.into())
            .encrypt(
                0,
                true,
                Payload {
                    msg: b"x",
                    aad: &frame_aad(&ih, 0, true),
                },
            )
            .unwrap();
        o.push(KIND_FINAL);
        o.extend_from_slice(&0u32.to_be_bytes());
        o.extend_from_slice(&(ct.len() as u32).to_be_bytes());
        o.extend_from_slice(&ct);
        let e = Exp {
            sha: c::sha256(&o),
            size: o.len() as u64,
            pre: preamble_sha256(o[..PREAMBLE_LEN].try_into().unwrap()),
            intent: ih,
            slot: c::domain_hash(c::L_DEK_SLOT, slot),
            scope: scope_of(intent),
        };
        (o, e)
    }

    /// Both the writer and the reader refuse `intent` with `slot` for `rule`.
    fn refused_both_ways(intent: &IntentMaterial, slot: &SlotMaterial, rule: &str) {
        let r = seal(
            &mut Cursor::new(plaintext(5)),
            &mut Vec::new(),
            &DEK,
            intent,
            slot,
        );
        assert_eq!(
            rule_of(r.map(|_| OpenOutcome {
                frame_count: 0,
                plaintext_len: 0
            })),
            rule
        );
        let (o, e) = object_around(&intent.exact_intent_bytes, &slot.exact_slot_bytes);
        let (r, out) = open_with(&o, &FKEK, &e);
        assert_eq!(rule_of(r), rule);
        assert!(out.is_empty());
    }

    struct SlotInputs {
        snapshot_id: [u8; 16],
        tenant_id: [u8; 16],
        fleet_id: [u8; 16],
        profile_id: [u8; 16],
        fkek_key_id: [u8; 32],
        key_generation: u64,
    }

    fn slot_from(s: &SlotInputs) -> SlotMaterial {
        build_dek_slot(
            &FKEK,
            &DEK,
            &[0x33; WRAP_NONCE_LEN],
            &SlotIds {
                tenant_id: &s.tenant_id,
                fleet_id: &s.fleet_id,
                profile_id: &s.profile_id,
                snapshot_id: &s.snapshot_id,
                fkek_key_id: &s.fkek_key_id,
                envelope_context_nonce: &[6; 16],
            },
            s.key_generation,
        )
        .unwrap()
    }

    #[test]
    fn a_slot_that_differs_from_the_intent_is_refused() {
        let good = || SlotInputs {
            snapshot_id: [4; 16],
            tenant_id: [1; 16],
            fleet_id: [2; 16],
            profile_id: [3; 16],
            fkek_key_id: [5; 32],
            key_generation: 1,
        };
        let intent_for = |slot: &SlotMaterial| {
            build_intent_v2(&ids(), &nums(FRAME, MAX_OBJECT_SIZE), &PREFIX, None, slot).unwrap()
        };

        // The helper object opens when nothing differs.
        let slot = slot_from(&good());
        let intent = intent_for(&slot);
        let (o, e) = object_around(&intent.exact_intent_bytes, &slot.exact_slot_bytes);
        let (r, out) = open_with(&o, &FKEK, &e);
        assert!(r.is_ok(), "{r:?}");
        assert_eq!(out, b"x");

        type Tweak = fn(&mut SlotInputs);
        let cases: [(&str, Tweak); 6] = [
            ("snapshot_id", |s| s.snapshot_id[0] ^= 1),
            ("tenant_id", |s| s.tenant_id[0] ^= 1),
            ("fleet_id", |s| s.fleet_id[0] ^= 1),
            ("profile_id", |s| s.profile_id[0] ^= 1),
            ("fkek_key_id", |s| s.fkek_key_id[0] ^= 1),
            ("key_generation", |s| s.key_generation = 2),
        ];
        for (field, change) in cases {
            let mut inputs = good();
            change(&mut inputs);
            let slot = slot_from(&inputs);
            refused_both_ways(&intent_for(&slot), &slot, &format!("mismatch {field}"));
        }

        // An intent naming the exact slot bytes but another context hash.
        let named = SlotMaterial {
            context_hash: [0xcc; 32],
            ..slot_from(&good())
        };
        refused_both_ways(
            &intent_for(&named),
            &slot_from(&good()),
            "mismatch dek_slot_context_hash",
        );
    }

    #[test]
    fn the_reader_refuses_an_open_map() {
        // An intent with an unknown field, every hash agreeing.
        let f = fixture();
        let extra = edit(&f.intent.exact_intent_bytes, |e| {
            e.push(("extra".into(), c::u(0)))
        });
        let (o, e) = object_around(&extra, &f.slot.exact_slot_bytes);
        let (r, out) = open_with(&o, &FKEK, &e);
        assert!(
            matches!(&r, Err(EnvelopeError::Record(RecordError::UnknownField { map: "EnvelopeIntentV2", field })) if field == "extra"),
            "{r:?}"
        );
        assert!(out.is_empty());

        // A slot, then a slot context, with an unknown field, named by the intent.
        let open_slot = edit(&f.slot.exact_slot_bytes, |e| {
            e.push(("extra".into(), c::u(0)))
        });
        let cx = edit(&f.slot.context_bytes, |e| e.push(("extra".into(), c::u(0))));
        for (slot_bytes, map) in [
            (open_slot, "DekSlotV2"),
            (slot_around(&cx), "DekSlotContextV2"),
        ] {
            let named = SlotMaterial {
                dek_slot_sha256: c::domain_hash(c::L_DEK_SLOT, &slot_bytes),
                exact_slot_bytes: slot_bytes,
                ..slot()
            };
            let intent =
                build_intent_v2(&ids(), &nums(FRAME, MAX_OBJECT_SIZE), &PREFIX, None, &named)
                    .unwrap();
            let want = format!(
                "{:?}",
                Err::<OpenOutcome, _>(EnvelopeError::Record(RecordError::UnknownField {
                    map,
                    field: "extra".into()
                }))
            );
            refused_both_ways(&intent, &named, &want);
        }
    }
}
