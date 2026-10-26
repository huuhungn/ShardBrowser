//! Encrypted profile backup, v2 container format.
//!
//! This module is the seam between the v1 portable snapshot (a gzip-tar of the
//! user-data dir, produced by [`crate::snapshot::pack`]) and the v2 crypto
//! primitives in [`crate::keys`], [`crate::signing`] and [`crate::envelope`].
//!
//! # Layering
//!
//! ```text
//!   snapshot::pack(udd)  ->  plaintext bytes
//!         |
//!         v
//!   backup::seal(...)    ->  [ magic | header | frame* | footer ]
//!         |
//!         v
//!   backup::open(...)    ->  plaintext bytes
//!         |
//!         v
//!   snapshot::unpack(bytes, udd)
//! ```
//!
//! The v1 functions are untouched and still callable on their own; a v1
//! snapshot file remains a valid gzip-tar. v2 is strictly an outer wrapper, so
//! restoring on an older build fails loudly on the magic rather than silently
//! misreading half a stream.
//!
//! # What the format guarantees
//!
//! * **Whole-file authenticity.** Every frame is AEAD-sealed with the intent
//!   hash as associated data, so a frame cannot be moved between envelopes,
//!   reordered, duplicated, or truncated without a tag failure.
//! * **Termination.** The last frame is sealed with a distinct final-flag nonce
//!   and the footer restates the frame count, so a stream cut short at a frame
//!   boundary is rejected instead of restoring a partial profile.
//! * **Signed head.** The footer carries the Ed25519 signature over the
//!   canonical head record, binding the intent to a signing identity.
//!
//! # Bounded memory
//!
//! Sealing streams a `Read` into frames of `FRAME_PLAINTEXT_SIZE` and opening
//! streams frames back into a `Write`, so peak memory is one frame plus
//! overhead regardless of profile size. The declared plaintext/ciphertext caps
//! in the intent are enforced while streaming — a hostile footer claiming a
//! small size cannot make the reader buffer a large one.

use std::io::{Read, Write};

use crate::canonical::{self as c, Value};
use crate::envelope::{
    build_dek_slot, build_envelope_intent, open_frame, seal_frame, IntentIds, IntentMaterial,
    IntentNumbers, SlotIds, SlotMaterial,
};
use crate::keys::{
    signing_key_id, unwrap_dek, DEK_LEN, ENVELOPE_SUITE_ID_CHACHA20POLY1305_STREAM,
    STREAM_NONCE_PREFIX_LEN, WRAP_NONCE_LEN,
};
use crate::signing::{build_signed_container, verify_tbs};
use ed25519_dalek::SigningKey;

/// File magic. Distinct from gzip's `1f 8b`, so a v1 reader handed a v2 file
/// fails on the header instead of decoding garbage.
pub const MAGIC: &[u8; 8] = b"SHRDXBK2";

/// Plaintext bytes per frame (64 KiB).
pub const FRAME_PLAINTEXT_SIZE: u32 = 65536;

/// Refuse to allocate for any single frame larger than this.
const MAX_FRAME_CIPHERTEXT: usize = FRAME_PLAINTEXT_SIZE as usize + 4096;

/// Hard ceiling on a restored profile (4 GiB), mirroring the v1 expansion cap.
pub const MAX_PLAINTEXT_SIZE: u64 = 4 * 1024 * 1024 * 1024;

/// Hard ceiling on the sealed stream, with room for per-frame tags.
pub const MAX_CIPHERTEXT_SIZE: u64 = MAX_PLAINTEXT_SIZE + (64 * 1024 * 1024);

// ------------------------------------------------------------------ errors ----

#[derive(Debug)]
pub enum BackupError {
    /// The file does not start with [`MAGIC`].
    BadMagic,
    /// Header/footer bytes are not canonical CBOR, or a field is missing.
    MalformedContainer(&'static str),
    /// A declared size exceeds the format's cap, or the stream exceeded it.
    SizeLimitExceeded { limit: u64, actual: u64 },
    /// A frame failed authentication — wrong key, tampered bytes, or a frame
    /// lifted from a different envelope.
    FrameAuthFailed { counter: u32 },
    /// The stream ended without a frame carrying the final flag.
    UnterminatedStream { frames_read: u32 },
    /// The footer's frame count disagrees with what was actually read.
    FrameCountMismatch { declared: u32, actual: u32 },
    /// The head signature did not verify against the declared signing key.
    SignatureInvalid,
    /// The DEK could not be unwrapped with the supplied FKEK.
    KeyUnwrapFailed,
    /// The intent could not be rebuilt (structural invariant violated).
    Intent(crate::envelope::IntentError),
    /// Underlying I/O failure.
    Io(std::io::Error),
}

impl std::fmt::Display for BackupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadMagic => write!(f, "not a ShardX v2 backup (bad magic)"),
            Self::MalformedContainer(w) => write!(f, "malformed backup container: {w}"),
            Self::SizeLimitExceeded { limit, actual } => {
                write!(f, "size limit exceeded: limit={limit} actual={actual}")
            }
            Self::FrameAuthFailed { counter } => {
                write!(f, "frame {counter} failed authentication")
            }
            Self::UnterminatedStream { frames_read } => write!(
                f,
                "stream ended without a final frame after {frames_read} frames"
            ),
            Self::FrameCountMismatch { declared, actual } => write!(
                f,
                "frame count mismatch: declared={declared} actual={actual}"
            ),
            Self::SignatureInvalid => write!(f, "head signature did not verify"),
            Self::KeyUnwrapFailed => write!(f, "DEK unwrap failed"),
            Self::Intent(e) => write!(f, "envelope intent rejected: {e}"),
            Self::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for BackupError {}

impl From<std::io::Error> for BackupError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<crate::envelope::IntentError> for BackupError {
    fn from(e: crate::envelope::IntentError) -> Self {
        Self::Intent(e)
    }
}

type Result<T> = std::result::Result<T, BackupError>;

// ------------------------------------------------------------------ params ----

/// Everything the caller must decide before a backup can be sealed.
///
/// These are the identity and versioning facts that end up inside the signed
/// intent; they are deliberately explicit rather than defaulted, because a
/// wrong `base_version` or `fencing_token` is a correctness bug that must not
/// be papered over by a convenient default.
pub struct BackupParams<'a> {
    pub ids: IntentIds,
    pub key_generation: u64,
    pub target_version: u64,
    pub base_version: u64,
    pub fencing_token: u64,
    pub restore_epoch: u64,
    pub created_at_ms: u64,
    pub envelope_context_nonce: &'a [u8; 16],
    /// `None` iff `base_version == 0`.
    pub previous_signed_head_hash: Option<&'a [u8; 32]>,
}

/// Per-backup secrets. Supplied by the caller so they can come from a real CSPRNG
/// in production and from fixtures in tests, without this module ever deciding
/// its own randomness policy.
pub struct BackupSecrets<'a> {
    pub fkek: &'a [u8; 32],
    pub dek: &'a [u8; DEK_LEN],
    pub wrap_nonce: &'a [u8; WRAP_NONCE_LEN],
    pub stream_nonce_prefix: &'a [u8; STREAM_NONCE_PREFIX_LEN],
}

/// What a successful seal produced, for the caller to record in its ledger.
pub struct SealOutcome {
    pub intent_hash: [u8; 32],
    pub signed_head_hash: [u8; 32],
    pub frame_count: u32,
    pub plaintext_len: u64,
    pub ciphertext_len: u64,
}

/// What a successful open recovered.
pub struct OpenOutcome {
    pub intent_hash: [u8; 32],
    pub signed_head_hash: [u8; 32],
    pub frame_count: u32,
    pub plaintext_len: u64,
    /// The intent's `profile_id`, so a caller can refuse a container sealed
    /// for another profile.
    pub profile_id: [u8; 16],
}

// -------------------------------------------------------------------- seal ----

fn build_material(
    params: &BackupParams<'_>,
    secrets: &BackupSecrets<'_>,
) -> Result<(SlotMaterial, IntentMaterial)> {
    let slot = build_dek_slot(
        secrets.fkek,
        secrets.dek,
        secrets.wrap_nonce,
        &SlotIds {
            tenant_id: &params.ids.tenant_id,
            fleet_id: &params.ids.fleet_id,
            profile_id: &params.ids.profile_id,
            snapshot_id: &params.ids.snapshot_id,
            fkek_key_id: &params.ids.fkek_key_id,
            envelope_context_nonce: params.envelope_context_nonce,
        },
        params.key_generation,
    )
    .map_err(|_| BackupError::KeyUnwrapFailed)?;

    let nums = IntentNumbers {
        target_version: params.target_version,
        base_version: params.base_version,
        fencing_token: params.fencing_token,
        key_generation: params.key_generation,
        restore_epoch: params.restore_epoch,
        frame_plaintext_size: FRAME_PLAINTEXT_SIZE,
        max_plaintext_size: MAX_PLAINTEXT_SIZE,
        max_ciphertext_size: MAX_CIPHERTEXT_SIZE,
        created_at_ms: params.created_at_ms,
    };

    let intent = build_envelope_intent(
        &params.ids,
        &nums,
        secrets.stream_nonce_prefix,
        params.previous_signed_head_hash,
        &slot,
    )?;

    Ok((slot, intent))
}

/// The canonical head record fields: the container's self-description.
///
/// These are TBS fields only — the signature and container hash are appended by
/// [`build_signed_container`] in the fixed order that keeps commitment acyclic.
fn head_tbs_fields<'a>(
    slot: &'a SlotMaterial,
    intent: &'a IntentMaterial,
    signer_key_id: &'a [u8; 32],
    verifying_key: &'a [u8; 32],
    frame_count: u32,
    plaintext_len: u64,
) -> Vec<(&'a str, Value)> {
    vec![
        ("container_domain", c::t("shardx.backup.head.v2")),
        ("version", c::u(2)),
        (
            "envelope_suite_id",
            c::u(ENVELOPE_SUITE_ID_CHACHA20POLY1305_STREAM as u64),
        ),
        ("canonical_dek_slot_bytes", c::b(&slot.exact_slot_bytes)),
        ("canonical_intent_bytes", c::b(&intent.exact_intent_bytes)),
        ("intent_hash", c::b(&intent.intent_hash)),
        ("frame_count", c::u(frame_count as u64)),
        ("plaintext_len", c::u(plaintext_len)),
        ("issuer_signing_key_id", c::b(signer_key_id)),
        ("issuer_verifying_key_bytes", c::b(verifying_key)),
    ]
}

/// Look up a field in a canonical map, without a general-purpose accessor that
/// would invite reading unauthenticated fields elsewhere.
fn field<'a>(v: &'a Value, name: &str) -> Option<&'a Value> {
    match v {
        Value::Map(entries) => entries.iter().find(|(k, _)| k == name).map(|(_, v)| v),
        _ => None,
    }
}

fn field_bytes(v: &Value, name: &str) -> Option<Vec<u8>> {
    match field(v, name)? {
        Value::Bytes(b) => Some(b.clone()),
        _ => None,
    }
}

fn field_u64(v: &Value, name: &str) -> Option<u64> {
    match field(v, name)? {
        Value::Uint(n) => Some(*n),
        _ => None,
    }
}

fn write_len_prefixed(out: &mut impl Write, bytes: &[u8]) -> Result<()> {
    out.write_all(&(bytes.len() as u32).to_be_bytes())?;
    out.write_all(bytes)?;
    Ok(())
}

/// Seal `plaintext` into a v2 backup container written to `out`.
///
/// Streams in bounded frames; `plaintext` is never fully buffered.
pub fn seal(
    plaintext: &mut impl Read,
    out: &mut impl Write,
    params: &BackupParams<'_>,
    secrets: &BackupSecrets<'_>,
    signer: &SigningKey,
) -> Result<SealOutcome> {
    let (slot, intent) = build_material(params, secrets)?;

    // The header is written before the frames so a reader can authenticate every
    // frame as it streams, rather than buffering the whole file to reach a
    // trailing header.
    out.write_all(MAGIC)?;
    write_len_prefixed(out, &slot.exact_slot_bytes)?;
    write_len_prefixed(out, &intent.exact_intent_bytes)?;

    let mut buf = vec![0u8; FRAME_PLAINTEXT_SIZE as usize];
    let mut carry: Option<Vec<u8>> = None;
    let mut counter: u32 = 0;
    let mut plaintext_len: u64 = 0;
    let mut ciphertext_len: u64 = 0;

    // One frame of lookahead: the final frame must be sealed with the final
    // flag set, and that is only knowable once the *next* read hits EOF. Exactly
    // one frame is emitted per loop turn, and the terminator is emitted once
    // after the loop — an exact multiple of the frame size must not produce a
    // trailing empty frame, or the reader's frame count disagrees.
    loop {
        let mut filled = 0usize;
        let mut eof = false;
        while filled < buf.len() {
            match plaintext.read(&mut buf[filled..])? {
                0 => {
                    eof = true;
                    break;
                }
                n => filled += n,
            }
        }

        if filled > 0 {
            // The previous chunk is now known to be non-final.
            if let Some(prev) = carry.replace(buf[..filled].to_vec()) {
                let sealed = emit_frame(out, &prev, counter, false, secrets, &intent)?;
                plaintext_len += prev.len() as u64;
                ciphertext_len += sealed;
                counter = counter
                    .checked_add(1)
                    .ok_or(BackupError::SizeLimitExceeded {
                        limit: u32::MAX as u64,
                        actual: u64::from(u32::MAX) + 1,
                    })?;
                if plaintext_len > MAX_PLAINTEXT_SIZE {
                    return Err(BackupError::SizeLimitExceeded {
                        limit: MAX_PLAINTEXT_SIZE,
                        actual: plaintext_len,
                    });
                }
            }
        }

        if eof {
            break;
        }
    }

    // Flush the lookahead as the terminator. An empty plaintext still emits
    // exactly one final frame, so every container ends authenticated.
    let last = carry.take().unwrap_or_default();
    let sealed = emit_frame(out, &last, counter, true, secrets, &intent)?;
    plaintext_len += last.len() as u64;
    ciphertext_len += sealed;
    if plaintext_len > MAX_PLAINTEXT_SIZE {
        return Err(BackupError::SizeLimitExceeded {
            limit: MAX_PLAINTEXT_SIZE,
            actual: plaintext_len,
        });
    }
    let frame_count = counter + 1;

    let vk_bytes = signer.verifying_key().to_bytes();
    let signer_key_id = signing_key_id(&vk_bytes);
    let head_fields = head_tbs_fields(
        &slot,
        &intent,
        &signer_key_id,
        &vk_bytes,
        frame_count,
        plaintext_len,
    );
    let container = build_signed_container(signer, head_fields);
    write_len_prefixed(out, &container.exact_bytes)?;
    out.flush()?;

    Ok(SealOutcome {
        intent_hash: intent.intent_hash,
        signed_head_hash: container.signed_container_hash,
        frame_count,
        plaintext_len,
        ciphertext_len,
    })
}

fn emit_frame(
    out: &mut impl Write,
    chunk: &[u8],
    counter: u32,
    is_final: bool,
    secrets: &BackupSecrets<'_>,
    intent: &IntentMaterial,
) -> Result<u64> {
    let ct = seal_frame(
        secrets.dek,
        secrets.stream_nonce_prefix,
        &intent.intent_hash,
        counter,
        is_final,
        chunk,
    )
    .map_err(|_| BackupError::FrameAuthFailed { counter })?;
    out.write_all(&[u8::from(is_final)])?;
    write_len_prefixed(out, &ct)?;
    Ok(ct.len() as u64 + 5)
}

// -------------------------------------------------------------------- open ----

fn read_exact_or(reader: &mut impl Read, n: usize, what: &'static str) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    reader
        .read_exact(&mut buf)
        .map_err(|_| BackupError::MalformedContainer(what))?;
    Ok(buf)
}

fn read_len_prefixed(reader: &mut impl Read, cap: usize, what: &'static str) -> Result<Vec<u8>> {
    let len_bytes = read_exact_or(reader, 4, what)?;
    let len = u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
    // Check the declared length against a cap *before* allocating, so a hostile
    // header cannot drive an allocation the machine cannot satisfy.
    if len > cap {
        return Err(BackupError::SizeLimitExceeded {
            limit: cap as u64,
            actual: len as u64,
        });
    }
    read_exact_or(reader, len, what)
}

/// Open a v2 backup container from `input`, writing recovered plaintext to `out`.
///
/// The FKEK and the expected signer are supplied by the caller: this function
/// authenticates, it does not decide trust.
///
/// **Output is not trustworthy until this function returns `Ok`.** Frames are
/// written as they are decrypted, because buffering the whole plaintext would
/// defeat the bounded-memory property that lets this run on a multi-gigabyte
/// profile. Every frame is individually authenticated before it is written, and
/// the signed head — which commits to the frame count, plaintext length and the
/// entire prologue — is verified only after the last frame. A caller must
/// therefore write to a temporary destination and promote it on `Ok`, never
/// restore in place from a partially-consumed stream.
pub fn open(
    input: &mut impl Read,
    out: &mut impl Write,
    fkek: &[u8; 32],
    expected_signer_key_id: &[u8; 32],
) -> Result<OpenOutcome> {
    let magic = read_exact_or(input, MAGIC.len(), "magic")?;
    if magic.as_slice() != MAGIC.as_slice() {
        return Err(BackupError::BadMagic);
    }

    let slot_bytes = read_len_prefixed(input, 64 * 1024, "dek slot")?;
    let intent_bytes = read_len_prefixed(input, 64 * 1024, "intent")?;

    // Reject a non-canonical header outright: accepting an alternate encoding
    // would let two different byte strings hash to the same logical intent.
    let slot_v = c::assert_canonical_roundtrip(&slot_bytes)
        .map_err(|_| BackupError::MalformedContainer("dek slot is not canonical"))?;
    let intent_v = c::assert_canonical_roundtrip(&intent_bytes)
        .map_err(|_| BackupError::MalformedContainer("intent is not canonical"))?;

    let intent_hash = c::domain_hash(c::L_ENVELOPE_INTENT, &intent_bytes);

    let ctx = field_bytes(&slot_v, "canonical_dek_slot_context_bytes")
        .ok_or(BackupError::MalformedContainer("slot context missing"))?;
    let wrap_nonce_v = field_bytes(&slot_v, "wrap_nonce_bytes")
        .ok_or(BackupError::MalformedContainer("wrap nonce missing"))?;
    let wrapped = field_bytes(&slot_v, "wrapped_dek_bytes")
        .ok_or(BackupError::MalformedContainer("wrapped dek missing"))?;
    let wrap_nonce: [u8; WRAP_NONCE_LEN] = wrap_nonce_v
        .as_slice()
        .try_into()
        .map_err(|_| BackupError::MalformedContainer("wrap nonce length"))?;

    let dek =
        unwrap_dek(fkek, &wrap_nonce, &wrapped, &ctx).map_err(|_| BackupError::KeyUnwrapFailed)?;

    let prefix_v = field_bytes(&intent_v, "stream_nonce_prefix").ok_or(
        BackupError::MalformedContainer("stream nonce prefix missing"),
    )?;
    let prefix: [u8; STREAM_NONCE_PREFIX_LEN] = prefix_v
        .as_slice()
        .try_into()
        .map_err(|_| BackupError::MalformedContainer("stream nonce prefix length"))?;

    let mut counter: u32 = 0;
    let mut plaintext_len: u64 = 0;
    let mut saw_final = false;

    while !saw_final {
        let flag = read_exact_or(input, 1, "frame flag")?;
        let is_final = match flag[0] {
            0 => false,
            1 => true,
            // Only two encodings are legal; anything else is a malformed or
            // hostile stream, not something to coerce into a bool.
            _ => return Err(BackupError::MalformedContainer("frame flag")),
        };
        let ct = read_len_prefixed(input, MAX_FRAME_CIPHERTEXT, "frame")?;
        let pt = open_frame(&dek, &prefix, &intent_hash, counter, is_final, &ct)
            .map_err(|_| BackupError::FrameAuthFailed { counter })?;

        plaintext_len += pt.len() as u64;
        if plaintext_len > MAX_PLAINTEXT_SIZE {
            return Err(BackupError::SizeLimitExceeded {
                limit: MAX_PLAINTEXT_SIZE,
                actual: plaintext_len,
            });
        }
        out.write_all(&pt)?;

        saw_final = is_final;
        if !saw_final {
            counter = counter
                .checked_add(1)
                .ok_or(BackupError::UnterminatedStream {
                    frames_read: u32::MAX,
                })?;
        }
    }
    let frame_count = counter + 1;

    let head_bytes = read_len_prefixed(input, 128 * 1024, "head")?;
    let head_v = c::assert_canonical_roundtrip(&head_bytes)
        .map_err(|_| BackupError::MalformedContainer("head is not canonical"))?;

    // Rebuild the TBS/core byte strings by *name*, not by position: the
    // canonical encoder sorts map entries by key, so the two appended
    // commitment fields do not land at the end of the decoded entry list.
    let (tbs_bytes, core_bytes) = match &head_v {
        Value::Map(entries) => {
            let strip = |drop: &[&str]| -> Vec<u8> {
                let kept: Vec<(&str, Value)> = entries
                    .iter()
                    .filter(|(k, _)| !drop.contains(&k.as_str()))
                    .map(|(k, v)| (k.as_str(), v.clone()))
                    .collect();
                c::encode(&c::m(kept))
            };
            (
                strip(&["signature_bytes", "signed_container_hash"]),
                strip(&["signed_container_hash"]),
            )
        }
        _ => return Err(BackupError::MalformedContainer("head is not a map")),
    };

    let sig = field_bytes(&head_v, "signature_bytes")
        .ok_or(BackupError::MalformedContainer("head signature missing"))?;
    let declared_key_id = field_bytes(&head_v, "issuer_signing_key_id").ok_or(
        BackupError::MalformedContainer("head signing key id missing"),
    )?;
    if declared_key_id.as_slice() != expected_signer_key_id.as_slice() {
        return Err(BackupError::SignatureInvalid);
    }

    let vk = field_bytes(&head_v, "issuer_verifying_key_bytes").ok_or(
        BackupError::MalformedContainer("head verifying key missing"),
    )?;
    let vk32: [u8; 32] = vk
        .as_slice()
        .try_into()
        .map_err(|_| BackupError::MalformedContainer("verifying key length"))?;
    // The declared key id must actually bind the declared key, or an attacker
    // could present their own key under a trusted id.
    if signing_key_id(&vk32).as_slice() != declared_key_id.as_slice() {
        return Err(BackupError::SignatureInvalid);
    }
    verify_tbs(&vk32, &tbs_bytes, &sig).map_err(|_| BackupError::SignatureInvalid)?;

    let signed_head_hash = c::domain_hash(c::L_SIGNED_CONTAINER, &core_bytes);
    let declared_hash = field_bytes(&head_v, "signed_container_hash").ok_or(
        BackupError::MalformedContainer("head container hash missing"),
    )?;
    if declared_hash.as_slice() != signed_head_hash.as_slice() {
        return Err(BackupError::SignatureInvalid);
    }

    // The head is signed, so these checks run against authenticated bytes and
    // catch a truncation that happened to land on a frame boundary.
    let declared_frames = field_u64(&head_v, "frame_count")
        .ok_or(BackupError::MalformedContainer("head frame_count"))?;
    if declared_frames != frame_count as u64 {
        return Err(BackupError::FrameCountMismatch {
            declared: declared_frames as u32,
            actual: frame_count,
        });
    }
    let declared_len = field_u64(&head_v, "plaintext_len")
        .ok_or(BackupError::MalformedContainer("head plaintext_len"))?;
    if declared_len != plaintext_len {
        return Err(BackupError::SizeLimitExceeded {
            limit: declared_len,
            actual: plaintext_len,
        });
    }
    let head_intent = field_bytes(&head_v, "intent_hash")
        .ok_or(BackupError::MalformedContainer("head intent_hash"))?;
    if head_intent.as_slice() != intent_hash.as_slice() {
        return Err(BackupError::MalformedContainer("head intent_hash mismatch"));
    }

    // Bind the prologue to the signed head. The intent hash alone does not
    // cover the slot, and the slot's own bytes are read before any signature is
    // available — so without these two equalities an attacker could swap the
    // unauthenticated prologue for one from another container. Compare the exact
    // bytes, not a re-encoding, so a substituted encoding cannot pass either.
    let head_slot = field_bytes(&head_v, "canonical_dek_slot_bytes")
        .ok_or(BackupError::MalformedContainer("head slot bytes"))?;
    if head_slot != slot_bytes {
        return Err(BackupError::MalformedContainer("prologue slot mismatch"));
    }
    let head_intent_bytes = field_bytes(&head_v, "canonical_intent_bytes")
        .ok_or(BackupError::MalformedContainer("head intent bytes"))?;
    if head_intent_bytes != intent_bytes {
        return Err(BackupError::MalformedContainer("prologue intent mismatch"));
    }

    // Authenticated: the signed head commits to these exact intent bytes.
    let profile_id: [u8; 16] = field_bytes(&intent_v, "profile_id")
        .and_then(|b| b.as_slice().try_into().ok())
        .ok_or(BackupError::MalformedContainer("intent profile_id"))?;

    out.flush()?;
    Ok(OpenOutcome {
        intent_hash,
        signed_head_hash,
        frame_count,
        plaintext_len,
        profile_id,
    })
}

// ------------------------------------------------------------------- tests ----

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::root_key_id;
    use sha2::{Digest, Sha256};

    /// Same deterministic fixture derivation the other v2 modules use.
    fn fixture_bytes<const N: usize>(label: &str) -> [u8; N] {
        let mut out = [0u8; N];
        let mut counter: u32 = 0;
        let mut off = 0;
        while off < N {
            let mut h = Sha256::new();
            h.update(b"SHARDX-G2-FIXTURE\0");
            h.update(label.as_bytes());
            h.update(counter.to_be_bytes());
            let d = h.finalize();
            let take = (N - off).min(32);
            out[off..off + take].copy_from_slice(&d[..take]);
            off += take;
            counter += 1;
        }
        out
    }

    struct Ctx {
        fkek: [u8; 32],
        dek: [u8; DEK_LEN],
        wrap_nonce: [u8; WRAP_NONCE_LEN],
        prefix: [u8; STREAM_NONCE_PREFIX_LEN],
        nonce16: [u8; 16],
        prev: [u8; 32],
        signer: SigningKey,
    }

    impl Ctx {
        fn new() -> Self {
            Self {
                fkek: fixture_bytes("fkek-gen-1"),
                dek: fixture_bytes("dek-snapshot-1"),
                wrap_nonce: fixture_bytes("wrap-nonce-1"),
                prefix: fixture_bytes("stream-prefix-1"),
                nonce16: fixture_bytes("envelope-context-nonce-1"),
                prev: fixture_bytes("prev-head-1"),
                signer: SigningKey::from_bytes(&fixture_bytes::<32>("snapshot-signer")),
            }
        }

        fn secrets(&self) -> BackupSecrets<'_> {
            BackupSecrets {
                fkek: &self.fkek,
                dek: &self.dek,
                wrap_nonce: &self.wrap_nonce,
                stream_nonce_prefix: &self.prefix,
            }
        }

        fn params(&self, genesis: bool) -> BackupParams<'_> {
            let vk = self.signer.verifying_key().to_bytes();
            BackupParams {
                ids: IntentIds {
                    snapshot_id: fixture_bytes("snapshot-1"),
                    tenant_id: fixture_bytes("tenant-a"),
                    fleet_id: fixture_bytes("fleet-a"),
                    profile_id: fixture_bytes("profile-a"),
                    lease_id: fixture_bytes("lease-1"),
                    manifest_replay_id: fixture_bytes("manifest-replay-1"),
                    server_instance_id: fixture_bytes("server-1"),
                    fkek_key_id: root_key_id(&self.fkek),
                    intended_signer_signing_key_id: signing_key_id(&vk),
                },
                key_generation: 1,
                target_version: if genesis { 1 } else { 5 },
                base_version: if genesis { 0 } else { 4 },
                fencing_token: if genesis { 1 } else { 42 },
                restore_epoch: 7,
                created_at_ms: 1_756_000_000_000,
                envelope_context_nonce: &self.nonce16,
                previous_signed_head_hash: if genesis { None } else { Some(&self.prev) },
            }
        }

        fn key_id(&self) -> [u8; 32] {
            signing_key_id(&self.signer.verifying_key().to_bytes())
        }

        fn seal_bytes(&self, pt: &[u8]) -> (Vec<u8>, SealOutcome) {
            let mut out = Vec::new();
            let o = seal(
                &mut &pt[..],
                &mut out,
                &self.params(false),
                &self.secrets(),
                &self.signer,
            )
            .expect("seal");
            (out, o)
        }

        fn open_bytes(&self, container: &[u8]) -> Result<(Vec<u8>, OpenOutcome)> {
            let mut plain = Vec::new();
            let o = open(&mut &container[..], &mut plain, &self.fkek, &self.key_id())?;
            Ok((plain, o))
        }
    }

    #[test]
    fn roundtrip_recovers_exact_plaintext() {
        let c = Ctx::new();
        for size in [0usize, 1, 100, 65535, 65536, 65537, 200_000] {
            let pt: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let (container, sealed) = c.seal_bytes(&pt);
            let (recovered, opened) = c.open_bytes(&container).expect("open");
            assert_eq!(recovered, pt, "size {size} must round-trip byte-for-byte");
            assert_eq!(sealed.plaintext_len, size as u64);
            assert_eq!(opened.plaintext_len, size as u64);
            assert_eq!(sealed.frame_count, opened.frame_count);
            assert_eq!(sealed.intent_hash, opened.intent_hash);
            assert_eq!(sealed.signed_head_hash, opened.signed_head_hash);
        }
    }

    #[test]
    fn frame_count_matches_plaintext_size() {
        let c = Ctx::new();
        // Exact multiples must not emit a spurious extra frame.
        assert_eq!(c.seal_bytes(&[]).1.frame_count, 1);
        assert_eq!(c.seal_bytes(&vec![7u8; 65536]).1.frame_count, 1);
        assert_eq!(c.seal_bytes(&vec![7u8; 65537]).1.frame_count, 2);
        assert_eq!(c.seal_bytes(&vec![7u8; 131_072]).1.frame_count, 2);
    }

    #[test]
    fn container_starts_with_magic_and_is_not_gzip() {
        let (c, _) = Ctx::new().seal_bytes(b"hello");
        assert_eq!(&c[..8], MAGIC);
        // A v1 reader keys off gzip's magic; v2 must not collide with it.
        assert_ne!(&c[..2], &[0x1f, 0x8b]);
    }

    #[test]
    fn wrong_fkek_fails_to_unwrap() {
        let c = Ctx::new();
        let (container, _) = c.seal_bytes(b"secret");
        let wrong: [u8; 32] = fixture_bytes("fkek-gen-2");
        let mut out = Vec::new();
        assert!(matches!(
            open(&mut &container[..], &mut out, &wrong, &c.key_id()),
            Err(BackupError::KeyUnwrapFailed)
        ));
    }

    #[test]
    fn wrong_signer_is_rejected() {
        let c = Ctx::new();
        let (container, _) = c.seal_bytes(b"secret");
        let other = SigningKey::from_bytes(&fixture_bytes::<32>("other-signer"));
        let other_id = signing_key_id(&other.verifying_key().to_bytes());
        let mut out = Vec::new();
        assert!(matches!(
            open(&mut &container[..], &mut out, &c.fkek, &other_id),
            Err(BackupError::SignatureInvalid)
        ));
    }

    #[test]
    fn every_single_byte_mutation_is_detected() {
        // Walk the whole container rather than sampling: a gap here is exactly
        // where a forgery would live. `open` streams, so a mutation may emit
        // bytes before failing — the contract is that it must still return Err,
        // which is why callers must not promote a partial output.
        let c = Ctx::new();
        let (container, _) = c.seal_bytes(b"the quick brown fox");
        for i in 0..container.len() {
            let mut m = container.clone();
            m[i] ^= 0x01;
            assert!(
                c.open_bytes(&m).is_err(),
                "mutation at byte {i} was not detected"
            );
        }
    }

    #[test]
    fn truncation_at_any_length_is_detected() {
        let c = Ctx::new();
        let (container, _) = c.seal_bytes(&vec![3u8; 200_000]);
        for cut in (0..container.len()).step_by(97) {
            assert!(
                c.open_bytes(&container[..cut]).is_err(),
                "truncation to {cut} bytes was not detected"
            );
        }
    }

    /// Offset of the first frame: after magic and the two length-prefixed
    /// prologue records. Computed from the container rather than hardcoded, so
    /// the test still targets a real frame if the prologue grows.
    fn first_frame_offset(container: &[u8]) -> usize {
        let rd = |at: usize| -> usize {
            u32::from_be_bytes(container[at..at + 4].try_into().unwrap()) as usize
        };
        let slot_len = rd(MAGIC.len());
        let intent_at = MAGIC.len() + 4 + slot_len;
        let intent_len = rd(intent_at);
        intent_at + 4 + intent_len
    }

    #[test]
    fn cross_envelope_frame_splice_is_rejected() {
        // Two envelopes over identical plaintext, differing only in intent:
        // a frame lifted from one must not authenticate in the other. The
        // prologue is byte-identical here, so the splice has to target the
        // frame region to be a real test of frame binding.
        let c = Ctx::new();
        let pt = vec![9u8; 130_000];
        let (a, _) = c.seal_bytes(&pt);

        let mut p = c.params(false);
        p.target_version = 6;
        p.base_version = 5;
        let mut b = Vec::new();
        seal(&mut &pt[..], &mut b, &p, &c.secrets(), &c.signer).expect("seal b");
        assert_ne!(a, b, "different intents must produce different containers");

        // Splice the ENTIRE first frame, tag included. Splicing only the body
        // would prove nothing: ChaCha20 keystream does not depend on the AAD,
        // so the ciphertext bytes are identical across envelopes and only the
        // Poly1305 tag carries the intent binding.
        let off = first_frame_offset(&a);
        assert_eq!(off, first_frame_offset(&b), "prologues must be same length");
        let frame_len = {
            let len = u32::from_be_bytes(a[off + 1..off + 5].try_into().unwrap()) as usize;
            1 + 4 + len
        };
        assert_ne!(
            a[off..off + frame_len],
            b[off..off + frame_len],
            "frames must differ, or the splice proves nothing"
        );

        b[off..off + frame_len].copy_from_slice(&a[off..off + frame_len]);
        assert!(
            c.open_bytes(&b).is_err(),
            "cross-envelope frame splice must not authenticate"
        );
    }

    #[test]
    fn genesis_backup_omits_previous_head() {
        let c = Ctx::new();
        let mut out = Vec::new();
        seal(
            &mut &b"genesis"[..],
            &mut out,
            &c.params(true),
            &c.secrets(),
            &c.signer,
        )
        .expect("genesis seal");
        let (recovered, _) = c.open_bytes(&out).expect("open genesis");
        assert_eq!(recovered, b"genesis");
    }

    #[test]
    fn non_sequential_version_is_rejected_before_any_output() {
        let c = Ctx::new();
        let mut p = c.params(false);
        p.target_version = 9;
        p.base_version = 4;
        let mut out = Vec::new();
        assert!(matches!(
            seal(&mut &b"x"[..], &mut out, &p, &c.secrets(), &c.signer),
            Err(BackupError::Intent(_))
        ));
        // Nothing may be written for a rejected intent.
        assert!(out.is_empty(), "no bytes may be emitted for a bad intent");
    }

    #[test]
    fn bad_magic_is_rejected() {
        let c = Ctx::new();
        let mut out = Vec::new();
        assert!(matches!(
            open(
                &mut &b"not a backup at all"[..],
                &mut out,
                &c.fkek,
                &c.key_id()
            ),
            Err(BackupError::BadMagic)
        ));
    }

    #[test]
    fn oversized_length_prefix_is_refused_without_allocating() {
        // A header claiming 4 GiB must be refused on the declared length.
        let c = Ctx::new();
        let mut hostile = Vec::from(&MAGIC[..]);
        hostile.extend_from_slice(&u32::MAX.to_be_bytes());
        let mut out = Vec::new();
        assert!(matches!(
            open(&mut &hostile[..], &mut out, &c.fkek, &c.key_id()),
            Err(BackupError::SizeLimitExceeded { .. })
        ));
    }

    #[test]
    fn sealing_is_deterministic_for_fixed_inputs() {
        let c = Ctx::new();
        let (a, _) = c.seal_bytes(b"determinism");
        let (b, _) = c.seal_bytes(b"determinism");
        assert_eq!(a, b, "same inputs must produce identical container bytes");
    }

    #[test]
    fn v1_snapshot_bytes_survive_a_v2_round_trip() {
        // The v2 layer must be transparent to whatever v1 produced: this is the
        // compatibility seam that lets an encrypted backup restore through the
        // existing unpack path.
        let c = Ctx::new();
        let gzip_like: Vec<u8> = {
            let mut v = vec![0x1f, 0x8b, 0x08, 0x00];
            v.extend((0..100_000u32).map(|i| (i % 256) as u8));
            v
        };
        let (container, _) = c.seal_bytes(&gzip_like);
        let (recovered, _) = c.open_bytes(&container).expect("open");
        assert_eq!(recovered, gzip_like);
    }
}
