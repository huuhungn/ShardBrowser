//! Key material and key identity for ShardX v0.2 encrypted profile backup.
//!
//! Three responsibilities, deliberately kept in one place so the invariants are
//! visible together:
//!
//!   * **Suite pinning.** Numeric suite/registry IDs and exact lengths that the
//!     wire schema commits to. These are not tunables — changing one changes
//!     bytes that signatures and AEAD tags authenticate.
//!   * **Key identity.** `*_key_id` derivations are domain-separated per role,
//!     so the same raw bytes used as a signing key and as an HPKE key can never
//!     produce the same identifier.
//!   * **DEK wrapping.** The per-snapshot data encryption key is wrapped under
//!     the fleet key-encryption key with the EXACT canonical `DekSlotContextV2`
//!     bytes as associated data — never a reconstructed map.
//!
//! Secret material is held in [`Zeroizing`] wrappers so it is scrubbed on drop,
//! and no secret type implements `Debug`.
//!
//! Values here were validated byte-for-byte by the G2 conformance gate; the
//! golden vectors in the test module are pinned from that gate's report.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use zeroize::Zeroizing;

use crate::canonical as c;

// ---------------------------------------------------------- pinned suites ---

/// `envelope_suite_id` — STREAM AEAD over ChaCha20-Poly1305 (IETF, 96-bit nonce).
pub const ENVELOPE_SUITE_ID_CHACHA20POLY1305_STREAM: u16 = 1;
/// `wrap_suite_id` — DEK wrap under FKEK with ChaCha20-Poly1305.
pub const WRAP_SUITE_ID_CHACHA20POLY1305: u16 = 1;

/// RFC 9180 base mode tuple required by `TenantRootKeyGrantV2`:
/// `(mode, KEM, KDF, AEAD) = (0, 0x0020, 0x0001, 0x0003)`
/// = (base, DHKEM(X25519,HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305).
pub const HPKE_MODE_BASE: u16 = 0;
pub const HPKE_KEM_X25519_HKDF_SHA256: u16 = 0x0020;
pub const HPKE_KDF_HKDF_SHA256: u16 = 0x0001;
pub const HPKE_AEAD_CHACHA20POLY1305: u16 = 0x0003;

/// Suite-specific exact lengths, pinned inside the plan's fixed bounds.
pub const DEK_LEN: usize = 32;
/// Within the `wrap_nonce_bytes` bound of (1, 64).
pub const WRAP_NONCE_LEN: usize = 12;
/// Within the `stream_nonce_prefix` bound of (1, 64).
pub const STREAM_NONCE_PREFIX_LEN: usize = 7;
/// ChaCha20-Poly1305 authentication tag length.
pub const AEAD_TAG_LEN: usize = 16;

/// Key-identity domains. Distinct per role so raw bytes cannot collide across
/// key uses.
pub const L_SIGNING_KEY_ID: &str = "SHARDX-SIGNING-KEY-ID-V2\0";
pub const L_HPKE_KEY_ID: &str = "SHARDX-HPKE-KEY-ID-V2\0";
pub const L_TENANT_ROOT_KEY_ID: &str = "SHARDX-TENANT-ROOT-KEY-ID-V2\0";

// ----------------------------------------------------------------- errors ---

#[derive(Debug, PartialEq, Eq)]
pub enum KeyError {
    /// AEAD open failed: wrong key, wrong nonce, or tampered ciphertext/AAD.
    /// Deliberately carries no detail — distinguishing these leaks an oracle.
    Aead,
    BadLength {
        field: &'static str,
        got: usize,
    },
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aead => write!(f, "AEAD authentication failed"),
            Self::BadLength { field, got } => {
                write!(f, "invalid length for {field}: got {got}")
            }
        }
    }
}

impl std::error::Error for KeyError {}

// --------------------------------------------------------------- key IDs ----

/// Signing-key ID: domain-separated hash of the raw 32-byte public key.
pub fn signing_key_id(vk_bytes: &[u8; 32]) -> [u8; 32] {
    c::domain_hash(L_SIGNING_KEY_ID, vk_bytes)
}

/// HPKE-key ID: a DIFFERENT domain from signing, so one raw key used in both
/// roles never yields the same identifier.
pub fn hpke_key_id(pk_bytes: &[u8]) -> [u8; 32] {
    c::domain_hash(L_HPKE_KEY_ID, pk_bytes)
}

/// Deterministic `root_key_id` over the raw 32-byte tenant root key.
/// Plan 5.6.4: `SHA256("SHARDX-TENANT-ROOT-KEY-ID-V2\0" + u32be(32) + trk)`.
pub fn root_key_id(trk: &[u8; 32]) -> [u8; 32] {
    c::domain_hash(L_TENANT_ROOT_KEY_ID, trk)
}

// ---------------------------------------------------------- DEK wrapping ----

/// Wrap the per-snapshot DEK under the FKEK.
///
/// `context_bytes` MUST be the exact canonical `DekSlotContextV2` encoding that
/// will be stored alongside the slot — not a re-derived map. Binding the wrap to
/// those literal bytes is what stops a slot being replayed into a different
/// tenant, fleet, profile or key generation.
pub fn wrap_dek(
    fkek: &[u8; 32],
    nonce: &[u8; WRAP_NONCE_LEN],
    dek: &[u8; DEK_LEN],
    context_bytes: &[u8],
) -> Result<Vec<u8>, KeyError> {
    let cipher = ChaCha20Poly1305::new(&(*fkek).into());
    cipher
        .encrypt(
            &(*nonce).into(),
            Payload {
                msg: dek,
                aad: context_bytes,
            },
        )
        .map_err(|_| KeyError::Aead)
}

/// Unwrap a DEK. Returns zeroizing key material; fails closed on any mismatch
/// of key, nonce, ciphertext or associated context bytes.
pub fn unwrap_dek(
    fkek: &[u8; 32],
    nonce: &[u8; WRAP_NONCE_LEN],
    wrapped: &[u8],
    context_bytes: &[u8],
) -> Result<Zeroizing<[u8; DEK_LEN]>, KeyError> {
    let cipher = ChaCha20Poly1305::new(&(*fkek).into());
    let pt = Zeroizing::new(
        cipher
            .decrypt(
                &(*nonce).into(),
                Payload {
                    msg: wrapped,
                    aad: context_bytes,
                },
            )
            .map_err(|_| KeyError::Aead)?,
    );
    let arr: [u8; DEK_LEN] = pt.as_slice().try_into().map_err(|_| KeyError::BadLength {
        field: "dek",
        got: pt.len(),
    })?;
    Ok(Zeroizing::new(arr))
}

/// Fill `out` with OS entropy.
///
/// Callers generate key seeds with this rather than reaching for a random
/// source of their own. Uses the unconditional `getrandom` 0.4 dependency:
/// the 0.2 one is Windows-only here, and key generation is not.
///
/// A failure means the OS entropy source is unavailable. That is not
/// recoverable and must never fall back to a weaker source.
pub fn fill_random(out: &mut [u8]) -> Result<(), getrandom04::Error> {
    getrandom04::fill(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(h: &[u8; 32]) -> String {
        h.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Byte-identical to the G2 gate's fixture generator so pinned vectors
    /// reproduce. Fixture material only — never a key-generation strategy.
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

    /// Rebuilds the exact plan 5.6.3 `DekSlotContextV2` map used by the G2 gate.
    fn g2_context_bytes() -> Vec<u8> {
        let fkek: [u8; 32] = fixture_bytes("fkek-gen-1");
        let context = c::m(vec![
            ("domain", c::t("shardx.envelope.dek-slot-context.v2")),
            ("version", c::u(2)),
            ("slot_index", c::u(0)),
            ("tenant_id", c::b(&fixture_bytes::<16>("tenant-a"))),
            ("fleet_id", c::b(&fixture_bytes::<16>("fleet-a"))),
            ("profile_id", c::b(&fixture_bytes::<16>("profile-a"))),
            ("snapshot_id", c::b(&fixture_bytes::<16>("snapshot-1"))),
            ("fkek_key_id", c::b(&root_key_id(&fkek))),
            ("key_generation", c::u(1)),
            ("wrap_suite_id", c::u(WRAP_SUITE_ID_CHACHA20POLY1305 as u64)),
            (
                "envelope_context_nonce",
                c::b(&fixture_bytes::<16>("envelope-context-nonce-1")),
            ),
        ]);
        c::encode(&context)
    }

    // ------------------------------------------------------ suite pinning ---

    #[test]
    fn rfc9180_base_mode_tuple_is_pinned() {
        assert_eq!(HPKE_MODE_BASE, 0);
        assert_eq!(HPKE_KEM_X25519_HKDF_SHA256, 0x0020);
        assert_eq!(HPKE_KDF_HKDF_SHA256, 0x0001);
        assert_eq!(HPKE_AEAD_CHACHA20POLY1305, 0x0003);
    }

    #[test]
    fn suite_lengths_are_pinned() {
        assert_eq!(DEK_LEN, 32);
        assert_eq!(WRAP_NONCE_LEN, 12);
        assert_eq!(STREAM_NONCE_PREFIX_LEN, 7);
        assert_eq!(AEAD_TAG_LEN, 16);
        assert_eq!(ENVELOPE_SUITE_ID_CHACHA20POLY1305_STREAM, 1);
        assert_eq!(WRAP_SUITE_ID_CHACHA20POLY1305, 1);
    }

    // --------------------------------------------------------- key IDs -----

    #[test]
    fn key_id_domains_are_role_separated() {
        // The same raw bytes in different roles must never collide.
        let raw = [0x42u8; 32];
        let a = signing_key_id(&raw);
        let b = hpke_key_id(&raw);
        let c_id = root_key_id(&raw);
        assert_ne!(a, b);
        assert_ne!(a, c_id);
        assert_ne!(b, c_id);
    }

    /// Pinned from the G2 report, probe `G2-VEC-root-key-id`. The input is the
    /// tenant root key, which is a distinct key role from the fleet KEK.
    #[test]
    fn g2_golden_vector_root_key_id() {
        let trk: [u8; 32] = fixture_bytes("tenant-root-key-gen1");
        assert_eq!(
            hex32(&root_key_id(&trk)),
            "a9ff431ad94588073a79aeea593edfe8819917f13249a867d70aef982ee12b7d",
            "root_key_id diverged from the G2-pinned golden vector"
        );
    }

    // ----------------------------------------------------- DEK wrapping ----

    #[test]
    fn wrap_unwrap_roundtrips() {
        let fkek: [u8; 32] = fixture_bytes("fkek-gen-1");
        let dek: [u8; DEK_LEN] = fixture_bytes("dek-snapshot-1");
        let nonce: [u8; WRAP_NONCE_LEN] = fixture_bytes("wrap-nonce-1");
        let ctx = g2_context_bytes();

        let wrapped = wrap_dek(&fkek, &nonce, &dek, &ctx).expect("wrap");
        // Ciphertext is DEK length plus the AEAD tag.
        assert_eq!(wrapped.len(), DEK_LEN + AEAD_TAG_LEN);
        // The plaintext DEK must not appear verbatim in the ciphertext.
        assert!(!wrapped.windows(DEK_LEN).any(|w| w == dek));

        let out = unwrap_dek(&fkek, &nonce, &wrapped, &ctx).expect("unwrap");
        assert_eq!(*out, dek);
    }

    #[test]
    fn unwrap_fails_closed_on_tampered_context() {
        let fkek: [u8; 32] = fixture_bytes("fkek-gen-1");
        let dek: [u8; DEK_LEN] = fixture_bytes("dek-snapshot-1");
        let nonce: [u8; WRAP_NONCE_LEN] = fixture_bytes("wrap-nonce-1");
        let ctx = g2_context_bytes();
        let wrapped = wrap_dek(&fkek, &nonce, &dek, &ctx).expect("wrap");

        // Flip one byte of the AAD: this is the cross-tenant replay defence.
        let mut bad_ctx = ctx.clone();
        let last = bad_ctx.len() - 1;
        bad_ctx[last] ^= 0x01;
        assert_eq!(
            unwrap_dek(&fkek, &nonce, &wrapped, &bad_ctx).err(),
            Some(KeyError::Aead)
        );
    }

    #[test]
    fn unwrap_fails_closed_on_wrong_key_nonce_or_ciphertext() {
        let fkek: [u8; 32] = fixture_bytes("fkek-gen-1");
        let dek: [u8; DEK_LEN] = fixture_bytes("dek-snapshot-1");
        let nonce: [u8; WRAP_NONCE_LEN] = fixture_bytes("wrap-nonce-1");
        let ctx = g2_context_bytes();
        let wrapped = wrap_dek(&fkek, &nonce, &dek, &ctx).expect("wrap");

        let other_fkek: [u8; 32] = fixture_bytes("fkek-gen-2");
        assert_eq!(
            unwrap_dek(&other_fkek, &nonce, &wrapped, &ctx).err(),
            Some(KeyError::Aead)
        );

        let other_nonce: [u8; WRAP_NONCE_LEN] = fixture_bytes("wrap-nonce-0");
        assert_eq!(
            unwrap_dek(&fkek, &other_nonce, &wrapped, &ctx).err(),
            Some(KeyError::Aead)
        );

        let mut bad = wrapped.clone();
        bad[0] ^= 0x01;
        assert_eq!(
            unwrap_dek(&fkek, &nonce, &bad, &ctx).err(),
            Some(KeyError::Aead)
        );

        // Truncating into the tag must also fail, not silently short-read.
        let truncated = &wrapped[..wrapped.len() - 1];
        assert_eq!(
            unwrap_dek(&fkek, &nonce, truncated, &ctx).err(),
            Some(KeyError::Aead)
        );
    }

    #[test]
    fn distinct_generations_produce_distinct_wraps() {
        let dek: [u8; DEK_LEN] = fixture_bytes("dek-snapshot-1");
        let nonce: [u8; WRAP_NONCE_LEN] = fixture_bytes("wrap-nonce-1");
        let ctx = g2_context_bytes();

        let a = wrap_dek(&fixture_bytes("fkek-gen-1"), &nonce, &dek, &ctx).expect("wrap");
        let b = wrap_dek(&fixture_bytes("fkek-gen-2"), &nonce, &dek, &ctx).expect("wrap");
        assert_ne!(a, b);
    }

    /// Key seeds come from here; a source returning constant bytes would hand
    /// every device the same identity.
    #[test]
    fn fill_random_produces_varying_bytes() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill_random(&mut a).expect("os entropy");
        fill_random(&mut b).expect("os entropy");
        assert_ne!(a, b, "two draws must not be identical");
        assert_ne!(a, [0u8; 32], "must not return all zeroes");
    }
}
