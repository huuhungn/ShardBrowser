//! Ed25519 signing identity and signed-container assembly for ShardX v0.2.
//!
//! Two invariants carry the security of every authorization, manifest and
//! transition record:
//!
//!   * **Domain-separated signing input.** A signature is never computed over
//!     bare canonical bytes. The input is
//!     `"SHARDX-SIGNED-RECORD-V2\0" + u32be(len(TBS)) + TBS`, so a payload
//!     signed as one record type can never be replayed as another.
//!   * **Acyclic commitment order.** The to-be-signed bytes cover the record
//!     fields only. `signature_bytes` is added afterwards to form the container
//!     core, and `signed_container_hash` is computed over that core — so
//!     nothing ever commits to a hash of itself.
//!
//! Verification is strict: exact 64-byte signatures, exact 32-byte public keys,
//! and non-canonical key encodings are rejected rather than coerced.
//!
//! Values here were validated byte-for-byte by the G2 conformance gate; the
//! golden vectors in the test module are pinned from that gate's report.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

// The caller needs these types to hold a signing identity and to check one, so
// they are part of this module's public surface rather than an internal detail.
pub use ed25519_dalek::{SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey};

use crate::canonical::{self as c, Value};
use crate::keys::signing_key_id;

/// `signature_suite_id` — Ed25519 (RFC 8032) with strict parsing.
pub const SIGNATURE_SUITE_ID_ED25519: u16 = 1;
/// `signature_version` for the pinned suite profile.
pub const SIGNATURE_VERSION: u16 = 1;
/// Exact Ed25519 signature length, within the `signature_bytes` bound (1, 4096).
pub const ED25519_SIG_LEN: usize = 64;

#[derive(Debug, PartialEq, Eq)]
pub enum SignError {
    /// Signature did not verify. Carries no detail by design.
    Signature,
    BadLength {
        field: &'static str,
        got: usize,
    },
    NonCanonicalKeyEncoding,
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Signature => write!(f, "signature verification failed"),
            Self::BadLength { field, got } => write!(f, "invalid length for {field}: got {got}"),
            Self::NonCanonicalKeyEncoding => write!(f, "non-canonical public key encoding"),
        }
    }
}

impl std::error::Error for SignError {}

// ------------------------------------------------------- signing contract ---

/// `authorization_tbs_bytes` signature input:
/// ASCII `SHARDX-SIGNED-RECORD-V2\0` + u32be(len(TBS)) + exact TBS bytes.
///
/// The length prefix makes the preimage unambiguous; the label prevents a
/// signature from being valid under a different record domain.
pub fn signed_record_signing_input(tbs_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(c::L_SIGNED_RECORD.len() + 4 + tbs_bytes.len());
    out.extend_from_slice(c::L_SIGNED_RECORD.as_bytes());
    out.extend_from_slice(&(tbs_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(tbs_bytes);
    out
}

pub fn sign_tbs(sk: &SigningKey, tbs_bytes: &[u8]) -> [u8; ED25519_SIG_LEN] {
    sk.sign(&signed_record_signing_input(tbs_bytes)).to_bytes()
}

/// Strict verification: exact 64-byte signature, exact 32-byte public key.
pub fn verify_tbs(vk_bytes: &[u8], tbs_bytes: &[u8], sig_bytes: &[u8]) -> Result<(), SignError> {
    verify_message_strict(vk_bytes, &signed_record_signing_input(tbs_bytes), sig_bytes)
}

/// Ed25519 (RFC 8032, pure) under `verify_strict`, the suite-1 rule (ADR 0002
/// D-8): small-order public keys and `R`, non-canonical encodings and `S >= L`
/// are rejected. Every ShardX verifier uses this one rule, so a signature
/// accepted on one device is accepted on all; other Ed25519 verifiers (cofactored,
/// ZIP-215) may disagree on edge cases such as speccheck case 4.
pub(crate) fn verify_message_strict(
    vk_bytes: &[u8],
    msg: &[u8],
    sig_bytes: &[u8],
) -> Result<(), SignError> {
    let vk_arr: [u8; 32] = vk_bytes.try_into().map_err(|_| SignError::BadLength {
        field: "verifying_key",
        got: vk_bytes.len(),
    })?;
    let sig_arr: [u8; ED25519_SIG_LEN] =
        sig_bytes.try_into().map_err(|_| SignError::BadLength {
            field: "signature_bytes",
            got: sig_bytes.len(),
        })?;
    let vk = VerifyingKey::from_bytes(&vk_arr).map_err(|_| SignError::NonCanonicalKeyEncoding)?;
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify_strict(msg, &sig)
        .map_err(|_| SignError::Signature)
}

/// Key ID of a signing identity, as embedded in `issuer_signing_key_id`.
pub fn identity_key_id(vk: &VerifyingKey) -> [u8; 32] {
    signing_key_id(vk.as_bytes())
}

// ---------------------------------------------- signed container assembly ---

/// A fully assembled signed container, exposing every byte string a caller may
/// legitimately need to persist, hash or transmit.
pub struct SignedContainer {
    /// Exact to-be-signed bytes (record fields only).
    pub tbs_bytes: Vec<u8>,
    /// TBS fields plus `signature_bytes`.
    pub core_bytes: Vec<u8>,
    /// `domain_hash(SHARDX-SIGNED-CONTAINER-V2, core_bytes)`.
    pub signed_container_hash: [u8; 32],
    /// Core fields plus `signed_container_hash` — the on-wire container.
    pub exact_bytes: Vec<u8>,
    pub exact_bytes_sha256: [u8; 32],
    pub signature_bytes: Vec<u8>,
}

/// Builds `SignedAuthorizationRecordV2`-shaped containers (also used for the
/// manifest and transition containers, which share the exact construction with
/// different field names).
///
/// `tbs_fields` are the record fields from `container_domain` through
/// `issuer_signing_key_id` — never `signature_bytes` or `signed_container_hash`,
/// which this function appends in the fixed order that keeps commitment acyclic.
pub fn build_signed_container(sk: &SigningKey, tbs_fields: Vec<(&str, Value)>) -> SignedContainer {
    let tbs_bytes = c::encode(&c::m(tbs_fields.clone()));

    let signature = sign_tbs(sk, &tbs_bytes);

    let mut core_fields = tbs_fields;
    core_fields.push(("signature_bytes", c::b(&signature)));
    let core_bytes = c::encode(&c::m(core_fields.clone()));

    let signed_container_hash = c::domain_hash(c::L_SIGNED_CONTAINER, &core_bytes);

    let mut outer_fields = core_fields;
    outer_fields.push(("signed_container_hash", c::b(&signed_container_hash)));
    let exact_bytes = c::encode(&c::m(outer_fields));
    let exact_bytes_sha256 = c::sha256(&exact_bytes);

    SignedContainer {
        tbs_bytes,
        core_bytes,
        signed_container_hash,
        exact_bytes,
        exact_bytes_sha256,
        signature_bytes: signature.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn keypair(seed_label: &str) -> SigningKey {
        SigningKey::from_bytes(&fixture_bytes::<32>(seed_label))
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 8032 section 7.1, TEST 1 to 3: (secret key, public key, message, signature).
    const RFC8032_VECTORS: [(&str, &str, &str, &str); 3] = [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
        (
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
    ];

    #[test]
    fn rfc8032_vectors_sign_and_verify_strictly() {
        for (sk, pk, msg, sig) in RFC8032_VECTORS {
            let key = SigningKey::from_bytes(&unhex(sk).try_into().unwrap());
            assert_eq!(key.verifying_key().as_bytes().to_vec(), unhex(pk));
            assert_eq!(key.sign(&unhex(msg)).to_bytes().to_vec(), unhex(sig));
            assert_eq!(
                verify_message_strict(&unhex(pk), &unhex(msg), &unhex(sig)),
                Ok(())
            );
            let mut bad = unhex(sig);
            bad[0] ^= 1;
            assert_eq!(
                verify_message_strict(&unhex(pk), &unhex(msg), &bad),
                Err(SignError::Signature)
            );
        }
    }

    /// The 12 edge cases of "Taming the many EdDSAs" (novifinancial/ed25519-speccheck
    /// `cases.json`, SHA-256
    /// 08e47a36d9aead288664930505584f353fff113ab854f2800db1e4f5b3540450): (message, public key, signature).
    /// Under `verify_strict` only case 3 verifies; the others cover small-order
    /// `A` and `R`, `S >= L`, and non-canonical `R` and `A`.
    const SPECCHECK_CASES: [(&str, &str, &str); 12] = [
        ("8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000"),
        ("9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04"),
        ("aebf3f2601a0c8c5d39cc7d8911642f740b78168218da8471772b35f9d35b9ab", "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa8c4bd45aecaca5b24fb97bc10ac27ac8751a7dfe1baff8b953ec9f5833ca260e"),
        ("9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79", "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d", "9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009"),
        ("e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c", "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d", "160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed5125ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09"),
        ("e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c", "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d", "21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405"),
        ("85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40", "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623", "e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e547f7690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514"),
        ("85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40", "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623", "8ce5b96c8f26d0ab6c47958c9e68b937104cd36e13c33566acd2fe8d38aa19427e71f98a473474f2f13f06f97c20d58cc3f54b8bd0d272f42b695dd7e89a8c22"),
        ("9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41", "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03be9678ac102edcd92b0210bb34d7428d12ffc5df5f37e359941266a4e35f0f"),
        ("9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41", "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffca8c5b64cd208982aa38d4936621a4775aa233aa0505711d8fdcfdaa943d4908"),
        ("e96b7021eb39c1a163b6da4e3093dcd3f21387da4cc4572be588fafae23c155b", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04"),
        ("39a591f5321bbe07fd5a23dc2f39d025d74526615746727ceefd6e82ae65c06f", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04"),
    ];

    #[test]
    fn speccheck_matrix_accepts_only_the_unambiguous_case() {
        for (i, (msg, pk, sig)) in SPECCHECK_CASES.iter().enumerate() {
            let got = verify_message_strict(&unhex(pk), &unhex(msg), &unhex(sig));
            assert_eq!(got.is_ok(), i == 3, "speccheck case {i}: {got:?}");
        }
    }

    #[test]
    fn small_order_public_key_is_refused_for_any_record() {
        // A = R = the identity point and S = 0 satisfy [S]B = R + [k]A for
        // every message, so plain `verify` accepts this one signature for any
        // record. `verify_strict` must refuse it.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let mut sig = [0u8; ED25519_SIG_LEN];
        sig[..32].copy_from_slice(&identity);
        for tbs in [&b"one record"[..], b"another record"] {
            assert_eq!(verify_tbs(&identity, tbs, &sig), Err(SignError::Signature));
        }
    }

    #[test]
    fn suite_constants_are_pinned() {
        assert_eq!(SIGNATURE_SUITE_ID_ED25519, 1);
        assert_eq!(SIGNATURE_VERSION, 1);
        assert_eq!(ED25519_SIG_LEN, 64);
    }

    #[test]
    fn signing_input_is_domain_and_length_prefixed() {
        let input = signed_record_signing_input(b"abc");
        let mut expected = Vec::new();
        expected.extend_from_slice(b"SHARDX-SIGNED-RECORD-V2\0");
        expected.extend_from_slice(&3u32.to_be_bytes());
        expected.extend_from_slice(b"abc");
        assert_eq!(input, expected);

        // Different splits of the same concatenation must not collide.
        assert_ne!(
            signed_record_signing_input(b"ab"),
            signed_record_signing_input(b"abc")
        );
    }

    #[test]
    fn sign_verify_roundtrips() {
        let sk = keypair("snapshot-signer");
        let vk = sk.verifying_key();
        let tbs = b"exact canonical tbs bytes";
        let sig = sign_tbs(&sk, tbs);
        assert_eq!(sig.len(), ED25519_SIG_LEN);
        assert_eq!(verify_tbs(vk.as_bytes(), tbs, &sig), Ok(()));
    }

    #[test]
    fn verify_rejects_mutated_tbs() {
        let sk = keypair("snapshot-signer");
        let vk = sk.verifying_key();
        let sig = sign_tbs(&sk, b"original tbs");
        assert_eq!(
            verify_tbs(vk.as_bytes(), b"modified tbs", &sig),
            Err(SignError::Signature)
        );
    }

    #[test]
    fn verify_rejects_mutated_signature_bytes() {
        let sk = keypair("snapshot-signer");
        let vk = sk.verifying_key();
        let tbs = b"exact canonical tbs bytes";
        let mut sig = sign_tbs(&sk, tbs);
        // Flip a bit in the signature itself, not the payload.
        sig[0] ^= 0x01;
        assert_eq!(
            verify_tbs(vk.as_bytes(), tbs, &sig),
            Err(SignError::Signature)
        );

        let mut sig2 = sign_tbs(&sk, tbs);
        let last = sig2.len() - 1;
        sig2[last] ^= 0x80;
        assert_eq!(
            verify_tbs(vk.as_bytes(), tbs, &sig2),
            Err(SignError::Signature)
        );
    }

    #[test]
    fn verify_rejects_wrong_signer() {
        let sk = keypair("snapshot-signer");
        let other = keypair("other-signer");
        let tbs = b"exact canonical tbs bytes";
        let sig = sign_tbs(&sk, tbs);
        assert_eq!(
            verify_tbs(other.verifying_key().as_bytes(), tbs, &sig),
            Err(SignError::Signature)
        );
    }

    #[test]
    fn verify_rejects_bad_lengths() {
        let sk = keypair("snapshot-signer");
        let vk = sk.verifying_key();
        let tbs = b"exact canonical tbs bytes";
        let sig = sign_tbs(&sk, tbs);

        assert_eq!(
            verify_tbs(&vk.as_bytes()[..31], tbs, &sig),
            Err(SignError::BadLength {
                field: "verifying_key",
                got: 31
            })
        );
        assert_eq!(
            verify_tbs(vk.as_bytes(), tbs, &sig[..63]),
            Err(SignError::BadLength {
                field: "signature_bytes",
                got: 63
            })
        );
    }

    #[test]
    fn signing_input_domain_differs_from_container_domain() {
        // A record signature must not be valid over a container preimage.
        assert_ne!(c::L_SIGNED_RECORD, c::L_SIGNED_CONTAINER);
    }

    #[test]
    fn container_commitment_is_acyclic() {
        let sk = keypair("snapshot-signer");
        let container = build_signed_container(
            &sk,
            vec![
                ("container_domain", c::t("shardx.auth.record.v2")),
                ("version", c::u(2)),
            ],
        );

        // TBS must not contain the signature, and the core must not contain the
        // container hash — otherwise a field would commit to a hash of itself.
        assert!(!container
            .tbs_bytes
            .windows(container.signature_bytes.len())
            .any(|w| w == container.signature_bytes.as_slice()));
        assert!(!container
            .core_bytes
            .windows(32)
            .any(|w| w == container.signed_container_hash));
        // The outer bytes do carry both.
        assert!(container
            .exact_bytes
            .windows(32)
            .any(|w| w == container.signed_container_hash));

        // And the signature actually verifies over the TBS bytes.
        assert_eq!(
            verify_tbs(
                sk.verifying_key().as_bytes(),
                &container.tbs_bytes,
                &container.signature_bytes
            ),
            Ok(())
        );
    }

    /// Pinned from the G2 report, probes `G2-VEC-auth-payload`,
    /// `G2-VEC-signed-container-hash` and `G2-VEC-signed-container`.
    /// Reproduces the gate's `SignedAuthorizationRecordV2` exactly: the nine
    /// pre-signature fields, in the plan's field set. Any change to the field
    /// set or the assembly sequence changes these hashes.
    #[test]
    fn g2_golden_vector_signed_container_hash() {
        let sk = keypair("issuer-signing-key");
        let vk = sk.verifying_key();

        let payload_bytes = c::encode(&c::m(vec![
            ("domain", c::t("shardx.authorization.device-enrollment.v2")),
            ("version", c::u(2)),
            ("tenant_id", c::b(&fixture_bytes::<16>("tenant-a"))),
            ("device_id", c::b(&fixture_bytes::<16>("device-a"))),
            ("server_instance_id", c::b(&fixture_bytes::<16>("server-1"))),
            ("restore_epoch", c::u(7)),
        ]));
        let payload_sha256 = c::sha256(&payload_bytes);
        assert_eq!(
            hex32(&payload_sha256),
            "44fe61fe61e434009456550622718c9dd3e4f8a40128543d49b28effc7191412",
            "authorization payload diverged from G2-pinned vector"
        );

        let container = build_signed_container(
            &sk,
            vec![
                (
                    "container_domain",
                    c::t("shardx.authorization.signed-container.v2"),
                ),
                ("container_version", c::u(2)),
                (
                    "payload_domain",
                    c::t("shardx.authorization.device-enrollment.v2"),
                ),
                ("payload_version", c::u(2)),
                ("canonical_payload_bytes", c::b(&payload_bytes)),
                ("payload_sha256", c::b(&payload_sha256)),
                (
                    "signature_suite_id",
                    c::u(SIGNATURE_SUITE_ID_ED25519 as u64),
                ),
                ("signature_version", c::u(SIGNATURE_VERSION as u64)),
                ("issuer_signing_key_id", c::b(&identity_key_id(&vk))),
            ],
        );

        assert_eq!(
            hex32(&container.signed_container_hash),
            "93c5409668ec3a58151913f7e236855d9c9524cf75a4d52b9e0dc999b6cb5500",
            "signed_container_hash diverged from the G2-pinned golden vector"
        );
        assert_eq!(
            hex32(&container.exact_bytes_sha256),
            "78aa38d3c6fe96592c69d43aa787409f6a836b950e8b991a62265157c5d97dbc",
            "exact container bytes diverged from the G2-pinned golden vector"
        );
    }
}
