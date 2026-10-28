//! G2-63: the numeric registry and the signing domains, checked together.
//!
//! Each module's golden vectors already pin its own bytes. What they cannot
//! see is a collision across modules: two roles signing under one domain, or
//! one domain label reused for two preimages, would let a record made for one
//! purpose verify as the other. This test holds every published domain and
//! label in one place and requires them to be distinct and well formed.
//! The reviewed values are recorded in docs/security-review-g2.md.

use shardx_core::{
    approval_receipt as ar, authz_record as az, canonical as c, envelope as ev, envelope_v2 as e2,
    fallback_key_file as fk, fleet_lifecycle as fl, fleet_manifest as fm, grants as gr, keys as k,
    mutation as mu, recovery_bundle as rb, session_binding as sb, signing as sg,
    trust_evidence as te,
};

const DOMAINS: &[&str] = &[
    ar::DOMAIN_DEVICE_APPROVAL_RECEIPT,
    az::CONTAINER_DOMAIN,
    az::DOMAIN_DEVICE_APPROVAL,
    az::DOMAIN_TENANT_CAPABILITY_GRANT,
    az::DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE,
    az::DOMAIN_FLEET_KEY_GRANT_RECOVERY,
    az::DOMAIN_FLEET_KEY_GRANT_ROTATION,
    az::DOMAIN_TENANT_ROOT_KEY_GRANT,
    az::DOMAIN_DEVICE_REVOCATION,
    az::DOMAIN_FLEET_KEY_GRANT_HPKE_INFO,
    az::DOMAIN_FLEET_RECOVERY_WRAP_CONTEXT,
    fk::DOMAIN_FALLBACK_KEY_FILE,
    fl::DOMAIN_FLEET_GENERATION_CREATE,
    fl::DOMAIN_FLEET_GENERATION_CREATED,
    fl::DOMAIN_FLEET_GRANT_CREATE,
    fl::DOMAIN_FLEET_GRANT_CREATED,
    fl::DOMAIN_FLEET_GRANT_ACK,
    fl::DOMAIN_FLEET_GRANT_ACKED,
    fl::DOMAIN_FLEET_GENERATION_ACTIVATE,
    fl::DOMAIN_FLEET_GENERATION_ACTIVATED,
    fl::DOMAIN_FLEET_GRANT_REVOKE,
    fl::DOMAIN_FLEET_GRANT_REVOKED,
    fm::DOMAIN_SNAPSHOT_MANIFEST,
    mu::DOMAIN_MUTATION_REQUEST,
    mu::DOMAIN_STORED_RESPONSE,
    mu::DOMAIN_ROOT_GENERATION_CREATE,
    mu::DOMAIN_ROOT_GENERATION_CREATED,
    mu::DOMAIN_ROOT_GRANT_ACK,
    mu::DOMAIN_ROOT_GRANT_ACKED,
    mu::DOMAIN_ROOT_GRANT_REVOKE,
    mu::DOMAIN_ROOT_GRANT_REVOKED,
    mu::DOMAIN_ROOT_GRANT_CREATE,
    mu::DOMAIN_ROOT_GRANT_CREATED,
    mu::DOMAIN_DEVICE_REVOKE,
    mu::DOMAIN_DEVICE_REVOKED,
    mu::DOMAIN_ROOT_GENERATION_ACTIVATE,
    mu::DOMAIN_ROOT_GENERATION_ACTIVATED,
    mu::DOMAIN_ROOT_GRANT_DESCRIPTOR,
    mu::DOMAIN_FLEET_DEVICE_GRANT_DESCRIPTOR,
    rb::DOMAIN_RECOVERY_BUNDLE,
    sb::DOMAIN_ENROLLMENT_BINDING,
    sb::DOMAIN_DEVICE_SESSION_BINDING,
    te::DOMAIN_TRUST_EVIDENCE_PAGE,
];

const LABELS: &[&str] = &[
    c::L_SIGNED_RECORD,
    c::L_SIGNED_CONTAINER,
    c::L_DEK_SLOT_CONTEXT,
    c::L_DEK_SLOT,
    c::L_ENVELOPE_INTENT,
    c::L_COMMIT_REQUEST,
    c::L_RESTORE_EPOCH_LEAF,
    c::L_RESTORE_EPOCH_NODE2,
    c::L_RESTORE_EPOCH_NODE1,
    c::L_RESTORE_EPOCH_PROOF,
    ev::L_ENVELOPE_FRAME,
    e2::L_ENVELOPE_PREAMBLE,
    k::L_SIGNING_KEY_ID,
    k::L_HPKE_KEY_ID,
    k::L_TENANT_ROOT_KEY_ID,
];

fn assert_distinct(what: &str, values: &[&str]) {
    for (i, a) in values.iter().enumerate() {
        for b in &values[i + 1..] {
            assert_ne!(a, b, "two {what} share one value");
        }
    }
}

#[test]
fn every_signing_domain_is_distinct_and_versioned() {
    assert_distinct("domains", DOMAINS);
    for d in DOMAINS {
        let parts: Vec<&str> = d.split('.').collect();
        assert!(
            parts.len() >= 4 && parts[0] == "shardx" && parts.last() == Some(&"v2"),
            "{d} is not shardx.<area>.<name>.v2"
        );
        assert!(
            d.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-'),
            "{d} has characters outside [a-z0-9.-]"
        );
    }
}

#[test]
fn every_hash_label_is_distinct_and_nul_terminated() {
    assert_distinct("labels", LABELS);
    for l in LABELS {
        let body = l
            .strip_suffix("-V2\0")
            .unwrap_or_else(|| panic!("{l:?} lacks -V2\\0"));
        assert!(body.starts_with("SHARDX-"), "{l:?}");
        // One NUL, at the end: a label can never be a prefix of another
        // label's preimage.
        assert!(!body.contains('\0'), "{l:?}");
    }
    // No label is also a domain, in any case.
    for l in LABELS {
        let folded = l.trim_end_matches('\0').to_ascii_lowercase();
        assert!(
            !DOMAINS.iter().any(|d| d.eq_ignore_ascii_case(&folded)),
            "{l:?}"
        );
    }
}

#[test]
fn the_numeric_registry_holds_the_reviewed_values() {
    // RFC 9180 base mode with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and
    // ChaCha20-Poly1305: the one HPKE suite the grants accept.
    assert_eq!(
        (
            k::HPKE_MODE_BASE,
            k::HPKE_KEM_X25519_HKDF_SHA256,
            k::HPKE_KDF_HKDF_SHA256,
            k::HPKE_AEAD_CHACHA20POLY1305
        ),
        (0, 0x0020, 0x0001, 0x0003)
    );
    // Local suite IDs: 1 is the only assigned value in each registry.
    assert_eq!(
        [
            k::ENVELOPE_SUITE_ID_CHACHA20POLY1305_STREAM,
            k::WRAP_SUITE_ID_CHACHA20POLY1305,
            k::ARCHIVE_FORMAT_ID_TAR,
            k::ARCHIVE_POLICY_ID_PROFILE_SNAPSHOT,
            k::COMPRESSION_ID_GZIP,
            sg::SIGNATURE_SUITE_ID_ED25519,
            az::HPKE_SUITE_ID_X25519_CHACHA,
            gr::HPKE_SUITE_ID_X25519_HKDF_SHA256_CHACHA20POLY1305,
        ],
        [1; 8]
    );
    // ChaCha20-Poly1305 fixes the key, nonce and tag; the STREAM prefix leaves
    // 5 bytes of the 12-byte nonce for the counter and the final flag.
    assert_eq!(
        (
            k::DEK_LEN,
            k::WRAP_NONCE_LEN,
            ev::STREAM_NONCE_LEN,
            k::AEAD_TAG_LEN
        ),
        (32, 12, 12, 16)
    );
    assert_eq!(k::STREAM_NONCE_PREFIX_LEN, 7);
    // Envelope v2 (ADR 0003): suite 2 is XChaCha20-Poly1305 under STREAM LE31,
    // whose 24-byte nonce leaves 20 bytes of prefix before the u32 counter word.
    assert_eq!(k::ENVELOPE_SUITE_ID_XCHACHA20POLY1305_STREAM_LE31, 2);
    assert_eq!(
        (
            e2::ENVELOPE_VERSION,
            e2::PREAMBLE_LEN,
            e2::STREAM_NONCE_PREFIX_LEN,
            e2::KIND_DATA,
            e2::KIND_FINAL
        ),
        (2, 64, 20, 0, 1)
    );
    assert_eq!(&e2::MAGIC, b"SHARDXBK");
    assert_eq!(sg::ED25519_SIG_LEN, 64);
    // Recovery bundle KDF defaults (ADR 0002 D-5); p=4 is pinned inside the
    // module by its own KAT.
    assert_eq!(
        (rb::DEFAULT_KDF_MEMORY_KIB, rb::DEFAULT_KDF_ITERATIONS),
        (65_536, 3)
    );
}
