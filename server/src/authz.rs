//! Verification of signed authorization records.
//!
//! A signature alone proves only that *someone* with the key signed *some*
//! bytes. It says nothing about whether this record was meant for this server,
//! this tenant, this moment, or whether it has already been used. Every check
//! below closes one of those gaps, and each is independently defeatable — so
//! all of them run, in an order that rejects cheaply before doing elliptic
//! curve work.
//!
//! Verification always runs against the exact stored container bytes. The
//! parsed columns beside them in SQLite are an index for querying, never the
//! source of truth: re-encoding parsed columns and verifying *that* would
//! accept a record whose stored bytes say something different.

use shared::canonical as c;
use shared::signing::{verify_tbs, SignError};

/// Domain the generic verifier's tests sign under. Device approvals moved to
/// `shared::authz_record` (ADR 0001 R3).
#[cfg(test)]
pub const DOMAIN_DEVICE_APPROVAL: &str = "shardx.authorization.device-approval.v2";
/// A second domain for the generic verifier's tests. Capability grants moved
/// to `shared::authz_record` (ADR 0002 D-2).
#[cfg(test)]
pub const DOMAIN_CAPABILITY_GRANT: &str = "shardx.authorization.capability-grant.v2";

/// Fleet key grant records. Distinct from the root domain so a root grant
/// can never be verified as a fleet grant, or the reverse.
pub const DOMAIN_FLEET_KEY_GRANT: &str = "shardx.authorization.fleet-key-grant.v2";
/// Domain separator for snapshot manifests.
///
/// Publishing a version is its own authorized action: reusing a capability
/// grant's domain here would let a record issued for one purpose authorise a
/// write, which is exactly what domain separation exists to prevent.
pub const DOMAIN_SNAPSHOT_MANIFEST: &str = "shardx.authorization.snapshot-manifest.v2";

/// Why a record was refused.
///
/// These are deliberately distinct: an operator reading a log needs to tell a
/// clock-skew rejection apart from a forged signature, because the responses
/// are completely different.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthzError {
    /// Container bytes were not canonical CBOR, or not a map.
    Malformed(&'static str),
    /// A required field was absent.
    MissingField(&'static str),
    /// A field was present with the wrong type or length.
    BadField(&'static str),
    /// The record is for a different record type than the caller expected.
    DomainMismatch { expected: String, found: String },
    /// The record was issued for a different server instance.
    InstanceMismatch,
    /// The record predates the current restore epoch.
    StaleEpoch { record: u64, current: u64 },
    /// The record is for another tenant.
    TenantMismatch,
    /// Presented before `not_before_ms`.
    NotYetValid { not_before_ms: u64, now_ms: u64 },
    /// Presented after `not_after_ms`.
    Expired { not_after_ms: u64, now_ms: u64 },
    /// Validity window is empty or inverted.
    InvalidWindow,
    /// The issuer is not a trusted signer for this tenant.
    UntrustedIssuer,
    /// The stored `signed_container_hash` does not commit to the record body.
    ContainerHashMismatch,
    /// Ed25519 verification failed.
    BadSignature,
}

impl std::fmt::Display for AuthzError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(w) => write!(f, "malformed authorization record: {w}"),
            Self::MissingField(n) => write!(f, "missing field: {n}"),
            Self::BadField(n) => write!(f, "invalid field: {n}"),
            Self::DomainMismatch { expected, found } => {
                write!(f, "domain mismatch: expected {expected}, found {found}")
            }
            Self::InstanceMismatch => write!(f, "record was issued for another server instance"),
            Self::StaleEpoch { record, current } => {
                write!(f, "stale restore epoch: record {record}, current {current}")
            }
            Self::TenantMismatch => write!(f, "record belongs to another tenant"),
            Self::NotYetValid { .. } => write!(f, "record is not yet valid"),
            Self::Expired { .. } => write!(f, "record has expired"),
            Self::InvalidWindow => write!(f, "record has an empty validity window"),
            Self::UntrustedIssuer => write!(f, "record was signed by an untrusted issuer"),
            Self::ContainerHashMismatch => write!(f, "signed container hash mismatch"),
            Self::BadSignature => write!(f, "signature verification failed"),
        }
    }
}

impl std::error::Error for AuthzError {}

/// The server-side facts a record must agree with.
#[derive(Debug, Clone)]
pub struct VerificationContext {
    pub tenant_id: [u8; 16],
    pub server_instance_id: [u8; 16],
    pub restore_epoch: u64,
    pub now_ms: u64,
    /// Ed25519 public keys trusted to issue for this tenant, by key id.
    ///
    /// Keyed by id so a rotated-out key can be dropped without the caller
    /// having to reason about which signature belongs to which key.
    pub trusted_issuers: std::collections::HashMap<[u8; 32], [u8; 32]>,
}

/// A record that passed every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRecord {
    pub domain: String,
    pub replay_id: [u8; 16],
    pub issuer_signing_key_id: [u8; 32],
    pub signed_container_hash: [u8; 32],
    /// The Ed25519 signature that was verified, for callers that persist the
    /// record alongside its proof.
    pub signature_bytes: [u8; 64],
    pub not_before_ms: u64,
    pub not_after_ms: u64,
    /// SHA-256 over the exact bytes that were verified, for the audit trail.
    pub exact_bytes_sha256: [u8; 32],
    /// The verified field map.
    ///
    /// A signature authorizes *these* values. A caller that reads the same
    /// value from an unsigned request body instead is trusting the sender,
    /// not the signer, so callers cross-check through the accessors below.
    pub(crate) fields: Vec<(String, c::Value)>,
}

impl VerifiedRecord {
    /// Read a signed 16-byte id.
    pub fn signed_id16(&self, name: &'static str) -> Option<[u8; 16]> {
        bytes_field(&self.fields, name, 16).ok()?.try_into().ok()
    }

    /// Read a signed 32-byte hash.
    pub fn signed_hash32(&self, name: &'static str) -> Option<[u8; 32]> {
        bytes_field(&self.fields, name, 32).ok()?.try_into().ok()
    }

    /// Read a signed unsigned integer.
    /// Read a signed text field.
    pub fn signed_text(&self, name: &'static str) -> Option<String> {
        text_field(&self.fields, name).ok()
    }

    /// Read a signed byte string of unconstrained length.
    ///
    /// Separate from `signed_id16`/`signed_hash32` because the HPKE payload
    /// fields have no fixed width; length is whatever the sealer produced.
    pub fn signed_bytes(&self, name: &'static str) -> Option<Vec<u8>> {
        match field(&self.fields, name).ok()? {
            c::Value::Bytes(b) => Some(b.clone()),
            _ => None,
        }
    }

    pub fn signed_uint(&self, name: &'static str) -> Option<u64> {
        uint_field(&self.fields, name).ok()
    }
}

fn field<'a>(
    map: &'a [(String, c::Value)],
    name: &'static str,
) -> Result<&'a c::Value, AuthzError> {
    map.iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v)
        .ok_or(AuthzError::MissingField(name))
}

fn bytes_field(
    map: &[(String, c::Value)],
    name: &'static str,
    expect_len: usize,
) -> Result<Vec<u8>, AuthzError> {
    match field(map, name)? {
        c::Value::Bytes(b) if b.len() == expect_len => Ok(b.clone()),
        _ => Err(AuthzError::BadField(name)),
    }
}

fn text_field(map: &[(String, c::Value)], name: &'static str) -> Result<String, AuthzError> {
    match field(map, name)? {
        c::Value::Text(s) => Ok(s.clone()),
        _ => Err(AuthzError::BadField(name)),
    }
}

fn uint_field(map: &[(String, c::Value)], name: &'static str) -> Result<u64, AuthzError> {
    match field(map, name)? {
        c::Value::Uint(n) => Ok(*n),
        _ => Err(AuthzError::BadField(name)),
    }
}

/// Verify a signed authorization record against server-side truth.
///
/// Order matters. Structural and binding checks run before the signature check
/// so that a malformed or misdirected record costs a parse rather than a
/// curve operation, and so the failure an operator sees names the actual
/// problem rather than "bad signature" for everything.
pub fn verify_record(
    exact_container_bytes: &[u8],
    expected_domain: &str,
    ctx: &VerificationContext,
) -> Result<VerifiedRecord, AuthzError> {
    // Canonical decode. A non-canonical encoding is rejected outright: two
    // different byte strings that mean the same thing would let the same
    // logical record be replayed under two different hashes.
    // Decode strictly. What matters here is that exactly one byte string can
    // ever represent a given record: a second encoding would hash differently
    // and so slip past a replay table keyed on those bytes.
    //
    // `decode` already enforces that on its own -- it rejects indefinite
    // lengths, non-minimal integers, tags, floats, unsorted keys, duplicate
    // keys and trailing bytes. `assert_canonical_roundtrip` adds a re-encode
    // equality check on top. Mutation testing confirmed no input distinguishes
    // the two, so this call is redundancy against a future decoder relaxation,
    // not a check that closes a currently-reachable gap.
    let value = c::assert_canonical_roundtrip(exact_container_bytes)
        .map_err(|_| AuthzError::Malformed("non-canonical CBOR"))?;
    let map = match &value {
        c::Value::Map(entries) => entries,
        _ => return Err(AuthzError::Malformed("record is not a map")),
    };

    // Domain first: everything below interprets fields according to the
    // record type, so confirm the type before trusting any interpretation.
    let domain = text_field(map, "container_domain")?;
    if domain != expected_domain {
        return Err(AuthzError::DomainMismatch {
            expected: expected_domain.to_string(),
            found: domain,
        });
    }

    // Binding to this server and this tenant. Without these, a record minted
    // by a legitimate issuer for one deployment would be accepted by another.
    let tenant_id = bytes_field(map, "tenant_id", 16)?;
    if tenant_id != ctx.tenant_id {
        return Err(AuthzError::TenantMismatch);
    }
    let instance = bytes_field(map, "server_instance_id", 16)?;
    if instance != ctx.server_instance_id {
        return Err(AuthzError::InstanceMismatch);
    }

    // Epoch binding. After a restore the epoch advances; a record from before
    // it must not be honoured, or a restore would silently reinstate
    // authorizations that were revoked after the backup was taken.
    let record_epoch = uint_field(map, "restore_epoch")?;
    if record_epoch != ctx.restore_epoch {
        return Err(AuthzError::StaleEpoch {
            record: record_epoch,
            current: ctx.restore_epoch,
        });
    }

    // Validity window, checked as a half-open interval [not_before, not_after).
    let not_before_ms = uint_field(map, "not_before_ms")?;
    let not_after_ms = uint_field(map, "not_after_ms")?;
    if not_after_ms <= not_before_ms {
        return Err(AuthzError::InvalidWindow);
    }
    if ctx.now_ms < not_before_ms {
        return Err(AuthzError::NotYetValid {
            not_before_ms,
            now_ms: ctx.now_ms,
        });
    }
    if ctx.now_ms >= not_after_ms {
        return Err(AuthzError::Expired {
            not_after_ms,
            now_ms: ctx.now_ms,
        });
    }

    let replay_id: [u8; 16] = bytes_field(map, "replay_id", 16)?.try_into().unwrap();
    let issuer_key_id: [u8; 32] = bytes_field(map, "issuer_signing_key_id", 32)?
        .try_into()
        .unwrap();

    // The issuer must be trusted for *this tenant*. A valid signature from a
    // key this tenant never authorized is still an unauthorized record.
    let issuer_public_key = ctx
        .trusted_issuers
        .get(&issuer_key_id)
        .ok_or(AuthzError::UntrustedIssuer)?;

    let signature = bytes_field(map, "signature_bytes", 64)?;
    let stored_hash: [u8; 32] = bytes_field(map, "signed_container_hash", 32)?
        .try_into()
        .unwrap();

    // The canonical codec sorts map entries by encoded key bytes, so the
    // signer's field order is not preserved on the wire and position-based
    // reconstruction would be wrong. Rebuild by name instead, and assert a
    // canonical round-trip: re-encoding the decoded map must reproduce the
    // input byte for byte. That single check subsumes non-canonical ordering,
    // duplicate keys and trailing garbage -- any of which would otherwise let
    // two distinct byte strings verify as the same logical record.
    let core_fields: Vec<(String, c::Value)> = map
        .iter()
        .filter(|(k, _)| k != "signed_container_hash")
        .cloned()
        .collect();
    let core_bytes = c::encode(&c::Value::Map(core_fields.clone()));

    // The container hash must commit to the body. Checking it before the
    // signature means a spliced container is caught as exactly that, instead
    // of surfacing as an opaque signature failure.
    let computed_hash = c::domain_hash(c::L_SIGNED_CONTAINER, &core_bytes);
    if computed_hash != stored_hash {
        return Err(AuthzError::ContainerHashMismatch);
    }

    let tbs_fields: Vec<(String, c::Value)> = core_fields
        .into_iter()
        .filter(|(k, _)| k != "signature_bytes")
        .collect();
    let tbs_bytes = c::encode(&c::Value::Map(tbs_fields));

    match verify_tbs(issuer_public_key, &tbs_bytes, &signature) {
        Ok(()) => {}
        Err(SignError::Signature) => return Err(AuthzError::BadSignature),
        Err(_) => return Err(AuthzError::BadField("signature_bytes")),
    }

    Ok(VerifiedRecord {
        domain,
        replay_id,
        issuer_signing_key_id: issuer_key_id,
        signed_container_hash: stored_hash,
        signature_bytes: signature
            .clone()
            .try_into()
            .map_err(|_| AuthzError::BadField("signature_bytes"))?,
        not_before_ms,
        not_after_ms,
        exact_bytes_sha256: c::sha256(exact_container_bytes),
        fields: map.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::signing::{
        build_signed_container, identity_key_id, Ed25519SigningKey as SigningKey,
    };

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn ctx_for(sk: &SigningKey) -> VerificationContext {
        let vk = sk.verifying_key();
        let mut trusted = std::collections::HashMap::new();
        trusted.insert(identity_key_id(&vk), vk.to_bytes());
        VerificationContext {
            tenant_id: [1u8; 16],
            server_instance_id: [2u8; 16],
            restore_epoch: 7,
            now_ms: 1_000_500,
            trusted_issuers: trusted,
        }
    }

    /// A well-formed approval for the context returned by `ctx_for`.
    fn approval_bytes(sk: &SigningKey) -> Vec<u8> {
        let vk = sk.verifying_key();
        build_signed_container(
            sk,
            vec![
                ("container_domain", c::t(DOMAIN_DEVICE_APPROVAL)),
                ("container_version", c::u(1)),
                ("tenant_id", c::b(&[1u8; 16])),
                ("replay_id", c::b(&[9u8; 16])),
                ("subject_account_id", c::b(&[3u8; 16])),
                ("subject_device_id", c::b(&[4u8; 16])),
                ("approved_use", c::t("profile.sync")),
                ("issued_at_ms", c::u(1_000_000)),
                ("not_before_ms", c::u(1_000_000)),
                ("not_after_ms", c::u(1_001_000)),
                ("server_instance_id", c::b(&[2u8; 16])),
                ("restore_epoch", c::u(7)),
                ("issuer_signing_key_id", c::b(&identity_key_id(&vk))),
            ],
        )
        .exact_bytes
    }

    #[test]
    fn a_well_formed_record_verifies() {
        let sk = signing_key(11);
        let bytes = approval_bytes(&sk);
        let verified = verify_record(&bytes, DOMAIN_DEVICE_APPROVAL, &ctx_for(&sk)).unwrap();
        assert_eq!(verified.replay_id, [9u8; 16]);
        assert_eq!(verified.exact_bytes_sha256, c::sha256(&bytes));
    }

    #[test]
    fn every_single_byte_mutation_is_rejected() {
        // The strongest statement available: no flipped byte anywhere in the
        // container produces something that still verifies.
        let sk = signing_key(11);
        let bytes = approval_bytes(&sk);
        let ctx = ctx_for(&sk);

        for i in 0..bytes.len() {
            let mut mutated = bytes.clone();
            mutated[i] ^= 0x01;
            assert!(
                verify_record(&mutated, DOMAIN_DEVICE_APPROVAL, &ctx).is_err(),
                "mutation at byte {i} was accepted"
            );
        }
    }

    #[test]
    fn a_record_for_another_tenant_is_rejected() {
        let sk = signing_key(11);
        let bytes = approval_bytes(&sk);
        let mut ctx = ctx_for(&sk);
        ctx.tenant_id = [0xAAu8; 16];
        assert_eq!(
            verify_record(&bytes, DOMAIN_DEVICE_APPROVAL, &ctx),
            Err(AuthzError::TenantMismatch)
        );
    }

    #[test]
    fn a_record_for_another_server_instance_is_rejected() {
        // Stops a record minted for one deployment being replayed at another.
        let sk = signing_key(11);
        let bytes = approval_bytes(&sk);
        let mut ctx = ctx_for(&sk);
        ctx.server_instance_id = [0xBBu8; 16];
        assert_eq!(
            verify_record(&bytes, DOMAIN_DEVICE_APPROVAL, &ctx),
            Err(AuthzError::InstanceMismatch)
        );
    }

    #[test]
    fn a_record_from_before_a_restore_is_rejected() {
        // The restore-epoch guarantee: a backup must not reinstate authority
        // that was revoked after it was taken.
        let sk = signing_key(11);
        let bytes = approval_bytes(&sk);
        let mut ctx = ctx_for(&sk);
        ctx.restore_epoch = 8;
        assert_eq!(
            verify_record(&bytes, DOMAIN_DEVICE_APPROVAL, &ctx),
            Err(AuthzError::StaleEpoch {
                record: 7,
                current: 8
            })
        );
    }

    #[test]
    fn the_validity_window_is_half_open() {
        let sk = signing_key(11);
        let bytes = approval_bytes(&sk);
        let mut ctx = ctx_for(&sk);

        // Exactly at not_before: valid.
        ctx.now_ms = 1_000_000;
        assert!(verify_record(&bytes, DOMAIN_DEVICE_APPROVAL, &ctx).is_ok());

        // One millisecond before: not yet.
        ctx.now_ms = 999_999;
        assert!(matches!(
            verify_record(&bytes, DOMAIN_DEVICE_APPROVAL, &ctx),
            Err(AuthzError::NotYetValid { .. })
        ));

        // Exactly at not_after: expired, since the interval is half-open.
        ctx.now_ms = 1_001_000;
        assert!(matches!(
            verify_record(&bytes, DOMAIN_DEVICE_APPROVAL, &ctx),
            Err(AuthzError::Expired { .. })
        ));

        // Last valid millisecond.
        ctx.now_ms = 1_000_999;
        assert!(verify_record(&bytes, DOMAIN_DEVICE_APPROVAL, &ctx).is_ok());
    }

    #[test]
    fn a_signature_from_an_untrusted_key_is_rejected() {
        // Valid signature, wrong signer: the record is still unauthorized.
        let attacker = signing_key(99);
        let bytes = approval_bytes(&attacker);
        let ctx = ctx_for(&signing_key(11));
        assert_eq!(
            verify_record(&bytes, DOMAIN_DEVICE_APPROVAL, &ctx),
            Err(AuthzError::UntrustedIssuer)
        );
    }

    #[test]
    fn a_record_cannot_be_used_under_another_domain() {
        // Domain separation: an approval must not be reinterpreted as a
        // capability grant, whose fields mean different things.
        let sk = signing_key(11);
        let bytes = approval_bytes(&sk);
        let ctx = ctx_for(&sk);
        assert!(matches!(
            verify_record(&bytes, DOMAIN_CAPABILITY_GRANT, &ctx),
            Err(AuthzError::DomainMismatch { .. })
        ));
    }

    #[test]
    fn an_inverted_validity_window_is_rejected() {
        let sk = signing_key(11);
        let vk = sk.verifying_key();
        let bytes = build_signed_container(
            &sk,
            vec![
                ("container_domain", c::t(DOMAIN_DEVICE_APPROVAL)),
                ("container_version", c::u(1)),
                ("tenant_id", c::b(&[1u8; 16])),
                ("replay_id", c::b(&[9u8; 16])),
                ("issued_at_ms", c::u(1_000_000)),
                ("not_before_ms", c::u(2_000_000)),
                ("not_after_ms", c::u(1_000_000)), // inverted
                ("server_instance_id", c::b(&[2u8; 16])),
                ("restore_epoch", c::u(7)),
                ("issuer_signing_key_id", c::b(&identity_key_id(&vk))),
            ],
        )
        .exact_bytes;

        assert_eq!(
            verify_record(&bytes, DOMAIN_DEVICE_APPROVAL, &ctx_for(&sk)),
            Err(AuthzError::InvalidWindow)
        );
    }

    #[test]
    fn a_truncated_container_is_rejected() {
        let sk = signing_key(11);
        let bytes = approval_bytes(&sk);
        let ctx = ctx_for(&sk);
        for cut in [1usize, bytes.len() / 2, bytes.len() - 1] {
            assert!(
                verify_record(&bytes[..cut], DOMAIN_DEVICE_APPROVAL, &ctx).is_err(),
                "truncation to {cut} bytes was accepted"
            );
        }
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        // Appended garbage must not be ignored: a decoder that stops at the
        // end of the map would let two different byte strings verify alike.
        let sk = signing_key(11);
        let mut bytes = approval_bytes(&sk);
        bytes.push(0x00);
        assert!(verify_record(&bytes, DOMAIN_DEVICE_APPROVAL, &ctx_for(&sk)).is_err());
    }

    #[test]
    fn a_non_canonical_re_encoding_of_a_valid_record_is_rejected() {
        // The attack this closes: take a record that legitimately verified,
        // re-encode it with a CBOR form that decodes identically but differs
        // in bytes (here, a non-minimal map header). Every field, the
        // signature and the container hash still check out -- but the SHA-256
        // of the exact bytes differs, so a replay table keyed on those bytes
        // would not recognise it as already consumed.
        //
        // Built by hand rather than via the canonical encoder, which cannot
        // emit a non-canonical form by construction.
        let sk = signing_key(11);
        let ctx = ctx_for(&sk);
        let canonical = approval_bytes(&sk);

        // Canonical: 15 pairs as a single-byte header (0xA0 | 15).
        assert_eq!(canonical[0], 0xAF, "fixture shape changed");
        assert!(verify_record(&canonical, DOMAIN_DEVICE_APPROVAL, &ctx).is_ok());

        // Non-canonical: same map, count promoted to a one-byte argument
        // (0xB8 0x0F). RFC 8949 core decoders accept this; canonical CBOR
        // requires the shortest form.
        let mut smuggled = vec![0xB8, 0x0F];
        smuggled.extend_from_slice(&canonical[1..]);

        // It really is a different byte string, and the strict decoder refuses
        // it outright: this codec rejects non-minimal integer forms at parse
        // time rather than accepting them and normalising. A lenient RFC 8949
        // decoder would have accepted it as the same map, which is exactly the
        // ambiguity that would yield a second hash for one logical record.
        assert_ne!(smuggled, canonical);
        assert!(matches!(
            c::decode(&smuggled),
            Err(c::CborError::NonCanonicalIntegerForm)
        ));
        assert!(c::decode(&canonical).is_ok());
        assert_ne!(c::sha256(&smuggled), c::sha256(&canonical));

        assert_eq!(
            verify_record(&smuggled, DOMAIN_DEVICE_APPROVAL, &ctx),
            Err(AuthzError::Malformed("non-canonical CBOR"))
        );
    }

    #[test]
    fn a_missing_required_field_is_named_in_the_error() {
        // Operators need the failure to say what is wrong, not just "invalid".
        let sk = signing_key(11);
        let vk = sk.verifying_key();
        let bytes = build_signed_container(
            &sk,
            vec![
                ("container_domain", c::t(DOMAIN_DEVICE_APPROVAL)),
                ("tenant_id", c::b(&[1u8; 16])),
                ("replay_id", c::b(&[9u8; 16])),
                ("not_before_ms", c::u(1_000_000)),
                ("not_after_ms", c::u(1_001_000)),
                ("server_instance_id", c::b(&[2u8; 16])),
                // restore_epoch omitted
                ("issuer_signing_key_id", c::b(&identity_key_id(&vk))),
            ],
        )
        .exact_bytes;

        assert_eq!(
            verify_record(&bytes, DOMAIN_DEVICE_APPROVAL, &ctx_for(&sk)),
            Err(AuthzError::MissingField("restore_epoch"))
        );
    }
}
