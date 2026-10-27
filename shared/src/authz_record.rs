//! Exact `SignedAuthorizationRecordV2` containers and closed payload parsers
//! (plan 5.6 and 5.6.1; ADR 0002 W1, D-2 and D-8).
//!
//! Parsing never trusts a value it can recompute. The TBS bytes, the core
//! bytes, `payload_sha256` and `signed_container_hash` are rebuilt from the
//! decoded fields and must equal what was received. Every map is closed: an
//! unknown key, a missing key or a key of the wrong type rejects the record, and
//! optional fields are omitted, never `null` (plan 5.6 codec rules).
//!
//! A parsed record is only well formed. Whether its issuer may sign it, and
//! whether `server_now` is inside its window, are checked by the caller against
//! live state (ADR 0002 D-2 issuer matrix).

use chacha20poly1305::aead::{Aead, KeyInit, Payload as AeadPayload};
use chacha20poly1305::ChaCha20Poly1305;
use ed25519_dalek::SigningKey;

use zeroize::Zeroizing;

use crate::canonical::{self as c, CborError, Value};
use crate::fleet_grants::{fkek_key_id, FKEK_LEN};
use crate::grants::{self, GrantError, GrantScope, TRK_LEN};
use crate::keys::{root_key_id, signing_key_id};
use crate::signing::{self, ED25519_SIG_LEN, SIGNATURE_SUITE_ID_ED25519, SIGNATURE_VERSION};

pub const CONTAINER_DOMAIN: &str = "shardx.authorization.signed-container.v2";
pub const CONTAINER_VERSION: u16 = 2;
pub const PAYLOAD_VERSION: u16 = 2;

pub const DOMAIN_DEVICE_APPROVAL: &str = "shardx.auth.device-approval.v2";
pub const DOMAIN_TENANT_CAPABILITY_GRANT: &str = "shardx.auth.tenant-capability-grant.v2";
pub const DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE: &str = "shardx.keys.fleet-key-grant.device-hpke.v2";
pub const DOMAIN_FLEET_KEY_GRANT_RECOVERY: &str = "shardx.keys.fleet-key-grant.recovery.v2";
pub const DOMAIN_FLEET_KEY_GRANT_ROTATION: &str = "shardx.keys.fleet-key-grant.rotation.v2";
/// Domain of the closed AEAD context of a `RecoveryGrant` (ADR 0002 D-5).
pub const DOMAIN_FLEET_RECOVERY_WRAP_CONTEXT: &str =
    "shardx.keys.fleet-key-grant.recovery.wrap-context.v2";
pub const DOMAIN_TENANT_ROOT_KEY_GRANT: &str = "shardx.keys.tenant-root-key-grant.v2";
/// Domain of the closed HPKE `info` map of a `DeviceHpkeGrant` (ADR 0002 D-8).
pub const DOMAIN_FLEET_KEY_GRANT_HPKE_INFO: &str =
    "shardx.keys.fleet-key-grant.device-hpke.hpke-info.v2";

/// `hpke_suite_id = 1`: base mode, X25519-HKDF-SHA256, HKDF-SHA256,
/// ChaCha20-Poly1305 (ADR 0002 D-8).
pub const HPKE_SUITE_ID_X25519_CHACHA: u16 = 1;
const HPKE_MODE_BASE: u64 = 0x00;
const HPKE_KEM_X25519_HKDF_SHA256: u64 = 0x0020;
const HPKE_KDF_HKDF_SHA256: u64 = 0x0001;
const HPKE_AEAD_CHACHA20POLY1305: u64 = 0x0003;
/// Suite 1 lengths: X25519 encapsulated key, and a 32-byte FKEK plus its tag.
const HPKE_SUITE1_ENCAPPED_LEN: usize = 32;
const HPKE_SUITE1_WRAPPED_FKEK_LEN: usize = 48;

const MAX_PAYLOAD_BYTES: usize = 65536;
const MAX_SIGNATURE_BYTES: usize = 4096;
/// Both byte fields at their caps plus room for the other nine fields, checked
/// before decoding so an oversized body is refused without being parsed.
pub const MAX_RECORD_BYTES: usize = MAX_PAYLOAD_BYTES + MAX_SIGNATURE_BYTES + 1024;

/// Why a record was refused. [`RecordError::code`] gives the plan's wire code.
#[derive(Debug, PartialEq, Eq)]
pub enum RecordError {
    /// Not canonical CBOR (plan 5.6 codec rules).
    Cbor(CborError),
    NotAMap(&'static str),
    UnknownField {
        map: &'static str,
        field: String,
    },
    MissingField {
        map: &'static str,
        field: &'static str,
    },
    /// Present with the wrong type or a length outside its bound.
    BadField {
        map: &'static str,
        field: &'static str,
    },
    /// Well typed, but a value or combination the contract does not allow.
    BadValue(&'static str),
    PayloadHashMismatch,
    ContainerHashMismatch,
    /// A suite or version this build does not support.
    Unsupported {
        field: &'static str,
        id: u64,
    },
    UnknownPayloadDomain(String),
    /// The public key the caller looked up does not hash to `issuer_signing_key_id`.
    IssuerKeyMismatch,
    Signature,
}

impl RecordError {
    /// Wire code from the plan's error table (L1233, L1237, L1240).
    pub fn code(&self) -> &'static str {
        match self {
            // Plan L1236: negative, overlong and too-large integers alike.
            Self::Cbor(
                CborError::IntegerOutOfSqliteDomain(_)
                | CborError::UnsupportedMajorType(1)
                | CborError::OverlongInteger,
            ) => "WIRE_INTEGER_OUT_OF_RANGE",
            Self::Cbor(_)
            | Self::NotAMap(_)
            | Self::UnknownField { .. }
            | Self::MissingField { .. }
            | Self::BadField { .. }
            | Self::BadValue(_) => "NON_CANONICAL_RECORD",
            Self::PayloadHashMismatch => "SIGNED_BYTES_MISMATCH",
            Self::ContainerHashMismatch => "SIGNED_CONTAINER_HASH_MISMATCH",
            Self::Unsupported { .. } | Self::UnknownPayloadDomain(_) => "SCHEMA_UNSUPPORTED",
            Self::IssuerKeyMismatch => "KEY_SUBSTITUTION_DETECTED",
            Self::Signature => "SIGNATURE_INVALID",
        }
    }
}

impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cbor(e) => write!(f, "{e}"),
            Self::NotAMap(m) => write!(f, "{m} is not a map"),
            Self::UnknownField { map, field } => write!(f, "unknown field {field} in {map}"),
            Self::MissingField { map, field } => write!(f, "missing field {field} in {map}"),
            Self::BadField { map, field } => {
                write!(f, "invalid type or length for {field} in {map}")
            }
            Self::BadValue(field) => write!(f, "value not allowed for {field}"),
            Self::PayloadHashMismatch => {
                write!(f, "payload_sha256 does not match the payload bytes")
            }
            Self::ContainerHashMismatch => {
                write!(f, "signed_container_hash does not match the container core")
            }
            Self::Unsupported { field, id } => write!(f, "unsupported {field} {id}"),
            Self::UnknownPayloadDomain(d) => write!(f, "unsupported payload_domain {d}"),
            Self::IssuerKeyMismatch => write!(f, "issuer key does not match issuer_signing_key_id"),
            Self::Signature => write!(f, "signature verification failed"),
        }
    }
}

impl std::error::Error for RecordError {}

impl From<CborError> for RecordError {
    fn from(e: CborError) -> Self {
        Self::Cbor(e)
    }
}

type Result<T> = std::result::Result<T, RecordError>;

// ------------------------------------------------------------ closed maps ---

/// A decoded map whose fields are taken one by one; [`Fields::finish`] rejects
/// whatever is left, which is what makes every record a closed map.
pub(crate) struct Fields {
    map: &'static str,
    entries: Vec<(String, Value)>,
}

impl Fields {
    pub(crate) fn open(map: &'static str, v: Value) -> Result<Self> {
        match v {
            Value::Map(entries) => Ok(Self { map, entries }),
            _ => Err(RecordError::NotAMap(map)),
        }
    }

    pub(crate) fn decode(map: &'static str, bytes: &[u8]) -> Result<Self> {
        Self::open(map, c::assert_canonical_roundtrip(bytes)?)
    }

    pub(crate) fn take(&mut self, field: &str) -> Option<Value> {
        let i = self.entries.iter().position(|(k, _)| k == field)?;
        Some(self.entries.remove(i).1)
    }

    pub(crate) fn req(&mut self, field: &'static str) -> Result<Value> {
        self.take(field).ok_or(RecordError::MissingField {
            map: self.map,
            field,
        })
    }

    pub(crate) fn bad(&self, field: &'static str) -> RecordError {
        RecordError::BadField {
            map: self.map,
            field,
        }
    }

    pub(crate) fn text(&mut self, field: &'static str) -> Result<String> {
        match self.req(field)? {
            Value::Text(s) => Ok(s),
            _ => Err(self.bad(field)),
        }
    }

    /// A text field that must hold exactly `expected`.
    pub(crate) fn exact_text(&mut self, field: &'static str, expected: &str) -> Result<()> {
        if self.text(field)? == expected {
            Ok(())
        } else {
            Err(RecordError::BadValue(field))
        }
    }

    pub(crate) fn uint(&mut self, field: &'static str) -> Result<u64> {
        match self.req(field)? {
            Value::Uint(n) => Ok(n),
            _ => Err(self.bad(field)),
        }
    }

    pub(crate) fn opt_uint(&mut self, field: &'static str) -> Result<Option<u64>> {
        match self.take(field) {
            None => Ok(None),
            Some(Value::Uint(n)) => Ok(Some(n)),
            Some(_) => Err(self.bad(field)),
        }
    }

    pub(crate) fn u16(&mut self, field: &'static str) -> Result<u16> {
        let n = self.uint(field)?;
        u16::try_from(n).map_err(|_| self.bad(field))
    }

    pub(crate) fn bytes(&mut self, field: &'static str, min: usize, max: usize) -> Result<Vec<u8>> {
        match self.req(field)? {
            Value::Bytes(b) if (min..=max).contains(&b.len()) => Ok(b),
            _ => Err(self.bad(field)),
        }
    }

    pub(crate) fn fixed<const N: usize>(&mut self, field: &'static str) -> Result<[u8; N]> {
        let b = self.bytes(field, N, N)?;
        Ok(b.try_into().expect("length checked"))
    }

    pub(crate) fn opt_fixed<const N: usize>(
        &mut self,
        field: &'static str,
    ) -> Result<Option<[u8; N]>> {
        match self.take(field) {
            None => Ok(None),
            Some(Value::Bytes(b)) if b.len() == N => {
                Ok(Some(b.try_into().expect("length checked")))
            }
            Some(_) => Err(self.bad(field)),
        }
    }

    pub(crate) fn finish(self) -> Result<()> {
        match self.entries.into_iter().next() {
            None => Ok(()),
            Some((field, _)) => Err(RecordError::UnknownField {
                map: self.map,
                field,
            }),
        }
    }
}

// -------------------------------------------------------------- container ---

/// The payload kinds this build can parse. Any other `payload_domain` is
/// `SCHEMA_UNSUPPORTED`: the record may be valid, but not for this build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    DeviceApproval(DeviceApprovalV2),
    TenantCapabilityGrant(TenantCapabilityGrantV2),
    DeviceHpkeGrant(DeviceHpkeGrantV2),
    RecoveryGrant(RecoveryGrantV2),
    RotationGrant(RotationGrantV2),
    TenantRootKeyGrant(TenantRootKeyGrantV2),
}

impl Payload {
    fn parse(domain: &str, bytes: &[u8]) -> Result<Self> {
        match domain {
            DOMAIN_DEVICE_APPROVAL => DeviceApprovalV2::parse(bytes).map(Self::DeviceApproval),
            DOMAIN_TENANT_CAPABILITY_GRANT => {
                TenantCapabilityGrantV2::parse(bytes).map(Self::TenantCapabilityGrant)
            }
            DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE => {
                DeviceHpkeGrantV2::parse(bytes).map(Self::DeviceHpkeGrant)
            }
            DOMAIN_FLEET_KEY_GRANT_RECOVERY => {
                RecoveryGrantV2::parse(bytes).map(Self::RecoveryGrant)
            }
            DOMAIN_FLEET_KEY_GRANT_ROTATION => {
                RotationGrantV2::parse(bytes).map(Self::RotationGrant)
            }
            DOMAIN_TENANT_ROOT_KEY_GRANT => {
                TenantRootKeyGrantV2::parse(bytes).map(Self::TenantRootKeyGrant)
            }
            other => Err(RecordError::UnknownPayloadDomain(other.to_string())),
        }
    }
}

/// A `SignedAuthorizationRecordV2` whose bytes, hashes, suite and payload were
/// checked. Fields are read-only, and the payload is reachable only through
/// [`AuthorizationRecord::verify_signature`], so nothing can act on a payload
/// whose signature was never checked, or on bytes changed after parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRecord {
    payload_domain: String,
    canonical_payload_bytes: Vec<u8>,
    payload_sha256: [u8; 32],
    issuer_signing_key_id: [u8; 32],
    signature_bytes: Vec<u8>,
    signed_container_hash: [u8; 32],
    exact_signed_container_bytes: Vec<u8>,
    exact_signed_container_bytes_sha256: [u8; 32],
    tbs_bytes: Vec<u8>,
    payload: Payload,
}

/// A record whose signature verified under the issuer key the caller supplied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRecord {
    record: AuthorizationRecord,
}

impl VerifiedRecord {
    pub fn record(&self) -> &AuthorizationRecord {
        &self.record
    }

    pub fn payload(&self) -> &Payload {
        &self.record.payload
    }
}

/// The nine TBS fields, from `container_domain` to `issuer_signing_key_id`.
fn tbs_fields(
    payload_domain: &str,
    payload_bytes: &[u8],
    payload_sha256: &[u8; 32],
    issuer_signing_key_id: &[u8; 32],
) -> Vec<(&'static str, Value)> {
    vec![
        ("container_domain", c::t(CONTAINER_DOMAIN)),
        ("container_version", c::u(CONTAINER_VERSION.into())),
        ("payload_domain", c::t(payload_domain)),
        ("payload_version", c::u(PAYLOAD_VERSION.into())),
        ("canonical_payload_bytes", c::b(payload_bytes)),
        ("payload_sha256", c::b(payload_sha256)),
        (
            "signature_suite_id",
            c::u(SIGNATURE_SUITE_ID_ED25519.into()),
        ),
        ("signature_version", c::u(SIGNATURE_VERSION.into())),
        ("issuer_signing_key_id", c::b(issuer_signing_key_id)),
    ]
}

/// Signs `payload_bytes` (already canonical) into exact container bytes.
pub fn build_record(sk: &SigningKey, payload_domain: &str, payload_bytes: &[u8]) -> Vec<u8> {
    let issuer = signing_key_id(sk.verifying_key().as_bytes());
    let fields = tbs_fields(
        payload_domain,
        payload_bytes,
        &c::sha256(payload_bytes),
        &issuer,
    );
    signing::build_signed_container(sk, fields).exact_bytes
}

impl AuthorizationRecord {
    /// Parses exact container bytes. Accepts only suite 1 version 1 (Ed25519,
    /// ADR 0002 D-8), checks that the payload's own `domain` and `version`
    /// equal the container's, and parses the payload by its closed schema.
    /// A newer container or payload version is `SCHEMA_UNSUPPORTED`.
    pub fn parse(exact: &[u8]) -> Result<Self> {
        if exact.len() > MAX_RECORD_BYTES {
            return Err(RecordError::BadField {
                map: "SignedAuthorizationRecordV2",
                field: "exact_signed_container_bytes",
            });
        }
        let mut f = Fields::decode("SignedAuthorizationRecordV2", exact)?;
        f.exact_text("container_domain", CONTAINER_DOMAIN)?;
        let container_version = f.u16("container_version")?;
        if container_version != CONTAINER_VERSION {
            return Err(RecordError::Unsupported {
                field: "container_version",
                id: container_version.into(),
            });
        }
        let payload_domain = f.text("payload_domain")?;
        let payload_version = f.u16("payload_version")?;
        if payload_version != PAYLOAD_VERSION {
            return Err(RecordError::Unsupported {
                field: "payload_version",
                id: payload_version.into(),
            });
        }
        let canonical_payload_bytes = f.bytes("canonical_payload_bytes", 1, MAX_PAYLOAD_BYTES)?;
        let payload_sha256 = f.fixed::<32>("payload_sha256")?;
        let signature_suite_id = f.u16("signature_suite_id")?;
        if signature_suite_id != SIGNATURE_SUITE_ID_ED25519 {
            return Err(RecordError::Unsupported {
                field: "signature_suite_id",
                id: signature_suite_id.into(),
            });
        }
        let signature_version = f.u16("signature_version")?;
        if signature_version != SIGNATURE_VERSION {
            return Err(RecordError::Unsupported {
                field: "signature_version",
                id: signature_version.into(),
            });
        }
        let issuer_signing_key_id = f.fixed::<32>("issuer_signing_key_id")?;
        let signature_bytes = f.bytes("signature_bytes", 1, MAX_SIGNATURE_BYTES)?;
        let signed_container_hash = f.fixed::<32>("signed_container_hash")?;
        f.finish()?;

        if signature_bytes.len() != ED25519_SIG_LEN {
            return Err(RecordError::BadField {
                map: "SignedAuthorizationRecordV2",
                field: "signature_bytes",
            });
        }
        if c::sha256(&canonical_payload_bytes) != payload_sha256 {
            return Err(RecordError::PayloadHashMismatch);
        }

        let mut core = tbs_fields(
            &payload_domain,
            &canonical_payload_bytes,
            &payload_sha256,
            &issuer_signing_key_id,
        );
        let tbs_bytes = c::encode(&c::m(core.clone()));
        core.push(("signature_bytes", c::b(&signature_bytes)));
        let core_bytes = c::encode(&c::m(core));
        if c::domain_hash(c::L_SIGNED_CONTAINER, &core_bytes) != signed_container_hash {
            return Err(RecordError::ContainerHashMismatch);
        }

        // The payload must be canonical and name the same domain and version.
        let mut p = Fields::decode("payload", &canonical_payload_bytes)?;
        if p.text("domain")? != payload_domain {
            return Err(RecordError::BadValue("payload_domain"));
        }
        if p.u16("version")? != payload_version {
            return Err(RecordError::BadValue("payload_version"));
        }
        let payload = Payload::parse(&payload_domain, &canonical_payload_bytes)?;
        // Plan 5.6.4 rule 1: a first self-grant is signed by its own subject.
        // The record alone decides that, so the parser checks it.
        if let Payload::TenantRootKeyGrant(g) = &payload {
            if g.variant == RootGrantVariant::FirstRootSelfGrant
                && g.subject_signing_key_id != issuer_signing_key_id
            {
                return Err(RecordError::BadValue("issuer_signing_key_id"));
            }
        }

        Ok(Self {
            payload_domain,
            canonical_payload_bytes,
            payload_sha256,
            issuer_signing_key_id,
            signature_bytes,
            signed_container_hash,
            exact_signed_container_bytes: exact.to_vec(),
            exact_signed_container_bytes_sha256: c::sha256(exact),
            tbs_bytes,
            payload,
        })
    }

    /// Checks the signature under the issuer key the caller looked up.
    ///
    /// The caller owns the lookup: the key must be found by tenant, server
    /// instance, epoch and `issuer_signing_key_id`, and its holder must satisfy
    /// the ADR 0002 D-2 issuer rule for this payload. This function only refuses
    /// a key whose ID differs from `issuer_signing_key_id`, before any curve
    /// arithmetic, and then verifies under `verify_strict`.
    pub fn verify_signature(self, issuer_public_key: &[u8; 32]) -> Result<VerifiedRecord> {
        if signing_key_id(issuer_public_key) != self.issuer_signing_key_id {
            return Err(RecordError::IssuerKeyMismatch);
        }
        signing::verify_tbs(issuer_public_key, &self.tbs_bytes, &self.signature_bytes)
            .map_err(|_| RecordError::Signature)?;
        Ok(VerifiedRecord { record: self })
    }

    pub fn payload_domain(&self) -> &str {
        &self.payload_domain
    }

    pub fn canonical_payload_bytes(&self) -> &[u8] {
        &self.canonical_payload_bytes
    }

    pub fn payload_sha256(&self) -> &[u8; 32] {
        &self.payload_sha256
    }

    /// Always suite 1 version 1; a record with any other value does not parse.
    pub fn signature_suite(&self) -> (u16, u16) {
        (SIGNATURE_SUITE_ID_ED25519, SIGNATURE_VERSION)
    }

    pub fn issuer_signing_key_id(&self) -> &[u8; 32] {
        &self.issuer_signing_key_id
    }

    pub fn signature_bytes(&self) -> &[u8] {
        &self.signature_bytes
    }

    pub fn signed_container_hash(&self) -> &[u8; 32] {
        &self.signed_container_hash
    }

    pub fn exact_signed_container_bytes(&self) -> &[u8] {
        &self.exact_signed_container_bytes
    }

    pub fn exact_signed_container_bytes_sha256(&self) -> &[u8; 32] {
        &self.exact_signed_container_bytes_sha256
    }

    /// The exact bytes the signature covers.
    pub fn tbs_bytes(&self) -> &[u8] {
        &self.tbs_bytes
    }
}

// --------------------------------------------------- common payload fields ---

/// Fields every 5.6.1 payload carries besides `domain` and `version`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommonFields {
    pub replay_id: [u8; 16],
    pub tenant_id: [u8; 16],
    pub issued_at_ms: u64,
    pub not_before_ms: u64,
    pub not_after_ms: u64,
    pub server_instance_id: [u8; 16],
    pub restore_epoch: u64,
}

impl CommonFields {
    fn take(f: &mut Fields, domain: &str) -> Result<Self> {
        f.exact_text("domain", domain)?;
        if f.u16("version")? != PAYLOAD_VERSION {
            return Err(RecordError::BadValue("version"));
        }
        let common = Self {
            replay_id: f.fixed("replay_id")?,
            tenant_id: f.fixed("tenant_id")?,
            issued_at_ms: f.uint("issued_at_ms")?,
            not_before_ms: f.uint("not_before_ms")?,
            not_after_ms: f.uint("not_after_ms")?,
            server_instance_id: f.fixed("server_instance_id")?,
            restore_epoch: f.uint("restore_epoch")?,
        };
        // Plan 5.6: issued_at_ms <= not_before_ms < not_after_ms. The check
        // against server_now and the tenant TTL belongs to the caller.
        if common.issued_at_ms > common.not_before_ms {
            return Err(RecordError::BadValue("issued_at_ms"));
        }
        if common.not_before_ms >= common.not_after_ms {
            return Err(RecordError::BadValue("not_after_ms"));
        }
        Ok(common)
    }

    fn put(&self, domain: &str, out: &mut Vec<(&'static str, Value)>) {
        out.extend([
            ("domain", c::t(domain)),
            ("version", c::u(PAYLOAD_VERSION.into())),
            ("replay_id", c::b(&self.replay_id)),
            ("tenant_id", c::b(&self.tenant_id)),
            ("issued_at_ms", c::u(self.issued_at_ms)),
            ("not_before_ms", c::u(self.not_before_ms)),
            ("not_after_ms", c::u(self.not_after_ms)),
            ("server_instance_id", c::b(&self.server_instance_id)),
            ("restore_epoch", c::u(self.restore_epoch)),
        ]);
    }
}

// ------------------------------------------------------ DeviceApprovalV2 ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalScopeKind {
    Tenant,
    Fleet,
}

impl ApprovalScopeKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Tenant => "tenant",
            Self::Fleet => "fleet",
        }
    }
}

/// Plan 5.6.1 `DeviceApprovalV2`; no optional fields, `approved_use = team.device`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceApprovalV2 {
    pub common: CommonFields,
    pub subject_account_id: [u8; 16],
    pub subject_device_id: [u8; 16],
    pub subject_signing_key_id: [u8; 32],
    pub subject_hpke_key_id: [u8; 32],
    pub approval_scope_kind: ApprovalScopeKind,
    pub approval_scope_id: [u8; 16],
}

const APPROVED_USE_TEAM_DEVICE: &str = "team.device";

impl DeviceApprovalV2 {
    fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("DeviceApprovalV2", payload)?;
        let common = CommonFields::take(&mut f, DOMAIN_DEVICE_APPROVAL)?;
        let subject_account_id = f.fixed("subject_account_id")?;
        let subject_device_id = f.fixed("subject_device_id")?;
        let subject_signing_key_id = f.fixed("subject_signing_key_id")?;
        let subject_hpke_key_id = f.fixed("subject_hpke_key_id")?;
        let approval_scope_kind = match f.text("approval_scope_kind")?.as_str() {
            "tenant" => ApprovalScopeKind::Tenant,
            "fleet" => ApprovalScopeKind::Fleet,
            _ => return Err(RecordError::BadValue("approval_scope_kind")),
        };
        let approval_scope_id = f.fixed("approval_scope_id")?;
        f.exact_text("approved_use", APPROVED_USE_TEAM_DEVICE)?;
        f.finish()?;

        if subject_signing_key_id == subject_hpke_key_id {
            return Err(RecordError::BadValue("subject_hpke_key_id"));
        }
        // A tenant-scoped approval names the tenant itself; which fleet a fleet
        // scope names is checked against live state by the caller.
        if approval_scope_kind == ApprovalScopeKind::Tenant && approval_scope_id != common.tenant_id
        {
            return Err(RecordError::BadValue("approval_scope_id"));
        }
        Ok(Self {
            common,
            subject_account_id,
            subject_device_id,
            subject_signing_key_id,
            subject_hpke_key_id,
            approval_scope_kind,
            approval_scope_id,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.common.put(DOMAIN_DEVICE_APPROVAL, &mut out);
        out.extend([
            ("subject_account_id", c::b(&self.subject_account_id)),
            ("subject_device_id", c::b(&self.subject_device_id)),
            ("subject_signing_key_id", c::b(&self.subject_signing_key_id)),
            ("subject_hpke_key_id", c::b(&self.subject_hpke_key_id)),
            (
                "approval_scope_kind",
                c::t(self.approval_scope_kind.as_str()),
            ),
            ("approval_scope_id", c::b(&self.approval_scope_id)),
            ("approved_use", c::t(APPROVED_USE_TEAM_DEVICE)),
        ]);
        c::encode(&c::m(out))
    }
}

// --------------------------------------------------------- Capability ---

/// The closed `Capability` set of ADR 0002 D-2. Any other string is
/// `NON_CANONICAL_RECORD`, even one that matches the plan's syntax.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    TenantManage,
    MembershipManage,
    FleetManage,
    DeviceApprove,
    DeviceRevoke,
    KeyRotate,
    RecoveryManage,
    LeaseForceExpire,
    ProfilePublish,
    ProfileCheckout,
    ProfileCommit,
    RootCustody,
    FleetKeyReceive,
    FleetKeyRecover,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityScopeKind {
    Tenant,
    Fleet,
    Profile,
}

impl CapabilityScopeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tenant => "tenant",
            Self::Fleet => "fleet",
            Self::Profile => "profile",
        }
    }
}

impl Capability {
    pub const ALL: [Capability; 14] = [
        Self::TenantManage,
        Self::MembershipManage,
        Self::FleetManage,
        Self::DeviceApprove,
        Self::DeviceRevoke,
        Self::KeyRotate,
        Self::RecoveryManage,
        Self::LeaseForceExpire,
        Self::ProfilePublish,
        Self::ProfileCheckout,
        Self::ProfileCommit,
        Self::RootCustody,
        Self::FleetKeyReceive,
        Self::FleetKeyRecover,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::TenantManage => "tenant.manage",
            Self::MembershipManage => "membership.manage",
            Self::FleetManage => "fleet.manage",
            Self::DeviceApprove => "device.approve",
            Self::DeviceRevoke => "device.revoke",
            Self::KeyRotate => "key.rotate",
            Self::RecoveryManage => "recovery.manage",
            Self::LeaseForceExpire => "lease.force_expire",
            Self::ProfilePublish => "profile.publish",
            Self::ProfileCheckout => "profile.checkout",
            Self::ProfileCommit => "profile.commit",
            Self::RootCustody => "root.custody",
            Self::FleetKeyReceive => "fleet.key.receive",
            Self::FleetKeyRecover => "fleet.key.recover",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == s)
    }

    /// Scope kinds a `TenantCapabilityGrantV2` may carry this value with
    /// (D-2 table). Empty for the values that never appear in a capability grant.
    pub fn grant_scopes(self) -> &'static [CapabilityScopeKind] {
        use CapabilityScopeKind::{Fleet, Profile, Tenant};
        match self {
            Self::TenantManage | Self::MembershipManage | Self::RecoveryManage => &[Tenant],
            Self::FleetManage
            | Self::DeviceApprove
            | Self::DeviceRevoke
            | Self::KeyRotate
            | Self::ProfilePublish => &[Tenant, Fleet],
            Self::LeaseForceExpire | Self::ProfileCheckout | Self::ProfileCommit => {
                &[Tenant, Fleet, Profile]
            }
            Self::RootCustody | Self::FleetKeyReceive | Self::FleetKeyRecover => &[],
        }
    }
}

// ------------------------------------------------ TenantCapabilityGrantV2 ---

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantSubject {
    /// Server RBAC only; never satisfies an issuer or signer rule (D-2).
    Account { account_id: [u8; 16] },
    Device {
        account_id: [u8; 16],
        device_id: [u8; 16],
        signing_key_id: [u8; 32],
        hpke_key_id: [u8; 32],
    },
}

/// Plan 5.6.1 `TenantCapabilityGrantV2` with the D-2 value set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantCapabilityGrantV2 {
    pub common: CommonFields,
    pub subject: GrantSubject,
    pub scope_kind: CapabilityScopeKind,
    pub scope_id: [u8; 16],
    pub capability: Capability,
}

impl TenantCapabilityGrantV2 {
    /// Parses the L484 shape. `root.custody` parses when device-scoped and
    /// tenant-scoped, as Q-2 keeps that shape, but [`Self::is_issuable`] refuses
    /// it: custody comes only from root grants.
    fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("TenantCapabilityGrantV2", payload)?;
        let common = CommonFields::take(&mut f, DOMAIN_TENANT_CAPABILITY_GRANT)?;
        let subject_kind = f.text("subject_kind")?;
        let account_id = f.fixed("subject_account_id")?;
        let device_id = f.opt_fixed::<16>("subject_device_id")?;
        let signing_key_id = f.opt_fixed::<32>("subject_signing_key_id")?;
        let hpke_key_id = f.opt_fixed::<32>("subject_hpke_key_id")?;
        let subject = match (
            subject_kind.as_str(),
            device_id,
            signing_key_id,
            hpke_key_id,
        ) {
            ("account", None, None, None) => GrantSubject::Account { account_id },
            ("device", Some(device_id), Some(signing_key_id), Some(hpke_key_id)) => {
                if signing_key_id == hpke_key_id {
                    return Err(RecordError::BadValue("subject_hpke_key_id"));
                }
                GrantSubject::Device {
                    account_id,
                    device_id,
                    signing_key_id,
                    hpke_key_id,
                }
            }
            // Device fields are present iff subject_kind = device.
            _ => return Err(RecordError::BadValue("subject_kind")),
        };
        let scope_kind = match f.text("scope_kind")?.as_str() {
            "tenant" => CapabilityScopeKind::Tenant,
            "fleet" => CapabilityScopeKind::Fleet,
            "profile" => CapabilityScopeKind::Profile,
            _ => return Err(RecordError::BadValue("scope_kind")),
        };
        let scope_id = f.fixed("scope_id")?;
        let capability =
            Capability::parse(&f.text("capability")?).ok_or(RecordError::BadValue("capability"))?;
        f.finish()?;

        match capability {
            Capability::RootCustody if !matches!(subject, GrantSubject::Device { .. }) => {
                return Err(RecordError::BadValue("capability"));
            }
            // Custody is tenant-wide: the root key covers every fleet, so only a
            // tenant scope describes it (this ADR's reading of L484 and Q-2).
            Capability::RootCustody if scope_kind != CapabilityScopeKind::Tenant => {
                return Err(RecordError::BadValue("scope_kind"));
            }
            Capability::RootCustody => {}
            Capability::FleetKeyReceive | Capability::FleetKeyRecover => {
                return Err(RecordError::BadValue("capability"));
            }
            _ if !capability.grant_scopes().contains(&scope_kind) => {
                return Err(RecordError::BadValue("scope_kind"));
            }
            _ => {}
        }
        if scope_kind == CapabilityScopeKind::Tenant && scope_id != common.tenant_id {
            return Err(RecordError::BadValue("scope_id"));
        }
        Ok(Self {
            common,
            subject,
            scope_kind,
            scope_id,
            capability,
        })
    }

    /// Whether a server may accept this grant for filing (D-2, Q-2).
    pub fn is_issuable(&self) -> bool {
        self.capability != Capability::RootCustody
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.common.put(DOMAIN_TENANT_CAPABILITY_GRANT, &mut out);
        match &self.subject {
            GrantSubject::Account { account_id } => out.extend([
                ("subject_kind", c::t("account")),
                ("subject_account_id", c::b(account_id)),
            ]),
            GrantSubject::Device {
                account_id,
                device_id,
                signing_key_id,
                hpke_key_id,
            } => out.extend([
                ("subject_kind", c::t("device")),
                ("subject_account_id", c::b(account_id)),
                ("subject_device_id", c::b(device_id)),
                ("subject_signing_key_id", c::b(signing_key_id)),
                ("subject_hpke_key_id", c::b(hpke_key_id)),
            ]),
        }
        out.extend([
            ("scope_kind", c::t(self.scope_kind.as_str())),
            ("scope_id", c::b(&self.scope_id)),
            ("capability", c::t(self.capability.as_str())),
        ]);
        c::encode(&c::m(out))
    }
}

// ---------------------------------------------- FleetKeyGrantV2::DeviceHpke ---

/// Plan 5.6.1 `FleetKeyGrantV2::DeviceHpkeGrant`, suite 1 only (D-8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceHpkeGrantV2 {
    pub common: CommonFields,
    pub fleet_id: [u8; 16],
    pub fkek_key_id: [u8; 32],
    pub generation: u64,
    pub subject_account_id: [u8; 16],
    pub subject_device_id: [u8; 16],
    pub subject_signing_key_id: [u8; 32],
    pub recipient_hpke_key_id: [u8; 32],
    pub hpke_encapped_key_bytes: Vec<u8>,
    pub hpke_wrapped_fleet_key_bytes: Vec<u8>,
}

const GRANT_VARIANT_DEVICE_HPKE: &str = "DeviceHpkeGrant";

impl DeviceHpkeGrantV2 {
    /// The closed HPKE `info` map (D-8). The grant carries these exact bytes,
    /// and parsing refuses a grant whose bytes differ, so the info a recipient
    /// opens with is always the one bound to the signed fields. That refusal is
    /// `NON_CANONICAL_RECORD`: the payload contradicts itself. A difference from
    /// a stored column is the caller's `AUTH_CLAIM_COLUMN_MISMATCH` (plan 7.2).
    pub fn hpke_info_bytes(&self) -> Vec<u8> {
        let k = &self.common;
        c::encode(&c::m(vec![
            ("domain", c::t(DOMAIN_FLEET_KEY_GRANT_HPKE_INFO)),
            ("version", c::u(PAYLOAD_VERSION.into())),
            ("replay_id", c::b(&k.replay_id)),
            ("tenant_id", c::b(&k.tenant_id)),
            ("server_instance_id", c::b(&k.server_instance_id)),
            ("restore_epoch", c::u(k.restore_epoch)),
            ("fleet_id", c::b(&self.fleet_id)),
            ("fkek_key_id", c::b(&self.fkek_key_id)),
            ("generation", c::u(self.generation)),
            ("subject_account_id", c::b(&self.subject_account_id)),
            ("subject_device_id", c::b(&self.subject_device_id)),
            ("recipient_hpke_key_id", c::b(&self.recipient_hpke_key_id)),
            ("hpke_suite_id", c::u(HPKE_SUITE_ID_X25519_CHACHA.into())),
            ("hpke_mode_id", c::u(HPKE_MODE_BASE)),
            ("hpke_kem_id", c::u(HPKE_KEM_X25519_HKDF_SHA256)),
            ("hpke_kdf_id", c::u(HPKE_KDF_HKDF_SHA256)),
            ("hpke_aead_id", c::u(HPKE_AEAD_CHACHA20POLY1305)),
            (
                "grant_capability",
                c::t(Capability::FleetKeyReceive.as_str()),
            ),
        ]))
    }

    fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("DeviceHpkeGrant", payload)?;
        let common = CommonFields::take(&mut f, DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE)?;
        f.exact_text("grant_variant", GRANT_VARIANT_DEVICE_HPKE)?;
        let fleet_id = f.fixed("fleet_id")?;
        let fkek_key_id = f.fixed("fkek_key_id")?;
        let generation = f.uint("generation")?;
        f.exact_text("grant_capability", Capability::FleetKeyReceive.as_str())?;
        let subject_account_id = f.fixed("subject_account_id")?;
        let subject_device_id = f.fixed("subject_device_id")?;
        let subject_signing_key_id = f.fixed("subject_signing_key_id")?;
        let recipient_hpke_key_id = f.fixed("recipient_hpke_key_id")?;
        let hpke_suite_id = f.u16("hpke_suite_id")?;
        let hpke_info_bytes = f.bytes("hpke_info_bytes", 1, 1024)?;
        let hpke_encapped_key_bytes = f.bytes("hpke_encapped_key_bytes", 1, 2048)?;
        let hpke_wrapped_fleet_key_bytes = f.bytes("hpke_wrapped_fleet_key_bytes", 1, 4096)?;
        f.finish()?;

        if hpke_suite_id != HPKE_SUITE_ID_X25519_CHACHA {
            return Err(RecordError::Unsupported {
                field: "hpke_suite_id",
                id: hpke_suite_id.into(),
            });
        }
        if hpke_encapped_key_bytes.len() != HPKE_SUITE1_ENCAPPED_LEN {
            return Err(RecordError::BadField {
                map: "DeviceHpkeGrant",
                field: "hpke_encapped_key_bytes",
            });
        }
        if hpke_wrapped_fleet_key_bytes.len() != HPKE_SUITE1_WRAPPED_FKEK_LEN {
            return Err(RecordError::BadField {
                map: "DeviceHpkeGrant",
                field: "hpke_wrapped_fleet_key_bytes",
            });
        }
        if subject_signing_key_id == recipient_hpke_key_id {
            return Err(RecordError::BadValue("recipient_hpke_key_id"));
        }
        let grant = Self {
            common,
            fleet_id,
            fkek_key_id,
            generation,
            subject_account_id,
            subject_device_id,
            subject_signing_key_id,
            recipient_hpke_key_id,
            hpke_encapped_key_bytes,
            hpke_wrapped_fleet_key_bytes,
        };
        if hpke_info_bytes != grant.hpke_info_bytes() {
            return Err(RecordError::BadValue("hpke_info_bytes"));
        }
        Ok(grant)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.common
            .put(DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE, &mut out);
        out.extend([
            ("grant_variant", c::t(GRANT_VARIANT_DEVICE_HPKE)),
            ("fleet_id", c::b(&self.fleet_id)),
            ("fkek_key_id", c::b(&self.fkek_key_id)),
            ("generation", c::u(self.generation)),
            (
                "grant_capability",
                c::t(Capability::FleetKeyReceive.as_str()),
            ),
            ("subject_account_id", c::b(&self.subject_account_id)),
            ("subject_device_id", c::b(&self.subject_device_id)),
            ("subject_signing_key_id", c::b(&self.subject_signing_key_id)),
            ("recipient_hpke_key_id", c::b(&self.recipient_hpke_key_id)),
            ("hpke_suite_id", c::u(HPKE_SUITE_ID_X25519_CHACHA.into())),
            ("hpke_info_bytes", c::b(&self.hpke_info_bytes())),
            (
                "hpke_encapped_key_bytes",
                c::b(&self.hpke_encapped_key_bytes),
            ),
            (
                "hpke_wrapped_fleet_key_bytes",
                c::b(&self.hpke_wrapped_fleet_key_bytes),
            ),
        ]);
        c::encode(&c::m(out))
    }
}

// ---------------------------------------------- FleetKeyGrantV2::Recovery ---

/// `root_wrap_suite_id = 1`: ChaCha20-Poly1305 keyed by the TRK, a random
/// 12-byte nonce, and the exact wrap context as AAD (ADR 0002 D-5).
pub const ROOT_WRAP_SUITE_ID_CHACHA: u16 = 1;
const ROOT_WRAP_NONCE_LEN: usize = 12;
/// A 32-byte FKEK plus its 16-byte tag.
const ROOT_WRAP_WRAPPED_FKEK_LEN: usize = 48;
const GRANT_VARIANT_RECOVERY: &str = "RecoveryGrant";

/// Plan 5.6.1 `FleetKeyGrantV2::RecoveryGrant`: the FKEK of one fleet
/// generation wrapped under the TRK of root generation
/// `recipient_root_generation`, suite 1 only (D-5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryGrantV2 {
    pub common: CommonFields,
    pub fleet_id: [u8; 16],
    pub fkek_key_id: [u8; 32],
    pub generation: u64,
    pub recipient_root_key_id: [u8; 32],
    pub recipient_root_generation: u64,
    pub root_wrap_nonce_bytes: [u8; ROOT_WRAP_NONCE_LEN],
    pub wrapped_fleet_key_bytes: [u8; ROOT_WRAP_WRAPPED_FKEK_LEN],
}

impl RecoveryGrantV2 {
    /// Exact `FleetRecoveryWrapContextV2` bytes (D-5). As with the HPKE info of
    /// a device grant, parsing refuses a payload whose stored bytes differ.
    pub fn root_wrap_context_bytes(&self) -> Vec<u8> {
        let k = &self.common;
        c::encode(&c::m(vec![
            ("domain", c::t(DOMAIN_FLEET_RECOVERY_WRAP_CONTEXT)),
            ("version", c::u(PAYLOAD_VERSION.into())),
            ("replay_id", c::b(&k.replay_id)),
            ("tenant_id", c::b(&k.tenant_id)),
            ("server_instance_id", c::b(&k.server_instance_id)),
            ("restore_epoch", c::u(k.restore_epoch)),
            ("fleet_id", c::b(&self.fleet_id)),
            ("fkek_key_id", c::b(&self.fkek_key_id)),
            ("generation", c::u(self.generation)),
            ("recipient_root_key_id", c::b(&self.recipient_root_key_id)),
            (
                "recipient_root_generation",
                c::u(self.recipient_root_generation),
            ),
            ("root_wrap_suite_id", c::u(ROOT_WRAP_SUITE_ID_CHACHA.into())),
            (
                "grant_capability",
                c::t(Capability::FleetKeyRecover.as_str()),
            ),
        ]))
    }

    /// Wraps `fkek` under `trk` with a fresh nonce. Refuses keys that do not
    /// hash to the key IDs this grant names, so a sealed grant never lies.
    pub fn seal(
        &mut self,
        trk: &[u8; TRK_LEN],
        fkek: &[u8; FKEK_LEN],
    ) -> std::result::Result<(), GrantError> {
        if root_key_id(trk) != self.recipient_root_key_id {
            return Err(GrantError::FieldMismatch("recipient_root_key_id"));
        }
        if fkek_key_id(fkek) != self.fkek_key_id {
            return Err(GrantError::FieldMismatch("fkek_key_id"));
        }
        let mut nonce = [0u8; ROOT_WRAP_NONCE_LEN];
        getrandom04::fill(&mut nonce).expect("OS entropy source unavailable");
        self.root_wrap_nonce_bytes = nonce;
        self.wrapped_fleet_key_bytes =
            root_wrap(trk, &nonce, &self.root_wrap_context_bytes(), fkek)?;
        Ok(())
    }

    /// Unwraps the FKEK and checks it hashes to `fkek_key_id` (D-5). The
    /// plaintext is `Zeroizing`, so a refused key is wiped on drop.
    pub fn open_fkek(
        &self,
        trk: &[u8; TRK_LEN],
    ) -> std::result::Result<Zeroizing<[u8; FKEK_LEN]>, GrantError> {
        if root_key_id(trk) != self.recipient_root_key_id {
            return Err(GrantError::FieldMismatch("recipient_root_key_id"));
        }
        let plain = Zeroizing::new(
            ChaCha20Poly1305::new(trk.into())
                .decrypt(
                    &self.root_wrap_nonce_bytes.into(),
                    AeadPayload {
                        msg: &self.wrapped_fleet_key_bytes,
                        aad: &self.root_wrap_context_bytes(),
                    },
                )
                .map_err(|_| GrantError::AeadFailure)?,
        );
        let fkek: Zeroizing<[u8; FKEK_LEN]> = Zeroizing::new(
            plain
                .as_slice()
                .try_into()
                .map_err(|_| GrantError::BadFkekLength)?,
        );
        if fkek_key_id(&fkek) != self.fkek_key_id {
            return Err(GrantError::FieldMismatch("fkek_key_id"));
        }
        Ok(fkek)
    }

    fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("RecoveryGrant", payload)?;
        let common = CommonFields::take(&mut f, DOMAIN_FLEET_KEY_GRANT_RECOVERY)?;
        f.exact_text("grant_variant", GRANT_VARIANT_RECOVERY)?;
        let fleet_id = f.fixed("fleet_id")?;
        let fkek_key_id = f.fixed("fkek_key_id")?;
        let generation = f.uint("generation")?;
        f.exact_text("grant_capability", Capability::FleetKeyRecover.as_str())?;
        let recipient_root_key_id = f.fixed("recipient_root_key_id")?;
        let recipient_root_generation = f.uint("recipient_root_generation")?;
        let root_wrap_suite_id = f.u16("root_wrap_suite_id")?;
        let nonce = f.bytes("root_wrap_nonce_bytes", 1, 64)?;
        let context = f.bytes("root_wrap_context_bytes", 1, 1024)?;
        let wrapped = f.bytes("wrapped_fleet_key_bytes", 1, 4096)?;
        f.finish()?;

        if root_wrap_suite_id != ROOT_WRAP_SUITE_ID_CHACHA {
            return Err(RecordError::Unsupported {
                field: "root_wrap_suite_id",
                id: root_wrap_suite_id.into(),
            });
        }
        let bad = |field| RecordError::BadField {
            map: "RecoveryGrant",
            field,
        };
        let grant = Self {
            common,
            fleet_id,
            fkek_key_id,
            generation,
            recipient_root_key_id,
            recipient_root_generation,
            root_wrap_nonce_bytes: nonce.try_into().map_err(|_| bad("root_wrap_nonce_bytes"))?,
            wrapped_fleet_key_bytes: wrapped
                .try_into()
                .map_err(|_| bad("wrapped_fleet_key_bytes"))?,
        };
        if context != grant.root_wrap_context_bytes() {
            return Err(RecordError::BadValue("root_wrap_context_bytes"));
        }
        Ok(grant)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.common.put(DOMAIN_FLEET_KEY_GRANT_RECOVERY, &mut out);
        out.extend([
            ("grant_variant", c::t(GRANT_VARIANT_RECOVERY)),
            ("fleet_id", c::b(&self.fleet_id)),
            ("fkek_key_id", c::b(&self.fkek_key_id)),
            ("generation", c::u(self.generation)),
            (
                "grant_capability",
                c::t(Capability::FleetKeyRecover.as_str()),
            ),
            ("recipient_root_key_id", c::b(&self.recipient_root_key_id)),
            (
                "recipient_root_generation",
                c::u(self.recipient_root_generation),
            ),
            ("root_wrap_suite_id", c::u(ROOT_WRAP_SUITE_ID_CHACHA.into())),
            ("root_wrap_nonce_bytes", c::b(&self.root_wrap_nonce_bytes)),
            (
                "root_wrap_context_bytes",
                c::b(&self.root_wrap_context_bytes()),
            ),
            (
                "wrapped_fleet_key_bytes",
                c::b(&self.wrapped_fleet_key_bytes),
            ),
        ]);
        c::encode(&c::m(out))
    }
}

fn root_wrap(
    trk: &[u8; TRK_LEN],
    nonce: &[u8; ROOT_WRAP_NONCE_LEN],
    context: &[u8],
    fkek: &[u8; FKEK_LEN],
) -> std::result::Result<[u8; ROOT_WRAP_WRAPPED_FKEK_LEN], GrantError> {
    let sealed = ChaCha20Poly1305::new(trk.into())
        .encrypt(
            nonce.into(),
            AeadPayload {
                msg: fkek,
                aad: context,
            },
        )
        .map_err(|_| GrantError::AeadFailure)?;
    sealed.try_into().map_err(|_| GrantError::AeadFailure)
}

// ---------------------------------------------- FleetKeyGrantV2::Rotation ---

const GRANT_VARIANT_ROTATION: &str = "RotationGrant";
/// D-4 and Q-4: a required set has `1..=65535` members on the wire.
const MAX_REQUIRED_GRANT_COUNT: u64 = 65535;

/// Plan 5.6.1 `FleetKeyGrantV2::RotationGrant`. The common `fkek_key_id` and
/// `generation` name the target generation; the previous pair names the one it
/// replaces. The set hash and the recovery grant hash bind the exact grants an
/// activation must find (D-4); checking them against stored rows is the caller's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationGrantV2 {
    pub common: CommonFields,
    pub fleet_id: [u8; 16],
    pub fkek_key_id: [u8; 32],
    pub generation: u64,
    pub previous_fkek_key_id: [u8; 32],
    pub previous_generation: u64,
    pub required_device_grant_count: u32,
    pub required_device_grant_set_hash: [u8; 32],
    pub recovery_grant_signed_container_hash: [u8; 32],
    pub activation_not_before_ms: u64,
}

impl RotationGrantV2 {
    fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("RotationGrant", payload)?;
        let common = CommonFields::take(&mut f, DOMAIN_FLEET_KEY_GRANT_ROTATION)?;
        f.exact_text("grant_variant", GRANT_VARIANT_ROTATION)?;
        let fleet_id = f.fixed("fleet_id")?;
        let fkek_key_id = f.fixed("fkek_key_id")?;
        let generation = f.uint("generation")?;
        f.exact_text("grant_capability", Capability::KeyRotate.as_str())?;
        let previous_fkek_key_id = f.fixed("previous_fkek_key_id")?;
        let previous_generation = f.uint("previous_generation")?;
        let count = f.uint("required_device_grant_count")?;
        let required_device_grant_count =
            u32::try_from(count).map_err(|_| f.bad("required_device_grant_count"))?;
        let required_device_grant_set_hash = f.fixed("required_device_grant_set_hash")?;
        let recovery_grant_signed_container_hash =
            f.fixed("recovery_grant_signed_container_hash")?;
        let activation_not_before_ms = f.uint("activation_not_before_ms")?;
        f.finish()?;

        if previous_generation.checked_add(1) != Some(generation) {
            return Err(RecordError::BadValue("generation"));
        }
        if fkek_key_id == previous_fkek_key_id {
            return Err(RecordError::BadValue("fkek_key_id"));
        }
        if !(1..=MAX_REQUIRED_GRANT_COUNT).contains(&count) {
            return Err(RecordError::BadValue("required_device_grant_count"));
        }
        if !(common.not_before_ms..common.not_after_ms).contains(&activation_not_before_ms) {
            return Err(RecordError::BadValue("activation_not_before_ms"));
        }
        Ok(Self {
            common,
            fleet_id,
            fkek_key_id,
            generation,
            previous_fkek_key_id,
            previous_generation,
            required_device_grant_count,
            required_device_grant_set_hash,
            recovery_grant_signed_container_hash,
            activation_not_before_ms,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.common.put(DOMAIN_FLEET_KEY_GRANT_ROTATION, &mut out);
        out.extend([
            ("grant_variant", c::t(GRANT_VARIANT_ROTATION)),
            ("fleet_id", c::b(&self.fleet_id)),
            ("fkek_key_id", c::b(&self.fkek_key_id)),
            ("generation", c::u(self.generation)),
            ("grant_capability", c::t(Capability::KeyRotate.as_str())),
            ("previous_fkek_key_id", c::b(&self.previous_fkek_key_id)),
            ("previous_generation", c::u(self.previous_generation)),
            (
                "required_device_grant_count",
                c::u(self.required_device_grant_count.into()),
            ),
            (
                "required_device_grant_set_hash",
                c::b(&self.required_device_grant_set_hash),
            ),
            (
                "recovery_grant_signed_container_hash",
                c::b(&self.recovery_grant_signed_container_hash),
            ),
            (
                "activation_not_before_ms",
                c::u(self.activation_not_before_ms),
            ),
        ]);
        c::encode(&c::m(out))
    }
}

// ------------------------------------------------- TenantRootKeyGrantV2 ---

/// Which root grant this is (plan 5.6.4). The previous-root pair exists only on
/// a rotation, so the enum carries it there and nowhere else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootGrantVariant {
    /// Generation 0, signed by its own subject in the one-time bootstrap.
    FirstRootSelfGrant,
    /// Another custodian of the ACTIVE generation.
    ExistingRootGrant,
    /// A custodian of PREPARING generation N+1, issued under ACTIVE N.
    RotationGrant {
        previous_root_key_id: [u8; 32],
        previous_root_generation: u64,
    },
}

impl RootGrantVariant {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FirstRootSelfGrant => "FirstRootSelfGrant",
            Self::ExistingRootGrant => "ExistingRootGrant",
            Self::RotationGrant { .. } => "RotationGrant",
        }
    }
}

/// Plan 5.6.4 `TenantRootKeyGrantV2`, suite 1 only. Parsing checks what the
/// payload alone decides: the exact HPKE tuple and lengths, the info bytes,
/// distinct subject keys and the generation rules of each variant. Whether
/// the issuer, approval link and generation match live state is the caller's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootKeyGrantV2 {
    pub common: CommonFields,
    pub variant: RootGrantVariant,
    pub root_key_id: [u8; 32],
    pub root_generation: u64,
    pub subject_account_id: [u8; 16],
    pub subject_device_id: [u8; 16],
    pub subject_signing_key_id: [u8; 32],
    pub recipient_hpke_key_id: [u8; 32],
    pub subject_device_approval_replay_id: [u8; 16],
    pub hpke_encapped_key_bytes: [u8; 32],
    pub hpke_wrapped_trk_bytes: [u8; 48],
}

impl TenantRootKeyGrantV2 {
    /// The fields the HPKE `info` binds.
    pub fn scope(&self) -> GrantScope {
        let k = &self.common;
        GrantScope {
            replay_id: k.replay_id,
            tenant_id: k.tenant_id,
            server_instance_id: k.server_instance_id,
            restore_epoch: k.restore_epoch,
            root_key_id: self.root_key_id,
            root_generation: self.root_generation,
            subject_account_id: self.subject_account_id,
            subject_device_id: self.subject_device_id,
            recipient_hpke_key_id: self.recipient_hpke_key_id,
        }
    }

    /// Exact `TenantRootKeyGrantHpkeInfoV2` bytes. As with the device grant,
    /// parsing refuses a payload whose stored bytes differ.
    pub fn hpke_info_bytes(&self) -> Vec<u8> {
        grants::root_grant_info(&self.scope())
    }

    /// Opens the wrapped TRK and checks it hashes to `root_key_id`. Every
    /// plaintext buffer is `Zeroizing`, so a refused TRK is wiped on drop.
    pub fn open_trk(
        &self,
        recipient_sk_bytes: &[u8],
    ) -> std::result::Result<Zeroizing<[u8; TRK_LEN]>, GrantError> {
        let trk = grants::open_trk(
            recipient_sk_bytes,
            &self.scope(),
            &self.hpke_encapped_key_bytes,
            &self.hpke_wrapped_trk_bytes,
        )?;
        if root_key_id(&trk) != self.root_key_id {
            return Err(GrantError::FieldMismatch("root_key_id"));
        }
        Ok(trk)
    }

    fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("TenantRootKeyGrantV2", payload)?;
        let common = CommonFields::take(&mut f, DOMAIN_TENANT_ROOT_KEY_GRANT)?;
        let variant = f.text("grant_variant")?;
        let root_key_id = f.fixed("root_key_id")?;
        let root_generation = f.uint("root_generation")?;
        f.exact_text("grant_capability", Capability::RootCustody.as_str())?;
        let subject_account_id = f.fixed("subject_account_id")?;
        let subject_device_id = f.fixed("subject_device_id")?;
        let subject_signing_key_id = f.fixed("subject_signing_key_id")?;
        let recipient_hpke_key_id = f.fixed("recipient_hpke_key_id")?;
        let subject_device_approval_replay_id = f.fixed("subject_device_approval_replay_id")?;
        let suite = [
            (
                "hpke_suite_id",
                u64::from(f.u16("hpke_suite_id")?),
                u64::from(HPKE_SUITE_ID_X25519_CHACHA),
            ),
            ("hpke_mode_id", f.uint("hpke_mode_id")?, HPKE_MODE_BASE),
            (
                "hpke_kem_id",
                u64::from(f.u16("hpke_kem_id")?),
                HPKE_KEM_X25519_HKDF_SHA256,
            ),
            (
                "hpke_kdf_id",
                u64::from(f.u16("hpke_kdf_id")?),
                HPKE_KDF_HKDF_SHA256,
            ),
            (
                "hpke_aead_id",
                u64::from(f.u16("hpke_aead_id")?),
                HPKE_AEAD_CHACHA20POLY1305,
            ),
        ];
        let hpke_info_bytes = f.bytes("hpke_info_bytes", 1, 1024)?;
        // Bytes32 and Bytes48 are the plan's field types, so a wrong length is
        // malformed before the suite is looked at (unlike the device grant,
        // whose lengths depend on its suite).
        let hpke_encapped_key_bytes = f.fixed("hpke_encapped_key_bytes")?;
        let hpke_wrapped_trk_bytes = f.fixed("hpke_wrapped_trk_bytes")?;
        let previous_root_key_id = f.opt_fixed::<32>("previous_root_key_id")?;
        let previous_root_generation = f.opt_uint("previous_root_generation")?;
        f.finish()?;

        // hpke_mode_id is a U8; a larger value is out of type, not a suite.
        if suite[1].1 > u64::from(u8::MAX) {
            return Err(RecordError::BadField {
                map: "TenantRootKeyGrantV2",
                field: "hpke_mode_id",
            });
        }
        for (field, id, exact) in suite {
            if id != exact {
                return Err(RecordError::Unsupported { field, id });
            }
        }
        let variant = match (
            variant.as_str(),
            previous_root_key_id,
            previous_root_generation,
        ) {
            ("FirstRootSelfGrant", None, None) => RootGrantVariant::FirstRootSelfGrant,
            ("ExistingRootGrant", None, None) => RootGrantVariant::ExistingRootGrant,
            ("RotationGrant", Some(previous_root_key_id), Some(previous_root_generation)) => {
                RootGrantVariant::RotationGrant {
                    previous_root_key_id,
                    previous_root_generation,
                }
            }
            // The previous-root pair is present iff the variant is a rotation.
            ("FirstRootSelfGrant" | "ExistingRootGrant" | "RotationGrant", _, _) => {
                return Err(RecordError::BadValue("previous_root_key_id"));
            }
            _ => return Err(RecordError::BadValue("grant_variant")),
        };
        match variant {
            // Bootstrap creates generation 0 and nothing else.
            RootGrantVariant::FirstRootSelfGrant if root_generation != 0 => {
                return Err(RecordError::BadValue("root_generation"));
            }
            RootGrantVariant::RotationGrant {
                previous_root_key_id,
                previous_root_generation,
            } => {
                if previous_root_generation.checked_add(1) != Some(root_generation) {
                    return Err(RecordError::BadValue("root_generation"));
                }
                if previous_root_key_id == root_key_id {
                    return Err(RecordError::BadValue("previous_root_key_id"));
                }
            }
            _ => {}
        }
        if subject_signing_key_id == recipient_hpke_key_id {
            return Err(RecordError::BadValue("recipient_hpke_key_id"));
        }
        let grant = Self {
            common,
            variant,
            root_key_id,
            root_generation,
            subject_account_id,
            subject_device_id,
            subject_signing_key_id,
            recipient_hpke_key_id,
            subject_device_approval_replay_id,
            hpke_encapped_key_bytes,
            hpke_wrapped_trk_bytes,
        };
        if hpke_info_bytes != grant.hpke_info_bytes() {
            return Err(RecordError::BadValue("hpke_info_bytes"));
        }
        Ok(grant)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.common.put(DOMAIN_TENANT_ROOT_KEY_GRANT, &mut out);
        out.extend([
            ("grant_variant", c::t(self.variant.as_str())),
            ("root_key_id", c::b(&self.root_key_id)),
            ("root_generation", c::u(self.root_generation)),
            ("grant_capability", c::t(Capability::RootCustody.as_str())),
            ("subject_account_id", c::b(&self.subject_account_id)),
            ("subject_device_id", c::b(&self.subject_device_id)),
            ("subject_signing_key_id", c::b(&self.subject_signing_key_id)),
            ("recipient_hpke_key_id", c::b(&self.recipient_hpke_key_id)),
            (
                "subject_device_approval_replay_id",
                c::b(&self.subject_device_approval_replay_id),
            ),
            ("hpke_suite_id", c::u(HPKE_SUITE_ID_X25519_CHACHA.into())),
            ("hpke_mode_id", c::u(HPKE_MODE_BASE)),
            ("hpke_kem_id", c::u(HPKE_KEM_X25519_HKDF_SHA256)),
            ("hpke_kdf_id", c::u(HPKE_KDF_HKDF_SHA256)),
            ("hpke_aead_id", c::u(HPKE_AEAD_CHACHA20POLY1305)),
            ("hpke_info_bytes", c::b(&self.hpke_info_bytes())),
            (
                "hpke_encapped_key_bytes",
                c::b(&self.hpke_encapped_key_bytes),
            ),
            ("hpke_wrapped_trk_bytes", c::b(&self.hpke_wrapped_trk_bytes)),
        ]);
        if let RootGrantVariant::RotationGrant {
            previous_root_key_id,
            previous_root_generation,
        } = self.variant
        {
            out.extend([
                ("previous_root_key_id", c::b(&previous_root_key_id)),
                ("previous_root_generation", c::u(previous_root_generation)),
            ]);
        }
        c::encode(&c::m(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Deterministic test bytes, the same generator as the signing tests.
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

    fn issuer() -> SigningKey {
        SigningKey::from_bytes(&fx::<32>("issuer-signing-key"))
    }

    fn common() -> CommonFields {
        CommonFields {
            replay_id: fx("replay"),
            tenant_id: fx("tenant-a"),
            issued_at_ms: 1_700_000_000_000,
            not_before_ms: 1_700_000_000_000,
            not_after_ms: 1_700_000_600_000,
            server_instance_id: fx("server-1"),
            restore_epoch: 7,
        }
    }

    fn approval() -> DeviceApprovalV2 {
        DeviceApprovalV2 {
            common: common(),
            subject_account_id: fx("account-a"),
            subject_device_id: fx("device-a"),
            subject_signing_key_id: fx("device-a-signing"),
            subject_hpke_key_id: fx("device-a-hpke"),
            approval_scope_kind: ApprovalScopeKind::Tenant,
            approval_scope_id: fx("tenant-a"),
        }
    }

    fn device_grant(
        capability: Capability,
        scope_kind: CapabilityScopeKind,
    ) -> TenantCapabilityGrantV2 {
        TenantCapabilityGrantV2 {
            common: common(),
            subject: GrantSubject::Device {
                account_id: fx("account-a"),
                device_id: fx("device-a"),
                signing_key_id: fx("device-a-signing"),
                hpke_key_id: fx("device-a-hpke"),
            },
            scope_kind,
            scope_id: if scope_kind == CapabilityScopeKind::Tenant {
                fx("tenant-a")
            } else {
                fx("scope")
            },
            capability,
        }
    }

    fn hpke_grant() -> DeviceHpkeGrantV2 {
        DeviceHpkeGrantV2 {
            common: common(),
            fleet_id: fx("fleet-1"),
            fkek_key_id: fx("fkek-1"),
            generation: 3,
            subject_account_id: fx("account-a"),
            subject_device_id: fx("device-a"),
            subject_signing_key_id: fx("device-a-signing"),
            recipient_hpke_key_id: fx("device-a-hpke"),
            hpke_encapped_key_bytes: fx::<32>("encapped").to_vec(),
            hpke_wrapped_fleet_key_bytes: fx::<48>("wrapped").to_vec(),
        }
    }

    fn recovery_grant() -> RecoveryGrantV2 {
        RecoveryGrantV2 {
            common: common(),
            fleet_id: fx("fleet-1"),
            fkek_key_id: fx("fkek-1"),
            generation: 3,
            recipient_root_key_id: fx("root-key-1"),
            recipient_root_generation: 2,
            root_wrap_nonce_bytes: fx("root-wrap-nonce"),
            wrapped_fleet_key_bytes: fx("root-wrapped-fkek"),
        }
    }

    fn rotation_grant() -> RotationGrantV2 {
        RotationGrantV2 {
            common: common(),
            fleet_id: fx("fleet-1"),
            fkek_key_id: fx("fkek-1"),
            generation: 3,
            previous_fkek_key_id: fx("fkek-0"),
            previous_generation: 2,
            required_device_grant_count: 2,
            required_device_grant_set_hash: fx("device-grant-set"),
            recovery_grant_signed_container_hash: fx("recovery-grant"),
            activation_not_before_ms: 1_700_000_300_000,
        }
    }

    /// The subject signs its own grant, which a first self-grant requires.
    fn root_grant(variant: RootGrantVariant, root_generation: u64) -> TenantRootKeyGrantV2 {
        TenantRootKeyGrantV2 {
            common: common(),
            variant,
            root_key_id: fx("root-key-1"),
            root_generation,
            subject_account_id: fx("account-a"),
            subject_device_id: fx("device-a"),
            subject_signing_key_id: signing_key_id(issuer().verifying_key().as_bytes()),
            recipient_hpke_key_id: fx("device-a-hpke"),
            subject_device_approval_replay_id: fx("approval-replay"),
            hpke_encapped_key_bytes: fx("root-encapped"),
            hpke_wrapped_trk_bytes: fx("root-wrapped"),
        }
    }

    fn rotation(previous_root_generation: u64) -> RootGrantVariant {
        RootGrantVariant::RotationGrant {
            previous_root_key_id: fx("root-key-0"),
            previous_root_generation,
        }
    }

    /// Re-encodes canonical map bytes with `edit` applied to the field list.
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

    fn code_of<T: std::fmt::Debug>(r: Result<T>) -> &'static str {
        r.expect_err("expected a rejection").code()
    }

    /// Signs `payload` under `domain`, then parses and verifies the record.
    fn sign_and_verify(domain: &str, payload: &[u8]) -> Result<VerifiedRecord> {
        let sk = issuer();
        AuthorizationRecord::parse(&build_record(&sk, domain, payload))?
            .verify_signature(sk.verifying_key().as_bytes())
    }

    // ---------------------------------------------------------- container ---

    #[test]
    fn record_roundtrips_and_verifies() {
        let sk = issuer();
        let payload = approval().encode();
        let exact = build_record(&sk, DOMAIN_DEVICE_APPROVAL, &payload);
        let rec = AuthorizationRecord::parse(&exact).unwrap();
        assert_eq!(rec.payload_domain(), DOMAIN_DEVICE_APPROVAL);
        assert_eq!(rec.canonical_payload_bytes(), payload);
        assert_eq!(rec.exact_signed_container_bytes(), exact);
        assert_eq!(
            rec.issuer_signing_key_id(),
            &signing_key_id(sk.verifying_key().as_bytes())
        );
        let verified = rec.verify_signature(sk.verifying_key().as_bytes()).unwrap();
        assert_eq!(verified.payload(), &Payload::DeviceApproval(approval()));
        assert_eq!(verified.record().exact_signed_container_bytes(), exact);
    }

    /// Regression vectors pinned at this commit, so any change to a field set,
    /// a payload encoding or the container assembly shows up as a diff.
    #[test]
    fn golden_vectors() {
        let cases = [
            (
                DOMAIN_DEVICE_APPROVAL,
                approval().encode(),
                "06985017828088ac0bce13425bf0e439af3937643091931a5e7648b913b60189",
                "a8d4bc42778377524176aa3f806306b133f94d26df10c3f07406856ee66987da",
            ),
            (
                DOMAIN_TENANT_CAPABILITY_GRANT,
                device_grant(Capability::DeviceApprove, CapabilityScopeKind::Fleet).encode(),
                "db116833af5bdf359b78f153c8f1bf1ecbee00993584effd8d782b1f75e938d8",
                "d039b6d784b7316f6feca96987c957760c05621905c11b458353576f9f8f4882",
            ),
            (
                DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE,
                hpke_grant().encode(),
                "f816e7b501732ffa3ce94236395d0497e7b30ba4537b04fbcaccf8415eed558f",
                "4a9150a067d5951fbaf6bb672d38c0b0271b5005daa87593cb4b34d5135fbc42",
            ),
            (
                DOMAIN_FLEET_KEY_GRANT_RECOVERY,
                recovery_grant().encode(),
                "b56bf03af50a7c5918681001896cd52e661337f1e1d2c66cedc078f8ecbf4b80",
                "73f67cd320747df9c490a2a797be805897a9b74bfc916be58dcf60dbfab13e94",
            ),
            (
                DOMAIN_FLEET_KEY_GRANT_ROTATION,
                rotation_grant().encode(),
                "f97f4939add237ed907d2371b83c9c72c81c98f6dfbd1637180a275714cddff9",
                "3f61b5444dd347870b8efbdd55d4dc183046fed1c56171c9eb97b3b8ff0a85ca",
            ),
            (
                DOMAIN_TENANT_ROOT_KEY_GRANT,
                root_grant(RootGrantVariant::FirstRootSelfGrant, 0).encode(),
                "bf221871b815b09dc45a849639431b139009a3dddf1a2ba9c8e4242b5ee42627",
                "06525a353d6cf1e6164e9b5fa19a74070ece459aa2e84473482264399a80403f",
            ),
            (
                DOMAIN_TENANT_ROOT_KEY_GRANT,
                root_grant(rotation(4), 5).encode(),
                "80ecf31281d0a761e65920d5f149169ff9e53ac246f28903648d30dc88629525",
                "2ebf1f30cad074f2b343e4f3cd2850434a26f8d7a73b9ca442658c0d42a3768d",
            ),
        ];
        for (domain, payload, container_hash, exact_sha) in cases {
            let rec =
                AuthorizationRecord::parse(&build_record(&issuer(), domain, &payload)).unwrap();
            assert_eq!(hex(rec.signed_container_hash()), container_hash, "{domain}");
            assert_eq!(
                hex(rec.exact_signed_container_bytes_sha256()),
                exact_sha,
                "{domain}"
            );
        }
        assert_eq!(
            hex(&c::sha256(&approval().encode())),
            "89e4d4c23e4a1aa0d085b812bedb12cf68c52433b4e2f50c4f972733e6031048"
        );
        // D-8 asks for golden info bytes; pinned by length and SHA-256.
        let info = hpke_grant().hpke_info_bytes();
        assert_eq!(info.len(), 492);
        assert_eq!(
            hex(&c::sha256(&info)),
            "2a4877e5df7b46a2c00c6809e334f58cdffdeefe063b36d78c7611c593f8e518"
        );
        // D-5 wrap context, pinned the same way.
        let ctx = recovery_grant().root_wrap_context_bytes();
        assert_eq!(ctx.len(), 399);
        assert_eq!(
            hex(&c::sha256(&ctx)),
            "6b7d2dfe351d2b078875dcb142be28e627c6d290120884b53fc60d3dca2945d1"
        );
        let info = root_grant(RootGrantVariant::FirstRootSelfGrant, 0).hpke_info_bytes();
        assert_eq!(info.len(), 460);
        assert_eq!(
            hex(&c::sha256(&info)),
            "83cf05a9e2a487fa64210dfa9fdc2486e9e84615f1a4842d920c8190a42f1493"
        );
    }

    #[test]
    fn container_rejects_every_field_level_defect() {
        let good = build_record(&issuer(), DOMAIN_DEVICE_APPROVAL, &approval().encode());
        let with = |key: &str, v: Value| edit_map(&good, |e| set(e, key, v));
        let without = |key: &str| edit_map(&good, |e| e.retain(|(k, _)| k != key));
        let parse = |b: &[u8]| AuthorizationRecord::parse(b);

        // Closed map.
        assert!(matches!(
            parse(&with("extra", c::u(1))),
            Err(RecordError::UnknownField { .. })
        ));
        assert!(matches!(
            parse(&without("payload_sha256")),
            Err(RecordError::MissingField {
                field: "payload_sha256",
                ..
            })
        ));
        // Exact values, and newer versions or suites this build cannot read.
        assert_eq!(
            parse(&with("container_domain", c::t("shardx.other"))),
            Err(RecordError::BadValue("container_domain"))
        );
        for (field, v) in [
            ("container_version", 3),
            ("payload_version", 3),
            ("signature_suite_id", 2),
            ("signature_version", 2),
        ] {
            assert_eq!(
                parse(&with(field, c::u(v))),
                Err(RecordError::Unsupported { field, id: v }),
                "{field}"
            );
            assert_eq!(code_of(parse(&with(field, c::u(v)))), "SCHEMA_UNSUPPORTED");
            // A newer version may add fields; its version decides, not the extra field.
            let newer = edit_map(&good, |e| {
                set(e, field, c::u(v));
                set(e, "added_in_newer_version", c::u(1));
            });
            assert_eq!(code_of(parse(&newer)), "SCHEMA_UNSUPPORTED", "{field}");
        }
        let oversized = with("extra", c::b(&vec![0u8; MAX_RECORD_BYTES]));
        assert_eq!(
            parse(&oversized),
            Err(RecordError::BadField {
                map: "SignedAuthorizationRecordV2",
                field: "exact_signed_container_bytes",
            })
        );
        assert_eq!(
            code_of(parse(&with("signature_bytes", c::b(&[1u8; 63])))),
            "NON_CANONICAL_RECORD"
        );
        // Hashes are recomputed, never trusted.
        assert_eq!(
            code_of(parse(&with("payload_sha256", c::b(&[0u8; 32])))),
            "SIGNED_BYTES_MISMATCH"
        );
        assert_eq!(
            code_of(parse(&with("signed_container_hash", c::b(&[0u8; 32])))),
            "SIGNED_CONTAINER_HASH_MISMATCH"
        );
        // A trailing byte and a non-shortest length are not canonical.
        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(code_of(parse(&trailing)), "NON_CANONICAL_RECORD");
        assert_eq!(code_of(parse(&[0x78, 0x01, b'a'])), "NON_CANONICAL_RECORD");
    }

    #[test]
    fn signature_binds_issuer_and_bytes() {
        let sk = issuer();
        let exact = build_record(&sk, DOMAIN_DEVICE_APPROVAL, &approval().encode());
        let parsed = || AuthorizationRecord::parse(&exact).unwrap();

        let other = SigningKey::from_bytes(&fx::<32>("someone-else"));
        assert_eq!(
            parsed().verify_signature(other.verifying_key().as_bytes()),
            Err(RecordError::IssuerKeyMismatch)
        );

        // A flipped signature with a recomputed container hash, which is what a
        // forger would send.
        let forged = edit_map(&exact, |e| {
            let Some((_, Value::Bytes(sig))) = e.iter_mut().find(|(k, _)| k == "signature_bytes")
            else {
                panic!()
            };
            sig[0] ^= 1;
            let core: Vec<(String, Value)> = e
                .iter()
                .filter(|(k, _)| k != "signed_container_hash")
                .cloned()
                .collect();
            let hash = c::domain_hash(c::L_SIGNED_CONTAINER, &c::encode(&Value::Map(core)));
            set(e, "signed_container_hash", c::b(&hash));
        });
        let rec = AuthorizationRecord::parse(&forged).unwrap();
        assert_eq!(
            code_of(rec.verify_signature(sk.verifying_key().as_bytes())),
            "SIGNATURE_INVALID"
        );
    }

    #[test]
    fn small_order_issuer_key_never_verifies() {
        // Issuer key = the identity point, R = identity, S = 0. Plain `verify`
        // accepts this signature for every message; `verify_strict` must not.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&identity);
        let payload = approval().encode();
        let mut core = tbs_fields(
            DOMAIN_DEVICE_APPROVAL,
            &payload,
            &c::sha256(&payload),
            &signing_key_id(&identity),
        );
        core.push(("signature_bytes", c::b(&sig)));
        let hash = c::domain_hash(c::L_SIGNED_CONTAINER, &c::encode(&c::m(core.clone())));
        core.push(("signed_container_hash", c::b(&hash)));
        let exact = c::encode(&c::m(core));

        let rec = AuthorizationRecord::parse(&exact).unwrap();
        assert_eq!(
            rec.verify_signature(&identity).err(),
            Some(RecordError::Signature)
        );
    }

    #[test]
    fn payload_must_match_the_container_and_a_known_schema() {
        let payload = approval().encode();
        // Signed under another known domain.
        assert_eq!(
            sign_and_verify(DOMAIN_TENANT_CAPABILITY_GRANT, &payload),
            Err(RecordError::BadValue("payload_domain"))
        );
        // A payload that says version 3 inside a container that says 2.
        let v3 = edit_map(&payload, |e| set(e, "version", c::u(3)));
        assert_eq!(
            sign_and_verify(DOMAIN_DEVICE_APPROVAL, &v3),
            Err(RecordError::BadValue("payload_version"))
        );
        // A domain this build does not know, named the same in both places.
        let unknown = edit_map(&payload, |e| set(e, "domain", c::t("shardx.auth.other.v2")));
        assert_eq!(
            sign_and_verify("shardx.auth.other.v2", &unknown),
            Err(RecordError::UnknownPayloadDomain(
                "shardx.auth.other.v2".into()
            ))
        );
        assert_eq!(
            code_of(sign_and_verify("shardx.auth.other.v2", &unknown)),
            "SCHEMA_UNSUPPORTED"
        );
    }

    #[test]
    fn integers_outside_the_sqlite_domain_have_their_own_code() {
        let payload = edit_map(&approval().encode(), |e| set(e, "restore_epoch", c::u(1)));
        let at = payload
            .windows(14)
            .position(|w| w == b"\x6drestore_epoch")
            .unwrap()
            + 14;
        // 2^63 (major 0, 8-byte argument), -1 (major 1), and 7 and -1 in
        // overlong forms.
        for value in [
            &[0x1b, 0x80, 0, 0, 0, 0, 0, 0, 0][..],
            &[0x20],
            &[0x18, 0x07],
            &[0x38, 0x00],
        ] {
            let mut raw = payload[..at].to_vec();
            raw.extend_from_slice(value);
            raw.extend_from_slice(&payload[at + 1..]);
            assert_eq!(
                code_of(DeviceApprovalV2::parse(&raw)),
                "WIRE_INTEGER_OUT_OF_RANGE",
                "{value:02x?}"
            );
        }
    }

    // --------------------------------------------------------- approvals ---

    #[test]
    fn approval_rejects_contract_violations() {
        let p = approval();
        let bad = |edit: &dyn Fn(&mut DeviceApprovalV2)| {
            let mut a = p.clone();
            edit(&mut a);
            DeviceApprovalV2::parse(&a.encode())
        };
        assert_eq!(
            bad(&|a| a.common.issued_at_ms = a.common.not_before_ms + 1),
            Err(RecordError::BadValue("issued_at_ms"))
        );
        assert_eq!(
            bad(&|a| a.common.not_after_ms = a.common.not_before_ms),
            Err(RecordError::BadValue("not_after_ms"))
        );
        assert_eq!(
            bad(&|a| a.subject_hpke_key_id = a.subject_signing_key_id),
            Err(RecordError::BadValue("subject_hpke_key_id"))
        );
        assert_eq!(
            bad(&|a| a.approval_scope_id = fx("other")),
            Err(RecordError::BadValue("approval_scope_id"))
        );
        // A fleet scope may name any fleet; the caller checks it.
        assert!(bad(&|a| {
            a.approval_scope_kind = ApprovalScopeKind::Fleet;
            a.approval_scope_id = fx("fleet-1");
        })
        .is_ok());

        let raw = p.encode();
        let edited =
            |key: &str, v: Value| DeviceApprovalV2::parse(&edit_map(&raw, |e| set(e, key, v)));
        assert_eq!(
            edited("approved_use", c::t("team.admin")),
            Err(RecordError::BadValue("approved_use"))
        );
        assert_eq!(
            edited("approval_scope_kind", c::t("profile")),
            Err(RecordError::BadValue("approval_scope_kind"))
        );
        assert_eq!(
            edited("version", c::u(1)),
            Err(RecordError::BadValue("version"))
        );
        assert_eq!(
            edited("domain", c::t(DOMAIN_TENANT_CAPABILITY_GRANT)),
            Err(RecordError::BadValue("domain"))
        );
        assert_eq!(
            code_of(edited("subject_device_id", c::b(&[0u8; 15]))),
            "NON_CANONICAL_RECORD"
        );
        assert_eq!(code_of(edited("note", c::t("x"))), "NON_CANONICAL_RECORD");
    }

    // ------------------------------------------------------- capabilities ---

    /// ADR 0002 D-2, written out by hand: each value and the scope kinds a
    /// capability grant may carry it with. `root.custody` keeps its L484 shape
    /// at tenant scope but is never issuable; the last two never appear here.
    const D2_TABLE: [(&str, &[&str]); 14] = [
        ("tenant.manage", &["tenant"]),
        ("membership.manage", &["tenant"]),
        ("fleet.manage", &["tenant", "fleet"]),
        ("device.approve", &["tenant", "fleet"]),
        ("device.revoke", &["tenant", "fleet"]),
        ("key.rotate", &["tenant", "fleet"]),
        ("recovery.manage", &["tenant"]),
        ("lease.force_expire", &["tenant", "fleet", "profile"]),
        ("profile.publish", &["tenant", "fleet"]),
        ("profile.checkout", &["tenant", "fleet", "profile"]),
        ("profile.commit", &["tenant", "fleet", "profile"]),
        ("root.custody", &["tenant"]),
        ("fleet.key.receive", &[]),
        ("fleet.key.recover", &[]),
    ];

    #[test]
    fn capability_grants_follow_the_d2_table() {
        use CapabilityScopeKind::{Fleet, Profile, Tenant};
        assert_eq!(Capability::ALL.len(), D2_TABLE.len());
        for (name, scopes) in D2_TABLE {
            let cap = Capability::parse(name).unwrap_or_else(|| panic!("{name} missing"));
            assert_eq!(cap.as_str(), name);
            for scope in [Tenant, Fleet, Profile] {
                let parsed = TenantCapabilityGrantV2::parse(&device_grant(cap, scope).encode());
                assert_eq!(
                    parsed.is_ok(),
                    scopes.contains(&scope.as_str()),
                    "{name} at {scope:?}: {parsed:?}"
                );
                if let Ok(g) = parsed {
                    assert_eq!(g.is_issuable(), name != "root.custody", "{name}");
                }
            }
        }
    }

    #[test]
    fn capability_strings_outside_the_closed_set_reject() {
        let raw = device_grant(Capability::DeviceApprove, CapabilityScopeKind::Tenant).encode();
        let edited = |field: &str, v: &str| {
            TenantCapabilityGrantV2::parse(&edit_map(&raw, |e| set(e, field, c::t(v))))
        };
        for s in [
            "root-custody",
            "Device.approve",
            "device.approve.",
            "fleet.key.grant",
            "device",
            "",
        ] {
            assert_eq!(
                edited("capability", s),
                Err(RecordError::BadValue("capability")),
                "{s:?}"
            );
        }
        assert_eq!(
            edited("subject_kind", "service"),
            Err(RecordError::BadValue("subject_kind"))
        );
        assert_eq!(
            edited("scope_kind", "account"),
            Err(RecordError::BadValue("scope_kind"))
        );
    }

    #[test]
    fn subject_device_fields_are_present_iff_device_scoped() {
        let device = device_grant(Capability::ProfileCommit, CapabilityScopeKind::Profile);
        let account = TenantCapabilityGrantV2 {
            subject: GrantSubject::Account {
                account_id: fx("account-a"),
            },
            ..device.clone()
        };
        assert_eq!(
            TenantCapabilityGrantV2::parse(&account.encode()).unwrap(),
            account
        );

        let with_device = edit_map(&account.encode(), |e| {
            set(e, "subject_device_id", c::b(&fx::<16>("device-a")))
        });
        assert_eq!(
            TenantCapabilityGrantV2::parse(&with_device),
            Err(RecordError::BadValue("subject_kind"))
        );

        let no_hpke = edit_map(&device.encode(), |e| {
            e.retain(|(k, _)| k != "subject_hpke_key_id")
        });
        assert_eq!(
            TenantCapabilityGrantV2::parse(&no_hpke),
            Err(RecordError::BadValue("subject_kind"))
        );

        // The device's signing and HPKE keys must differ.
        let same_keys = edit_map(&device.encode(), |e| {
            set(
                e,
                "subject_hpke_key_id",
                c::b(&fx::<32>("device-a-signing")),
            )
        });
        assert_eq!(
            TenantCapabilityGrantV2::parse(&same_keys),
            Err(RecordError::BadValue("subject_hpke_key_id"))
        );

        // root.custody is device-only (L484).
        let root_account = TenantCapabilityGrantV2 {
            capability: Capability::RootCustody,
            scope_kind: CapabilityScopeKind::Tenant,
            scope_id: fx("tenant-a"),
            ..account
        };
        assert_eq!(
            TenantCapabilityGrantV2::parse(&root_account.encode()),
            Err(RecordError::BadValue("capability"))
        );
    }

    #[test]
    fn tenant_scope_must_name_the_tenant() {
        let mut g = device_grant(Capability::TenantManage, CapabilityScopeKind::Tenant);
        g.scope_id = fx("other-tenant");
        assert_eq!(
            TenantCapabilityGrantV2::parse(&g.encode()),
            Err(RecordError::BadValue("scope_id"))
        );
    }

    // -------------------------------------------------- device HPKE grants ---

    #[test]
    fn grants_roundtrip_inside_a_record() {
        let g = hpke_grant();
        let verified = sign_and_verify(DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE, &g.encode()).unwrap();
        assert_eq!(verified.payload(), &Payload::DeviceHpkeGrant(g));

        let g = device_grant(Capability::KeyRotate, CapabilityScopeKind::Fleet);
        let verified = sign_and_verify(DOMAIN_TENANT_CAPABILITY_GRANT, &g.encode()).unwrap();
        assert_eq!(verified.payload(), &Payload::TenantCapabilityGrant(g));
    }

    #[test]
    fn hpke_grant_binds_info_suite_and_lengths() {
        let raw = hpke_grant().encode();
        let edited =
            |key: &str, v: Value| DeviceHpkeGrantV2::parse(&edit_map(&raw, |e| set(e, key, v)));

        // Info built for another generation does not match the signed fields.
        let other_info = DeviceHpkeGrantV2 {
            generation: 4,
            ..hpke_grant()
        }
        .hpke_info_bytes();
        assert_eq!(
            edited("hpke_info_bytes", c::b(&other_info)),
            Err(RecordError::BadValue("hpke_info_bytes"))
        );
        assert_eq!(
            code_of(edited("hpke_suite_id", c::u(2))),
            "SCHEMA_UNSUPPORTED"
        );
        assert_eq!(
            code_of(edited("hpke_encapped_key_bytes", c::b(&[1u8; 31]))),
            "NON_CANONICAL_RECORD"
        );
        assert_eq!(
            code_of(edited("hpke_wrapped_fleet_key_bytes", c::b(&[1u8; 49]))),
            "NON_CANONICAL_RECORD"
        );
        assert_eq!(
            edited("grant_capability", c::t("key.rotate")),
            Err(RecordError::BadValue("grant_capability"))
        );
        assert_eq!(
            edited("grant_variant", c::t("FirstFleetSelfGrant")),
            Err(RecordError::BadValue("grant_variant"))
        );
        assert!(matches!(
            edited("extra", c::u(1)),
            Err(RecordError::UnknownField { .. })
        ));
        let missing = edit_map(&raw, |e| e.retain(|(k, _)| k != "fleet_id"));
        assert!(matches!(
            DeviceHpkeGrantV2::parse(&missing),
            Err(RecordError::MissingField {
                field: "fleet_id",
                ..
            })
        ));

        let same_keys = DeviceHpkeGrantV2 {
            recipient_hpke_key_id: fx("device-a-signing"),
            ..hpke_grant()
        };
        assert_eq!(
            DeviceHpkeGrantV2::parse(&same_keys.encode()),
            Err(RecordError::BadValue("recipient_hpke_key_id"))
        );
    }

    // ------------------------------------------ fleet recovery and rotation ---

    #[test]
    fn recovery_and_rotation_grants_roundtrip_inside_a_record() {
        let g = recovery_grant();
        let verified = sign_and_verify(DOMAIN_FLEET_KEY_GRANT_RECOVERY, &g.encode()).unwrap();
        assert_eq!(verified.payload(), &Payload::RecoveryGrant(g));

        let g = rotation_grant();
        let verified = sign_and_verify(DOMAIN_FLEET_KEY_GRANT_ROTATION, &g.encode()).unwrap();
        assert_eq!(verified.payload(), &Payload::RotationGrant(g));

        // A variant signed under another variant's domain is refused.
        assert_eq!(
            code_of(sign_and_verify(
                DOMAIN_FLEET_KEY_GRANT_ROTATION,
                &recovery_grant().encode()
            )),
            "NON_CANONICAL_RECORD"
        );
    }

    #[test]
    fn recovery_grant_binds_context_suite_and_lengths() {
        let raw = recovery_grant().encode();
        let edited =
            |key: &str, v: Value| RecoveryGrantV2::parse(&edit_map(&raw, |e| set(e, key, v)));

        let other_ctx = RecoveryGrantV2 {
            recipient_root_generation: 3,
            ..recovery_grant()
        }
        .root_wrap_context_bytes();
        assert_eq!(
            edited("root_wrap_context_bytes", c::b(&other_ctx)),
            Err(RecordError::BadValue("root_wrap_context_bytes"))
        );
        assert_eq!(
            code_of(edited("root_wrap_suite_id", c::u(2))),
            "SCHEMA_UNSUPPORTED"
        );
        assert_eq!(
            code_of(edited("root_wrap_nonce_bytes", c::b(&[1u8; 24]))),
            "NON_CANONICAL_RECORD"
        );
        assert_eq!(
            code_of(edited("wrapped_fleet_key_bytes", c::b(&[1u8; 47]))),
            "NON_CANONICAL_RECORD"
        );
        assert_eq!(
            edited("grant_capability", c::t("fleet.key.receive")),
            Err(RecordError::BadValue("grant_capability"))
        );
        assert_eq!(
            edited("grant_variant", c::t("DeviceHpkeGrant")),
            Err(RecordError::BadValue("grant_variant"))
        );
        // Plan L495: no device or HPKE fields.
        assert!(matches!(
            edited("recipient_hpke_key_id", c::b(&[1u8; 32])),
            Err(RecordError::UnknownField { .. })
        ));
    }

    #[test]
    fn recovery_grant_opens_only_under_its_root_and_to_its_fkek() {
        let trk = fx::<32>("tenant-root-key");
        let fkek = fx::<32>("fleet-key");
        let named = || RecoveryGrantV2 {
            recipient_root_key_id: root_key_id(&trk),
            fkek_key_id: fkek_key_id(&fkek),
            ..recovery_grant()
        };
        let mut g = named();
        g.seal(&trk, &fkek).unwrap();
        let g = RecoveryGrantV2::parse(&g.encode()).unwrap();
        assert_eq!(*g.open_fkek(&trk).unwrap(), fkek);

        // seal refuses keys the grant does not name.
        assert_eq!(
            named().seal(&fx("other-root"), &fkek),
            Err(GrantError::FieldMismatch("recipient_root_key_id"))
        );
        assert_eq!(
            named().seal(&trk, &fx("other-fkek")),
            Err(GrantError::FieldMismatch("fkek_key_id"))
        );
        // Another TRK is refused before any unwrap.
        assert_eq!(
            g.open_fkek(&fx("other-root")),
            Err(GrantError::FieldMismatch("recipient_root_key_id"))
        );
        // A grant whose signed fields moved no longer unwraps.
        let moved = RecoveryGrantV2 {
            generation: 4,
            ..g.clone()
        };
        assert_eq!(moved.open_fkek(&trk), Err(GrantError::AeadFailure));
        // Wrapped honestly under its own context, but around another FKEK:
        // refused after unwrap.
        let mut lying = named();
        lying.wrapped_fleet_key_bytes = root_wrap(
            &trk,
            &lying.root_wrap_nonce_bytes,
            &lying.root_wrap_context_bytes(),
            &fx("other-fkek"),
        )
        .unwrap();
        assert_eq!(
            lying.open_fkek(&trk),
            Err(GrantError::FieldMismatch("fkek_key_id"))
        );
    }

    #[test]
    fn rotation_grant_follows_its_generation_window_and_count_rules() {
        let parse = |g: RotationGrantV2| RotationGrantV2::parse(&g.encode());
        let base = rotation_grant();

        assert_eq!(
            parse(RotationGrantV2 {
                generation: 4,
                ..base.clone()
            }),
            Err(RecordError::BadValue("generation"))
        );
        assert_eq!(
            parse(RotationGrantV2 {
                previous_fkek_key_id: base.fkek_key_id,
                ..base.clone()
            }),
            Err(RecordError::BadValue("fkek_key_id"))
        );
        for count in [0, 65536] {
            assert_eq!(
                parse(RotationGrantV2 {
                    required_device_grant_count: count,
                    ..base.clone()
                }),
                Err(RecordError::BadValue("required_device_grant_count"))
            );
        }
        assert!(parse(RotationGrantV2 {
            required_device_grant_count: 65535,
            ..base.clone()
        })
        .is_ok());
        let raw = base.encode();
        assert_eq!(
            code_of(RotationGrantV2::parse(&edit_map(&raw, |e| set(
                e,
                "required_device_grant_count",
                c::u(1 << 32)
            )))),
            "NON_CANONICAL_RECORD"
        );
        // activation_not_before_ms is inside [not_before_ms, not_after_ms).
        let k = &base.common;
        for (at, ok) in [
            (k.not_before_ms - 1, false),
            (k.not_before_ms, true),
            (k.not_after_ms - 1, true),
            (k.not_after_ms, false),
        ] {
            let r = parse(RotationGrantV2 {
                activation_not_before_ms: at,
                ..base.clone()
            });
            if ok {
                assert!(r.is_ok(), "{at}");
            } else {
                assert_eq!(r, Err(RecordError::BadValue("activation_not_before_ms")));
            }
        }
        assert_eq!(
            RotationGrantV2::parse(&edit_map(&raw, |e| set(
                e,
                "grant_capability",
                c::t("fleet.manage")
            ))),
            Err(RecordError::BadValue("grant_capability"))
        );
    }

    // ------------------------------------------------- tenant root grants ---

    #[test]
    fn root_grants_roundtrip_inside_a_record() {
        for g in [
            root_grant(RootGrantVariant::FirstRootSelfGrant, 0),
            root_grant(RootGrantVariant::ExistingRootGrant, 0),
            root_grant(RootGrantVariant::ExistingRootGrant, 3),
            root_grant(rotation(0), 1),
        ] {
            let raw = g.encode();
            assert_eq!(TenantRootKeyGrantV2::parse(&raw).unwrap().encode(), raw);
            let verified = sign_and_verify(DOMAIN_TENANT_ROOT_KEY_GRANT, &raw).unwrap();
            assert_eq!(verified.payload(), &Payload::TenantRootKeyGrant(g));
        }
        // The info map of plan 5.6.4, written out here rather than taken from
        // the helper the codec uses, so a wrong helper cannot pin itself.
        let g = root_grant(RootGrantVariant::ExistingRootGrant, 3);
        let k = &g.common;
        let plan_info = c::encode(&c::m(vec![
            (
                "domain",
                c::t("shardx.keys.tenant-root-key-grant.hpke-info.v2"),
            ),
            ("version", c::u(2)),
            ("replay_id", c::b(&k.replay_id)),
            ("tenant_id", c::b(&k.tenant_id)),
            ("server_instance_id", c::b(&k.server_instance_id)),
            ("restore_epoch", c::u(k.restore_epoch)),
            ("root_key_id", c::b(&g.root_key_id)),
            ("root_generation", c::u(3)),
            ("subject_account_id", c::b(&g.subject_account_id)),
            ("subject_device_id", c::b(&g.subject_device_id)),
            ("recipient_hpke_key_id", c::b(&g.recipient_hpke_key_id)),
            ("hpke_suite_id", c::u(1)),
            ("hpke_mode_id", c::u(0)),
            ("hpke_kem_id", c::u(0x0020)),
            ("hpke_kdf_id", c::u(0x0001)),
            ("hpke_aead_id", c::u(0x0003)),
            ("grant_capability", c::t("root.custody")),
        ]));
        assert_eq!(g.hpke_info_bytes(), plan_info);
    }

    #[test]
    fn a_first_self_grant_is_signed_by_its_subject() {
        let other = SigningKey::from_bytes(&fx::<32>("another-custodian"));
        let signed_by_other = |g: TenantRootKeyGrantV2| {
            AuthorizationRecord::parse(&build_record(
                &other,
                DOMAIN_TENANT_ROOT_KEY_GRANT,
                &g.encode(),
            ))
        };
        assert_eq!(
            signed_by_other(root_grant(RootGrantVariant::FirstRootSelfGrant, 0)),
            Err(RecordError::BadValue("issuer_signing_key_id"))
        );
        // Any custodian may issue the other variants; the caller checks which.
        assert!(signed_by_other(root_grant(RootGrantVariant::ExistingRootGrant, 0)).is_ok());
        assert!(signed_by_other(root_grant(rotation(0), 1)).is_ok());
    }

    #[test]
    fn root_grant_pins_the_hpke_tuple_info_and_lengths() {
        let raw = root_grant(RootGrantVariant::ExistingRootGrant, 3).encode();
        let edited =
            |key: &str, v: Value| TenantRootKeyGrantV2::parse(&edit_map(&raw, |e| set(e, key, v)));

        for (field, wrong) in [
            ("hpke_suite_id", 2),
            ("hpke_mode_id", 1),
            ("hpke_kem_id", 0x0021),
            ("hpke_kdf_id", 0x0002),
            ("hpke_aead_id", 0x0001),
        ] {
            assert_eq!(
                edited(field, c::u(wrong)),
                Err(RecordError::Unsupported { field, id: wrong }),
                "{field}"
            );
        }
        // Out of type is malformed, not a suite this build lacks.
        assert!(matches!(
            edited("hpke_mode_id", c::u(256)),
            Err(RecordError::BadField {
                field: "hpke_mode_id",
                ..
            })
        ));
        assert!(matches!(
            edited("hpke_kem_id", c::u(0x1_0000)),
            Err(RecordError::BadField {
                field: "hpke_kem_id",
                ..
            })
        ));
        let other_info = root_grant(RootGrantVariant::ExistingRootGrant, 4).hpke_info_bytes();
        assert_eq!(
            edited("hpke_info_bytes", c::b(&other_info)),
            Err(RecordError::BadValue("hpke_info_bytes"))
        );
        for (field, len) in [
            ("hpke_encapped_key_bytes", 31),
            ("hpke_encapped_key_bytes", 33),
            ("hpke_wrapped_trk_bytes", 47),
            ("hpke_wrapped_trk_bytes", 49),
        ] {
            assert_eq!(
                code_of(edited(field, c::b(&vec![1u8; len]))),
                "NON_CANONICAL_RECORD",
                "{field} {len}"
            );
        }
        assert_eq!(
            edited("grant_capability", c::t("fleet.key.receive")),
            Err(RecordError::BadValue("grant_capability"))
        );
        assert_eq!(
            edited("grant_variant", c::t("DeviceHpkeGrant")),
            Err(RecordError::BadValue("grant_variant"))
        );
        assert!(matches!(
            edited("extra", c::u(1)),
            Err(RecordError::UnknownField { .. })
        ));
        let missing = edit_map(&raw, |e| {
            e.retain(|(k, _)| k != "subject_device_approval_replay_id")
        });
        assert!(matches!(
            TenantRootKeyGrantV2::parse(&missing),
            Err(RecordError::MissingField {
                field: "subject_device_approval_replay_id",
                ..
            })
        ));
        let g = root_grant(RootGrantVariant::ExistingRootGrant, 3);
        let same_keys = TenantRootKeyGrantV2 {
            recipient_hpke_key_id: g.subject_signing_key_id,
            ..g
        };
        assert_eq!(
            TenantRootKeyGrantV2::parse(&same_keys.encode()),
            Err(RecordError::BadValue("recipient_hpke_key_id"))
        );
    }

    #[test]
    fn root_grant_variants_follow_their_generation_rules() {
        let parse = |g: TenantRootKeyGrantV2| TenantRootKeyGrantV2::parse(&g.encode());
        // Bootstrap is generation 0 only.
        assert_eq!(
            parse(root_grant(RootGrantVariant::FirstRootSelfGrant, 1)),
            Err(RecordError::BadValue("root_generation"))
        );
        // A rotation targets exactly previous + 1, under another key.
        for target in [4, 6, 0] {
            assert_eq!(
                parse(root_grant(rotation(4), target)),
                Err(RecordError::BadValue("root_generation")),
                "{target}"
            );
        }
        let same_key = TenantRootKeyGrantV2 {
            variant: RootGrantVariant::RotationGrant {
                previous_root_key_id: fx("root-key-1"),
                previous_root_generation: 4,
            },
            ..root_grant(rotation(4), 5)
        };
        assert_eq!(
            parse(same_key),
            Err(RecordError::BadValue("previous_root_key_id"))
        );

        // The previous-root pair is present iff the variant is a rotation.
        let rot = root_grant(rotation(4), 5).encode();
        let plain = root_grant(RootGrantVariant::ExistingRootGrant, 5).encode();
        let first = root_grant(RootGrantVariant::FirstRootSelfGrant, 0).encode();
        for (raw, edit) in [
            (&rot, ("drop", "previous_root_key_id")),
            (&rot, ("drop", "previous_root_generation")),
            (&rot, ("variant", "ExistingRootGrant")),
            (&rot, ("variant", "FirstRootSelfGrant")),
            (&plain, ("add", "previous_root_key_id")),
            (&plain, ("add", "previous_root_generation")),
            (&first, ("add", "previous_root_key_id")),
            (&first, ("add", "previous_root_generation")),
        ] {
            let bytes = edit_map(raw, |e| match edit {
                ("drop", key) => e.retain(|(k, _)| k != key),
                ("variant", v) => set(e, "grant_variant", c::t(v)),
                (_, "previous_root_key_id") => set(e, "previous_root_key_id", c::b(&[9u8; 32])),
                (_, key) => set(e, key, c::u(4)),
            });
            assert_eq!(
                TenantRootKeyGrantV2::parse(&bytes),
                Err(RecordError::BadValue("previous_root_key_id")),
                "{edit:?}"
            );
        }
        let rot_bad_type = edit_map(&rot, |e| set(e, "previous_root_generation", c::t("4")));
        assert!(matches!(
            TenantRootKeyGrantV2::parse(&rot_bad_type),
            Err(RecordError::BadField {
                field: "previous_root_generation",
                ..
            })
        ));
    }

    #[test]
    fn root_grant_opens_only_to_the_trk_its_key_id_names() {
        let (sk, pk) = grants::generate_keypair();
        let trk = fx::<32>("tenant-root-key");
        let sealed = |root_key_id: [u8; 32]| {
            let mut g = TenantRootKeyGrantV2 {
                root_key_id,
                recipient_hpke_key_id: crate::keys::hpke_key_id(&pk),
                ..root_grant(RootGrantVariant::FirstRootSelfGrant, 0)
            };
            let s = grants::seal_trk(&pk, &g.scope(), &trk).unwrap();
            assert_eq!(s.hpke_info_bytes, g.hpke_info_bytes());
            g.hpke_encapped_key_bytes = s.encapped_key_bytes.try_into().unwrap();
            g.hpke_wrapped_trk_bytes = s.ciphertext_bytes.try_into().unwrap();
            TenantRootKeyGrantV2::parse(&g.encode()).unwrap()
        };

        let good = sealed(root_key_id(&trk));
        assert_eq!(*good.open_trk(&sk).unwrap(), trk);

        // Sealed honestly, but naming another key ID: refused after opening.
        let lying = sealed(fx("root-key-1"));
        assert_eq!(
            lying.open_trk(&sk),
            Err(GrantError::FieldMismatch("root_key_id"))
        );
        // A grant whose signed fields moved no longer opens at all.
        let moved = TenantRootKeyGrantV2 {
            root_generation: 1,
            variant: RootGrantVariant::ExistingRootGrant,
            ..good.clone()
        };
        assert_eq!(moved.open_trk(&sk), Err(GrantError::HpkeFailure));
        let (other_sk, _) = grants::generate_keypair();
        assert_eq!(good.open_trk(&other_sk), Err(GrantError::HpkeFailure));
    }
}
