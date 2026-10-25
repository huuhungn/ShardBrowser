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

use ed25519_dalek::SigningKey;

use crate::canonical::{self as c, CborError, Value};
use crate::keys::signing_key_id;
use crate::signing::{self, ED25519_SIG_LEN, SIGNATURE_SUITE_ID_ED25519, SIGNATURE_VERSION};

pub const CONTAINER_DOMAIN: &str = "shardx.authorization.signed-container.v2";
pub const CONTAINER_VERSION: u16 = 2;
pub const PAYLOAD_VERSION: u16 = 2;

pub const DOMAIN_DEVICE_APPROVAL: &str = "shardx.auth.device-approval.v2";
pub const DOMAIN_TENANT_CAPABILITY_GRANT: &str = "shardx.auth.tenant-capability-grant.v2";
pub const DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE: &str = "shardx.keys.fleet-key-grant.device-hpke.v2";
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
    UnsupportedSuite {
        field: &'static str,
        id: u64,
    },
    /// The public key the caller looked up does not hash to `issuer_signing_key_id`.
    IssuerKeyMismatch,
    Signature,
}

impl RecordError {
    /// Wire code from the plan's error table (L1233, L1237, L1240).
    pub fn code(&self) -> &'static str {
        match self {
            Self::Cbor(CborError::IntegerOutOfSqliteDomain(_)) => "WIRE_INTEGER_OUT_OF_RANGE",
            Self::Cbor(_)
            | Self::NotAMap(_)
            | Self::UnknownField { .. }
            | Self::MissingField { .. }
            | Self::BadField { .. }
            | Self::BadValue(_) => "NON_CANONICAL_RECORD",
            Self::PayloadHashMismatch => "SIGNED_BYTES_MISMATCH",
            Self::ContainerHashMismatch => "SIGNED_CONTAINER_HASH_MISMATCH",
            Self::UnsupportedSuite { .. } => "SCHEMA_UNSUPPORTED",
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
            Self::UnsupportedSuite { field, id } => write!(f, "unsupported {field} {id}"),
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
struct Fields {
    map: &'static str,
    entries: Vec<(String, Value)>,
}

impl Fields {
    fn open(map: &'static str, v: Value) -> Result<Self> {
        match v {
            Value::Map(entries) => Ok(Self { map, entries }),
            _ => Err(RecordError::NotAMap(map)),
        }
    }

    fn decode(map: &'static str, bytes: &[u8]) -> Result<Self> {
        Self::open(map, c::assert_canonical_roundtrip(bytes)?)
    }

    fn take(&mut self, field: &str) -> Option<Value> {
        let i = self.entries.iter().position(|(k, _)| k == field)?;
        Some(self.entries.remove(i).1)
    }

    fn req(&mut self, field: &'static str) -> Result<Value> {
        self.take(field).ok_or(RecordError::MissingField {
            map: self.map,
            field,
        })
    }

    fn bad(&self, field: &'static str) -> RecordError {
        RecordError::BadField {
            map: self.map,
            field,
        }
    }

    fn text(&mut self, field: &'static str) -> Result<String> {
        match self.req(field)? {
            Value::Text(s) => Ok(s),
            _ => Err(self.bad(field)),
        }
    }

    /// A text field that must hold exactly `expected`.
    fn exact_text(&mut self, field: &'static str, expected: &str) -> Result<()> {
        if self.text(field)? == expected {
            Ok(())
        } else {
            Err(RecordError::BadValue(field))
        }
    }

    fn uint(&mut self, field: &'static str) -> Result<u64> {
        match self.req(field)? {
            Value::Uint(n) => Ok(n),
            _ => Err(self.bad(field)),
        }
    }

    fn u16(&mut self, field: &'static str) -> Result<u16> {
        let n = self.uint(field)?;
        u16::try_from(n).map_err(|_| self.bad(field))
    }

    fn bytes(&mut self, field: &'static str, min: usize, max: usize) -> Result<Vec<u8>> {
        match self.req(field)? {
            Value::Bytes(b) if (min..=max).contains(&b.len()) => Ok(b),
            _ => Err(self.bad(field)),
        }
    }

    fn fixed<const N: usize>(&mut self, field: &'static str) -> Result<[u8; N]> {
        let b = self.bytes(field, N, N)?;
        Ok(b.try_into().expect("length checked"))
    }

    fn opt_fixed<const N: usize>(&mut self, field: &'static str) -> Result<Option<[u8; N]>> {
        match self.take(field) {
            None => Ok(None),
            Some(Value::Bytes(b)) if b.len() == N => {
                Ok(Some(b.try_into().expect("length checked")))
            }
            Some(_) => Err(self.bad(field)),
        }
    }

    fn finish(self) -> Result<()> {
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

/// A `SignedAuthorizationRecordV2` whose bytes, hashes and suite were checked.
/// The signature is checked separately by [`AuthorizationRecord::verify_signature`],
/// because the caller first has to look up the issuer key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRecord {
    pub payload_domain: String,
    pub payload_version: u16,
    pub canonical_payload_bytes: Vec<u8>,
    pub payload_sha256: [u8; 32],
    pub signature_suite_id: u16,
    pub signature_version: u16,
    pub issuer_signing_key_id: [u8; 32],
    pub signature_bytes: Vec<u8>,
    pub signed_container_hash: [u8; 32],
    pub exact_signed_container_bytes: Vec<u8>,
    pub exact_signed_container_bytes_sha256: [u8; 32],
    tbs_bytes: Vec<u8>,
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
    /// ADR 0002 D-8) and checks that the payload's own `domain` and `version`
    /// equal the container's.
    pub fn parse(exact: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("SignedAuthorizationRecordV2", exact)?;
        f.exact_text("container_domain", CONTAINER_DOMAIN)?;
        if f.u16("container_version")? != CONTAINER_VERSION {
            return Err(RecordError::BadValue("container_version"));
        }
        let payload_domain = f.text("payload_domain")?;
        let payload_version = f.u16("payload_version")?;
        let canonical_payload_bytes = f.bytes("canonical_payload_bytes", 1, MAX_PAYLOAD_BYTES)?;
        let payload_sha256 = f.fixed::<32>("payload_sha256")?;
        let signature_suite_id = f.u16("signature_suite_id")?;
        let signature_version = f.u16("signature_version")?;
        let issuer_signing_key_id = f.fixed::<32>("issuer_signing_key_id")?;
        let signature_bytes = f.bytes("signature_bytes", 1, MAX_SIGNATURE_BYTES)?;
        let signed_container_hash = f.fixed::<32>("signed_container_hash")?;
        f.finish()?;

        if payload_version != PAYLOAD_VERSION {
            return Err(RecordError::BadValue("payload_version"));
        }
        if signature_suite_id != SIGNATURE_SUITE_ID_ED25519 {
            return Err(RecordError::UnsupportedSuite {
                field: "signature_suite_id",
                id: signature_suite_id.into(),
            });
        }
        if signature_version != SIGNATURE_VERSION {
            return Err(RecordError::UnsupportedSuite {
                field: "signature_version",
                id: signature_version.into(),
            });
        }
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

        Ok(Self {
            payload_domain,
            payload_version,
            canonical_payload_bytes,
            payload_sha256,
            signature_suite_id,
            signature_version,
            issuer_signing_key_id,
            signature_bytes,
            signed_container_hash,
            exact_signed_container_bytes: exact.to_vec(),
            exact_signed_container_bytes_sha256: c::sha256(exact),
            tbs_bytes,
        })
    }

    /// Checks the signature under the issuer key the caller looked up by
    /// `issuer_signing_key_id`. A key with a different ID is refused before any
    /// curve arithmetic, so a lookup bug cannot verify under the wrong key.
    pub fn verify_signature(&self, issuer_public_key: &[u8; 32]) -> Result<()> {
        if signing_key_id(issuer_public_key) != self.issuer_signing_key_id {
            return Err(RecordError::IssuerKeyMismatch);
        }
        signing::verify_tbs(issuer_public_key, &self.tbs_bytes, &self.signature_bytes)
            .map_err(|_| RecordError::Signature)
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
    pub fn parse(payload: &[u8]) -> Result<Self> {
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
    fn as_str(self) -> &'static str {
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
    /// Parses the L484 shape. `root.custody` parses when device-scoped, as Q-2
    /// keeps that shape, but [`Self::is_issuable`] refuses it: custody comes only
    /// from root grants.
    pub fn parse(payload: &[u8]) -> Result<Self> {
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
    /// and [`Self::parse`] refuses a grant whose bytes differ, so the info a
    /// recipient opens with is always the one bound to the signed fields.
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

    pub fn parse(payload: &[u8]) -> Result<Self> {
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
            return Err(RecordError::UnsupportedSuite {
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

    /// Re-encodes `payload` with `edit` applied to its field list.
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

    // ---------------------------------------------------------- container ---

    #[test]
    fn record_roundtrips_and_verifies() {
        let sk = issuer();
        let payload = approval().encode();
        let exact = build_record(&sk, DOMAIN_DEVICE_APPROVAL, &payload);
        let rec = AuthorizationRecord::parse(&exact).unwrap();
        assert_eq!(rec.payload_domain, DOMAIN_DEVICE_APPROVAL);
        assert_eq!(rec.canonical_payload_bytes, payload);
        assert_eq!(rec.exact_signed_container_bytes, exact);
        assert_eq!(rec.verify_signature(sk.verifying_key().as_bytes()), Ok(()));
        assert_eq!(
            DeviceApprovalV2::parse(&rec.canonical_payload_bytes).unwrap(),
            approval()
        );
    }

    /// Regression vector pinned at this commit, so any change to the field set,
    /// the payload encoding or the container assembly shows up as a diff.
    #[test]
    fn device_approval_golden_vector() {
        let payload = approval().encode();
        let exact = build_record(&issuer(), DOMAIN_DEVICE_APPROVAL, &payload);
        let rec = AuthorizationRecord::parse(&exact).unwrap();
        assert_eq!(
            hex(&rec.payload_sha256),
            "89e4d4c23e4a1aa0d085b812bedb12cf68c52433b4e2f50c4f972733e6031048"
        );
        assert_eq!(
            hex(&rec.signed_container_hash),
            "06985017828088ac0bce13425bf0e439af3937643091931a5e7648b913b60189"
        );
        assert_eq!(
            hex(&rec.exact_signed_container_bytes_sha256),
            "a8d4bc42778377524176aa3f806306b133f94d26df10c3f07406856ee66987da"
        );
    }

    #[test]
    fn container_rejects_every_field_level_defect() {
        let sk = issuer();
        let payload = approval().encode();
        let good = build_record(&sk, DOMAIN_DEVICE_APPROVAL, &payload);

        let with = |key: &str, v: Value| edit_map(&good, |e| set(e, key, v));
        let without = |key: &str| edit_map(&good, |e| e.retain(|(k, _)| k != key));

        // Closed map.
        assert_eq!(
            code_of(AuthorizationRecord::parse(&with("extra", c::u(1)))),
            "NON_CANONICAL_RECORD"
        );
        assert!(matches!(
            AuthorizationRecord::parse(&without("payload_sha256")),
            Err(RecordError::MissingField {
                field: "payload_sha256",
                ..
            })
        ));
        // Exact values.
        assert_eq!(
            AuthorizationRecord::parse(&with("container_domain", c::t("shardx.other"))),
            Err(RecordError::BadValue("container_domain"))
        );
        assert_eq!(
            AuthorizationRecord::parse(&with("container_version", c::u(1))),
            Err(RecordError::BadValue("container_version"))
        );
        assert_eq!(
            code_of(AuthorizationRecord::parse(&with(
                "signature_suite_id",
                c::u(2)
            ))),
            "SCHEMA_UNSUPPORTED"
        );
        assert_eq!(
            code_of(AuthorizationRecord::parse(&with(
                "signature_bytes",
                c::b(&[1u8; 63])
            ))),
            "NON_CANONICAL_RECORD"
        );
        // Hashes are recomputed, never trusted.
        assert_eq!(
            code_of(AuthorizationRecord::parse(&with(
                "payload_sha256",
                c::b(&[0u8; 32])
            ))),
            "SIGNED_BYTES_MISMATCH"
        );
        assert_eq!(
            code_of(AuthorizationRecord::parse(&with(
                "signed_container_hash",
                c::b(&[0u8; 32])
            ))),
            "SIGNED_CONTAINER_HASH_MISMATCH"
        );
        // Trailing byte and a non-shortest integer are not canonical.
        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(
            code_of(AuthorizationRecord::parse(&trailing)),
            "NON_CANONICAL_RECORD"
        );
        assert_eq!(
            code_of(AuthorizationRecord::parse(&[0x18, 0x01])),
            "NON_CANONICAL_RECORD"
        );
    }

    #[test]
    fn signature_binds_issuer_and_bytes() {
        let sk = issuer();
        let exact = build_record(&sk, DOMAIN_DEVICE_APPROVAL, &approval().encode());
        let rec = AuthorizationRecord::parse(&exact).unwrap();

        let other = SigningKey::from_bytes(&fx::<32>("someone-else"));
        assert_eq!(
            rec.verify_signature(other.verifying_key().as_bytes()),
            Err(RecordError::IssuerKeyMismatch)
        );

        // A signature flipped in place keeps a valid container hash only if the
        // hash is recomputed too, which is what a forger would do.
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
    fn payload_domain_and_version_must_match_the_container() {
        let sk = issuer();
        let payload = approval().encode();
        let as_grant = build_record(&sk, DOMAIN_TENANT_CAPABILITY_GRANT, &payload);
        assert_eq!(
            AuthorizationRecord::parse(&as_grant),
            Err(RecordError::BadValue("payload_domain"))
        );
    }

    #[test]
    fn integer_above_the_sqlite_domain_is_its_own_code() {
        // restore_epoch = 2^63 encoded by hand: major 0, 8-byte argument.
        let payload = edit_map(&approval().encode(), |e| set(e, "restore_epoch", c::u(1)));
        let at = payload
            .windows(14)
            .position(|w| w == b"\x6drestore_epoch")
            .unwrap()
            + 14;
        let mut raw = payload[..at].to_vec();
        raw.extend_from_slice(&[0x1b, 0x80, 0, 0, 0, 0, 0, 0, 0]);
        raw.extend_from_slice(&payload[at + 1..]);
        assert_eq!(
            code_of(DeviceApprovalV2::parse(&raw)),
            "WIRE_INTEGER_OUT_OF_RANGE"
        );
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

    #[test]
    fn every_grantable_value_parses_in_its_scopes_and_only_there() {
        use CapabilityScopeKind::{Fleet, Profile, Tenant};
        let mut grantable = 0;
        for cap in Capability::ALL {
            for scope in [Tenant, Fleet, Profile] {
                let parsed = TenantCapabilityGrantV2::parse(&device_grant(cap, scope).encode());
                let allowed = cap.grant_scopes().contains(&scope) || cap == Capability::RootCustody;
                assert_eq!(
                    parsed.is_ok(),
                    allowed,
                    "{} at {scope:?}: {parsed:?}",
                    cap.as_str()
                );
                if let Ok(g) = parsed {
                    assert_eq!(g.is_issuable(), cap != Capability::RootCustody);
                    grantable += usize::from(g.is_issuable());
                }
            }
        }
        // D-2: 11 grantable values over their scope lists.
        assert_eq!(grantable, 3 + 5 * 2 + 3 * 3);
    }

    #[test]
    fn capability_strings_outside_the_closed_set_reject() {
        let raw = device_grant(Capability::DeviceApprove, CapabilityScopeKind::Tenant).encode();
        for s in [
            "root-custody",
            "Device.approve",
            "device.approve.",
            "fleet.key.grant",
            "device",
            "",
        ] {
            let edited = edit_map(&raw, |e| set(e, "capability", c::t(s)));
            assert_eq!(
                TenantCapabilityGrantV2::parse(&edited),
                Err(RecordError::BadValue("capability")),
                "{s:?}"
            );
        }
        for cap in [Capability::FleetKeyReceive, Capability::FleetKeyRecover] {
            let g = device_grant(cap, CapabilityScopeKind::Fleet).encode();
            assert_eq!(
                TenantCapabilityGrantV2::parse(&g),
                Err(RecordError::BadValue("capability"))
            );
        }
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

        let raw = account.encode();
        let with_device = edit_map(&raw, |e| {
            set(e, "subject_device_id", c::b(&fx::<16>("device-a")))
        });
        assert_eq!(
            TenantCapabilityGrantV2::parse(&with_device),
            Err(RecordError::BadValue("subject_kind"))
        );

        let raw = device.encode();
        let no_hpke = edit_map(&raw, |e| e.retain(|(k, _)| k != "subject_hpke_key_id"));
        assert_eq!(
            TenantCapabilityGrantV2::parse(&no_hpke),
            Err(RecordError::BadValue("subject_kind"))
        );

        // root.custody is device-only (L484).
        let root_account = TenantCapabilityGrantV2 {
            capability: Capability::RootCustody,
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
    fn hpke_grant_roundtrips_inside_a_record() {
        let sk = issuer();
        let g = hpke_grant();
        let exact = build_record(&sk, DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE, &g.encode());
        let rec = AuthorizationRecord::parse(&exact).unwrap();
        rec.verify_signature(sk.verifying_key().as_bytes()).unwrap();
        assert_eq!(
            DeviceHpkeGrantV2::parse(&rec.canonical_payload_bytes).unwrap(),
            g
        );
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

        let same_keys = DeviceHpkeGrantV2 {
            recipient_hpke_key_id: fx("device-a-signing"),
            ..hpke_grant()
        };
        assert_eq!(
            DeviceHpkeGrantV2::parse(&same_keys.encode()),
            Err(RecordError::BadValue("recipient_hpke_key_id"))
        );
    }
}
