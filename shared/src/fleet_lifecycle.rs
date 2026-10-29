//! ADR 0002 D-9 fleet key-generation lifecycle maps: generation create, grant
//! filing, per-grant acknowledgement, activation and grant revocation, each a
//! request payload and its stored response payload.
//!
//! Built like the root lifecycle maps in `mutation`, and wrapped the same way
//! in an `IdempotentMutationRequestV2`. Each `parse` checks the rules one map
//! can decide alone (generation arithmetic, fields present iff their mode or
//! variant, recomputed hashes). Whether the actor may run the operation, and
//! whether the payload matches live state, is the caller's to check.

use crate::authz_record::{Fields, RecordError};
use crate::canonical::{self as c, Value};
use crate::mutation::{
    exact_version, u32_in, ACK_OUTCOME_ACKNOWLEDGED, GENERATION_STATE_ACTIVE,
    GENERATION_STATE_PREPARING, GENERATION_STATE_RETIRED, MAX_EMBEDDED_GRANT_BYTES, VERSION,
};

type Result<T> = std::result::Result<T, RecordError>;

pub const DOMAIN_FLEET_GENERATION_CREATE: &str = "shardx.keys.fleet-key-generation-create.v2";
pub const DOMAIN_FLEET_GENERATION_CREATED: &str = "shardx.keys.fleet-key-generation-created.v2";
pub const RECORD_TYPE_FLEET_GENERATION_CREATED: &str = "FleetKeyGenerationCreatedV2";
pub const DOMAIN_FLEET_GRANT_CREATE: &str = "shardx.keys.fleet-key-grant-create.v2";
pub const DOMAIN_FLEET_GRANT_CREATED: &str = "shardx.keys.fleet-key-grant-created.v2";
pub const RECORD_TYPE_FLEET_GRANT_CREATED: &str = "FleetKeyGrantCreatedV2";
pub const DOMAIN_FLEET_GRANT_ACK: &str = "shardx.keys.fleet-key-grant-ack.v2";
pub const DOMAIN_FLEET_GRANT_ACKED: &str = "shardx.keys.fleet-key-grant-acked.v2";
pub const RECORD_TYPE_FLEET_GRANT_ACKED: &str = "FleetKeyGrantAckedV2";
pub const DOMAIN_FLEET_GENERATION_ACTIVATE: &str = "shardx.keys.fleet-key-generation-activate.v2";
pub const DOMAIN_FLEET_GENERATION_ACTIVATED: &str = "shardx.keys.fleet-key-generation-activated.v2";
pub const RECORD_TYPE_FLEET_GENERATION_ACTIVATED: &str = "FleetKeyGenerationActivatedV2";
pub const DOMAIN_FLEET_GRANT_REVOKE: &str = "shardx.keys.fleet-key-grant-revoke.v2";
pub const DOMAIN_FLEET_GRANT_REVOKED: &str = "shardx.keys.fleet-key-grant-revoked.v2";
pub const RECORD_TYPE_FLEET_GRANT_REVOKED: &str = "FleetGrantRevokedV2";
const GRANT_STATE_PENDING_ACK: &str = "PENDING_ACK";

/// The fields common to every D-9 map: the context and the one generation the
/// operation acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FleetGenerationRef {
    pub tenant_id: [u8; 16],
    pub server_instance_id: [u8; 16],
    pub restore_epoch: u64,
    pub fleet_id: [u8; 16],
    pub generation: u64,
    pub fkek_key_id: [u8; 32],
}

impl FleetGenerationRef {
    fn take(f: &mut Fields) -> Result<Self> {
        Ok(Self {
            tenant_id: f.fixed("tenant_id")?,
            server_instance_id: f.fixed("server_instance_id")?,
            restore_epoch: f.uint("restore_epoch")?,
            fleet_id: f.fixed("fleet_id")?,
            generation: f.uint("generation")?,
            fkek_key_id: f.fixed("fkek_key_id")?,
        })
    }

    fn put(&self, out: &mut Vec<(&'static str, Value)>) {
        out.extend([
            ("tenant_id", c::b(&self.tenant_id)),
            ("server_instance_id", c::b(&self.server_instance_id)),
            ("restore_epoch", c::u(self.restore_epoch)),
            ("fleet_id", c::b(&self.fleet_id)),
            ("generation", c::u(self.generation)),
            ("fkek_key_id", c::b(&self.fkek_key_id)),
        ]);
    }
}

fn opening(domain: &'static str) -> Vec<(&'static str, Value)> {
    vec![("domain", c::t(domain)), ("version", c::u(VERSION))]
}

/// The three `FleetKeyGrantV2` variants D-9 files, acknowledges and revokes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FleetGrantVariant {
    DeviceHpke,
    Recovery,
    Rotation,
}

impl FleetGrantVariant {
    pub const ALL: [Self; 3] = [Self::DeviceHpke, Self::Recovery, Self::Rotation];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeviceHpke => "DeviceHpkeGrant",
            Self::Recovery => "RecoveryGrant",
            Self::Rotation => "RotationGrant",
        }
    }

    fn take(f: &mut Fields) -> Result<Self> {
        let s = f.text("grant_variant")?;
        Self::ALL
            .into_iter()
            .find(|v| v.as_str() == s)
            .ok_or(RecordError::BadValue("grant_variant"))
    }
}

// ------------------------------------------------- generation create/activate ---

/// The generation a rotation follows and the `RotationGrant` that moves to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FleetRotation {
    pub previous_generation: u64,
    pub previous_fkek_key_id: [u8; 32],
    pub rotation_grant_signed_container_hash: [u8; 32],
}

/// The terms a generation is created and activated under. Generation 0 is the
/// bootstrap and has no rotation; every later generation is a rotation from
/// the one before it under another key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FleetGenerationTerms {
    pub generation: FleetGenerationRef,
    pub required_device_grant_count: u32,
    /// ADR 0002 D-4 `fleet_device_grant_set_hash` of the required grants.
    pub required_device_grant_set_hash: [u8; 32],
    pub recovery_grant_signed_container_hash: [u8; 32],
    pub rotation: Option<FleetRotation>,
}

impl FleetGenerationTerms {
    fn take(f: &mut Fields) -> Result<Self> {
        let generation = FleetGenerationRef::take(f)?;
        let required_device_grant_count = u32_in(f, "required_device_grant_count", 1, 65535)?;
        let required_device_grant_set_hash = f.fixed("required_device_grant_set_hash")?;
        let recovery_grant_signed_container_hash =
            f.fixed("recovery_grant_signed_container_hash")?;
        let previous_generation = f.opt_uint("previous_generation")?;
        let previous_fkek_key_id = f.opt_fixed::<32>("previous_fkek_key_id")?;
        let rotation_hash = f.opt_fixed::<32>("rotation_grant_signed_container_hash")?;
        let rotation = match (
            generation.generation,
            previous_generation,
            previous_fkek_key_id,
            rotation_hash,
        ) {
            (0, None, None, None) => None,
            (n, Some(previous_generation), Some(previous_fkek_key_id), Some(hash)) if n > 0 => {
                if previous_generation.checked_add(1) != Some(n) {
                    return Err(RecordError::BadValue("generation"));
                }
                if previous_fkek_key_id == generation.fkek_key_id {
                    return Err(RecordError::BadValue("previous_fkek_key_id"));
                }
                Some(FleetRotation {
                    previous_generation,
                    previous_fkek_key_id,
                    rotation_grant_signed_container_hash: hash,
                })
            }
            _ => return Err(RecordError::BadValue("previous_generation")),
        };
        Ok(Self {
            generation,
            required_device_grant_count,
            required_device_grant_set_hash,
            recovery_grant_signed_container_hash,
            rotation,
        })
    }

    fn put(&self, out: &mut Vec<(&'static str, Value)>) {
        self.generation.put(out);
        out.extend([
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
        ]);
        if let Some(r) = &self.rotation {
            out.extend([
                ("previous_generation", c::u(r.previous_generation)),
                ("previous_fkek_key_id", c::b(&r.previous_fkek_key_id)),
                (
                    "rotation_grant_signed_container_hash",
                    c::b(&r.rotation_grant_signed_container_hash),
                ),
            ]);
        }
    }

    /// Takes `mode`, which must say what the generation number already does.
    fn take_mode(&self, f: &mut Fields) -> Result<()> {
        f.exact_text("mode", self.mode())
    }

    fn mode(&self) -> &'static str {
        if self.rotation.is_some() {
            "rotation"
        } else {
            "bootstrap"
        }
    }
}

/// `FleetKeyGenerationCreateV2`, the `FLEET_GENERATION_CREATE` payload.
/// `root_generation` is the ACTIVE root the recovery grant is wrapped under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetKeyGenerationCreateV2 {
    pub terms: FleetGenerationTerms,
    pub root_generation: u64,
}

impl FleetKeyGenerationCreateV2 {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("FleetKeyGenerationCreateV2", payload)?;
        exact_version(&mut f, DOMAIN_FLEET_GENERATION_CREATE)?;
        let terms = FleetGenerationTerms::take(&mut f)?;
        terms.take_mode(&mut f)?;
        let root_generation = f.uint("root_generation")?;
        f.finish()?;
        Ok(Self {
            terms,
            root_generation,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = opening(DOMAIN_FLEET_GENERATION_CREATE);
        self.terms.put(&mut out);
        out.extend([
            ("mode", c::t(self.terms.mode())),
            ("root_generation", c::u(self.root_generation)),
        ]);
        c::encode(&c::m(out))
    }
}

/// `FleetKeyGenerationCreatedV2`, the stored `FLEET_GENERATION_CREATE` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetKeyGenerationCreatedV2 {
    pub create: FleetKeyGenerationCreateV2,
    pub created_at_ms: u64,
}

impl FleetKeyGenerationCreatedV2 {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("FleetKeyGenerationCreatedV2", payload)?;
        exact_version(&mut f, DOMAIN_FLEET_GENERATION_CREATED)?;
        let terms = FleetGenerationTerms::take(&mut f)?;
        terms.take_mode(&mut f)?;
        let root_generation = f.uint("root_generation")?;
        f.exact_text("generation_state", GENERATION_STATE_PREPARING)?;
        let created_at_ms = f.uint("created_at_ms")?;
        f.finish()?;
        Ok(Self {
            create: FleetKeyGenerationCreateV2 {
                terms,
                root_generation,
            },
            created_at_ms,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = opening(DOMAIN_FLEET_GENERATION_CREATED);
        self.create.terms.put(&mut out);
        out.extend([
            ("mode", c::t(self.create.terms.mode())),
            ("root_generation", c::u(self.create.root_generation)),
            ("generation_state", c::t(GENERATION_STATE_PREPARING)),
            ("created_at_ms", c::u(self.created_at_ms)),
        ]);
        c::encode(&c::m(out))
    }
}

/// `FleetKeyGenerationActivateV2`, the `FLEET_GENERATION_ACTIVATE` payload. It
/// restates the terms the generation was created with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetKeyGenerationActivateV2 {
    pub terms: FleetGenerationTerms,
}

impl FleetKeyGenerationActivateV2 {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("FleetKeyGenerationActivateV2", payload)?;
        exact_version(&mut f, DOMAIN_FLEET_GENERATION_ACTIVATE)?;
        let terms = FleetGenerationTerms::take(&mut f)?;
        f.finish()?;
        Ok(Self { terms })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = opening(DOMAIN_FLEET_GENERATION_ACTIVATE);
        self.terms.put(&mut out);
        c::encode(&c::m(out))
    }
}

/// `FleetKeyGenerationActivatedV2`, the stored activation response;
/// `previous_state` is `RETIRED` iff the activation was a rotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetKeyGenerationActivatedV2 {
    pub terms: FleetGenerationTerms,
    pub activated_at_ms: u64,
}

impl FleetKeyGenerationActivatedV2 {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("FleetKeyGenerationActivatedV2", payload)?;
        exact_version(&mut f, DOMAIN_FLEET_GENERATION_ACTIVATED)?;
        let terms = FleetGenerationTerms::take(&mut f)?;
        f.exact_text("target_state", GENERATION_STATE_ACTIVE)?;
        let previous_state = f.take("previous_state");
        let activated_at_ms = f.uint("activated_at_ms")?;
        f.finish()?;
        let retired = Some(Value::Text(GENERATION_STATE_RETIRED.into()));
        if previous_state != terms.rotation.and(retired) {
            return Err(RecordError::BadValue("previous_state"));
        }
        Ok(Self {
            terms,
            activated_at_ms,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = opening(DOMAIN_FLEET_GENERATION_ACTIVATED);
        self.terms.put(&mut out);
        out.push(("target_state", c::t(GENERATION_STATE_ACTIVE)));
        if self.terms.rotation.is_some() {
            out.push(("previous_state", c::t(GENERATION_STATE_RETIRED)));
        }
        out.push(("activated_at_ms", c::u(self.activated_at_ms)));
        c::encode(&c::m(out))
    }
}

// ------------------------------------------------------- grant create and ack ---

/// The fields that name one filed fleet grant exactly: its generation, variant,
/// replay ID and both container hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FleetGrantRef {
    pub generation: FleetGenerationRef,
    pub grant_variant: FleetGrantVariant,
    pub replay_id: [u8; 16],
    pub signed_container_hash: [u8; 32],
    pub exact_signed_grant_container_bytes_sha256: [u8; 32],
}

impl FleetGrantRef {
    fn take(f: &mut Fields) -> Result<Self> {
        Ok(Self {
            generation: FleetGenerationRef::take(f)?,
            grant_variant: FleetGrantVariant::take(f)?,
            replay_id: f.fixed("replay_id")?,
            signed_container_hash: f.fixed("signed_container_hash")?,
            exact_signed_grant_container_bytes_sha256: f
                .fixed("exact_signed_grant_container_bytes_sha256")?,
        })
    }

    fn put(&self, out: &mut Vec<(&'static str, Value)>) {
        self.generation.put(out);
        out.extend([
            ("grant_variant", c::t(self.grant_variant.as_str())),
            ("replay_id", c::b(&self.replay_id)),
            ("signed_container_hash", c::b(&self.signed_container_hash)),
            (
                "exact_signed_grant_container_bytes_sha256",
                c::b(&self.exact_signed_grant_container_bytes_sha256),
            ),
        ]);
    }
}

/// `FleetKeyGrantCreateV2`, the `FLEET_GRANT_CREATE` payload. `parse` checks
/// the bytes hash; the caller parses the embedded container and requires it
/// to be exactly `grant.grant_variant` with equal common and replay fields and
/// `signed_container_hash`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetKeyGrantCreateV2 {
    pub grant: FleetGrantRef,
    pub exact_signed_grant_container_bytes: Vec<u8>,
}

impl FleetKeyGrantCreateV2 {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("FleetKeyGrantCreateV2", payload)?;
        exact_version(&mut f, DOMAIN_FLEET_GRANT_CREATE)?;
        let grant = FleetGrantRef::take(&mut f)?;
        let bytes = f.bytes(
            "exact_signed_grant_container_bytes",
            1,
            MAX_EMBEDDED_GRANT_BYTES,
        )?;
        f.finish()?;
        if grant.exact_signed_grant_container_bytes_sha256 != c::sha256(&bytes) {
            return Err(RecordError::BadValue(
                "exact_signed_grant_container_bytes_sha256",
            ));
        }
        Ok(Self {
            grant,
            exact_signed_grant_container_bytes: bytes,
        })
    }

    /// Builds the payload, taking the bytes hash from the bytes.
    pub fn new(
        generation: FleetGenerationRef,
        grant_variant: FleetGrantVariant,
        replay_id: [u8; 16],
        signed_container_hash: [u8; 32],
        exact_signed_grant_container_bytes: Vec<u8>,
    ) -> Self {
        Self {
            grant: FleetGrantRef {
                generation,
                grant_variant,
                replay_id,
                signed_container_hash,
                exact_signed_grant_container_bytes_sha256: c::sha256(
                    &exact_signed_grant_container_bytes,
                ),
            },
            exact_signed_grant_container_bytes,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = opening(DOMAIN_FLEET_GRANT_CREATE);
        self.grant.put(&mut out);
        out.push((
            "exact_signed_grant_container_bytes",
            c::b(&self.exact_signed_grant_container_bytes),
        ));
        c::encode(&c::m(out))
    }
}

/// What a created grant names beyond its ref: the subject device of a
/// `DeviceHpkeGrant`, the root generation a `RecoveryGrant` is wrapped under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FleetGrantTarget {
    Device { subject_device_id: [u8; 16] },
    Root { recipient_root_generation: u64 },
    Rotation,
}

/// `FleetKeyGrantCreatedV2`, the stored `FLEET_GRANT_CREATE` response. Every
/// variant starts `PENDING_ACK`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetKeyGrantCreatedV2 {
    pub grant: FleetGrantRef,
    pub target: FleetGrantTarget,
    pub created_at_ms: u64,
}

impl FleetKeyGrantCreatedV2 {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("FleetKeyGrantCreatedV2", payload)?;
        exact_version(&mut f, DOMAIN_FLEET_GRANT_CREATED)?;
        let grant = FleetGrantRef::take(&mut f)?;
        let subject = f.opt_fixed::<16>("subject_device_id")?;
        let root = f.opt_uint("recipient_root_generation")?;
        f.exact_text("grant_state", GRANT_STATE_PENDING_ACK)?;
        let created_at_ms = f.uint("created_at_ms")?;
        f.finish()?;
        let target = match (grant.grant_variant, subject, root) {
            (FleetGrantVariant::DeviceHpke, Some(subject_device_id), None) => {
                FleetGrantTarget::Device { subject_device_id }
            }
            (FleetGrantVariant::Recovery, None, Some(recipient_root_generation)) => {
                FleetGrantTarget::Root {
                    recipient_root_generation,
                }
            }
            (FleetGrantVariant::Rotation, None, None) => FleetGrantTarget::Rotation,
            (FleetGrantVariant::DeviceHpke, _, _) | (_, Some(_), _) => {
                return Err(RecordError::BadValue("subject_device_id"))
            }
            _ => return Err(RecordError::BadValue("recipient_root_generation")),
        };
        Ok(Self {
            grant,
            target,
            created_at_ms,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = opening(DOMAIN_FLEET_GRANT_CREATED);
        self.grant.put(&mut out);
        match self.target {
            FleetGrantTarget::Device { subject_device_id } => {
                out.push(("subject_device_id", c::b(&subject_device_id)))
            }
            FleetGrantTarget::Root {
                recipient_root_generation,
            } => out.push(("recipient_root_generation", c::u(recipient_root_generation))),
            FleetGrantTarget::Rotation => {}
        }
        out.extend([
            ("grant_state", c::t(GRANT_STATE_PENDING_ACK)),
            ("created_at_ms", c::u(self.created_at_ms)),
        ]);
        c::encode(&c::m(out))
    }
}

/// `FleetKeyGrantAckV2`, the `FLEET_GRANT_ACK` payload, one grant per request.
/// The actor sends it after it opened the grant and the FKEK it holds
/// re-derived `fkek_key_id`, so `locally_unwrapped_fkek_key_id` always equals
/// it; a different value does not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetKeyGrantAckV2 {
    pub grant: FleetGrantRef,
}

impl FleetKeyGrantAckV2 {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("FleetKeyGrantAckV2", payload)?;
        exact_version(&mut f, DOMAIN_FLEET_GRANT_ACK)?;
        let grant = FleetGrantRef::take(&mut f)?;
        let unwrapped: [u8; 32] = f.fixed("locally_unwrapped_fkek_key_id")?;
        f.finish()?;
        if unwrapped != grant.generation.fkek_key_id {
            return Err(RecordError::BadValue("locally_unwrapped_fkek_key_id"));
        }
        Ok(Self { grant })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = opening(DOMAIN_FLEET_GRANT_ACK);
        self.grant.put(&mut out);
        out.push((
            "locally_unwrapped_fkek_key_id",
            c::b(&self.grant.generation.fkek_key_id),
        ));
        c::encode(&c::m(out))
    }
}

/// `FleetKeyGrantAckedV2`, the stored `FLEET_GRANT_ACK` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetKeyGrantAckedV2 {
    pub grant: FleetGrantRef,
    pub acked_at_ms: u64,
}

impl FleetKeyGrantAckedV2 {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("FleetKeyGrantAckedV2", payload)?;
        exact_version(&mut f, DOMAIN_FLEET_GRANT_ACKED)?;
        let grant = FleetGrantRef::take(&mut f)?;
        f.exact_text("ack_outcome", ACK_OUTCOME_ACKNOWLEDGED)?;
        let acked_at_ms = f.uint("acked_at_ms")?;
        f.finish()?;
        Ok(Self { grant, acked_at_ms })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = opening(DOMAIN_FLEET_GRANT_ACKED);
        self.grant.put(&mut out);
        out.extend([
            ("ack_outcome", c::t(ACK_OUTCOME_ACKNOWLEDGED)),
            ("acked_at_ms", c::u(self.acked_at_ms)),
        ]);
        c::encode(&c::m(out))
    }
}

// ------------------------------------------------------------------- revoke ---

/// Why a fleet grant is revoked. Every reason but `Superseded` leaves the fleet
/// `rotation_required` (ADR 0002 D-9, C-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FleetGrantRevokeReason {
    MemberRemoved,
    DeviceRevoked,
    Superseded,
    Compromised,
}

impl FleetGrantRevokeReason {
    pub const ALL: [Self; 4] = [
        Self::MemberRemoved,
        Self::DeviceRevoked,
        Self::Superseded,
        Self::Compromised,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::MemberRemoved => "member_removed",
            Self::DeviceRevoked => "device_revoked",
            Self::Superseded => "superseded",
            Self::Compromised => "compromised",
        }
    }
}

/// The grant a revocation names and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FleetGrantRevocation {
    pub generation: FleetGenerationRef,
    pub grant_variant: FleetGrantVariant,
    pub replay_id: [u8; 16],
    pub signed_container_hash: [u8; 32],
    pub reason_code: FleetGrantRevokeReason,
}

impl FleetGrantRevocation {
    fn take(f: &mut Fields) -> Result<Self> {
        let generation = FleetGenerationRef::take(f)?;
        let grant_variant = FleetGrantVariant::take(f)?;
        let replay_id = f.fixed("replay_id")?;
        let signed_container_hash = f.fixed("signed_container_hash")?;
        let reason = f.text("reason_code")?;
        let reason_code = FleetGrantRevokeReason::ALL
            .into_iter()
            .find(|r| r.as_str() == reason)
            .ok_or(RecordError::BadValue("reason_code"))?;
        Ok(Self {
            generation,
            grant_variant,
            replay_id,
            signed_container_hash,
            reason_code,
        })
    }

    fn put(&self, out: &mut Vec<(&'static str, Value)>) {
        self.generation.put(out);
        out.extend([
            ("grant_variant", c::t(self.grant_variant.as_str())),
            ("replay_id", c::b(&self.replay_id)),
            ("signed_container_hash", c::b(&self.signed_container_hash)),
            ("reason_code", c::t(self.reason_code.as_str())),
        ]);
    }
}

/// `FleetGrantRevokeV2`, the `FLEET_GRANT_REVOKE` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetGrantRevokeV2 {
    pub revocation: FleetGrantRevocation,
}

impl FleetGrantRevokeV2 {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("FleetGrantRevokeV2", payload)?;
        exact_version(&mut f, DOMAIN_FLEET_GRANT_REVOKE)?;
        let revocation = FleetGrantRevocation::take(&mut f)?;
        f.finish()?;
        Ok(Self { revocation })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = opening(DOMAIN_FLEET_GRANT_REVOKE);
        self.revocation.put(&mut out);
        c::encode(&c::m(out))
    }
}

/// `FleetGrantRevokedV2`, the stored `FLEET_GRANT_REVOKE` response.
/// `invalidation_count` counts what the revocation invalidated, as the root
/// grant revoke response does (plan L947).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetGrantRevokedV2 {
    pub revocation: FleetGrantRevocation,
    pub revoked_at_ms: u64,
    pub invalidation_count: u32,
}

impl FleetGrantRevokedV2 {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("FleetGrantRevokedV2", payload)?;
        exact_version(&mut f, DOMAIN_FLEET_GRANT_REVOKED)?;
        let revocation = FleetGrantRevocation::take(&mut f)?;
        let revoked_at_ms = f.uint("revoked_at_ms")?;
        let invalidation_count = u32_in(&mut f, "invalidation_count", 0, u32::MAX.into())?;
        f.finish()?;
        Ok(Self {
            revocation,
            revoked_at_ms,
            invalidation_count,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = opening(DOMAIN_FLEET_GRANT_REVOKED);
        self.revocation.put(&mut out);
        out.extend([
            ("revoked_at_ms", c::u(self.revoked_at_ms)),
            ("invalidation_count", c::u(self.invalidation_count.into())),
        ]);
        c::encode(&c::m(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mutation::{
        fleet_device_grant_set_hash, IdempotentMutationRequestV2, OperationKind,
    };

    fn fx<const N: usize>(label: &str) -> [u8; N] {
        let mut out = [0u8; N];
        for (i, chunk) in out.chunks_mut(32).enumerate() {
            let h = c::sha256(format!("{label}/{i}").as_bytes());
            chunk.copy_from_slice(&h[..chunk.len()]);
        }
        out
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn edit(bytes: &[u8], f: impl FnOnce(&mut Vec<(String, Value)>)) -> Vec<u8> {
        let Value::Map(mut entries) = c::decode(bytes).unwrap() else {
            panic!("not a map")
        };
        f(&mut entries);
        c::encode(&Value::Map(entries))
    }

    fn set(e: &mut Vec<(String, Value)>, key: &str, v: Value) {
        e.retain(|(k, _)| k != key);
        e.push((key.to_string(), v));
    }

    type Editor<'a> = &'a dyn Fn(&mut Vec<(String, Value)>);

    fn drop_key(e: &mut Vec<(String, Value)>, key: &str) {
        e.retain(|(k, _)| k != key);
    }

    fn gen_ref(generation: u64, key: &str) -> FleetGenerationRef {
        FleetGenerationRef {
            tenant_id: fx("tenant"),
            server_instance_id: fx("instance"),
            restore_epoch: 3,
            fleet_id: fx("fleet"),
            generation,
            fkek_key_id: fx(key),
        }
    }

    fn boot_terms() -> FleetGenerationTerms {
        FleetGenerationTerms {
            generation: gen_ref(0, "fkek-0"),
            required_device_grant_count: 1,
            required_device_grant_set_hash: fleet_device_grant_set_hash(&[fx("device-grant")])
                .unwrap(),
            recovery_grant_signed_container_hash: fx("recovery-grant"),
            rotation: None,
        }
    }

    fn rotation_terms() -> FleetGenerationTerms {
        FleetGenerationTerms {
            generation: gen_ref(3, "fkek-3"),
            required_device_grant_count: 2,
            required_device_grant_set_hash: fleet_device_grant_set_hash(&[
                fx("device-grant"),
                fx("device-grant-2"),
            ])
            .unwrap(),
            recovery_grant_signed_container_hash: fx("recovery-grant-3"),
            rotation: Some(FleetRotation {
                previous_generation: 2,
                previous_fkek_key_id: fx("fkek-2"),
                rotation_grant_signed_container_hash: fx("rotation-grant"),
            }),
        }
    }

    fn create(terms: FleetGenerationTerms) -> FleetKeyGenerationCreateV2 {
        FleetKeyGenerationCreateV2 {
            terms,
            root_generation: 4,
        }
    }

    fn grant_create(variant: FleetGrantVariant) -> FleetKeyGrantCreateV2 {
        FleetKeyGrantCreateV2::new(
            gen_ref(3, "fkek-3"),
            variant,
            fx("grant-replay"),
            fx("grant-container-hash"),
            b"signed fleet grant container".to_vec(),
        )
    }

    fn grant_created(variant: FleetGrantVariant) -> FleetKeyGrantCreatedV2 {
        FleetKeyGrantCreatedV2 {
            grant: grant_create(variant).grant,
            target: match variant {
                FleetGrantVariant::DeviceHpke => FleetGrantTarget::Device {
                    subject_device_id: fx("device"),
                },
                FleetGrantVariant::Recovery => FleetGrantTarget::Root {
                    recipient_root_generation: 4,
                },
                FleetGrantVariant::Rotation => FleetGrantTarget::Rotation,
            },
            created_at_ms: 1_700_000_000_000,
        }
    }

    fn revocation() -> FleetGrantRevocation {
        FleetGrantRevocation {
            generation: gen_ref(3, "fkek-3"),
            grant_variant: FleetGrantVariant::DeviceHpke,
            replay_id: fx("grant-replay"),
            signed_container_hash: fx("grant-container-hash"),
            reason_code: FleetGrantRevokeReason::MemberRemoved,
        }
    }

    /// Each map's exact bytes and a parse that drops the value.
    type Reencode = fn(&[u8]) -> Result<Vec<u8>>;

    fn maps() -> Vec<(String, Vec<u8>, Reencode)> {
        let mut out: Vec<(String, Vec<u8>, Reencode)> = Vec::new();
        for (name, terms) in [("bootstrap", boot_terms()), ("rotation", rotation_terms())] {
            out.push((format!("create {name}"), create(terms).encode(), |b| {
                FleetKeyGenerationCreateV2::parse(b).map(|m| m.encode())
            }));
            let created = FleetKeyGenerationCreatedV2 {
                create: create(terms),
                created_at_ms: 9,
            };
            out.push((format!("created {name}"), created.encode(), |b| {
                FleetKeyGenerationCreatedV2::parse(b).map(|m| m.encode())
            }));
            out.push((
                format!("activate {name}"),
                FleetKeyGenerationActivateV2 { terms }.encode(),
                |b| FleetKeyGenerationActivateV2::parse(b).map(|m| m.encode()),
            ));
            let activated = FleetKeyGenerationActivatedV2 {
                terms,
                activated_at_ms: 10,
            };
            out.push((format!("activated {name}"), activated.encode(), |b| {
                FleetKeyGenerationActivatedV2::parse(b).map(|m| m.encode())
            }));
        }
        for v in FleetGrantVariant::ALL {
            let name = v.as_str();
            out.push((
                format!("grant create {name}"),
                grant_create(v).encode(),
                |b| FleetKeyGrantCreateV2::parse(b).map(|m| m.encode()),
            ));
            out.push((
                format!("grant created {name}"),
                grant_created(v).encode(),
                |b| FleetKeyGrantCreatedV2::parse(b).map(|m| m.encode()),
            ));
            let grant = grant_create(v).grant;
            out.push((
                format!("ack {name}"),
                FleetKeyGrantAckV2 { grant }.encode(),
                |b| FleetKeyGrantAckV2::parse(b).map(|m| m.encode()),
            ));
            let acked = FleetKeyGrantAckedV2 {
                grant,
                acked_at_ms: 11,
            };
            out.push((format!("acked {name}"), acked.encode(), |b| {
                FleetKeyGrantAckedV2::parse(b).map(|m| m.encode())
            }));
        }
        out.push((
            "revoke".into(),
            FleetGrantRevokeV2 {
                revocation: revocation(),
            }
            .encode(),
            |b| FleetGrantRevokeV2::parse(b).map(|m| m.encode()),
        ));
        let revoked = FleetGrantRevokedV2 {
            revocation: revocation(),
            revoked_at_ms: 12,
            invalidation_count: 2,
        };
        out.push(("revoked".into(), revoked.encode(), |b| {
            FleetGrantRevokedV2::parse(b).map(|m| m.encode())
        }));
        out
    }

    #[test]
    fn every_map_roundtrips_byte_for_byte() {
        for terms in [boot_terms(), rotation_terms()] {
            let g = create(terms);
            assert_eq!(FleetKeyGenerationCreateV2::parse(&g.encode()).unwrap(), g);
            let g = FleetKeyGenerationActivatedV2 {
                terms,
                activated_at_ms: 10,
            };
            assert_eq!(
                FleetKeyGenerationActivatedV2::parse(&g.encode()).unwrap(),
                g
            );
        }
        for v in FleetGrantVariant::ALL {
            assert_eq!(
                FleetKeyGrantCreatedV2::parse(&grant_created(v).encode()).unwrap(),
                grant_created(v)
            );
        }
        let maps = maps();
        assert_eq!(maps.len(), 22);
        for (name, raw, reencode) in maps {
            assert_eq!(reencode(&raw).unwrap(), raw, "{name}");
        }
    }

    #[test]
    fn every_map_refuses_another_domain_version_or_extra_field() {
        for (name, raw, reencode) in maps() {
            for domain in [
                "shardx.keys.tenant-root-grant-ack.v2",
                DOMAIN_FLEET_GRANT_REVOKED,
                DOMAIN_FLEET_GENERATION_CREATE,
            ] {
                let edited = edit(&raw, |e| set(e, "domain", c::t(domain)));
                if edited != raw {
                    assert_eq!(
                        reencode(&edited),
                        Err(RecordError::BadValue("domain")),
                        "{name} {domain}"
                    );
                }
            }
            for version in [1, 3] {
                assert_eq!(
                    reencode(&edit(&raw, |e| set(e, "version", c::u(version)))),
                    Err(RecordError::BadValue("version")),
                    "{name} {version}"
                );
            }
            assert!(
                reencode(&edit(&raw, |e| set(e, "extra", c::u(1)))).is_err(),
                "{name}"
            );
            assert!(
                reencode(&edit(&raw, |e| drop_key(e, "fleet_id"))).is_err(),
                "{name}"
            );
        }
    }

    #[test]
    fn generations_follow_the_bootstrap_and_rotation_rules() {
        let parse =
            |t: FleetGenerationTerms| FleetKeyGenerationCreateV2::parse(&create(t).encode());
        // Rotation with a gap.
        let mut t = rotation_terms();
        t.rotation.as_mut().unwrap().previous_generation = 1;
        assert_eq!(parse(t), Err(RecordError::BadValue("generation")));
        // A rotation under the key it rotates away from.
        let mut t = rotation_terms();
        t.rotation.as_mut().unwrap().previous_fkek_key_id = t.generation.fkek_key_id;
        assert_eq!(parse(t), Err(RecordError::BadValue("previous_fkek_key_id")));
        // Generation 0 has no previous; every later one has all three fields.
        let mut t = boot_terms();
        t.rotation = rotation_terms().rotation;
        assert_eq!(parse(t), Err(RecordError::BadValue("previous_generation")));
        let mut t = rotation_terms();
        t.rotation = None;
        assert_eq!(parse(t), Err(RecordError::BadValue("previous_generation")));
        let raw = edit(&create(rotation_terms()).encode(), |e| {
            drop_key(e, "rotation_grant_signed_container_hash")
        });
        assert_eq!(
            FleetKeyGenerationCreateV2::parse(&raw),
            Err(RecordError::BadValue("previous_generation"))
        );
        // `mode` must say what the generation already does.
        for (terms, wrong) in [(boot_terms(), "rotation"), (rotation_terms(), "bootstrap")] {
            let raw = edit(&create(terms).encode(), |e| set(e, "mode", c::t(wrong)));
            assert_eq!(
                FleetKeyGenerationCreateV2::parse(&raw),
                Err(RecordError::BadValue("mode"))
            );
        }
        // D-4: 1..65535 required device grants.
        for n in [0u64, 65536] {
            let raw = edit(&create(boot_terms()).encode(), |e| {
                set(e, "required_device_grant_count", c::u(n))
            });
            assert!(FleetKeyGenerationCreateV2::parse(&raw).is_err(), "{n}");
        }
        // The activation response says RETIRED iff it rotated.
        for terms in [boot_terms(), rotation_terms()] {
            let raw = FleetKeyGenerationActivatedV2 {
                terms,
                activated_at_ms: 10,
            }
            .encode();
            let flipped = if terms.rotation.is_some() {
                edit(&raw, |e| drop_key(e, "previous_state"))
            } else {
                edit(&raw, |e| set(e, "previous_state", c::t("RETIRED")))
            };
            assert_eq!(
                FleetKeyGenerationActivatedV2::parse(&flipped),
                Err(RecordError::BadValue("previous_state"))
            );
        }
        let raw = edit(
            &FleetKeyGenerationCreatedV2 {
                create: create(boot_terms()),
                created_at_ms: 9,
            }
            .encode(),
            |e| set(e, "generation_state", c::t("ACTIVE")),
        );
        assert!(FleetKeyGenerationCreatedV2::parse(&raw).is_err());
    }

    #[test]
    fn grant_maps_check_their_hashes_variants_and_targets() {
        // The bytes hash is recomputed.
        let raw = edit(&grant_create(FleetGrantVariant::Recovery).encode(), |e| {
            set(
                e,
                "exact_signed_grant_container_bytes",
                c::b(b"other bytes"),
            )
        });
        assert_eq!(
            FleetKeyGrantCreateV2::parse(&raw),
            Err(RecordError::BadValue(
                "exact_signed_grant_container_bytes_sha256"
            ))
        );
        let raw = edit(&grant_create(FleetGrantVariant::Recovery).encode(), |e| {
            set(e, "grant_variant", c::t("FirstFleetSelfGrant"))
        });
        assert_eq!(
            FleetKeyGrantCreateV2::parse(&raw),
            Err(RecordError::BadValue("grant_variant"))
        );
        // An ack names the key the actor unwrapped, which must be the grant's.
        let ack = FleetKeyGrantAckV2 {
            grant: grant_create(FleetGrantVariant::Rotation).grant,
        };
        let raw = edit(&ack.encode(), |e| {
            set(
                e,
                "locally_unwrapped_fkek_key_id",
                c::b(&fx::<32>("fkek-2")),
            )
        });
        assert_eq!(
            FleetKeyGrantAckV2::parse(&raw),
            Err(RecordError::BadValue("locally_unwrapped_fkek_key_id"))
        );
        // A created grant names a subject iff device, a root iff recovery.
        let device = grant_created(FleetGrantVariant::DeviceHpke).encode();
        let recovery = grant_created(FleetGrantVariant::Recovery).encode();
        let rotation = grant_created(FleetGrantVariant::Rotation).encode();
        let cases: [(&[u8], Editor, &str); 4] = [
            (
                &device,
                &|e| drop_key(e, "subject_device_id"),
                "subject_device_id",
            ),
            (
                &recovery,
                &|e| set(e, "subject_device_id", c::b(&fx::<16>("device"))),
                "subject_device_id",
            ),
            (
                &recovery,
                &|e| drop_key(e, "recipient_root_generation"),
                "recipient_root_generation",
            ),
            (
                &rotation,
                &|e| set(e, "recipient_root_generation", c::u(4)),
                "recipient_root_generation",
            ),
        ];
        for (raw, f, field) in cases {
            assert_eq!(
                FleetKeyGrantCreatedV2::parse(&edit(raw, f)),
                Err(RecordError::BadValue(field)),
                "{field}"
            );
        }
        let raw = edit(&device, |e| set(e, "grant_state", c::t("ACKNOWLEDGED")));
        assert!(FleetKeyGrantCreatedV2::parse(&raw).is_err());
        let raw = edit(
            &FleetGrantRevokeV2 {
                revocation: revocation(),
            }
            .encode(),
            |e| set(e, "reason_code", c::t("expired")),
        );
        assert_eq!(
            FleetGrantRevokeV2::parse(&raw),
            Err(RecordError::BadValue("reason_code"))
        );
    }

    #[test]
    fn a_fleet_payload_rides_in_the_outer_request() {
        let req = IdempotentMutationRequestV2 {
            operation_kind: OperationKind::FleetGenerationCreate,
            idempotency_key: fx("idem"),
            canonical_payload_bytes: create(rotation_terms()).encode(),
            client_request_nonce: fx("nonce"),
            server_instance_id: fx("instance"),
            restore_epoch: 3,
        };
        let back = IdempotentMutationRequestV2::parse(&req.encode()).unwrap();
        assert_eq!(
            FleetKeyGenerationCreateV2::parse(&back.canonical_payload_bytes).unwrap(),
            create(rotation_terms())
        );
    }

    /// Pins the field sets of one map per kind.
    #[test]
    fn golden_vectors() {
        let pins: [(&str, Vec<u8>, &str); 5] = [
            (
                "create rotation",
                create(rotation_terms()).encode(),
                "60537dd310eec6f8c1c37de741ee762f8c37946887cb3f7540b41c19123d6748",
            ),
            (
                "grant create recovery",
                grant_create(FleetGrantVariant::Recovery).encode(),
                "f3520c99643f943b74aafaf887c518a158de0b19b13b5cd5556b233ff7c13c59",
            ),
            (
                "ack rotation",
                FleetKeyGrantAckV2 {
                    grant: grant_create(FleetGrantVariant::Rotation).grant,
                }
                .encode(),
                "d20ab205d08bb18868d6701056337b8ee4a15629e2df29392ff76c83403e171b",
            ),
            (
                "activated rotation",
                FleetKeyGenerationActivatedV2 {
                    terms: rotation_terms(),
                    activated_at_ms: 10,
                }
                .encode(),
                "b57c0048fef79f0584e263994573080aece852fad38b402b37e20ad7c11f0137",
            ),
            (
                "revoked",
                FleetGrantRevokedV2 {
                    revocation: revocation(),
                    revoked_at_ms: 12,
                    invalidation_count: 2,
                }
                .encode(),
                "8dda791d4cf66d0734c9433ae3ffda1a70d79bcf11eaaaf5a2cae6aa6b75b8b7",
            ),
        ];
        for (name, raw, want) in pins {
            assert_eq!(hex(&c::sha256(&raw)), want, "{name}");
        }
    }
}
