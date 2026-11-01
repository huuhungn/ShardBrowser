//! Exact idempotent mutation maps (plan 5.6.5) and the root generation
//! lifecycle maps: create, grant readback, acknowledgement and activation
//! (plan 5.6.4, ADR 0002 D-9 for the fleet kinds).
//!
//! The outer request and stored response wrap one operation payload each.
//! Their hashes are recomputed from the decoded fields and must equal what was
//! received, as in `authz_record`. Whether the actor may run the operation,
//! and whether the payload matches live state, is the caller's to check.

use crate::authz_record::{
    AuthorizationRecord, DeviceRevocationReason, Fields, Payload, RecordError, VerifiedRecord,
    CONTAINER_DOMAIN, CONTAINER_VERSION, MAX_RECORD_BYTES,
};
use crate::canonical::{self as c, Value};
use crate::fleet_lifecycle::{FleetKeyGenerationActivateV2, DOMAIN_FLEET_GENERATION_ACTIVATE};

type Result<T> = std::result::Result<T, RecordError>;

pub const DOMAIN_MUTATION_REQUEST: &str = "shardx.sync.idempotent-mutation-request.v2";
pub const DOMAIN_STORED_RESPONSE: &str = "shardx.sync.idempotent-stored-response.v2";
pub const DOMAIN_ROOT_GENERATION_CREATE: &str = "shardx.keys.tenant-root-generation-create.v2";
pub const DOMAIN_ROOT_GENERATION_CREATED: &str = "shardx.keys.tenant-root-generation-created.v2";
pub const RECORD_TYPE_ROOT_GENERATION_CREATED: &str = "TenantRootGenerationCreatedV2";
pub const DOMAIN_ROOT_GRANT_ACK: &str = "shardx.keys.tenant-root-grant-ack.v2";
pub const DOMAIN_ROOT_GRANT_ACKED: &str = "shardx.keys.tenant-root-grant-acked.v2";
pub const RECORD_TYPE_ROOT_GRANT_ACKED: &str = "TenantRootGrantAckedV2";
pub const DOMAIN_ROOT_GRANT_CREATE: &str = "shardx.keys.tenant-root-grant-create.v2";
pub const DOMAIN_ROOT_GRANT_CREATED: &str = "shardx.keys.tenant-root-grant-created.v2";
pub const RECORD_TYPE_ROOT_GRANT_CREATED: &str = "TenantRootGrantCreatedV2";
pub const DOMAIN_ROOT_GRANT_REVOKE: &str = "shardx.keys.tenant-root-grant-revoke.v2";
pub const DOMAIN_ROOT_GRANT_REVOKED: &str = "shardx.keys.tenant-root-grant-revoked.v2";
pub const RECORD_TYPE_ROOT_GRANT_REVOKED: &str = "TenantRootGrantRevokedV2";
/// ADR 0002 Q-13 names the request body but no domain for it or for the
/// stored response; these are the ones chosen here.
pub const DOMAIN_DEVICE_REVOKE: &str = "shardx.authz.device-revoke.v2";
pub const DOMAIN_DEVICE_REVOKED: &str = "shardx.authz.device-revoked.v2";
pub const RECORD_TYPE_DEVICE_REVOKED: &str = "DeviceRevokedV2";
pub const DOMAIN_ROOT_GENERATION_ACTIVATE: &str = "shardx.keys.tenant-root-generation-activate.v2";
pub const DOMAIN_ROOT_GENERATION_ACTIVATED: &str =
    "shardx.keys.tenant-root-generation-activated.v2";
pub const RECORD_TYPE_ROOT_GENERATION_ACTIVATED: &str = "TenantRootGenerationActivatedV2";
/// The plan names no domain for the GET readback descriptor; this is the one
/// chosen here.
pub const DOMAIN_ROOT_GRANT_DESCRIPTOR: &str = "shardx.keys.tenant-root-grant-descriptor.v2";
pub const DOMAIN_FLEET_DEVICE_GRANT_DESCRIPTOR: &str =
    "shardx.keys.fleet-device-grant-descriptor.v2";
pub(crate) const VERSION: u64 = 2;
const L_REQUEST_HASH: &str = "SHARDX-IDEMPOTENT-MUTATION-REQUEST-V2\0";
const L_RESPONSE_HASH: &str = "SHARDX-IDEMPOTENT-STORED-RESPONSE-V2\0";
const MAX_OPERATION_PAYLOAD: usize = 262144;
/// Plan 5.6.4 bound on an embedded signed grant container.
pub const MAX_EMBEDDED_GRANT_BYTES: usize = 131072;
const OUTCOME_SUCCEEDED: &str = "succeeded";
pub(crate) const GENERATION_STATE_PREPARING: &str = "PREPARING";
const L_ROOT_CUSTODIAN_SET: &str = "SHARDX-ROOT-CUSTODIAN-GRANT-SET-V2\0";
const L_FLEET_DEVICE_SET: &str = "SHARDX-FLEET-DEVICE-GRANT-SET-V2\0";

/// ADR 0002 D-4 `required_custodian_grant_set_hash`: the members' internal
/// `signed_container_hash` values, sorted ascending, concatenated and domain
/// hashed. `None` for an empty set or a repeated member, which D-4 forbids.
pub fn root_custodian_grant_set_hash(members: &[[u8; 32]]) -> Option<[u8; 32]> {
    grant_set_hash(L_ROOT_CUSTODIAN_SET, members)
}

/// ADR 0002 D-4 `required_device_grant_set_hash`, built like the root set over
/// the required `DeviceHpkeGrant`s, under its own label.
pub fn fleet_device_grant_set_hash(members: &[[u8; 32]]) -> Option<[u8; 32]> {
    grant_set_hash(L_FLEET_DEVICE_SET, members)
}

fn grant_set_hash(label: &str, members: &[[u8; 32]]) -> Option<[u8; 32]> {
    let mut sorted = members.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.is_empty() || sorted.len() != members.len() {
        return None;
    }
    Some(c::domain_hash(label, &sorted.concat()))
}

/// The closed `operation_kind` enum of plan L913 with the six D-9 kinds, and
/// the one scope each kind is filed under. `COMMIT` and `DEVICE_APPROVE` have
/// their own request maps and never appear in an outer request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationKind {
    ProfilePublishCreate,
    ProfileCheckout,
    CreateUpload,
    FinalizeUpload,
    ReleaseLease,
    LocalUnbind,
    RootGenerationCreate,
    RootGrantCreate,
    RootGrantAck,
    RootGenerationActivate,
    RootGrantRevoke,
    FleetGenerationCreate,
    FleetGrantCreate,
    FleetGrantAck,
    FleetGenerationActivate,
    FleetGrantRevoke,
    DeviceRevoke,
}

impl OperationKind {
    pub const ALL: [OperationKind; 17] = [
        Self::ProfilePublishCreate,
        Self::ProfileCheckout,
        Self::CreateUpload,
        Self::FinalizeUpload,
        Self::ReleaseLease,
        Self::LocalUnbind,
        Self::RootGenerationCreate,
        Self::RootGrantCreate,
        Self::RootGrantAck,
        Self::RootGenerationActivate,
        Self::RootGrantRevoke,
        Self::FleetGenerationCreate,
        Self::FleetGrantCreate,
        Self::FleetGrantAck,
        Self::FleetGenerationActivate,
        Self::FleetGrantRevoke,
        Self::DeviceRevoke,
    ];

    pub fn as_str(self) -> &'static str {
        self.names().0
    }

    pub fn scope(self) -> &'static str {
        self.names().1
    }

    fn names(self) -> (&'static str, &'static str) {
        match self {
            Self::ProfilePublishCreate => ("PROFILE_PUBLISH_CREATE", "profile.publish-create.v2"),
            Self::ProfileCheckout => ("PROFILE_CHECKOUT", "profile.checkout.v2"),
            Self::CreateUpload => ("CREATE_UPLOAD", "profile.create-upload.v2"),
            Self::FinalizeUpload => ("FINALIZE_UPLOAD", "profile.finalize-upload.v2"),
            Self::ReleaseLease => ("RELEASE_LEASE", "profile.release-lease.v2"),
            Self::LocalUnbind => ("LOCAL_UNBIND", "local.profile.unbind.v2"),
            Self::RootGenerationCreate => {
                ("ROOT_GENERATION_CREATE", "tenant.root-generation-create.v2")
            }
            Self::RootGrantCreate => ("ROOT_GRANT_CREATE", "tenant.root-grant-create.v2"),
            Self::RootGrantAck => ("ROOT_GRANT_ACK", "tenant.root-grant-ack.v2"),
            Self::RootGenerationActivate => (
                "ROOT_GENERATION_ACTIVATE",
                "tenant.root-generation-activate.v2",
            ),
            Self::RootGrantRevoke => ("ROOT_GRANT_REVOKE", "tenant.root-grant-revoke.v2"),
            Self::FleetGenerationCreate => {
                ("FLEET_GENERATION_CREATE", "fleet.key-generation-create.v2")
            }
            Self::FleetGrantCreate => ("FLEET_GRANT_CREATE", "fleet.key-grant-create.v2"),
            Self::FleetGrantAck => ("FLEET_GRANT_ACK", "fleet.key-grant-ack.v2"),
            Self::FleetGenerationActivate => (
                "FLEET_GENERATION_ACTIVATE",
                "fleet.key-generation-activate.v2",
            ),
            Self::FleetGrantRevoke => ("FLEET_GRANT_REVOKE", "fleet.key-grant-revoke.v2"),
            Self::DeviceRevoke => ("DEVICE_REVOKE", "device.revoke.v2"),
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

pub(crate) fn exact_version(f: &mut Fields, domain: &str) -> Result<()> {
    f.exact_text("domain", domain)?;
    if f.uint("version")? != VERSION {
        return Err(RecordError::BadValue("version"));
    }
    Ok(())
}

/// Takes the kind and scope, which must name each other.
fn take_kind(f: &mut Fields) -> Result<OperationKind> {
    let kind = OperationKind::parse(&f.text("operation_kind")?)
        .ok_or(RecordError::BadValue("operation_kind"))?;
    f.exact_text("operation_scope", kind.scope())?;
    Ok(kind)
}

pub(crate) fn u32_in(f: &mut Fields, field: &'static str, min: u64, max: u64) -> Result<u32> {
    let n = f.uint(field)?;
    if !(min..=max).contains(&n) {
        return Err(f.bad(field));
    }
    Ok(n as u32)
}

// ------------------------------------------------ IdempotentMutationRequestV2 ---

/// Plan 5.6.5 outer request. `parse` checks the payload hash and the request
/// hash; `exact_request_bytes_sha256` is what storage keeps beside them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdempotentMutationRequestV2 {
    pub operation_kind: OperationKind,
    pub idempotency_key: [u8; 16],
    pub canonical_payload_bytes: Vec<u8>,
    pub client_request_nonce: [u8; 16],
    pub server_instance_id: [u8; 16],
    pub restore_epoch: u64,
}

impl IdempotentMutationRequestV2 {
    fn core(&self) -> Vec<(&'static str, Value)> {
        vec![
            ("domain", c::t(DOMAIN_MUTATION_REQUEST)),
            ("version", c::u(VERSION)),
            ("operation_kind", c::t(self.operation_kind.as_str())),
            ("operation_scope", c::t(self.operation_kind.scope())),
            ("idempotency_key", c::b(&self.idempotency_key)),
            (
                "canonical_payload_bytes",
                c::b(&self.canonical_payload_bytes),
            ),
            (
                "payload_sha256",
                c::b(&c::sha256(&self.canonical_payload_bytes)),
            ),
            ("client_request_nonce", c::b(&self.client_request_nonce)),
            ("server_instance_id", c::b(&self.server_instance_id)),
            ("restore_epoch", c::u(self.restore_epoch)),
        ]
    }

    pub fn canonical_request_hash(&self) -> [u8; 32] {
        c::domain_hash(L_REQUEST_HASH, &c::encode(&c::m(self.core())))
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut map = self.core();
        map.push((
            "canonical_request_hash",
            c::b(&self.canonical_request_hash()),
        ));
        c::encode(&c::m(map))
    }

    pub fn parse(exact: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("IdempotentMutationRequestV2", exact)?;
        exact_version(&mut f, DOMAIN_MUTATION_REQUEST)?;
        let operation_kind = take_kind(&mut f)?;
        let idempotency_key = f.fixed("idempotency_key")?;
        let canonical_payload_bytes =
            f.bytes("canonical_payload_bytes", 1, MAX_OPERATION_PAYLOAD)?;
        let payload_sha256: [u8; 32] = f.fixed("payload_sha256")?;
        let client_request_nonce = f.fixed("client_request_nonce")?;
        let server_instance_id = f.fixed("server_instance_id")?;
        let restore_epoch = f.uint("restore_epoch")?;
        let canonical_request_hash: [u8; 32] = f.fixed("canonical_request_hash")?;
        f.finish()?;

        if payload_sha256 != c::sha256(&canonical_payload_bytes) {
            return Err(RecordError::PayloadHashMismatch);
        }
        let req = Self {
            operation_kind,
            idempotency_key,
            canonical_payload_bytes,
            client_request_nonce,
            server_instance_id,
            restore_epoch,
        };
        if canonical_request_hash != req.canonical_request_hash() {
            return Err(RecordError::BadValue("canonical_request_hash"));
        }
        Ok(req)
    }
}

// ------------------------------------------------ IdempotentStoredResponseV2 ---

/// Plan 5.6.5 stored response, persisted and replayed as its exact bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdempotentStoredResponseV2 {
    pub operation_kind: OperationKind,
    pub idempotency_key: [u8; 16],
    /// The request's `canonical_request_hash`, as in the commit receipt (plan
    /// L572), not the SHA-256 of its exact bytes.
    pub exact_request_hash: [u8; 32],
    pub response_record_type: String,
    pub canonical_response_payload_bytes: Vec<u8>,
    pub server_instance_id: [u8; 16],
    pub restore_epoch: u64,
    pub committed_at_ms: u64,
    pub receipt_id: [u8; 16],
}

impl IdempotentStoredResponseV2 {
    fn core(&self) -> Vec<(&'static str, Value)> {
        vec![
            ("domain", c::t(DOMAIN_STORED_RESPONSE)),
            ("version", c::u(VERSION)),
            ("operation_kind", c::t(self.operation_kind.as_str())),
            ("operation_scope", c::t(self.operation_kind.scope())),
            ("idempotency_key", c::b(&self.idempotency_key)),
            ("exact_request_hash", c::b(&self.exact_request_hash)),
            ("response_record_type", c::t(&self.response_record_type)),
            (
                "canonical_response_payload_bytes",
                c::b(&self.canonical_response_payload_bytes),
            ),
            (
                "response_payload_sha256",
                c::b(&c::sha256(&self.canonical_response_payload_bytes)),
            ),
            ("outcome", c::t(OUTCOME_SUCCEEDED)),
            ("server_instance_id", c::b(&self.server_instance_id)),
            ("restore_epoch", c::u(self.restore_epoch)),
            ("committed_at_ms", c::u(self.committed_at_ms)),
            ("receipt_id", c::b(&self.receipt_id)),
        ]
    }

    pub fn stored_response_hash(&self) -> [u8; 32] {
        c::domain_hash(L_RESPONSE_HASH, &c::encode(&c::m(self.core())))
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut map = self.core();
        map.push(("stored_response_hash", c::b(&self.stored_response_hash())));
        c::encode(&c::m(map))
    }

    pub fn parse(exact: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("IdempotentStoredResponseV2", exact)?;
        exact_version(&mut f, DOMAIN_STORED_RESPONSE)?;
        let operation_kind = take_kind(&mut f)?;
        let idempotency_key = f.fixed("idempotency_key")?;
        let exact_request_hash = f.fixed("exact_request_hash")?;
        let response_record_type = f.text("response_record_type")?;
        let canonical_response_payload_bytes =
            f.bytes("canonical_response_payload_bytes", 1, MAX_OPERATION_PAYLOAD)?;
        let response_payload_sha256: [u8; 32] = f.fixed("response_payload_sha256")?;
        f.exact_text("outcome", OUTCOME_SUCCEEDED)?;
        let server_instance_id = f.fixed("server_instance_id")?;
        let restore_epoch = f.uint("restore_epoch")?;
        let committed_at_ms = f.uint("committed_at_ms")?;
        let receipt_id = f.fixed("receipt_id")?;
        let stored_response_hash: [u8; 32] = f.fixed("stored_response_hash")?;
        f.finish()?;

        // shortcut: plan L927 leaves the type unbounded and does not tie it to
        // the kind; 128 bytes holds every 5.6.4 record name. Bind it to the
        // kind when a second kind has a codec.
        if !(1..=128).contains(&response_record_type.len()) {
            return Err(RecordError::BadField {
                map: "IdempotentStoredResponseV2",
                field: "response_record_type",
            });
        }
        if response_payload_sha256 != c::sha256(&canonical_response_payload_bytes) {
            return Err(RecordError::PayloadHashMismatch);
        }
        let resp = Self {
            operation_kind,
            idempotency_key,
            exact_request_hash,
            response_record_type,
            canonical_response_payload_bytes,
            server_instance_id,
            restore_epoch,
            committed_at_ms,
            receipt_id,
        };
        if stored_response_hash != resp.stored_response_hash() {
            return Err(RecordError::BadValue("stored_response_hash"));
        }
        Ok(resp)
    }
}

// ----------------------------------------- TenantRootGenerationCreate(d)V2 ---

/// How a root generation comes to exist (plan 5.6.4). Bootstrap carries the
/// embedded first self-grant; a rotation names the ACTIVE generation it follows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootGenerationMode<B> {
    Bootstrap(B),
    Rotation {
        previous_root_key_id: [u8; 32],
        previous_root_generation: u64,
    },
}

/// The first self-grant as the request embeds it. `parse` checks the bytes
/// hash; the container hash and the grant itself are checked by the caller,
/// which must parse the container anyway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddedSelfGrant {
    pub container_bytes: Vec<u8>,
    pub signed_container_hash: [u8; 32],
}

/// The first self-grant as the response names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfGrantIdentity {
    pub replay_id: [u8; 16],
    pub signed_container_hash: [u8; 32],
    pub container_bytes_sha256: [u8; 32],
}

/// Fields the create request and its response share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootGenerationTarget {
    pub tenant_id: [u8; 16],
    pub server_instance_id: [u8; 16],
    pub restore_epoch: u64,
    pub root_key_id: [u8; 32],
    pub root_generation: u64,
    pub required_custodian_grant_count: u32,
    pub required_custodian_grant_set_hash: [u8; 32],
    pub recovery_bundle_sha256: [u8; 32],
}

impl RootGenerationTarget {
    fn take(f: &mut Fields) -> Result<Self> {
        Ok(Self {
            tenant_id: f.fixed("tenant_id")?,
            server_instance_id: f.fixed("server_instance_id")?,
            restore_epoch: f.uint("restore_epoch")?,
            root_key_id: f.fixed("root_key_id")?,
            root_generation: f.uint("root_generation")?,
            required_custodian_grant_count: u32_in(f, "required_custodian_grant_count", 1, 65535)?,
            required_custodian_grant_set_hash: f.fixed("required_custodian_grant_set_hash")?,
            recovery_bundle_sha256: f.fixed("recovery_bundle_sha256")?,
        })
    }

    fn put(&self, out: &mut Vec<(&'static str, Value)>) {
        out.extend([
            ("tenant_id", c::b(&self.tenant_id)),
            ("server_instance_id", c::b(&self.server_instance_id)),
            ("restore_epoch", c::u(self.restore_epoch)),
            ("root_key_id", c::b(&self.root_key_id)),
            ("root_generation", c::u(self.root_generation)),
            (
                "required_custodian_grant_count",
                c::u(self.required_custodian_grant_count.into()),
            ),
            (
                "required_custodian_grant_set_hash",
                c::b(&self.required_custodian_grant_set_hash),
            ),
            ("recovery_bundle_sha256", c::b(&self.recovery_bundle_sha256)),
        ]);
    }
}

/// Takes `mode` and the previous-root pair, which is present iff rotation, and
/// checks the generation rule of each mode: bootstrap is generation 0, and a
/// rotation targets previous + 1 under another key.
fn take_mode(f: &mut Fields, target: &RootGenerationTarget) -> Result<RootGenerationMode<()>> {
    let mode = f.text("mode")?;
    let previous_root_key_id = f.opt_fixed::<32>("previous_root_key_id")?;
    let previous_root_generation = f.opt_uint("previous_root_generation")?;
    let mode = match (
        mode.as_str(),
        previous_root_key_id,
        previous_root_generation,
    ) {
        ("bootstrap", None, None) => RootGenerationMode::Bootstrap(()),
        ("rotation", Some(previous_root_key_id), Some(previous_root_generation)) => {
            RootGenerationMode::Rotation {
                previous_root_key_id,
                previous_root_generation,
            }
        }
        ("bootstrap" | "rotation", _, _) => {
            return Err(RecordError::BadValue("previous_root_key_id"))
        }
        _ => return Err(RecordError::BadValue("mode")),
    };
    match mode {
        RootGenerationMode::Bootstrap(()) if target.root_generation != 0 => {
            Err(RecordError::BadValue("root_generation"))
        }
        RootGenerationMode::Rotation {
            previous_root_key_id,
            previous_root_generation,
        } => {
            if previous_root_generation.checked_add(1) != Some(target.root_generation) {
                return Err(RecordError::BadValue("root_generation"));
            }
            if previous_root_key_id == target.root_key_id {
                return Err(RecordError::BadValue("previous_root_key_id"));
            }
            Ok(mode)
        }
        _ => Ok(mode),
    }
}

/// ADR 0002 D-4: the custodian set of a bootstrap is its self-grant alone,
/// and both are named in the same map.
fn bootstrap_set_is_self_grant(target: &RootGenerationTarget, self_grant: &[u8; 32]) -> Result<()> {
    if target.required_custodian_grant_count != 1 {
        return Err(RecordError::BadValue("required_custodian_grant_count"));
    }
    if root_custodian_grant_set_hash(&[*self_grant])
        != Some(target.required_custodian_grant_set_hash)
    {
        return Err(RecordError::BadValue("required_custodian_grant_set_hash"));
    }
    Ok(())
}

fn put_mode<B>(mode: &RootGenerationMode<B>, out: &mut Vec<(&'static str, Value)>) {
    match mode {
        RootGenerationMode::Bootstrap(_) => out.push(("mode", c::t("bootstrap"))),
        RootGenerationMode::Rotation {
            previous_root_key_id,
            previous_root_generation,
        } => out.extend([
            ("mode", c::t("rotation")),
            ("previous_root_key_id", c::b(previous_root_key_id)),
            ("previous_root_generation", c::u(*previous_root_generation)),
        ]),
    }
}

/// Plan 5.6.4 `TenantRootGenerationCreateV2`, the `ROOT_GENERATION_CREATE` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootGenerationCreateV2 {
    pub target: RootGenerationTarget,
    pub mode: RootGenerationMode<EmbeddedSelfGrant>,
}

impl TenantRootGenerationCreateV2 {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("TenantRootGenerationCreateV2", payload)?;
        exact_version(&mut f, DOMAIN_ROOT_GENERATION_CREATE)?;
        let target = RootGenerationTarget::take(&mut f)?;
        let mode = take_mode(&mut f, &target)?;
        let bytes = f
            .take("first_self_grant_container_bytes")
            .map(|v| match v {
                Value::Bytes(b) if (1..=MAX_EMBEDDED_GRANT_BYTES).contains(&b.len()) => Ok(b),
                _ => Err(f.bad("first_self_grant_container_bytes")),
            })
            .transpose()?;
        let hash = f.opt_fixed::<32>("first_self_grant_signed_container_hash")?;
        let bytes_sha = f.opt_fixed::<32>("first_self_grant_container_bytes_sha256")?;
        f.finish()?;

        let mode = match (mode, bytes, hash, bytes_sha) {
            (RootGenerationMode::Bootstrap(()), Some(container_bytes), Some(hash), Some(sha)) => {
                if sha != c::sha256(&container_bytes) {
                    return Err(RecordError::BadValue(
                        "first_self_grant_container_bytes_sha256",
                    ));
                }
                bootstrap_set_is_self_grant(&target, &hash)?;
                RootGenerationMode::Bootstrap(EmbeddedSelfGrant {
                    container_bytes,
                    signed_container_hash: hash,
                })
            }
            (
                RootGenerationMode::Rotation {
                    previous_root_key_id,
                    previous_root_generation,
                },
                None,
                None,
                None,
            ) => RootGenerationMode::Rotation {
                previous_root_key_id,
                previous_root_generation,
            },
            // The embedded grant is present iff bootstrap.
            _ => return Err(RecordError::BadValue("first_self_grant_container_bytes")),
        };
        Ok(Self { target, mode })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![
            ("domain", c::t(DOMAIN_ROOT_GENERATION_CREATE)),
            ("version", c::u(VERSION)),
        ];
        self.target.put(&mut out);
        put_mode(&self.mode, &mut out);
        if let RootGenerationMode::Bootstrap(g) = &self.mode {
            out.extend([
                ("first_self_grant_container_bytes", c::b(&g.container_bytes)),
                (
                    "first_self_grant_signed_container_hash",
                    c::b(&g.signed_container_hash),
                ),
                (
                    "first_self_grant_container_bytes_sha256",
                    c::b(&c::sha256(&g.container_bytes)),
                ),
            ]);
        }
        c::encode(&c::m(out))
    }
}

/// Plan 5.6.4 `TenantRootGenerationCreatedV2`, the stored response payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootGenerationCreatedV2 {
    pub target: RootGenerationTarget,
    pub mode: RootGenerationMode<SelfGrantIdentity>,
    pub created_at_ms: u64,
}

impl TenantRootGenerationCreatedV2 {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("TenantRootGenerationCreatedV2", payload)?;
        exact_version(&mut f, DOMAIN_ROOT_GENERATION_CREATED)?;
        let target = RootGenerationTarget::take(&mut f)?;
        let mode = take_mode(&mut f, &target)?;
        f.exact_text("generation_state", GENERATION_STATE_PREPARING)?;
        let replay_id = f.opt_fixed::<16>("first_self_grant_replay_id")?;
        let hash = f.opt_fixed::<32>("first_self_grant_signed_container_hash")?;
        let bytes_sha = f.opt_fixed::<32>("first_self_grant_container_bytes_sha256")?;
        let created_at_ms = f.uint("created_at_ms")?;
        f.finish()?;

        let mode = match (mode, replay_id, hash, bytes_sha) {
            (RootGenerationMode::Bootstrap(()), Some(replay_id), Some(hash), Some(sha)) => {
                bootstrap_set_is_self_grant(&target, &hash)?;
                RootGenerationMode::Bootstrap(SelfGrantIdentity {
                    replay_id,
                    signed_container_hash: hash,
                    container_bytes_sha256: sha,
                })
            }
            (
                RootGenerationMode::Rotation {
                    previous_root_key_id,
                    previous_root_generation,
                },
                None,
                None,
                None,
            ) => RootGenerationMode::Rotation {
                previous_root_key_id,
                previous_root_generation,
            },
            _ => return Err(RecordError::BadValue("first_self_grant_replay_id")),
        };
        Ok(Self {
            target,
            mode,
            created_at_ms,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![
            ("domain", c::t(DOMAIN_ROOT_GENERATION_CREATED)),
            ("version", c::u(VERSION)),
        ];
        self.target.put(&mut out);
        put_mode(&self.mode, &mut out);
        out.push(("generation_state", c::t(GENERATION_STATE_PREPARING)));
        if let RootGenerationMode::Bootstrap(g) = &self.mode {
            out.extend([
                ("first_self_grant_replay_id", c::b(&g.replay_id)),
                (
                    "first_self_grant_signed_container_hash",
                    c::b(&g.signed_container_hash),
                ),
                (
                    "first_self_grant_container_bytes_sha256",
                    c::b(&g.container_bytes_sha256),
                ),
            ]);
        }
        out.push(("created_at_ms", c::u(self.created_at_ms)));
        c::encode(&c::m(out))
    }
}

// -------------------------------------------------------- root grant refs ---

/// The fields that name one stored root grant exactly: its context, its
/// generation and root key, its replay ID and both container hashes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootGrantRef {
    pub tenant_id: [u8; 16],
    pub server_instance_id: [u8; 16],
    pub restore_epoch: u64,
    pub root_generation: u64,
    pub root_key_id: [u8; 32],
    pub replay_id: [u8; 16],
    pub signed_container_hash: [u8; 32],
    pub exact_signed_container_bytes_sha256: [u8; 32],
}

impl RootGrantRef {
    fn take(f: &mut Fields) -> Result<Self> {
        Ok(Self {
            tenant_id: f.fixed("tenant_id")?,
            server_instance_id: f.fixed("server_instance_id")?,
            restore_epoch: f.uint("restore_epoch")?,
            root_generation: f.uint("root_generation")?,
            root_key_id: f.fixed("root_key_id")?,
            replay_id: f.fixed("replay_id")?,
            signed_container_hash: f.fixed("signed_container_hash")?,
            exact_signed_container_bytes_sha256: f.fixed("exact_signed_container_bytes_sha256")?,
        })
    }

    fn put(&self, out: &mut Vec<(&'static str, Value)>) {
        out.extend([
            ("tenant_id", c::b(&self.tenant_id)),
            ("server_instance_id", c::b(&self.server_instance_id)),
            ("restore_epoch", c::u(self.restore_epoch)),
            ("root_generation", c::u(self.root_generation)),
            ("root_key_id", c::b(&self.root_key_id)),
            ("replay_id", c::b(&self.replay_id)),
            ("signed_container_hash", c::b(&self.signed_container_hash)),
            (
                "exact_signed_container_bytes_sha256",
                c::b(&self.exact_signed_container_bytes_sha256),
            ),
        ]);
    }
}

/// Plan 5.6.4 `TenantRootGrantAckV2`, the `ROOT_GRANT_ACK` payload. The
/// subject sends it after it opened the grant and the TRK it got re-derived the
/// target root key ID, so `locally_unwrapped_trk_key_id` always equals
/// `root_key_id`; a different value does not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootGrantAckV2 {
    pub grant: RootGrantRef,
}

impl TenantRootGrantAckV2 {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("TenantRootGrantAckV2", payload)?;
        exact_version(&mut f, DOMAIN_ROOT_GRANT_ACK)?;
        let grant = RootGrantRef::take(&mut f)?;
        let unwrapped: [u8; 32] = f.fixed("locally_unwrapped_trk_key_id")?;
        f.finish()?;
        if unwrapped != grant.root_key_id {
            return Err(RecordError::BadValue("locally_unwrapped_trk_key_id"));
        }
        Ok(Self { grant })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![
            ("domain", c::t(DOMAIN_ROOT_GRANT_ACK)),
            ("version", c::u(VERSION)),
        ];
        self.grant.put(&mut out);
        out.push((
            "locally_unwrapped_trk_key_id",
            c::b(&self.grant.root_key_id),
        ));
        c::encode(&c::m(out))
    }
}

pub(crate) const ACK_OUTCOME_ACKNOWLEDGED: &str = "acknowledged";

/// Plan 5.6.5 `TenantRootGrantAckedV2`, the stored `ROOT_GRANT_ACK` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootGrantAckedV2 {
    pub grant: RootGrantRef,
    pub acked_at_ms: u64,
}

impl TenantRootGrantAckedV2 {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("TenantRootGrantAckedV2", payload)?;
        exact_version(&mut f, DOMAIN_ROOT_GRANT_ACKED)?;
        let grant = RootGrantRef::take(&mut f)?;
        f.exact_text("ack_outcome", ACK_OUTCOME_ACKNOWLEDGED)?;
        let acked_at_ms = f.uint("acked_at_ms")?;
        f.finish()?;
        Ok(Self { grant, acked_at_ms })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![
            ("domain", c::t(DOMAIN_ROOT_GRANT_ACKED)),
            ("version", c::u(VERSION)),
        ];
        self.grant.put(&mut out);
        out.extend([
            ("ack_outcome", c::t(ACK_OUTCOME_ACKNOWLEDGED)),
            ("acked_at_ms", c::u(self.acked_at_ms)),
        ]);
        c::encode(&c::m(out))
    }
}

// ------------------------------------------------------------------ create ---

/// Plan L946 `TenantRootGrantCreateV2`, the `ROOT_GRANT_CREATE` payload: the
/// grant's identity and its exact signed container, which must hash to both
/// named hashes. Which variants a server files is the route's rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootGrantCreateV2 {
    pub grant: RootGrantRef,
    pub exact_signed_grant_container_bytes: Vec<u8>,
}

impl TenantRootGrantCreateV2 {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("TenantRootGrantCreateV2", payload)?;
        exact_version(&mut f, DOMAIN_ROOT_GRANT_CREATE)?;
        let grant = RootGrantRef::take(&mut f)?;
        let bytes = f.bytes(
            "exact_signed_grant_container_bytes",
            1,
            MAX_EMBEDDED_GRANT_BYTES,
        )?;
        f.finish()?;
        if grant.exact_signed_container_bytes_sha256 != c::sha256(&bytes) {
            return Err(RecordError::BadValue("exact_signed_container_bytes_sha256"));
        }
        Ok(Self {
            grant,
            exact_signed_grant_container_bytes: bytes,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![
            ("domain", c::t(DOMAIN_ROOT_GRANT_CREATE)),
            ("version", c::u(VERSION)),
        ];
        self.grant.put(&mut out);
        out.push((
            "exact_signed_grant_container_bytes",
            c::b(&self.exact_signed_grant_container_bytes),
        ));
        c::encode(&c::m(out))
    }
}

/// The grant variants `ROOT_GRANT_CREATE` carries (plan L946); the first
/// self-grant arrives with the bootstrap instead.
pub const ROOT_GRANT_CREATE_VARIANTS: [&str; 2] = ["ExistingRootGrant", "RotationGrant"];

/// Plan L946 `TenantRootGrantCreatedV2`, the stored `ROOT_GRANT_CREATE`
/// response. A filed grant is always pending its acknowledgement, and only
/// the two variants this route files can be named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootGrantCreatedV2 {
    pub grant: RootGrantRef,
    pub grant_variant: &'static str,
    pub subject_device_id: [u8; 16],
    pub recipient_hpke_key_id: [u8; 32],
    pub created_at_ms: u64,
}

impl TenantRootGrantCreatedV2 {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("TenantRootGrantCreatedV2", payload)?;
        exact_version(&mut f, DOMAIN_ROOT_GRANT_CREATED)?;
        let grant = RootGrantRef::take(&mut f)?;
        let variant = f.text("grant_variant")?;
        let grant_variant = ROOT_GRANT_CREATE_VARIANTS
            .into_iter()
            .find(|v| *v == variant)
            .ok_or(RecordError::BadValue("grant_variant"))?;
        let subject_device_id = f.fixed("subject_device_id")?;
        let recipient_hpke_key_id = f.fixed("recipient_hpke_key_id")?;
        f.exact_text("grant_state", RootGrantState::PendingAck.as_str())?;
        let created_at_ms = f.uint("created_at_ms")?;
        f.finish()?;
        Ok(Self {
            grant,
            grant_variant,
            subject_device_id,
            recipient_hpke_key_id,
            created_at_ms,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![
            ("domain", c::t(DOMAIN_ROOT_GRANT_CREATED)),
            ("version", c::u(VERSION)),
        ];
        self.grant.put(&mut out);
        out.extend([
            ("grant_variant", c::t(self.grant_variant)),
            ("subject_device_id", c::b(&self.subject_device_id)),
            ("recipient_hpke_key_id", c::b(&self.recipient_hpke_key_id)),
            ("grant_state", c::t(RootGrantState::PendingAck.as_str())),
            ("created_at_ms", c::u(self.created_at_ms)),
        ]);
        c::encode(&c::m(out))
    }
}

// ------------------------------------------------------------------ revoke ---

/// Plan L949 `reason_code` of a root grant revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootGrantRevokeReason {
    DeviceLost,
    CustodyRemoved,
    RotationExclusion,
}

impl RootGrantRevokeReason {
    pub const ALL: [Self; 3] = [
        Self::DeviceLost,
        Self::CustodyRemoved,
        Self::RotationExclusion,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeviceLost => "device_lost",
            Self::CustodyRemoved => "custody_removed",
            Self::RotationExclusion => "rotation_exclusion",
        }
    }

    fn take(f: &mut Fields) -> Result<Self> {
        let reason = f.text("reason_code")?;
        Self::ALL
            .into_iter()
            .find(|r| r.as_str() == reason)
            .ok_or(RecordError::BadValue("reason_code"))
    }
}

/// Plan L949 `TenantRootGrantRevokeV2`, the `ROOT_GRANT_REVOKE` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootGrantRevokeV2 {
    pub grant: RootGrantRef,
    pub reason_code: RootGrantRevokeReason,
}

impl TenantRootGrantRevokeV2 {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("TenantRootGrantRevokeV2", payload)?;
        exact_version(&mut f, DOMAIN_ROOT_GRANT_REVOKE)?;
        let grant = RootGrantRef::take(&mut f)?;
        let reason_code = RootGrantRevokeReason::take(&mut f)?;
        f.finish()?;
        Ok(Self { grant, reason_code })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![
            ("domain", c::t(DOMAIN_ROOT_GRANT_REVOKE)),
            ("version", c::u(VERSION)),
        ];
        self.grant.put(&mut out);
        out.push(("reason_code", c::t(self.reason_code.as_str())));
        c::encode(&c::m(out))
    }
}

pub(crate) const REVOKE_OUTCOME_REVOKED: &str = "revoked";

/// Plan L949 `TenantRootGrantRevokedV2`, the stored `ROOT_GRANT_REVOKE`
/// response. A replay returns these bytes, so the count and time never change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootGrantRevokedV2 {
    pub grant: RootGrantRef,
    pub reason_code: RootGrantRevokeReason,
    pub sessions_invalidated_count: u32,
    pub revoked_at_ms: u64,
}

impl TenantRootGrantRevokedV2 {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("TenantRootGrantRevokedV2", payload)?;
        exact_version(&mut f, DOMAIN_ROOT_GRANT_REVOKED)?;
        let grant = RootGrantRef::take(&mut f)?;
        let reason_code = RootGrantRevokeReason::take(&mut f)?;
        f.exact_text("revoke_outcome", REVOKE_OUTCOME_REVOKED)?;
        let sessions_invalidated_count =
            u32_in(&mut f, "sessions_invalidated_count", 0, u32::MAX.into())?;
        let revoked_at_ms = f.uint("revoked_at_ms")?;
        f.finish()?;
        Ok(Self {
            grant,
            reason_code,
            sessions_invalidated_count,
            revoked_at_ms,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![
            ("domain", c::t(DOMAIN_ROOT_GRANT_REVOKED)),
            ("version", c::u(VERSION)),
        ];
        self.grant.put(&mut out);
        out.extend([
            ("reason_code", c::t(self.reason_code.as_str())),
            ("revoke_outcome", c::t(REVOKE_OUTCOME_REVOKED)),
            (
                "sessions_invalidated_count",
                c::u(self.sessions_invalidated_count.into()),
            ),
            ("revoked_at_ms", c::u(self.revoked_at_ms)),
        ]);
        c::encode(&c::m(out))
    }
}

// ----------------------------------------------------------- device revoke ---

/// One activation a revocation carries (ADR 0002 Q-13, C-1): the exact
/// request payload of a standalone root or fleet generation activation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenerationActivation {
    Root(TenantRootGenerationActivateV2),
    Fleet(FleetKeyGenerationActivateV2),
}

impl GenerationActivation {
    fn parse(item: Value) -> Result<Self> {
        let bad = || RecordError::BadValue("activations");
        let Value::Bytes(bytes) = item else {
            return Err(bad());
        };
        let domain = match c::decode(&bytes) {
            Ok(Value::Map(entries)) => entries.into_iter().find(|(k, _)| k == "domain"),
            _ => None,
        };
        let parsed = match domain {
            Some((_, Value::Text(d))) if d == DOMAIN_ROOT_GENERATION_ACTIVATE => {
                Self::Root(TenantRootGenerationActivateV2::parse(&bytes)?)
            }
            Some((_, Value::Text(d))) if d == DOMAIN_FLEET_GENERATION_ACTIVATE => {
                Self::Fleet(FleetKeyGenerationActivateV2::parse(&bytes)?)
            }
            _ => return Err(bad()),
        };
        if parsed.encode() != bytes {
            return Err(bad());
        }
        Ok(parsed)
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Root(a) => a.encode(),
            Self::Fleet(a) => a.encode(),
        }
    }

    /// The ADR's order (kind, fleet_id, generation): roots first, under an
    /// all-zero fleet_id since a root generation belongs to no fleet.
    fn sort_key(&self) -> (u8, [u8; 16], u64) {
        match self {
            Self::Root(a) => (0, [0; 16], a.target.root_generation),
            Self::Fleet(a) => (
                1,
                a.terms.generation.fleet_id,
                a.terms.generation.generation,
            ),
        }
    }
}

/// ADR 0002 Q-13 `DeviceRevokeRequestV2`, the `DEVICE_REVOKE` payload: the
/// exact signed `DeviceRevocationV2` container, its hash, and the optional
/// activations committed with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRevokeRequestV2 {
    pub signed_container_hash: [u8; 32],
    pub exact_signed_revocation_container_bytes: Vec<u8>,
    pub activations: Vec<GenerationActivation>,
}

impl DeviceRevokeRequestV2 {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("DeviceRevokeRequestV2", payload)?;
        exact_version(&mut f, DOMAIN_DEVICE_REVOKE)?;
        let signed_container_hash = f.fixed("signed_container_hash")?;
        let bytes = f.bytes(
            "exact_signed_revocation_container_bytes",
            1,
            MAX_EMBEDDED_GRANT_BYTES,
        )?;
        let Value::Array(items) = f.req("activations")? else {
            return Err(RecordError::BadValue("activations"));
        };
        if items.len() > usize::from(u16::MAX) {
            return Err(RecordError::BadValue("activations"));
        }
        let activations = items
            .into_iter()
            .map(GenerationActivation::parse)
            .collect::<Result<Vec<_>>>()?;
        // Strictly increasing keys: sorted, and no generation twice.
        if !activations
            .windows(2)
            .all(|w| w[0].sort_key() < w[1].sort_key())
        {
            return Err(RecordError::BadValue("activations"));
        }
        f.finish()?;
        let rec = AuthorizationRecord::parse(&bytes)?;
        if *rec.signed_container_hash() != signed_container_hash {
            return Err(RecordError::BadValue("signed_container_hash"));
        }
        Ok(Self {
            signed_container_hash,
            exact_signed_revocation_container_bytes: bytes,
            activations,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        c::encode(&c::m(vec![
            ("domain", c::t(DOMAIN_DEVICE_REVOKE)),
            ("version", c::u(VERSION)),
            ("signed_container_hash", c::b(&self.signed_container_hash)),
            (
                "exact_signed_revocation_container_bytes",
                c::b(&self.exact_signed_revocation_container_bytes),
            ),
            (
                "activations",
                Value::Array(self.activations.iter().map(|a| c::b(&a.encode())).collect()),
            ),
        ]))
    }
}

/// The stored `DEVICE_REVOKE` response. A replay returns these bytes, so the
/// count and time never change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRevokedV2 {
    pub tenant_id: [u8; 16],
    pub subject_device_id: [u8; 16],
    pub replay_id: [u8; 16],
    pub signed_container_hash: [u8; 32],
    pub reason_code: DeviceRevocationReason,
    pub sessions_invalidated_count: u32,
    pub revoked_at_ms: u64,
}

impl DeviceRevokedV2 {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("DeviceRevokedV2", payload)?;
        exact_version(&mut f, DOMAIN_DEVICE_REVOKED)?;
        let tenant_id = f.fixed("tenant_id")?;
        let subject_device_id = f.fixed("subject_device_id")?;
        let replay_id = f.fixed("replay_id")?;
        let signed_container_hash = f.fixed("signed_container_hash")?;
        let reason = f.text("reason_code")?;
        let reason_code = DeviceRevocationReason::ALL
            .into_iter()
            .find(|r| r.as_str() == reason)
            .ok_or(RecordError::BadValue("reason_code"))?;
        f.exact_text("revoke_outcome", REVOKE_OUTCOME_REVOKED)?;
        let sessions_invalidated_count =
            u32_in(&mut f, "sessions_invalidated_count", 0, u32::MAX.into())?;
        let revoked_at_ms = f.uint("revoked_at_ms")?;
        f.finish()?;
        Ok(Self {
            tenant_id,
            subject_device_id,
            replay_id,
            signed_container_hash,
            reason_code,
            sessions_invalidated_count,
            revoked_at_ms,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        c::encode(&c::m(vec![
            ("domain", c::t(DOMAIN_DEVICE_REVOKED)),
            ("version", c::u(VERSION)),
            ("tenant_id", c::b(&self.tenant_id)),
            ("subject_device_id", c::b(&self.subject_device_id)),
            ("replay_id", c::b(&self.replay_id)),
            ("signed_container_hash", c::b(&self.signed_container_hash)),
            ("reason_code", c::t(self.reason_code.as_str())),
            ("revoke_outcome", c::t(REVOKE_OUTCOME_REVOKED)),
            (
                "sessions_invalidated_count",
                c::u(self.sessions_invalidated_count.into()),
            ),
            ("revoked_at_ms", c::u(self.revoked_at_ms)),
        ]))
    }
}

// -------------------------------------------------------------- activation ---

/// The ACTIVE generation an activation retires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreviousRoot {
    pub root_key_id: [u8; 32],
    pub root_generation: u64,
}

/// Takes the previous-root pair, present iff the target is not generation 0,
/// and holds it to the rotation rule: the target is previous + 1 under another
/// key.
fn take_previous(f: &mut Fields, target: &RootGenerationTarget) -> Result<Option<PreviousRoot>> {
    let key = f.opt_fixed::<32>("previous_root_key_id")?;
    let generation = f.opt_uint("previous_root_generation")?;
    let previous = match (target.root_generation, key, generation) {
        // ADR 0002 D-4: generation 0 is held by its one self-grant.
        (0, None, None) if target.required_custodian_grant_count == 1 => None,
        (0, None, None) => return Err(RecordError::BadValue("required_custodian_grant_count")),
        (n, Some(root_key_id), Some(root_generation)) if n > 0 => Some(PreviousRoot {
            root_key_id,
            root_generation,
        }),
        _ => return Err(RecordError::BadValue("previous_root_key_id")),
    };
    if let Some(p) = previous {
        if p.root_generation.checked_add(1) != Some(target.root_generation) {
            return Err(RecordError::BadValue("root_generation"));
        }
        if p.root_key_id == target.root_key_id {
            return Err(RecordError::BadValue("previous_root_key_id"));
        }
    }
    Ok(previous)
}

fn put_previous(previous: &Option<PreviousRoot>, out: &mut Vec<(&'static str, Value)>) {
    if let Some(p) = previous {
        out.extend([
            ("previous_root_key_id", c::b(&p.root_key_id)),
            ("previous_root_generation", c::u(p.root_generation)),
        ]);
    }
}

/// Plan 5.6.4 `TenantRootGenerationActivateV2`, the `ROOT_GENERATION_ACTIVATE`
/// payload. It restates the terms the generation was created with, so the
/// activation names exactly what it makes ACTIVE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootGenerationActivateV2 {
    pub target: RootGenerationTarget,
    pub previous: Option<PreviousRoot>,
}

impl TenantRootGenerationActivateV2 {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("TenantRootGenerationActivateV2", payload)?;
        exact_version(&mut f, DOMAIN_ROOT_GENERATION_ACTIVATE)?;
        let target = RootGenerationTarget::take(&mut f)?;
        let previous = take_previous(&mut f, &target)?;
        f.finish()?;
        Ok(Self { target, previous })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![
            ("domain", c::t(DOMAIN_ROOT_GENERATION_ACTIVATE)),
            ("version", c::u(VERSION)),
        ];
        self.target.put(&mut out);
        put_previous(&self.previous, &mut out);
        c::encode(&c::m(out))
    }
}

pub(crate) const GENERATION_STATE_ACTIVE: &str = "ACTIVE";
pub(crate) const GENERATION_STATE_RETIRED: &str = "RETIRED";

/// Plan 5.6.5 `TenantRootGenerationActivatedV2`, the stored activation
/// response. The tenant's active root pointer is the target generation, and
/// `previous_state` is `RETIRED` iff a previous pair exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootGenerationActivatedV2 {
    pub target: RootGenerationTarget,
    pub previous: Option<PreviousRoot>,
    pub activated_at_ms: u64,
}

impl TenantRootGenerationActivatedV2 {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("TenantRootGenerationActivatedV2", payload)?;
        exact_version(&mut f, DOMAIN_ROOT_GENERATION_ACTIVATED)?;
        let target = RootGenerationTarget::take(&mut f)?;
        let previous = take_previous(&mut f, &target)?;
        f.exact_text("target_state", GENERATION_STATE_ACTIVE)?;
        let previous_state = f.take("previous_state");
        let pointer = f.uint("active_root_generation")?;
        let activated_at_ms = f.uint("activated_at_ms")?;
        f.finish()?;
        let retired = Some(Value::Text(GENERATION_STATE_RETIRED.into()));
        if previous_state != previous.map(|_| ()).and(retired) {
            return Err(RecordError::BadValue("previous_state"));
        }
        if pointer != target.root_generation {
            return Err(RecordError::BadValue("active_root_generation"));
        }
        Ok(Self {
            target,
            previous,
            activated_at_ms,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![
            ("domain", c::t(DOMAIN_ROOT_GENERATION_ACTIVATED)),
            ("version", c::u(VERSION)),
        ];
        self.target.put(&mut out);
        put_previous(&self.previous, &mut out);
        out.push(("target_state", c::t(GENERATION_STATE_ACTIVE)));
        if self.previous.is_some() {
            out.push(("previous_state", c::t(GENERATION_STATE_RETIRED)));
        }
        out.extend([
            ("active_root_generation", c::u(self.target.root_generation)),
            ("activated_at_ms", c::u(self.activated_at_ms)),
        ]);
        c::encode(&c::m(out))
    }
}

// ---------------------------------------------------------------- readback ---

/// The lifecycle state of a stored root grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootGrantState {
    PendingAck,
    Acknowledged,
    Revoked,
}

impl RootGrantState {
    pub const ALL: [Self; 3] = [Self::PendingAck, Self::Acknowledged, Self::Revoked];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PendingAck => "PENDING_ACK",
            Self::Acknowledged => "ACKNOWLEDGED",
            Self::Revoked => "REVOKED",
        }
    }
}

/// The lifecycle state of a root generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootGenerationState {
    Preparing,
    Active,
    Retired,
}

impl RootGenerationState {
    pub const ALL: [Self; 3] = [Self::Preparing, Self::Active, Self::Retired];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Preparing => GENERATION_STATE_PREPARING,
            Self::Active => GENERATION_STATE_ACTIVE,
            Self::Retired => GENERATION_STATE_RETIRED,
        }
    }
}

/// Plan 5.6.4 GET readback descriptor: the exact signed grant container, every
/// plan 7.2 column it determines, and the grant and generation states.
///
/// The typed columns are not independent data. `encode` derives them from the
/// verified record, and `parse` verifies the embedded container under the
/// issuer key the caller trusts, rebuilds the descriptor from it and requires
/// the received bytes to be exactly that. A descriptor whose columns disagree
/// with its container, or that adds or drops a column, does not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootGrantDescriptorV2 {
    record: VerifiedRecord,
    grant_state: RootGrantState,
    generation_state: RootGenerationState,
}

/// The container, the payload twice (as columns and as bytes) and a few
/// fixed-size columns.
const MAX_DESCRIPTOR_BYTES: usize = 3 * MAX_RECORD_BYTES + 4096;

impl TenantRootGrantDescriptorV2 {
    /// `None` unless `record` holds a root key grant.
    pub fn new(
        record: VerifiedRecord,
        grant_state: RootGrantState,
        generation_state: RootGenerationState,
    ) -> Option<Self> {
        matches!(record.payload(), Payload::TenantRootKeyGrant(_)).then_some(Self {
            record,
            grant_state,
            generation_state,
        })
    }

    pub fn record(&self) -> &VerifiedRecord {
        &self.record
    }

    pub fn grant_state(&self) -> RootGrantState {
        self.grant_state
    }

    pub fn generation_state(&self) -> RootGenerationState {
        self.generation_state
    }

    pub fn encode(&self) -> Vec<u8> {
        encode_descriptor(
            DOMAIN_ROOT_GRANT_DESCRIPTOR,
            &self.record,
            self.grant_state,
            self.generation_state,
        )
    }

    /// Verifies the embedded container under `issuer_public_key`.
    pub fn parse(exact: &[u8], issuer_public_key: &[u8; 32]) -> Result<Self> {
        let (record, grant_state, generation_state) = parse_descriptor(
            "TenantRootGrantDescriptorV2",
            DOMAIN_ROOT_GRANT_DESCRIPTOR,
            exact,
            issuer_public_key,
        )?;
        let descriptor = Self::new(record, grant_state, generation_state)
            .ok_or(RecordError::BadValue("payload_domain"))?;
        // The remaining fields are checked by rebuilding them from the record.
        if descriptor.encode() != exact {
            return Err(RecordError::BadValue("descriptor"));
        }
        Ok(descriptor)
    }
}

/// Plan L1131 GET readback descriptor of a fleet `DeviceHpkeGrant`: the same
/// closed shape as [`TenantRootGrantDescriptorV2`], under its own domain, with
/// the grant's state and its fleet generation's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetDeviceGrantDescriptorV2 {
    record: VerifiedRecord,
    grant_state: RootGrantState,
    generation_state: RootGenerationState,
}

impl FleetDeviceGrantDescriptorV2 {
    /// `None` unless `record` holds a `DeviceHpkeGrant`.
    pub fn new(
        record: VerifiedRecord,
        grant_state: RootGrantState,
        generation_state: RootGenerationState,
    ) -> Option<Self> {
        matches!(record.payload(), Payload::DeviceHpkeGrant(_)).then_some(Self {
            record,
            grant_state,
            generation_state,
        })
    }

    pub fn record(&self) -> &VerifiedRecord {
        &self.record
    }

    pub fn grant_state(&self) -> RootGrantState {
        self.grant_state
    }

    pub fn generation_state(&self) -> RootGenerationState {
        self.generation_state
    }

    pub fn encode(&self) -> Vec<u8> {
        encode_descriptor(
            DOMAIN_FLEET_DEVICE_GRANT_DESCRIPTOR,
            &self.record,
            self.grant_state,
            self.generation_state,
        )
    }

    /// Verifies the embedded container under `issuer_public_key`.
    pub fn parse(exact: &[u8], issuer_public_key: &[u8; 32]) -> Result<Self> {
        let (record, grant_state, generation_state) = parse_descriptor(
            "FleetDeviceGrantDescriptorV2",
            DOMAIN_FLEET_DEVICE_GRANT_DESCRIPTOR,
            exact,
            issuer_public_key,
        )?;
        let descriptor = Self::new(record, grant_state, generation_state)
            .ok_or(RecordError::BadValue("payload_domain"))?;
        if descriptor.encode() != exact {
            return Err(RecordError::BadValue("descriptor"));
        }
        Ok(descriptor)
    }
}

fn encode_descriptor(
    domain: &str,
    record: &VerifiedRecord,
    grant_state: RootGrantState,
    generation_state: RootGenerationState,
) -> Vec<u8> {
    let r = record.record();
    // Every payload field under its own name, except the two that would
    // clash with the descriptor's: they are the payload domain and version.
    let Ok(Value::Map(payload)) = c::decode(r.canonical_payload_bytes()) else {
        unreachable!("a parsed record's payload is a canonical map")
    };
    let mut out: Vec<(String, Value)> = payload
        .into_iter()
        .map(|(k, v)| match k.as_str() {
            "domain" => ("payload_domain".to_string(), v),
            "version" => ("payload_version".to_string(), v),
            _ => (k, v),
        })
        .collect();
    let (suite, version) = r.signature_suite();
    for (k, v) in [
        ("domain", c::t(domain)),
        ("version", c::u(VERSION)),
        ("container_domain", c::t(CONTAINER_DOMAIN)),
        ("container_version", c::u(CONTAINER_VERSION.into())),
        ("canonical_payload_bytes", c::b(r.canonical_payload_bytes())),
        ("payload_sha256", c::b(r.payload_sha256())),
        ("signature_suite_id", c::u(suite.into())),
        ("signature_version", c::u(version.into())),
        ("issuer_signing_key_id", c::b(r.issuer_signing_key_id())),
        ("signature_bytes", c::b(r.signature_bytes())),
        ("signed_container_hash", c::b(r.signed_container_hash())),
        (
            "exact_signed_container_bytes",
            c::b(r.exact_signed_container_bytes()),
        ),
        (
            "exact_signed_container_bytes_sha256",
            c::b(r.exact_signed_container_bytes_sha256()),
        ),
        ("grant_state", c::t(grant_state.as_str())),
        ("generation_state", c::t(generation_state.as_str())),
    ] {
        out.push((k.to_string(), v));
    }
    c::encode(&Value::Map(out))
}

/// The verified container and the two states of a descriptor; the caller
/// rebuilds the descriptor and requires it to equal `exact`.
fn parse_descriptor(
    map: &'static str,
    domain: &str,
    exact: &[u8],
    issuer_public_key: &[u8; 32],
) -> Result<(VerifiedRecord, RootGrantState, RootGenerationState)> {
    if exact.len() > MAX_DESCRIPTOR_BYTES {
        return Err(RecordError::BadValue("descriptor"));
    }
    let mut f = Fields::decode(map, exact)?;
    exact_version(&mut f, domain)?;
    let container = f.bytes("exact_signed_container_bytes", 1, MAX_RECORD_BYTES)?;
    let grant_state = f.text("grant_state")?;
    let grant_state = RootGrantState::ALL
        .into_iter()
        .find(|s| s.as_str() == grant_state)
        .ok_or(RecordError::BadValue("grant_state"))?;
    let generation_state = f.text("generation_state")?;
    let generation_state = RootGenerationState::ALL
        .into_iter()
        .find(|s| s.as_str() == generation_state)
        .ok_or(RecordError::BadValue("generation_state"))?;
    let parsed = AuthorizationRecord::parse(&container)?;
    let record = parsed.verify_signature(issuer_public_key)?;
    Ok((record, grant_state, generation_state))
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn target(root_generation: u64) -> RootGenerationTarget {
        RootGenerationTarget {
            tenant_id: fx("tenant"),
            server_instance_id: fx("instance"),
            restore_epoch: 3,
            root_key_id: fx("root-key-1"),
            root_generation,
            required_custodian_grant_count: 1,
            required_custodian_grant_set_hash: fx("grant-set"),
            recovery_bundle_sha256: fx("recovery"),
        }
    }

    /// Generation 0, whose custodian set is the fixture self-grant (D-4).
    fn boot_target() -> RootGenerationTarget {
        RootGenerationTarget {
            required_custodian_grant_set_hash: root_custodian_grant_set_hash(&[fx(
                "container-hash",
            )])
            .unwrap(),
            ..target(0)
        }
    }

    fn bootstrap() -> TenantRootGenerationCreateV2 {
        TenantRootGenerationCreateV2 {
            target: boot_target(),
            mode: RootGenerationMode::Bootstrap(EmbeddedSelfGrant {
                container_bytes: b"signed self-grant container".to_vec(),
                signed_container_hash: fx("container-hash"),
            }),
        }
    }

    fn rotation() -> TenantRootGenerationCreateV2 {
        TenantRootGenerationCreateV2 {
            target: target(5),
            mode: RootGenerationMode::Rotation {
                previous_root_key_id: fx("root-key-0"),
                previous_root_generation: 4,
            },
        }
    }

    fn created() -> TenantRootGenerationCreatedV2 {
        TenantRootGenerationCreatedV2 {
            target: boot_target(),
            mode: RootGenerationMode::Bootstrap(SelfGrantIdentity {
                replay_id: fx("self-grant-replay"),
                signed_container_hash: fx("container-hash"),
                container_bytes_sha256: c::sha256(b"signed self-grant container"),
            }),
            created_at_ms: 1_700_000_000_000,
        }
    }

    fn request() -> IdempotentMutationRequestV2 {
        IdempotentMutationRequestV2 {
            operation_kind: OperationKind::RootGenerationCreate,
            idempotency_key: fx("idem"),
            canonical_payload_bytes: bootstrap().encode(),
            client_request_nonce: fx("nonce"),
            server_instance_id: fx("instance"),
            restore_epoch: 3,
        }
    }

    fn rotated() -> TenantRootGenerationCreatedV2 {
        TenantRootGenerationCreatedV2 {
            target: target(5),
            mode: RootGenerationMode::Rotation {
                previous_root_key_id: fx("root-key-0"),
                previous_root_generation: 4,
            },
            created_at_ms: 9,
        }
    }

    /// Each map's exact bytes and a parse that drops the value.
    type Reencode = fn(&[u8]) -> Result<Vec<u8>>;

    fn maps() -> Vec<(&'static str, Vec<u8>, Reencode)> {
        vec![
            ("request", request().encode(), |b| {
                IdempotentMutationRequestV2::parse(b).map(|m| m.encode())
            }),
            ("response", response().encode(), |b| {
                IdempotentStoredResponseV2::parse(b).map(|m| m.encode())
            }),
            ("bootstrap", bootstrap().encode(), |b| {
                TenantRootGenerationCreateV2::parse(b).map(|m| m.encode())
            }),
            ("rotation", rotation().encode(), |b| {
                TenantRootGenerationCreateV2::parse(b).map(|m| m.encode())
            }),
            ("created", created().encode(), |b| {
                TenantRootGenerationCreatedV2::parse(b).map(|m| m.encode())
            }),
            ("rotated", rotated().encode(), |b| {
                TenantRootGenerationCreatedV2::parse(b).map(|m| m.encode())
            }),
        ]
    }

    fn response() -> IdempotentStoredResponseV2 {
        IdempotentStoredResponseV2 {
            operation_kind: OperationKind::RootGenerationCreate,
            idempotency_key: fx("idem"),
            exact_request_hash: request().canonical_request_hash(),
            response_record_type: RECORD_TYPE_ROOT_GENERATION_CREATED.into(),
            canonical_response_payload_bytes: created().encode(),
            server_instance_id: fx("instance"),
            restore_epoch: 3,
            committed_at_ms: 1_700_000_000_001,
            receipt_id: fx("receipt"),
        }
    }

    #[test]
    fn every_map_roundtrips_byte_for_byte() {
        let raw = request().encode();
        assert_eq!(IdempotentMutationRequestV2::parse(&raw).unwrap(), request());
        assert_eq!(
            IdempotentMutationRequestV2::parse(&raw).unwrap().encode(),
            raw
        );
        let raw = response().encode();
        assert_eq!(IdempotentStoredResponseV2::parse(&raw).unwrap(), response());
        for g in [bootstrap(), rotation()] {
            assert_eq!(TenantRootGenerationCreateV2::parse(&g.encode()).unwrap(), g);
        }
        for g in [created(), rotated()] {
            assert_eq!(
                TenantRootGenerationCreatedV2::parse(&g.encode()).unwrap(),
                g
            );
        }
        for (name, raw, reencode) in maps() {
            assert_eq!(reencode(&raw).unwrap(), raw, "{name}");
        }
    }

    #[test]
    fn every_map_refuses_another_domain_or_version() {
        for (name, raw, reencode) in maps() {
            for domain in ["shardx.sync.other.v2", "shardx.auth.device-approval.v2"] {
                assert_eq!(
                    reencode(&edit(&raw, |e| set(e, "domain", c::t(domain)))),
                    Err(RecordError::BadValue("domain")),
                    "{name} {domain}"
                );
            }
            for version in [1, 3] {
                assert_eq!(
                    reencode(&edit(&raw, |e| set(e, "version", c::u(version)))),
                    Err(RecordError::BadValue("version")),
                    "{name} {version}"
                );
            }
        }
        // One map's bytes never parse as another's.
        assert!(TenantRootGenerationCreatedV2::parse(&bootstrap().encode()).is_err());
        assert!(TenantRootGenerationCreateV2::parse(&created().encode()).is_err());
    }

    /// Plan L913 and 5.6.4 name the root kinds and scopes, ADR 0002 D-9 the
    /// fleet and device ones. The plan names no scope for the six profile
    /// kinds; these are the names this module files them under.
    #[test]
    fn the_kind_and_scope_table_is_exact() {
        let table = [
            ("PROFILE_PUBLISH_CREATE", "profile.publish-create.v2"),
            ("PROFILE_CHECKOUT", "profile.checkout.v2"),
            ("CREATE_UPLOAD", "profile.create-upload.v2"),
            ("FINALIZE_UPLOAD", "profile.finalize-upload.v2"),
            ("RELEASE_LEASE", "profile.release-lease.v2"),
            ("LOCAL_UNBIND", "local.profile.unbind.v2"),
            ("ROOT_GENERATION_CREATE", "tenant.root-generation-create.v2"),
            ("ROOT_GRANT_CREATE", "tenant.root-grant-create.v2"),
            ("ROOT_GRANT_ACK", "tenant.root-grant-ack.v2"),
            (
                "ROOT_GENERATION_ACTIVATE",
                "tenant.root-generation-activate.v2",
            ),
            ("ROOT_GRANT_REVOKE", "tenant.root-grant-revoke.v2"),
            ("FLEET_GENERATION_CREATE", "fleet.key-generation-create.v2"),
            ("FLEET_GRANT_CREATE", "fleet.key-grant-create.v2"),
            ("FLEET_GRANT_ACK", "fleet.key-grant-ack.v2"),
            (
                "FLEET_GENERATION_ACTIVATE",
                "fleet.key-generation-activate.v2",
            ),
            ("FLEET_GRANT_REVOKE", "fleet.key-grant-revoke.v2"),
            ("DEVICE_REVOKE", "device.revoke.v2"),
        ];
        let actual: Vec<_> = OperationKind::ALL
            .iter()
            .map(|k| (k.as_str(), k.scope()))
            .collect();
        assert_eq!(actual, table);
    }

    #[test]
    fn a_bootstrap_custodian_set_is_its_self_grant_alone() {
        let mut g = bootstrap();
        g.target.required_custodian_grant_count = 2;
        assert_eq!(
            TenantRootGenerationCreateV2::parse(&g.encode()),
            Err(RecordError::BadValue("required_custodian_grant_count"))
        );
        let mut g = bootstrap();
        g.target.required_custodian_grant_set_hash = fx("grant-set");
        assert_eq!(
            TenantRootGenerationCreateV2::parse(&g.encode()),
            Err(RecordError::BadValue("required_custodian_grant_set_hash"))
        );
        let mut g = created();
        g.target.required_custodian_grant_count = 2;
        assert_eq!(
            TenantRootGenerationCreatedV2::parse(&g.encode()),
            Err(RecordError::BadValue("required_custodian_grant_count"))
        );
        let mut g = created();
        g.target.required_custodian_grant_set_hash = fx("grant-set");
        assert_eq!(
            TenantRootGenerationCreatedV2::parse(&g.encode()),
            Err(RecordError::BadValue("required_custodian_grant_set_hash"))
        );
        // A rotation names its custodians elsewhere; any set parses here.
        let mut g = rotation();
        g.target.required_custodian_grant_count = 3;
        assert!(TenantRootGenerationCreateV2::parse(&g.encode()).is_ok());
    }

    /// Pins the hash constructions and the field sets.
    #[test]
    fn golden_vectors() {
        assert_eq!(
            hex(&request().canonical_request_hash()),
            "0e1a42ce3b2eae6840e90894e351e9da5608d23da626174261de2c259ed270a6"
        );
        assert_eq!(
            hex(&response().stored_response_hash()),
            "decc4d687516199a5b88213a10c197e4ba744b485307b24ebf29cf9276b78a49"
        );
        assert_eq!(
            hex(&c::sha256(&rotation().encode())),
            "4a42f0a7092b8125f81e1be6f60648035ce210b4e3a9e0083f92045e9c14f8df"
        );
        // The request hash is the length-prefixed domain hash of the core.
        let core = edit(&request().encode(), |e| {
            drop_key(e, "canonical_request_hash")
        });
        let mut pre = L_REQUEST_HASH.as_bytes().to_vec();
        pre.extend((core.len() as u32).to_be_bytes());
        pre.extend(&core);
        assert_eq!(c::sha256(&pre), request().canonical_request_hash());
    }

    #[test]
    fn the_custodian_set_hash_is_order_free_and_refuses_bad_sets() {
        let (a, b) = (fx::<32>("grant-a"), fx::<32>("grant-b"));
        let (lo, hi) = if a < b { (a, b) } else { (b, a) };
        let mut pre = L_ROOT_CUSTODIAN_SET.as_bytes().to_vec();
        pre.extend(64u32.to_be_bytes());
        pre.extend(lo);
        pre.extend(hi);
        assert_eq!(
            root_custodian_grant_set_hash(&[a, b]),
            Some(c::sha256(&pre))
        );
        assert_eq!(
            root_custodian_grant_set_hash(&[b, a]),
            root_custodian_grant_set_hash(&[a, b])
        );
        assert_eq!(root_custodian_grant_set_hash(&[]), None);
        assert_eq!(root_custodian_grant_set_hash(&[a, a]), None);
    }

    /// D-4 vectors n = 1, 2, 3, and the label keeps the two sets apart.
    #[test]
    fn the_fleet_device_set_hash_has_its_own_label() {
        let m: Vec<[u8; 32]> = ["grant-a", "grant-b", "grant-c"].map(fx).to_vec();
        for n in 1..=3 {
            let mut sorted = m[..n].to_vec();
            sorted.sort_unstable();
            let mut pre = L_FLEET_DEVICE_SET.as_bytes().to_vec();
            pre.extend((32 * n as u32).to_be_bytes());
            pre.extend(sorted.concat());
            let mut reversed = m[..n].to_vec();
            reversed.reverse();
            assert_eq!(
                fleet_device_grant_set_hash(&reversed),
                Some(c::sha256(&pre))
            );
            assert_ne!(
                fleet_device_grant_set_hash(&m[..n]),
                root_custodian_grant_set_hash(&m[..n])
            );
        }
        assert_eq!(fleet_device_grant_set_hash(&[]), None);
        assert_eq!(fleet_device_grant_set_hash(&[m[0], m[1], m[0]]), None);
    }

    #[test]
    fn every_kind_has_one_scope_and_the_scope_must_match() {
        let mut scopes: Vec<_> = OperationKind::ALL.iter().map(|k| k.scope()).collect();
        scopes.sort();
        scopes.dedup();
        assert_eq!(scopes.len(), OperationKind::ALL.len());
        for k in OperationKind::ALL {
            assert_eq!(OperationKind::parse(k.as_str()), Some(k));
        }

        let raw = request().encode();
        let reparse = |e: Vec<u8>| IdempotentMutationRequestV2::parse(&e);
        // The other root kind's scope, with the request hash recomputed so only
        // the scope is wrong.
        let wrong_scope = edit(&raw, |e| {
            set(e, "operation_scope", c::t("tenant.root-grant-create.v2"))
        });
        assert_eq!(
            reparse(wrong_scope),
            Err(RecordError::BadValue("operation_scope"))
        );
        for kind in ["COMMIT", "DEVICE_APPROVE", "root_generation_create"] {
            assert_eq!(
                reparse(edit(&raw, |e| set(e, "operation_kind", c::t(kind)))),
                Err(RecordError::BadValue("operation_kind")),
                "{kind}"
            );
        }
    }

    #[test]
    fn hashes_and_closed_fields_are_checked() {
        let raw = request().encode();
        let req = |f: Editor| IdempotentMutationRequestV2::parse(&edit(&raw, |e| f(e)));
        assert_eq!(
            req(&|e| set(e, "payload_sha256", c::b(&[0u8; 32]))),
            Err(RecordError::PayloadHashMismatch)
        );
        assert_eq!(
            req(&|e| set(e, "restore_epoch", c::u(4))),
            Err(RecordError::BadValue("canonical_request_hash"))
        );
        assert_eq!(
            req(&|e| set(e, "version", c::u(3))),
            Err(RecordError::BadValue("version"))
        );
        assert!(matches!(
            req(&|e| set(e, "extra", c::u(1))),
            Err(RecordError::UnknownField { .. })
        ));
        for len in [0, 262145] {
            assert!(matches!(
                req(&|e| set(e, "canonical_payload_bytes", c::b(&vec![1; len]))),
                Err(RecordError::BadField {
                    field: "canonical_payload_bytes",
                    ..
                })
            ));
        }

        let raw = response().encode();
        let resp = |f: Editor| IdempotentStoredResponseV2::parse(&edit(&raw, |e| f(e)));
        assert_eq!(
            resp(&|e| set(e, "response_payload_sha256", c::b(&[0u8; 32]))),
            Err(RecordError::PayloadHashMismatch)
        );
        assert_eq!(
            resp(&|e| set(e, "committed_at_ms", c::u(1))),
            Err(RecordError::BadValue("stored_response_hash"))
        );
        assert_eq!(
            resp(&|e| set(e, "outcome", c::t("failed"))),
            Err(RecordError::BadValue("outcome"))
        );
        for len in [0, 129] {
            assert!(matches!(
                resp(&|e| set(e, "response_record_type", c::t(&"T".repeat(len)))),
                Err(RecordError::BadField {
                    field: "response_record_type",
                    ..
                }),
            ));
        }
        for len in [0, 262145] {
            assert!(matches!(
                resp(&|e| set(e, "canonical_response_payload_bytes", c::b(&vec![1; len]))),
                Err(RecordError::BadField {
                    field: "canonical_response_payload_bytes",
                    ..
                })
            ));
        }
    }

    #[test]
    fn root_generation_modes_carry_exactly_their_fields() {
        let parse =
            |g: &TenantRootGenerationCreateV2| TenantRootGenerationCreateV2::parse(&g.encode());
        let mut g = bootstrap();
        g.target.root_generation = 1;
        assert_eq!(parse(&g), Err(RecordError::BadValue("root_generation")));
        for gen in [4, 6] {
            let mut g = rotation();
            g.target.root_generation = gen;
            assert_eq!(parse(&g), Err(RecordError::BadValue("root_generation")));
        }
        let mut g = rotation();
        g.target.root_key_id = fx("root-key-0");
        assert_eq!(
            parse(&g),
            Err(RecordError::BadValue("previous_root_key_id"))
        );
        for count in [0, 65536] {
            let mut g = bootstrap();
            g.target.required_custodian_grant_count = count;
            assert!(matches!(
                parse(&g),
                Err(RecordError::BadField {
                    field: "required_custodian_grant_count",
                    ..
                })
            ));
        }

        let boot = bootstrap().encode();
        let rot = rotation().encode();
        let p = TenantRootGenerationCreateV2::parse;
        assert_eq!(
            p(&edit(&boot, |e| set(
                e,
                "first_self_grant_container_bytes_sha256",
                c::b(&[0; 32])
            ))),
            Err(RecordError::BadValue(
                "first_self_grant_container_bytes_sha256"
            ))
        );
        for key in [
            "first_self_grant_container_bytes",
            "first_self_grant_signed_container_hash",
            "first_self_grant_container_bytes_sha256",
        ] {
            assert_eq!(
                p(&edit(&boot, |e| drop_key(e, key))),
                Err(RecordError::BadValue("first_self_grant_container_bytes")),
                "{key}"
            );
            assert_eq!(
                p(&edit(&rot, |e| set(e, key, c::b(&[1; 32])))),
                Err(RecordError::BadValue("first_self_grant_container_bytes")),
                "{key}"
            );
        }
        // The previous-root pair is present iff rotation, both halves.
        for (raw, edited) in [
            (
                &rot,
                edit(&rot, |e| drop_key(e, "previous_root_generation")),
            ),
            (&rot, edit(&rot, |e| drop_key(e, "previous_root_key_id"))),
            (
                &boot,
                edit(&boot, |e| set(e, "previous_root_generation", c::u(0))),
            ),
            (
                &boot,
                edit(&boot, |e| set(e, "previous_root_key_id", c::b(&[9; 32]))),
            ),
        ] {
            assert_ne!(raw, &edited);
            assert_eq!(
                p(&edited),
                Err(RecordError::BadValue("previous_root_key_id"))
            );
        }
        assert_eq!(
            p(&edit(&boot, |e| set(e, "mode", c::t("restore")))),
            Err(RecordError::BadValue("mode"))
        );
        for len in [0, 131073] {
            assert!(matches!(
                p(&edit(&boot, |e| set(
                    e,
                    "first_self_grant_container_bytes",
                    c::b(&vec![1; len])
                ))),
                Err(RecordError::BadField {
                    field: "first_self_grant_container_bytes",
                    ..
                })
            ));
        }

        let made = created().encode();
        let q = TenantRootGenerationCreatedV2::parse;
        assert_eq!(
            q(&edit(&made, |e| set(e, "generation_state", c::t("ACTIVE")))),
            Err(RecordError::BadValue("generation_state"))
        );
        // The self-grant identity is present iff bootstrap, every field.
        let rot = rotated().encode();
        for key in [
            "first_self_grant_replay_id",
            "first_self_grant_signed_container_hash",
            "first_self_grant_container_bytes_sha256",
        ] {
            assert_eq!(
                q(&edit(&made, |e| drop_key(e, key))),
                Err(RecordError::BadValue("first_self_grant_replay_id")),
                "{key}"
            );
            let len = if key == "first_self_grant_replay_id" {
                16
            } else {
                32
            };
            assert_eq!(
                q(&edit(&rot, |e| set(e, key, c::b(&vec![1; len])))),
                Err(RecordError::BadValue("first_self_grant_replay_id")),
                "{key}"
            );
        }
    }

    // ------------------------------------------------- lifecycle maps ---

    use crate::authz_record::{
        build_record, ApprovalScopeKind, CommonFields, DeviceApprovalV2, DeviceHpkeGrantV2,
        RootGrantVariant, TenantRootKeyGrantV2, DOMAIN_DEVICE_APPROVAL,
        DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE, DOMAIN_TENANT_ROOT_KEY_GRANT,
    };
    use ed25519_dalek::SigningKey;

    fn grant_ref() -> RootGrantRef {
        RootGrantRef {
            tenant_id: fx("tenant"),
            server_instance_id: fx("instance"),
            restore_epoch: 3,
            root_generation: 0,
            root_key_id: fx("root-key-1"),
            replay_id: fx("self-grant-replay"),
            signed_container_hash: fx("container-hash"),
            exact_signed_container_bytes_sha256: fx("container-sha"),
        }
    }

    fn ack() -> TenantRootGrantAckV2 {
        TenantRootGrantAckV2 { grant: grant_ref() }
    }

    fn acked() -> TenantRootGrantAckedV2 {
        TenantRootGrantAckedV2 {
            grant: grant_ref(),
            acked_at_ms: 1_700_000_000_002,
        }
    }

    fn grant_create() -> TenantRootGrantCreateV2 {
        let bytes = b"an exact signed grant container".to_vec();
        TenantRootGrantCreateV2 {
            grant: RootGrantRef {
                exact_signed_container_bytes_sha256: c::sha256(&bytes),
                ..grant_ref()
            },
            exact_signed_grant_container_bytes: bytes,
        }
    }

    fn grant_created() -> TenantRootGrantCreatedV2 {
        TenantRootGrantCreatedV2 {
            grant: grant_ref(),
            grant_variant: "ExistingRootGrant",
            subject_device_id: fx("subject-device"),
            recipient_hpke_key_id: fx("recipient-hpke"),
            created_at_ms: 1_700_000_000_004,
        }
    }

    fn revoke() -> TenantRootGrantRevokeV2 {
        TenantRootGrantRevokeV2 {
            grant: grant_ref(),
            reason_code: RootGrantRevokeReason::CustodyRemoved,
        }
    }

    fn revoked() -> TenantRootGrantRevokedV2 {
        TenantRootGrantRevokedV2 {
            grant: grant_ref(),
            reason_code: RootGrantRevokeReason::DeviceLost,
            sessions_invalidated_count: 2,
            revoked_at_ms: 1_700_000_000_003,
        }
    }

    fn activate(root_generation: u64) -> TenantRootGenerationActivateV2 {
        TenantRootGenerationActivateV2 {
            target: target(root_generation),
            previous: (root_generation > 0).then(|| PreviousRoot {
                root_key_id: fx("root-key-0"),
                root_generation: root_generation - 1,
            }),
        }
    }

    fn activated(root_generation: u64) -> TenantRootGenerationActivatedV2 {
        let a = activate(root_generation);
        TenantRootGenerationActivatedV2 {
            target: a.target,
            previous: a.previous,
            activated_at_ms: 1_700_000_000_003,
        }
    }

    fn custodian() -> SigningKey {
        SigningKey::from_bytes(&fx::<32>("custodian-signing-key"))
    }

    fn common() -> CommonFields {
        CommonFields {
            replay_id: fx("self-grant-replay"),
            tenant_id: fx("tenant"),
            issued_at_ms: 1_700_000_000_000,
            not_before_ms: 1_700_000_000_000,
            not_after_ms: 1_700_086_400_000,
            server_instance_id: fx("instance"),
            restore_epoch: 3,
        }
    }

    fn root_record(variant: RootGrantVariant, root_generation: u64) -> Vec<u8> {
        let sk = custodian();
        let g = TenantRootKeyGrantV2 {
            common: common(),
            variant,
            root_key_id: fx("root-key-1"),
            root_generation,
            subject_account_id: fx("account"),
            subject_device_id: fx("device"),
            subject_signing_key_id: crate::keys::signing_key_id(sk.verifying_key().as_bytes()),
            recipient_hpke_key_id: fx("device-hpke"),
            subject_device_approval_replay_id: fx("approval"),
            hpke_encapped_key_bytes: fx("encapped"),
            hpke_wrapped_trk_bytes: fx("wrapped"),
        };
        build_record(&sk, DOMAIN_TENANT_ROOT_KEY_GRANT, &g.encode())
    }

    fn descriptor(container: &[u8]) -> TenantRootGrantDescriptorV2 {
        let record = AuthorizationRecord::parse(container)
            .unwrap()
            .verify_signature(custodian().verifying_key().as_bytes())
            .unwrap();
        TenantRootGrantDescriptorV2::new(
            record,
            RootGrantState::PendingAck,
            RootGenerationState::Preparing,
        )
        .unwrap()
    }

    #[test]
    fn lifecycle_maps_roundtrip_byte_for_byte() {
        type Reparse = fn(&[u8]) -> Result<Vec<u8>>;
        let maps: Vec<(&str, Vec<u8>, Reparse)> = vec![
            ("ack", ack().encode(), |b| {
                TenantRootGrantAckV2::parse(b).map(|m| m.encode())
            }),
            ("acked", acked().encode(), |b| {
                TenantRootGrantAckedV2::parse(b).map(|m| m.encode())
            }),
            ("activate 0", activate(0).encode(), |b| {
                TenantRootGenerationActivateV2::parse(b).map(|m| m.encode())
            }),
            ("activate 5", activate(5).encode(), |b| {
                TenantRootGenerationActivateV2::parse(b).map(|m| m.encode())
            }),
            ("activated 0", activated(0).encode(), |b| {
                TenantRootGenerationActivatedV2::parse(b).map(|m| m.encode())
            }),
            ("activated 5", activated(5).encode(), |b| {
                TenantRootGenerationActivatedV2::parse(b).map(|m| m.encode())
            }),
            ("create", grant_create().encode(), |b| {
                TenantRootGrantCreateV2::parse(b).map(|m| m.encode())
            }),
            ("created", grant_created().encode(), |b| {
                TenantRootGrantCreatedV2::parse(b).map(|m| m.encode())
            }),
            ("revoke", revoke().encode(), |b| {
                TenantRootGrantRevokeV2::parse(b).map(|m| m.encode())
            }),
            ("revoked", revoked().encode(), |b| {
                TenantRootGrantRevokedV2::parse(b).map(|m| m.encode())
            }),
        ];
        for (name, raw, reparse) in &maps {
            assert_eq!(reparse(raw).as_ref(), Ok(raw), "{name}");
            for domain in ["shardx.keys.other.v2", DOMAIN_ROOT_GENERATION_CREATE] {
                assert_eq!(
                    reparse(&edit(raw, |e| set(e, "domain", c::t(domain)))),
                    Err(RecordError::BadValue("domain")),
                    "{name} {domain}"
                );
            }
            for version in [1, 3] {
                assert_eq!(
                    reparse(&edit(raw, |e| set(e, "version", c::u(version)))),
                    Err(RecordError::BadValue("version")),
                    "{name} {version}"
                );
            }
            assert!(matches!(
                reparse(&edit(raw, |e| set(e, "extra", c::u(1)))),
                Err(RecordError::UnknownField { .. })
            ));
            assert!(matches!(
                reparse(&edit(raw, |e| drop_key(e, "restore_epoch"))),
                Err(RecordError::MissingField { .. })
            ));
        }
        assert_eq!(TenantRootGrantAckV2::parse(&ack().encode()), Ok(ack()));
        assert_eq!(
            TenantRootGenerationActivatedV2::parse(&activated(5).encode()),
            Ok(activated(5))
        );
        let pinned: Vec<(&str, String)> = maps
            .iter()
            .map(|(name, raw, _)| (*name, hex(&c::sha256(raw))))
            .collect();
        assert_eq!(pinned, GOLDEN_LIFECYCLE.map(|(n, h)| (n, h.to_string())));
    }

    /// Q-13: the revoke request carries exactly one parseable container under
    /// its own hash and sorted, unique activations; the response roundtrips.
    #[test]
    fn device_revoke_maps_carry_one_container_and_roundtrip() {
        use crate::authz_record::{
            build_record, CommonFields, DeviceRevocationV2, DOMAIN_DEVICE_REVOCATION,
        };
        let sk = crate::signing::Ed25519SigningKey::from_bytes(&[9; 32]);
        let revocation = DeviceRevocationV2 {
            common: CommonFields {
                replay_id: [1; 16],
                tenant_id: [2; 16],
                issued_at_ms: 1_700_000_000_000,
                not_before_ms: 1_700_000_000_000,
                not_after_ms: 1_700_086_400_000,
                server_instance_id: [3; 16],
                restore_epoch: 0,
            },
            subject_account_id: [4; 16],
            subject_device_id: [5; 16],
            subject_signing_key_id: [6; 32],
            subject_hpke_key_id: [7; 32],
            reason_code: DeviceRevocationReason::Lost,
        };
        let container = build_record(&sk, DOMAIN_DEVICE_REVOCATION, &revocation.encode());
        let request = DeviceRevokeRequestV2 {
            signed_container_hash: *AuthorizationRecord::parse(&container)
                .unwrap()
                .signed_container_hash(),
            exact_signed_revocation_container_bytes: container.clone(),
            activations: Vec::new(),
        };
        let raw = request.encode();
        assert_eq!(DeviceRevokeRequestV2::parse(&raw), Ok(request.clone()));

        // C-1: the optional activations, each the exact standalone request
        // payload, sorted by (kind, fleet_id, generation) with root first.
        let fleet = |fleet_id: u8| {
            use crate::fleet_lifecycle::{FleetGenerationRef, FleetGenerationTerms};
            FleetKeyGenerationActivateV2 {
                terms: FleetGenerationTerms {
                    generation: FleetGenerationRef {
                        tenant_id: [2; 16],
                        server_instance_id: [3; 16],
                        restore_epoch: 0,
                        fleet_id: [fleet_id; 16],
                        generation: 0,
                        fkek_key_id: [fleet_id; 32],
                    },
                    required_device_grant_count: 1,
                    required_device_grant_set_hash: [8; 32],
                    recovery_grant_signed_container_hash: [9; 32],
                    rotation: None,
                },
            }
        };
        let items = |list: &[&[u8]]| {
            edit(&raw, |e| {
                set(
                    e,
                    "activations",
                    Value::Array(list.iter().map(|b| c::b(b)).collect()),
                )
            })
        };
        let (root, f1, f2) = (activate(1).encode(), fleet(1).encode(), fleet(2).encode());
        let with = items(&[&root, &f1, &f2]);
        let parsed = DeviceRevokeRequestV2::parse(&with).unwrap();
        assert_eq!(
            parsed.activations,
            vec![
                GenerationActivation::Root(activate(1)),
                GenerationActivation::Fleet(fleet(1)),
                GenerationActivation::Fleet(fleet(2)),
            ]
        );
        assert_eq!(parsed.encode(), with);
        let unknown = activated(1).encode();
        let broken = edit(&f1, |e| drop_key(e, "generation"));
        for list in [
            vec![&f2[..], &f1[..]],
            vec![&f1[..], &f1[..]],
            vec![&f1[..], &root[..]],
            vec![&unknown[..]],
        ] {
            assert_eq!(
                DeviceRevokeRequestV2::parse(&items(&list)),
                Err(RecordError::BadValue("activations"))
            );
        }
        assert!(DeviceRevokeRequestV2::parse(&items(&[&broken])).is_err());

        // At most 65535 activations: the limit itself parses, one more does not.
        let many = |n: u32| {
            let list: Vec<Vec<u8>> = (1..=n)
                .map(|i| {
                    let mut a = fleet(1);
                    a.terms.generation.fleet_id[..4].copy_from_slice(&i.to_be_bytes());
                    a.encode()
                })
                .collect();
            items(&list.iter().map(Vec::as_slice).collect::<Vec<_>>())
        };
        assert_eq!(
            DeviceRevokeRequestV2::parse(&many(65535)).map(|r| r.activations.len()),
            Ok(65535)
        );
        assert_eq!(
            DeviceRevokeRequestV2::parse(&many(65536)),
            Err(RecordError::BadValue("activations"))
        );

        for (field, value, err) in [
            (
                "signed_container_hash",
                c::b(&[0; 32]),
                "signed_container_hash",
            ),
            ("activations", Value::Array(vec![c::b(&[1])]), "activations"),
            ("activations", c::u(0), "activations"),
        ] {
            assert_eq!(
                DeviceRevokeRequestV2::parse(&edit(&raw, |e| set(e, field, value))),
                Err(RecordError::BadValue(err)),
                "{field}"
            );
        }
        let garbage = edit(&raw, |e| {
            set(
                e,
                "exact_signed_revocation_container_bytes",
                c::b(b"not a container"),
            )
        });
        assert!(DeviceRevokeRequestV2::parse(&garbage).is_err());

        let revoked = DeviceRevokedV2 {
            tenant_id: [2; 16],
            subject_device_id: [5; 16],
            replay_id: [1; 16],
            signed_container_hash: request.signed_container_hash,
            reason_code: DeviceRevocationReason::Compromised,
            sessions_invalidated_count: 2,
            revoked_at_ms: 1_700_000_000_123,
        };
        let raw_revoked = revoked.encode();
        assert_eq!(DeviceRevokedV2::parse(&raw_revoked), Ok(revoked));
        for (field, value) in [
            ("revoke_outcome", c::t("kept")),
            ("reason_code", c::t("stolen")),
            ("domain", c::t(DOMAIN_DEVICE_REVOKE)),
        ] {
            assert!(
                DeviceRevokedV2::parse(&edit(&raw_revoked, |e| set(e, field, value))).is_err(),
                "{field}"
            );
        }
        assert_eq!(
            [hex(&c::sha256(&raw)), hex(&c::sha256(&raw_revoked))],
            [
                "bbef370b40bd98ec9223503326328f74596a027557b0e63fa26a436eb4eba741",
                "9b5dda131cc3ba8ca8ea9049751472762c7bed7672ef57c48f761cc03c4ed312"
            ]
        );
    }

    const GOLDEN_LIFECYCLE: [(&str, &str); 10] = [
        (
            "ack",
            "148a758a45a53e4f3abfac172ade4d2b3327596ec3b090c50bd7a9b38a018e2a",
        ),
        (
            "acked",
            "d53eed89d922de2f3135f250b40c274efbf0f1214ccc0d0865ad286eaaa58e80",
        ),
        (
            "activate 0",
            "426ad32a4c79fc8175e1b03601504383c5700b9e2be839bbf1c68cd82f7390e7",
        ),
        (
            "activate 5",
            "f294bc81d4d0e3513d1d44096eacb9f69e037e1d6b61adfb4cbec1a98951e5a8",
        ),
        (
            "activated 0",
            "c2182c07a36a7ee98adc7f6ed7103ef68e181bf1264164475992fd300e5347da",
        ),
        (
            "activated 5",
            "6adc9ba8a9030fd6a6bd92e9b8723e8f60bf3021edf5fcc0fa1db2acd7354b17",
        ),
        (
            "create",
            "852926543d82a0a6166aedfa8f2b5f27817aac2aac4363f6489a2ff49084f734",
        ),
        (
            "created",
            "aeba1738442af89e9a864a87fd8a32aa3a11b293a9379001e560e8e7ca7d66cc",
        ),
        (
            "revoke",
            "1b119552d925bfabab02a362c61eab388bffa485fed2959cc04684c10db54b35",
        ),
        (
            "revoked",
            "174b89bac21fe64eec43051f56372b5cbaeb27c30952c36717a36352ad812f92",
        ),
    ];

    #[test]
    fn lifecycle_names_are_the_plan_strings() {
        assert_eq!(
            RootGrantState::ALL.map(RootGrantState::as_str),
            ["PENDING_ACK", "ACKNOWLEDGED", "REVOKED"]
        );
        assert_eq!(
            RootGenerationState::ALL.map(RootGenerationState::as_str),
            ["PREPARING", "ACTIVE", "RETIRED"]
        );
        assert_eq!(
            [
                DOMAIN_ROOT_GRANT_ACK,
                DOMAIN_ROOT_GRANT_ACKED,
                DOMAIN_ROOT_GENERATION_ACTIVATE,
                DOMAIN_ROOT_GENERATION_ACTIVATED,
                DOMAIN_ROOT_GRANT_DESCRIPTOR,
                DOMAIN_ROOT_GRANT_REVOKE,
                DOMAIN_ROOT_GRANT_REVOKED,
                DOMAIN_ROOT_GRANT_CREATE,
                DOMAIN_ROOT_GRANT_CREATED,
            ],
            [
                "shardx.keys.tenant-root-grant-ack.v2",
                "shardx.keys.tenant-root-grant-acked.v2",
                "shardx.keys.tenant-root-generation-activate.v2",
                "shardx.keys.tenant-root-generation-activated.v2",
                "shardx.keys.tenant-root-grant-descriptor.v2",
                "shardx.keys.tenant-root-grant-revoke.v2",
                "shardx.keys.tenant-root-grant-revoked.v2",
                "shardx.keys.tenant-root-grant-create.v2",
                "shardx.keys.tenant-root-grant-created.v2",
            ]
        );
        assert_eq!(ACK_OUTCOME_ACKNOWLEDGED, "acknowledged");
        assert_eq!(REVOKE_OUTCOME_REVOKED, "revoked");
    }

    #[test]
    fn an_ack_names_the_key_it_unwrapped_and_its_outcome() {
        let raw = ack().encode();
        assert_eq!(
            TenantRootGrantAckV2::parse(&edit(&raw, |e| set(
                e,
                "locally_unwrapped_trk_key_id",
                c::b(&fx::<32>("root-key-0"))
            ))),
            Err(RecordError::BadValue("locally_unwrapped_trk_key_id"))
        );
        let raw = acked().encode();
        assert_eq!(
            TenantRootGrantAckedV2::parse(&edit(&raw, |e| set(e, "ack_outcome", c::t("rejected")))),
            Err(RecordError::BadValue("ack_outcome"))
        );
    }

    #[test]
    fn a_grant_create_carries_exactly_the_container_it_names() {
        let raw = grant_create().encode();
        assert_eq!(
            TenantRootGrantCreateV2::parse(&edit(&raw, |e| set(
                e,
                "exact_signed_grant_container_bytes",
                c::b(b"other bytes")
            ))),
            Err(RecordError::BadValue("exact_signed_container_bytes_sha256"))
        );
        for bytes in [vec![], vec![0; MAX_EMBEDDED_GRANT_BYTES + 1]] {
            assert!(TenantRootGrantCreateV2::parse(&edit(&raw, |e| set(
                e,
                "exact_signed_grant_container_bytes",
                c::b(&bytes)
            )))
            .is_err());
        }
        let raw = grant_created().encode();
        for (key, value) in [
            ("grant_state", c::t("ACKNOWLEDGED")),
            ("grant_variant", c::t("SomeGrant")),
        ] {
            assert!(
                TenantRootGrantCreatedV2::parse(&edit(&raw, |e| set(e, key, value.clone())))
                    .is_err(),
                "{key}"
            );
        }
    }

    #[test]
    fn a_revocation_names_a_known_reason_and_its_outcome() {
        assert_eq!(
            RootGrantRevokeReason::ALL.map(RootGrantRevokeReason::as_str),
            ["device_lost", "custody_removed", "rotation_exclusion"]
        );
        for reason in RootGrantRevokeReason::ALL {
            let r = TenantRootGrantRevokeV2 {
                reason_code: reason,
                ..revoke()
            };
            assert_eq!(TenantRootGrantRevokeV2::parse(&r.encode()), Ok(r));
        }
        let raw = revoke().encode();
        assert_eq!(
            TenantRootGrantRevokeV2::parse(&edit(&raw, |e| set(e, "reason_code", c::t("lost")))),
            Err(RecordError::BadValue("reason_code"))
        );
        let raw = revoked().encode();
        assert_eq!(
            TenantRootGrantRevokedV2::parse(&edit(&raw, |e| set(
                e,
                "revoke_outcome",
                c::t("refused")
            ))),
            Err(RecordError::BadValue("revoke_outcome"))
        );
        assert!(TenantRootGrantRevokedV2::parse(&edit(&raw, |e| set(
            e,
            "sessions_invalidated_count",
            c::u(u64::from(u32::MAX) + 1)
        )))
        .is_err());
    }

    #[test]
    fn an_activation_names_its_previous_root_iff_it_retires_one() {
        let p = TenantRootGenerationActivateV2::parse;
        let boot = activate(0).encode();
        let rot = activate(5).encode();
        for edited in [
            edit(&boot, |e| set(e, "previous_root_key_id", c::b(&[9; 32]))),
            edit(&boot, |e| set(e, "previous_root_generation", c::u(0))),
            // Both halves on generation 0 are refused as a pair, not only by
            // the previous + 1 rule.
            edit(&boot, |e| {
                set(e, "previous_root_key_id", c::b(&[9; 32]));
                set(e, "previous_root_generation", c::u(0));
            }),
            edit(&rot, |e| drop_key(e, "previous_root_key_id")),
            edit(&rot, |e| drop_key(e, "previous_root_generation")),
        ] {
            assert_eq!(
                p(&edited),
                Err(RecordError::BadValue("previous_root_key_id"))
            );
        }
        // Generation 0 is held by its one self-grant (D-4).
        for count in [2, 7] {
            let mut a = activate(0);
            a.target.required_custodian_grant_count = count;
            assert_eq!(
                p(&a.encode()),
                Err(RecordError::BadValue("required_custodian_grant_count"))
            );
            let mut d = activated(0);
            d.target.required_custodian_grant_count = count;
            assert_eq!(
                TenantRootGenerationActivatedV2::parse(&d.encode()),
                Err(RecordError::BadValue("required_custodian_grant_count"))
            );
        }
        for previous in [3, 5] {
            assert_eq!(
                p(&edit(&rot, |e| set(
                    e,
                    "previous_root_generation",
                    c::u(previous)
                ))),
                Err(RecordError::BadValue("root_generation")),
                "{previous}"
            );
        }
        assert_eq!(
            p(&edit(&rot, |e| set(
                e,
                "previous_root_key_id",
                c::b(&fx::<32>("root-key-1"))
            ))),
            Err(RecordError::BadValue("previous_root_key_id"))
        );

        let q = TenantRootGenerationActivatedV2::parse;
        let made = activated(0).encode();
        let rotated = activated(5).encode();
        for (raw, edited, field) in [
            (
                &rotated,
                edit(&rotated, |e| drop_key(e, "previous_state")),
                "previous_state",
            ),
            (
                &rotated,
                edit(&rotated, |e| set(e, "previous_state", c::t("ACTIVE"))),
                "previous_state",
            ),
            (
                &made,
                edit(&made, |e| set(e, "previous_state", c::t("RETIRED"))),
                "previous_state",
            ),
            (
                &made,
                edit(&made, |e| set(e, "target_state", c::t("PREPARING"))),
                "target_state",
            ),
            (
                &rotated,
                edit(&rotated, |e| set(e, "active_root_generation", c::u(4))),
                "active_root_generation",
            ),
        ] {
            assert_ne!(raw, &edited);
            assert_eq!(q(&edited), Err(RecordError::BadValue(field)), "{field}");
        }
    }

    const GOLDEN_DESCRIPTORS: [&str; 3] = [
        "d5f863d23d0f931e5a416bfc917161a770e2c69a647fb920b68e12470dcd9004",
        "a6cb85d129e68fe2fed8b9b358bffd718c4da07405b810e3f45ccbe0dbb286da",
        "1eeede1fada9e91cd6a668bc2efd5060f96afcb2c1e5740dd8aa33553d0470f2",
    ];

    fn fleet_record() -> Vec<u8> {
        let g = DeviceHpkeGrantV2 {
            common: common(),
            fleet_id: fx("fleet"),
            fkek_key_id: fx("fkek"),
            generation: 1,
            subject_account_id: fx("account"),
            subject_device_id: fx("device"),
            subject_signing_key_id: fx("device-signing"),
            recipient_hpke_key_id: fx("device-hpke"),
            hpke_encapped_key_bytes: fx::<32>("encapped").to_vec(),
            hpke_wrapped_fleet_key_bytes: fx::<48>("wrapped").to_vec(),
        };
        build_record(
            &custodian(),
            DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE,
            &g.encode(),
        )
    }

    #[test]
    fn a_fleet_descriptor_holds_only_a_device_grant_under_its_own_domain() {
        let issuer = *custodian().verifying_key().as_bytes();
        let verify = |container: &[u8]| {
            AuthorizationRecord::parse(container)
                .unwrap()
                .verify_signature(&issuer)
                .unwrap()
        };
        let d = FleetDeviceGrantDescriptorV2::new(
            verify(&fleet_record()),
            RootGrantState::Acknowledged,
            RootGenerationState::Active,
        )
        .unwrap();
        let raw = d.encode();
        assert_eq!(
            hex(&c::sha256(&raw)),
            "4fd18276735219923ab2df70d1c0815b383cddd54174deca0ee36799a597c2e6"
        );
        assert_eq!(FleetDeviceGrantDescriptorV2::parse(&raw, &issuer), Ok(d));
        // A root grant is no fleet descriptor, and the two domains never mix.
        let root = verify(&root_record(RootGrantVariant::FirstRootSelfGrant, 0));
        assert!(FleetDeviceGrantDescriptorV2::new(
            root.clone(),
            RootGrantState::Acknowledged,
            RootGenerationState::Active
        )
        .is_none());
        let root_raw = TenantRootGrantDescriptorV2::new(
            root,
            RootGrantState::Acknowledged,
            RootGenerationState::Active,
        )
        .unwrap()
        .encode();
        assert!(FleetDeviceGrantDescriptorV2::parse(&root_raw, &issuer).is_err());
        assert!(TenantRootGrantDescriptorV2::parse(&raw, &issuer).is_err());
        // Columns are rebuilt from the container, so an edited one fails.
        assert_eq!(
            FleetDeviceGrantDescriptorV2::parse(
                &edit(&raw, |e| set(e, "generation", c::u(2))),
                &issuer
            ),
            Err(RecordError::BadValue("descriptor"))
        );
    }

    #[test]
    fn a_descriptor_is_exactly_its_verified_container() {
        let issuer = *custodian().verifying_key().as_bytes();
        let container = root_record(RootGrantVariant::FirstRootSelfGrant, 0);
        let d = descriptor(&container);
        let raw = d.encode();
        let parse = |b: &[u8]| TenantRootGrantDescriptorV2::parse(b, &issuer);
        assert_eq!(parse(&raw), Ok(d.clone()));
        // One golden per grant state; Preparing and Active pin the generation
        // states.
        let pinned: Vec<String> = [
            (RootGrantState::PendingAck, RootGenerationState::Preparing),
            (RootGrantState::Acknowledged, RootGenerationState::Active),
            (RootGrantState::Revoked, RootGenerationState::Retired),
        ]
        .into_iter()
        .map(|(g, s)| {
            let mut other = d.clone();
            other.grant_state = g;
            other.generation_state = s;
            hex(&c::sha256(&other.encode()))
        })
        .collect();
        assert_eq!(pinned, GOLDEN_DESCRIPTORS);

        // Each payload field is one column and no descriptor column shadows
        // one: the map holds them all plus its own 15.
        let Value::Map(payload) = c::decode(d.record().record().canonical_payload_bytes()).unwrap()
        else {
            panic!("not a map")
        };
        let Value::Map(columns) = c::decode(&raw).unwrap() else {
            panic!("not a map")
        };
        assert_eq!(columns.len(), payload.len() + 15);

        // A rotation carries its previous pair as columns too.
        let rotation = root_record(
            RootGrantVariant::RotationGrant {
                previous_root_key_id: fx("root-key-0"),
                previous_root_generation: 4,
            },
            5,
        );
        let r = descriptor(&rotation).encode();
        assert_eq!(parse(&r).unwrap().encode(), r);
        let Value::Map(entries) = c::decode(&r).unwrap() else {
            panic!("not a map")
        };
        assert!(entries.iter().any(|(k, _)| k == "previous_root_generation"));

        // Every column must be exactly what the container says.
        for (column, value) in [
            ("root_generation", c::u(1)),
            ("subject_device_id", c::b(&[1; 16])),
            ("recipient_hpke_key_id", c::b(&[2; 32])),
            ("hpke_wrapped_trk_bytes", c::b(&[3; 48])),
            ("subject_device_approval_replay_id", c::b(&[4; 16])),
            ("signature_bytes", c::b(&[5; 64])),
            ("signed_container_hash", c::b(&[6; 32])),
            ("payload_domain", c::t("shardx.keys.other.v2")),
            ("container_version", c::u(3)),
            ("extra", c::u(1)),
        ] {
            assert_eq!(
                parse(&edit(&raw, |e| set(e, column, value))),
                Err(RecordError::BadValue("descriptor")),
                "{column}"
            );
        }
        for column in [
            "subject_account_id",
            "payload_sha256",
            "hpke_info_bytes",
            "canonical_payload_bytes",
        ] {
            assert_eq!(
                parse(&edit(&raw, |e| drop_key(e, column))),
                Err(RecordError::BadValue("descriptor")),
                "{column}"
            );
        }
        // States are closed sets and part of the bytes.
        for state in [RootGrantState::Acknowledged, RootGrantState::Revoked] {
            let mut other = d.clone();
            other.grant_state = state;
            assert_eq!(parse(&other.encode()), Ok(other));
        }
        assert_eq!(
            parse(&edit(&raw, |e| set(e, "grant_state", c::t("LOST")))),
            Err(RecordError::BadValue("grant_state"))
        );
        assert_eq!(
            parse(&edit(&raw, |e| set(e, "generation_state", c::t("GONE")))),
            Err(RecordError::BadValue("generation_state"))
        );

        // Larger than any descriptor of a valid container.
        assert_eq!(
            parse(&vec![0; MAX_DESCRIPTOR_BYTES + 1]),
            Err(RecordError::BadValue("descriptor"))
        );

        // Another issuer, a tampered container, another record domain.
        let stranger = *SigningKey::from_bytes(&fx::<32>("stranger"))
            .verifying_key()
            .as_bytes();
        assert_eq!(
            TenantRootGrantDescriptorV2::parse(&raw, &stranger),
            Err(RecordError::IssuerKeyMismatch)
        );
        let mut flipped = container.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 1;
        assert!(parse(&edit(&raw, |e| set(
            e,
            "exact_signed_container_bytes",
            c::b(&flipped)
        )))
        .is_err());
        let approval = DeviceApprovalV2 {
            common: common(),
            subject_account_id: fx("account"),
            subject_device_id: fx("device"),
            subject_signing_key_id: fx("device-signing"),
            subject_hpke_key_id: fx("device-hpke"),
            approval_scope_kind: ApprovalScopeKind::Tenant,
            approval_scope_id: fx("tenant"),
        };
        let foreign = build_record(&custodian(), DOMAIN_DEVICE_APPROVAL, &approval.encode());
        assert_eq!(
            parse(&edit(&raw, |e| set(
                e,
                "exact_signed_container_bytes",
                c::b(&foreign)
            ))),
            Err(RecordError::BadValue("payload_domain"))
        );
    }
}
