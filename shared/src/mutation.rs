//! Exact idempotent mutation maps (plan 5.6.5) and the root generation create
//! pair (plan 5.6.4, ADR 0002 D-9 for the fleet kinds).
//!
//! The outer request and stored response wrap one operation payload each.
//! Their hashes are recomputed from the decoded fields and must equal what was
//! received, as in `authz_record`. Whether the actor may run the operation,
//! and whether the payload matches live state, is the caller's to check.

use crate::authz_record::{Fields, RecordError};
use crate::canonical::{self as c, Value};

type Result<T> = std::result::Result<T, RecordError>;

pub const DOMAIN_MUTATION_REQUEST: &str = "shardx.sync.idempotent-mutation-request.v2";
pub const DOMAIN_STORED_RESPONSE: &str = "shardx.sync.idempotent-stored-response.v2";
pub const DOMAIN_ROOT_GENERATION_CREATE: &str = "shardx.keys.tenant-root-generation-create.v2";
pub const DOMAIN_ROOT_GENERATION_CREATED: &str = "shardx.keys.tenant-root-generation-created.v2";
pub const RECORD_TYPE_ROOT_GENERATION_CREATED: &str = "TenantRootGenerationCreatedV2";
const VERSION: u64 = 2;
const L_REQUEST_HASH: &str = "SHARDX-IDEMPOTENT-MUTATION-REQUEST-V2\0";
const L_RESPONSE_HASH: &str = "SHARDX-IDEMPOTENT-STORED-RESPONSE-V2\0";
const MAX_OPERATION_PAYLOAD: usize = 262144;
/// Plan 5.6.4 bound on an embedded signed grant container.
pub const MAX_EMBEDDED_GRANT_BYTES: usize = 131072;
const OUTCOME_SUCCEEDED: &str = "succeeded";
const GENERATION_STATE_PREPARING: &str = "PREPARING";
const L_ROOT_CUSTODIAN_SET: &str = "SHARDX-ROOT-CUSTODIAN-GRANT-SET-V2\0";

/// ADR 0002 D-4 `required_custodian_grant_set_hash`: the members' internal
/// `signed_container_hash` values, sorted ascending, concatenated and domain
/// hashed. `None` for an empty set or a repeated member, which D-4 forbids.
pub fn root_custodian_grant_set_hash(members: &[[u8; 32]]) -> Option<[u8; 32]> {
    let mut sorted = members.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.is_empty() || sorted.len() != members.len() {
        return None;
    }
    Some(c::domain_hash(L_ROOT_CUSTODIAN_SET, &sorted.concat()))
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

fn exact_version(f: &mut Fields, domain: &str) -> Result<()> {
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

fn u32_in(f: &mut Fields, field: &'static str, min: u64, max: u64) -> Result<u32> {
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
}
