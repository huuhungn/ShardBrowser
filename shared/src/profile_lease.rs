//! Plan 5.6.5 profile lease maps: the `PROFILE_PUBLISH_CREATE` (L948),
//! `PROFILE_CHECKOUT` (L949), `CREATE_UPLOAD` (L950) and `RELEASE_LEASE`
//! (L952) payloads, their stored response payloads and the `FINALIZE_UPLOAD`
//! response (L951), the `LOCAL_UNBIND` maps (L953) with their ADR 0002 D-7
//! tombstone, and the lease renew map of L1139/L1143. The
//! `FINALIZE_UPLOAD` request wraps a commit request, so it is
//! [`crate::snapshot_v2::FinalizeUploadV2`].
//!
//! Built like the maps in `mutation`, and wrapped the same way in an
//! `IdempotentMutationRequestV2` (renew is not: L913 has no kind for it).
//! Each `parse` checks the rules one map can decide alone (bounds, fields
//! present iff their condition). Whether the actor may run the operation, and
//! whether the payload matches live state, is the caller's to check.

use crate::authz_record::{Fields, RecordError};
use crate::canonical::{self as c, Value};
use crate::envelope_v2::MAX_OBJECT_SIZE;
use crate::mutation::{exact_version, u32_in, VERSION};

type Result<T> = std::result::Result<T, RecordError>;

pub const DOMAIN_PUBLISH_CREATE_REQUEST: &str = "shardx.sync.profile-publish-create-request.v2";
pub const DOMAIN_PUBLISH_CREATE_RESPONSE: &str = "shardx.sync.profile-publish-create-response.v2";
pub const DOMAIN_CHECKOUT_REQUEST: &str = "shardx.sync.profile-checkout-request.v2";
pub const DOMAIN_CHECKOUT_RESPONSE: &str = "shardx.sync.profile-checkout-response.v2";
pub const DOMAIN_RELEASE_LEASE_REQUEST: &str = "shardx.sync.release-lease-request.v2";
pub const DOMAIN_RELEASE_LEASE_RESPONSE: &str = "shardx.sync.release-lease-response.v2";
/// L927 names no record type for these responses; these are the ones chosen
/// here.
pub const RECORD_TYPE_PUBLISH_CREATED: &str = "ProfilePublishCreateResponseV2";
pub const RECORD_TYPE_CHECKED_OUT: &str = "ProfileCheckoutResponseV2";
pub const RECORD_TYPE_LEASE_RELEASED: &str = "ReleaseLeaseResponseV2";
/// L1139 routes renew but defines no map; these domains are the ones chosen
/// here.
pub const DOMAIN_LEASE_RENEW_REQUEST: &str = "shardx.sync.lease-renew-request.v2";
pub const DOMAIN_LEASE_RENEW_RESPONSE: &str = "shardx.sync.lease-renew-response.v2";
const RELEASE_OUTCOME_RELEASED: &str = "released";
pub const DOMAIN_CREATE_UPLOAD_REQUEST: &str = "shardx.sync.create-upload-request.v2";
pub const DOMAIN_CREATE_UPLOAD_RESPONSE: &str = "shardx.sync.create-upload-response.v2";
pub const DOMAIN_FINALIZE_UPLOAD_RESPONSE: &str = "shardx.sync.finalize-upload-response.v2";
/// Chosen here, like the lease record types above.
pub const RECORD_TYPE_UPLOAD_CREATED: &str = "CreateUploadResponseV2";
pub const RECORD_TYPE_UPLOAD_FINALIZED: &str = "FinalizeUploadResponseV2";
const UPLOAD_STATE_OPEN: &str = "OPEN";
const UPLOAD_STATE_READY: &str = "READY";
/// L948 `label_ciphertext:Bytes(1,4096)`.
pub const MAX_LABEL_CIPHERTEXT: usize = 4096;
/// L948/L949 `requested_lease_ttl_seconds` in `30..900`.
pub const MIN_LEASE_TTL_SECONDS: u64 = 30;
pub const MAX_LEASE_TTL_SECONDS: u64 = 900;

fn take_ttl(f: &mut Fields) -> Result<u32> {
    u32_in(
        f,
        "requested_lease_ttl_seconds",
        MIN_LEASE_TTL_SECONDS,
        MAX_LEASE_TTL_SECONDS,
    )
}

/// The tenant, fleet and profile every lease map names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileRef {
    pub tenant_id: [u8; 16],
    pub fleet_id: [u8; 16],
    pub profile_id: [u8; 16],
}

impl ProfileRef {
    fn take(f: &mut Fields) -> Result<Self> {
        Ok(Self {
            tenant_id: f.fixed("tenant_id")?,
            fleet_id: f.fixed("fleet_id")?,
            profile_id: f.fixed("profile_id")?,
        })
    }

    fn head(&self, domain: &'static str) -> Vec<(&'static str, Value)> {
        vec![
            ("domain", c::t(domain)),
            ("version", c::u(VERSION)),
            ("tenant_id", c::b(&self.tenant_id)),
            ("fleet_id", c::b(&self.fleet_id)),
            ("profile_id", c::b(&self.profile_id)),
        ]
    }
}

/// The lease ID, fence and base a release or renew names (L952).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseRef {
    pub lease_id: [u8; 16],
    pub fencing_token: u64,
    pub base_version: u64,
}

impl LeaseRef {
    fn take(f: &mut Fields) -> Result<Self> {
        Ok(Self {
            lease_id: f.fixed("lease_id")?,
            fencing_token: f.uint("fencing_token")?,
            base_version: f.uint("base_version")?,
        })
    }

    fn push(&self, map: &mut Vec<(&'static str, Value)>) {
        map.push(("lease_id", c::b(&self.lease_id)));
        map.push(("fencing_token", c::u(self.fencing_token)));
        map.push(("base_version", c::u(self.base_version)));
    }
}

// ------------------------------------------------- PROFILE_PUBLISH_CREATE ---

/// L948 request: a client-generated profile ID, its label ciphertext, and the
/// FKEK generation the client will encrypt under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfilePublishCreateV2 {
    pub profile: ProfileRef,
    pub label_ciphertext: Vec<u8>,
    pub requested_lease_ttl_seconds: u32,
    pub fkek_key_id: [u8; 32],
    pub key_generation: u64,
}

impl ProfilePublishCreateV2 {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("ProfilePublishCreateV2", payload)?;
        exact_version(&mut f, DOMAIN_PUBLISH_CREATE_REQUEST)?;
        let profile = ProfileRef::take(&mut f)?;
        let label_ciphertext = f.bytes("label_ciphertext", 1, MAX_LABEL_CIPHERTEXT)?;
        let requested_lease_ttl_seconds = take_ttl(&mut f)?;
        let fkek_key_id = f.fixed("fkek_key_id")?;
        let key_generation = f.uint("key_generation")?;
        f.finish()?;
        Ok(Self {
            profile,
            label_ciphertext,
            requested_lease_ttl_seconds,
            fkek_key_id,
            key_generation,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut map = self.profile.head(DOMAIN_PUBLISH_CREATE_REQUEST);
        map.push(("label_ciphertext", c::b(&self.label_ciphertext)));
        map.push((
            "requested_lease_ttl_seconds",
            c::u(self.requested_lease_ttl_seconds.into()),
        ));
        map.push(("fkek_key_id", c::b(&self.fkek_key_id)));
        map.push(("key_generation", c::u(self.key_generation)));
        c::encode(&c::m(map))
    }
}

// ------------------------------------------------------- PROFILE_CHECKOUT ---

/// L949 request: the version and head the client last saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileCheckoutV2 {
    pub profile: ProfileRef,
    pub observed_version: u64,
    /// Omitted iff `observed_version` is 0.
    pub observed_signed_head_hash: Option<[u8; 32]>,
    pub requested_lease_ttl_seconds: u32,
}

impl ProfileCheckoutV2 {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("ProfileCheckoutV2", payload)?;
        exact_version(&mut f, DOMAIN_CHECKOUT_REQUEST)?;
        let profile = ProfileRef::take(&mut f)?;
        let observed_version = f.uint("observed_version")?;
        let observed_signed_head_hash = f.opt_fixed("observed_signed_head_hash")?;
        let requested_lease_ttl_seconds = take_ttl(&mut f)?;
        f.finish()?;
        if observed_signed_head_hash.is_some() != (observed_version != 0) {
            return Err(RecordError::BadValue("observed_signed_head_hash"));
        }
        Ok(Self {
            profile,
            observed_version,
            observed_signed_head_hash,
            requested_lease_ttl_seconds,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut map = self.profile.head(DOMAIN_CHECKOUT_REQUEST);
        map.push(("observed_version", c::u(self.observed_version)));
        if let Some(h) = &self.observed_signed_head_hash {
            map.push(("observed_signed_head_hash", c::b(h)));
        }
        map.push((
            "requested_lease_ttl_seconds",
            c::u(self.requested_lease_ttl_seconds.into()),
        ));
        c::encode(&c::m(map))
    }
}

/// Which operation granted a lease: the response maps of L948 and L949 have
/// the same fields under their own domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseOrigin {
    PublishCreate,
    Checkout,
}

impl LeaseOrigin {
    fn domain(self) -> &'static str {
        match self {
            Self::PublishCreate => DOMAIN_PUBLISH_CREATE_RESPONSE,
            Self::Checkout => DOMAIN_CHECKOUT_RESPONSE,
        }
    }

    pub fn record_type(self) -> &'static str {
        match self {
            Self::PublishCreate => RECORD_TYPE_PUBLISH_CREATED,
            Self::Checkout => RECORD_TYPE_CHECKED_OUT,
        }
    }
}

/// The L948/L949 response: the lease, its fence and base, the server expiry
/// and the fleet's ACTIVE FKEK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileLeaseV2 {
    pub profile: ProfileRef,
    pub lease: LeaseRef,
    pub expires_at_ms: u64,
    pub fkek_key_id: [u8; 32],
    pub key_generation: u64,
    /// Omitted iff the base is 0; always omitted after a publish.
    pub current_signed_head_hash: Option<[u8; 32]>,
    pub server_instance_id: [u8; 16],
    pub restore_epoch: u64,
}

impl ProfileLeaseV2 {
    pub fn parse(origin: LeaseOrigin, payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("ProfileLeaseV2", payload)?;
        exact_version(&mut f, origin.domain())?;
        let profile = ProfileRef::take(&mut f)?;
        let lease = LeaseRef::take(&mut f)?;
        let expires_at_ms = f.uint("expires_at_ms")?;
        let fkek_key_id = f.fixed("fkek_key_id")?;
        let key_generation = f.uint("key_generation")?;
        let current_signed_head_hash = f.opt_fixed("current_signed_head_hash")?;
        let server_instance_id = f.fixed("server_instance_id")?;
        let restore_epoch = f.uint("restore_epoch")?;
        f.finish()?;
        if origin == LeaseOrigin::PublishCreate && lease.base_version != 0 {
            return Err(RecordError::BadValue("base_version"));
        }
        if current_signed_head_hash.is_some() != (lease.base_version != 0) {
            return Err(RecordError::BadValue("current_signed_head_hash"));
        }
        Ok(Self {
            profile,
            lease,
            expires_at_ms,
            fkek_key_id,
            key_generation,
            current_signed_head_hash,
            server_instance_id,
            restore_epoch,
        })
    }

    pub fn encode(&self, origin: LeaseOrigin) -> Vec<u8> {
        let mut map = self.profile.head(origin.domain());
        self.lease.push(&mut map);
        map.push(("expires_at_ms", c::u(self.expires_at_ms)));
        map.push(("fkek_key_id", c::b(&self.fkek_key_id)));
        map.push(("key_generation", c::u(self.key_generation)));
        if let Some(h) = &self.current_signed_head_hash {
            map.push(("current_signed_head_hash", c::b(h)));
        }
        map.push(("server_instance_id", c::b(&self.server_instance_id)));
        map.push(("restore_epoch", c::u(self.restore_epoch)));
        c::encode(&c::m(map))
    }
}

// ---------------------------------------------------------- CREATE_UPLOAD ---

/// L950 request: everything an upload binds before its first byte. The
/// expected size is `1..536870912`, the envelope object cap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateUploadV2 {
    pub profile: ProfileRef,
    pub snapshot_id: [u8; 16],
    pub manifest_replay_id: [u8; 16],
    pub lease: LeaseRef,
    pub intent_hash: [u8; 32],
    pub preamble_sha256: [u8; 32],
    pub dek_slot_sha256: [u8; 32],
    pub fkek_key_id: [u8; 32],
    pub key_generation: u64,
    pub expected_ciphertext_size: u64,
    pub expected_ciphertext_sha256: [u8; 32],
}

impl CreateUploadV2 {
    fn take(f: &mut Fields) -> Result<Self> {
        let profile = ProfileRef::take(f)?;
        let snapshot_id = f.fixed("snapshot_id")?;
        let manifest_replay_id = f.fixed("manifest_replay_id")?;
        let lease = LeaseRef::take(f)?;
        let intent_hash = f.fixed("intent_hash")?;
        let preamble_sha256 = f.fixed("preamble_sha256")?;
        let dek_slot_sha256 = f.fixed("dek_slot_sha256")?;
        let fkek_key_id = f.fixed("fkek_key_id")?;
        let key_generation = f.uint("key_generation")?;
        let expected_ciphertext_size = f.uint("expected_ciphertext_size")?;
        if !(1..=MAX_OBJECT_SIZE).contains(&expected_ciphertext_size) {
            return Err(f.bad("expected_ciphertext_size"));
        }
        let expected_ciphertext_sha256 = f.fixed("expected_ciphertext_sha256")?;
        Ok(Self {
            profile,
            snapshot_id,
            manifest_replay_id,
            lease,
            intent_hash,
            preamble_sha256,
            dek_slot_sha256,
            fkek_key_id,
            key_generation,
            expected_ciphertext_size,
            expected_ciphertext_sha256,
        })
    }

    fn map(&self, domain: &'static str) -> Vec<(&'static str, Value)> {
        let mut map = self.profile.head(domain);
        map.push(("snapshot_id", c::b(&self.snapshot_id)));
        map.push(("manifest_replay_id", c::b(&self.manifest_replay_id)));
        self.lease.push(&mut map);
        map.push(("intent_hash", c::b(&self.intent_hash)));
        map.push(("preamble_sha256", c::b(&self.preamble_sha256)));
        map.push(("dek_slot_sha256", c::b(&self.dek_slot_sha256)));
        map.push(("fkek_key_id", c::b(&self.fkek_key_id)));
        map.push(("key_generation", c::u(self.key_generation)));
        map.push((
            "expected_ciphertext_size",
            c::u(self.expected_ciphertext_size),
        ));
        map.push((
            "expected_ciphertext_sha256",
            c::b(&self.expected_ciphertext_sha256),
        ));
        map
    }

    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("CreateUploadV2", payload)?;
        exact_version(&mut f, DOMAIN_CREATE_UPLOAD_REQUEST)?;
        let r = Self::take(&mut f)?;
        f.finish()?;
        Ok(r)
    }

    pub fn encode(&self) -> Vec<u8> {
        c::encode(&c::m(self.map(DOMAIN_CREATE_UPLOAD_REQUEST)))
    }
}

/// The L950 response: the same bindings, the server's upload ID and expiry,
/// at offset 0 in state `OPEN`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadCreatedV2 {
    pub terms: CreateUploadV2,
    pub upload_id: [u8; 16],
    pub expires_at_ms: u64,
    pub server_instance_id: [u8; 16],
    pub restore_epoch: u64,
}

impl UploadCreatedV2 {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("UploadCreatedV2", payload)?;
        exact_version(&mut f, DOMAIN_CREATE_UPLOAD_RESPONSE)?;
        let terms = CreateUploadV2::take(&mut f)?;
        let upload_id = f.fixed("upload_id")?;
        if f.uint("committed_offset")? != 0 {
            return Err(f.bad("committed_offset"));
        }
        f.exact_text("state", UPLOAD_STATE_OPEN)?;
        let expires_at_ms = f.uint("expires_at_ms")?;
        let server_instance_id = f.fixed("server_instance_id")?;
        let restore_epoch = f.uint("restore_epoch")?;
        f.finish()?;
        Ok(Self {
            terms,
            upload_id,
            expires_at_ms,
            server_instance_id,
            restore_epoch,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut map = self.terms.map(DOMAIN_CREATE_UPLOAD_RESPONSE);
        map.push(("upload_id", c::b(&self.upload_id)));
        map.push(("committed_offset", c::u(0)));
        map.push(("state", c::t(UPLOAD_STATE_OPEN)));
        map.push(("expires_at_ms", c::u(self.expires_at_ms)));
        map.push(("server_instance_id", c::b(&self.server_instance_id)));
        map.push(("restore_epoch", c::u(self.restore_epoch)));
        c::encode(&c::m(map))
    }
}

// -------------------------------------------------------- FINALIZE_UPLOAD ---

/// The L951 response: the upload is `READY` under its immutable size and hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadFinalizedV2 {
    pub upload_id: [u8; 16],
    pub snapshot_id: [u8; 16],
    pub manifest_replay_id: [u8; 16],
    pub ciphertext_size: u64,
    pub ciphertext_sha256: [u8; 32],
    pub object_receipt_id: [u8; 16],
    pub server_instance_id: [u8; 16],
    pub restore_epoch: u64,
}

impl UploadFinalizedV2 {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("UploadFinalizedV2", payload)?;
        exact_version(&mut f, DOMAIN_FINALIZE_UPLOAD_RESPONSE)?;
        let upload_id = f.fixed("upload_id")?;
        let snapshot_id = f.fixed("snapshot_id")?;
        let manifest_replay_id = f.fixed("manifest_replay_id")?;
        f.exact_text("state", UPLOAD_STATE_READY)?;
        let ciphertext_size = f.uint("ciphertext_size")?;
        let ciphertext_sha256 = f.fixed("ciphertext_sha256")?;
        let object_receipt_id = f.fixed("object_receipt_id")?;
        let server_instance_id = f.fixed("server_instance_id")?;
        let restore_epoch = f.uint("restore_epoch")?;
        f.finish()?;
        Ok(Self {
            upload_id,
            snapshot_id,
            manifest_replay_id,
            ciphertext_size,
            ciphertext_sha256,
            object_receipt_id,
            server_instance_id,
            restore_epoch,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        c::encode(&c::m(vec![
            ("domain", c::t(DOMAIN_FINALIZE_UPLOAD_RESPONSE)),
            ("version", c::u(VERSION)),
            ("upload_id", c::b(&self.upload_id)),
            ("snapshot_id", c::b(&self.snapshot_id)),
            ("manifest_replay_id", c::b(&self.manifest_replay_id)),
            ("state", c::t(UPLOAD_STATE_READY)),
            ("ciphertext_size", c::u(self.ciphertext_size)),
            ("ciphertext_sha256", c::b(&self.ciphertext_sha256)),
            ("object_receipt_id", c::b(&self.object_receipt_id)),
            ("server_instance_id", c::b(&self.server_instance_id)),
            ("restore_epoch", c::u(self.restore_epoch)),
        ]))
    }
}

// ---------------------------------------------------------- RELEASE_LEASE ---

/// L952 `reason_code`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseReason {
    UserRelease,
    CancelPublish,
    ShutdownCleanup,
}

impl ReleaseReason {
    pub const ALL: [ReleaseReason; 3] = [
        Self::UserRelease,
        Self::CancelPublish,
        Self::ShutdownCleanup,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserRelease => "user_release",
            Self::CancelPublish => "cancel_publish",
            Self::ShutdownCleanup => "shutdown_cleanup",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseLeaseV2 {
    pub profile: ProfileRef,
    pub lease: LeaseRef,
    pub reason_code: ReleaseReason,
}

impl ReleaseLeaseV2 {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("ReleaseLeaseV2", payload)?;
        exact_version(&mut f, DOMAIN_RELEASE_LEASE_REQUEST)?;
        let profile = ProfileRef::take(&mut f)?;
        let lease = LeaseRef::take(&mut f)?;
        let reason = f.text("reason_code")?;
        let reason_code = ReleaseReason::ALL
            .into_iter()
            .find(|r| r.as_str() == reason)
            .ok_or(RecordError::BadValue("reason_code"))?;
        f.finish()?;
        Ok(Self {
            profile,
            lease,
            reason_code,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut map = self.profile.head(DOMAIN_RELEASE_LEASE_REQUEST);
        self.lease.push(&mut map);
        map.push(("reason_code", c::t(self.reason_code.as_str())));
        c::encode(&c::m(map))
    }
}

/// The L952 response, stored and replayed after the lease row is gone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseReleasedV2 {
    pub profile: ProfileRef,
    pub lease: LeaseRef,
    pub released_at_ms: u64,
    pub server_instance_id: [u8; 16],
    pub restore_epoch: u64,
}

impl LeaseReleasedV2 {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("LeaseReleasedV2", payload)?;
        exact_version(&mut f, DOMAIN_RELEASE_LEASE_RESPONSE)?;
        let profile = ProfileRef::take(&mut f)?;
        let lease = LeaseRef::take(&mut f)?;
        f.exact_text("release_outcome", RELEASE_OUTCOME_RELEASED)?;
        let released_at_ms = f.uint("released_at_ms")?;
        let server_instance_id = f.fixed("server_instance_id")?;
        let restore_epoch = f.uint("restore_epoch")?;
        f.finish()?;
        Ok(Self {
            profile,
            lease,
            released_at_ms,
            server_instance_id,
            restore_epoch,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut map = self.profile.head(DOMAIN_RELEASE_LEASE_RESPONSE);
        self.lease.push(&mut map);
        map.push(("release_outcome", c::t(RELEASE_OUTCOME_RELEASED)));
        map.push(("released_at_ms", c::u(self.released_at_ms)));
        map.push(("server_instance_id", c::b(&self.server_instance_id)));
        map.push(("restore_epoch", c::u(self.restore_epoch)));
        c::encode(&c::m(map))
    }
}

// ----------------------------------------------------------- LOCAL_UNBIND ---

pub const DOMAIN_LOCAL_UNBIND_REQUEST: &str = "shardx.local.unbind-request.v2";
pub const DOMAIN_LOCAL_UNBIND_RESPONSE: &str = "shardx.local.unbind-response.v2";
/// Chosen here, like the lease record types above.
pub const RECORD_TYPE_LOCAL_UNBOUND: &str = "LocalUnbindResponseV2";
/// ADR 0002 D-7.
pub const DOMAIN_LOCAL_BINDING_TOMBSTONE: &str = "shardx.local.binding-tombstone.v2";
pub const L_LOCAL_BINDING_TOMBSTONE: &str = "SHARDX-LOCAL-BINDING-TOMBSTONE-V2\0";
const UNBIND_OUTCOME_UNBOUND: &str = "unbound";
/// L953 `server_id:Text(1,512)` and `local_profile_id:Text(1,255)`, in bytes.
pub const MAX_SERVER_ID: usize = 512;
pub const MAX_LOCAL_PROFILE_ID: usize = 255;

fn take_text(f: &mut Fields, field: &'static str, max: usize) -> Result<String> {
    let s = f.text(field)?;
    if !(1..=max).contains(&s.len()) {
        return Err(f.bad(field));
    }
    Ok(s)
}

/// The binding a local unbind names (L953): the same in its request, its
/// response and its D-7 tombstone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnboundBinding {
    pub server_id: String,
    pub server_instance_id: [u8; 16],
    pub restore_epoch: u64,
    pub tenant_id: [u8; 16],
    pub fleet_id: [u8; 16],
    pub remote_profile_id: [u8; 16],
    pub local_profile_id: String,
    pub remote_version: u64,
    /// Omitted iff `remote_version` is 0.
    pub expected_signed_head_hash: Option<[u8; 32]>,
}

impl UnboundBinding {
    fn take(f: &mut Fields) -> Result<Self> {
        let b = Self {
            server_id: take_text(f, "server_id", MAX_SERVER_ID)?,
            server_instance_id: f.fixed("server_instance_id")?,
            restore_epoch: f.uint("restore_epoch")?,
            tenant_id: f.fixed("tenant_id")?,
            fleet_id: f.fixed("fleet_id")?,
            remote_profile_id: f.fixed("remote_profile_id")?,
            local_profile_id: take_text(f, "local_profile_id", MAX_LOCAL_PROFILE_ID)?,
            remote_version: f.uint("remote_version")?,
            expected_signed_head_hash: f.opt_fixed("expected_signed_head_hash")?,
        };
        if b.expected_signed_head_hash.is_some() != (b.remote_version != 0) {
            return Err(RecordError::BadValue("expected_signed_head_hash"));
        }
        Ok(b)
    }

    fn map(&self, domain: &'static str) -> Vec<(&'static str, Value)> {
        let mut map = vec![
            ("domain", c::t(domain)),
            ("version", c::u(VERSION)),
            ("server_id", c::t(&self.server_id)),
            ("server_instance_id", c::b(&self.server_instance_id)),
            ("restore_epoch", c::u(self.restore_epoch)),
            ("tenant_id", c::b(&self.tenant_id)),
            ("fleet_id", c::b(&self.fleet_id)),
            ("remote_profile_id", c::b(&self.remote_profile_id)),
            ("local_profile_id", c::t(&self.local_profile_id)),
            ("remote_version", c::u(self.remote_version)),
        ];
        if let Some(h) = &self.expected_signed_head_hash {
            map.push(("expected_signed_head_hash", c::b(h)));
        }
        map
    }
}

/// The L953 request: delete the binding only with no lease and no pending
/// operation, both required `true`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalUnbindV2 {
    pub binding: UnboundBinding,
}

impl LocalUnbindV2 {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("LocalUnbindV2", payload)?;
        exact_version(&mut f, DOMAIN_LOCAL_UNBIND_REQUEST)?;
        let binding = UnboundBinding::take(&mut f)?;
        for flag in ["require_no_lease", "require_no_pending_operation"] {
            if f.req(flag)? != Value::Bool(true) {
                return Err(RecordError::BadValue(flag));
            }
        }
        f.finish()?;
        Ok(Self { binding })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut map = self.binding.map(DOMAIN_LOCAL_UNBIND_REQUEST);
        map.push(("require_no_lease", Value::Bool(true)));
        map.push(("require_no_pending_operation", Value::Bool(true)));
        c::encode(&c::m(map))
    }
}

/// The L953 response, stored and replayed after the binding row is gone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalUnboundV2 {
    pub binding: UnboundBinding,
    pub binding_tombstone_sha256: [u8; 32],
    pub completed_at_ms: u64,
}

impl LocalUnboundV2 {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("LocalUnboundV2", payload)?;
        exact_version(&mut f, DOMAIN_LOCAL_UNBIND_RESPONSE)?;
        let binding = UnboundBinding::take(&mut f)?;
        f.exact_text("unbind_outcome", UNBIND_OUTCOME_UNBOUND)?;
        let binding_tombstone_sha256 = f.fixed("binding_tombstone_sha256")?;
        let completed_at_ms = f.uint("completed_at_ms")?;
        f.finish()?;
        Ok(Self {
            binding,
            binding_tombstone_sha256,
            completed_at_ms,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut map = self.binding.map(DOMAIN_LOCAL_UNBIND_RESPONSE);
        map.push(("unbind_outcome", c::t(UNBIND_OUTCOME_UNBOUND)));
        map.push((
            "binding_tombstone_sha256",
            c::b(&self.binding_tombstone_sha256),
        ));
        map.push(("completed_at_ms", c::u(self.completed_at_ms)));
        c::encode(&c::m(map))
    }
}

/// ADR 0002 D-7 `LocalBindingTombstoneV2`, the `UNBIND` receipt: built from
/// the request and response fields alone, so it is recomputed after the
/// binding row is deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalBindingTombstoneV2 {
    pub binding: UnboundBinding,
    pub unbind_idempotency_key: [u8; 16],
    pub completed_at_ms: u64,
}

impl LocalBindingTombstoneV2 {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("LocalBindingTombstoneV2", bytes)?;
        exact_version(&mut f, DOMAIN_LOCAL_BINDING_TOMBSTONE)?;
        let binding = UnboundBinding::take(&mut f)?;
        let unbind_idempotency_key = f.fixed("unbind_idempotency_key")?;
        let completed_at_ms = f.uint("completed_at_ms")?;
        f.finish()?;
        Ok(Self {
            binding,
            unbind_idempotency_key,
            completed_at_ms,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut map = self.binding.map(DOMAIN_LOCAL_BINDING_TOMBSTONE);
        map.push(("unbind_idempotency_key", c::b(&self.unbind_idempotency_key)));
        map.push(("completed_at_ms", c::u(self.completed_at_ms)));
        c::encode(&c::m(map))
    }

    /// D-7 `binding_tombstone_sha256`.
    pub fn hash(&self) -> [u8; 32] {
        c::domain_hash(L_LOCAL_BINDING_TOMBSTONE, &self.encode())
    }

    /// The response this tombstone completes.
    pub fn response(&self) -> LocalUnboundV2 {
        LocalUnboundV2 {
            binding: self.binding.clone(),
            binding_tombstone_sha256: self.hash(),
            completed_at_ms: self.completed_at_ms,
        }
    }
}

// ------------------------------------------------------------------ renew ---

/// The renew request body (L1139): the held lease and a new TTL from now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseRenewV2 {
    pub profile: ProfileRef,
    pub lease: LeaseRef,
    pub requested_lease_ttl_seconds: u32,
}

impl LeaseRenewV2 {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("LeaseRenewV2", payload)?;
        exact_version(&mut f, DOMAIN_LEASE_RENEW_REQUEST)?;
        let profile = ProfileRef::take(&mut f)?;
        let lease = LeaseRef::take(&mut f)?;
        let requested_lease_ttl_seconds = take_ttl(&mut f)?;
        f.finish()?;
        Ok(Self {
            profile,
            lease,
            requested_lease_ttl_seconds,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut map = self.profile.head(DOMAIN_LEASE_RENEW_REQUEST);
        self.lease.push(&mut map);
        map.push((
            "requested_lease_ttl_seconds",
            c::u(self.requested_lease_ttl_seconds.into()),
        ));
        c::encode(&c::m(map))
    }
}

/// The renew response: the same lease with its new server expiry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseRenewedV2 {
    pub profile: ProfileRef,
    pub lease: LeaseRef,
    pub expires_at_ms: u64,
}

impl LeaseRenewedV2 {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("LeaseRenewedV2", payload)?;
        exact_version(&mut f, DOMAIN_LEASE_RENEW_RESPONSE)?;
        let profile = ProfileRef::take(&mut f)?;
        let lease = LeaseRef::take(&mut f)?;
        let expires_at_ms = f.uint("expires_at_ms")?;
        f.finish()?;
        Ok(Self {
            profile,
            lease,
            expires_at_ms,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut map = self.profile.head(DOMAIN_LEASE_RENEW_RESPONSE);
        self.lease.push(&mut map);
        map.push(("expires_at_ms", c::u(self.expires_at_ms)));
        c::encode(&c::m(map))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: ProfileRef = ProfileRef {
        tenant_id: [1; 16],
        fleet_id: [2; 16],
        profile_id: [3; 16],
    };
    const L: LeaseRef = LeaseRef {
        lease_id: [4; 16],
        fencing_token: 7,
        base_version: 0,
    };

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

    fn publish() -> ProfilePublishCreateV2 {
        ProfilePublishCreateV2 {
            profile: P,
            label_ciphertext: vec![9; 12],
            requested_lease_ttl_seconds: 300,
            fkek_key_id: [5; 32],
            key_generation: 0,
        }
    }

    fn lease(base_version: u64, head: Option<[u8; 32]>) -> ProfileLeaseV2 {
        ProfileLeaseV2 {
            profile: P,
            lease: LeaseRef { base_version, ..L },
            expires_at_ms: 1_800_000_000_000,
            fkek_key_id: [5; 32],
            key_generation: 0,
            current_signed_head_hash: head,
            server_instance_id: [6; 16],
            restore_epoch: 0,
        }
    }

    #[test]
    fn every_map_round_trips() {
        let p = publish();
        assert_eq!(ProfilePublishCreateV2::parse(&p.encode()).unwrap(), p);
        for (version, head) in [(0, None), (3, Some([8; 32]))] {
            let r = ProfileCheckoutV2 {
                profile: P,
                observed_version: version,
                observed_signed_head_hash: head,
                requested_lease_ttl_seconds: 30,
            };
            assert_eq!(ProfileCheckoutV2::parse(&r.encode()).unwrap(), r);
            let l = lease(version, head);
            let back =
                ProfileLeaseV2::parse(LeaseOrigin::Checkout, &l.encode(LeaseOrigin::Checkout));
            assert_eq!(back.unwrap(), l);
        }
        let l = lease(0, None);
        let bytes = l.encode(LeaseOrigin::PublishCreate);
        assert_eq!(
            ProfileLeaseV2::parse(LeaseOrigin::PublishCreate, &bytes).unwrap(),
            l
        );
        // The two origins are told apart by their domains.
        assert!(ProfileLeaseV2::parse(LeaseOrigin::Checkout, &bytes).is_err());
        for reason_code in ReleaseReason::ALL {
            let r = ReleaseLeaseV2 {
                profile: P,
                lease: L,
                reason_code,
            };
            assert_eq!(ReleaseLeaseV2::parse(&r.encode()).unwrap(), r);
        }
        let r = LeaseReleasedV2 {
            profile: P,
            lease: L,
            released_at_ms: 9,
            server_instance_id: [6; 16],
            restore_epoch: 1,
        };
        assert_eq!(LeaseReleasedV2::parse(&r.encode()).unwrap(), r);
        let r = LeaseRenewV2 {
            profile: P,
            lease: L,
            requested_lease_ttl_seconds: 900,
        };
        assert_eq!(LeaseRenewV2::parse(&r.encode()).unwrap(), r);
        let r = LeaseRenewedV2 {
            profile: P,
            lease: L,
            expires_at_ms: 10,
        };
        assert_eq!(LeaseRenewedV2::parse(&r.encode()).unwrap(), r);
    }

    fn upload() -> CreateUploadV2 {
        CreateUploadV2 {
            profile: P,
            snapshot_id: [10; 16],
            manifest_replay_id: [11; 16],
            lease: L,
            intent_hash: [12; 32],
            preamble_sha256: [13; 32],
            dek_slot_sha256: [14; 32],
            fkek_key_id: [5; 32],
            key_generation: 1,
            expected_ciphertext_size: 4096,
            expected_ciphertext_sha256: [15; 32],
        }
    }

    #[test]
    fn the_upload_maps_round_trip_and_fix_their_constants() {
        let u = upload();
        assert_eq!(CreateUploadV2::parse(&u.encode()).unwrap(), u);
        for size in [0, MAX_OBJECT_SIZE + 1] {
            let bad = edit(&u.encode(), |e| {
                set(e, "expected_ciphertext_size", c::u(size))
            });
            assert!(CreateUploadV2::parse(&bad).is_err(), "{size}");
        }
        let ok = edit(&u.encode(), |e| {
            set(e, "expected_ciphertext_size", c::u(MAX_OBJECT_SIZE))
        });
        assert!(CreateUploadV2::parse(&ok).is_ok());

        let created = UploadCreatedV2 {
            terms: u,
            upload_id: [16; 16],
            expires_at_ms: 9,
            server_instance_id: [6; 16],
            restore_epoch: 1,
        };
        let bytes = created.encode();
        assert_eq!(UploadCreatedV2::parse(&bytes).unwrap(), created);
        for (field, v) in [("committed_offset", c::u(1)), ("state", c::t("READY"))] {
            let bad = edit(&bytes, |e| set(e, field, v));
            assert!(UploadCreatedV2::parse(&bad).is_err(), "{field}");
        }

        let ready = UploadFinalizedV2 {
            upload_id: [16; 16],
            snapshot_id: [10; 16],
            manifest_replay_id: [11; 16],
            ciphertext_size: 4096,
            ciphertext_sha256: [15; 32],
            object_receipt_id: [17; 16],
            server_instance_id: [6; 16],
            restore_epoch: 1,
        };
        let bytes = ready.encode();
        assert_eq!(UploadFinalizedV2::parse(&bytes).unwrap(), ready);
        let bad = edit(&bytes, |e| set(e, "state", c::t("OPEN")));
        assert!(UploadFinalizedV2::parse(&bad).is_err());
    }

    #[test]
    fn bounds_and_optional_fields_are_exact() {
        let p = publish().encode();
        for (field, v) in [
            ("requested_lease_ttl_seconds", c::u(29)),
            ("requested_lease_ttl_seconds", c::u(901)),
            ("label_ciphertext", c::b(&[])),
            ("label_ciphertext", c::b(&[0; MAX_LABEL_CIPHERTEXT + 1])),
            ("version", c::u(3)),
        ] {
            let bad = edit(&p, |e| set(e, field, v));
            assert!(ProfilePublishCreateV2::parse(&bad).is_err(), "{field}");
        }
        let extra = edit(&p, |e| set(e, "extra", c::u(1)));
        assert!(ProfilePublishCreateV2::parse(&extra).is_err());
        for ttl in [30, 900] {
            let ok = edit(&p, |e| set(e, "requested_lease_ttl_seconds", c::u(ttl)));
            assert!(ProfilePublishCreateV2::parse(&ok).is_ok());
        }

        // A head is named iff the version is not 0.
        let checkout = |version: u64, head: Option<[u8; 32]>| {
            let mut map = P.head(DOMAIN_CHECKOUT_REQUEST);
            map.push(("observed_version", c::u(version)));
            if let Some(h) = &head {
                map.push(("observed_signed_head_hash", c::b(h)));
            }
            map.push(("requested_lease_ttl_seconds", c::u(60)));
            ProfileCheckoutV2::parse(&c::encode(&c::m(map)))
        };
        assert!(checkout(0, Some([8; 32])).is_err());
        assert!(checkout(2, None).is_err());
        for (base, head) in [(0, Some([8; 32])), (2, None)] {
            let bad = lease(base, head).encode(LeaseOrigin::Checkout);
            assert!(ProfileLeaseV2::parse(LeaseOrigin::Checkout, &bad).is_err());
        }
        // A publish grants base 0 only.
        let bad = lease(2, Some([8; 32])).encode(LeaseOrigin::PublishCreate);
        assert!(ProfileLeaseV2::parse(LeaseOrigin::PublishCreate, &bad).is_err());

        let release = ReleaseLeaseV2 {
            profile: P,
            lease: L,
            reason_code: ReleaseReason::UserRelease,
        }
        .encode();
        let bad = edit(&release, |e| set(e, "reason_code", c::t("expired")));
        assert!(ReleaseLeaseV2::parse(&bad).is_err());
    }

    fn unbound(remote_version: u64, head: Option<[u8; 32]>) -> UnboundBinding {
        UnboundBinding {
            server_id: "a1".repeat(16),
            server_instance_id: [6; 16],
            restore_epoch: 1,
            tenant_id: P.tenant_id,
            fleet_id: P.fleet_id,
            remote_profile_id: P.profile_id,
            local_profile_id: "local-profile".into(),
            remote_version,
            expected_signed_head_hash: head,
        }
    }

    fn tombstone(remote_version: u64, head: Option<[u8; 32]>) -> LocalBindingTombstoneV2 {
        LocalBindingTombstoneV2 {
            binding: unbound(remote_version, head),
            unbind_idempotency_key: [18; 16],
            completed_at_ms: 1_800_000_000_000,
        }
    }

    /// ADR 0002 D-7 vectors at `remote_version` 0 (head omitted) and 7, and
    /// the tombstone hash as the length-prefixed domain hash of its bytes.
    #[test]
    fn the_unbind_maps_round_trip_and_pin_the_tombstone() {
        let mut pinned = Vec::new();
        for (version, head) in [(0, None), (7, Some([8; 32]))] {
            let t = tombstone(version, head);
            let bytes = t.encode();
            assert_eq!(LocalBindingTombstoneV2::parse(&bytes).unwrap(), t);
            let mut pre = L_LOCAL_BINDING_TOMBSTONE.as_bytes().to_vec();
            pre.extend((bytes.len() as u32).to_be_bytes());
            pre.extend(&bytes);
            assert_eq!(t.hash(), c::sha256(&pre));
            let r = LocalUnbindV2 {
                binding: t.binding.clone(),
            };
            assert_eq!(LocalUnbindV2::parse(&r.encode()).unwrap(), r);
            let resp = t.response();
            assert_eq!(resp.binding_tombstone_sha256, t.hash());
            assert_eq!(LocalUnboundV2::parse(&resp.encode()).unwrap(), resp);
            pinned.push(hex(&c::sha256(&bytes)));
            pinned.push(hex(&t.hash()));
            pinned.push(hex(&c::sha256(&r.encode())));
            pinned.push(hex(&c::sha256(&resp.encode())));
        }
        // Regression vectors pinned at this commit: per version, SHA-256 of
        // the tombstone, its D-7 hash, SHA-256 of the request and response.
        assert_eq!(
            pinned,
            [
                "774ce58878b464ddb29e9f5f19b021d57dacc136e664d8c2531b36dd9f42116d",
                "97ad1c4f2ebe14de0dfd925d3c5a034ee5a1f94cba3ebf3b9e0babdaa8f3eccf",
                "117cd4389450afb4586b626f6f348f4937a1446a41c2e7287f5035af0fe58b09",
                "9207be88e317e744c1db5d1c59b0327404100e3c33363f7fc8c381ad678f56ed",
                "879440b49881303deb78f9c8f6942724dec17cb3dbc98c3132a699f33fd60bca",
                "65af66e2f3560b5e2d631162783ed282c1aa4285329111659039f41f8afb1f44",
                "cb67fc13ffbeae8c7342dd1d50c7071d789d324706268ae83d6d6077676a83b9",
                "60f425b9ffae2a00d7d01679df6c4e584a6a453c77573804a27e0fe4a2df6c50",
            ]
        );
        // The three maps are told apart by their domains.
        let t = tombstone(0, None).encode();
        assert!(LocalUnboundV2::parse(&t).is_err());
        assert!(LocalUnbindV2::parse(&t).is_err());
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// D-7 negatives: a head at 0 or none at 7, a 256-byte local ID, an
    /// empty server ID; and every closed-map refusal of the three maps.
    #[test]
    fn the_unbind_maps_refuse_what_l953_does_not_allow() {
        let base = [
            tombstone(7, Some([8; 32])).encode(),
            LocalUnbindV2 {
                binding: unbound(7, Some([8; 32])),
            }
            .encode(),
            tombstone(7, Some([8; 32])).response().encode(),
        ];
        let parse = |i: usize, b: &[u8]| match i {
            0 => LocalBindingTombstoneV2::parse(b).is_ok(),
            1 => LocalUnbindV2::parse(b).is_ok(),
            _ => LocalUnboundV2::parse(b).is_ok(),
        };
        for (i, bytes) in base.iter().enumerate() {
            assert!(parse(i, bytes), "{i}");
            for (field, v) in [
                ("server_id", c::t("")),
                ("server_id", c::t(&"s".repeat(MAX_SERVER_ID + 1))),
                ("local_profile_id", c::t("")),
                (
                    "local_profile_id",
                    c::t(&"l".repeat(MAX_LOCAL_PROFILE_ID + 1)),
                ),
                ("remote_version", c::u(0)),
                ("version", c::u(3)),
                ("server_instance_id", c::b(&[6; 15])),
                ("remote_profile_id", c::t("profile")),
                ("extra", c::u(1)),
            ] {
                let bad = edit(bytes, |e| set(e, field, v));
                assert!(!parse(i, &bad), "{i} {field}");
            }
            for (field, max) in [
                ("server_id", MAX_SERVER_ID),
                ("local_profile_id", MAX_LOCAL_PROFILE_ID),
            ] {
                let ok = edit(bytes, |e| set(e, field, c::t(&"x".repeat(max))));
                assert!(parse(i, &ok), "{i} {field} at its bound");
            }
            let timed = if i == 1 {
                None
            } else {
                Some("completed_at_ms")
            };
            for field in ["expected_signed_head_hash", "tenant_id"]
                .into_iter()
                .chain(timed)
            {
                let gone = edit(bytes, |e| e.retain(|(k, _)| k != field));
                assert!(!parse(i, &gone), "{i} without {field}");
            }
        }
        let at_zero = edit(&tombstone(0, None).encode(), |e| {
            set(e, "expected_signed_head_hash", c::b(&[8; 32]))
        });
        assert!(LocalBindingTombstoneV2::parse(&at_zero).is_err());
        for (field, v) in [
            ("require_no_lease", Value::Bool(false)),
            ("require_no_pending_operation", Value::Bool(false)),
            ("require_no_lease", c::u(1)),
        ] {
            let bad = edit(&base[1], |e| set(e, field, v));
            assert!(LocalUnbindV2::parse(&bad).is_err(), "{field}");
        }
        let gone = edit(&base[1], |e| e.retain(|(k, _)| k != "require_no_lease"));
        assert!(LocalUnbindV2::parse(&gone).is_err());
        let bad = edit(&base[2], |e| set(e, "unbind_outcome", c::t("released")));
        assert!(LocalUnboundV2::parse(&bad).is_err());
    }
}
