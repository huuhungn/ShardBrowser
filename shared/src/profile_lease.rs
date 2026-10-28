//! Plan 5.6.5 profile lease maps: the `PROFILE_PUBLISH_CREATE` (L948),
//! `PROFILE_CHECKOUT` (L949) and `RELEASE_LEASE` (L952) payloads and their
//! stored response payloads, and the lease renew map of L1139/L1143.
//!
//! Built like the maps in `mutation`, and wrapped the same way in an
//! `IdempotentMutationRequestV2` (renew is not: L913 has no kind for it).
//! Each `parse` checks the rules one map can decide alone (bounds, fields
//! present iff their condition). Whether the actor may run the operation, and
//! whether the payload matches live state, is the caller's to check.

use crate::authz_record::{Fields, RecordError};
use crate::canonical::{self as c, Value};
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
}
