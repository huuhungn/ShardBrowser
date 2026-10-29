//! `FleetProfilePageV2`: one page of `GET /v2/fleets/{fleet_id}/profiles`
//! (plan 8.1 L1136), the heads of a fleet's published profiles, read without a
//! lease.
//!
//! L1136 routes the list but defines no map; this one is chosen here. Each
//! entry carries what a checkout must observe (L949: the version and, past
//! version 0, the signed head hash), the profile's key generation and its
//! exact label ciphertext; never a plaintext label. Nothing here is signed: a
//! client verifies a head through the exact manifest at
//! `/v2/profiles/{profile_id}/snapshots/{version}/manifest` before it trusts
//! it. Entries are in ascending profile ID order, so the last ID names where
//! the next page starts.

use crate::authz_record::{Fields, RecordError};
use crate::canonical::{self as c, Value};
use crate::mutation::exact_version;
use crate::profile_lease::MAX_LABEL_CIPHERTEXT;

type Result<T> = std::result::Result<T, RecordError>;

pub const DOMAIN_FLEET_PROFILE_PAGE: &str = "shardx.sync.fleet-profile-page.v2";
/// At most this many profiles on one page.
pub const MAX_FLEET_PROFILE_PAGE: usize = 256;

/// One published profile's current head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetProfileHeadV2 {
    pub profile_id: [u8; 16],
    pub current_version: u64,
    /// Omitted iff `current_version` is 0.
    pub current_signed_head_hash: Option<[u8; 32]>,
    pub key_generation: u64,
    pub label_ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetProfilePageV2 {
    pub server_instance_id: [u8; 16],
    pub restore_epoch: u64,
    pub tenant_id: [u8; 16],
    pub fleet_id: [u8; 16],
    pub profiles: Vec<FleetProfileHeadV2>,
    /// The last profile ID of a full page with more after it; omitted on the
    /// last page. The next page is `?after=<it as hex>`.
    pub next_after: Option<[u8; 16]>,
}

impl FleetProfilePageV2 {
    pub fn encode(&self) -> Vec<u8> {
        let profiles = self
            .profiles
            .iter()
            .map(|p| {
                let mut map = vec![
                    ("profile_id", c::b(&p.profile_id)),
                    ("current_version", c::u(p.current_version)),
                    ("key_generation", c::u(p.key_generation)),
                    ("label_ciphertext", c::b(&p.label_ciphertext)),
                ];
                if let Some(h) = &p.current_signed_head_hash {
                    map.push(("current_signed_head_hash", c::b(h)));
                }
                c::m(map)
            })
            .collect();
        let mut map = vec![
            ("domain", c::t(DOMAIN_FLEET_PROFILE_PAGE)),
            ("version", c::u(crate::mutation::VERSION)),
            ("server_instance_id", c::b(&self.server_instance_id)),
            ("restore_epoch", c::u(self.restore_epoch)),
            ("tenant_id", c::b(&self.tenant_id)),
            ("fleet_id", c::b(&self.fleet_id)),
            ("profiles", Value::Array(profiles)),
        ];
        if let Some(a) = &self.next_after {
            map.push(("next_after", c::b(a)));
        }
        c::encode(&c::m(map))
    }

    /// Parses one exact page: bounded, ascending and unique IDs, a head hash
    /// iff past version 0, and a `next_after` only after a full page, equal to
    /// its last ID.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut f = Fields::decode("FleetProfilePageV2", bytes)?;
        exact_version(&mut f, DOMAIN_FLEET_PROFILE_PAGE)?;
        let server_instance_id = f.fixed("server_instance_id")?;
        let restore_epoch = f.uint("restore_epoch")?;
        let tenant_id = f.fixed("tenant_id")?;
        let fleet_id = f.fixed("fleet_id")?;
        let items = match f.req("profiles")? {
            Value::Array(items) if items.len() <= MAX_FLEET_PROFILE_PAGE => items,
            _ => return Err(f.bad("profiles")),
        };
        let mut profiles: Vec<FleetProfileHeadV2> = Vec::with_capacity(items.len());
        for v in items {
            let mut e = Fields::open("FleetProfileHeadV2", v)?;
            let p = FleetProfileHeadV2 {
                profile_id: e.fixed("profile_id")?,
                current_version: e.uint("current_version")?,
                key_generation: e.uint("key_generation")?,
                label_ciphertext: e.bytes("label_ciphertext", 1, MAX_LABEL_CIPHERTEXT)?,
                current_signed_head_hash: e.opt_fixed("current_signed_head_hash")?,
            };
            e.finish()?;
            if p.current_signed_head_hash.is_some() != (p.current_version != 0) {
                return Err(RecordError::BadValue("current_signed_head_hash"));
            }
            if profiles
                .last()
                .is_some_and(|l| l.profile_id >= p.profile_id)
            {
                return Err(RecordError::BadValue("profiles"));
            }
            profiles.push(p);
        }
        let next_after = f.opt_fixed("next_after")?;
        f.finish()?;
        if next_after.is_some()
            && (profiles.len() != MAX_FLEET_PROFILE_PAGE
                || next_after != profiles.last().map(|p| p.profile_id))
        {
            return Err(RecordError::BadValue("next_after"));
        }
        Ok(Self {
            server_instance_id,
            restore_epoch,
            tenant_id,
            fleet_id,
            profiles,
            next_after,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(id: u8, version: u64) -> FleetProfileHeadV2 {
        FleetProfileHeadV2 {
            profile_id: [id; 16],
            current_version: version,
            current_signed_head_hash: (version != 0).then_some([id; 32]),
            key_generation: 3,
            label_ciphertext: vec![id; 8],
        }
    }

    fn page(profiles: Vec<FleetProfileHeadV2>) -> FleetProfilePageV2 {
        FleetProfilePageV2 {
            server_instance_id: [7; 16],
            restore_epoch: 2,
            tenant_id: [1; 16],
            fleet_id: [2; 16],
            profiles,
            next_after: None,
        }
    }

    #[test]
    fn a_page_round_trips_and_every_rule_rejects() {
        let p = page(vec![head(1, 0), head(2, 5)]);
        assert_eq!(FleetProfilePageV2::parse(&p.encode()), Ok(p.clone()));

        let mut full = page((0..=255).map(|i| head(i, 1)).collect());
        assert_eq!(full.profiles.len(), MAX_FLEET_PROFILE_PAGE);
        full.next_after = Some([255; 16]);
        assert_eq!(FleetProfilePageV2::parse(&full.encode()), Ok(full.clone()));

        let bad = |p: FleetProfilePageV2, field| {
            assert_eq!(
                FleetProfilePageV2::parse(&p.encode()),
                Err(RecordError::BadValue(field))
            )
        };
        let mut x = p.clone();
        x.profiles[0].current_signed_head_hash = Some([9; 32]);
        bad(x, "current_signed_head_hash");
        let mut x = p.clone();
        x.profiles[1].current_signed_head_hash = None;
        bad(x, "current_signed_head_hash");
        bad(page(vec![head(2, 1), head(1, 1)]), "profiles");
        bad(page(vec![head(1, 1), head(1, 1)]), "profiles");
        let mut x = p.clone();
        x.next_after = Some([2; 16]);
        bad(x, "next_after");
        let mut x = full.clone();
        x.next_after = Some([0; 16]);
        bad(x, "next_after");
        let mut x = full;
        x.profiles.push(head(0, 1));
        x.next_after = None;
        assert_eq!(
            FleetProfilePageV2::parse(&x.encode()),
            Err(RecordError::BadField {
                map: "FleetProfilePageV2",
                field: "profiles"
            })
        );
    }
}
