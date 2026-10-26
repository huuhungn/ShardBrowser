//! `TenantTrustEvidencePageV2`: one page of a tenant's trust evidence (ADR
//! 0002 B2, "Evidence"; round-2 M13).
//!
//! The server pages out the full ancestry a client needs to verify custody:
//! every root grant of the tenant, and the approvals and capability grants of
//! every root grant subject and of every signer the client asks about, expired
//! and revoked records included. Containers travel as their exact signed bytes
//! and the client verifies each one itself; nothing in a page is trusted for
//! acceptance. Omitting a page can only make a client refuse, and the unsigned
//! revocation reports can only tighten.

use std::collections::BTreeSet;

use crate::authz_record::{Fields, RecordError};
use crate::canonical::{self as c, Value};

type Result<T> = std::result::Result<T, RecordError>;

pub const DOMAIN_TRUST_EVIDENCE_PAGE: &str = "shardx.trust.tenant-evidence-page.v2";
const VERSION: u64 = 2;

/// At most this many containers on one page.
pub const MAX_PAGE_CONTAINERS: usize = 1024;
/// Each container is at most this long (the bound of every grant table).
pub const MAX_CONTAINER_BYTES: usize = 131_072;
/// At most this many encoded bytes in one page.
pub const MAX_PAGE_BYTES: usize = 4 * 1024 * 1024;
/// The cursor is opaque to the client, and at most this long.
pub const MAX_CURSOR_BYTES: usize = 64;
/// A client stops at this many containers over all pages and fails closed.
pub const MAX_EVIDENCE_CONTAINERS: usize = 65_536;

/// A record the server reports revoked; it only ever tightens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokedRecord {
    pub payload_domain: String,
    pub replay_id: [u8; 16],
    pub revoked_at_ms: u64,
}

/// A device the server reports revoked; it only ever tightens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokedDevice {
    pub device_id: [u8; 16],
    pub revoked_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantTrustEvidencePageV2 {
    pub server_instance_id: [u8; 16],
    pub tenant_id: [u8; 16],
    pub server_now_ms: u64,
    pub page_index: u32,
    /// Empty on the last page.
    pub next_cursor: Vec<u8>,
    pub signing_public_keys: Vec<[u8; 32]>,
    pub containers: Vec<Vec<u8>>,
    pub revocations: Vec<RevokedRecord>,
    pub device_revocations: Vec<RevokedDevice>,
}

fn array(f: &mut Fields, field: &'static str, max: usize) -> Result<Vec<Value>> {
    match f.req(field)? {
        Value::Array(items) if items.len() <= max => Ok(items),
        _ => Err(f.bad(field)),
    }
}

/// `true` when every item is new to `seen`.
fn all_unique<T: Ord>(items: impl IntoIterator<Item = T>) -> bool {
    let mut seen = BTreeSet::new();
    items.into_iter().all(|item| seen.insert(item))
}

impl TenantTrustEvidencePageV2 {
    pub fn encode(&self) -> Vec<u8> {
        let revocations = self
            .revocations
            .iter()
            .map(|r| {
                c::m(vec![
                    ("payload_domain", c::t(&r.payload_domain)),
                    ("replay_id", c::b(&r.replay_id)),
                    ("revoked_at_ms", c::u(r.revoked_at_ms)),
                ])
            })
            .collect();
        let device_revocations = self
            .device_revocations
            .iter()
            .map(|r| {
                c::m(vec![
                    ("device_id", c::b(&r.device_id)),
                    ("revoked_at_ms", c::u(r.revoked_at_ms)),
                ])
            })
            .collect();
        c::encode(&c::m(vec![
            ("domain", c::t(DOMAIN_TRUST_EVIDENCE_PAGE)),
            ("version", c::u(VERSION)),
            ("server_instance_id", c::b(&self.server_instance_id)),
            ("tenant_id", c::b(&self.tenant_id)),
            ("server_now_ms", c::u(self.server_now_ms)),
            ("page_index", c::u(self.page_index.into())),
            ("next_cursor", c::b(&self.next_cursor)),
            (
                "signing_public_keys",
                Value::Array(self.signing_public_keys.iter().map(|k| c::b(k)).collect()),
            ),
            (
                "containers",
                Value::Array(self.containers.iter().map(|b| c::b(b)).collect()),
            ),
            ("revocations", Value::Array(revocations)),
            ("device_revocations", Value::Array(device_revocations)),
        ]))
    }

    /// Parses one exact page. The containers are only bounded here; the
    /// client parses and verifies each one under its own rules.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        const MAP: &str = "TenantTrustEvidencePageV2";
        if bytes.len() > MAX_PAGE_BYTES {
            return Err(RecordError::BadValue("page"));
        }
        let mut f = Fields::decode(MAP, bytes)?;
        f.exact_text("domain", DOMAIN_TRUST_EVIDENCE_PAGE)?;
        if f.uint("version")? != VERSION {
            return Err(RecordError::Unsupported {
                field: "version",
                id: VERSION,
            });
        }
        let server_instance_id = f.fixed("server_instance_id")?;
        let tenant_id = f.fixed("tenant_id")?;
        let server_now_ms = f.uint("server_now_ms")?;
        let page_index = u32::try_from(f.uint("page_index")?).map_err(|_| f.bad("page_index"))?;
        let next_cursor = f.bytes("next_cursor", 0, MAX_CURSOR_BYTES)?;

        let mut signing_public_keys = Vec::new();
        for v in array(&mut f, "signing_public_keys", MAX_PAGE_CONTAINERS)? {
            match v {
                Value::Bytes(k) if k.len() == 32 => {
                    signing_public_keys.push(k.try_into().expect("length checked"))
                }
                _ => return Err(f.bad("signing_public_keys")),
            }
        }
        let mut containers = Vec::new();
        for v in array(&mut f, "containers", MAX_PAGE_CONTAINERS)? {
            match v {
                Value::Bytes(b) if (1..=MAX_CONTAINER_BYTES).contains(&b.len()) => {
                    containers.push(b)
                }
                _ => return Err(f.bad("containers")),
            }
        }
        let mut revocations = Vec::new();
        for v in array(&mut f, "revocations", MAX_PAGE_CONTAINERS)? {
            let mut r = Fields::open("RevokedRecord", v)?;
            revocations.push(RevokedRecord {
                payload_domain: r.text("payload_domain")?,
                replay_id: r.fixed("replay_id")?,
                revoked_at_ms: r.uint("revoked_at_ms")?,
            });
            r.finish()?;
        }
        let mut device_revocations = Vec::new();
        for v in array(&mut f, "device_revocations", MAX_PAGE_CONTAINERS)? {
            let mut r = Fields::open("RevokedDevice", v)?;
            device_revocations.push(RevokedDevice {
                device_id: r.fixed("device_id")?,
                revoked_at_ms: r.uint("revoked_at_ms")?,
            });
            r.finish()?;
        }
        f.finish()?;

        // One entry per key, container and revoked record or device, so a
        // page never says one thing twice.
        if !all_unique(&signing_public_keys) {
            return Err(RecordError::BadValue("signing_public_keys"));
        }
        if !all_unique(&containers) {
            return Err(RecordError::BadValue("containers"));
        }
        if !all_unique(revocations.iter().map(|r| (&r.payload_domain, r.replay_id))) {
            return Err(RecordError::BadValue("revocations"));
        }
        if !all_unique(device_revocations.iter().map(|r| r.device_id)) {
            return Err(RecordError::BadValue("device_revocations"));
        }
        Ok(Self {
            server_instance_id,
            tenant_id,
            server_now_ms,
            page_index,
            next_cursor,
            signing_public_keys,
            containers,
            revocations,
            device_revocations,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn page() -> TenantTrustEvidencePageV2 {
        TenantTrustEvidencePageV2 {
            server_instance_id: [7; 16],
            tenant_id: [0x41; 16],
            server_now_ms: 1_800_000_000_000,
            page_index: 3,
            next_cursor: vec![9; 13],
            signing_public_keys: vec![[1; 32], [2; 32]],
            containers: vec![vec![0xa0, 1], vec![0xa0, 2]],
            revocations: vec![RevokedRecord {
                payload_domain: "shardx.auth.device-approval.v2".into(),
                replay_id: [5; 16],
                revoked_at_ms: 1_700_000_000_000,
            }],
            device_revocations: vec![RevokedDevice {
                device_id: [6; 16],
                revoked_at_ms: 1_700_000_000_001,
            }],
        }
    }

    const GOLDEN_PAGE: &str = "b0a739972400b7f219c74ef6ed2b46e580efefb58d0a81d9b7b28b6814c1a0f2";

    #[test]
    fn a_page_round_trips_exactly_and_is_pinned() {
        let p = page();
        let raw = p.encode();
        assert_eq!(TenantTrustEvidencePageV2::parse(&raw), Ok(p.clone()));
        assert_eq!(hex(&c::sha256(&raw)), GOLDEN_PAGE);

        // The last page has an empty cursor, and empty lists are lists.
        let last = TenantTrustEvidencePageV2 {
            next_cursor: vec![],
            signing_public_keys: vec![],
            containers: vec![],
            revocations: vec![],
            device_revocations: vec![],
            ..p
        };
        assert_eq!(TenantTrustEvidencePageV2::parse(&last.encode()), Ok(last));
    }

    #[test]
    fn a_page_says_nothing_twice_and_stays_in_its_bounds() {
        let parse = |p: &TenantTrustEvidencePageV2| TenantTrustEvidencePageV2::parse(&p.encode());
        let mut p = page();
        p.signing_public_keys.push([1; 32]);
        assert_eq!(parse(&p), Err(RecordError::BadValue("signing_public_keys")));
        let mut p = page();
        p.containers.push(vec![0xa0, 1]);
        assert_eq!(parse(&p), Err(RecordError::BadValue("containers")));
        let mut p = page();
        let again = p.revocations[0].clone();
        p.revocations.push(RevokedRecord {
            revoked_at_ms: 1,
            ..again
        });
        assert_eq!(parse(&p), Err(RecordError::BadValue("revocations")));
        let mut p = page();
        p.device_revocations.push(RevokedDevice {
            device_id: [6; 16],
            revoked_at_ms: 2,
        });
        assert_eq!(parse(&p), Err(RecordError::BadValue("device_revocations")));

        let bad = |field| {
            Err(RecordError::BadField {
                map: "TenantTrustEvidencePageV2",
                field,
            })
        };
        let mut p = page();
        p.next_cursor = vec![0; MAX_CURSOR_BYTES + 1];
        assert_eq!(parse(&p), bad("next_cursor"));
        let mut p = page();
        p.containers = vec![vec![]];
        assert_eq!(parse(&p), bad("containers"));
        let mut p = page();
        p.containers = vec![vec![1; MAX_CONTAINER_BYTES + 1]];
        assert_eq!(parse(&p), bad("containers"));
        let mut p = page();
        p.containers = (0..=MAX_PAGE_CONTAINERS as u32)
            .map(|i| i.to_be_bytes().to_vec())
            .collect();
        assert_eq!(parse(&p), bad("containers"));
        let mut p = page();
        p.containers = (0..40).map(|i| vec![i; MAX_CONTAINER_BYTES]).collect();
        assert!(p.encode().len() > MAX_PAGE_BYTES);
        assert_eq!(parse(&p), Err(RecordError::BadValue("page")));
    }

    #[test]
    fn a_page_is_a_closed_map() {
        let raw = page().encode();
        let Value::Map(mut entries) = c::decode(&raw).unwrap() else {
            panic!("a map")
        };
        let parse = |entries: &Vec<(String, Value)>| {
            TenantTrustEvidencePageV2::parse(&c::encode(&Value::Map(entries.clone())))
        };
        entries.push(("extra".into(), c::u(1)));
        assert!(matches!(
            parse(&entries),
            Err(RecordError::UnknownField { .. })
        ));
        entries.pop();
        for (field, value) in [
            ("domain", c::t("shardx.trust.other.v2")),
            ("page_index", c::u(u64::from(u32::MAX) + 1)),
            ("server_instance_id", c::b(&[7; 15])),
        ] {
            let mut edited = entries.clone();
            edited.iter_mut().find(|(k, _)| k == field).unwrap().1 = value;
            assert!(parse(&edited).is_err(), "{field}");
        }
        let mut edited = entries.clone();
        edited.retain(|(k, _)| k != "device_revocations");
        assert!(matches!(
            parse(&edited),
            Err(RecordError::MissingField { .. })
        ));
    }
}
