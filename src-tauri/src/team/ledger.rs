//! The W6 trust ledger: what this device remembers between trust-evidence
//! evaluations, so a hostile server cannot make it forget (ADR 0002 D-6,
//! Q-13, and the trust chain's verification algorithm).
//!
//! `shardx_core::trust_chain` evaluates a device without history. The launcher
//! evaluates through [`evaluate`], then runs [`record`]:
//!
//! - **Pinned anchor.** The bootstrap device pins `A0` once; a later
//!   different anchor is refused ([`pin_anchor`]). A joining device pins its
//!   own in the Q-12 join ceremony after the SAS comparison; until then it
//!   verifies nothing. A join pin never replaces an earlier pin.
//! - **First sighting.** Each container's first evaluation and local time.
//! - **Sticky proven revocation and local distrust** (D-6 (d), (e); rule 1).
//!   Once a `DeviceRevocationV2` of device `D` is counted (rule 6), or the
//!   user distrusts a key, every container signed by that key and first seen
//!   in a later evaluation is dropped, whatever its `issued_at_ms`. Containers
//!   first seen before, or in the counting evaluation itself, keep their
//!   standing ("Order"). Rows are never deleted, so an omission by the server
//!   changes nothing.
//! - **Sticky server reports.** Reported revocations are kept at their
//!   earliest time and handed back to every later evaluation: reports only
//!   tighten (ADR 0002, "Server-reported revocations only tighten").
//! - **Highest verified generation** per fleet, which never goes back
//!   ("Fleet generation freshness") and moves one step at a time.
//! - **Custodian keys** (D-6 (a)-(c)): every key a counted root grant made a
//!   custodian, with the earliest `not_before_ms` of those grants, which only
//!   moves earlier and starts the 1095-day clip of every later evaluation,
//!   the latest end, which only moves later, and the local time this device
//!   first found that known custody ended (sticky lapse, [`lapse_allows`]).
//!   That lapse is taken from history before new containers are accepted
//!   (Q-25, [`observe_lapses`]), never from the evidence being accepted.
//! - **Fleet key grants** (G2-35): the exact grant behind each collected
//!   fleet key and the pages it verified against, so sync pull reverifies it
//!   before each use ([`fleet_key_grant`], [`withdrawn`]).
//! - **Holdings and activations** (C-1, Q-18): every root or fleet
//!   generation any evaluated evidence showed a key holding, and the root
//!   generation each verified fleet activation binds, so the commit block
//!   never forgets an exposure ([`holdings`], [`commit_blocked`]).
//!
//! - **Renewed after revocation** (D-6 (a), rule 1 "Sticky proven
//!   revocation"): a self-renewal of a key with a counted
//!   `DeviceRevocationV2`, signed by that key and dropped as first seen after
//!   the count, is kept once per key in `trust_custodian_alerts`
//!   (`custodian.renewed_after_revocation`).
//! - **Closure** (D12, ADR 0002 Q-58): a not-yet-counted revocation of a key
//!   that held custody counts only in a closure evidence naming every known
//!   device signer, one complete listing per 64 of them, merged (ADR 0002
//!   Q-62, [`closure_evidence`]), so the approvals that custodian issued are
//!   first seen in the counting evaluation and keep their standing ("Order").
//!
//! Not here yet: the other custodian change events of D-6 (a), and the
//! acknowledgement of any, whose wording follows the Q-17 UX review.

use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension};
use std::collections::BTreeMap;

use shardx_core::authz_record::{
    AuthorizationRecord, Capability, DeviceRevocationReason, DeviceRevocationV2, Payload,
    RootGrantVariant, DOMAIN_DEVICE_REVOCATION, DOMAIN_TENANT_ROOT_KEY_GRANT,
};
use shardx_core::canonical::{decode, encode, Value};
use shardx_core::trust_chain::{
    Binding, Evidence, Scope, TrustChain, CLOCK_TOLERANCE_MS, MAX_CUSTODIAN_KEY_AGE_MS,
    MAX_EVIDENCE_LISTINGS,
};
use shardx_core::trust_evidence::{RevokedDevice, RevokedRecord, TenantTrustEvidencePageV2};

use super::db::Db;
use crate::fleet_client::{decode_hex16, decode_hex32, hex, FleetClient};

type Keys = BTreeMap<[u8; 32], [u8; 32]>;

/// Complete trust evidence listings, each every page of one request, in
/// order (ADR 0002 Q-62). Never concatenated: each is checked on its own.
pub type Listings = Vec<Vec<TenantTrustEvidencePageV2>>;

/// The public keys `listings` list, by the ID each hashes to.
fn keys_of(listings: &[Vec<TenantTrustEvidencePageV2>]) -> Keys {
    listings
        .iter()
        .flatten()
        .flat_map(|p| &p.signing_public_keys)
        .map(|pk| (shardx_core::keys::signing_key_id(pk), *pk))
        .collect()
}

/// A fleet key grant an evaluation accepted and opened (G2-35).
pub struct Opened<'a> {
    /// The team server the grant came from, for its `server_origins` row.
    pub server_url: &'a str,
    pub fleet_id: &'a [u8; 16],
    pub generation: u64,
    pub fkek_key_id: [u8; 32],
    /// The grant's exact container, and the listings it verified against as
    /// the server sent them.
    pub container: &'a [u8],
    pub pages: &'a [Vec<TenantTrustEvidencePageV2>],
}

fn ids(b: &Binding) -> (String, String) {
    (hex(&b.server_instance_id), hex(&b.tenant_id))
}

/// A local time or generation as the ledger stores it.
fn wire(v: u64) -> Result<i64> {
    i64::try_from(v).map_err(|_| anyhow::anyhow!("WIRE_INTEGER_OUT_OF_RANGE"))
}

/// How an anchor was pinned: by the device that bootstrapped custody, or in
/// the Q-12 join ceremony.
pub const BOOTSTRAP: &str = "BOOTSTRAP";
pub const JOIN: &str = "JOIN";

/// Pins `anchor` for `binding` with `source`, or checks it against the one
/// already pinned, whose source stays. False when another anchor is pinned:
/// a server-supplied new anchor is never accepted ("Anchor loss").
pub fn pin_anchor(
    db: &Db,
    binding: &Binding,
    anchor: &[u8; 32],
    source: &str,
    now: u64,
) -> Result<bool> {
    let (instance, tenant) = ids(binding);
    db.conn.execute(
        "INSERT INTO trust_anchors VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT DO NOTHING",
        params![instance, tenant, hex(anchor), source, wire(now)?],
    )?;
    let pinned: String = db.conn.query_row(
        "SELECT anchor_key_id FROM trust_anchors WHERE server_instance_id = ?1 AND tenant_id = ?2",
        params![instance, tenant],
        |r| r.get(0),
    )?;
    Ok(pinned == hex(anchor))
}

/// The binding, anchor and source of `tenant_id`'s pin, when this device
/// keeps exactly one for the tenant.
pub fn tenant_pin(db: &Db, tenant_id: &[u8; 16]) -> Result<Option<(Binding, [u8; 32], String)>> {
    let rows = db
        .conn
        .prepare(
            "SELECT server_instance_id, anchor_key_id, source FROM trust_anchors
             WHERE tenant_id = ?1",
        )?
        .query_map([hex(tenant_id)], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let [(instance, anchor, source)] = &rows[..] else {
        return Ok(None);
    };
    let binding = Binding {
        server_instance_id: decode_hex16(instance, "server_instance_id")?,
        tenant_id: *tenant_id,
    };
    Ok(Some((
        binding,
        decode_hex32(anchor, "anchor_key_id")?,
        source.clone(),
    )))
}

/// The highest generation of `fleet_id` this device has verified.
/// The cached `first_not_before` (D-6 (c)) of custodian key `key`, if the
/// ledger counted it.
pub fn first_not_before(db: &Db, binding: &Binding, key: &[u8; 32]) -> Result<Option<u64>> {
    let (instance, tenant) = ids(binding);
    let at: Option<i64> = db
        .conn
        .query_row(
            "SELECT first_not_before_ms FROM trust_custodian_keys
             WHERE server_instance_id = ?1 AND tenant_id = ?2 AND signing_key_id = ?3",
            params![instance, tenant, hex(key)],
            |r| r.get(0),
        )
        .optional()?;
    Ok(at.map(|at| at as u64))
}

pub fn highest_generation(db: &Db, binding: &Binding, fleet_id: &[u8; 16]) -> Result<Option<u64>> {
    let (instance, tenant) = ids(binding);
    let g: Option<i64> = db
        .conn
        .query_row(
            "SELECT highest_verified_generation FROM trust_fleet_generations
             WHERE server_instance_id = ?1 AND tenant_id = ?2 AND fleet_id = ?3",
            params![instance, tenant, hex(fleet_id)],
            |r| r.get(0),
        )
        .optional()?;
    Ok(g.map(|g| g as u64))
}

/// Whether evidence this device evaluated shows `key` holding generation
/// `generation` of `fleet_id` (C-1, `trust_key_holdings`).
pub fn holds(
    db: &Db,
    binding: &Binding,
    key: &[u8; 32],
    fleet_id: &[u8; 16],
    generation: u64,
) -> Result<bool> {
    let (instance, tenant) = ids(binding);
    Ok(db.conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM trust_key_holdings
           WHERE server_instance_id = ?1 AND tenant_id = ?2 AND signing_key_id = ?3
             AND fleet_id = ?4 AND generation = ?5)",
        params![instance, tenant, hex(key), hex(fleet_id), wire(generation)?],
        |r| r.get(0),
    )?)
}

/// Holds `key` as distrusted from now on (D-6 (d)): its records first seen
/// after the latest evaluation are ignored. The binding must be pinned. The
/// Team settings action that calls this follows the Q-17 UX review.
pub fn distrust_key(db: &Db, binding: &Binding, key: &[u8; 32], now: u64) -> Result<()> {
    let (instance, tenant) = ids(binding);
    db.conn.execute(
        "INSERT INTO trust_proven_revocations
         SELECT ?1, ?2, ?3, 'LOCAL_DISTRUST', coalesce(max(evaluation_id), 0), ?4, NULL
         FROM trust_evaluations WHERE server_instance_id = ?1 AND tenant_id = ?2
         ON CONFLICT DO NOTHING",
        params![instance, tenant, hex(key), wire(now)?],
    )?;
    Ok(())
}

/// `listings` at `now` as this device's history lets it see them: first the
/// lapses history shows ([`observe_lapses`]), then [`prepare`], and the chain
/// they verify to from `anchor`, with every key's windows clipped from its
/// cached `first_not_before` when that is earlier (D-6 (c)). `None` when they
/// do not verify.
pub fn evaluate(
    db: &Db,
    binding: &Binding,
    anchor: &[u8; 32],
    listings: &[Vec<TenantTrustEvidencePageV2>],
    now: u64,
) -> Result<Option<(Listings, TrustChain)>> {
    observe_lapses(db, binding, now)?;
    let seen = prepare(db, binding, listings, now)?;
    let Ok(mut evidence) = Evidence::collect_listings(binding, &seen) else {
        return Ok(None);
    };
    let (instance, tenant) = ids(binding);
    let mut s = db.conn.prepare(
        "SELECT signing_key_id, first_not_before_ms FROM trust_custodian_keys
         WHERE server_instance_id = ?1 AND tenant_id = ?2",
    )?;
    let mut rows = s.query(params![instance, tenant])?;
    while let Some(r) = rows.next()? {
        let key = decode_hex32(&r.get::<_, String>(0)?, "signing_key_id")?;
        evidence.remember_first_not_before(key, r.get::<_, i64>(1)? as u64);
    }
    Ok(TrustChain::evaluate(evidence, Some(anchor))
        .ok()
        .map(|chain| (seen, chain)))
}

/// Q-25, before any new container is accepted: every custodian key whose
/// known custody, from the root grants earlier evaluations counted, has
/// ended at `now` is held as lapsed as of the latest evaluation, so whatever
/// is first seen from here on meets that lapse. For such a key nothing in the
/// evidence being accepted can backdate past it or extend the key first, and
/// a key the evidence leaves out is not lapsed while its known custody runs.
///
/// Only keys an earlier evaluation counted are covered (the D-6 no-history
/// limit): a server that withheld D's root grant for all of D's window, or a
/// device offline for it, finds nothing here, so when the root grant arrives
/// later with a grant backdated into that window from D's stolen key, the
/// lapse is recorded in that accepting evaluation and the grant keeps its
/// standing.
fn observe_lapses(db: &Db, binding: &Binding, now: u64) -> Result<()> {
    let (instance, tenant) = ids(binding);
    let latest: Option<i64> = db.conn.query_row(
        "SELECT max(evaluation_id) FROM trust_evaluations
         WHERE server_instance_id = ?1 AND tenant_id = ?2",
        params![instance, tenant],
        |r| r.get(0),
    )?;
    match latest {
        Some(evaluation) => hold_lapses(&db.conn, binding, evaluation, now),
        None => Ok(()),
    }
}

/// Holds as lapsed in `evaluation`, at `now`, every custodian key of
/// `binding` not yet lapsed whose known custody, clipped at its key age, has
/// ended within the clock tolerance.
fn hold_lapses(
    conn: &rusqlite::Connection,
    binding: &Binding,
    evaluation: i64,
    now: u64,
) -> Result<()> {
    let (instance, tenant) = ids(binding);
    conn.execute(
        "UPDATE trust_custodian_keys SET lapsed_evaluation = ?3, observed_lapsed_at_ms = ?4
         WHERE server_instance_id = ?1 AND tenant_id = ?2 AND lapsed_evaluation IS NULL
           AND min(latest_not_after_ms, first_not_before_ms + ?5) <= ?6",
        params![
            instance,
            tenant,
            evaluation,
            wire(now)?,
            wire(MAX_CUSTODIAN_KEY_AGE_MS)?,
            wire(now.saturating_sub(CLOCK_TOLERANCE_MS))?
        ],
    )?;
    Ok(())
}

/// Whether an evaluation recorded here counted `key` as a root custodian's,
/// at any time (D-6 (a)).
pub fn held_custody(db: &Db, binding: &Binding, key: &[u8; 32]) -> Result<bool> {
    let (instance, tenant) = ids(binding);
    Ok(db.conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM trust_custodian_keys
           WHERE server_instance_id = ?1 AND tenant_id = ?2 AND signing_key_id = ?3)",
        params![instance, tenant, hex(key)],
        |row| row.get(0),
    )?)
}

/// Q-26: whether `key` is now proven revoked (rule 6) or locally distrusted,
/// whenever that was learned.
pub fn withdrawn(db: &Db, binding: &Binding, key: &[u8; 32]) -> Result<bool> {
    withdrawn_in(&db.conn, binding, key)
}

/// [`withdrawn`] inside the caller's transaction `tx`, so it sees what
/// [`record_in`] counted there.
pub fn withdrawn_in(tx: &rusqlite::Connection, binding: &Binding, key: &[u8; 32]) -> Result<bool> {
    let (instance, tenant) = ids(binding);
    Ok(tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM trust_proven_revocations
         WHERE server_instance_id = ?1 AND tenant_id = ?2 AND signing_key_id = ?3)",
        params![instance, tenant, hex(key)],
        |r| r.get(0),
    )?)
}

/// Q-25: when this device observed `key` lapse, if it did. Anything it first
/// sees from `key` from now on and dated at or before then is refused, as
/// [`lapse_allows`] refuses a container; a later date still needs custody
/// after the lapse, which only a re-appointment gives.
pub fn lapsed_at(db: &Db, binding: &Binding, key: &[u8; 32]) -> Result<Option<u64>> {
    let (instance, tenant) = ids(binding);
    let at: Option<Option<i64>> = db
        .conn
        .query_row(
            "SELECT observed_lapsed_at_ms FROM trust_custodian_keys
             WHERE server_instance_id = ?1 AND tenant_id = ?2 AND signing_key_id = ?3",
            params![instance, tenant, hex(key)],
            |r| r.get(0),
        )
        .optional()?;
    Ok(at.flatten().map(|ms| ms as u64))
}

/// `pages` as this device's history lets it see them: containers signed by a
/// proven-revoked or distrusted key and not seen by the evaluation that
/// counted it are dropped, so are those sticky lapse refuses
/// ([`lapse_allows`]), and every revocation the server ever reported is
/// reported again. A dropped self-renewal of a revoked key raises its alert
/// at `now` ([`renewed_after_revocation`]).
fn prepare(
    db: &Db,
    binding: &Binding,
    listings: &[Vec<TenantTrustEvidencePageV2>],
    now: u64,
) -> Result<Listings> {
    let (instance, tenant) = ids(binding);
    let mut cutoffs = BTreeMap::new();
    {
        let mut s = db.conn.prepare(
            "SELECT signing_key_id, min(counted_evaluation) FROM trust_proven_revocations
             WHERE server_instance_id = ?1 AND tenant_id = ?2 GROUP BY signing_key_id",
        )?;
        let mut rows = s.query(params![instance, tenant])?;
        while let Some(r) = rows.next()? {
            cutoffs.insert(r.get::<_, String>(0)?, r.get::<_, i64>(1)?);
        }
    }
    // `cutoffs` has no source: only a counted revocation, not local distrust,
    // raises an alert, for a container first seen after it counted.
    let revoked: BTreeMap<String, i64> = db
        .conn
        .prepare(
            "SELECT signing_key_id, min(counted_evaluation) FROM trust_proven_revocations
             WHERE server_instance_id = ?1 AND tenant_id = ?2 AND source = 'DEVICE_REVOCATION'
             GROUP BY signing_key_id",
        )?
        .query_map(params![instance, tenant], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let mut lapses = BTreeMap::new();
    {
        let mut s = db.conn.prepare(
            "SELECT signing_key_id, lapsed_evaluation, observed_lapsed_at_ms
             FROM trust_custodian_keys WHERE server_instance_id = ?1 AND tenant_id = ?2
             AND lapsed_evaluation IS NOT NULL",
        )?;
        let mut rows = s.query(params![instance, tenant])?;
        while let Some(r) = rows.next()? {
            let at = r.get::<_, i64>(2)? as u64;
            lapses.insert(r.get::<_, String>(0)?, (r.get::<_, i64>(1)?, at));
        }
    }
    let keys = keys_of(listings);
    let mut first_seen = db.conn.prepare(
        "SELECT first_seen_evaluation FROM trust_sightings
         WHERE server_instance_id = ?1 AND tenant_id = ?2 AND signed_container_hash = ?3",
    )?;
    let mut out = listings.to_vec();
    for page in out.iter_mut().flatten() {
        let mut kept = Vec::with_capacity(page.containers.len());
        for c in std::mem::take(&mut page.containers) {
            if let Ok(r) = AuthorizationRecord::parse(&c) {
                let seen: Option<i64> = first_seen
                    .query_row(
                        params![instance, tenant, hex(r.signed_container_hash())],
                        |row| row.get(0),
                    )
                    .optional()?;
                let issuer = hex(r.issuer_signing_key_id());
                if let Some(&cutoff) = cutoffs.get(&issuer) {
                    if !seen.is_some_and(|s| s <= cutoff) {
                        if revoked
                            .get(&issuer)
                            .is_some_and(|&at| !seen.is_some_and(|s| s <= at))
                        {
                            renewed_after_revocation(db, binding, &keys, r, now)?;
                        }
                        continue;
                    }
                }
                if !lapse_allows(&lapses, &keys, r, seen) {
                    continue;
                }
            }
            kept.push(c);
        }
        page.containers = kept;
    }
    // The merge counts a report from any listing: the first page carries them.
    let Some(first) = out.first_mut().and_then(|l| l.first_mut()) else {
        return Ok(out);
    };
    let mut s = db.conn.prepare(
        "SELECT payload_domain, replay_id, revoked_at_ms FROM trust_reported_revocations
         WHERE server_instance_id = ?1 AND tenant_id = ?2",
    )?;
    let mut rows = s.query(params![instance, tenant])?;
    while let Some(r) = rows.next()? {
        first.revocations.push(RevokedRecord {
            payload_domain: r.get(0)?,
            replay_id: decode_hex16(&r.get::<_, String>(1)?, "replay_id")?,
            revoked_at_ms: r.get::<_, i64>(2)? as u64,
        });
    }
    let mut s = db.conn.prepare(
        "SELECT device_id, revoked_at_ms FROM trust_reported_device_revocations
         WHERE server_instance_id = ?1 AND tenant_id = ?2",
    )?;
    let mut rows = s.query(params![instance, tenant])?;
    while let Some(r) = rows.next()? {
        first.device_revocations.push(RevokedDevice {
            device_id: decode_hex16(&r.get::<_, String>(0)?, "device_id")?,
            revoked_at_ms: r.get::<_, i64>(1)? as u64,
        });
    }
    Ok(out)
}

/// D-6 (a) and rule 1, "Sticky proven revocation": `r`, dropped because its
/// issuer `D` has a counted `DeviceRevocationV2`, raises
/// `custodian.renewed_after_revocation` when it verifies under D's key from
/// `keys` and is a root grant renewing D itself. One row per key, keeping
/// the first container, so a server cannot grow or rewrite the table.
fn renewed_after_revocation(
    db: &Db,
    binding: &Binding,
    keys: &Keys,
    r: AuthorizationRecord,
    now: u64,
) -> Result<()> {
    let issuer = *r.issuer_signing_key_id();
    let container = hex(r.signed_container_hash());
    let Some(Ok(verified)) = keys.get(&issuer).map(|pk| r.verify_signature(pk)) else {
        return Ok(());
    };
    let Payload::TenantRootKeyGrant(g) = verified.payload() else {
        return Ok(());
    };
    if g.variant == RootGrantVariant::FirstRootSelfGrant || g.subject_signing_key_id != issuer {
        return Ok(());
    }
    let (instance, tenant) = ids(binding);
    db.conn.execute(
        "INSERT INTO trust_custodian_alerts(server_instance_id, tenant_id, kind, signing_key_id,
           signed_container_hash, raised_at_ms)
         SELECT ?1, ?2, 'custodian.renewed_after_revocation', ?3, ?4, ?5
         WHERE NOT EXISTS (SELECT 1 FROM trust_custodian_alerts
           WHERE server_instance_id = ?1 AND tenant_id = ?2
             AND kind = 'custodian.renewed_after_revocation' AND signing_key_id = ?3)",
        params![instance, tenant, hex(&issuer), container, wire(now)?],
    )?;
    Ok(())
}

/// D-6 (b), sticky lapse, for `record` first seen in evaluation `seen`. Once
/// this device found that a key's known custody had ended (`lapses`:
/// the observing evaluation and its local time), a container first seen in a
/// later evaluation:
/// - signed by that key counts only when its `issued_at_ms` is after the
///   observed lapse, so a record backdated into the key's old windows is
///   refused whatever time it claims, and a later one still needs custody
///   after the lapse, which only a re-appointment or a window this device
///   already held gives;
/// - extending that key counts only as a re-appointment: another issuer, and
///   an `issued_at_ms` after the observed lapse.
///
/// Containers first seen no later than the observing evaluation keep their
/// standing, as with a counted revocation ("Order", Q-19 (A)). A container
/// whose signature does not verify is left to the chain, which drops it.
fn lapse_allows(
    lapses: &BTreeMap<String, (i64, u64)>,
    keys: &Keys,
    record: AuthorizationRecord,
    seen: Option<i64>,
) -> bool {
    let lapsed_before = |key: &[u8; 32]| {
        lapses
            .get(&hex(key))
            .filter(|(evaluation, _)| !seen.is_some_and(|s| s <= *evaluation))
            .map(|&(_, at)| at)
    };
    let issuer = *record.issuer_signing_key_id();
    let signer_lapse = lapsed_before(&issuer);
    if signer_lapse.is_none() && record.payload_domain() != DOMAIN_TENANT_ROOT_KEY_GRANT {
        return true;
    }
    let Some(verified) = keys
        .get(&issuer)
        .and_then(|pk| record.verify_signature(pk).ok())
    else {
        return true;
    };
    let issued = verified.payload().common().issued_at_ms;
    if signer_lapse.is_some_and(|at| issued <= at) {
        return false;
    }
    match verified.payload() {
        Payload::TenantRootKeyGrant(g) => lapsed_before(&g.subject_signing_key_id)
            .is_none_or(|at| g.subject_signing_key_id != issuer && issued > at),
        _ => true,
    }
}

/// `evidence_pages` as [`record_in`] keeps them: one listing as a CBOR array
/// of page bytes (the v2.10 shape), several as an array of such arrays.
/// `None` when the bytes are neither.
fn stored_listings(bytes: &[u8]) -> Option<Listings> {
    let Ok(Value::Array(items)) = decode(bytes) else {
        return None;
    };
    let pages = |items: Vec<Value>| -> Option<Vec<TenantTrustEvidencePageV2>> {
        items
            .into_iter()
            .map(|item| match item {
                Value::Bytes(b) => TenantTrustEvidencePageV2::parse(&b).ok(),
                _ => None,
            })
            .collect()
    };
    if !matches!(items.first(), Some(Value::Array(_))) {
        return Some(vec![pages(items)?]);
    }
    items
        .into_iter()
        .map(|item| match item {
            Value::Array(listing) => pages(listing),
            _ => None,
        })
        .collect()
}

/// G2-35: the exact grant kept for `generation` of `fleet_id` and the
/// listings it was accepted from, when `anchor` is the one pinned for
/// `binding`.
pub fn fleet_key_grant(
    db: &Db,
    binding: &Binding,
    anchor: &[u8; 32],
    fleet_id: &[u8; 16],
    generation: u64,
) -> Result<Option<(Vec<u8>, Listings)>> {
    let (instance, tenant) = ids(binding);
    let row: Option<(Vec<u8>, Vec<u8>)> = db
        .conn
        .query_row(
            "SELECT g.exact_signed_container_bytes, g.evidence_pages
             FROM trust_fleet_key_grants g JOIN trust_anchors a
               USING (server_instance_id, tenant_id)
             WHERE g.server_instance_id = ?1 AND g.tenant_id = ?2 AND a.anchor_key_id = ?3
               AND g.fleet_id = ?4 AND g.generation = ?5",
            params![
                instance,
                tenant,
                hex(anchor),
                hex(fleet_id),
                wire(generation)?
            ],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((container, pages)) = row else {
        return Ok(None);
    };
    let pages = stored_listings(&pages)
        .ok_or_else(|| anyhow!(crate::errcode::code("team.trustLedgerUnreadable")))?;
    Ok(Some((container, pages)))
}

/// A key's hold on a generation (ADR 0002 C-1): a root generation (`None`),
/// or a generation of the fleet named.
pub(crate) type Holding = ([u8; 32], Option<[u8; 16]>, u64);

/// C-1 "exposed": every key that a container of `binding` in `pages`, signed
/// by a key the pages list, shows holding a generation. Issuer and subject
/// of a `DeviceHpkeGrant` or root grant hold its generation; the issuer of a
/// `RecoveryGrant` holds its fleet generation and the root generation it is
/// wrapped under; the issuer of a fleet `RotationGrant` holds its generation.
/// Whoever issues a key-carrying grant holds the key.
pub(crate) fn holdings(
    binding: &Binding,
    pages: &[Vec<TenantTrustEvidencePageV2>],
) -> std::collections::BTreeSet<Holding> {
    let keys = keys_of(pages);
    let mut out = std::collections::BTreeSet::new();
    for c in pages.iter().flatten().flat_map(|p| &p.containers) {
        let Ok(r) = AuthorizationRecord::parse(c) else {
            continue;
        };
        let issuer = *r.issuer_signing_key_id();
        let Some(Ok(v)) = keys.get(&issuer).map(|pk| r.verify_signature(pk)) else {
            continue;
        };
        let p = v.payload();
        if p.common().tenant_id != binding.tenant_id
            || p.common().server_instance_id != binding.server_instance_id
        {
            continue;
        }
        match p {
            Payload::DeviceHpkeGrant(g) => {
                out.insert((issuer, Some(g.fleet_id), g.generation));
                out.insert((g.subject_signing_key_id, Some(g.fleet_id), g.generation));
            }
            Payload::RecoveryGrant(g) => {
                out.insert((issuer, Some(g.fleet_id), g.generation));
                out.insert((issuer, None, g.recipient_root_generation));
            }
            Payload::RotationGrant(g) => {
                out.insert((issuer, Some(g.fleet_id), g.generation));
            }
            Payload::TenantRootKeyGrant(g) => {
                out.insert((issuer, None, g.root_generation));
                out.insert((g.subject_signing_key_id, None, g.root_generation));
            }
            _ => {}
        }
    }
    out
}

/// C-1's client test for the root clause: for each fleet `RotationGrant` in
/// `seen` signed by a custodian holding `key.rotate` over its fleet when it
/// was issued, the fleet, generation and key it activates and the root
/// generation of the `RecoveryGrant` it binds by hash, when that grant is in
/// `seen` and names the same fleet, generation and key.
fn activations(
    chain: &TrustChain,
    binding: &Binding,
    seen: &[Vec<TenantTrustEvidencePageV2>],
) -> Vec<([u8; 16], u64, [u8; 32], u64)> {
    let keys = keys_of(seen);
    let mut recoveries = BTreeMap::new();
    let mut rotations = Vec::new();
    for c in seen.iter().flatten().flat_map(|p| &p.containers) {
        let Ok(r) = AuthorizationRecord::parse(c) else {
            continue;
        };
        let (issuer, hash) = (*r.issuer_signing_key_id(), *r.signed_container_hash());
        let Some(Ok(v)) = keys.get(&issuer).map(|pk| r.verify_signature(pk)) else {
            continue;
        };
        let common = v.payload().common();
        if common.tenant_id != binding.tenant_id
            || common.server_instance_id != binding.server_instance_id
        {
            continue;
        }
        match v.payload() {
            Payload::RecoveryGrant(g) => {
                recoveries.insert(hash, g.clone());
            }
            Payload::RotationGrant(g) => rotations.push((issuer, g.clone())),
            _ => {}
        }
    }
    rotations
        .into_iter()
        .filter(|(issuer, g)| {
            let t = g.common.issued_at_ms;
            chain.custodian_at(issuer, t)
                && chain.capability_at(issuer, Capability::KeyRotate, Scope::Fleet(g.fleet_id), t)
        })
        .filter_map(|(_, g)| {
            let r = recoveries.get(&g.recovery_grant_signed_container_hash)?;
            (r.fleet_id == g.fleet_id
                && r.generation == g.generation
                && r.fkek_key_id == g.fkek_key_id)
                .then_some((
                    g.fleet_id,
                    g.generation,
                    g.fkek_key_id,
                    r.recipient_root_generation,
                ))
        })
        .collect()
}

/// Files `held` as first seen in `evaluation`; a holding already filed keeps
/// its first evaluation.
fn file_holdings(
    tx: &rusqlite::Connection,
    binding: &Binding,
    held: &std::collections::BTreeSet<Holding>,
    evaluation: i64,
) -> Result<()> {
    let (instance, tenant) = ids(binding);
    for (key, fleet, generation) in held {
        // A generation past i64::MAX names no key a commit can use.
        let Ok(generation) = wire(*generation) else {
            continue;
        };
        tx.execute(
            "INSERT INTO trust_key_holdings VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT DO NOTHING",
            params![
                instance,
                tenant,
                hex(key),
                fleet.map(|f| hex(&f)).unwrap_or_default(),
                generation,
                evaluation
            ],
        )?;
    }
    Ok(())
}

/// Version 7 (G2-64 B2): the holdings of the evidence each kept fleet grant
/// verified against, as first seen in that grant's evaluation. What earlier
/// evidence held and a later collection replaced is gone; activations need
/// the trust chain, so each fleet stays flagged until it is collected again.
/// Kept pages that do not parse file nothing rather than fail the upgrade:
/// that fleet has no activation either, so Q-18 keeps it blocked.
pub(crate) fn backfill_holdings(tx: &rusqlite::Connection) -> Result<()> {
    let rows: Vec<(String, String, i64, Vec<u8>)> = tx
        .prepare(
            "SELECT server_instance_id, tenant_id, verified_evaluation, evidence_pages
             FROM trust_fleet_key_grants",
        )?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
        .collect::<rusqlite::Result<_>>()?;
    for (instance, tenant, evaluation, pages) in rows {
        let binding = Binding {
            server_instance_id: decode_hex16(&instance, "server_instance_id")?,
            tenant_id: decode_hex16(&tenant, "tenant_id")?,
        };
        let Some(pages) = stored_listings(&pages) else {
            continue;
        };
        file_holdings(tx, &binding, &holdings(&binding, &pages), evaluation)?;
    }
    Ok(())
}

/// ADR 0002 Q-18: whether this device refuses to commit under `generation`
/// of `fleet_id` because a counted `DeviceRevocationV2` with reason
/// `compromised` exposes it (C-1). Exposed means any of:
///
/// - this device verified the generation no later than it counted the
///   revocation, so a newer, unexposed generation is not yet ACTIVE here;
/// - the revoked key holds the generation, in any evidence this device ever
///   evaluated ([`holdings`]; an exposure is never forgotten);
/// - the root clause: the revoked key holds the root generation the
///   generation's activation evidence binds, or any root generation above it,
///   PREPARING included. Generation 0 has no `RotationGrant`, so its range
///   starts at the first root generation. Missing activation evidence counts
///   as flagged, and so does a revoked key this device knows as a custodian
///   but has no root holding filed for.
///
/// A revocation whose reason this device cannot verify counts as
/// `compromised`.
pub fn commit_blocked(
    db: &Db,
    binding: &Binding,
    anchor: &[u8; 32],
    fleet_id: &[u8; 16],
    generation: u64,
) -> Result<bool> {
    let unreadable = || anyhow!(crate::errcode::code("team.trustLedgerUnreadable"));
    let (instance, tenant) = ids(binding);
    let kept = fleet_key_grant(db, binding, anchor, fleet_id, generation)?;
    let row: Option<(i64, String)> = db
        .conn
        .query_row(
            "SELECT verified_evaluation, fkek_key_id FROM trust_fleet_key_grants
             WHERE server_instance_id = ?1 AND tenant_id = ?2 AND fleet_id = ?3 AND generation = ?4",
            params![instance, tenant, hex(fleet_id), wire(generation)?],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let bound: Option<i64> = match (&row, generation) {
        (_, 0) => Some(0),
        (None, _) => None,
        (Some((_, fkek)), _) => db.conn.query_row(
            "SELECT min(recipient_root_generation) FROM trust_fleet_activations
             WHERE server_instance_id = ?1 AND tenant_id = ?2 AND fleet_id = ?3
               AND generation = ?4 AND fkek_key_id = ?5",
            params![instance, tenant, hex(fleet_id), wire(generation)?, fkek],
            |r| r.get(0),
        )?,
    };
    let verified = row.map(|(v, _)| v);
    let pages = kept.map(|(_, pages)| pages).unwrap_or_default();
    let keys = keys_of(&pages);
    let payload = |c: &[u8]| {
        let r = AuthorizationRecord::parse(c).ok()?;
        let pk = keys.get(r.issuer_signing_key_id())?;
        Some(r.verify_signature(pk).ok()?.payload().clone())
    };
    let mut s = db.conn.prepare(
        "SELECT signing_key_id, counted_evaluation, exact_signed_container_bytes
         FROM trust_proven_revocations WHERE server_instance_id = ?1 AND tenant_id = ?2
           AND source = 'DEVICE_REVOCATION'",
    )?;
    let mut rows = s.query(params![instance, tenant])?;
    while let Some(r) = rows.next()? {
        let key = decode_hex32(&r.get::<_, String>(0)?, "signing_key_id")?;
        let counted: i64 = r.get(1)?;
        let container: Vec<u8> = r.get(2)?;
        // Plan L2032, G2-35: the kept container reloads as a revocation of
        // this tenant and instance, of the key its row names, or the ledger
        // is unreadable. One this device cannot verify still counts.
        let Ok(record) = AuthorizationRecord::parse(&container) else {
            return Err(unreadable());
        };
        if record.payload_domain() != DOMAIN_DEVICE_REVOCATION {
            return Err(unreadable());
        }
        match payload(&container) {
            Some(Payload::DeviceRevocation(d)) => {
                if d.subject_signing_key_id != key
                    || d.common.server_instance_id != binding.server_instance_id
                    || d.common.tenant_id != binding.tenant_id
                {
                    return Err(unreadable());
                }
                if d.reason_code != DeviceRevocationReason::Compromised {
                    continue;
                }
            }
            Some(_) => return Err(unreadable()),
            None => {}
        }
        if verified.is_none_or(|v| v <= counted) {
            return Ok(true);
        }
        let Some(bound) = bound else {
            return Ok(true);
        };
        // A known custodian with no root holding filed (a version 6 file
        // kept no holdings) holds every root generation: missing evidence.
        let held: bool = db.conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM trust_key_holdings
               WHERE server_instance_id = ?1 AND tenant_id = ?2 AND signing_key_id = ?3
                 AND ((fleet_id = ?4 AND generation = ?5) OR (fleet_id = '' AND generation >= ?6)))
             OR (EXISTS (SELECT 1 FROM trust_custodian_keys
                   WHERE server_instance_id = ?1 AND tenant_id = ?2 AND signing_key_id = ?3)
                 AND NOT EXISTS (SELECT 1 FROM trust_key_holdings
                   WHERE server_instance_id = ?1 AND tenant_id = ?2 AND signing_key_id = ?3
                     AND fleet_id = ''))",
            params![
                instance,
                tenant,
                hex(&key),
                hex(fleet_id),
                wire(generation)?,
                bound
            ],
            |r| r.get(0),
        )?;
        if held {
            return Ok(true);
        }
    }
    Ok(false)
}

/// D12: whether recording `seen`, evaluated as `chain`, at `now` would count
/// a `DeviceRevocationV2` (rule 6) of a key that held custody, one `chain`
/// counts a root grant of or this device's history keeps as a custodian, and
/// that this device does not hold withdrawn yet.
fn needs_closure(
    conn: &rusqlite::Connection,
    binding: &Binding,
    seen: &[Vec<TenantTrustEvidencePageV2>],
    chain: &TrustChain,
    now: u64,
) -> Result<bool> {
    let (instance, tenant) = ids(binding);
    let keys = keys_of(seen);
    for c in seen.iter().flatten().flat_map(|p| &p.containers) {
        let Ok(r) = AuthorizationRecord::parse(c) else {
            continue;
        };
        if r.payload_domain() != DOMAIN_DEVICE_REVOCATION {
            continue;
        }
        // As `record_in` dates it: its first sighting, or this evaluation.
        let first_seen: Option<i64> = conn
            .query_row(
                "SELECT first_seen_ms FROM trust_sightings
                 WHERE server_instance_id = ?1 AND tenant_id = ?2 AND signed_container_hash = ?3",
                params![instance, tenant, hex(r.signed_container_hash())],
                |row| row.get(0),
            )
            .optional()?;
        let first_seen = first_seen.map_or(now, |ms| ms as u64);
        let Some(d) = counted(chain, binding, &keys, r, first_seen) else {
            continue;
        };
        let key = d.subject_signing_key_id;
        if withdrawn_in(conn, binding, &key)? {
            continue;
        }
        let known: bool = conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM trust_custodian_keys
               WHERE server_instance_id = ?1 AND tenant_id = ?2 AND signing_key_id = ?3)",
            params![instance, tenant, hex(&key)],
            |row| row.get(0),
        )?;
        if known || chain.custodians().any(|(k, _, _)| *k == key) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// D12: when `listings`, evaluated at `now` to `anchor` without being recorded,
/// would count a not-yet-counted revocation of a key that held custody, the
/// signers a closure listing names: the subject of every `DeviceHpkeGrant`
/// they hold, which the server serves for every fleet grant of the tenant.
/// `None` when no closure is needed, or when they do not verify, which the
/// caller's own evaluation then refuses. Evaluating writes lapses and alerts
/// as [`evaluate`] does; nothing else is recorded.
pub fn closure_signers(
    db: &Db,
    binding: &Binding,
    anchor: &[u8; 32],
    listings: &[Vec<TenantTrustEvidencePageV2>],
    now: u64,
) -> Result<Option<std::collections::BTreeSet<[u8; 32]>>> {
    let Some((seen, chain)) = evaluate(db, binding, anchor, listings, now)? else {
        return Ok(None);
    };
    if !needs_closure(&db.conn, binding, &seen, &chain, now)? {
        return Ok(None);
    }
    let keys = keys_of(listings);
    let subjects = listings
        .iter()
        .flatten()
        .flat_map(|p| &p.containers)
        .filter_map(|c| {
            let r = AuthorizationRecord::parse(c).ok()?;
            let pk = keys.get(r.issuer_signing_key_id())?;
            let v = r.verify_signature(pk).ok()?;
            match v.payload() {
                Payload::DeviceHpkeGrant(g) => Some(g.subject_signing_key_id),
                _ => None,
            }
        })
        .collect();
    Ok(Some(subjects))
}

/// D12 (ADR 0002 Q-58): the trust evidence of `tenant` naming `named`, read
/// over the session `access`, as complete listings ([`listings_of`]) for the
/// caller to evaluate and record, and whether they are a closure listing.
/// When recording them would count a not-yet-counted revocation of a key that held
/// custody ([`closure_signers`]), it is read again, once, naming every known
/// device signer: `named` (a walk's head signers), every fleet grant
/// subject, the active rows a custodian session lists, and the signers of
/// the heads this device's bindings pin. So each approval of those devices
/// is first seen in the counting evaluation and keeps its standing. Names
/// add evidence, never trust: the listing and the manifests are the
/// server's word. More than 1024 signers fail closed with
/// `fleet.trustClosureTooLarge` (Q-62).
pub async fn closure_evidence(
    client: &FleetClient,
    access: &str,
    tenant: &str,
    db: &mut Db,
    (binding, anchor): &(Binding, [u8; 32]),
    named: &[[u8; 32]],
    now: u64,
) -> Result<(Listings, bool)> {
    let pages = listings_of(client, access, tenant, named.iter().copied().collect()).await?;
    let Some(mut signers) = closure_signers(db, binding, anchor, &pages, now)? else {
        return Ok((pages, false));
    };
    signers.extend(named);
    // Only a custodian session may list the devices: a refusal names none.
    if let Ok(rows) = client.list_tenant_devices(access, tenant).await {
        signers.extend(
            rows.iter()
                .filter(|r| r.status == "active")
                .filter_map(|r| decode_hex32(&r.signing_key_id, "signing_key_id").ok()),
        );
    }
    let (instance, tenant_hex) = ids(binding);
    let pins: Vec<(String, i64)> = db
        .conn
        .prepare(
            "SELECT remote_profile_id, remote_version FROM profile_bindings
             WHERE server_instance_id = ?1 AND tenant_id = ?2 AND remote_version > 0",
        )?
        .query_map(params![instance, tenant_hex], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    for (profile, version) in pins {
        let profile = decode_hex16(&profile, "remote_profile_id")?;
        let reply = client
            .snapshot_manifest(access, &profile, version as u64)
            .await?;
        // A manifest the server no longer serves names no one.
        if let Ok(m) = shardx_core::snapshot_v2::SignedSnapshotManifestV2::parse(&reply.body) {
            signers.insert(*m.signer_signing_key_id());
        }
    }
    let n = signers.len();
    if n > MAX_LISTED_SIGNERS {
        eprintln!("[closure] a custodian revocation to count: {n} signers, refused");
        anyhow::bail!(crate::errcode::code("fleet.trustClosureTooLarge"));
    }
    eprintln!("[closure] a custodian revocation to count: {n} signers");
    Ok((listings_of(client, access, tenant, signers).await?, true))
}

/// The most signers the evidence of one evaluation names (ADR 0002 Q-62).
pub(crate) const MAX_LISTED_SIGNERS: usize =
    crate::fleet_custody::MAX_SIGNERS * MAX_EVIDENCE_LISTINGS;

/// Q-62: one complete listing per 64 of `signers` (in key order), or one
/// listing naming none; more than [`MAX_LISTED_SIGNERS`] fail closed with
/// `fleet.trustClosureTooLarge`.
async fn listings_of(
    client: &FleetClient,
    access: &str,
    tenant: &str,
    signers: std::collections::BTreeSet<[u8; 32]>,
) -> Result<Listings> {
    if signers.len() > MAX_LISTED_SIGNERS {
        anyhow::bail!(crate::errcode::code("fleet.trustClosureTooLarge"));
    }
    let signers: Vec<[u8; 32]> = signers.into_iter().collect();
    let mut out = Vec::new();
    for chunk in signers.chunks(crate::fleet_custody::MAX_SIGNERS) {
        out.push(client.trust_evidence_of(access, tenant, chunk).await?);
    }
    if out.is_empty() {
        out.push(client.trust_evidence_of(access, tenant, &[]).await?);
    }
    Ok(out)
}

/// After `chain` evaluated `seen` (from [`evaluate`]), in one transaction:
/// a new evaluation, the first sighting of every container, the reported
/// revocations, every `DeviceRevocationV2` rule 6 counts, the custodian keys
/// with their `first_not_before` and observed lapses, and, when a grant
/// opened, its fleet's generation and the grant itself, also as a kept
/// signed authorization record (`team::records`). A not-yet-counted
/// revocation of a key that held custody is counted only when `closure`
/// says `seen` is a closure listing ([`closure_evidence`]); otherwise
/// nothing is recorded and the error is `fleet.trustClosureNeeded`.
pub fn record(
    db: &mut Db,
    binding: &Binding,
    seen: &[Vec<TenantTrustEvidencePageV2>],
    chain: &TrustChain,
    opened: Option<Opened>,
    closure: bool,
    now: u64,
) -> Result<()> {
    let tx = db.conn.transaction()?;
    record_in(&tx, binding, seen, chain, opened, closure, now)?;
    tx.commit()?;
    Ok(())
}

/// [`record`] inside the caller's transaction `tx`, so the evaluation is kept
/// with what it let the caller do.
pub fn record_in(
    tx: &rusqlite::Connection,
    binding: &Binding,
    seen: &[Vec<TenantTrustEvidencePageV2>],
    chain: &TrustChain,
    opened: Option<Opened>,
    closure: bool,
    now: u64,
) -> Result<()> {
    if !closure && needs_closure(tx, binding, seen, chain, now)? {
        anyhow::bail!(crate::errcode::code("fleet.trustClosureNeeded"));
    }
    let (instance, tenant) = ids(binding);
    tx.execute(
        "INSERT INTO trust_evaluations(server_instance_id, tenant_id, evaluated_at_ms)
         VALUES (?1, ?2, ?3)",
        params![instance, tenant, wire(now)?],
    )?;
    let evaluation = tx.last_insert_rowid();
    let keys = keys_of(seen);
    for c in seen.iter().flatten().flat_map(|p| &p.containers) {
        let Ok(r) = AuthorizationRecord::parse(c) else {
            continue;
        };
        let hash = hex(r.signed_container_hash());
        tx.execute(
            "INSERT INTO trust_sightings VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT DO NOTHING",
            params![
                instance,
                tenant,
                hash,
                hex(r.issuer_signing_key_id()),
                evaluation,
                wire(now)?
            ],
        )?;
        if r.payload_domain() != DOMAIN_DEVICE_REVOCATION {
            continue;
        }
        let first_seen_ms: i64 = tx.query_row(
            "SELECT first_seen_ms FROM trust_sightings
             WHERE server_instance_id = ?1 AND tenant_id = ?2 AND signed_container_hash = ?3",
            params![instance, tenant, hash],
            |row| row.get(0),
        )?;
        let Some(d) = counted(chain, binding, &keys, r, first_seen_ms as u64) else {
            continue;
        };
        let revoked = hex(&d.subject_signing_key_id);
        let kept: Option<Vec<u8>> = tx
            .query_row(
                "SELECT exact_signed_container_bytes FROM trust_proven_revocations
                 WHERE server_instance_id = ?1 AND tenant_id = ?2 AND signing_key_id = ?3
                   AND source = 'DEVICE_REVOCATION'",
                params![instance, tenant, revoked],
                |row| row.get(0),
            )
            .optional()?;
        let kept_compromised = |k: &[u8]| {
            AuthorizationRecord::parse(k)
                .ok()
                .and_then(|r| {
                    let pk = keys.get(r.issuer_signing_key_id())?;
                    r.verify_signature(pk).ok()
                })
                .is_some_and(|v| {
                    matches!(v.payload(), Payload::DeviceRevocation(p)
                        if p.reason_code == DeviceRevocationReason::Compromised)
                })
        };
        let Some(k) = kept.as_deref() else {
            tx.execute(
                "INSERT INTO trust_proven_revocations
                 VALUES (?1, ?2, ?3, 'DEVICE_REVOCATION', ?4, ?5, ?6) ON CONFLICT DO NOTHING",
                params![instance, tenant, revoked, evaluation, wire(now)?, c],
            )?;
            continue;
        };
        // Q-18: only a compromised revocation replaces a kept one, and only a
        // kept one that is not (verifiably) compromised, so the block starts.
        if d.reason_code != DeviceRevocationReason::Compromised || kept_compromised(k) {
            continue;
        }
        // The earliest count stays: no generation made after it went to the
        // revoked key, and the holdings clauses still catch real exposure.
        tx.execute(
            "UPDATE trust_proven_revocations SET exact_signed_container_bytes = ?4
             WHERE server_instance_id = ?1 AND tenant_id = ?2 AND signing_key_id = ?3
               AND source = 'DEVICE_REVOCATION'",
            params![instance, tenant, revoked, c],
        )?;
    }
    file_holdings(tx, binding, &holdings(binding, seen), evaluation)?;
    for (fleet, generation, fkek, root) in activations(chain, binding, seen) {
        let (Ok(generation), Ok(root)) = (wire(generation), wire(root)) else {
            continue;
        };
        // The lowest bound root generation seen: a lower one only widens the
        // range the root clause checks.
        tx.execute(
            "INSERT INTO trust_fleet_activations VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT DO UPDATE SET recipient_root_generation =
               min(recipient_root_generation, excluded.recipient_root_generation)",
            params![
                instance,
                tenant,
                hex(&fleet),
                generation,
                hex(&fkek),
                root,
                evaluation
            ],
        )?;
    }
    for r in seen.iter().flatten().flat_map(|p| &p.revocations) {
        // A time past i64::MAX revokes nothing before the year 292 million.
        let Ok(at) = i64::try_from(r.revoked_at_ms) else {
            continue;
        };
        tx.execute(
            "INSERT INTO trust_reported_revocations VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT DO UPDATE SET revoked_at_ms = min(revoked_at_ms, excluded.revoked_at_ms)",
            params![instance, tenant, r.payload_domain, hex(&r.replay_id), at],
        )?;
    }
    for d in seen.iter().flatten().flat_map(|p| &p.device_revocations) {
        let Ok(at) = i64::try_from(d.revoked_at_ms) else {
            continue;
        };
        tx.execute(
            "INSERT INTO trust_reported_device_revocations VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT DO UPDATE SET revoked_at_ms = min(revoked_at_ms, excluded.revoked_at_ms)",
            params![instance, tenant, hex(&d.device_id), at],
        )?;
    }
    // D-6 (a)-(c), from counted root grants only: the cached
    // `first_not_before` only moves earlier, the known end of custody only
    // later, and a key whose known custody (clipped at its key age) has
    // ended is held as lapsed from this evaluation on, if the history
    // `evaluate` read had not lapsed it already (Q-25). A key the server
    // leaves out keeps what this device already knows.
    for (key, first_not_before, end) in chain.custodians() {
        // A window that starts past the year 292 million is no custody yet.
        let Ok(at) = wire(first_not_before) else {
            continue;
        };
        tx.execute(
            "INSERT INTO trust_custodian_keys VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, NULL)
             ON CONFLICT DO UPDATE SET
               first_not_before_ms = min(first_not_before_ms, excluded.first_not_before_ms),
               latest_not_after_ms = max(latest_not_after_ms, excluded.latest_not_after_ms)",
            params![
                instance,
                tenant,
                hex(key),
                evaluation,
                at,
                wire(end.min(i64::MAX as u64))?
            ],
        )?;
    }
    hold_lapses(tx, binding, evaluation, now)?;
    if let Some(o) = opened {
        tx.execute(
            "INSERT INTO trust_fleet_generations VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT DO UPDATE SET highest_verified_generation =
               max(highest_verified_generation, excluded.highest_verified_generation)",
            params![instance, tenant, hex(o.fleet_id), wire(o.generation)?],
        )?;
        // shortcut: each generation keeps the whole evidence it verified
        // against, up to the client's evidence cap; keep only the grant's
        // ancestry once the signed-claim store (W6, probe 3) lands.
        let listing = |l: &[TenantTrustEvidencePageV2]| {
            Value::Array(l.iter().map(|p| Value::Bytes(p.encode())).collect())
        };
        // One listing keeps the v2.10 shape (`stored_listings`).
        let pages = encode(&match o.pages {
            [one] => listing(one),
            several => Value::Array(several.iter().map(|l| listing(l)).collect()),
        });
        // A renewed grant of the same key replaces the kept one; a grant of
        // another key never does (rule 5, `KEY_SUBSTITUTION_DETECTED`).
        tx.execute(
            "INSERT INTO trust_fleet_key_grants VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT DO UPDATE SET verified_evaluation = excluded.verified_evaluation,
               exact_signed_container_bytes = excluded.exact_signed_container_bytes,
               evidence_pages = excluded.evidence_pages
             WHERE fkek_key_id = excluded.fkek_key_id",
            params![
                instance,
                tenant,
                hex(o.fleet_id),
                wire(o.generation)?,
                hex(&o.fkek_key_id),
                evaluation,
                o.container,
                pages
            ],
        )?;
        // Probe 3 (L2032): the exact grant with every column it decides.
        super::records::keep(tx, o.server_url, o.container, now)?;
        keep_key_state(tx, &instance, &tenant, &o)?;
    }
    Ok(())
}

/// G2-36 (plan L1484, L1748): the account, device and fleet key rows a
/// binding's foreign keys name, filed with the grant that delivered the key.
/// The grant's subject is this device. The newest generation filed for a
/// fleet is its ACTIVE one and retires the one before; a renewed grant of the
/// same key moves the row to the new record, and another key of a generation
/// already filed leaves the row as filed (the grant above keeps the same rule). The account's role is the
/// least privilege: authority comes from signed capability grants, never from
/// this column. The cached key stays the one the ledger's grant verifies.
fn keep_key_state(
    tx: &rusqlite::Connection,
    instance: &str,
    tenant: &str,
    o: &Opened,
) -> Result<()> {
    let server = super::records::origin(tx, o.server_url, instance, 0)?;
    let (record, account, device, signing, hpke): (String, String, String, String, String) = tx
        .query_row(
            "SELECT record_id, subject_account_id, subject_device_id, subject_signing_key_id,
               recipient_hpke_key_id
             FROM signed_authorization_records WHERE exact_signed_container_bytes = ?1",
            [o.container],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .map_err(|_| anyhow!(crate::errcode::code("team.trustLedgerUnreadable")))?;
    let (fleet, generation) = (hex(o.fleet_id), wire(o.generation)?);
    tx.execute(
        "INSERT OR IGNORE INTO accounts VALUES (?1, ?2, ?3, ?4, 'member', 'ACTIVE')",
        params![server, tenant, account, device],
    )?;
    tx.execute(
        "INSERT OR IGNORE INTO device_state VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0)",
        params![
            server,
            tenant,
            account,
            device,
            signing,
            hpke,
            format!("device-signing.{device}"),
            format!("device-hpke.{device}")
        ],
    )?;
    let newest: bool = tx.query_row(
        "SELECT NOT EXISTS (SELECT 1 FROM fleet_key_state
           WHERE server_id = ?1 AND server_instance_id = ?2 AND tenant_id = ?3
             AND fleet_id = ?4 AND generation > ?5)",
        params![server, instance, tenant, fleet, generation],
        |r| r.get(0),
    )?;
    if newest {
        tx.execute(
            "UPDATE fleet_key_state SET state = 'RETIRED'
             WHERE server_id = ?1 AND server_instance_id = ?2 AND tenant_id = ?3
               AND fleet_id = ?4 AND state = 'ACTIVE' AND generation < ?5",
            params![server, instance, tenant, fleet, generation],
        )?;
    }
    tx.execute(
        "INSERT INTO fleet_key_state(server_id, server_instance_id, tenant_id, fleet_id,
           generation, fkek_key_id, device_id, device_hpke_grant_record_id, fkek_credential_ref,
           state, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
         ON CONFLICT DO UPDATE SET device_hpke_grant_record_id = excluded.device_hpke_grant_record_id
         WHERE fkek_key_id = excluded.fkek_key_id",
        params![
            server,
            instance,
            tenant,
            fleet,
            generation,
            hex(&o.fkek_key_id),
            device,
            record,
            format!("fleet-key.{fleet}.{}", o.generation),
            if newest { "ACTIVE" } else { "RETIRED" }
        ],
    )?;
    Ok(())
}

/// Rule 6: the signing key a usable `DeviceRevocationV2` revokes, when its
/// issuer was a custodian holding a device-scoped `device.revoke` covering
/// the subject's approval scope at its `issued_at_ms` (the fleet when every
/// approval of the subject names it, else the tenant, as the server files
/// it), and is still a custodian when this device first saw it. Its subject
/// device must be one a usable approval of its subject key names, so the
/// record revokes that key's own device; until such an approval is seen, it
/// does not count.
fn counted(
    chain: &TrustChain,
    binding: &Binding,
    keys: &BTreeMap<[u8; 32], [u8; 32]>,
    record: AuthorizationRecord,
    first_seen_ms: u64,
) -> Option<DeviceRevocationV2> {
    let issuer = *record.issuer_signing_key_id();
    let verified = record.verify_signature(keys.get(&issuer)?).ok()?;
    let Payload::DeviceRevocation(d) = verified.payload() else {
        return None;
    };
    let t = d.common.issued_at_ms;
    (d.common.tenant_id == binding.tenant_id
        && d.common.server_instance_id == binding.server_instance_id
        && chain.approves_device(&d.subject_signing_key_id, &d.subject_device_id)
        && chain.custodian_at(&issuer, t)
        && chain.capability_at(
            &issuer,
            Capability::DeviceRevoke,
            chain.revocation_scope(&d.subject_signing_key_id),
            t,
        )
        && chain.custodian_now(&issuer, first_seen_ms))
    .then(|| d.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use shardx_core::authz_record::*;
    use shardx_core::signing::Ed25519SigningKey;

    const B: Binding = Binding {
        server_instance_id: [3; 16],
        tenant_id: [2; 16],
    };
    /// When this device observed D's lapse.
    const L: u64 = 1_800_000_000_000;

    fn id(sk: &Ed25519SigningKey) -> [u8; 32] {
        shardx_core::keys::signing_key_id(sk.verifying_key().as_bytes())
    }

    fn common(replay: u8, issued: u64) -> CommonFields {
        CommonFields {
            replay_id: [replay; 16],
            tenant_id: B.tenant_id,
            issued_at_ms: issued,
            not_before_ms: issued,
            not_after_ms: issued + 1,
            server_instance_id: B.server_instance_id,
            restore_epoch: 0,
        }
    }

    /// An approval `issuer` signed at `issued`.
    fn signed_by(issuer: &Ed25519SigningKey, replay: u8, issued: u64) -> Vec<u8> {
        let a = DeviceApprovalV2 {
            common: common(replay, issued),
            subject_account_id: [6; 16],
            subject_device_id: [7; 16],
            subject_signing_key_id: [8; 32],
            subject_hpke_key_id: [9; 32],
            approval_scope_kind: ApprovalScopeKind::Tenant,
            approval_scope_id: B.tenant_id,
        };
        build_record(issuer, DOMAIN_DEVICE_APPROVAL, &a.encode())
    }

    /// A root grant from `issuer` to `subject`, issued at `issued`.
    fn extending(
        issuer: &Ed25519SigningKey,
        subject: &Ed25519SigningKey,
        replay: u8,
        issued: u64,
    ) -> Vec<u8> {
        let g = TenantRootKeyGrantV2 {
            common: common(replay, issued),
            variant: RootGrantVariant::ExistingRootGrant,
            root_key_id: [8; 32],
            root_generation: 0,
            subject_account_id: [6; 16],
            subject_device_id: [7; 16],
            subject_signing_key_id: id(subject),
            recipient_hpke_key_id: [9; 32],
            subject_device_approval_replay_id: [5; 16],
            hpke_encapped_key_bytes: [3; 32],
            hpke_wrapped_trk_bytes: [4; 48],
        };
        build_record(issuer, DOMAIN_TENANT_ROOT_KEY_GRANT, &g.encode())
    }

    fn page(keys: &[&Ed25519SigningKey], containers: Vec<Vec<u8>>) -> TenantTrustEvidencePageV2 {
        TenantTrustEvidencePageV2 {
            server_instance_id: B.server_instance_id,
            tenant_id: B.tenant_id,
            server_now_ms: L,
            page_index: 0,
            next_cursor: Vec::new(),
            signing_public_keys: keys.iter().map(|k| k.verifying_key().to_bytes()).collect(),
            containers,
            revocations: Vec::new(),
            device_revocations: Vec::new(),
        }
    }

    /// D-6 (b): D's lapse was observed in evaluation 1 at `L`. Of what is
    /// first seen afterwards, D's records count only when dated after `L`,
    /// and an extension of D only as another issuer's re-appointment dated
    /// after `L`. What evaluation 1 already saw keeps its standing, a key
    /// with no observed lapse is untouched, and a record whose signature
    /// cannot be checked is left to the chain.
    #[test]
    fn a_join_pin_never_replaces_an_earlier_pin() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open_at(&dir.path().join("t.db")).unwrap();
        let (first, other) = ([0x0a; 32], [0x0b; 32]);
        assert_eq!(tenant_pin(&db, &B.tenant_id).unwrap(), None);
        assert!(pin_anchor(&db, &B, &first, BOOTSTRAP, 1).unwrap());
        assert!(!pin_anchor(&db, &B, &other, JOIN, 2).unwrap());
        assert!(pin_anchor(&db, &B, &first, JOIN, 3).unwrap());
        assert_eq!(
            tenant_pin(&db, &B.tenant_id).unwrap(),
            Some((B, first, BOOTSTRAP.to_string()))
        );
    }

    #[test]
    fn a_lapsed_key_counts_only_after_its_observed_lapse() {
        let (d, x) = (
            Ed25519SigningKey::from_bytes(&[2; 32]),
            Ed25519SigningKey::from_bytes(&[3; 32]),
        );
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open_at(&dir.path().join("t.db")).unwrap();
        assert!(pin_anchor(&db, &B, &id(&x), BOOTSTRAP, 0).unwrap());
        let (i, t) = ids(&B);
        let (seen_then, seen_later) = (signed_by(&d, 3, L - 1), signed_by(&d, 4, L - 1));
        let hash = |c: &[u8]| {
            hex(AuthorizationRecord::parse(c)
                .unwrap()
                .signed_container_hash())
        };
        db.conn
            .execute_batch(&format!(
                "INSERT INTO trust_evaluations VALUES (1, '{i}', '{t}', 0);
                 INSERT INTO trust_evaluations VALUES (2, '{i}', '{t}', 0);
                 INSERT INTO trust_custodian_keys VALUES ('{i}', '{t}', '{d}', 1, 0, 0, 1, {L});
                 INSERT INTO trust_custodian_keys VALUES ('{i}', '{t}', '{x}', 1, 0, 0, NULL, NULL);
                 INSERT INTO trust_sightings VALUES ('{i}', '{t}', '{a}', '{d}', 1, 0);
                 INSERT INTO trust_sightings VALUES ('{i}', '{t}', '{b}', '{d}', 2, 0);",
                d = hex(&id(&d)),
                x = hex(&id(&x)),
                a = hash(&seen_then),
                b = hash(&seen_later),
            ))
            .unwrap();
        let cases = [
            (signed_by(&d, 1, L), false),
            (signed_by(&d, 2, L + 1), true),
            (seen_then, true),
            (seen_later, false),
            (extending(&x, &d, 5, L + 1), true),
            (extending(&x, &d, 6, L), false),
            (extending(&d, &d, 7, L + 1), false),
            (signed_by(&x, 8, L - 1), true),
            (extending(&x, &x, 9, L - 1), true),
        ];
        let all: Vec<Vec<u8>> = cases.iter().map(|(c, _)| c.clone()).collect();
        let kept = prepare(&db, &B, &[vec![page(&[&d, &x], all)]], 0).unwrap();
        for (c, expected) in &cases {
            assert_eq!(kept[0][0].containers.contains(c), *expected, "{}", hash(c));
        }
        let unverifiable = signed_by(&d, 10, L - 1);
        let kept = prepare(&db, &B, &[vec![page(&[&x], vec![unverifiable.clone()])]], 0).unwrap();
        assert_eq!(kept[0][0].containers, [unverifiable]);
    }

    /// C-1 "exposed", the issuer clause included: whoever issues or receives
    /// a key-carrying grant holds its generation, the issuer of a
    /// `RecoveryGrant` also holds the root generation it is wrapped under, and
    /// a root `RotationGrant`'s issuer holds the new root. Containers signed
    /// by a key the pages do not list, or of another tenant, show nothing.
    #[test]
    fn holdings_name_every_issuer_and_subject_of_a_key_carrying_grant() {
        let (d, e) = (
            Ed25519SigningKey::from_bytes(&[2; 32]),
            Ed25519SigningKey::from_bytes(&[3; 32]),
        );
        let fleet = [4; 16];
        let rotation = TenantRootKeyGrantV2 {
            common: common(1, L),
            variant: RootGrantVariant::RotationGrant {
                previous_root_key_id: [8; 32],
                previous_root_generation: 0,
            },
            root_key_id: [9; 32],
            root_generation: 1,
            subject_account_id: [6; 16],
            subject_device_id: [7; 16],
            subject_signing_key_id: id(&e),
            recipient_hpke_key_id: [9; 32],
            subject_device_approval_replay_id: [5; 16],
            hpke_encapped_key_bytes: [3; 32],
            hpke_wrapped_trk_bytes: [4; 48],
        };
        let recovery = RecoveryGrantV2 {
            common: common(2, L),
            fleet_id: fleet,
            fkek_key_id: [0x5a; 32],
            generation: 3,
            recipient_root_key_id: [9; 32],
            recipient_root_generation: 1,
            root_wrap_nonce_bytes: [1; 12],
            wrapped_fleet_key_bytes: [2; 48],
        };
        let fleet_rotation = RotationGrantV2 {
            common: common(3, L),
            fleet_id: fleet,
            fkek_key_id: [0x5a; 32],
            generation: 3,
            previous_fkek_key_id: [0x59; 32],
            previous_generation: 2,
            required_device_grant_count: 1,
            required_device_grant_set_hash: [0; 32],
            recovery_grant_signed_container_hash: [0; 32],
            activation_not_before_ms: L,
        };
        let other_tenant = TenantRootKeyGrantV2 {
            common: CommonFields {
                tenant_id: [0xee; 16],
                ..common(4, L)
            },
            ..rotation.clone()
        };
        let x = Ed25519SigningKey::from_bytes(&[4; 32]);
        let containers = vec![
            build_record(&d, DOMAIN_TENANT_ROOT_KEY_GRANT, &rotation.encode()),
            build_record(&d, DOMAIN_FLEET_KEY_GRANT_RECOVERY, &recovery.encode()),
            build_record(
                &e,
                DOMAIN_FLEET_KEY_GRANT_ROTATION,
                &fleet_rotation.encode(),
            ),
            build_record(&d, DOMAIN_TENANT_ROOT_KEY_GRANT, &other_tenant.encode()),
            extending(&x, &x, 5, L),
        ];
        let held: Vec<Holding> = holdings(&B, &[vec![page(&[&d, &e], containers)]])
            .into_iter()
            .collect();
        let mut expected = vec![
            (id(&d), None, 1),
            (id(&e), None, 1),
            (id(&d), Some(fleet), 3),
            (id(&e), Some(fleet), 3),
        ];
        expected.sort();
        assert_eq!(held, expected);
    }

    /// Version 6 to 7 (G2-64 B2): the holdings of the evidence a kept fleet
    /// grant verified against are filed as first seen in its evaluation, so
    /// an upgraded device still knows the exposures it saw.
    #[test]
    fn a_version_6_file_files_the_holdings_of_its_kept_evidence() {
        let d = Ed25519SigningKey::from_bytes(&[2; 32]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        let db = Db::open_at(&path).unwrap();
        let (i, t) = ids(&B);
        let pages = encode(&Value::Array(vec![Value::Bytes(
            page(&[&d], vec![extending(&d, &d, 1, L)]).encode(),
        )]));
        db.conn
            .execute_batch(&format!(
                "DROP TABLE trust_key_holdings;
                 DROP TABLE trust_fleet_activations;
                 DROP TABLE skipped_heads;
                 DROP TABLE trust_custodian_alerts;
                 DROP TABLE revert_swaps;
                 UPDATE schema_meta SET schema_version = 6, min_reader_version = 6;
                 INSERT INTO trust_anchors VALUES ('{i}', '{t}', '{a}', 'BOOTSTRAP', 0);
                 INSERT INTO trust_evaluations VALUES (4, '{i}', '{t}', 0);",
                a = hex(&id(&d)),
            ))
            .unwrap();
        db.conn
            .execute(
                "INSERT INTO trust_fleet_key_grants VALUES (?1, ?2, ?3, 1, ?4, 4, x'ab', ?5)",
                params![i, t, "44".repeat(16), "cd".repeat(32), pages],
            )
            .unwrap();
        drop(db);
        let db = Db::open_at(&path).unwrap();
        let rows: Vec<(String, String, i64, i64)> = db
            .conn
            .prepare(
                "SELECT signing_key_id, fleet_id, generation, first_seen_evaluation
                 FROM trust_key_holdings",
            )
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(rows, [(hex(&id(&d)), String::new(), 0, 4)]);
        let err = db
            .conn
            .execute("DELETE FROM trust_key_holdings", [])
            .unwrap_err();
        assert!(err.to_string().contains("never forgotten"), "{err}");
    }

    /// A version 6 file whose kept evidence pages do not parse still opens:
    /// that grant files no holding and no activation, so Q-18 keeps its fleet
    /// blocked, and the other kept grants are backfilled as usual.
    #[test]
    fn a_version_6_file_with_unreadable_kept_pages_still_opens() {
        let d = Ed25519SigningKey::from_bytes(&[2; 32]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        let db = Db::open_at(&path).unwrap();
        let (i, t) = ids(&B);
        let pages = encode(&Value::Array(vec![Value::Bytes(
            page(&[&d], vec![extending(&d, &d, 1, L)]).encode(),
        )]));
        db.conn
            .execute_batch(&format!(
                "DROP TABLE trust_key_holdings;
                 DROP TABLE trust_fleet_activations;
                 DROP TABLE skipped_heads;
                 DROP TABLE trust_custodian_alerts;
                 DROP TABLE revert_swaps;
                 UPDATE schema_meta SET schema_version = 6, min_reader_version = 6;
                 INSERT INTO trust_anchors VALUES ('{i}', '{t}', '{a}', 'BOOTSTRAP', 0);
                 INSERT INTO trust_evaluations VALUES (4, '{i}', '{t}', 0);",
                a = hex(&id(&d)),
            ))
            .unwrap();
        for (fleet, pages) in [
            ("44".repeat(16), b"garbage".to_vec()),
            ("45".repeat(16), pages),
        ] {
            db.conn
                .execute(
                    "INSERT INTO trust_fleet_key_grants VALUES (?1, ?2, ?3, 1, ?4, 4, x'ab', ?5)",
                    params![i, t, fleet, "cd".repeat(32), pages],
                )
                .unwrap();
        }
        drop(db);
        let db = Db::open_at(&path).unwrap();
        let count = |sql: &str| -> i64 { db.conn.query_row(sql, [], |r| r.get(0)).unwrap() };
        assert_eq!(count("SELECT count(*) FROM trust_key_holdings"), 1);
        assert_eq!(count("SELECT count(*) FROM trust_fleet_activations"), 0);
    }

    /// L-2: the instance reached through a second origin (another URL) files
    /// the key state of a new generation. The credential references name the
    /// device's and fleet's secrets, which both origins share, so they are
    /// unique per server and the second origin gets its own rows; a second
    /// row of the same server still may not take a reference already used.
    #[test]
    fn a_second_origin_of_the_instance_files_a_new_generation() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open_at(&dir.path().join("t.db")).unwrap();
        let (i, t, f) = ("33".repeat(16), "44".repeat(16), "55".repeat(16));
        super::super::db::fixtures::seed_binding(&db.conn, "s", "p", &i, &t, &f, &f, 0);
        db.conn
            .execute_batch(&format!(
                "CREATE TEMP TABLE copy AS SELECT * FROM signed_authorization_records
                   WHERE record_id = 'rec-{f}';
                 UPDATE copy SET record_id = 'rec2', generation = 2,
                   replay_id = x'{:0>32}', fkek_key_id = '{}', exact_signed_container_bytes = x'ac';
                 INSERT INTO signed_authorization_records SELECT * FROM copy;
                 DROP TABLE copy;",
                "02",
                "e2".repeat(32)
            ))
            .unwrap();
        let tx = db.conn.unchecked_transaction().unwrap();
        keep_key_state(
            &tx,
            &i,
            &t,
            &Opened {
                server_url: "https://alias.test",
                fleet_id: &decode_hex16(&f, "fleet").unwrap(),
                generation: 2,
                fkek_key_id: decode_hex32(&"e2".repeat(32), "fkek_key_id").unwrap(),
                container: &[0xac],
                pages: &[],
            },
        )
        .unwrap();
        tx.commit().unwrap();
        let count = |sql: &str| -> i64 { db.conn.query_row(sql, [], |r| r.get(0)).unwrap() };
        assert_eq!(count("SELECT count(*) FROM server_origins"), 2);
        assert_eq!(
            count(
                "SELECT count(DISTINCT server_id) FROM device_state
                 WHERE signing_credential_ref = 'device-signing.' || device_id"
            ),
            2
        );
        assert_eq!(
            count(
                "SELECT count(*) FROM fleet_key_state k JOIN server_origins o USING (server_id)
                 WHERE o.host = 'alias.test' AND k.generation = 2 AND k.state = 'ACTIVE'"
            ),
            1
        );
        // The fleet key's reference is shared the same way: the first
        // generation's row, copied to the second origin under another grant.
        db.conn
            .execute_batch(&format!(
                "CREATE TEMP TABLE copy AS SELECT * FROM signed_authorization_records
                   WHERE record_id = 'rec-{f}';
                 UPDATE copy SET record_id = 'rec3', replay_id = x'{:0>32}',
                   exact_signed_container_bytes = x'ad';
                 INSERT INTO signed_authorization_records SELECT * FROM copy;
                 DROP TABLE copy;
                 INSERT INTO fleet_key_state
                   SELECT o.server_id, k.server_instance_id, k.tenant_id, k.fleet_id,
                     k.generation, k.fkek_key_id, k.device_id, 'rec3', k.fkek_credential_ref,
                     'RETIRED', NULL, k.created_at
                   FROM fleet_key_state k, server_origins o
                   WHERE k.server_id = 's' AND k.generation = 1 AND o.host = 'alias.test';",
                "03"
            ))
            .unwrap();
        let err = db
            .conn
            .execute(
                "INSERT INTO device_state SELECT server_id, tenant_id, account_id, 'other',
                   'k1', 'k2', signing_credential_ref, 'x', 0 FROM device_state LIMIT 1",
                [],
            )
            .unwrap_err();
        assert!(err.to_string().contains("UNIQUE"), "{err}");
    }

    /// G2-36: a grant filed as opened files the account, device and fleet key
    /// rows it names. The newest generation is ACTIVE and retires the one
    /// before, an older one is filed RETIRED, a renewed grant of the same key
    /// moves the row to the new record, and another key of a filed
    /// generation leaves the row as filed.
    #[test]
    fn a_filed_grant_files_the_key_state_it_names() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open_at(&dir.path().join("t.db")).unwrap();
        let (i, t, f) = ("33".repeat(16), "44".repeat(16), "55".repeat(16));
        super::super::db::fixtures::seed_binding(&db.conn, "s", "p", &i, &t, &f, &f, 0);
        // The grants of generations 2 and 3, and a renewed one of 2, as
        // copies of the filed grant.
        for (record, replay, generation, key, container) in [
            ("rec2", "02", 2, "e2", "ac"),
            ("rec3", "03", 3, "e3", "ad"),
            ("rec2b", "04", 2, "e2", "ae"),
            ("rec2c", "05", 2, "e9", "af"),
        ] {
            db.conn
                .execute_batch(&format!(
                    "CREATE TEMP TABLE copy AS SELECT * FROM signed_authorization_records
                       WHERE record_id = 'rec-{f}';
                     UPDATE copy SET record_id = '{record}', generation = {generation},
                       replay_id = x'{replay:0>32}',
                       fkek_key_id = '{}', exact_signed_container_bytes = x'{container}';
                     INSERT INTO signed_authorization_records SELECT * FROM copy;
                     DROP TABLE copy;",
                    key.repeat(32)
                ))
                .unwrap();
        }
        let file = |generation: u64, key: &str, container: u8| {
            let fkek_key_id = decode_hex32(&key.repeat(32), "fkek_key_id").unwrap();
            keep_key_state(
                &db.conn,
                &i,
                &t,
                &Opened {
                    server_url: "https://h33333333.test",
                    fleet_id: &decode_hex16(&f, "fleet").unwrap(),
                    generation,
                    fkek_key_id,
                    container: &[container],
                    pages: &[],
                },
            )
            .unwrap();
        };
        let states = |db: &Db| -> Vec<(i64, String, String, String)> {
            db.conn
                .prepare(
                    "SELECT generation, state, device_hpke_grant_record_id, substr(fkek_key_id, 1, 2)
                     FROM fleet_key_state ORDER BY generation",
                )
                .unwrap()
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap()
        };
        let row =
            |g: i64, s: &str, r: &str, k: &str| (g, s.to_string(), r.to_string(), k.to_string());
        let first = row(1, "ACTIVE", &format!("rec-{f}"), "cd");
        assert_eq!(states(&db), [first]);
        file(2, "e2", 0xac);
        assert_eq!(
            states(&db),
            [
                row(1, "RETIRED", &format!("rec-{f}"), "cd"),
                row(2, "ACTIVE", "rec2", "e2")
            ]
        );
        file(3, "e3", 0xad);
        file(1, "cd", 0xab);
        assert_eq!(
            states(&db),
            [
                row(1, "RETIRED", &format!("rec-{f}"), "cd"),
                row(2, "RETIRED", "rec2", "e2"),
                row(3, "ACTIVE", "rec3", "e3")
            ]
        );
        // A renewed grant of generation 2's key moves its row to the new
        // record and keeps its state; another key of generation 2 changes
        // nothing.
        file(2, "e2", 0xae);
        file(2, "e9", 0xaf);
        assert_eq!(
            states(&db),
            [
                row(1, "RETIRED", &format!("rec-{f}"), "cd"),
                row(2, "RETIRED", "rec2b", "e2"),
                row(3, "ACTIVE", "rec3", "e3")
            ]
        );
        let n = |sql: &str| -> i64 { db.conn.query_row(sql, [], |r| r.get(0)).unwrap() };
        assert_eq!(n("SELECT count(*) FROM accounts"), 1);
        assert_eq!(n("SELECT count(*) FROM device_state"), 1);
    }

    // ---- v0.2.3 fleet key rotation: the analysis assumptions ----

    const FLEET: [u8; 16] = [4; 16];
    const T0: u64 = 1_800_000_000_000;
    const DAY: u64 = 86_400_000;

    fn live(replay: u8) -> CommonFields {
        CommonFields {
            not_after_ms: T0 + 300 * DAY,
            ..common(replay, T0)
        }
    }

    /// The bootstrap custodian A0 of `B`.
    struct Custodian {
        sk: Ed25519SigningKey,
        hpke_sk: zeroize::Zeroizing<Vec<u8>>,
        hpke_pk: Vec<u8>,
        to: shardx_core::trust_chain::Recipient,
    }

    fn a0() -> Custodian {
        let sk = Ed25519SigningKey::from_bytes(&[1; 32]);
        let (hpke_sk, hpke_pk) = shardx_core::grants::derive_keypair(&[7; 32]);
        let to = shardx_core::trust_chain::Recipient {
            account_id: [6; 16],
            device_id: [5; 16],
            signing_key_id: id(&sk),
            hpke_key_id: shardx_core::keys::hpke_key_id(&hpke_pk),
        };
        Custodian {
            sk,
            hpke_sk,
            hpke_pk,
            to,
        }
    }

    /// A0's D1 approval, root self-grant and fleet-scoped `fleet.manage`,
    /// with the fleet-scoped `key.rotate` the rotation files (S0) when
    /// `rotate`, and `extra`.
    fn evidence(
        a: &Custodian,
        rotate: bool,
        extra: Vec<Vec<u8>>,
    ) -> Vec<TenantTrustEvidencePageV2> {
        let to = &a.to;
        let approval = DeviceApprovalV2 {
            common: live(10),
            subject_account_id: to.account_id,
            subject_device_id: to.device_id,
            subject_signing_key_id: to.signing_key_id,
            subject_hpke_key_id: to.hpke_key_id,
            approval_scope_kind: ApprovalScopeKind::Tenant,
            approval_scope_id: B.tenant_id,
        };
        let root = TenantRootKeyGrantV2 {
            common: live(11),
            variant: RootGrantVariant::FirstRootSelfGrant,
            root_key_id: [8; 32],
            root_generation: 0,
            subject_account_id: to.account_id,
            subject_device_id: to.device_id,
            subject_signing_key_id: to.signing_key_id,
            recipient_hpke_key_id: to.hpke_key_id,
            subject_device_approval_replay_id: [10; 16],
            hpke_encapped_key_bytes: [3; 32],
            hpke_wrapped_trk_bytes: [4; 48],
        };
        let capability = |replay, capability| {
            let g = TenantCapabilityGrantV2 {
                common: live(replay),
                subject: GrantSubject::Device {
                    account_id: to.account_id,
                    device_id: to.device_id,
                    signing_key_id: to.signing_key_id,
                    hpke_key_id: to.hpke_key_id,
                },
                scope_kind: CapabilityScopeKind::Fleet,
                scope_id: FLEET,
                capability,
            };
            build_record(&a.sk, DOMAIN_TENANT_CAPABILITY_GRANT, &g.encode())
        };
        let mut containers = vec![
            build_record(&a.sk, DOMAIN_DEVICE_APPROVAL, &approval.encode()),
            build_record(&a.sk, DOMAIN_TENANT_ROOT_KEY_GRANT, &root.encode()),
            capability(12, Capability::FleetManage),
        ];
        if rotate {
            containers.push(capability(13, Capability::KeyRotate));
        }
        containers.extend(extra);
        vec![page(&[&a.sk], containers)]
    }

    /// A0's grant of `fkek` as `generation` of `FLEET` to `to`.
    fn device_grant(
        a: &Custodian,
        to: &shardx_core::trust_chain::Recipient,
        generation: u64,
        fkek: &[u8; 32],
        replay: u8,
    ) -> Vec<u8> {
        let mut g = DeviceHpkeGrantV2 {
            common: live(replay),
            fleet_id: FLEET,
            fkek_key_id: shardx_core::fleet_grants::fkek_key_id(fkek),
            generation,
            subject_account_id: to.account_id,
            subject_device_id: to.device_id,
            subject_signing_key_id: to.signing_key_id,
            recipient_hpke_key_id: to.hpke_key_id,
            hpke_encapped_key_bytes: Vec::new(),
            hpke_wrapped_fleet_key_bytes: Vec::new(),
        };
        // Sealed to A0: only the subject matters for a holding.
        shardx_core::grants::seal_device_fkek(&a.hpke_pk, &mut g, fkek).unwrap();
        build_record(&a.sk, DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE, &g.encode())
    }

    /// A0's `RecoveryGrant` of `generation` (key `fkek`) under root 0, and
    /// its own `RotationGrant` from the generation before (key `previous`)
    /// that binds it, as sequence K step 4 builds them.
    fn rotation(
        a: &Custodian,
        generation: u64,
        fkek: &[u8; 32],
        previous: &[u8; 32],
    ) -> Vec<Vec<u8>> {
        let fkek_key_id = shardx_core::fleet_grants::fkek_key_id(fkek);
        let recovery = RecoveryGrantV2 {
            common: live(60),
            fleet_id: FLEET,
            fkek_key_id,
            generation,
            recipient_root_key_id: [8; 32],
            recipient_root_generation: 0,
            root_wrap_nonce_bytes: [1; 12],
            wrapped_fleet_key_bytes: [2; 48],
        };
        let recovery = build_record(&a.sk, DOMAIN_FLEET_KEY_GRANT_RECOVERY, &recovery.encode());
        let grant = RotationGrantV2 {
            common: live(61),
            fleet_id: FLEET,
            fkek_key_id,
            generation,
            previous_fkek_key_id: shardx_core::fleet_grants::fkek_key_id(previous),
            previous_generation: generation - 1,
            required_device_grant_count: 1,
            required_device_grant_set_hash: [0; 32],
            recovery_grant_signed_container_hash: *AuthorizationRecord::parse(&recovery)
                .unwrap()
                .signed_container_hash(),
            activation_not_before_ms: T0,
        };
        let grant = build_record(&a.sk, DOMAIN_FLEET_KEY_GRANT_ROTATION, &grant.encode());
        vec![recovery, grant]
    }

    /// A0 collects its grant of `generation` (key `fkek`) from `pages`, as
    /// a new evaluation, through the launcher's own verified open.
    fn collect(
        db: &mut Db,
        a: &Custodian,
        generation: u64,
        fkek: &[u8; 32],
        replay: u8,
        mut pages: Vec<TenantTrustEvidencePageV2>,
    ) {
        let grant = device_grant(a, &a.to, generation, fkek, replay);
        pages[0].containers.push(grant.clone());
        let opened = crate::open_fleet_grant(
            &grant,
            &[pages],
            &(B, a.to.signing_key_id),
            &a.to,
            &FLEET,
            generation,
            &a.hpke_sk,
            T0 + DAY,
            db,
            "https://fleet.test",
            true,
        )
        .unwrap();
        assert!(opened.is_some(), "generation {generation} verifies");
    }

    /// Q-62: A0's grant of generation 0 in a second listing, the records
    /// that make A0 a custodian with `fleet.manage` in the first. Opened
    /// through the launcher's verified open into `db`. The listings.
    fn open_from_two_listings(db: &mut Db, a: &Custodian, fkek: &[u8; 32]) -> Listings {
        let grant = device_grant(a, &a.to, 0, fkek, 40);
        let listings = vec![
            evidence(a, false, vec![]),
            vec![page(&[&a.sk], vec![grant.clone()])],
        ];
        let opened = crate::open_fleet_grant(
            &grant,
            &listings,
            &(B, a.to.signing_key_id),
            &a.to,
            &FLEET,
            0,
            &a.hpke_sk,
            T0 + DAY,
            db,
            "https://fleet.test",
            false,
        )
        .unwrap();
        assert!(opened.is_some(), "the grant verifies across both listings");
        listings
    }

    /// The `evidence_pages` kept for generation 0 of `FLEET`.
    fn stored(db: &Db) -> Vec<u8> {
        db.conn
            .query_row(
                "SELECT evidence_pages FROM trust_fleet_key_grants WHERE generation = 0",
                [],
                |r| r.get(0),
            )
            .unwrap()
    }

    #[test]
    fn a_key_opened_from_two_listings_reverifies_from_its_stored_listings() {
        let a = a0();
        let k0 = [0x30; 32];
        let dir = tempfile::tempdir().unwrap();
        let mut db = Db::open_at(&dir.path().join("t.db")).unwrap();
        let listings = open_from_two_listings(&mut db, &a, &k0);
        let pin = (B, a.to.signing_key_id);
        let (_, kept) = fleet_key_grant(&db, &B, &pin.1, &FLEET, 0)
            .unwrap()
            .unwrap();
        assert_eq!(kept, listings, "both listings, each as served");
        assert!(
            matches!(decode(&stored(&db)), Ok(Value::Array(v)) if matches!(v[0], Value::Array(_)))
        );
        assert!(crate::fleet_key_verifies(&db, &pin, &a.to, &FLEET, 0, &k0, T0 + DAY).unwrap());
        assert!(
            !crate::fleet_key_verifies(&db, &pin, &a.to, &FLEET, 0, &[0x31; 32], T0 + DAY).unwrap()
        );
    }

    #[test]
    fn a_single_listing_is_stored_in_the_v2_10_shape() {
        let a = a0();
        let dir = tempfile::tempdir().unwrap();
        let mut db = Db::open_at(&dir.path().join("t.db")).unwrap();
        let pages = evidence(&a, false, vec![]);
        collect(&mut db, &a, 0, &[0x30; 32], 40, pages);
        let (_, kept) = fleet_key_grant(&db, &B, &a.to.signing_key_id, &FLEET, 0)
            .unwrap()
            .unwrap();
        assert_eq!(kept.len(), 1);
        // Exactly what 2.10 wrote: a CBOR array of the page bytes.
        let v2_10 = encode(&Value::Array(
            kept[0].iter().map(|p| Value::Bytes(p.encode())).collect(),
        ));
        assert_eq!(stored(&db), v2_10);
    }

    #[test]
    fn a_stored_flat_page_array_still_reads() {
        let a = a0();
        let k0 = [0x30; 32];
        let dir = tempfile::tempdir().unwrap();
        let mut db = Db::open_at(&dir.path().join("t.db")).unwrap();
        let listings = open_from_two_listings(&mut db, &a, &k0);
        // A 2.10 ledger kept one listing as a flat array of page bytes.
        let mut one = listings[0][0].clone();
        one.containers.extend(listings[1][0].containers.clone());
        let flat = encode(&Value::Array(vec![Value::Bytes(one.encode())]));
        let set = |bytes: &[u8]| {
            db.conn
                .execute(
                    "UPDATE trust_fleet_key_grants SET evidence_pages = ?1",
                    [bytes],
                )
                .unwrap();
        };
        set(&flat);
        let pin = (B, a.to.signing_key_id);
        let (_, kept) = fleet_key_grant(&db, &B, &pin.1, &FLEET, 0)
            .unwrap()
            .unwrap();
        assert_eq!(kept, vec![vec![one.clone()]]);
        assert!(crate::fleet_key_verifies(&db, &pin, &a.to, &FLEET, 0, &k0, T0 + DAY).unwrap());
        // A shape mixing a page and a listing is no ledger this launcher wrote.
        let mixed = encode(&Value::Array(vec![
            Value::Array(vec![Value::Bytes(one.encode())]),
            Value::Bytes(one.encode()),
        ]));
        set(&mixed);
        let err = fleet_key_grant(&db, &B, &pin.1, &FLEET, 0).unwrap_err();
        assert!(crate::errcode::has_code(
            &err.to_string(),
            "team.trustLedgerUnreadable"
        ));
    }

    /// Unvalidated assumption 1 (v0.2.3 analysis), first half: the evidence
    /// of a rotation by the custodian itself, with its fleet-scoped
    /// `key.rotate`, is activation evidence of the new generation under the
    /// root its recovery grant names. Without `key.rotate` it is none.
    #[test]
    fn a_custodians_own_rotation_grant_records_the_activation() {
        let a = a0();
        let (k0, k1) = ([0x30; 32], [0x31; 32]);
        let activations = |rotate: bool| -> Vec<(i64, String, i64)> {
            let dir = tempfile::tempdir().unwrap();
            let mut db = Db::open_at(&dir.path().join("t.db")).unwrap();
            collect(&mut db, &a, 0, &k0, 40, evidence(&a, rotate, vec![]));
            let more = rotation(&a, 1, &k1, &k0);
            collect(&mut db, &a, 1, &k1, 41, evidence(&a, rotate, more));
            let rows = db
                .conn
                .prepare(
                    "SELECT generation, fkek_key_id, recipient_root_generation
                     FROM trust_fleet_activations",
                )
                .unwrap()
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            rows
        };
        let k1_id = hex(&shardx_core::fleet_grants::fkek_key_id(&k1));
        assert_eq!(activations(true), [(1, k1_id, 0)]);
        assert!(
            activations(false).is_empty(),
            "no key.rotate, no activation"
        );
    }

    /// Unvalidated assumption 1, second half (ADR 0002 Q-18): a key revoked
    /// as `compromised` that holds N blocks commits under N, but not under
    /// N+1 once the custodian rotated by its own `RotationGrant` and this
    /// device verified N+1 after counting the revocation.
    #[test]
    fn a_compromised_holder_of_n_blocks_n_but_not_the_rotated_n_plus_1() {
        let a = a0();
        let x = shardx_core::trust_chain::Recipient {
            device_id: [0x77; 16],
            signing_key_id: [0x77; 32],
            ..a.to
        };
        let (k0, k1) = ([0x30; 32], [0x31; 32]);
        let dir = tempfile::tempdir().unwrap();
        let mut db = Db::open_at(&dir.path().join("t.db")).unwrap();
        let to_x = device_grant(&a, &x, 0, &k0, 42);
        collect(&mut db, &a, 0, &k0, 40, evidence(&a, true, vec![to_x]));
        let counted: i64 = db
            .conn
            .query_row(
                "SELECT verified_evaluation FROM trust_fleet_key_grants WHERE generation = 0",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let revocation = DeviceRevocationV2 {
            common: live(30),
            subject_account_id: x.account_id,
            subject_device_id: x.device_id,
            subject_signing_key_id: x.signing_key_id,
            subject_hpke_key_id: x.hpke_key_id,
            reason_code: DeviceRevocationReason::Compromised,
        };
        let container = build_record(&a.sk, DOMAIN_DEVICE_REVOCATION, &revocation.encode());
        let (i, t) = ids(&B);
        db.conn
            .execute(
                "INSERT INTO trust_proven_revocations
                 VALUES (?1, ?2, ?3, 'DEVICE_REVOCATION', ?4, 0, ?5)",
                params![i, t, hex(&x.signing_key_id), counted, container],
            )
            .unwrap();
        let anchor = a.to.signing_key_id;
        let blocked = |db: &Db, g| commit_blocked(db, &B, &anchor, &FLEET, g).unwrap();
        assert!(blocked(&db, 0), "X holds N");

        collect(
            &mut db,
            &a,
            1,
            &k1,
            41,
            evidence(&a, true, rotation(&a, 1, &k1, &k0)),
        );
        assert!(blocked(&db, 0), "N stays blocked");
        assert!(!blocked(&db, 1), "the rotated N+1 is not");
    }

    // ---- v2.10 hand-over: the assumption probes (U1) ----

    /// `live` issued and starting at `t`.
    fn live_from(replay: u8, t: u64) -> CommonFields {
        CommonFields {
            issued_at_ms: t,
            not_before_ms: t,
            ..live(replay)
        }
    }

    /// Gate G1: member M last evaluated when A0 was the only custodian. Its
    /// next evaluation first sees, together, A0's tenant approval and
    /// `ExistingRootGrant` of B, B's own `device.revoke`, and B's revocation
    /// of A0. The revocation counts, and B, first seen in that counting
    /// evaluation, keeps its custody and approval in every later evaluation
    /// ("Order"), while A0 is withdrawn.
    #[test]
    fn an_offline_member_keeps_the_new_custodian_seen_with_the_old_roots_revocation() {
        let a = a0();
        let b = Ed25519SigningKey::from_bytes(&[0x0b; 32]);
        let (b_device, b_hpke) = ([0x0b; 16], [0x0c; 32]);
        let me_b = GrantSubject::Device {
            account_id: a.to.account_id,
            device_id: b_device,
            signing_key_id: id(&b),
            hpke_key_id: b_hpke,
        };
        let capability = |issuer: &Ed25519SigningKey, subject, replay, t, capability| {
            let g = TenantCapabilityGrantV2 {
                common: live_from(replay, t),
                subject,
                scope_kind: CapabilityScopeKind::Tenant,
                scope_id: B.tenant_id,
                capability,
            };
            build_record(issuer, DOMAIN_TENANT_CAPABILITY_GRANT, &g.encode())
        };
        let me_a = GrantSubject::Device {
            account_id: a.to.account_id,
            device_id: a.to.device_id,
            signing_key_id: a.to.signing_key_id,
            hpke_key_id: a.to.hpke_key_id,
        };
        let a_approves = capability(&a.sk, me_a, 20, T0, Capability::DeviceApprove);
        let approval = DeviceApprovalV2 {
            common: live_from(21, T0 + DAY),
            subject_account_id: a.to.account_id,
            subject_device_id: b_device,
            subject_signing_key_id: id(&b),
            subject_hpke_key_id: b_hpke,
            approval_scope_kind: ApprovalScopeKind::Tenant,
            approval_scope_id: B.tenant_id,
        };
        let root = TenantRootKeyGrantV2 {
            common: live_from(22, T0 + 2 * DAY),
            variant: RootGrantVariant::ExistingRootGrant,
            root_key_id: [8; 32],
            root_generation: 0,
            subject_account_id: a.to.account_id,
            subject_device_id: b_device,
            subject_signing_key_id: id(&b),
            recipient_hpke_key_id: b_hpke,
            subject_device_approval_replay_id: [21; 16],
            hpke_encapped_key_bytes: [3; 32],
            hpke_wrapped_trk_bytes: [4; 48],
        };
        let revocation = DeviceRevocationV2 {
            common: live_from(24, T0 + 4 * DAY),
            subject_account_id: a.to.account_id,
            subject_device_id: a.to.device_id,
            subject_signing_key_id: a.to.signing_key_id,
            subject_hpke_key_id: a.to.hpke_key_id,
            reason_code: DeviceRevocationReason::Retired,
        };
        let hand_over = vec![
            build_record(&a.sk, DOMAIN_DEVICE_APPROVAL, &approval.encode()),
            build_record(&a.sk, DOMAIN_TENANT_ROOT_KEY_GRANT, &root.encode()),
            capability(&b, me_b, 23, T0 + 3 * DAY, Capability::DeviceRevoke),
            build_record(&b, DOMAIN_DEVICE_REVOCATION, &revocation.encode()),
        ];

        let dir = tempfile::tempdir().unwrap();
        let mut db = Db::open_at(&dir.path().join("t.db")).unwrap();
        let anchor = a.to.signing_key_id;
        assert!(pin_anchor(&db, &B, &anchor, JOIN, T0).unwrap());
        let mut evaluate_at = |pages: &[TenantTrustEvidencePageV2], now| {
            let (seen, chain) = evaluate(&db, &B, &anchor, &[pages.to_vec()], now)
                .unwrap()
                .unwrap();
            record(&mut db, &B, &seen, &chain, None, true, now).unwrap();
            chain
        };
        let before = evidence(&a, false, vec![a_approves.clone()]);
        assert!(evaluate_at(&before, T0 + DAY / 2).custodian_now(&anchor, T0 + DAY / 2));

        let mut after = evidence(&a, false, [vec![a_approves], hand_over].concat());
        after[0]
            .signing_public_keys
            .push(b.verifying_key().to_bytes());
        after[0].device_revocations.push(RevokedDevice {
            device_id: a.to.device_id,
            revoked_at_ms: T0 + 4 * DAY,
        });
        for now in [T0 + 5 * DAY, T0 + 6 * DAY] {
            let chain = evaluate_at(&after, now);
            assert!(chain.custodian_now(&id(&b), now), "B is custodian at {now}");
            assert!(!chain.custodian_now(&anchor, now), "A0 is not at {now}");
            assert!(chain.approval_valid_at(&id(&b), Scope::Tenant, now));
        }
        assert!(
            withdrawn(&db, &B, &anchor).unwrap(),
            "A0's revocation counted"
        );
    }

    /// Gate G5 (characterization, v2.11 input): this device collected
    /// generation 1 under key `k1`, the rotation was then abandoned, and a
    /// new rotation filed generation 1 again under `k1b`. The new grant
    /// verifies and opens, but the ledger keeps the abandoned key's grant for
    /// that number (rule 5: another key never replaces it), so only `k1`
    /// verifies as generation 1 and `k1b` never does.
    #[test]
    fn a_cached_grant_of_an_abandoned_generation_meets_a_new_key_under_that_number() {
        let a = a0();
        let (k0, k1, k1b) = ([0x30; 32], [0x31; 32], [0x41; 32]);
        let dir = tempfile::tempdir().unwrap();
        let mut db = Db::open_at(&dir.path().join("t.db")).unwrap();
        collect(&mut db, &a, 0, &k0, 40, evidence(&a, true, vec![]));
        let more = rotation(&a, 1, &k1, &k0);
        collect(&mut db, &a, 1, &k1, 41, evidence(&a, true, more));
        let more = rotation(&a, 1, &k1b, &k0);
        collect(&mut db, &a, 1, &k1b, 42, evidence(&a, true, more));

        let kept: String = db
            .conn
            .query_row(
                "SELECT fkek_key_id FROM trust_fleet_key_grants WHERE generation = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let k1_id = hex(&shardx_core::fleet_grants::fkek_key_id(&k1));
        assert_eq!(kept, k1_id, "the abandoned key's grant stays");
        assert_eq!(highest_generation(&db, &B, &FLEET).unwrap(), Some(1));
        let pin = (B, a.to.signing_key_id);
        let verifies = |k: &[u8; 32]| {
            crate::fleet_key_verifies(&db, &pin, &a.to, &FLEET, 1, k, T0 + DAY).unwrap()
        };
        assert!(verifies(&k1), "the abandoned key still verifies as 1");
        assert!(!verifies(&k1b), "the new key under that number never does");
    }

    // ---- v2.10 hand-over: member trust after a custodian revocation (U1b, G6) ----

    /// A0 approved `members` member devices for the fleet, let each commit to
    /// it and granted each generation 0, then appointed B, and B revoked A0:
    /// the evidence a server serves to every session, as it was before the
    /// hand-over and after, and what it serves only for a named signer.
    struct HandOver {
        a: Custodian,
        members: Vec<Ed25519SigningKey>,
        before: Vec<Vec<u8>>,
        after: Vec<Vec<u8>>,
        named: Named,
        keys: Vec<[u8; 32]>,
    }

    type Named = BTreeMap<[u8; 32], Vec<Vec<u8>>>;

    fn hand_over(members: u16) -> HandOver {
        let a = a0();
        let b = Ed25519SigningKey::from_bytes(&[0x0b; 32]);
        let device = |to: &shardx_core::trust_chain::Recipient| GrantSubject::Device {
            account_id: to.account_id,
            device_id: to.device_id,
            signing_key_id: to.signing_key_id,
            hpke_key_id: to.hpke_key_id,
        };
        let capability = |issuer: &Ed25519SigningKey, subject, replay, t, capability, fleet| {
            let (scope_kind, scope_id) = if fleet {
                (CapabilityScopeKind::Fleet, FLEET)
            } else {
                (CapabilityScopeKind::Tenant, B.tenant_id)
            };
            let g = TenantCapabilityGrantV2 {
                common: live_from(replay, t),
                subject,
                scope_kind,
                scope_id,
                capability,
            };
            build_record(issuer, DOMAIN_TENANT_CAPABILITY_GRANT, &g.encode())
        };
        let mut before = evidence(&a, false, Vec::new()).remove(0).containers;
        before.push(capability(
            &a.sk,
            device(&a.to),
            20,
            T0,
            Capability::DeviceApprove,
            false,
        ));
        let mut named = Named::new();
        let keys: Vec<Ed25519SigningKey> = (0..members)
            .map(|i| {
                let mut seed = [0x60; 32];
                seed[..2].copy_from_slice(&i.to_le_bytes());
                Ed25519SigningKey::from_bytes(&seed)
            })
            .collect();
        for (i, m) in (0u16..).zip(&keys) {
            let mut device_id = [0x61; 16];
            device_id[..2].copy_from_slice(&i.to_le_bytes());
            let to = shardx_core::trust_chain::Recipient {
                account_id: a.to.account_id,
                device_id,
                signing_key_id: id(m),
                // `device_grant` seals to A0's key: only the subject matters.
                hpke_key_id: a.to.hpke_key_id,
            };
            let approval = DeviceApprovalV2 {
                common: live(25),
                subject_account_id: to.account_id,
                subject_device_id: to.device_id,
                subject_signing_key_id: to.signing_key_id,
                subject_hpke_key_id: to.hpke_key_id,
                approval_scope_kind: ApprovalScopeKind::Fleet,
                approval_scope_id: FLEET,
            };
            let commit = capability(&a.sk, device(&to), 26, T0, Capability::ProfileCommit, true);
            named.insert(
                to.signing_key_id,
                vec![
                    build_record(&a.sk, DOMAIN_DEVICE_APPROVAL, &approval.encode()),
                    commit,
                ],
            );
            before.push(device_grant(&a, &to, 0, &[0x30; 32], 27));
        }
        let me_b = shardx_core::trust_chain::Recipient {
            account_id: a.to.account_id,
            device_id: [0x0b; 16],
            signing_key_id: id(&b),
            hpke_key_id: [0x0c; 32],
        };
        let approval = DeviceApprovalV2 {
            common: live_from(21, T0 + DAY),
            subject_account_id: me_b.account_id,
            subject_device_id: me_b.device_id,
            subject_signing_key_id: me_b.signing_key_id,
            subject_hpke_key_id: me_b.hpke_key_id,
            approval_scope_kind: ApprovalScopeKind::Tenant,
            approval_scope_id: B.tenant_id,
        };
        let root = TenantRootKeyGrantV2 {
            common: live_from(22, T0 + 2 * DAY),
            variant: RootGrantVariant::ExistingRootGrant,
            root_key_id: [8; 32],
            root_generation: 0,
            subject_account_id: me_b.account_id,
            subject_device_id: me_b.device_id,
            subject_signing_key_id: me_b.signing_key_id,
            recipient_hpke_key_id: me_b.hpke_key_id,
            subject_device_approval_replay_id: [21; 16],
            hpke_encapped_key_bytes: [3; 32],
            hpke_wrapped_trk_bytes: [4; 48],
        };
        let revocation = DeviceRevocationV2 {
            common: live_from(24, T0 + 4 * DAY),
            subject_account_id: a.to.account_id,
            subject_device_id: a.to.device_id,
            subject_signing_key_id: a.to.signing_key_id,
            subject_hpke_key_id: a.to.hpke_key_id,
            reason_code: DeviceRevocationReason::Retired,
        };
        let mut after = before.clone();
        after.extend([
            build_record(&a.sk, DOMAIN_DEVICE_APPROVAL, &approval.encode()),
            build_record(&a.sk, DOMAIN_TENANT_ROOT_KEY_GRANT, &root.encode()),
            capability(
                &b,
                device(&me_b),
                23,
                T0 + 3 * DAY,
                Capability::DeviceRevoke,
                false,
            ),
            build_record(&b, DOMAIN_DEVICE_REVOCATION, &revocation.encode()),
        ]);
        HandOver {
            keys: vec![
                a.sk.verifying_key().to_bytes(),
                b.verifying_key().to_bytes(),
            ],
            a,
            members: keys,
            before,
            after,
            named,
        }
    }

    /// What the server serves to every session, and per signer asked for.
    type Served = std::sync::Arc<std::sync::Mutex<(Vec<Vec<u8>>, Named)>>;

    /// This device, its ledger pinned to A0 in the join ceremony, against a
    /// server serving `h`'s evidence from before the hand-over. The server
    /// reports A0's device revoked once it serves a revocation.
    struct Device {
        rt: tokio::runtime::Runtime,
        client: FleetClient,
        seen: crate::fleet_custody::tests::Seen,
        served: Served,
        db: Db,
        anchor: [u8; 32],
        _dir: tempfile::TempDir,
    }

    fn device(h: &HandOver) -> Device {
        let served: Served =
            std::sync::Arc::new(std::sync::Mutex::new((h.before.clone(), h.named.clone())));
        let (from, keys) = (served.clone(), h.keys.clone());
        let revoked = h.a.to.device_id;
        let reply = move |call: &str, _: &[u8]| {
            let (base, named) = &*from.lock().unwrap();
            let mut p = page(&[], base.clone());
            p.signing_public_keys = keys.clone();
            for s in call
                .split_once('?')
                .map_or("", |(_, q)| q)
                .split('&')
                .filter_map(|kv| kv.strip_prefix("signer="))
            {
                let signer = decode_hex32(s, "signer").unwrap();
                p.containers
                    .extend(named.get(&signer).cloned().unwrap_or_default());
            }
            if p.containers.iter().any(|c| {
                AuthorizationRecord::parse(c)
                    .is_ok_and(|r| r.payload_domain() == DOMAIN_DEVICE_REVOCATION)
            }) {
                p.device_revocations.push(RevokedDevice {
                    device_id: revoked,
                    revoked_at_ms: T0 + 4 * DAY,
                });
            }
            (200, p.encode())
        };
        let rt = crate::fleet_custody::tests::runtime();
        let (client, seen) = rt.block_on(crate::fleet_custody::tests::mock(std::sync::Arc::new(
            reply,
        )));
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open_at(&dir.path().join("t.db")).unwrap();
        let anchor = h.a.to.signing_key_id;
        assert!(pin_anchor(&db, &B, &anchor, JOIN, T0).unwrap());
        Device {
            rt,
            client,
            seen,
            served,
            db,
            anchor,
            _dir: dir,
        }
    }

    impl Device {
        /// The server now serves `base`, and `named` per signer.
        fn serve(&self, base: &[Vec<u8>], named: &Named) {
            *self.served.lock().unwrap() = (base.to_vec(), named.clone());
        }

        /// One evidence read naming `named`, through the closure path.
        fn fetch(&mut self, named: &[[u8; 32]], now: u64) -> Result<(Listings, bool)> {
            let pin = (B, self.anchor);
            self.rt.block_on(closure_evidence(
                &self.client,
                "t",
                &hex(&B.tenant_id),
                &mut self.db,
                &pin,
                named,
                now,
            ))
        }

        /// What a collect or a walk does with one read naming `named`: it
        /// evaluates and records the listing. The chain it evaluated.
        fn evaluate(&mut self, named: &[[u8; 32]], now: u64) -> Result<TrustChain> {
            let (pages, closure) = self.fetch(named, now)?;
            let (seen, chain) = evaluate(&self.db, &B, &self.anchor, &pages, now)?.unwrap();
            record(&mut self.db, &B, &seen, &chain, None, closure, now)?;
            Ok(chain)
        }

        /// The signers each evidence request named, sorted.
        fn asked(&self) -> Vec<Vec<String>> {
            self.seen
                .lock()
                .unwrap()
                .iter()
                .filter(|(c, _)| c.contains("/trust-evidence"))
                .map(|(c, _)| {
                    let mut s: Vec<String> = c
                        .split_once('?')
                        .map_or("", |(_, q)| q)
                        .split('&')
                        .filter_map(|kv| kv.strip_prefix("signer=").map(str::to_owned))
                        .collect();
                    s.sort();
                    s
                })
                .collect()
        }

        fn evaluations(&self) -> i64 {
            self.db
                .conn
                .query_row("SELECT count(*) FROM trust_evaluations", [], |r| r.get(0))
                .unwrap()
        }
    }

    /// When the hand-over's evidence is served.
    const AFTER: u64 = T0 + 5 * DAY;

    /// A member's standing as a walk over its head checks it.
    fn trusts(chain: &TrustChain, m: &Ed25519SigningKey, t: u64) -> bool {
        chain.approval_valid_at(&id(m), Scope::Fleet(FLEET), t)
            && chain.capability_at(&id(m), Capability::ProfileCommit, Scope::Fleet(FLEET), t)
    }

    /// Architect G1b: a device whose first evaluation comes after B revoked
    /// A0 (a join, a collect, an import) counts the revocation in a closure,
    /// so a member approved by A0 that it first walks later is trusted.
    #[test]
    fn a_device_first_evaluating_after_the_old_roots_revocation_trusts_a_members_head() {
        let h = hand_over(1);
        let mut d = device(&h);
        d.serve(&h.after, &h.named);
        d.evaluate(&[], AFTER).unwrap();
        assert!(
            withdrawn(&d.db, &B, &d.anchor).unwrap(),
            "A0's revocation counted"
        );
        let m = &h.members[0];
        let chain = d.evaluate(&[id(m)], AFTER + DAY).unwrap();
        assert!(trusts(&chain, m, AFTER + DAY), "M's head is trusted");
    }

    /// Critic G6: a member device that evaluated before the hand-over counts
    /// A0's revocation in a closure, so another member's A0-issued approval
    /// it first sees afterwards was seen in the counting evaluation.
    #[test]
    fn a_device_that_counted_the_old_roots_revocation_accepts_a_member_approval_it_first_sees_later(
    ) {
        let h = hand_over(2);
        let mut d = device(&h);
        let chain = d.evaluate(&[id(&h.members[0])], T0 + DAY / 2).unwrap();
        assert!(trusts(&chain, &h.members[0], T0 + DAY / 2));
        d.serve(&h.after, &h.named);
        d.evaluate(&[], AFTER).unwrap();
        assert!(withdrawn(&d.db, &B, &d.anchor).unwrap());
        let later = &h.members[1];
        let chain = d.evaluate(&[id(later)], AFTER + DAY).unwrap();
        assert!(
            trusts(&chain, later, AFTER + DAY),
            "the later approval stands"
        );
    }

    /// D12: the closure is one listing naming every fleet grant subject the
    /// unscoped evidence holds, evaluated and recorded as one evaluation.
    #[test]
    fn the_closure_evaluates_one_named_signer_listing() {
        let h = hand_over(3);
        let mut d = device(&h);
        d.serve(&h.after, &h.named);
        d.evaluate(&[], AFTER).unwrap();
        let mut subjects: Vec<String> = h.members.iter().map(|m| hex(&id(m))).collect();
        subjects.sort();
        assert_eq!(d.asked(), [Vec::new(), subjects]);
        assert_eq!(d.evaluations(), 1, "only the closure listing is recorded");
        assert!(withdrawn(&d.db, &B, &d.anchor).unwrap());
    }

    /// ADR 0002 Q-62: a closure naming 65 signers reads one listing per 64
    /// of them and counts the revocation in one evaluation of both, so the
    /// 65th member's approval keeps its standing.
    #[test]
    fn a_closure_over_65_signers_reads_two_listings_and_counts_the_revocation() {
        let h = hand_over(65);
        let mut d = device(&h);
        d.serve(&h.after, &h.named);
        d.evaluate(&[], AFTER).unwrap();
        let sizes: Vec<usize> = d.asked().iter().map(Vec::len).collect();
        assert_eq!(sizes, [0, 64, 1]);
        assert_eq!(d.evaluations(), 1, "only the closure listings are recorded");
        assert!(withdrawn(&d.db, &B, &d.anchor).unwrap());
        let last = &h.members[64];
        let chain = d.evaluate(&[id(last)], AFTER + DAY).unwrap();
        assert!(trusts(&chain, last, AFTER + DAY), "the 65th member stands");
    }

    /// Q-62 fails closed past 1024 signers: nothing is recorded and no
    /// listing is read beyond the first. 1000 fleet grant subjects (a page
    /// holds at most 1024 containers) and 25 more named signers.
    #[test]
    fn more_than_1024_closure_signers_fail_closed() {
        let h = hand_over(1000);
        let mut d = device(&h);
        d.serve(&h.after, &h.named);
        let named: Vec<[u8; 32]> = (0..25u8).map(|i| [0xe0 + i; 32]).collect();
        let err = d.fetch(&named, AFTER).unwrap_err();
        assert!(
            crate::errcode::has_code(&err.to_string(), "fleet.trustClosureTooLarge"),
            "{err:#}"
        );
        let sizes: Vec<usize> = d.asked().iter().map(Vec::len).collect();
        assert_eq!(sizes, [25]);
        assert_eq!(d.evaluations(), 0);
        assert!(!withdrawn(&d.db, &B, &d.anchor).unwrap());
        assert_eq!(MAX_LISTED_SIGNERS, 1024);
    }

    /// D12 costs nothing without a custodian revocation: a first evaluation
    /// reads one unscoped listing, however many fleet grants it holds.
    #[test]
    fn a_first_evaluation_without_a_custodian_revocation_needs_no_closure() {
        let h = hand_over(70);
        let mut d = device(&h);
        d.evaluate(&[], T0 + DAY / 2).unwrap();
        assert_eq!(d.asked(), [Vec::<String>::new()]);
        assert_eq!(d.evaluations(), 1);
    }

    /// Execution note 1: `record` refuses to count a not-yet-counted
    /// revocation of a custodian key outside a closure listing, and records
    /// nothing; the same listing flagged as a closure counts it.
    #[test]
    fn record_refuses_to_count_a_custodian_revocation_outside_a_closure() {
        let h = hand_over(1);
        let dir = tempfile::tempdir().unwrap();
        let mut db = Db::open_at(&dir.path().join("t.db")).unwrap();
        let anchor = h.a.to.signing_key_id;
        assert!(pin_anchor(&db, &B, &anchor, JOIN, T0).unwrap());
        let mut pages = vec![page(&[], h.after.clone())];
        pages[0].signing_public_keys = h.keys.clone();
        let (seen, chain) = evaluate(&db, &B, &anchor, &[pages], AFTER)
            .unwrap()
            .unwrap();
        let err = record(&mut db, &B, &seen, &chain, None, false, AFTER).unwrap_err();
        assert!(
            crate::errcode::has_code(&err.to_string(), "fleet.trustClosureNeeded"),
            "{err:#}"
        );
        let n: i64 = db
            .conn
            .query_row("SELECT count(*) FROM trust_evaluations", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "nothing recorded");
        assert!(!withdrawn(&db, &B, &anchor).unwrap());
        record(&mut db, &B, &seen, &chain, None, true, AFTER).unwrap();
        assert!(withdrawn(&db, &B, &anchor).unwrap());
    }

    /// The C-1 bound (section 9): a member the server omits from the closure
    /// listing is first seen after the count and stays untrusted; it must
    /// enroll again.
    #[test]
    fn a_member_the_server_omits_from_the_closure_is_untrusted() {
        let h = hand_over(1);
        let mut d = device(&h);
        d.serve(&h.after, &Named::new());
        d.evaluate(&[], AFTER).unwrap();
        assert!(withdrawn(&d.db, &B, &d.anchor).unwrap());
        d.serve(&h.after, &h.named);
        let m = &h.members[0];
        let chain = d.evaluate(&[id(m)], AFTER + DAY).unwrap();
        assert!(
            !trusts(&chain, m, AFTER + DAY),
            "the omitted member is untrusted"
        );
    }
}
