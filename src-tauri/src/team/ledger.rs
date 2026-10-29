//! The W6 trust ledger: what this device remembers between trust-evidence
//! evaluations, so a hostile server cannot make it forget (ADR 0002 D-6,
//! Q-13, and the trust chain's verification algorithm).
//!
//! `shardx_core::trust_chain` evaluates a device without history. The launcher
//! evaluates through [`evaluate`], then runs [`record`]:
//!
//! - **Pinned anchor.** The bootstrap device pins `A0` once; a later
//!   different anchor is refused ([`pin_anchor`]). A joining device pins in
//!   the Q-12 join ceremony after the SAS comparison, which has not shipped,
//!   so a joining device stays unpinned and verifies nothing.
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
//!
//! Not here yet: the custodian change events of D-6 (a), whose wording and
//! acknowledgement follow the Q-17 UX review.

use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension};
use std::collections::BTreeMap;

use shardx_core::authz_record::{
    AuthorizationRecord, Capability, Payload, DOMAIN_DEVICE_REVOCATION,
    DOMAIN_TENANT_ROOT_KEY_GRANT,
};
use shardx_core::canonical::{decode, encode, Value};
use shardx_core::trust_chain::{
    Binding, Evidence, Scope, TrustChain, CLOCK_TOLERANCE_MS, MAX_CUSTODIAN_KEY_AGE_MS,
};
use shardx_core::trust_evidence::{RevokedDevice, RevokedRecord, TenantTrustEvidencePageV2};

use super::db::Db;
use crate::fleet_client::{decode_hex16, decode_hex32, hex};

type Keys = BTreeMap<[u8; 32], [u8; 32]>;

/// The public keys `pages` list, by the ID each hashes to.
fn keys_of(pages: &[TenantTrustEvidencePageV2]) -> Keys {
    pages
        .iter()
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
    /// The grant's exact container, and the pages it verified against as the
    /// server sent them.
    pub container: &'a [u8],
    pub pages: &'a [TenantTrustEvidencePageV2],
}

fn ids(b: &Binding) -> (String, String) {
    (hex(&b.server_instance_id), hex(&b.tenant_id))
}

/// A local time or generation as the ledger stores it.
fn wire(v: u64) -> Result<i64> {
    i64::try_from(v).map_err(|_| anyhow::anyhow!("WIRE_INTEGER_OUT_OF_RANGE"))
}

/// Pins `anchor` for `binding` as the bootstrap device's, or checks it
/// against the one already pinned. False when another anchor is pinned: a
/// server-supplied new anchor is never accepted ("Anchor loss").
pub fn pin_anchor(db: &Db, binding: &Binding, anchor: &[u8; 32], now: u64) -> Result<bool> {
    let (instance, tenant) = ids(binding);
    db.conn.execute(
        "INSERT INTO trust_anchors VALUES (?1, ?2, ?3, 'BOOTSTRAP', ?4) ON CONFLICT DO NOTHING",
        params![instance, tenant, hex(anchor), wire(now)?],
    )?;
    let pinned: String = db.conn.query_row(
        "SELECT anchor_key_id FROM trust_anchors WHERE server_instance_id = ?1 AND tenant_id = ?2",
        params![instance, tenant],
        |r| r.get(0),
    )?;
    Ok(pinned == hex(anchor))
}

/// The highest generation of `fleet_id` this device has verified.
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

/// `pages` at `now` as this device's history lets it see them: first the
/// lapses history shows ([`observe_lapses`]), then [`prepare`], and the chain
/// they verify to from `anchor`, with every key's windows clipped from its
/// cached `first_not_before` when that is earlier (D-6 (c)). `None` when they
/// do not verify.
pub fn evaluate(
    db: &Db,
    binding: &Binding,
    anchor: &[u8; 32],
    pages: &[TenantTrustEvidencePageV2],
    now: u64,
) -> Result<Option<(Vec<TenantTrustEvidencePageV2>, TrustChain)>> {
    observe_lapses(db, binding, now)?;
    let seen = prepare(db, binding, pages)?;
    let Ok(mut evidence) = Evidence::collect(binding, &seen) else {
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

/// Q-26: whether `key` is now proven revoked (rule 6) or locally distrusted,
/// whenever that was learned.
pub fn withdrawn(db: &Db, binding: &Binding, key: &[u8; 32]) -> Result<bool> {
    let (instance, tenant) = ids(binding);
    Ok(db.conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM trust_proven_revocations
         WHERE server_instance_id = ?1 AND tenant_id = ?2 AND signing_key_id = ?3)",
        params![instance, tenant, hex(key)],
        |r| r.get(0),
    )?)
}

/// `pages` as this device's history lets it see them: containers signed by a
/// proven-revoked or distrusted key and not seen by the evaluation that
/// counted it are dropped, so are those sticky lapse refuses
/// ([`lapse_allows`]), and every revocation the server ever reported is
/// reported again.
fn prepare(
    db: &Db,
    binding: &Binding,
    pages: &[TenantTrustEvidencePageV2],
) -> Result<Vec<TenantTrustEvidencePageV2>> {
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
    let keys = keys_of(pages);
    let mut first_seen = db.conn.prepare(
        "SELECT first_seen_evaluation FROM trust_sightings
         WHERE server_instance_id = ?1 AND tenant_id = ?2 AND signed_container_hash = ?3",
    )?;
    let mut out = pages.to_vec();
    for page in &mut out {
        let mut kept = Vec::with_capacity(page.containers.len());
        for c in std::mem::take(&mut page.containers) {
            if let Ok(r) = AuthorizationRecord::parse(&c) {
                let seen: Option<i64> = first_seen
                    .query_row(
                        params![instance, tenant, hex(r.signed_container_hash())],
                        |row| row.get(0),
                    )
                    .optional()?;
                if let Some(&cutoff) = cutoffs.get(&hex(r.issuer_signing_key_id())) {
                    if !seen.is_some_and(|s| s <= cutoff) {
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
    let Some(first) = out.first_mut() else {
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

/// G2-35: the exact grant kept for `generation` of `fleet_id` and the pages it
/// was accepted from, when `anchor` is the one pinned for `binding`.
pub fn fleet_key_grant(
    db: &Db,
    binding: &Binding,
    anchor: &[u8; 32],
    fleet_id: &[u8; 16],
    generation: u64,
) -> Result<Option<(Vec<u8>, Vec<TenantTrustEvidencePageV2>)>> {
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
    let unreadable = || anyhow!(crate::errcode::code("team.trustLedgerUnreadable"));
    let Ok(Value::Array(items)) = decode(&pages) else {
        return Err(unreadable());
    };
    let pages = items
        .into_iter()
        .map(|item| match item {
            Value::Bytes(b) => TenantTrustEvidencePageV2::parse(&b).map_err(|_| unreadable()),
            _ => Err(unreadable()),
        })
        .collect::<Result<_>>()?;
    Ok(Some((container, pages)))
}

/// ADR 0002 Q-18: whether this device refuses to commit under `generation`
/// of `fleet_id` because a counted `DeviceRevocationV2` with reason
/// `compromised` exposes it. Exposed means the kept evidence of the
/// generation shows a `DeviceHpkeGrant` of it to, or issued by, the revoked
/// key, or this device verified the generation no later than it counted the
/// revocation, so a newer, unexposed generation is not yet ACTIVE here
/// (missing evidence counts as flagged, C-1). A revocation whose reason this
/// device cannot verify counts as `compromised`.
// shortcut: the fleet flagged through the root (a RecoveryGrant under an
// exposed root generation, C-1) is not derived; add it with the root
// rotation banner (Q-20).
pub fn commit_blocked(
    db: &Db,
    binding: &Binding,
    anchor: &[u8; 32],
    fleet_id: &[u8; 16],
    generation: u64,
) -> Result<bool> {
    use shardx_core::authz_record::DeviceRevocationReason;
    let (instance, tenant) = ids(binding);
    let kept = fleet_key_grant(db, binding, anchor, fleet_id, generation)?;
    let verified: Option<i64> = db
        .conn
        .query_row(
            "SELECT verified_evaluation FROM trust_fleet_key_grants
             WHERE server_instance_id = ?1 AND tenant_id = ?2 AND fleet_id = ?3 AND generation = ?4",
            params![instance, tenant, hex(fleet_id), wire(generation)?],
            |r| r.get(0),
        )
        .optional()?;
    let pages = kept.map(|(_, pages)| pages).unwrap_or_default();
    let keys = keys_of(&pages);
    let payload = |c: &[u8]| {
        let r = AuthorizationRecord::parse(c).ok()?;
        let pk = keys.get(r.issuer_signing_key_id())?;
        let issuer = *r.issuer_signing_key_id();
        Some((issuer, r.verify_signature(pk).ok()?.payload().clone()))
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
        if matches!(payload(&container), Some((_, Payload::DeviceRevocation(d)))
            if d.reason_code != DeviceRevocationReason::Compromised)
        {
            continue;
        }
        if verified.is_none_or(|v| v <= counted) {
            return Ok(true);
        }
        let exposes = pages.iter().flat_map(|p| &p.containers).any(|c| {
            matches!(payload(c), Some((issuer, Payload::DeviceHpkeGrant(g)))
                if g.fleet_id == *fleet_id && g.generation == generation
                    && (issuer == key || g.subject_signing_key_id == key))
        });
        if exposes {
            return Ok(true);
        }
    }
    Ok(false)
}

/// After `chain` evaluated `seen` (from [`evaluate`]), in one transaction:
/// a new evaluation, the first sighting of every container, the reported
/// revocations, every `DeviceRevocationV2` rule 6 counts, the custodian keys
/// with their `first_not_before` and observed lapses, and, when a grant
/// opened, its fleet's generation and the grant itself, also as a kept
/// signed authorization record (`team::records`).
pub fn record(
    db: &mut Db,
    binding: &Binding,
    seen: &[TenantTrustEvidencePageV2],
    chain: &TrustChain,
    opened: Option<Opened>,
    now: u64,
) -> Result<()> {
    let (instance, tenant) = ids(binding);
    let tx = db.conn.transaction()?;
    tx.execute(
        "INSERT INTO trust_evaluations(server_instance_id, tenant_id, evaluated_at_ms)
         VALUES (?1, ?2, ?3)",
        params![instance, tenant, wire(now)?],
    )?;
    let evaluation = tx.last_insert_rowid();
    let keys = keys_of(seen);
    for c in seen.iter().flat_map(|p| &p.containers) {
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
        if let Some(revoked) = counted(chain, binding, &keys, r, first_seen_ms as u64) {
            tx.execute(
                "INSERT INTO trust_proven_revocations
                 VALUES (?1, ?2, ?3, 'DEVICE_REVOCATION', ?4, ?5, ?6) ON CONFLICT DO NOTHING",
                params![instance, tenant, hex(&revoked), evaluation, wire(now)?, c],
            )?;
        }
    }
    for r in seen.iter().flat_map(|p| &p.revocations) {
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
    for d in seen.iter().flat_map(|p| &p.device_revocations) {
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
    hold_lapses(&tx, binding, evaluation, now)?;
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
        let pages = encode(&Value::Array(
            o.pages.iter().map(|p| Value::Bytes(p.encode())).collect(),
        ));
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
        super::records::keep(&tx, o.server_url, o.container, now)?;
    }
    tx.commit()?;
    Ok(())
}

/// Rule 6: the signing key a usable `DeviceRevocationV2` revokes, when its
/// issuer was a custodian holding a device-scoped `device.revoke` at its
/// `issued_at_ms`, and is still a custodian when this device first saw it.
// shortcut: only a tenant-scoped `device.revoke` counts, so a fleet-scoped
// revocation of a fleet-approved device is not held; custodians are always
// tenant-approved (Q-22), so fleet keys are covered; count fleet scope once
// head acceptance needs non-custodian signers revoked (W6 manifests).
fn counted(
    chain: &TrustChain,
    binding: &Binding,
    keys: &BTreeMap<[u8; 32], [u8; 32]>,
    record: AuthorizationRecord,
    first_seen_ms: u64,
) -> Option<[u8; 32]> {
    let issuer = *record.issuer_signing_key_id();
    let verified = record.verify_signature(keys.get(&issuer)?).ok()?;
    let Payload::DeviceRevocation(d) = verified.payload() else {
        return None;
    };
    let t = d.common.issued_at_ms;
    (d.common.tenant_id == binding.tenant_id
        && d.common.server_instance_id == binding.server_instance_id
        && chain.custodian_at(&issuer, t)
        && chain.capability_at(&issuer, Capability::DeviceRevoke, Scope::Tenant, t)
        && chain.custodian_now(&issuer, first_seen_ms))
    .then_some(d.subject_signing_key_id)
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
    fn a_lapsed_key_counts_only_after_its_observed_lapse() {
        let (d, x) = (
            Ed25519SigningKey::from_bytes(&[2; 32]),
            Ed25519SigningKey::from_bytes(&[3; 32]),
        );
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open_at(&dir.path().join("t.db")).unwrap();
        assert!(pin_anchor(&db, &B, &id(&x), 0).unwrap());
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
        let kept = prepare(&db, &B, &[page(&[&d, &x], all)]).unwrap();
        for (c, expected) in &cases {
            assert_eq!(kept[0].containers.contains(c), *expected, "{}", hash(c));
        }
        let unverifiable = signed_by(&d, 10, L - 1);
        let kept = prepare(&db, &B, &[page(&[&x], vec![unverifiable.clone()])]).unwrap();
        assert_eq!(kept[0].containers, [unverifiable]);
    }
}
