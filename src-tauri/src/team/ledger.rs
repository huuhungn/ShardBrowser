//! The W6 trust ledger: what this device remembers between trust-evidence
//! evaluations, so a hostile server cannot make it forget (ADR 0002 D-6,
//! Q-13, and the trust chain's verification algorithm).
//!
//! `shardx_core::trust_chain` evaluates a device without history. Around each
//! evaluation the launcher runs [`prepare`] and [`record`]:
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
//!   ("Fleet generation freshness").
//!
//! Not here yet: the custodian ledger and its events (D-6 (a)), sticky lapse
//! (b), and the cached `first_not_before` of the clip (c). They need the
//! custodian windows, which `TrustChain` does not expose.

use anyhow::Result;
use rusqlite::{params, OptionalExtension};
use std::collections::BTreeMap;

use shardx_core::authz_record::{
    AuthorizationRecord, Capability, Payload, DOMAIN_DEVICE_REVOCATION,
};
use shardx_core::trust_chain::{Binding, Scope, TrustChain};
use shardx_core::trust_evidence::{RevokedDevice, RevokedRecord, TenantTrustEvidencePageV2};

use super::db::Db;
use crate::fleet_client::{decode_hex16, hex};

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

/// `pages` as this device's history lets it see them: containers signed by a
/// proven-revoked or distrusted key and not seen by the evaluation that
/// counted it are dropped, and every revocation the server ever reported is
/// reported again.
pub fn prepare(
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
    let mut first_seen = db.conn.prepare(
        "SELECT first_seen_evaluation FROM trust_sightings
         WHERE server_instance_id = ?1 AND tenant_id = ?2 AND signed_container_hash = ?3",
    )?;
    let mut out = pages.to_vec();
    for page in &mut out {
        let mut kept = Vec::with_capacity(page.containers.len());
        for c in std::mem::take(&mut page.containers) {
            if let Ok(r) = AuthorizationRecord::parse(&c) {
                if let Some(&cutoff) = cutoffs.get(&hex(r.issuer_signing_key_id())) {
                    let seen: Option<i64> = first_seen
                        .query_row(
                            params![instance, tenant, hex(r.signed_container_hash())],
                            |row| row.get(0),
                        )
                        .optional()?;
                    if !seen.is_some_and(|s| s <= cutoff) {
                        continue;
                    }
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

/// After `chain` evaluated `seen` (from [`prepare`]), in one transaction:
/// a new evaluation, the first sighting of every container, the reported
/// revocations, every `DeviceRevocationV2` rule 6 counts, and, when a grant
/// opened, its fleet's generation.
pub fn record(
    db: &mut Db,
    binding: &Binding,
    seen: &[TenantTrustEvidencePageV2],
    chain: &TrustChain,
    opened: Option<(&[u8; 16], u64)>,
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
    let keys: BTreeMap<[u8; 32], [u8; 32]> = seen
        .iter()
        .flat_map(|p| &p.signing_public_keys)
        .map(|pk| (shardx_core::keys::signing_key_id(pk), *pk))
        .collect();
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
    if let Some((fleet_id, generation)) = opened {
        tx.execute(
            "INSERT INTO trust_fleet_generations VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT DO UPDATE SET highest_verified_generation =
               max(highest_verified_generation, excluded.highest_verified_generation)",
            params![instance, tenant, hex(fleet_id), wire(generation)?],
        )?;
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
