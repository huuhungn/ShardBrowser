//! `GET /v2/tenants/{tenant_id}/trust-evidence`: a tenant's trust evidence,
//! paged (ADR 0002 B2, "Evidence"; round-2 M13).
//!
//! The evidence is the full ancestry, expired and revoked records included:
//! every root grant of the tenant, and every approval and capability grant
//! whose subject signing key is a root grant subject or a `signer` the client
//! names, and every filed `DeviceRevocationV2` (Q-13) with an unsigned report
//! of its subject device. Containers are served as their exact signed bytes
//! with the issuers' public keys; the client verifies everything itself, so
//! the server only has to leave nothing out. Pages are read from one snapshot
//! each and ordered by kind, then by row, so a cursor names where the next
//! page starts.
//!
//! shortcut: the fleet evidence (`DeviceHpkeGrant`, `RotationGrant`,
//! `RecoveryGrant`) is not served yet; add it with the fleet trust rules (W4).
//! Its absence can only make a client refuse.

use std::collections::BTreeSet;

use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use axum::response::Response;
use sqlx::{Row, SqliteConnection};

use shared::trust_evidence::{
    RevokedDevice, RevokedRecord, TenantTrustEvidencePageV2, MAX_PAGE_BYTES, MAX_PAGE_CONTAINERS,
};

use super::v2_approval::{cbor, coded};
use super::v2_auth::{reload_session, unhex, verified, Principal};
use crate::error::AppError;
use crate::identity::Verified;
use crate::state::AppState;
use crate::util::now_ms;
use shared::canonical::sha256;

/// At most this many `signer` parameters in one request.
pub const MAX_SIGNERS: usize = 64;

/// The evidence tables, in page order, with the quarantine kind of their
/// rows. Approvals and capability grants are those of the root grant subjects
/// and of the named signers; root grants and revocations are all served.
const KINDS: [(&str, Option<&str>); 4] = [
    ("v2_tenant_root_key_grants", Some("root_grant")),
    ("v2_device_approvals", None),
    ("v2_capability_grants", Some("capability_grant")),
    (REVOCATIONS, None),
];
const REVOCATIONS: &str = "v2_device_revocations";

/// The page's fixed fields, well over their encoded size.
const PAGE_HEADER_BYTES: usize = 1024;
/// What one entry costs on the wire beyond its own bytes, well over the
/// encoded array item and map headers.
const ENTRY_OVERHEAD_BYTES: usize = 16;

/// Where a page starts: its index, the kind it starts in, and the last row
/// of that kind already served. Opaque to the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cursor {
    page_index: u32,
    kind: u8,
    after_rowid: i64,
}

impl Cursor {
    const START: Self = Self {
        page_index: 0,
        kind: 0,
        after_rowid: 0,
    };

    fn encode(self) -> Vec<u8> {
        let mut out = self.page_index.to_be_bytes().to_vec();
        out.push(self.kind);
        out.extend(self.after_rowid.to_be_bytes());
        out
    }

    fn decode(hex: &str) -> Option<Self> {
        let b = unhex::<13>(hex)?;
        let c = Self {
            page_index: u32::from_be_bytes(b[0..4].try_into().ok()?),
            kind: b[4],
            after_rowid: i64::from_be_bytes(b[5..13].try_into().ok()?),
        };
        (usize::from(c.kind) < KINDS.len() && c.page_index > 0 && c.after_rowid >= 0).then_some(c)
    }
}

fn bad(msg: &str) -> AppError {
    AppError::BadRequest(msg.into())
}

/// The cursor (at most once) and the signers (at most [`MAX_SIGNERS`]);
/// anything else is refused rather than ignored.
fn query(raw: Option<&str>) -> Result<(Cursor, Vec<[u8; 32]>), AppError> {
    let mut cursor = None;
    let mut signers = BTreeSet::new();
    for pair in raw.unwrap_or_default().split('&').filter(|p| !p.is_empty()) {
        match pair.split_once('=') {
            Some(("cursor", v)) if cursor.is_none() => {
                cursor = Some(
                    Cursor::decode(v)
                        .ok_or_else(|| bad("the cursor is not one this server gave"))?,
                );
            }
            Some(("signer", v)) => {
                signers.insert(
                    unhex::<32>(v).ok_or_else(|| bad("a signer is a 64-digit hex key id"))?,
                );
            }
            _ => return Err(bad("the query takes one cursor and signer key ids")),
        }
    }
    if signers.len() > MAX_SIGNERS {
        return Err(bad("too many signers"));
    }
    Ok((
        cursor.unwrap_or(Cursor::START),
        signers.into_iter().collect(),
    ))
}

/// A reported revocation time: the row's RFC 3339 time in ms, or 0 when it
/// does not parse, since a report only ever tightens.
fn revoked_at_ms(revoked_at: &str) -> u64 {
    chrono::DateTime::parse_from_rfc3339(revoked_at)
        .ok()
        .and_then(|t| u64::try_from(t.timestamp_millis()).ok())
        .unwrap_or_else(|| {
            tracing::warn!("a revocation time does not parse; it is reported as 0");
            0
        })
}

/// The rows of `kind` after `after`, at most `limit`, without their
/// containers: a page loads only the containers it serves. Quarantined rows
/// are left out.
async fn rows(
    conn: &mut SqliteConnection,
    v: &Verified,
    tenant: &[u8; 16],
    signers: &[[u8; 32]],
    kind: u8,
    after: i64,
    limit: i64,
) -> Result<Vec<sqlx::sqlite::SqliteRow>, AppError> {
    let (table, quarantine_kind) = KINDS[usize::from(kind)];
    let quarantined = quarantine_kind.map_or(String::new(), |k| {
        format!(
            " AND NOT EXISTS (SELECT 1 FROM v2_grant_quarantine q
                               WHERE q.kind = '{k}' AND q.server_instance_id = t.server_instance_id
                                 AND q.tenant_id = t.tenant_id AND q.replay_id = t.replay_id)"
        )
    });
    let subjects = if kind == 0 || table == REVOCATIONS {
        String::new()
    } else {
        // Numbered after the four fixed parameters.
        let named = (0..signers.len())
            .map(|i| format!("?{}", i + 5))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            " AND (subject_signing_key_id IN (SELECT subject_signing_key_id
                                                FROM v2_tenant_root_key_grants
                                               WHERE server_instance_id = ?1 AND tenant_id = ?2)
                   OR subject_signing_key_id IN ({named}))"
        )
    };
    // A revocation is never itself revoked.
    let revoked_at = if table == REVOCATIONS {
        "NULL AS revoked_at"
    } else {
        "revoked_at"
    };
    let sql = format!(
        "SELECT rowid, payload_domain, replay_id, issuer_signing_key_id, {revoked_at},
                length(exact_signed_container_bytes) AS len
           FROM {table} t
          WHERE server_instance_id = ?1 AND tenant_id = ?2 AND rowid > ?3{subjects}{quarantined}
          ORDER BY rowid LIMIT ?4"
    );
    let mut q = sqlx::query(&sql)
        .bind(v.server_instance_id.as_slice())
        .bind(tenant.as_slice())
        .bind(after)
        .bind(limit);
    for signer in signers {
        q = q.bind(signer.as_slice());
    }
    Ok(q.fetch_all(&mut *conn).await?)
}

pub async fn trust_evidence(
    State(app): State<AppState>,
    who: Principal,
    Path(tenant): Path<String>,
    RawQuery(raw): RawQuery,
) -> Result<Response, AppError> {
    let v = verified(&app)?;
    // Any device session of the tenant reads it, a joining device included;
    // a ticket proves only a password.
    let Principal::Session(presented) = who else {
        return Err(AppError::Forbidden);
    };
    let tenant = unhex::<16>(&tenant).ok_or_else(|| bad("tenant id must be 32 hex digits"))?;
    let (cursor, signers) = query(raw.as_deref())?;

    let mut tx = app.db.begin().await?;
    let s = reload_session(&mut tx, &presented, v, now_ms())
        .await?
        .ok_or(AppError::Unauthorized)?;
    if s.tenant_id != tenant {
        return Err(coded(
            StatusCode::NOT_FOUND,
            "RESOURCE_NOT_FOUND",
            "no such tenant",
        ));
    }

    let mut page = TenantTrustEvidencePageV2 {
        server_instance_id: v.server_instance_id,
        tenant_id: tenant,
        server_now_ms: u64::try_from(now_ms()).unwrap_or(0),
        page_index: cursor.page_index,
        next_cursor: Vec::new(),
        signing_public_keys: Vec::new(),
        containers: Vec::new(),
        revocations: Vec::new(),
        device_revocations: Vec::new(),
    };
    let mut issuers = BTreeSet::new();
    let mut served = BTreeSet::new();
    let mut bytes = PAGE_HEADER_BYTES;
    let (mut kind, mut after) = (cursor.kind, cursor.after_rowid);
    'kinds: while usize::from(kind) < KINDS.len() {
        let room = MAX_PAGE_CONTAINERS - page.containers.len();
        let batch = rows(&mut tx, v, &tenant, &signers, kind, after, room as i64 + 1).await?;
        let exhausted = batch.len() <= room;
        for row in batch {
            // Everything this row adds to the page: its container, its
            // revocation report and its issuer's key, each over its encoded
            // size. The final size check below stays the guarantee.
            let len = usize::try_from(row.get::<i64, _>("len")).unwrap_or(usize::MAX);
            let issuer: Vec<u8> = row.get("issuer_signing_key_id");
            let revoked_at: Option<String> = row.get("revoked_at");
            let payload_domain: String = row.get("payload_domain");
            let table = KINDS[usize::from(kind)].0;
            let cost = len.saturating_add(ENTRY_OVERHEAD_BYTES)
                + revoked_at.as_ref().map_or(0, |_| payload_domain.len() + 64)
                + if table == REVOCATIONS { 64 } else { 0 }
                + if issuers.contains(&issuer) {
                    0
                } else {
                    32 + ENTRY_OVERHEAD_BYTES
                };
            if page.containers.len() == MAX_PAGE_CONTAINERS
                || bytes.saturating_add(cost) > MAX_PAGE_BYTES
            {
                let page_index = cursor
                    .page_index
                    .checked_add(1)
                    .ok_or_else(|| bad("the evidence has more pages than a cursor can name"))?;
                page.next_cursor = Cursor {
                    page_index,
                    kind,
                    after_rowid: after,
                }
                .encode();
                break 'kinds;
            }
            after = row.get("rowid");
            let container: Vec<u8> = sqlx::query_scalar(&format!(
                "SELECT exact_signed_container_bytes FROM {table} WHERE rowid = ?"
            ))
            .bind(after)
            .fetch_one(&mut *tx)
            .await?;
            // Two rows holding one container say one thing; the page says it
            // once.
            if !served.insert(sha256(&container)) {
                continue;
            }
            bytes += cost;
            issuers.insert(issuer);
            if let Some(revoked_at) = revoked_at {
                let replay: Vec<u8> = row.get("replay_id");
                page.revocations.push(RevokedRecord {
                    payload_domain,
                    replay_id: replay
                        .try_into()
                        .map_err(|_| AppError::Internal("a replay id is not 16 bytes".into()))?,
                    revoked_at_ms: revoked_at_ms(&revoked_at),
                });
            }
            if table == REVOCATIONS {
                let (device, filed_at): (Vec<u8>, i64) = sqlx::query_as(
                    "SELECT subject_device_id, filed_at_ms FROM v2_device_revocations WHERE rowid = ?",
                )
                .bind(after)
                .fetch_one(&mut *tx)
                .await?;
                let device_id: [u8; 16] = device
                    .try_into()
                    .map_err(|_| AppError::Internal("a device id is not 16 bytes".into()))?;
                // The earliest filing on this page; a client takes the
                // earliest over all pages, so a later one only repeats it.
                if !page
                    .device_revocations
                    .iter()
                    .any(|d| d.device_id == device_id)
                {
                    page.device_revocations.push(RevokedDevice {
                        device_id,
                        revoked_at_ms: u64::try_from(filed_at).unwrap_or(0),
                    });
                }
            }
            page.containers.push(container);
        }
        if !exhausted {
            continue;
        }
        kind += 1;
        after = 0;
    }

    // The issuers' keys, revoked devices included: a signature stays the one
    // it was when the record was filed. A key the server lacks is left out,
    // and the client refuses what it signed.
    for issuer in issuers {
        let key: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT signing_public_key FROM v2_devices WHERE tenant_id = ? AND signing_key_id = ?",
        )
        .bind(tenant.as_slice())
        .bind(issuer.as_slice())
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(key) = key.and_then(|k| <[u8; 32]>::try_from(k).ok()) {
            page.signing_public_keys.push(key);
        }
    }
    tx.commit().await?;
    let encoded = page.encode();
    if encoded.len() > MAX_PAGE_BYTES {
        return Err(AppError::Internal(format!(
            "a trust evidence page came to {} bytes",
            encoded.len()
        )));
    }
    Ok(cbor(StatusCode::OK, encoded))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cursor_round_trips_and_only_its_own_shape_is_accepted() {
        let c = Cursor {
            page_index: 7,
            kind: 2,
            after_rowid: 42,
        };
        let hex: String = c.encode().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(Cursor::decode(&hex), Some(c));
        for bad in [
            // page 0 is never named by a cursor; kind 4 does not exist;
            // a negative row; a short cursor.
            "00000000020000000000000001",
            "00000001040000000000000001",
            "0000000102ffffffffffffffff",
            "000000010200",
        ] {
            assert_eq!(Cursor::decode(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_query_takes_one_cursor_and_bounded_signers() {
        assert_eq!(query(None).unwrap(), (Cursor::START, vec![]));
        let signer = "ab".repeat(32);
        let (_, signers) = query(Some(&format!("signer={signer}&signer={signer}"))).unwrap();
        assert_eq!(signers, vec![[0xab; 32]]);
        let cursor = "00000001010000000000000005";
        for refused in [
            format!("cursor={cursor}&cursor={cursor}"),
            "other=1".to_string(),
            "signer=abcd".to_string(),
            "cursor=zz".to_string(),
            (0..=MAX_SIGNERS)
                .map(|i| format!("signer={:064x}", i))
                .collect::<Vec<_>>()
                .join("&"),
        ] {
            assert!(query(Some(&refused)).is_err(), "{refused}");
        }
    }

    #[test]
    fn a_report_that_does_not_parse_revokes_from_the_start() {
        assert_eq!(revoked_at_ms("1970-01-01T00:00:01+00:00"), 1000);
        assert_eq!(revoked_at_ms("now"), 0);
    }
}
