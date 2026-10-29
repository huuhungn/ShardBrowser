//! Push and pull of a published profile over the G2 wire (plan 8.1
//! L1137-L1215, 10.2 L1418-L1427, 11.1).
//!
//! A profile is published when `team-sync.db` holds its `profile_bindings`
//! row; every other profile keeps the passphrase path of `sync_cmd`.
//!
//! - **Durable before sent.** Every mutation request is stored as exact bytes
//!   with its hashes in `operations` before it is sent, and a retry, in this
//!   run or after a restart, sends those bytes again. Before any resend the
//!   stored columns are compared with the bytes; a mismatch quarantines the
//!   binding and nothing is sent (G2-37).
//! - **Finalize only after the commit is stored** (L1150): the exact
//!   `SignedSnapshotManifestV2` container and the exact `CommitRequestV2` are
//!   in the COMMIT operation, with the `upload_sessions` row, first.
//! - **The fleet key, never the passphrase** (L1370-L1387): a snapshot is
//!   sealed and opened only under a key whose grant reverifies at use
//!   (`fleet_key_verifies`, ADR 0002 Q-25/Q-26).
//! - **Rule 6** (ADR 0002 trust chain): the binding pins its head and its
//!   accepted restore epoch; a listed head behind it, or another epoch,
//!   quarantines. A new head's signer needs, now, an approval covering the
//!   fleet and a device-scoped `profile.commit` covering the profile.
//! - **Restore epochs** (L2243, L2057; ADR 0002 D-1, Q-34): a later epoch
//!   is accepted only through its tenant's custodian-signed transition and
//!   the binding's own inclusion proof, filed as exact bytes; a stored
//!   request the restore rolled back ends at its superseded answer.
//!
//! The device session is opened by the caller and only borrowed here: no
//! access token, key or passphrase reaches this database (L2048).

use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use rusqlite::{params, OptionalExtension};
use zeroize::Zeroizing;

use shardx_core::authz_record::Capability;
use shardx_core::canonical::sha256;
use shardx_core::envelope::{build_dek_slot, IntentIds, IntentNumbers, SlotIds};
use shardx_core::envelope_v2::{
    build_intent_v2, check_public, open, seal, Expected, Scope as Sealed,
    DEFAULT_FRAME_PLAINTEXT_SIZE, MAX_OBJECT_SIZE,
};
use shardx_core::fleet_profiles::{FleetProfileHeadV2, FleetProfilePageV2};
use shardx_core::mutation::{
    IdempotentMutationRequestV2, IdempotentStoredResponseV2, OperationKind,
};
use shardx_core::profile_lease::{
    CreateUploadV2, LeaseOrigin, LeaseRef, LeaseReleasedV2, LeaseRenewV2, LeaseRenewedV2,
    LocalBindingTombstoneV2, LocalUnbindV2, LocalUnboundV2, ProfileCheckoutV2, ProfileLeaseV2,
    ProfileRef, ReleaseLeaseV2, ReleaseReason, UnboundBinding, UploadCreatedV2, UploadFinalizedV2,
    RECORD_TYPE_CHECKED_OUT, RECORD_TYPE_LEASE_RELEASED, RECORD_TYPE_LOCAL_UNBOUND,
    RECORD_TYPE_UPLOAD_CREATED, RECORD_TYPE_UPLOAD_FINALIZED,
};
use shardx_core::restore_epoch::{
    verify_inclusion, InclusionError, RestoreEpochInclusionProofV2, SignedRestoreEpochTransitionV2,
};
use shardx_core::signing::Ed25519SigningKey;
use shardx_core::snapshot_v2::{
    CommitReceiptBindingV2, CommitRequestV2, FinalizeUploadV2, SignedSnapshotManifestV2,
    SnapshotManifestV2,
};
use shardx_core::trust_chain::{Binding, Recipient, Scope};

use super::{db::Db, ledger};
use crate::errcode::{code, code_with};
use crate::fleet_client::{decode_hex16, hex, Exact, FleetClient};

/// The pilot lease TTL (plan 10.1 L1398 proposes 90 s; uploads renew).
const LEASE_TTL_SECONDS: u32 = 300;
/// PATCH chunk size; the server takes up to 8 MiB.
#[cfg(not(test))]
const CHUNK: usize = 4 << 20;
#[cfg(test)]
const CHUNK: usize = 64 << 10;
const COMMIT_RECORD: &str = "CommitReceiptBindingV2";

/// This device, as sync needs it: its signing key, the identity a fleet key
/// grant names, and the anchor it pinned.
pub(crate) struct Device {
    pub signer: Ed25519SigningKey,
    pub me: Recipient,
    pub pin: (Binding, [u8; 32]),
}

/// A finished push.
#[derive(Debug)]
pub(crate) struct Pushed {
    pub version: u64,
    pub ciphertext_size: u64,
    pub ciphertext_sha256: [u8; 32],
}

/// A `profile_bindings` row.
struct Bound {
    local: String,
    instance: [u8; 16],
    tenant: [u8; 16],
    fleet: [u8; 16],
    profile: [u8; 16],
    version: u64,
    head: Option<[u8; 32]>,
    epoch: u64,
    lease: Option<LeaseRef>,
    state: String,
    error: Option<String>,
}

impl Bound {
    fn pref(&self) -> ProfileRef {
        ProfileRef {
            tenant_id: self.tenant,
            fleet_id: self.fleet,
            profile_id: self.profile,
        }
    }
}

/// An `operations` row.
struct Op {
    op_id: String,
    kind: String,
    state: String,
    instance: String,
    epoch: u64,
    remote_profile: Option<String>,
    key: String,
    canonical: Vec<u8>,
    exact: Vec<u8>,
    exact_sha: Vec<u8>,
    upload: Option<String>,
    lease_id: Option<String>,
    fence: Option<i64>,
    base: Option<i64>,
    snapshot: Option<Vec<u8>>,
    replay: Option<Vec<u8>>,
    intent: Option<Vec<u8>>,
    cipher: Option<Vec<u8>>,
    manifest: Option<Vec<u8>>,
    manifest_hash: Option<Vec<u8>>,
    manifest_sha: Option<Vec<u8>>,
    receipt: Option<Vec<u8>>,
}

/// What a new operation row carries besides its request.
#[derive(Default)]
struct Columns<'a> {
    upload: Option<[u8; 16]>,
    lease: Option<LeaseRef>,
    snapshot: Option<([u8; 16], [u8; 16])>,
    intent: Option<[u8; 32]>,
    cipher: Option<[u8; 32]>,
    manifest: Option<&'a SignedSnapshotManifestV2>,
}

fn bad(field: &str) -> anyhow::Error {
    anyhow!(code_with("sync.badReplySync", &[("field", field)]))
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    // `getrandom` is Windows-only in this crate; shared has it everywhere.
    shardx_core::keys::fill_random(&mut b).map_err(|e| anyhow!("{e}"))?;
    Ok(b)
}

fn wire(v: u64) -> Result<i64> {
    i64::try_from(v).map_err(|_| anyhow!("WIRE_INTEGER_OUT_OF_RANGE"))
}

fn fixed<const N: usize>(v: &[u8]) -> Result<[u8; N]> {
    v.try_into()
        .map_err(|_| anyhow!(code("team.trustLedgerUnreadable")))
}

fn spool(name: &str) -> Result<std::path::PathBuf> {
    Ok(crate::store::config_root()?
        .join("team-sync")
        .join("spool")
        .join(format!("{name}.part")))
}

/// Whether `local` is a published profile. No team database means none is.
// shortcut: a missing team database reads as unpublished, so the legacy path
// runs and the server refuses its writes (PROFILE_PUBLISHED); opening the
// database needs write access to the config root. Restore bindings from the
// server once the Team profile UI records them.
pub(crate) fn is_published(local: &str) -> Result<bool> {
    if !Db::path()?.exists() {
        return Ok(false);
    }
    let db = Db::open()?;
    Ok(db
        .conn
        .query_row(
            "SELECT 1 FROM profile_bindings WHERE local_profile_id = ?1",
            [local],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn bound(db: &Db, local: &str) -> Result<Bound> {
    let row = db
        .conn
        .query_row(
            "SELECT server_instance_id, tenant_id, fleet_id, remote_profile_id, remote_version,
                    last_observed_head_hash, accepted_restore_epoch, lease_id, fencing_token,
                    sync_state, last_error_code
             FROM profile_bindings WHERE local_profile_id = ?1",
            [local],
            |r| {
                Ok((
                    [r.get::<_, String>(0)?, r.get(1)?, r.get(2)?, r.get(3)?],
                    r.get::<_, i64>(4)?,
                    r.get::<_, Option<Vec<u8>>>(5)?,
                    r.get::<_, i64>(6)?,
                    r.get::<_, Option<String>>(7)?,
                    r.get::<_, Option<i64>>(8)?,
                    r.get::<_, String>(9)?,
                    r.get::<_, Option<String>>(10)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| anyhow!(code("sync.profileNotListed")))?;
    let ([instance, tenant, fleet, profile], version, head, epoch, lease_id, fence, state, error) =
        row;
    let version = version as u64;
    let lease = match (lease_id, fence) {
        (Some(id), Some(f)) => Some(LeaseRef {
            lease_id: decode_hex16(&id, "lease_id")?,
            fencing_token: f as u64,
            base_version: version,
        }),
        _ => None,
    };
    Ok(Bound {
        local: local.to_string(),
        instance: decode_hex16(&instance, "server_instance_id")?,
        tenant: decode_hex16(&tenant, "tenant_id")?,
        fleet: decode_hex16(&fleet, "fleet_id")?,
        profile: decode_hex16(&profile, "remote_profile_id")?,
        version,
        head: head.map(|h| fixed(&h)).transpose()?,
        epoch: epoch as u64,
        lease,
        state,
        error,
    })
}

/// Quarantines `local` with `reason` (plan L1233, L1237) and returns `err`.
fn quarantine(db: &Db, local: &str, reason: &str, err: anyhow::Error) -> anyhow::Error {
    let marked = db.conn.execute(
        "UPDATE profile_bindings SET sync_state = 'QUARANTINED', last_error_code = ?2
         WHERE local_profile_id = ?1",
        params![local, reason],
    );
    match marked {
        Ok(_) => err,
        Err(e) => anyhow!(e).context(err.to_string()),
    }
}

fn refuse_quarantined(b: &Bound) -> Result<()> {
    if b.state == "QUARANTINED" {
        bail!(code_with(
            "sync.bindingQuarantined",
            &[("reason", b.error.as_deref().unwrap_or_default())]
        ));
    }
    Ok(())
}

const OP_COLUMNS: &str = "op_id, kind, state, server_instance_id, restore_epoch,
    remote_profile_id, idempotency_key, canonical_request_hash, exact_request_bytes,
    exact_request_bytes_sha256, remote_upload_id, lease_id, fencing_token, base_version,
    snapshot_id, manifest_replay_id, intent_hash, ciphertext_sha256,
    signed_manifest_container_bytes, signed_manifest_container_hash,
    signed_manifest_container_bytes_sha256, exact_receipt_bytes";

fn op_row(r: &rusqlite::Row) -> rusqlite::Result<Op> {
    Ok(Op {
        op_id: r.get(0)?,
        kind: r.get(1)?,
        state: r.get(2)?,
        instance: r.get(3)?,
        epoch: r.get::<_, i64>(4)? as u64,
        remote_profile: r.get(5)?,
        key: r.get(6)?,
        canonical: r.get(7)?,
        exact: r.get(8)?,
        exact_sha: r.get(9)?,
        upload: r.get(10)?,
        lease_id: r.get(11)?,
        fence: r.get(12)?,
        base: r.get(13)?,
        snapshot: r.get(14)?,
        replay: r.get(15)?,
        intent: r.get(16)?,
        cipher: r.get(17)?,
        manifest: r.get(18)?,
        manifest_hash: r.get(19)?,
        manifest_sha: r.get(20)?,
        receipt: r.get(21)?,
    })
}

/// The newest live `kind` operation of `local`, for `lease` when given, in
/// `state` when given. A FAILED or QUARANTINED one is never resumed.
fn find(
    db: &Db,
    local: &str,
    kind: &str,
    lease: Option<&LeaseRef>,
    state: Option<&str>,
) -> Result<Option<Op>> {
    let lease = lease.map(|l| hex(&l.lease_id));
    Ok(db
        .conn
        .query_row(
            &format!(
                "SELECT {OP_COLUMNS} FROM operations
                 WHERE local_profile_id = ?1 AND kind = ?2 AND (?3 IS NULL OR lease_id = ?3)
                   AND state IN ('PENDING', 'COMPLETED') AND (?4 IS NULL OR state = ?4)
                 ORDER BY rowid DESC LIMIT 1"
            ),
            params![local, kind, lease, state],
            op_row,
        )
        .optional()?)
}

fn get_op(db: &Db, op_id: &str) -> Result<Op> {
    Ok(db.conn.query_row(
        &format!("SELECT {OP_COLUMNS} FROM operations WHERE op_id = ?1"),
        [op_id],
        op_row,
    )?)
}

/// Stores a PENDING `kind` operation for `b` whose exact request is `exact`.
#[allow(clippy::too_many_arguments)]
fn insert_op(
    conn: &rusqlite::Connection,
    b: &Bound,
    op_id: &str,
    kind: &str,
    scope: &str,
    key: &[u8; 16],
    canonical: &[u8; 32],
    exact: &[u8],
    c: &Columns,
) -> Result<()> {
    let m = c.manifest;
    conn.execute(
        "INSERT INTO operations(op_id, local_profile_id, local_profile_id_at_request,
           server_instance_id, restore_epoch, tenant_id, fleet_id, remote_profile_id,
           snapshot_id, manifest_replay_id, operation_scope, kind, idempotency_key,
           canonical_request_hash, exact_request_bytes, exact_request_bytes_sha256,
           remote_upload_id, lease_id, fencing_token, base_version, intent_hash,
           ciphertext_sha256, signed_manifest_container_bytes, signed_manifest_container_hash,
           signed_manifest_container_bytes_sha256, state, created_at, updated_at)
         VALUES (?1, ?2, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
           ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, 'PENDING',
           strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
        params![
            op_id,
            b.local,
            hex(&b.instance),
            wire(b.epoch)?,
            hex(&b.tenant),
            hex(&b.fleet),
            hex(&b.profile),
            c.snapshot.map(|s| s.0.to_vec()),
            c.snapshot.map(|s| s.1.to_vec()),
            format!("{scope} {}/{}", hex(&b.instance), b.epoch),
            kind,
            hex(key),
            canonical.to_vec(),
            exact,
            sha256(exact).to_vec(),
            c.upload.map(|u| hex(&u)),
            c.lease.map(|l| hex(&l.lease_id)),
            c.lease.map(|l| wire(l.fencing_token)).transpose()?,
            c.lease.map(|l| wire(l.base_version)).transpose()?,
            c.intent.map(|h| h.to_vec()),
            c.cipher.map(|h| h.to_vec()),
            m.map(|m| m.exact_bytes().to_vec()),
            m.map(|m| m.signed_container_hash().to_vec()),
            m.map(|m| m.exact_bytes_sha256().to_vec()),
        ],
    )?;
    Ok(())
}

/// The exact request of an idempotent mutation of `kind` over `payload`.
fn mutation(
    kind: OperationKind,
    payload: Vec<u8>,
    b: &Bound,
) -> Result<([u8; 16], Vec<u8>, [u8; 32])> {
    let req = IdempotentMutationRequestV2 {
        operation_kind: kind,
        idempotency_key: random()?,
        canonical_payload_bytes: payload,
        client_request_nonce: random()?,
        server_instance_id: b.instance,
        restore_epoch: b.epoch,
    };
    Ok((
        req.idempotency_key,
        req.encode(),
        req.canonical_request_hash(),
    ))
}

fn kind_of(kind: &str) -> Option<OperationKind> {
    Some(match kind {
        "CHECKOUT" => OperationKind::ProfileCheckout,
        "UPLOAD" => OperationKind::CreateUpload,
        "FINALIZE" => OperationKind::FinalizeUpload,
        "RELEASE" => OperationKind::ReleaseLease,
        "UNBIND" => OperationKind::LocalUnbind,
        _ => return None,
    })
}

/// G2-37: the columns of `op` (and of its upload session and spool, for an
/// upload or commit) against its exact stored bytes. The first that differs,
/// if any.
fn first_drift(db: &Db, op: &Op) -> Result<Option<&'static str>> {
    let same = |col: &Option<Vec<u8>>, v: &[u8]| col.as_deref() == Some(v);
    let text = |col: &Option<String>, v: &[u8]| col.as_deref() == Some(hex(v).as_str());
    let lease_is = |l: &LeaseRef| {
        text(&op.lease_id, &l.lease_id)
            && op.fence == Some(l.fencing_token as i64)
            && op.base == Some(l.base_version as i64)
    };
    let mut checks = vec![(
        "exact_request_bytes_sha256",
        op.exact_sha == sha256(&op.exact),
    )];
    if let Some(kind) = kind_of(&op.kind) {
        let Ok(req) = IdempotentMutationRequestV2::parse(&op.exact) else {
            return Ok(Some("exact_request_bytes"));
        };
        checks.extend([
            ("operation_kind", req.operation_kind == kind),
            ("idempotency_key", op.key == hex(&req.idempotency_key)),
            (
                "canonical_request_hash",
                op.canonical == req.canonical_request_hash(),
            ),
            (
                "server_instance_id",
                op.instance == hex(&req.server_instance_id),
            ),
            ("restore_epoch", op.epoch == req.restore_epoch),
        ]);
        let p = &req.canonical_payload_bytes;
        match kind {
            OperationKind::ProfileCheckout => {
                let ok = ProfileCheckoutV2::parse(p)
                    .is_ok_and(|c| text(&op.remote_profile, &c.profile.profile_id));
                checks.push(("remote_profile_id", ok));
            }
            OperationKind::CreateUpload => {
                let Ok(t) = CreateUploadV2::parse(p) else {
                    return Ok(Some("canonical_payload_bytes"));
                };
                let spooled = std::fs::read(spool(&op.op_id)?).unwrap_or_default();
                checks.extend([
                    (
                        "remote_profile_id",
                        text(&op.remote_profile, &t.profile.profile_id),
                    ),
                    ("snapshot_id", same(&op.snapshot, &t.snapshot_id)),
                    (
                        "manifest_replay_id",
                        same(&op.replay, &t.manifest_replay_id),
                    ),
                    ("lease_id", lease_is(&t.lease)),
                    ("intent_hash", same(&op.intent, &t.intent_hash)),
                    (
                        "ciphertext_sha256",
                        same(&op.cipher, &t.expected_ciphertext_sha256),
                    ),
                    ("spool", sha256(&spooled) == t.expected_ciphertext_sha256),
                ]);
            }
            OperationKind::FinalizeUpload => {
                let Ok(f) = FinalizeUploadV2::parse(p) else {
                    return Ok(Some("canonical_payload_bytes"));
                };
                let c = f.commit();
                let commit = op
                    .upload
                    .as_deref()
                    .map(|u| {
                        db.conn
                            .query_row(
                                "SELECT exact_request_bytes FROM operations
                                 WHERE kind = 'COMMIT' AND remote_upload_id = ?1",
                                [u],
                                |r| r.get::<_, Vec<u8>>(0),
                            )
                            .optional()
                    })
                    .transpose()?
                    .flatten();
                checks.extend([
                    ("remote_upload_id", text(&op.upload, c.upload_id())),
                    ("commit_request", commit.as_deref() == Some(c.exact_bytes())),
                ]);
            }
            OperationKind::ReleaseLease => {
                let ok = ReleaseLeaseV2::parse(p).is_ok_and(|r| lease_is(&r.lease));
                checks.push(("lease_id", ok));
            }
            OperationKind::LocalUnbind => {
                let ok = LocalUnbindV2::parse(p)
                    .is_ok_and(|u| text(&op.remote_profile, &u.binding.remote_profile_id));
                checks.push(("remote_profile_id", ok));
            }
            _ => {}
        }
    } else if op.kind == "COMMIT" {
        let Ok(c) = CommitRequestV2::parse(&op.exact) else {
            return Ok(Some("exact_request_bytes"));
        };
        let m = c.manifest();
        let p = SnapshotManifestV2::parse(m.canonical_manifest_payload_bytes())
            .map_err(|_| bad("signed_manifest_container_bytes"))?;
        checks.extend([
            ("idempotency_key", op.key == hex(c.idempotency_key())),
            (
                "canonical_request_hash",
                op.canonical == c.canonical_request_hash(),
            ),
            ("remote_upload_id", text(&op.upload, c.upload_id())),
            (
                "server_instance_id",
                op.instance == hex(&p.server_instance_id),
            ),
            ("restore_epoch", op.epoch == p.restore_epoch),
            ("snapshot_id", same(&op.snapshot, &p.snapshot_id)),
            (
                "manifest_replay_id",
                same(&op.replay, &p.manifest_replay_id),
            ),
            (
                "lease_id",
                lease_is(&LeaseRef {
                    lease_id: p.lease_id,
                    fencing_token: p.fencing_token,
                    base_version: p.base_version,
                }),
            ),
            ("intent_hash", same(&op.intent, &p.intent_hash)),
            ("ciphertext_sha256", same(&op.cipher, &p.ciphertext_sha256)),
            (
                "signed_manifest_container_bytes",
                same(&op.manifest, m.exact_bytes()),
            ),
            (
                "signed_manifest_container_hash",
                same(&op.manifest_hash, m.signed_container_hash()),
            ),
            (
                "signed_manifest_container_bytes_sha256",
                same(&op.manifest_sha, m.exact_bytes_sha256()),
            ),
        ]);
        let s = session(db, &op.op_id)?;
        let spooled = std::fs::read(spool(&s.spool)?).unwrap_or_default();
        checks.extend([
            (
                "upload.server_instance_id",
                s.instance == hex(&p.server_instance_id),
            ),
            ("upload.restore_epoch", s.epoch == p.restore_epoch),
            ("upload.remote_upload_id", s.upload == hex(c.upload_id())),
            ("upload.snapshot_id", s.snapshot[..] == p.snapshot_id),
            (
                "upload.manifest_replay_id",
                s.replay[..] == p.manifest_replay_id,
            ),
            ("upload.intent_hash", s.intent[..] == p.intent_hash),
            (
                "upload.preamble_sha256",
                s.preamble[..] == p.preamble_sha256,
            ),
            (
                "upload.dek_slot_sha256",
                s.dek_slot[..] == p.dek_slot_sha256,
            ),
            ("upload.fkek_key_id", s.fkek_key_id == hex(&p.fkek_key_id)),
            (
                "upload.key_generation",
                s.key_generation == p.key_generation,
            ),
            (
                "upload.expected_ciphertext_sha256",
                s.sha[..] == p.ciphertext_sha256,
            ),
            (
                "upload.expected_ciphertext_size",
                s.size == p.ciphertext_size,
            ),
            ("spool", sha256(&spooled) == p.ciphertext_sha256),
        ]);
    }
    Ok(checks.into_iter().find(|(_, ok)| !ok).map(|(f, _)| f))
}

/// `op`'s exact stored bytes, once its columns still match them; otherwise
/// the binding is quarantined and nothing is sent.
fn stored<'a>(db: &Db, b: &Bound, op: &'a Op) -> Result<&'a [u8]> {
    if let Some(field) = first_drift(db, op)? {
        let _ = db.conn.execute(
            "UPDATE operations SET state = 'QUARANTINED' WHERE op_id = ?1",
            [&op.op_id],
        );
        return Err(quarantine(
            db,
            &b.local,
            "STORED_REQUEST_MISMATCH",
            anyhow!(code_with("sync.storedRequestMismatch", &[("field", field)])),
        ));
    }
    Ok(&op.exact)
}

/// A reply to a stored request: the body on success. A refusal fails the
/// operation, so it is never resent; anything else (a lost reply, 401, 408,
/// 429, 5xx) leaves it PENDING for the next attempt to resend as it is.
fn settle(db: &Db, op: &Op, reply: Exact) -> Result<std::result::Result<Vec<u8>, anyhow::Error>> {
    if (200..300).contains(&reply.status) {
        return Ok(Ok(reply.body));
    }
    let err = refused(&reply);
    if terminal(reply.status) {
        db.conn.execute(
            "UPDATE operations SET state = 'FAILED', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE op_id = ?1",
            [&op.op_id],
        )?;
        return Ok(Err(err));
    }
    Err(err)
}

/// A 4xx the request itself caused. A 401 only ends the session, and 408/429
/// ask to resend later (plan 8.2 L1224, L1244).
fn terminal(status: u16) -> bool {
    (400..500).contains(&status) && !matches!(status, 401 | 408 | 429)
}

fn refused(reply: &Exact) -> anyhow::Error {
    if reply.status == 401 {
        return anyhow!(code("sync.authRequired"));
    }
    let detail: String = String::from_utf8_lossy(&reply.body)
        .chars()
        .take(300)
        .collect();
    anyhow!(code_with(
        "fleet.refusedSync",
        &[("status", &reply.status.to_string()), ("detail", &detail)]
    ))
}

/// A reply that is not a stored request's: success or an error.
fn ok(reply: Exact) -> Result<Exact> {
    if (200..300).contains(&reply.status) {
        Ok(reply)
    } else {
        Err(refused(&reply))
    }
}

/// The error `code` of a refused reply and, for a commit a server restore
/// rolled back, the `superseded_by_restore_epoch` it names (ADR 0002 D-1,
/// Q-34; plan 8.2 L1220).
fn refusal_of(reply: &Exact) -> (Option<String>, Option<u64>) {
    let v: serde_json::Value = serde_json::from_slice(&reply.body).unwrap_or_default();
    (
        v["code"].as_str().map(str::to_string),
        v["superseded_by_restore_epoch"].as_u64(),
    )
}

/// Q-34: an upload or finalize a server restore rolled back. The local
/// profile is untouched and the next push starts a new upload.
fn superseded_upload() -> anyhow::Error {
    anyhow!(code("sync.uploadSuperseded"))
}

/// The payload of a stored response to `op`, once it names `op` exactly.
fn stored_response(op: &Op, record_type: &str, body: &[u8]) -> Result<Vec<u8>> {
    let r =
        IdempotentStoredResponseV2::parse(body).map_err(|_| bad("IdempotentStoredResponseV2"))?;
    let checks = [
        (
            "operation_kind",
            Some(r.operation_kind) == kind_of(&op.kind),
        ),
        ("idempotency_key", op.key == hex(&r.idempotency_key)),
        ("exact_request_hash", op.canonical == r.exact_request_hash),
        (
            "response_record_type",
            r.response_record_type == record_type,
        ),
        (
            "server_instance_id",
            op.instance == hex(&r.server_instance_id),
        ),
        ("restore_epoch", op.epoch == r.restore_epoch),
    ];
    if let Some((field, _)) = checks.iter().find(|(_, ok)| !ok) {
        return Err(bad(field));
    }
    Ok(r.canonical_response_payload_bytes)
}

/// Marks `op` COMPLETED with its exact response, which is also its receipt
/// for a commit or release.
fn complete(conn: &rusqlite::Connection, op: &Op, record_type: &str, body: &[u8]) -> Result<()> {
    let receipt = matches!(op.kind.as_str(), "COMMIT" | "RELEASE");
    conn.execute(
        "UPDATE operations SET state = 'COMPLETED', response_record_type = ?2,
           exact_response_bytes = ?3, exact_response_bytes_sha256 = ?4,
           exact_receipt_bytes = CASE WHEN ?5 THEN ?3 END,
           receipt_sha256 = CASE WHEN ?5 THEN ?4 END,
           updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
         WHERE op_id = ?1 AND state = 'PENDING'",
        params![op.op_id, record_type, body, sha256(body).to_vec(), receipt],
    )?;
    Ok(())
}

/// An `upload_sessions` row.
struct Session {
    upload_local_id: String,
    instance: String,
    epoch: u64,
    upload: String,
    snapshot: Vec<u8>,
    replay: Vec<u8>,
    intent: Vec<u8>,
    preamble: Vec<u8>,
    dek_slot: Vec<u8>,
    fkek_key_id: String,
    key_generation: u64,
    sha: Vec<u8>,
    size: u64,
    spool: String,
    state: String,
}

fn session(db: &Db, commit_op: &str) -> Result<Session> {
    Ok(db.conn.query_row(
        "SELECT upload_local_id, server_instance_id, restore_epoch, remote_upload_id, snapshot_id,
                manifest_replay_id, intent_hash, preamble_sha256, dek_slot_sha256, fkek_key_id,
                key_generation, expected_ciphertext_sha256, expected_ciphertext_size, spool_ref,
                state
         FROM upload_sessions WHERE commit_op_id = ?1",
        [commit_op],
        |r| {
            Ok(Session {
                upload_local_id: r.get(0)?,
                instance: r.get(1)?,
                epoch: r.get::<_, i64>(2)? as u64,
                upload: r.get(3)?,
                snapshot: r.get(4)?,
                replay: r.get(5)?,
                intent: r.get(6)?,
                preamble: r.get(7)?,
                dek_slot: r.get(8)?,
                fkek_key_id: r.get(9)?,
                key_generation: r.get::<_, i64>(10)? as u64,
                sha: r.get(11)?,
                size: r.get::<_, i64>(12)? as u64,
                spool: r.get(13)?,
                state: r.get(14)?,
            })
        },
    )?)
}

/// The server's restore epoch and `b`'s listed head, from the fleet listing
/// pages up to the one that lists it. Every page names `b`'s instance,
/// tenant and fleet, at one epoch.
async fn listing(
    client: &FleetClient,
    access: &str,
    b: &Bound,
) -> Result<(u64, Option<FleetProfileHeadV2>)> {
    let mut after: Option<[u8; 16]> = None;
    let mut epoch = None;
    loop {
        let reply = ok(client
            .list_fleet_profiles(access, &b.fleet, after.as_ref())
            .await?)?;
        let page = FleetProfilePageV2::parse(&reply.body).map_err(|_| bad("FleetProfilePageV2"))?;
        if (page.server_instance_id, page.tenant_id, page.fleet_id)
            != (b.instance, b.tenant, b.fleet)
        {
            return Err(bad("server_instance_id"));
        }
        if *epoch.get_or_insert(page.restore_epoch) != page.restore_epoch {
            return Err(bad("restore_epoch"));
        }
        if let Some(p) = page.profiles.iter().find(|p| p.profile_id == b.profile) {
            return Ok((page.restore_epoch, Some(p.clone())));
        }
        match page.next_after {
            Some(a) if after.is_none_or(|x| a > x) => after = Some(a),
            Some(_) => return Err(bad("next_after")),
            None => return Ok((page.restore_epoch, None)),
        }
    }
}

/// Rule 6 against the listed head: the binding's instance and accepted
/// epoch, and never behind the pinned head. A rollback, or an epoch with no
/// accepted transition, quarantines the binding.
async fn listed(
    client: &FleetClient,
    access: &str,
    db: &mut Db,
    b: &Bound,
) -> Result<FleetProfileHeadV2> {
    let (epoch, p) = listing(client, access, b).await?;
    if epoch != b.epoch {
        let (reason, key) = if epoch < b.epoch {
            ("HEAD_ROLLBACK_DETECTED", "sync.headRollback")
        } else {
            (TRANSITION_REQUIRED, "sync.epochTransitionRequired")
        };
        return Err(quarantine(db, &b.local, reason, anyhow!(code(key))));
    }
    let p = p.ok_or_else(|| anyhow!(code("sync.profileNotListed")))?;
    if p.current_version < b.version
        || (p.current_version == b.version && p.current_signed_head_hash != b.head)
    {
        return Err(quarantine(
            db,
            &b.local,
            "HEAD_ROLLBACK_DETECTED",
            anyhow!(code("sync.headRollback")),
        ));
    }
    Ok(p)
}

const TRANSITION_REQUIRED: &str = "RESTORE_EPOCH_TRANSITION_REQUIRED";

/// Whether `b` waits for a restore epoch transition that was not served yet
/// (plan 8.2 L1237). A transition or proof that was served and refused
/// (invalid, another tenant's, no proof for `b`) stays quarantined until an
/// operator acts.
fn awaits_transition(b: &Bound) -> bool {
    b.state == "QUARANTINED" && b.error.as_deref() == Some(TRANSITION_REQUIRED)
}

/// How many versions at or below the pinned one the leaf's new head is
/// looked for; past it the server is not believed (fails closed).
const LEAF_SEARCH: u64 = 64;

/// One verified `E -> E+1` step of a binding: the signed transition and its
/// inclusion proof, as exact bytes.
struct Step {
    transition: shardx_core::restore_epoch::VerifiedTransition,
    proof: RestoreEpochInclusionProofV2,
    proof_bytes: Vec<u8>,
}

/// Why a served transition or proof does not move a binding: its
/// quarantine reason (plan 8.2 L1237) and the error the user sees.
fn refusal(reason: &'static str, field: &str) -> (&'static str, anyhow::Error) {
    let err = match reason {
        TRANSITION_REQUIRED => anyhow!(code("sync.epochTransitionMissing")),
        "RESTORE_EPOCH_PROOF_MISSING" => anyhow!(code("sync.epochProofMissing")),
        "RESTORE_EPOCH_CROSS_TENANT" => anyhow!(code("sync.epochCrossTenant")),
        _ => anyhow!(code_with(
            "sync.epochTransitionInvalid",
            &[("field", field)]
        )),
    };
    (reason, err)
}

/// Rule 6, L2243, L2057: moves `b` from its accepted epoch to the server's
/// through its tenant's signed `E -> E+1` transitions, each signed by a key
/// trusted as a revocation's issuer is ([`verify_transition`]), and its own
/// inclusion proof in each, whose leaf starts at the head `b` pinned (or at
/// the head it ends at, as when the restore rolled back only a commit `b`
/// never pinned). A new head the last leaf ends at is accepted as rule 6
/// accepts one ([`verify_leaf_head`]). A lease from before the restore is
/// released first. The exact transition and proof bytes are stored and read
/// back, the binding, as it was read, accepts the new epoch and pins the
/// leaf's new head, and the trust evaluation they relied on is recorded
/// (`ledger::record`), in one transaction. Anything else keeps it
/// quarantined under a named reason, and the evaluation is still recorded,
/// as collecting a fleet key records one whose grant does not open, so a
/// lapse it observed is kept; a lost reply changes nothing else.
// shortcut: a binding pinned behind both heads of its leaf (it missed
// commits before the restore) stays quarantined; accept it once the
// manifests from its pin to the leaf's previous head can be verified.
async fn accept_transitions(
    client: &FleetClient,
    access: &str,
    dev: &Device,
    db: &mut Db,
    b: &Bound,
    now: u64,
) -> Result<()> {
    // The restore released every lease (D-1): one held from before it is
    // released as any other, and the binding keeps waiting.
    let released;
    let b = match b.lease {
        Some(lease) => {
            let op = match find(db, &b.local, "RELEASE", Some(&lease), Some("PENDING"))? {
                Some(op) => op,
                None => get_op(db, &release_op(&db.conn, b, lease)?)?,
            };
            release_reply(client, access, db, b, &op).await?;
            db.conn.execute(
                "UPDATE profile_bindings SET sync_state = 'QUARANTINED', last_error_code = ?2
                 WHERE local_profile_id = ?1",
                params![b.local, TRANSITION_REQUIRED],
            )?;
            released = bound(db, &b.local)?;
            &released
        }
        None => b,
    };
    let (epoch, listed) = listing(client, access, b).await?;
    if epoch <= b.epoch {
        return Err(quarantine(
            db,
            &b.local,
            "HEAD_ROLLBACK_DETECTED",
            anyhow!(code("sync.headRollback")),
        ));
    }
    let listed = listed.ok_or_else(|| anyhow!(code("sync.profileNotListed")))?;
    let pages = client.trust_evidence(access, &hex(&b.tenant)).await?;
    let evaluated = ledger::evaluate(db, &dev.pin.0, &dev.pin.1, &pages, now)?;
    let chain = evaluated.as_ref().map(|(_, c)| c);
    // A reborrow moves in: the future stays Send across its awaits.
    let accepted = {
        let db = &mut *db;
        let pages = &pages;
        async move {
            let keys: std::collections::BTreeMap<[u8; 32], [u8; 32]> = pages
                .iter()
                .flat_map(|p| &p.signing_public_keys)
                .map(|pk| (shardx_core::keys::signing_key_id(pk), *pk))
                .collect();
            let mut head = b.head;
            let mut steps = Vec::new();
            for e in b.epoch..epoch {
                let epochs = (e, e + 1);
                let get =
                    |profile| client.restore_epoch_transition(access, &b.tenant, epochs, profile);
                let reply = get(None).await?;
                let checked = match reply.status {
                    404 => Err(refusal(TRANSITION_REQUIRED, "")),
                    _ => {
                        let body = ok(reply)?.body;
                        verify_transition(db, dev, b, chain, &keys, epochs, &body, now)
                    }
                };
                let checked = match checked {
                    Ok(t) => {
                        let reply = get(Some(&b.profile)).await?;
                        match reply.status {
                            404 => Err(refusal("RESTORE_EPOCH_PROOF_MISSING", "")),
                            _ => {
                                let body = ok(reply)?.body;
                                verify_proof(&t, b, head, body).map(|(p, bytes)| (t, p, bytes))
                            }
                        }
                    }
                    Err(r) => Err(r),
                };
                let (transition, proof, proof_bytes) = match checked {
                    Ok(s) => s,
                    Err((reason, err)) => return Err(quarantine(db, &b.local, reason, err)),
                };
                head = Some(proof.leaf.new_signed_head_hash);
                steps.push(Step {
                    transition,
                    proof,
                    proof_bytes,
                });
            }
            // An unchanged pin keeps its version. Otherwise the leaf's new head is a
            // committed manifest whose exact bytes hash to it, at most `LEAF_SEARCH`
            // versions at or below the pinned one (a restore only goes back), and
            // accepted as a new head is (rule 6) except for its earlier epoch.
            let version = if head == b.head {
                b.version
            } else {
                let top = b.version.min(listed.current_version);
                let low = top.saturating_sub(LEAF_SEARCH - 1).max(1);
                let mut found = None;
                for v in (low..=top).rev() {
                    let reply = ok(client.snapshot_manifest(access, &b.profile, v).await?)?;
                    let m = SignedSnapshotManifestV2::parse(&reply.body)
                        .map_err(|_| bad("SignedSnapshotManifestV2"))?;
                    if Some(m.head_hash()) == head {
                        found = Some((v, m));
                        break;
                    }
                }
                let checked = match found {
                    Some((v, m)) => {
                        verify_leaf_head(db, dev, b, chain, &keys, m, (v, epoch), now).map(|()| v)
                    }
                    None => Err(refusal(
                        "RESTORE_EPOCH_TRANSITION_INVALID",
                        "new_signed_head_hash",
                    )),
                };
                match checked {
                    Ok(v) => v,
                    Err((reason, err)) => return Err(quarantine(db, &b.local, reason, err)),
                }
            };
            Ok::<_, anyhow::Error>((steps, version, head))
        }
    }
    .await;
    let record = |tx: &rusqlite::Connection| match &evaluated {
        Some((seen, c)) => ledger::record_in(tx, &dev.pin.0, seen, c, None, now),
        None => Ok(()),
    };
    let refused = match accepted.and_then(|(steps, version, head)| {
        let url = client.base_url();
        store_transitions(db, url, b, &steps, (epoch, version, head), record)
    }) {
        Ok(true) => return Ok(()),
        Ok(false) => {
            let (reason, err) = refusal("RESTORE_EPOCH_TRANSITION_INVALID", "readback");
            quarantine(db, &b.local, reason, err)
        }
        Err(e) => e,
    };
    // In its own transaction, and never in place of the refusal: a record
    // that fails leaves nothing behind, and the next evaluation records.
    if let Some((seen, c)) = &evaluated {
        if let Err(e) = ledger::record(db, &dev.pin.0, seen, c, None, now) {
            eprintln!("[sync] trust ledger: {e:#}");
        }
    }
    Err(refused)
}

type Refused = (&'static str, anyhow::Error);

/// The served `epochs` transition of `b`'s tenant, once its exact bytes
/// parse, its signature verifies under the key it names, it names `b`'s
/// tenant, instance and exactly `epochs`, and its signer is trusted as a
/// revocation's issuer is (rule 6): a root custodian at its `issued_at_ms`,
/// still one now, when this device first sees it, not dated at or before
/// a lapse this device observed (Q-25: the signer chooses `issued_at_ms`,
/// so it is not backdated past one; a re-appointment after it signs again),
/// and not withdrawn.
#[allow(clippy::too_many_arguments)]
fn verify_transition(
    db: &Db,
    dev: &Device,
    b: &Bound,
    chain: Option<&shardx_core::trust_chain::TrustChain>,
    keys: &std::collections::BTreeMap<[u8; 32], [u8; 32]>,
    epochs: (u64, u64),
    body: &[u8],
    now: u64,
) -> std::result::Result<shardx_core::restore_epoch::VerifiedTransition, Refused> {
    let invalid = |field| refusal("RESTORE_EPOCH_TRANSITION_INVALID", field);
    let parsed = SignedRestoreEpochTransitionV2::parse(body)
        .map_err(|_| invalid("SignedRestoreEpochTransitionV2"))?;
    let signer = *parsed.approver_signing_key_id();
    let pk = keys
        .get(&signer)
        .ok_or_else(|| invalid("approver_signing_key_id"))?;
    let t = parsed
        .verify_signature(pk)
        .map_err(|_| invalid("signature_bytes"))?;
    let p = t.payload();
    if p.tenant_id != b.tenant {
        return Err(refusal("RESTORE_EPOCH_CROSS_TENANT", "tenant_id"));
    }
    if p.server_instance_id != b.instance {
        return Err(invalid("server_instance_id"));
    }
    if (p.previous_epoch, p.new_epoch) != epochs {
        return Err(invalid("previous_epoch"));
    }
    let withdrawn = ledger::withdrawn(db, &dev.pin.0, &signer).unwrap_or(true);
    let lapsed = ledger::lapsed_at(db, &dev.pin.0, &signer)
        .map(|at| at.is_some_and(|at| p.issued_at_ms <= at))
        .unwrap_or(true);
    let custodian = chain
        .is_some_and(|c| c.custodian_at(&signer, p.issued_at_ms) && c.custodian_now(&signer, now));
    if !custodian || lapsed || withdrawn {
        return Err(invalid("approver_signing_key_id"));
    }
    Ok(t)
}

/// Rule 6, first acceptance, for the manifest a transition's leaf ends at,
/// found at `version` under the new `epoch`: its signature verifies under a
/// key the evidence holds, it names `b`'s tenant, fleet, profile and
/// instance at `version` and an epoch before `epoch` (the leaf's own
/// exception, L2243), and its signer holds now an approval covering the
/// fleet and a device-scoped `profile.commit` covering the profile or its
/// fleet, and is not withdrawn.
#[allow(clippy::too_many_arguments)]
fn verify_leaf_head(
    db: &Db,
    dev: &Device,
    b: &Bound,
    chain: Option<&shardx_core::trust_chain::TrustChain>,
    keys: &std::collections::BTreeMap<[u8; 32], [u8; 32]>,
    m: SignedSnapshotManifestV2,
    (version, epoch): (u64, u64),
    now: u64,
) -> std::result::Result<(), Refused> {
    let invalid = |field| refusal("RESTORE_EPOCH_TRANSITION_INVALID", field);
    let signer = *m.signer_signing_key_id();
    let pk = keys
        .get(&signer)
        .ok_or_else(|| invalid("signer_signing_key_id"))?;
    let p = m
        .verify_signature(pk)
        .map_err(|_| invalid("signature_bytes"))?
        .payload()
        .clone();
    let checks = [
        ("tenant_id", p.tenant_id == b.tenant),
        ("fleet_id", p.fleet_id == b.fleet),
        ("profile_id", p.profile_id == b.profile),
        ("server_instance_id", p.server_instance_id == b.instance),
        ("target_version", p.target_version == version),
        ("restore_epoch", p.restore_epoch < epoch),
    ];
    if let Some((field, _)) = checks.iter().find(|(_, ok)| !ok) {
        return Err(invalid(field));
    }
    let Some(chain) = chain else {
        return Err(invalid("signer_signing_key_id"));
    };
    let commits = |scope| chain.capability_at(&signer, Capability::ProfileCommit, scope, now);
    if !chain.approval_valid_at(&signer, Scope::Fleet(b.fleet), now)
        || !(commits(Scope::Profile(b.profile)) || commits(Scope::Fleet(b.fleet)))
        || ledger::withdrawn(db, &dev.pin.0, &signer).unwrap_or(true)
    {
        return Err(invalid("signer_signing_key_id"));
    }
    Ok(())
}

/// `b`'s served proof under `t`, once it proves `b`'s own leaf against the
/// signed root and that leaf starts or ends at `head`, the head `b` holds.
fn verify_proof(
    t: &shardx_core::restore_epoch::VerifiedTransition,
    b: &Bound,
    head: Option<[u8; 32]>,
    body: Vec<u8>,
) -> std::result::Result<(RestoreEpochInclusionProofV2, Vec<u8>), Refused> {
    let invalid = |field| refusal("RESTORE_EPOCH_TRANSITION_INVALID", field);
    let proof = RestoreEpochInclusionProofV2::parse(&body)
        .map_err(|_| invalid("RestoreEpochInclusionProofV2"))?;
    verify_inclusion(t, &proof, &b.profile).map_err(|e| match e {
        InclusionError::CrossTenant => refusal("RESTORE_EPOCH_CROSS_TENANT", "tenant_id"),
        InclusionError::Mismatch(field) => invalid(field),
        InclusionError::Proof(_) => invalid("steps"),
    })?;
    let leaf = &proof.leaf;
    if head != Some(leaf.previous_signed_head_hash) && head != Some(leaf.new_signed_head_hash) {
        return Err(invalid("previous_signed_head_hash"));
    }
    Ok((proof, body))
}

/// Files `steps` exactly (L1967-L2029), or finds them filed with the same
/// bytes, then reads them back and moves `b` to `epoch` at `version` and
/// `head`, in one transaction. `false` when what is filed differs.
fn store_transitions(
    db: &mut Db,
    server_url: &str,
    b: &Bound,
    steps: &[Step],
    (epoch, version, head): (u64, u64, Option<[u8; 32]>),
    record: impl FnOnce(&rusqlite::Connection) -> Result<()>,
) -> Result<bool> {
    let tx = db.conn.transaction()?;
    let (instance, tenant, profile) = (hex(&b.instance), hex(&b.tenant), hex(&b.profile));
    let server = super::records::origin(&tx, server_url, &instance, wire(b.epoch)?)?;
    for s in steps {
        let (c, t) = (s.transition.container(), s.transition.payload());
        let (previous, new) = (wire(t.previous_epoch)?, wire(t.new_epoch)?);
        tx.execute(
            "INSERT OR IGNORE INTO restore_epoch_transitions(server_id, tenant_id,
               server_instance_id, transition_replay_id, previous_epoch, new_epoch, mapping_codec,
               mapping_count, profile_head_mapping_root, reason_code, approver_account_id,
               approver_device_id, approver_signing_key_id, issued_at_ms, nonce,
               canonical_transition_payload_bytes, transition_payload_sha256, signature_suite_id,
               signature_version, signature_bytes, signed_transition_container_hash,
               exact_signed_transition_bytes, exact_signed_transition_bytes_sha256, verified_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17,
               ?18, ?19, ?20, ?21, ?22, ?23, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
            params![
                server,
                tenant,
                instance,
                t.transition_replay_id.to_vec(),
                previous,
                new,
                shardx_core::restore_epoch::MAPPING_CODEC,
                wire(t.mapping_count)?,
                t.profile_head_mapping_root.to_vec(),
                t.reason_code.as_str(),
                hex(&t.approver_account_id),
                hex(&t.approver_device_id),
                hex(&t.approver_signing_key_id),
                wire(t.issued_at_ms)?,
                t.nonce.to_vec(),
                c.canonical_transition_payload_bytes(),
                c.transition_payload_sha256().to_vec(),
                shardx_core::signing::SIGNATURE_SUITE_ID_ED25519,
                shardx_core::signing::SIGNATURE_VERSION,
                c.signature_bytes(),
                c.signed_transition_container_hash().to_vec(),
                c.exact_signed_transition_bytes(),
                c.exact_signed_transition_bytes_sha256().to_vec(),
            ],
        )?;
        let leaf = &s.proof.leaf;
        tx.execute(
            "INSERT OR IGNORE INTO restore_epoch_binding_proofs(server_id, tenant_id,
               server_instance_id, previous_epoch, new_epoch, remote_profile_id,
               previous_signed_head_hash, new_signed_head_hash, leaf_index, leaf_count,
               canonical_leaf_bytes, leaf_hash, expected_root, canonical_inclusion_proof_bytes,
               proof_sha256, verified_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
               strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
            params![
                server,
                tenant,
                instance,
                previous,
                new,
                profile,
                leaf.previous_signed_head_hash.to_vec(),
                leaf.new_signed_head_hash.to_vec(),
                wire(s.proof.leaf_index)?,
                wire(s.proof.leaf_count)?,
                leaf.encode(),
                leaf.hash().to_vec(),
                s.proof.expected_root.to_vec(),
                s.proof_bytes,
                s.proof.proof_sha256().to_vec(),
            ],
        )?;
        // The readback: exactly the bytes verified above, under their key.
        let filed: Option<(Vec<u8>, Vec<u8>)> = tx
            .query_row(
                "SELECT t.exact_signed_transition_bytes, p.canonical_inclusion_proof_bytes
                 FROM restore_epoch_transitions t JOIN restore_epoch_binding_proofs p
                   USING (server_id, tenant_id, server_instance_id, previous_epoch, new_epoch)
                 WHERE server_id = ?1 AND tenant_id = ?2 AND server_instance_id = ?3
                   AND previous_epoch = ?4 AND new_epoch = ?5 AND p.remote_profile_id = ?6",
                params![server, tenant, instance, previous, new, profile],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if filed.as_ref().map(|(t, p)| (&t[..], &p[..]))
            != Some((c.exact_signed_transition_bytes(), &s.proof_bytes[..]))
        {
            return Ok(false);
        }
    }
    tx.execute(
        "UPDATE server_origins SET last_restore_epoch = ?2
         WHERE server_id = ?1 AND last_restore_epoch < ?2",
        params![server, wire(epoch)?],
    )?;
    let moved = tx.execute(
        "UPDATE profile_bindings SET accepted_restore_epoch = ?2, remote_version = ?3,
           last_observed_head_hash = ?4, last_error_code = NULL, sync_state = 'AVAILABLE'
         WHERE local_profile_id = ?1 AND accepted_restore_epoch = ?5
           AND sync_state = 'QUARANTINED' AND last_error_code IS ?6 AND remote_version = ?7
           AND last_observed_head_hash IS ?8 AND lease_id IS NULL",
        params![
            b.local,
            wire(epoch)?,
            wire(version)?,
            head.map(|h| h.to_vec()),
            wire(b.epoch)?,
            b.error,
            wire(b.version)?,
            b.head.map(|h| h.to_vec()),
        ],
    )?;
    if moved != 1 {
        bail!(code("sync.bindingChanged"));
    }
    record(&tx)?;
    tx.commit()?;
    Ok(true)
}

/// The FKEK of `generation` naming `fkek_key_id`, from a grant that
/// reverifies now (G2-35, Q-25, Q-26). A generation below the highest this
/// device verified is refused ("Fleet generation freshness"). Never a
/// passphrase.
fn verified_key(
    db: &Db,
    dev: &Device,
    fleet: &[u8; 16],
    generation: u64,
    fkek_key_id: &[u8; 32],
    now: u64,
) -> Result<Zeroizing<[u8; 32]>> {
    let none = || anyhow!(code("sync.noVerifiedFleetKey"));
    if ledger::highest_generation(db, &dev.pin.0, fleet)?.is_some_and(|h| generation < h) {
        return Err(none());
    }
    let store = crate::fleet_keys::load()?;
    store
        .keys_newest_first(&hex(fleet), |_, _| true)
        .into_iter()
        .find(|(k, g)| {
            *g == generation
                && shardx_core::fleet_grants::fkek_key_id(k) == *fkek_key_id
                && crate::fleet_key_verifies(db, &dev.pin, &dev.me, fleet, *g, k, now)
                    .unwrap_or(false)
        })
        .map(|(k, _)| Zeroizing::new(k))
        .ok_or_else(|| {
            if crate::fleet_key_needs_recollect(db, &dev.pin, fleet, generation) {
                anyhow!(code("sync.fleetKeyRecollect"))
            } else {
                none()
            }
        })
}

// ---------------------------------------------------------------- push ----

/// Pushes the published profile `local` from `udd`, resuming whatever
/// operation an earlier attempt left (plan L1137-L1215).
pub(crate) async fn push(
    client: &FleetClient,
    access: &str,
    dev: &Device,
    local: &str,
    udd: &Path,
    now: u64,
) -> Result<Pushed> {
    let mut db = Db::open()?;
    loop {
        let b = bound(&db, local)?;
        if awaits_transition(&b) {
            accept_transitions(client, access, dev, &mut db, &b, now).await?;
            continue;
        }
        refuse_quarantined(&b)?;
        // G2-34: a release whose reply was lost is replayed first.
        if let Some(op) = find(&db, local, "RELEASE", None, Some("PENDING"))? {
            release_reply(client, access, &mut db, &b, &op).await?;
            continue;
        }
        let Some(lease) = b.lease else {
            // A listing that shows a restore quarantines; the loop accepts it.
            if let Err(e) = checkout(client, access, &mut db, &b, now).await {
                if !awaits_transition(&bound(&db, local)?) {
                    return Err(e);
                }
            }
            continue;
        };
        let Some(commit_op) = find(&db, local, "COMMIT", Some(&lease), None)? else {
            match find(&db, local, "UPLOAD", Some(&lease), None)? {
                None => seal_snapshot(client, access, &mut db, dev, &b, lease, udd, now).await?,
                Some(op) if op.state == "PENDING" => {
                    create_upload(client, access, &mut db, &b, lease, &op).await?
                }
                Some(op) => prepare_commit(&mut db, dev, &b, &op)?,
            }
            continue;
        };
        if commit_op.state == "COMPLETED" {
            return finish(client, access, &mut db, &b, &commit_op).await;
        }
        let s = session(&db, &commit_op.op_id)?;
        match s.state.as_str() {
            "OPEN" => {
                if find(&db, local, "FINALIZE", Some(&lease), Some("PENDING"))?.is_none() {
                    transfer(client, access, &mut db, &b, lease, &commit_op, &s).await?;
                }
                finalize(client, access, &mut db, &b, lease, &commit_op).await?;
            }
            "READY" => commit(client, access, &mut db, &b, lease, &commit_op).await?,
            _ => return Err(bad("upload_sessions.state")),
        }
    }
}

/// `PROFILE_CHECKOUT` at the pinned head, or the replay of a stored one.
async fn checkout(
    client: &FleetClient,
    access: &str,
    db: &mut Db,
    b: &Bound,
    now: u64,
) -> Result<()> {
    let replay = find(db, &b.local, "CHECKOUT", None, Some("PENDING"))?;
    let replayed = replay.is_some();
    let op = match replay {
        Some(op) => {
            // A restore since it was stored quarantines here, first.
            listed(client, access, db, b).await?;
            op
        }
        None => {
            let head = listed(client, access, db, b).await?;
            if head.current_version > b.version {
                bail!(code("sync.remoteAhead"));
            }
            let payload = ProfileCheckoutV2 {
                profile: b.pref(),
                observed_version: b.version,
                observed_signed_head_hash: b.head,
                requested_lease_ttl_seconds: LEASE_TTL_SECONDS,
            }
            .encode();
            let kind = OperationKind::ProfileCheckout;
            let (key, exact, canonical) = mutation(kind, payload, b)?;
            let op_id = hex(&random::<16>()?);
            let scope = format!("{} /v2/profiles/{}/checkout", kind.scope(), hex(&b.profile));
            let none = Columns::default();
            insert_op(
                &db.conn, b, &op_id, "CHECKOUT", &scope, &key, &canonical, &exact, &none,
            )?;
            get_op(db, &op_id)?
        }
    };
    let exact = stored(db, b, &op)?;
    let reply = client.checkout_profile(access, &b.profile, exact).await?;
    let body = settle(db, &op, reply)??;
    let payload = stored_response(&op, RECORD_TYPE_CHECKED_OUT, &body)?;
    let g = ProfileLeaseV2::parse(LeaseOrigin::Checkout, &payload)
        .map_err(|_| bad("ProfileLeaseV2"))?;
    let checks = [
        ("profile", g.profile == b.pref()),
        ("server_instance_id", g.server_instance_id == b.instance),
        ("restore_epoch", g.restore_epoch == op.epoch),
    ];
    if let Some((field, _)) = checks.iter().find(|(_, ok)| !ok) {
        return Err(bad(field));
    }
    // A replayed checkout from before the binding moved on holds a lease on an
    // old head or epoch, and one replayed after its stored expiry a lease that
    // ended (probe 11, L2046): it is released as stored, and the next one
    // starts afresh under a new key.
    if (g.lease.base_version, g.current_signed_head_hash) != (b.version, b.head)
        || op.epoch != b.epoch
        || (replayed && g.expires_at_ms <= now)
    {
        let release = {
            let tx = db.conn.transaction()?;
            tx.execute(
                "UPDATE operations SET state = 'FAILED', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE op_id = ?1",
                [&op.op_id],
            )?;
            let release = release_op(&tx, b, g.lease)?;
            tx.commit()?;
            get_op(db, &release)?
        };
        return release_reply(client, access, db, b, &release).await;
    }
    let tx = db.conn.transaction()?;
    complete(&tx, &op, RECORD_TYPE_CHECKED_OUT, &body)?;
    tx.execute(
        "UPDATE operations SET lease_id = ?2, fencing_token = ?3, base_version = ?4 WHERE op_id = ?1",
        params![
            op.op_id,
            hex(&g.lease.lease_id),
            wire(g.lease.fencing_token)?,
            wire(g.lease.base_version)?
        ],
    )?;
    tx.execute(
        "UPDATE profile_bindings SET lease_id = ?2, fencing_token = ?3, sync_state = 'CHECKED_OUT'
         WHERE local_profile_id = ?1",
        params![
            b.local,
            hex(&g.lease.lease_id),
            wire(g.lease.fencing_token)?
        ],
    )?;
    tx.commit()?;
    Ok(())
}

/// The lease the completed checkout of `lease` granted.
fn granted(db: &Db, b: &Bound, lease: &LeaseRef) -> Result<ProfileLeaseV2> {
    let op = find(db, &b.local, "CHECKOUT", Some(lease), Some("COMPLETED"))?
        .ok_or_else(|| bad("lease_id"))?;
    let body: Vec<u8> = db.conn.query_row(
        "SELECT exact_response_bytes FROM operations WHERE op_id = ?1",
        [&op.op_id],
        |r| r.get(0),
    )?;
    let payload = stored_response(&op, RECORD_TYPE_CHECKED_OUT, &body)?;
    ProfileLeaseV2::parse(LeaseOrigin::Checkout, &payload).map_err(|_| bad("ProfileLeaseV2"))
}

/// Seals the profile under the verified ACTIVE FKEK the checkout named, keeps
/// the ciphertext in the spool and stores `CREATE_UPLOAD` before sending it.
/// Without a verified key, or under a generation Q-18 blocks, the lease is
/// released instead.
#[allow(clippy::too_many_arguments)]
async fn seal_snapshot(
    client: &FleetClient,
    access: &str,
    db: &mut Db,
    dev: &Device,
    b: &Bound,
    lease: LeaseRef,
    udd: &Path,
    now: u64,
) -> Result<()> {
    let g = granted(db, b, &lease)?;
    let generation = g.key_generation;
    let fkek = match verified_key(db, dev, &b.fleet, generation, &g.fkek_key_id, now) {
        Ok(k) => k,
        Err(e) => return Err(abandon(client, access, db, b, lease, e).await),
    };
    if ledger::commit_blocked(db, &dev.pin.0, &dev.pin.1, &b.fleet, generation)? {
        let e = anyhow!(code("sync.commitBlockedCompromised"));
        return Err(abandon(client, access, db, b, lease, e).await);
    }
    let owned = udd.to_path_buf();
    let plaintext = tokio::task::spawn_blocking(move || shardx_core::snapshot::pack(&owned))
        .await
        .map_err(|e| {
            anyhow!(code_with(
                "sync.sealTaskFailed",
                &[("error", &e.to_string())]
            ))
        })??;
    let (snapshot_id, manifest_replay_id) = (random::<16>()?, random::<16>()?);
    let dek = Zeroizing::new(random::<32>()?);
    let slot = build_dek_slot(
        &fkek,
        &dek,
        &random()?,
        &SlotIds {
            tenant_id: &b.tenant,
            fleet_id: &b.fleet,
            profile_id: &b.profile,
            snapshot_id: &snapshot_id,
            fkek_key_id: &g.fkek_key_id,
            envelope_context_nonce: &random()?,
        },
        generation,
    )
    .map_err(|e| anyhow!("{e}"))?;
    let intent = build_intent_v2(
        &IntentIds {
            snapshot_id,
            tenant_id: b.tenant,
            fleet_id: b.fleet,
            profile_id: b.profile,
            lease_id: lease.lease_id,
            manifest_replay_id,
            server_instance_id: b.instance,
            fkek_key_id: g.fkek_key_id,
            intended_signer_signing_key_id: dev.me.signing_key_id,
        },
        &IntentNumbers {
            target_version: b.version + 1,
            base_version: b.version,
            fencing_token: lease.fencing_token,
            key_generation: generation,
            restore_epoch: b.epoch,
            frame_plaintext_size: DEFAULT_FRAME_PLAINTEXT_SIZE,
            max_plaintext_size: MAX_OBJECT_SIZE,
            max_ciphertext_size: MAX_OBJECT_SIZE,
            created_at_ms: now,
        },
        &random()?,
        b.head.as_ref(),
        &slot,
    )
    .map_err(|e| anyhow!("{e}"))?;
    let mut object = Vec::new();
    let d = seal(&mut &plaintext[..], &mut object, &dek, &intent, &slot).map_err(|e| {
        anyhow!(code_with(
            "sync.sealTaskFailed",
            &[("error", &e.to_string())]
        ))
    })?;
    let terms = CreateUploadV2 {
        profile: b.pref(),
        snapshot_id,
        manifest_replay_id,
        lease,
        intent_hash: intent.intent_hash,
        preamble_sha256: d.preamble_sha256,
        dek_slot_sha256: slot.dek_slot_sha256,
        fkek_key_id: g.fkek_key_id,
        key_generation: generation,
        expected_ciphertext_size: d.ciphertext_size,
        expected_ciphertext_sha256: d.ciphertext_sha256,
    };
    let kind = OperationKind::CreateUpload;
    let (key, exact, canonical) = mutation(kind, terms.encode(), b)?;
    let op_id = hex(&random::<16>()?);
    let path = spool(&op_id)?;
    std::fs::create_dir_all(path.parent().context("spool")?)?;
    crate::durable::write_private(&path, &object)?;
    let scope = format!("{} /v2/profiles/{}/uploads", kind.scope(), hex(&b.profile));
    let columns = Columns {
        lease: Some(lease),
        snapshot: Some((snapshot_id, manifest_replay_id)),
        intent: Some(intent.intent_hash),
        cipher: Some(d.ciphertext_sha256),
        ..Default::default()
    };
    {
        let tx = db.conn.transaction()?;
        insert_op(
            &tx, b, &op_id, "UPLOAD", &scope, &key, &canonical, &exact, &columns,
        )?;
        tx.execute(
            "UPDATE profile_bindings SET sync_state = 'UPLOADING' WHERE local_profile_id = ?1",
            [&b.local],
        )?;
        tx.commit()?;
    }
    let op = get_op(db, &op_id)?;
    create_upload(client, access, db, b, lease, &op).await
}

/// Sends the stored `CREATE_UPLOAD` and keeps the upload it names.
async fn create_upload(
    client: &FleetClient,
    access: &str,
    db: &mut Db,
    b: &Bound,
    lease: LeaseRef,
    op: &Op,
) -> Result<()> {
    let exact = stored(db, b, op)?;
    let reply = client.create_upload(access, &b.profile, exact).await?;
    let gone = refusal_of(&reply).0.as_deref() == Some("RESOURCE_NOT_FOUND");
    let body = match settle(db, op, reply)? {
        Ok(body) => body,
        Err(e) => {
            let e = if gone { superseded_upload() } else { e };
            return Err(abandon(client, access, db, b, lease, e).await);
        }
    };
    let terms = IdempotentMutationRequestV2::parse(exact)
        .ok()
        .and_then(|r| CreateUploadV2::parse(&r.canonical_payload_bytes).ok())
        .ok_or_else(|| bad("CreateUploadV2"))?;
    let payload = stored_response(op, RECORD_TYPE_UPLOAD_CREATED, &body)?;
    let created = UploadCreatedV2::parse(&payload).map_err(|_| bad("UploadCreatedV2"))?;
    if created.terms != terms
        || (created.server_instance_id, created.restore_epoch) != (b.instance, b.epoch)
    {
        return Err(bad("terms"));
    }
    let tx = db.conn.transaction()?;
    complete(&tx, op, RECORD_TYPE_UPLOAD_CREATED, &body)?;
    tx.execute(
        "UPDATE operations SET remote_upload_id = ?2 WHERE op_id = ?1",
        params![op.op_id, hex(&created.upload_id)],
    )?;
    tx.commit()?;
    Ok(())
}

/// Signs the manifest of the uploaded snapshot and stores the COMMIT
/// operation with its exact manifest and request, and the upload session,
/// in one transaction: everything finalize needs is durable before it is
/// sent (L1150, L1421).
fn prepare_commit(db: &mut Db, dev: &Device, b: &Bound, up: &Op) -> Result<()> {
    let terms = IdempotentMutationRequestV2::parse(stored(db, b, up)?)
        .ok()
        .and_then(|r| CreateUploadV2::parse(&r.canonical_payload_bytes).ok())
        .ok_or_else(|| bad("CreateUploadV2"))?;
    let upload_id = decode_hex16(up.upload.as_deref().unwrap_or_default(), "upload_id")?;
    let object = std::fs::read(spool(&up.op_id)?)?;
    let view = check_public(
        &mut std::io::Cursor::new(&object),
        &Expected {
            ciphertext_sha256: &terms.expected_ciphertext_sha256,
            ciphertext_size: terms.expected_ciphertext_size,
            preamble_sha256: &terms.preamble_sha256,
            intent_hash: &terms.intent_hash,
            dek_slot_sha256: &terms.dek_slot_sha256,
            scope: &Sealed {
                snapshot_id: terms.snapshot_id,
                tenant_id: b.tenant,
                fleet_id: b.fleet,
                profile_id: b.profile,
                target_version: terms.lease.base_version + 1,
                key_generation: terms.key_generation,
            },
        },
    )
    .map_err(|_| bad("spool"))?;
    let manifest = SnapshotManifestV2 {
        snapshot_id: terms.snapshot_id,
        tenant_id: b.tenant,
        fleet_id: b.fleet,
        profile_id: b.profile,
        lease_id: terms.lease.lease_id,
        target_version: view.target_version,
        base_version: terms.lease.base_version,
        fencing_token: terms.lease.fencing_token,
        key_generation: terms.key_generation,
        fkek_key_id: terms.fkek_key_id,
        preamble_sha256: terms.preamble_sha256,
        intent_hash: terms.intent_hash,
        dek_slot_sha256: terms.dek_slot_sha256,
        ciphertext_sha256: terms.expected_ciphertext_sha256,
        ciphertext_size: terms.expected_ciphertext_size,
        previous_signed_head_hash: view.previous_signed_head_hash,
        signer_signing_key_id: dev.me.signing_key_id,
        server_instance_id: view.server_instance_id,
        restore_epoch: view.restore_epoch,
        manifest_replay_id: terms.manifest_replay_id,
        created_at_ms: view.created_at_ms,
    };
    let signed =
        SignedSnapshotManifestV2::sign(&dev.signer, &manifest).map_err(|e| anyhow!("{e}"))?;
    let request = CommitRequestV2::build(&signed, upload_id, random()?, random()?);
    let op_id = hex(&random::<16>()?);
    let scope = format!(
        "{} /v2/uploads/{}/commit",
        shardx_core::snapshot_v2::OPERATION_SCOPE_COMMIT,
        hex(&upload_id)
    );
    let columns = Columns {
        upload: Some(upload_id),
        lease: Some(terms.lease),
        snapshot: Some((terms.snapshot_id, terms.manifest_replay_id)),
        intent: Some(terms.intent_hash),
        cipher: Some(terms.expected_ciphertext_sha256),
        manifest: Some(&signed),
    };
    let tx = db.conn.transaction()?;
    insert_op(
        &tx,
        b,
        &op_id,
        "COMMIT",
        &scope,
        request.idempotency_key(),
        request.canonical_request_hash(),
        request.exact_bytes(),
        &columns,
    )?;
    tx.execute(
        "INSERT INTO upload_sessions(upload_local_id, local_profile_id,
           local_profile_id_at_request, commit_op_id, server_instance_id, restore_epoch,
           tenant_id, fleet_id, remote_profile_id, remote_upload_id, snapshot_id,
           manifest_replay_id, intent_hash, preamble_sha256, dek_slot_sha256, fkek_key_id,
           key_generation, expected_ciphertext_sha256, expected_ciphertext_size, spool_ref,
           state, created_at, updated_at)
         VALUES (?1, ?2, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17,
           ?18, ?19, 'OPEN', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
           strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
        params![
            hex(&random::<16>()?),
            b.local,
            op_id,
            hex(&b.instance),
            wire(b.epoch)?,
            hex(&b.tenant),
            hex(&b.fleet),
            hex(&b.profile),
            hex(&upload_id),
            terms.snapshot_id.to_vec(),
            terms.manifest_replay_id.to_vec(),
            terms.intent_hash.to_vec(),
            terms.preamble_sha256.to_vec(),
            terms.dek_slot_sha256.to_vec(),
            hex(&terms.fkek_key_id),
            wire(terms.key_generation)?,
            terms.expected_ciphertext_sha256.to_vec(),
            wire(terms.expected_ciphertext_size)?,
            up.op_id,
        ],
    )?;
    tx.commit()?;
    Ok(())
}

/// The upload's committed offset and state, as `HEAD` reports them.
fn offset_of(reply: &Exact) -> Option<(u64, &str)> {
    let h = &reply.headers;
    let offset = h.get("upload-offset")?.to_str().ok()?.parse().ok()?;
    Some((offset, h.get("upload-state")?.to_str().ok()?))
}

/// Gives up the upload of `commit_op` after the server refused it, and the
/// lease with it.
async fn fail_upload(
    client: &FleetClient,
    access: &str,
    db: &mut Db,
    b: &Bound,
    lease: LeaseRef,
    commit_op: &Op,
    err: anyhow::Error,
) -> anyhow::Error {
    let _ = db.conn.execute(
        "UPDATE upload_sessions SET state = 'ABORTED' WHERE commit_op_id = ?1",
        [&commit_op.op_id],
    );
    abandon(client, access, db, b, lease, err).await
}

/// G2-36: sends the spooled ciphertext from the offset `HEAD` reports, never
/// a guessed one; an offset conflict asks `HEAD` again.
async fn transfer(
    client: &FleetClient,
    access: &str,
    db: &mut Db,
    b: &Bound,
    lease: LeaseRef,
    commit_op: &Op,
    s: &Session,
) -> Result<()> {
    stored(db, b, commit_op)?;
    let object = std::fs::read(spool(&s.spool)?)?;
    let upload = decode_hex16(&s.upload, "upload_id")?;
    let mut renewed = std::time::Instant::now();
    for _ in 0..3 {
        let reply = client.upload_head(access, &upload).await?;
        if terminal(reply.status) {
            let e = refused(&reply);
            return Err(fail_upload(client, access, db, b, lease, commit_op, e).await);
        }
        let reply = ok(reply)?;
        let (mut at, state) = offset_of(&reply).ok_or_else(|| bad("upload-offset"))?;
        if state != "OPEN" || at > s.size {
            return Err(bad("upload-state"));
        }
        loop {
            db.conn.execute(
                "UPDATE upload_sessions SET committed_offset = ?2,
                   updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE upload_local_id = ?1",
                params![s.upload_local_id, wire(at)?],
            )?;
            if at == s.size {
                return Ok(());
            }
            if renewed.elapsed().as_secs() > u64::from(LEASE_TTL_SECONDS / 3) {
                renew(client, access, b, lease).await?;
                renewed = std::time::Instant::now();
            }
            let end = (at + CHUNK as u64).min(s.size);
            let chunk = &object[at as usize..end as usize];
            let reply = client.upload_patch(access, &upload, at, chunk).await?;
            if reply.status == 409 {
                break;
            }
            let reply = ok(reply)?;
            let got = reply
                .headers
                .get("upload-offset")
                .and_then(|h| h.to_str().ok()?.parse::<u64>().ok());
            if got != Some(end) {
                return Err(bad("upload-offset"));
            }
            at = end;
        }
    }
    Err(bad("upload-offset"))
}

/// `LeaseRenewV2` for the lease this push holds (L1139).
async fn renew(client: &FleetClient, access: &str, b: &Bound, lease: LeaseRef) -> Result<()> {
    let body = LeaseRenewV2 {
        profile: b.pref(),
        lease,
        requested_lease_ttl_seconds: LEASE_TTL_SECONDS,
    }
    .encode();
    let reply = ok(client
        .renew_lease_v2(access, &b.profile, &lease.lease_id, &body)
        .await?)?;
    let r = LeaseRenewedV2::parse(&reply.body).map_err(|_| bad("LeaseRenewedV2"))?;
    if (r.profile, r.lease) != (b.pref(), lease) {
        return Err(bad("lease_id"));
    }
    Ok(())
}

/// `FINALIZE_UPLOAD` around the stored commit request, stored before it is
/// sent; READY is kept with its exact response.
async fn finalize(
    client: &FleetClient,
    access: &str,
    db: &mut Db,
    b: &Bound,
    lease: LeaseRef,
    commit_op: &Op,
) -> Result<()> {
    let request =
        CommitRequestV2::parse(stored(db, b, commit_op)?).map_err(|_| bad("CommitRequestV2"))?;
    let upload = *request.upload_id();
    let op = match find(db, &b.local, "FINALIZE", Some(&lease), Some("PENDING"))? {
        Some(op) => op,
        None => {
            let kind = OperationKind::FinalizeUpload;
            let payload = FinalizeUploadV2::new(request.clone()).encode();
            let (key, exact, canonical) = mutation(kind, payload, b)?;
            let op_id = hex(&random::<16>()?);
            let scope = format!("{} /v2/uploads/{}/finalize", kind.scope(), hex(&upload));
            let columns = Columns {
                upload: Some(upload),
                lease: Some(lease),
                ..Default::default()
            };
            insert_op(
                &db.conn, b, &op_id, "FINALIZE", &scope, &key, &canonical, &exact, &columns,
            )?;
            get_op(db, &op_id)?
        }
    };
    let exact = stored(db, b, &op)?;
    let reply = client.finalize_upload(access, &upload, exact).await?;
    let gone = refusal_of(&reply).0.as_deref() == Some("RESOURCE_NOT_FOUND");
    let body = match settle(db, &op, reply)? {
        Ok(body) => body,
        Err(e) => {
            let e = if gone { superseded_upload() } else { e };
            return Err(fail_upload(client, access, db, b, lease, commit_op, e).await);
        }
    };
    let payload = stored_response(&op, RECORD_TYPE_UPLOAD_FINALIZED, &body)?;
    let r = UploadFinalizedV2::parse(&payload).map_err(|_| bad("UploadFinalizedV2"))?;
    let p = SnapshotManifestV2::parse(request.manifest().canonical_manifest_payload_bytes())
        .map_err(|_| bad("manifest"))?;
    if (r.upload_id, r.snapshot_id, r.manifest_replay_id)
        != (upload, p.snapshot_id, p.manifest_replay_id)
        || (r.ciphertext_size, r.ciphertext_sha256) != (p.ciphertext_size, p.ciphertext_sha256)
        || (r.server_instance_id, r.restore_epoch) != (b.instance, b.epoch)
    {
        return Err(bad("UploadFinalizedV2"));
    }
    let tx = db.conn.transaction()?;
    complete(&tx, &op, RECORD_TYPE_UPLOAD_FINALIZED, &body)?;
    tx.execute(
        "UPDATE upload_sessions SET state = 'READY', exact_finalize_response_bytes = ?2,
           finalize_response_sha256 = ?3, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
         WHERE commit_op_id = ?1 AND state = 'OPEN'",
        params![commit_op.op_id, body, sha256(&body).to_vec()],
    )?;
    tx.commit()?;
    Ok(())
}

/// Sends the stored `CommitRequestV2` byte for byte and keeps the exact
/// receipt once it binds that request (G2-38).
async fn commit(
    client: &FleetClient,
    access: &str,
    db: &mut Db,
    b: &Bound,
    lease: LeaseRef,
    op: &Op,
) -> Result<()> {
    let exact = stored(db, b, op)?;
    let request = CommitRequestV2::parse(exact).map_err(|_| bad("CommitRequestV2"))?;
    let reply = client
        .commit_upload(access, request.upload_id(), exact)
        .await?;
    let superseded = match refusal_of(&reply) {
        (Some(c), Some(epoch)) if c == "BASE_VERSION_MISMATCH" => Some(epoch),
        _ => None,
    };
    let body = match settle(db, op, reply)? {
        Ok(body) => body,
        Err(e) => {
            let Some(epoch) = superseded else {
                return Err(fail_upload(client, access, db, b, lease, op, e).await);
            };
            let e = anyhow!(code("sync.commitSuperseded"));
            let e = fail_upload(client, access, db, b, lease, op, e).await;
            // The epoch it names goes straight to its transition (D-1).
            if epoch > b.epoch {
                return Err(quarantine(db, &b.local, TRANSITION_REQUIRED, e));
            }
            return Err(e);
        }
    };
    let receipt = CommitReceiptBindingV2::parse(&body).map_err(|_| bad(COMMIT_RECORD))?;
    receipt
        .check_binds(&request)
        .map_err(|_| bad(COMMIT_RECORD))?;
    let tx = db.conn.transaction()?;
    complete(&tx, op, COMMIT_RECORD, &body)?;
    tx.execute(
        "UPDATE upload_sessions SET state = 'COMMITTED', exact_commit_receipt_binding_bytes = ?2,
           commit_receipt_binding_bytes_sha256 = ?3,
           updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
         WHERE commit_op_id = ?1 AND state = 'READY'",
        params![op.op_id, body, sha256(&body).to_vec()],
    )?;
    tx.commit()?;
    Ok(())
}

/// Reads the committed snapshot back (G2-38): the exact manifest, the
/// object's hash, and the listed head the receipt names. Then the binding
/// pins that head and drops the lease the commit released.
async fn finish(
    client: &FleetClient,
    access: &str,
    db: &mut Db,
    b: &Bound,
    op: &Op,
) -> Result<Pushed> {
    let request = CommitRequestV2::parse(&op.exact).map_err(|_| bad("CommitRequestV2"))?;
    let receipt = op
        .receipt
        .as_deref()
        .and_then(|r| CommitReceiptBindingV2::parse(r).ok())
        .ok_or_else(|| bad(COMMIT_RECORD))?;
    receipt
        .check_binds(&request)
        .map_err(|_| bad(COMMIT_RECORD))?;
    let version = receipt.resulting_version;
    let p = SnapshotManifestV2::parse(request.manifest().canonical_manifest_payload_bytes())
        .map_err(|_| bad("manifest"))?;
    let mismatch = |field: &str| anyhow!(code_with("sync.readbackMismatch", &[("field", field)]));
    let manifest = ok(client
        .snapshot_manifest(access, &b.profile, version)
        .await?)?;
    if manifest.body != request.manifest().exact_bytes() {
        return Err(mismatch("manifest"));
    }
    let object = ok(client
        .snapshot_range(access, &b.profile, version, 0, 0)
        .await?)?;
    let etag = format!("\"{}\"", hex(&p.ciphertext_sha256));
    if object.headers.get("etag").and_then(|h| h.to_str().ok()) != Some(etag.as_str()) {
        return Err(mismatch("etag"));
    }
    // The readback above is of `version` itself, so a head another device
    // committed on top since then does not undo it.
    let head = listed(client, access, db, b).await?;
    if head.current_version < version
        || (head.current_version == version
            && head.current_signed_head_hash != Some(receipt.resulting_head_hash))
    {
        return Err(mismatch("head"));
    }
    let s = session(db, &op.op_id)?;
    db.conn.execute(
        "UPDATE profile_bindings SET remote_version = ?2, last_observed_head_hash = ?3,
           lease_id = NULL, fencing_token = NULL, sync_state = 'AVAILABLE', last_error_code = NULL
         WHERE local_profile_id = ?1",
        params![
            b.local,
            wire(version)?,
            receipt.resulting_head_hash.to_vec()
        ],
    )?;
    let _ = std::fs::remove_file(spool(&s.spool)?);
    Ok(Pushed {
        version,
        ciphertext_size: p.ciphertext_size,
        ciphertext_sha256: p.ciphertext_sha256,
    })
}

/// Releases `lease` after a refusal and returns `err`. A release whose reply
/// is lost stays PENDING, and the next push replays it first (G2-34).
async fn abandon(
    client: &FleetClient,
    access: &str,
    db: &mut Db,
    b: &Bound,
    lease: LeaseRef,
    err: anyhow::Error,
) -> anyhow::Error {
    let released = async {
        let op_id = release_op(&db.conn, b, lease)?;
        let op = get_op(db, &op_id)?;
        release_reply(client, access, db, b, &op).await
    };
    if let Err(e) = released.await {
        eprintln!("[sync] release: {e:#}");
    }
    err
}

/// Stores a `RELEASE_LEASE` of `lease` and returns its operation ID.
fn release_op(conn: &rusqlite::Connection, b: &Bound, lease: LeaseRef) -> Result<String> {
    let kind = OperationKind::ReleaseLease;
    let payload = ReleaseLeaseV2 {
        profile: b.pref(),
        lease,
        reason_code: ReleaseReason::UserRelease,
    }
    .encode();
    let (key, exact, canonical) = mutation(kind, payload, b)?;
    let op_id = hex(&random::<16>()?);
    let scope = format!(
        "{} /v2/profiles/{}/leases/{}/release",
        kind.scope(),
        hex(&b.profile),
        hex(&lease.lease_id)
    );
    let columns = Columns {
        lease: Some(lease),
        ..Default::default()
    };
    insert_op(
        conn, b, &op_id, "RELEASE", &scope, &key, &canonical, &exact, &columns,
    )?;
    Ok(op_id)
}

/// Sends the stored `RELEASE_LEASE`. Released, or refused because the lease
/// is no longer this device's, the binding drops it and every operation still
/// pending under it. A 2xx that does not parse is a protocol error: it is
/// reported, and the release stays PENDING to be replayed as stored.
async fn release_reply(
    client: &FleetClient,
    access: &str,
    db: &mut Db,
    b: &Bound,
    op: &Op,
) -> Result<()> {
    let lease_id = decode_hex16(op.lease_id.as_deref().unwrap_or_default(), "lease_id")?;
    let exact = stored(db, b, op)?;
    let reply = client
        .release_lease_v2(access, &b.profile, &lease_id, exact)
        .await?;
    let released = match settle(db, op, reply)? {
        Ok(body) => {
            let payload = stored_response(op, RECORD_TYPE_LEASE_RELEASED, &body)?;
            let r = LeaseReleasedV2::parse(&payload).map_err(|_| bad("LeaseReleasedV2"))?;
            if r.profile != b.pref() || r.lease.lease_id != lease_id {
                return Err(bad("lease_id"));
            }
            Some(body)
        }
        Err(e) => {
            eprintln!("[sync] release refused: {e:#}");
            None
        }
    };
    let tx = db.conn.transaction()?;
    if let Some(body) = released {
        complete(&tx, op, RECORD_TYPE_LEASE_RELEASED, &body)?;
    }
    let lease = hex(&lease_id);
    tx.execute(
        "UPDATE operations SET state = 'FAILED' WHERE local_profile_id = ?1 AND lease_id = ?2
           AND state = 'PENDING'",
        params![b.local, lease],
    )?;
    tx.execute(
        "UPDATE upload_sessions SET state = 'ABORTED' WHERE local_profile_id = ?1
           AND state IN ('OPEN', 'READY')
           AND commit_op_id IN (SELECT op_id FROM operations WHERE lease_id = ?2)",
        params![b.local, lease],
    )?;
    tx.execute(
        "UPDATE profile_bindings SET lease_id = NULL, fencing_token = NULL, sync_state = 'AVAILABLE'
         WHERE local_profile_id = ?1 AND lease_id = ?2",
        params![b.local, lease],
    )?;
    tx.commit()?;
    Ok(())
}

// -------------------------------------------------------------- unbind ----

/// `LOCAL_UNBIND` of `local` at `now` (L953, L1143, L2239; ADR 0002 D-7),
/// in the Launcher DB alone: no server is called (L934-L936). One
/// transaction reads back that the binding holds no lease and has no pending
/// operation, stores the completed `UNBIND` with its exact stored response
/// and its tombstone receipt, and deletes the binding; its operations keep
/// their bytes with `local_profile_id` set NULL (probe 1, L2036). Once the
/// binding is gone, a retry returns the stored response again, after its
/// tombstone recomputes from the stored request and response (L969-L970).
/// `server_url` names the `server_id` the tombstone carries.
pub(crate) fn unbind(local: &str, server_url: &str, now: u64) -> Result<Vec<u8>> {
    let db = Db::open()?;
    let tx =
        rusqlite::Transaction::new_unchecked(&db.conn, rusqlite::TransactionBehavior::Immediate)?;
    let is_bound: bool = tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM profile_bindings WHERE local_profile_id = ?1)",
        [local],
        |r| r.get(0),
    )?;
    if !is_bound {
        return unbound_reply(&db, local);
    }
    let b = bound(&db, local)?;
    if b.lease.is_some() {
        bail!(code("sync.unbindLeaseHeld"));
    }
    let pending: bool = tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM operations WHERE local_profile_id = ?1
           AND state IN ('PENDING', 'RUNNING', 'AWAITING_RETRY'))",
        [local],
        |r| r.get(0),
    )?;
    if pending {
        bail!(code("sync.unbindPending"));
    }
    let binding = UnboundBinding {
        server_id: super::records::origin(&tx, server_url, &hex(&b.instance), wire(b.epoch)?)?,
        server_instance_id: b.instance,
        restore_epoch: b.epoch,
        tenant_id: b.tenant,
        fleet_id: b.fleet,
        remote_profile_id: b.profile,
        local_profile_id: b.local.clone(),
        remote_version: b.version,
        expected_signed_head_hash: b.head,
    };
    let kind = OperationKind::LocalUnbind;
    let payload = LocalUnbindV2 {
        binding: binding.clone(),
    }
    .encode();
    let (key, exact, canonical) = mutation(kind, payload, &b)?;
    let op_id = hex(&random::<16>()?);
    insert_op(
        &tx,
        &b,
        &op_id,
        "UNBIND",
        kind.scope(),
        &key,
        &canonical,
        &exact,
        &Columns::default(),
    )?;
    let tombstone = LocalBindingTombstoneV2 {
        binding,
        unbind_idempotency_key: key,
        completed_at_ms: now,
    };
    let response = IdempotentStoredResponseV2 {
        operation_kind: kind,
        idempotency_key: key,
        exact_request_hash: canonical,
        response_record_type: RECORD_TYPE_LOCAL_UNBOUND.into(),
        canonical_response_payload_bytes: tombstone.response().encode(),
        server_instance_id: b.instance,
        restore_epoch: b.epoch,
        committed_at_ms: now,
        receipt_id: random()?,
    }
    .encode();
    let receipt = tombstone.encode();
    tx.execute(
        "UPDATE operations SET state = 'COMPLETED', response_record_type = ?2,
           exact_response_bytes = ?3, exact_response_bytes_sha256 = ?4,
           exact_receipt_bytes = ?5, receipt_sha256 = ?6,
           updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
         WHERE op_id = ?1 AND state = 'PENDING'",
        params![
            op_id,
            RECORD_TYPE_LOCAL_UNBOUND,
            response,
            sha256(&response).to_vec(),
            receipt,
            sha256(&receipt).to_vec()
        ],
    )?;
    tx.execute(
        "DELETE FROM profile_bindings WHERE local_profile_id = ?1",
        [local],
    )?;
    // The readback: what a retry would return, from the stored bytes alone.
    let reply = unbound_reply(&db, local)?;
    tx.commit()?;
    Ok(reply)
}

/// The exact stored response of the newest completed unbind of `local`, once
/// its columns match its request and its tombstone recomputes from the
/// stored request and response (ADR 0002 D-7); otherwise nothing is trusted.
fn unbound_reply(db: &Db, local: &str) -> Result<Vec<u8>> {
    let (op, response, response_sha, receipt_sha) = db
        .conn
        .query_row(
            &format!(
                "SELECT {OP_COLUMNS}, exact_response_bytes, exact_response_bytes_sha256,
                   receipt_sha256
                 FROM operations WHERE kind = 'UNBIND' AND state = 'COMPLETED'
                   AND local_profile_id IS NULL AND local_profile_id_at_request = ?1
                 ORDER BY rowid DESC LIMIT 1"
            ),
            [local],
            |r| {
                Ok((
                    op_row(r)?,
                    r.get::<_, Vec<u8>>(22)?,
                    r.get::<_, Vec<u8>>(23)?,
                    r.get::<_, Vec<u8>>(24)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| anyhow!(code("sync.unbindNotBound")))?;
    let mismatch = |field: &str| {
        anyhow!(code_with(
            "sync.unbindTombstoneMismatch",
            &[("field", field)]
        ))
    };
    if let Some(field) = first_drift(db, &op)? {
        return Err(mismatch(field));
    }
    let req = IdempotentMutationRequestV2::parse(&op.exact)
        .map_err(|_| mismatch("exact_request_bytes"))?;
    let asked = LocalUnbindV2::parse(&req.canonical_payload_bytes)
        .map_err(|_| mismatch("canonical_payload_bytes"))?;
    let payload = stored_response(&op, RECORD_TYPE_LOCAL_UNBOUND, &response)
        .map_err(|_| mismatch("exact_response_bytes"))?;
    let done = LocalUnboundV2::parse(&payload).map_err(|_| mismatch("LocalUnboundV2"))?;
    let tombstone = LocalBindingTombstoneV2 {
        binding: asked.binding,
        unbind_idempotency_key: req.idempotency_key,
        completed_at_ms: done.completed_at_ms,
    };
    let receipt = tombstone.encode();
    let checks = [
        (
            "exact_response_bytes_sha256",
            response_sha == sha256(&response),
        ),
        (
            "local_profile_id",
            tombstone.binding.local_profile_id == local,
        ),
        ("binding_tombstone_sha256", tombstone.response() == done),
        (
            "exact_receipt_bytes",
            op.receipt.as_deref() == Some(&receipt[..]),
        ),
        ("receipt_sha256", receipt_sha == sha256(&receipt)),
    ];
    if let Some((field, _)) = checks.iter().find(|(_, ok)| !ok) {
        return Err(mismatch(field));
    }
    Ok(response)
}

// ---------------------------------------------------------------- pull ----

/// Pulls the listed head of the published profile `local` into `udd`: every
/// manifest since the pinned head verified (rule 6), the ciphertext fetched
/// by `Range`, opened under a key that reverifies now, and the head pinned.
pub(crate) async fn pull(
    client: &FleetClient,
    access: &str,
    dev: &Device,
    local: &str,
    udd: &Path,
    now: u64,
) -> Result<u64> {
    let mut db = Db::open()?;
    let mut b = bound(&db, local)?;
    if awaits_transition(&b) {
        accept_transitions(client, access, dev, &mut db, &b, now).await?;
        b = bound(&db, local)?;
    }
    refuse_quarantined(&b)?;
    // A push in flight would seal what this pull wrote over the user's data.
    let pending: bool = db.conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM operations WHERE local_profile_id = ?1 AND state = 'PENDING')",
        [local],
        |r| r.get(0),
    )?;
    if b.lease.is_some() || pending {
        bail!(code("sync.pushPending"));
    }
    let head = match listed(client, access, &mut db, &b).await {
        // A listing that shows a restore quarantines; it is accepted at once.
        Err(_) if awaits_transition(&bound(&db, local)?) => {
            b = bound(&db, local)?;
            accept_transitions(client, access, dev, &mut db, &b, now).await?;
            b = bound(&db, local)?;
            listed(client, access, &mut db, &b).await?
        }
        head => head?,
    };
    if head.current_version == 0 {
        bail!(code("profile.theTeamServerHasNoSnapshotForThisProfi"));
    }
    let untrusted = || anyhow!(code("sync.signerUntrusted"));
    let pages = client.trust_evidence(access, &hex(&b.tenant)).await?;
    let (_, chain) =
        ledger::evaluate(&db, &dev.pin.0, &dev.pin.1, &pages, now)?.ok_or_else(untrusted)?;
    let keys: std::collections::BTreeMap<[u8; 32], [u8; 32]> = pages
        .iter()
        .flat_map(|p| &p.signing_public_keys)
        .map(|pk| (shardx_core::keys::signing_key_id(pk), *pk))
        .collect();
    let mut prev = b.head;
    let mut last = None;
    for v in b.version.max(1)..=head.current_version {
        let reply = ok(client.snapshot_manifest(access, &b.profile, v).await?)?;
        let m = SignedSnapshotManifestV2::parse(&reply.body)
            .map_err(|_| bad("SignedSnapshotManifestV2"))?;
        if v == b.version {
            // The pinned head: its bytes were verified when they were
            // pinned (rule 6, "Pinning"), so neither its signer nor its epoch
            // is re-checked; it must still be this binding's at `v`.
            if Some(m.head_hash()) != b.head {
                return Err(bad("current_signed_head_hash"));
            }
            let p = SnapshotManifestV2::parse(m.canonical_manifest_payload_bytes())
                .map_err(|_| bad("manifest"))?;
            let checks = [
                ("tenant_id", p.tenant_id == b.tenant),
                ("fleet_id", p.fleet_id == b.fleet),
                ("profile_id", p.profile_id == b.profile),
                ("server_instance_id", p.server_instance_id == b.instance),
                ("target_version", p.target_version == v),
            ];
            if let Some((field, _)) = checks.iter().find(|(_, ok)| !ok) {
                return Err(bad(field));
            }
            last = Some(p);
            continue;
        }
        let signer = *m.signer_signing_key_id();
        let pk = keys.get(&signer).ok_or_else(untrusted)?;
        let p = m
            .clone()
            .verify_signature(pk)
            .map_err(|_| untrusted())?
            .payload()
            .clone();
        let checks = [
            ("tenant_id", p.tenant_id == b.tenant),
            ("fleet_id", p.fleet_id == b.fleet),
            ("profile_id", p.profile_id == b.profile),
            ("server_instance_id", p.server_instance_id == b.instance),
            (
                "target_version",
                p.target_version == v && p.base_version + 1 == v,
            ),
            (
                "previous_signed_head_hash",
                p.previous_signed_head_hash == prev,
            ),
        ];
        if let Some((field, _)) = checks.iter().find(|(_, ok)| !ok) {
            return Err(bad(field));
        }
        if p.restore_epoch != b.epoch {
            let (reason, key) = if p.restore_epoch < b.epoch {
                ("HEAD_ROLLBACK_DETECTED", "sync.headRollback")
            } else {
                (
                    "RESTORE_EPOCH_TRANSITION_REQUIRED",
                    "sync.epochTransitionRequired",
                )
            };
            return Err(quarantine(&db, &b.local, reason, anyhow!(code(key))));
        }
        let commits = |scope| chain.capability_at(&signer, Capability::ProfileCommit, scope, now);
        if !chain.approval_valid_at(&signer, Scope::Fleet(b.fleet), now)
            || !(commits(Scope::Profile(b.profile)) || commits(Scope::Fleet(b.fleet)))
            || ledger::withdrawn(&db, &dev.pin.0, &signer)?
        {
            return Err(untrusted());
        }
        prev = Some(m.head_hash());
        last = Some(p);
    }
    if prev != head.current_signed_head_hash {
        return Err(bad("current_signed_head_hash"));
    }
    let p = last.ok_or_else(|| bad("manifest"))?;
    let mut object = Vec::with_capacity(p.ciphertext_size as usize);
    let etag = format!("\"{}\"", hex(&p.ciphertext_sha256));
    while (object.len() as u64) < p.ciphertext_size {
        let start = object.len() as u64;
        let end = (start + CHUNK as u64).min(p.ciphertext_size) - 1;
        let reply = ok(client
            .snapshot_range(access, &b.profile, head.current_version, start, end)
            .await?)?;
        if reply.headers.get("etag").and_then(|h| h.to_str().ok()) != Some(etag.as_str())
            || reply.body.len() as u64 != end - start + 1
        {
            return Err(bad("range"));
        }
        object.extend_from_slice(&reply.body);
    }
    let fkek = verified_key(&db, dev, &b.fleet, p.key_generation, &p.fkek_key_id, now)?;
    let target = udd.to_path_buf();
    let restored = tokio::task::spawn_blocking(move || -> Result<u64> {
        let mut plaintext = Zeroizing::new(Vec::new());
        open(
            &mut std::io::Cursor::new(&object),
            &mut *plaintext,
            &fkek,
            &Expected {
                ciphertext_sha256: &p.ciphertext_sha256,
                ciphertext_size: p.ciphertext_size,
                preamble_sha256: &p.preamble_sha256,
                intent_hash: &p.intent_hash,
                dek_slot_sha256: &p.dek_slot_sha256,
                scope: &Sealed {
                    snapshot_id: p.snapshot_id,
                    tenant_id: p.tenant_id,
                    fleet_id: p.fleet_id,
                    profile_id: p.profile_id,
                    target_version: p.target_version,
                    key_generation: p.key_generation,
                },
            },
        )
        .map_err(|_| bad("envelope"))?;
        shardx_core::snapshot::unpack(&plaintext, &target)?;
        Ok(plaintext.len() as u64)
    })
    .await
    .map_err(|e| {
        anyhow!(code_with(
            "sync.restoreTaskFailed",
            &[("error", &e.to_string())]
        ))
    })??;
    db.conn.execute(
        "UPDATE profile_bindings SET remote_version = ?2, last_observed_head_hash = ?3
         WHERE local_profile_id = ?1 AND remote_version = ?4",
        params![
            b.local,
            wire(head.current_version)?,
            head.current_signed_head_hash.map(|h| h.to_vec()),
            wire(b.version)?
        ],
    )?;
    Ok(restored)
}

#[cfg(test)]
mod tests {
    //! Push and pull against a fake v2 server that stores and replays exact
    //! responses the way `server/src/routes/v2_*` do, with response loss and
    //! refusals injected per route.

    use super::*;
    use axum::body::Bytes;
    use axum::extract::State;
    use axum::http::{HeaderMap, Method, StatusCode, Uri};
    use axum::response::{IntoResponse, Response};
    use shardx_core::authz_record::*;
    use shardx_core::profile_lease::{ReleaseLeaseV2, RECORD_TYPE_CHECKED_OUT};
    use shardx_core::restore_epoch::{
        build_signed_transition, mapping_root, RestoreEpochLeafV2, RestoreEpochTransitionV2,
        RestoreReason,
    };
    use shardx_core::snapshot_v2::LeaseReleaseOutcome;
    use shardx_core::trust_evidence::TenantTrustEvidencePageV2;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    const T0: u64 = 1_800_000_000_000;
    const DAY: u64 = 86_400_000;
    const NOW: u64 = T0 + DAY;
    const TENANT: [u8; 16] = [2; 16];
    const INSTANCE: [u8; 16] = [3; 16];
    const FLEET: [u8; 16] = [4; 16];
    const PROFILE: [u8; 16] = [0xc1; 16];
    const FKEK: [u8; 32] = [0x5a; 32];
    const GEN: u64 = 1;
    const LOCAL: &str = "local-profile";

    struct Me {
        sk: Ed25519SigningKey,
        hpke_sk: Zeroizing<Vec<u8>>,
        hpke_pk: Vec<u8>,
        to: Recipient,
    }

    fn me() -> Me {
        let sk = Ed25519SigningKey::from_bytes(&[1; 32]);
        let (hpke_sk, hpke_pk) = shardx_core::grants::derive_keypair(&[7; 32]);
        let to = Recipient {
            account_id: [6; 16],
            device_id: [5; 16],
            signing_key_id: shardx_core::keys::signing_key_id(sk.verifying_key().as_bytes()),
            hpke_key_id: shardx_core::keys::hpke_key_id(&hpke_pk),
        };
        Me {
            sk,
            hpke_sk,
            hpke_pk,
            to,
        }
    }

    fn device(me: &Me) -> Device {
        Device {
            signer: me.sk.clone(),
            me: me.to,
            pin: (
                Binding {
                    server_instance_id: INSTANCE,
                    tenant_id: TENANT,
                },
                me.to.signing_key_id,
            ),
        }
    }

    fn common(replay: u8) -> CommonFields {
        CommonFields {
            replay_id: [replay; 16],
            tenant_id: TENANT,
            issued_at_ms: T0,
            not_before_ms: T0,
            not_after_ms: T0 + 300 * DAY,
            server_instance_id: INSTANCE,
            restore_epoch: 0,
        }
    }

    fn device_subject(me: &Me) -> GrantSubject {
        GrantSubject::Device {
            account_id: me.to.account_id,
            device_id: me.to.device_id,
            signing_key_id: me.to.signing_key_id,
            hpke_key_id: me.to.hpke_key_id,
        }
    }

    /// This device's grant to `to` of `fkek` as `generation` of `FLEET`.
    fn grant_to(me: &Me, to: &Recipient, generation: u64, fkek: &[u8; 32], replay: u8) -> Vec<u8> {
        let mut g = DeviceHpkeGrantV2 {
            common: common(replay),
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
        shardx_core::grants::seal_device_fkek(&me.hpke_pk, &mut g, fkek).unwrap();
        build_record(&me.sk, DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE, &g.encode())
    }

    fn grant(me: &Me) -> Vec<u8> {
        grant_to(me, &me.to, GEN, &FKEK, 40)
    }

    /// What the evidence holds besides custody and the fleet grant.
    struct Ev {
        /// The scope of this device's `profile.commit`, if it holds one.
        commit: Option<CapabilityScopeKind>,
        approval_ends: u64,
        extra: Vec<Vec<u8>>,
    }

    impl Default for Ev {
        fn default() -> Self {
            Self {
                commit: Some(CapabilityScopeKind::Profile),
                approval_ends: T0 + 300 * DAY,
                extra: Vec::new(),
            }
        }
    }

    /// A tenant this device bootstrapped: its approval, root self-grant,
    /// `fleet.manage`, its fleet grant, and what `ev` adds.
    fn pages(me: &Me, grant: &[u8], ev: &Ev) -> Vec<TenantTrustEvidencePageV2> {
        let approval = DeviceApprovalV2 {
            common: CommonFields {
                not_after_ms: ev.approval_ends,
                ..common(10)
            },
            subject_account_id: me.to.account_id,
            subject_device_id: me.to.device_id,
            subject_signing_key_id: me.to.signing_key_id,
            subject_hpke_key_id: me.to.hpke_key_id,
            approval_scope_kind: ApprovalScopeKind::Tenant,
            approval_scope_id: TENANT,
        };
        let root = TenantRootKeyGrantV2 {
            common: common(11),
            variant: RootGrantVariant::FirstRootSelfGrant,
            root_key_id: [8; 32],
            root_generation: 0,
            subject_account_id: me.to.account_id,
            subject_device_id: me.to.device_id,
            subject_signing_key_id: me.to.signing_key_id,
            recipient_hpke_key_id: me.to.hpke_key_id,
            subject_device_approval_replay_id: [10; 16],
            hpke_encapped_key_bytes: [3; 32],
            hpke_wrapped_trk_bytes: [4; 48],
        };
        let capability = |replay, capability, scope_kind| {
            let scope_id = match scope_kind {
                CapabilityScopeKind::Tenant => TENANT,
                CapabilityScopeKind::Fleet => FLEET,
                CapabilityScopeKind::Profile => PROFILE,
            };
            let g = TenantCapabilityGrantV2 {
                common: common(replay),
                subject: device_subject(me),
                scope_kind,
                scope_id,
                capability,
            };
            build_record(&me.sk, DOMAIN_TENANT_CAPABILITY_GRANT, &g.encode())
        };
        let mut containers = vec![
            build_record(&me.sk, DOMAIN_DEVICE_APPROVAL, &approval.encode()),
            build_record(&me.sk, DOMAIN_TENANT_ROOT_KEY_GRANT, &root.encode()),
            capability(12, Capability::FleetManage, CapabilityScopeKind::Tenant),
            grant.to_vec(),
        ];
        if let Some(scope) = ev.commit {
            containers.push(capability(13, Capability::ProfileCommit, scope));
        }
        containers.extend(ev.extra.iter().cloned());
        vec![TenantTrustEvidencePageV2 {
            server_instance_id: INSTANCE,
            tenant_id: TENANT,
            server_now_ms: T0,
            page_index: 0,
            next_cursor: Vec::new(),
            signing_public_keys: vec![me.sk.verifying_key().to_bytes()],
            containers,
            revocations: Vec::new(),
            device_revocations: Vec::new(),
        }]
    }

    // ------------------------------------------------------------ fake ----

    struct Upload {
        terms: CreateUploadV2,
        data: Vec<u8>,
        state: &'static str,
        commit: Option<Vec<u8>>,
        /// The version its commit made.
        version: Option<u64>,
    }

    /// The server side of `v2_profiles`/`v2_uploads`, reduced to what the
    /// client depends on: stored exact responses replayed by idempotency key,
    /// one lease per profile, exact-offset PATCH, READY before commit.
    #[derive(Default)]
    struct Fake {
        version: u64,
        head: Option<[u8; 32]>,
        epoch: u64,
        /// The version and head the list reports, when not the real ones.
        listed: Option<(u64, Option<[u8; 32]>)>,
        /// The active key a checkout names, when not `GEN` and `FKEK`.
        generation: Option<u64>,
        fkek_key_id: Option<[u8; 32]>,
        /// Routes whose next request is refused unprocessed, with a status.
        refuse: Vec<(&'static str, u16)>,
        fence: u64,
        lease: Option<LeaseRef>,
        stored: HashMap<[u8; 16], (Vec<u8>, u16, Vec<u8>)>,
        uploads: HashMap<[u8; 16], Upload>,
        manifests: HashMap<u64, Vec<u8>>,
        objects: HashMap<u64, Vec<u8>>,
        pages: Vec<u8>,
        signer_pk: [u8; 32],
        log: Vec<(String, Vec<u8>)>,
        /// Routes whose next request is processed and its reply lost.
        lose: Vec<&'static str>,
        /// Routes whose next request is dropped unprocessed.
        skip: Vec<&'static str>,
        /// PATCHes accepted before one is dropped.
        patch_budget: Option<usize>,
        /// Replies altered on the way out: "receipt", "manifest", "checkout",
        /// "release" (unreadable) or "huge" (an oversized list).
        tamper: Option<&'static str>,
        commits: usize,
        /// The `expires_at_ms` a checkout grants, when not `NOW` + TTL.
        expires: Option<u64>,
        /// Other profiles the list reports after `PROFILE`.
        others: Vec<FleetProfileHeadV2>,
        /// Restore-epoch transitions and proofs, by path after
        /// `restore-epoch-transitions/`.
        epoch_files: HashMap<String, Vec<u8>>,
        /// Replies a restore left for rolled-back idempotency keys (Q-34).
        superseded: HashMap<[u8; 16], (u16, Vec<u8>)>,
        /// The idempotency keys of uploads and finalizes, by upload, and of
        /// commits, by the version they made.
        upload_keys: Vec<([u8; 16], [u8; 16])>,
        commit_keys: Vec<([u8; 16], u64)>,
        /// SQL another writer runs on the launcher's database when the next
        /// proof is served.
        on_proof: Option<String>,
    }

    fn take(list: &mut Vec<&'static str>, tag: &str) -> bool {
        let at = list.iter().position(|t| *t == tag);
        at.map(|i| list.remove(i)).is_some()
    }

    fn reply(status: u16, headers: &[(&str, String)], body: Vec<u8>) -> Response {
        let mut r = (StatusCode::from_u16(status).unwrap(), body).into_response();
        for (k, v) in headers {
            r.headers_mut().insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        r
    }

    impl Fake {
        /// An idempotent mutation: the stored reply for a known key, a
        /// conflict for other bytes under it, else `run` once and store.
        fn mutation(
            &mut self,
            body: &[u8],
            status: u16,
            record: &str,
            run: impl FnOnce(&mut Self, &[u8]) -> Result<Vec<u8>, u16>,
        ) -> (u16, Vec<u8>) {
            let Ok(req) = IdempotentMutationRequestV2::parse(body) else {
                return (422, b"bad request".to_vec());
            };
            // Q-34: the ledger answers before the epoch is checked.
            if let Some((st, resp)) = self.superseded.get(&req.idempotency_key) {
                return (*st, resp.clone());
            }
            if let Some((bytes, st, resp)) = self.stored.get(&req.idempotency_key) {
                return if bytes == body {
                    (*st, resp.clone())
                } else {
                    (409, b"IDEMPOTENCY_MISMATCH".to_vec())
                };
            }
            if req.restore_epoch != self.epoch {
                return (409, b"RESTORE_EPOCH_MISMATCH".to_vec());
            }
            match run(self, &req.canonical_payload_bytes) {
                Err(code) => (code, b"refused".to_vec()),
                Ok(payload) => {
                    let resp = IdempotentStoredResponseV2 {
                        operation_kind: req.operation_kind,
                        idempotency_key: req.idempotency_key,
                        exact_request_hash: req.canonical_request_hash(),
                        response_record_type: record.into(),
                        canonical_response_payload_bytes: payload,
                        server_instance_id: INSTANCE,
                        restore_epoch: self.epoch,
                        committed_at_ms: T0,
                        receipt_id: [9; 16],
                    }
                    .encode();
                    self.stored
                        .insert(req.idempotency_key, (body.to_vec(), status, resp.clone()));
                    (status, resp)
                }
            }
        }

        /// A restore to `keep` (ADR 0002 D-1): the epoch moves on, later
        /// versions and every upload not committed at or below `keep` are
        /// gone, no lease survives, and their idempotency keys are
        /// superseded (Q-34).
        fn restore(&mut self, keep: u64) {
            self.epoch += 1;
            self.manifests.retain(|v, _| *v <= keep);
            self.objects.retain(|v, _| *v <= keep);
            self.version = keep;
            self.head = self
                .manifests
                .get(&keep)
                .map(|m| SignedSnapshotManifestV2::parse(m).unwrap().head_hash());
            self.lease = None;
            let commit = serde_json::json!({
                "code": "BASE_VERSION_MISMATCH",
                "superseded_by_restore_epoch": self.epoch,
            });
            for (key, v) in self.commit_keys.clone() {
                if v > keep {
                    self.superseded
                        .insert(key, (409, commit.to_string().into_bytes()));
                }
            }
            self.uploads
                .retain(|_, u| u.version.is_some_and(|v| v <= keep));
            for (key, upload) in self.upload_keys.clone() {
                if !self.uploads.contains_key(&upload) {
                    let gone = br#"{"code":"RESOURCE_NOT_FOUND"}"#.to_vec();
                    self.superseded.insert(key, (404, gone));
                }
            }
        }

        fn route(
            &mut self,
            method: &Method,
            parts: &[&str],
            h: &HeaderMap,
            body: &[u8],
        ) -> Response {
            let id = |s: &str| decode_hex16(s, "id").unwrap();
            let header = |name: &str| {
                h.get(name)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string)
            };
            match (method.as_str(), parts) {
                ("GET", ["v2", "fleets", _, "profiles"]) if self.tamper == Some("huge") => {
                    reply(200, &[], vec![0; 9 << 20])
                }
                ("GET", ["v2", "fleets", _, "profiles"]) => {
                    let (version, head) = self.listed.unwrap_or((self.version, self.head));
                    let page = FleetProfilePageV2 {
                        server_instance_id: INSTANCE,
                        restore_epoch: self.epoch,
                        tenant_id: TENANT,
                        fleet_id: FLEET,
                        profiles: std::iter::once(FleetProfileHeadV2 {
                            profile_id: PROFILE,
                            current_version: version,
                            current_signed_head_hash: head,
                            key_generation: GEN,
                            label_ciphertext: vec![1],
                        })
                        .chain(self.others.iter().cloned())
                        .collect(),
                        next_after: None,
                    };
                    reply(200, &[], page.encode())
                }
                ("GET", ["v2", "tenants", _, "trust-evidence"]) => {
                    reply(200, &[], self.pages.clone())
                }
                ("POST", ["v2", "profiles", _, "checkout"]) => {
                    let (st, out) = self.mutation(body, 201, RECORD_TYPE_CHECKED_OUT, |f, p| {
                        let c = ProfileCheckoutV2::parse(p).map_err(|_| 422u16)?;
                        if c.observed_version != f.version || c.observed_signed_head_hash != f.head
                        {
                            return Err(409);
                        }
                        f.fence += 1;
                        let lease = LeaseRef {
                            lease_id: random().unwrap(),
                            fencing_token: f.fence,
                            base_version: f.version,
                        };
                        f.lease = Some(lease);
                        Ok(ProfileLeaseV2 {
                            profile: c.profile,
                            lease,
                            expires_at_ms: f.expires.unwrap_or(NOW + 300_000),
                            fkek_key_id: f
                                .fkek_key_id
                                .unwrap_or_else(|| shardx_core::fleet_grants::fkek_key_id(&FKEK)),
                            key_generation: f.generation.unwrap_or(GEN),
                            current_signed_head_hash: f.head,
                            server_instance_id: INSTANCE,
                            restore_epoch: f.epoch,
                        }
                        .encode(LeaseOrigin::Checkout))
                    });
                    if self.tamper == Some("checkout") && st == 201 {
                        let mut r = IdempotentStoredResponseV2::parse(&out).unwrap();
                        r.exact_request_hash = [0; 32];
                        return reply(st, &[], r.encode());
                    }
                    reply(st, &[], out)
                }
                ("POST", ["v2", "profiles", _, "leases", _, "release"]) => {
                    let (st, out) = self.mutation(body, 200, RECORD_TYPE_LEASE_RELEASED, |f, p| {
                        let r = ReleaseLeaseV2::parse(p).map_err(|_| 422u16)?;
                        if f.lease != Some(r.lease) {
                            return Err(409);
                        }
                        f.lease = None;
                        Ok(LeaseReleasedV2 {
                            profile: r.profile,
                            lease: r.lease,
                            released_at_ms: T0,
                            server_instance_id: INSTANCE,
                            restore_epoch: f.epoch,
                        }
                        .encode())
                    });
                    if self.tamper == Some("release") && st == 200 {
                        return reply(200, &[], b"not a stored response".to_vec());
                    }
                    reply(st, &[], out)
                }
                ("POST", ["v2", "profiles", _, "leases", _, "renew"]) => {
                    let r = LeaseRenewV2::parse(body).unwrap();
                    let out = LeaseRenewedV2 {
                        profile: r.profile,
                        lease: r.lease,
                        expires_at_ms: T0,
                    };
                    reply(200, &[], out.encode())
                }
                ("POST", ["v2", "profiles", _, "uploads"]) => {
                    let (st, out) = self.mutation(body, 201, RECORD_TYPE_UPLOAD_CREATED, |f, p| {
                        let terms = CreateUploadV2::parse(p).map_err(|_| 422u16)?;
                        if f.lease != Some(terms.lease) {
                            return Err(409);
                        }
                        let upload_id = random().unwrap();
                        let created = UploadCreatedV2 {
                            terms: terms.clone(),
                            upload_id,
                            expires_at_ms: T0,
                            server_instance_id: INSTANCE,
                            restore_epoch: f.epoch,
                        };
                        f.uploads.insert(
                            upload_id,
                            Upload {
                                terms,
                                data: Vec::new(),
                                state: "OPEN",
                                commit: None,
                                version: None,
                            },
                        );
                        Ok(created.encode())
                    });
                    if st == 201 {
                        let r = IdempotentStoredResponseV2::parse(&out).unwrap();
                        let created =
                            UploadCreatedV2::parse(&r.canonical_response_payload_bytes).unwrap();
                        self.upload_keys
                            .push((r.idempotency_key, created.upload_id));
                    }
                    reply(st, &[], out)
                }
                ("HEAD", ["v2", "uploads", u]) => {
                    let up = &self.uploads[&id(u)];
                    let headers = [
                        ("upload-offset", up.data.len().to_string()),
                        ("upload-state", up.state.to_string()),
                    ];
                    reply(200, &headers, Vec::new())
                }
                ("PATCH", ["v2", "uploads", u]) => {
                    let up = self.uploads.get_mut(&id(u)).unwrap();
                    let offset: usize = header("upload-offset").unwrap().parse().unwrap();
                    if offset != up.data.len() {
                        return reply(409, &[], b"UPLOAD_OFFSET_MISMATCH".to_vec());
                    }
                    assert_eq!(header("upload-chunk-sha256").unwrap(), hex(&sha256(body)));
                    up.data.extend_from_slice(body);
                    reply(
                        200,
                        &[("upload-offset", up.data.len().to_string())],
                        Vec::new(),
                    )
                }
                ("POST", ["v2", "uploads", u, "finalize"]) => {
                    let upload = id(u);
                    let (st, out) =
                        self.mutation(body, 200, RECORD_TYPE_UPLOAD_FINALIZED, |f, p| {
                            let fin = FinalizeUploadV2::parse(p).map_err(|_| 422u16)?;
                            let up = f.uploads.get_mut(&upload).ok_or(404u16)?;
                            if sha256(&up.data) != up.terms.expected_ciphertext_sha256 {
                                return Err(409);
                            }
                            up.state = "READY";
                            up.commit = Some(fin.commit().exact_bytes().to_vec());
                            Ok(UploadFinalizedV2 {
                                upload_id: upload,
                                snapshot_id: up.terms.snapshot_id,
                                manifest_replay_id: up.terms.manifest_replay_id,
                                ciphertext_size: up.data.len() as u64,
                                ciphertext_sha256: sha256(&up.data),
                                object_receipt_id: [7; 16],
                                server_instance_id: INSTANCE,
                                restore_epoch: f.epoch,
                            }
                            .encode())
                        });
                    if st == 200 {
                        let key = IdempotentMutationRequestV2::parse(body)
                            .unwrap()
                            .idempotency_key;
                        self.upload_keys.push((key, upload));
                    }
                    reply(st, &[], out)
                }
                ("POST", ["v2", "uploads", u, "commit"]) => {
                    let c = CommitRequestV2::parse(body).unwrap();
                    if let Some((st, resp)) = self.superseded.get(c.idempotency_key()) {
                        return reply(*st, &[], resp.clone());
                    }
                    let receipt = match self.stored.get(c.idempotency_key()) {
                        Some((bytes, _, _)) if bytes != body => {
                            return reply(409, &[], b"IDEMPOTENCY_MISMATCH".to_vec())
                        }
                        Some((_, _, receipt)) => receipt.clone(),
                        None => {
                            let up = self.uploads.get_mut(&id(u)).unwrap();
                            if up.state != "READY" || up.commit.as_deref() != Some(body) {
                                return reply(409, &[], b"UPLOAD_STATE_CONFLICT".to_vec());
                            }
                            up.state = "COMMITTED";
                            let data = up.data.clone();
                            let verified = c.clone().verify_signature(&self.signer_pk).unwrap();
                            let r = CommitReceiptBindingV2::for_request(
                                &verified,
                                LeaseReleaseOutcome::Released,
                                T0,
                                [8; 16],
                            );
                            self.version = r.resulting_version;
                            self.head = Some(r.resulting_head_hash);
                            self.lease = None;
                            self.manifests
                                .insert(self.version, c.manifest().exact_bytes().to_vec());
                            self.objects.insert(self.version, data);
                            self.commits += 1;
                            up.version = Some(r.resulting_version);
                            self.commit_keys
                                .push((*c.idempotency_key(), r.resulting_version));
                            let bytes = r.encode();
                            self.stored
                                .insert(*c.idempotency_key(), (body.to_vec(), 201, bytes.clone()));
                            bytes
                        }
                    };
                    if self.tamper == Some("receipt") {
                        let mut r = CommitReceiptBindingV2::parse(&receipt).unwrap();
                        r.resulting_version += 1;
                        return reply(201, &[], r.encode());
                    }
                    reply(201, &[], receipt)
                }
                ("GET", ["v2", "recovery", "restore-epoch-transitions", rest @ ..]) => {
                    if rest.contains(&"proofs") {
                        if let Some(sql) = self.on_proof.take() {
                            let c = rusqlite::Connection::open(Db::path().unwrap()).unwrap();
                            assert_eq!(c.execute(&sql, []).unwrap(), 1, "{sql}");
                        }
                    }
                    match self.epoch_files.get(&rest.join("/")) {
                        Some(b) => reply(200, &[], b.clone()),
                        None => reply(404, &[], br#"{"code":"RESOURCE_NOT_FOUND"}"#.to_vec()),
                    }
                }
                ("GET", ["v2", "profiles", _, "snapshots", v, "manifest"]) => {
                    let Some(mut m) = self.manifests.get(&v.parse().unwrap()).cloned() else {
                        return reply(404, &[], br#"{"code":"RESOURCE_NOT_FOUND"}"#.to_vec());
                    };
                    if self.tamper == Some("manifest") {
                        *m.last_mut().unwrap() ^= 1;
                    }
                    reply(200, &[], m)
                }
                ("GET", ["v2", "profiles", _, "snapshots", v]) => {
                    let o = &self.objects[&v.parse().unwrap()];
                    let (a, b) = header("range")
                        .unwrap()
                        .trim_start_matches("bytes=")
                        .split_once('-')
                        .map(|(a, b)| (a.parse::<usize>().unwrap(), b.parse::<usize>().unwrap()))
                        .unwrap();
                    let etag = format!("\"{}\"", hex(&sha256(o)));
                    reply(206, &[("etag", etag)], o[a..=b.min(o.len() - 1)].to_vec())
                }
                _ => reply(404, &[], b"no route".to_vec()),
            }
        }
    }

    async fn handle(
        State(fake): State<Arc<Mutex<Fake>>>,
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        body: Bytes,
    ) -> Response {
        let mut f = fake.lock().unwrap();
        assert!(f.log.len() < 400, "request storm");
        let path = uri.path().to_string();
        f.log.push((format!("{method} {path}"), body.to_vec()));
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        let tag = match (method.as_str(), parts.last().copied()) {
            ("PATCH", _) => "patch",
            ("HEAD", _) => "head",
            (_, Some(last)) => last,
            _ => "",
        };
        let tag = if parts.get(3) == Some(&"uploads") {
            "upload"
        } else {
            tag
        };
        if tag == "patch" {
            if let Some(n) = f.patch_budget.as_mut() {
                if *n == 0 {
                    f.patch_budget = None;
                    return reply(503, &[], Vec::new());
                }
                *n -= 1;
            }
        }
        if take(&mut f.skip, tag) {
            return reply(503, &[], Vec::new());
        }
        if let Some(i) = f.refuse.iter().position(|(t, _)| *t == tag) {
            let (_, status) = f.refuse.remove(i);
            return reply(status, &[("retry-after", "0".into())], b"refused".to_vec());
        }
        let r = f.route(&method, &parts, &headers, &body);
        if take(&mut f.lose, tag) {
            return reply(503, &[], Vec::new());
        }
        r
    }

    /// One device: its config root (team database, fleet keys), its copy of
    /// the profile, and the fake server it syncs with.
    struct World {
        _lock: std::sync::MutexGuard<'static, ()>,
        _dir: tempfile::TempDir,
        rt: tokio::runtime::Runtime,
        fake: Arc<Mutex<Fake>>,
        client: FleetClient,
        me: Me,
        dev: Device,
        grant: Vec<u8>,
        extra: Vec<Vec<u8>>,
        udd: std::path::PathBuf,
    }

    impl Drop for World {
        fn drop(&mut self) {
            crate::store::set_config_root(None);
        }
    }

    /// This device, bound to `PROFILE`, holding `FKEK` from a verified grant,
    /// with a profile worth several chunks.
    fn world() -> World {
        world_with(Vec::new())
    }

    /// `world` with `extra` containers in its trust evidence.
    fn world_with(extra: Vec<Vec<u8>>) -> World {
        let lock = crate::store::config_root_test_lock()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let me = me();
        let dev = device(&me);
        let grant = grant(&me);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let ev = Ev {
            extra: extra.clone(),
            ..Ev::default()
        };
        let fake = Arc::new(Mutex::new(Fake {
            pages: pages(&me, &grant, &ev)[0].encode(),
            signer_pk: me.sk.verifying_key().to_bytes(),
            ..Default::default()
        }));
        let app = axum::Router::new()
            .fallback(handle)
            .with_state(fake.clone());
        let base = rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            format!("http://{addr}")
        });
        let client = FleetClient::new(&base, "").unwrap();
        let udd = dir.path().join("udd");
        std::fs::create_dir_all(udd.join("Default")).unwrap();
        std::fs::write(udd.join("Preferences"), b"{}").unwrap();
        let mut x: u32 = 1;
        let noise: Vec<u8> = (0..200_000)
            .map(|_| {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                (x >> 16) as u8
            })
            .collect();
        std::fs::write(udd.join("Default").join("noise.bin"), noise).unwrap();
        let w = World {
            _lock: lock,
            _dir: dir,
            rt,
            fake,
            client,
            me,
            dev,
            grant,
            extra,
            udd,
        };
        w.enroll(w._dir.path());
        w
    }

    impl World {
        /// Makes `root` this device's config root, collects the fleet key
        /// from its verified grant and binds `LOCAL` to `PROFILE`.
        fn enroll(&self, root: &Path) {
            crate::store::set_config_root(Some(root.to_path_buf()));
            let mut db = Db::open().unwrap();
            let ev = Ev {
                extra: self.extra.clone(),
                ..Ev::default()
            };
            let pages = pages(&self.me, &self.grant, &ev);
            let fkek = crate::open_fleet_grant(
                &self.grant,
                &pages,
                &self.dev.pin,
                &self.me.to,
                &FLEET,
                GEN,
                &self.me.hpke_sk,
                NOW,
                &mut db,
                "https://fleet.test",
            )
            .unwrap()
            .expect("the grant verifies");
            assert_eq!(*fkek, FKEK);
            assert!(crate::fleet_keys::collect(&hex(&FLEET), GEN, &fkek).unwrap());
            db.conn
                .execute(
                    "INSERT INTO profile_bindings(local_profile_id, server_instance_id, tenant_id,
                       fleet_id, remote_profile_id, remote_version, accepted_restore_epoch,
                       sync_state)
                     VALUES (?1, ?2, ?3, ?4, ?5, 0, 0, 'AVAILABLE')",
                    params![
                        LOCAL,
                        hex(&INSTANCE),
                        hex(&TENANT),
                        hex(&FLEET),
                        hex(&PROFILE)
                    ],
                )
                .unwrap();
        }

        fn push(&self) -> Result<Pushed> {
            self.rt
                .block_on(push(&self.client, "t", &self.dev, LOCAL, &self.udd, NOW))
        }

        fn pull(&self, udd: &Path) -> Result<u64> {
            self.rt
                .block_on(pull(&self.client, "t", &self.dev, LOCAL, udd, NOW))
        }

        fn fake(&self) -> std::sync::MutexGuard<'_, Fake> {
            self.fake.lock().unwrap()
        }

        /// The bodies of every request whose `METHOD path` ends with `tail`.
        fn sent(&self, method: &str, tail: &str) -> Vec<Vec<u8>> {
            self.fake()
                .log
                .iter()
                .filter(|(m, _)| m.starts_with(method) && m.ends_with(tail))
                .map(|(_, b)| b.clone())
                .collect()
        }

        fn db(&self) -> Db {
            Db::open().unwrap()
        }

        fn count(&self, sql: &str) -> i64 {
            self.db().conn.query_row(sql, [], |r| r.get(0)).unwrap()
        }
    }

    fn has(err: &anyhow::Error, key: &str) -> bool {
        crate::errcode::has_code(&format!("{err:#}"), key)
    }

    /// A push seals under the verified fleet key, stores every request before
    /// sending it, keeps the exact receipt and reads it back; another device
    /// pulls exactly that head and restores the profile.
    #[test]
    fn a_published_profile_pushes_and_another_device_pulls_it() {
        let w = world();
        assert!(!is_published("not-published").unwrap());
        assert!(is_published(LOCAL).unwrap());
        let pushed = w.push().unwrap();
        assert_eq!(pushed.version, 1);
        let (commit_req, kept): (Vec<u8>, Vec<u8>) = w
            .db()
            .conn
            .query_row(
                "SELECT exact_request_bytes, exact_receipt_bytes FROM operations
                 WHERE kind = 'COMMIT' AND state = 'COMPLETED'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        let request = CommitRequestV2::parse(&commit_req).unwrap();
        assert_eq!(
            w.fake().stored[request.idempotency_key()].2,
            kept,
            "the exact receipt the server stored"
        );
        assert_eq!(w.sent("POST", "/commit"), std::slice::from_ref(&commit_req));
        assert_eq!(w.fake().commits, 1);
        for (sql, n) in [
            (
                "SELECT count(*) FROM upload_sessions WHERE state = 'COMMITTED'",
                1,
            ),
            (
                "SELECT count(*) FROM operations WHERE state <> 'COMPLETED'",
                0,
            ),
            (
                "SELECT count(*) FROM profile_bindings WHERE remote_version = 1
                   AND lease_id IS NULL AND sync_state = 'AVAILABLE'",
                1,
            ),
        ] {
            assert_eq!(w.count(sql), n, "{sql}");
        }
        let head: Vec<u8> = w
            .db()
            .conn
            .query_row(
                "SELECT last_observed_head_hash FROM profile_bindings",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            Some(head.as_slice()),
            w.fake().head.as_ref().map(|h| &h[..])
        );
        // The server received the object sealed under the fleet key.
        let object = w.fake().objects[&1].clone();
        assert_eq!(sha256(&object), pushed.ciphertext_sha256);
        assert!(std::fs::read_dir(spool("x").unwrap().parent().unwrap())
            .unwrap()
            .next()
            .is_none());

        // Another device, same identity, its own team database.
        let other = tempfile::tempdir().unwrap();
        w.enroll(other.path());
        let restored = other.path().join("restored");
        assert!(w.pull(&restored).unwrap() > 0);
        assert_eq!(
            std::fs::read(restored.join("Default").join("noise.bin")).unwrap(),
            std::fs::read(w.udd.join("Default").join("noise.bin")).unwrap()
        );
        assert_eq!(
            w.count("SELECT count(*) FROM profile_bindings WHERE remote_version = 1"),
            1
        );
        // Re-reading the pinned head restores it again.
        assert!(w.pull(&restored).is_ok());
    }

    /// G2-37: the push stops at each of the three request/response crash
    /// points, before finalize is sent, after its reply is lost and after the
    /// commit's reply is lost. The next push, from the database alone, sends
    /// the exact stored bytes again and commits once.
    #[test]
    fn every_crash_point_resumes_with_the_exact_stored_bytes() {
        for (lost, dropped, route) in [
            (None, Some("finalize"), "/finalize"),
            (Some("finalize"), None, "/finalize"),
            (Some("commit"), None, "/commit"),
        ] {
            let w = world();
            {
                let mut f = w.fake();
                f.lose.extend(lost);
                f.skip.extend(dropped);
            }
            let err = w.push().expect_err(route);
            assert!(has(&err, "fleet.refusedSync"), "{route}: {err:#}");
            assert_eq!(
                w.count(
                    "SELECT count(*) FROM operations o JOIN upload_sessions s
                       ON s.commit_op_id = o.op_id
                     WHERE o.kind = 'COMMIT' AND o.signed_manifest_container_bytes IS NOT NULL"
                ),
                1,
                "{route}: manifest and request stored before finalize"
            );
            assert_eq!(w.push().expect(route).version, 1);
            let sent = w.sent("POST", route);
            assert_eq!(sent.len(), 2, "{route}");
            assert_eq!(sent[0], sent[1], "{route}: the exact stored bytes");
            assert_eq!(w.fake().commits, 1, "{route}");
        }
    }

    /// G2-37: a stored column that no longer matches the exact bytes it
    /// describes, or a spool that no longer hashes to them, quarantines the
    /// binding before anything is sent, even with foreign keys bypassed.
    #[test]
    fn a_stored_column_that_drifts_from_its_bytes_is_never_sent() {
        let other = format!("'{}'", "99".repeat(16));
        for sql in [
            "UPDATE operations SET snapshot_id = zeroblob(16) WHERE kind = 'COMMIT'".to_string(),
            "UPDATE operations SET manifest_replay_id = zeroblob(16) WHERE kind = 'COMMIT'".into(),
            format!("UPDATE operations SET server_instance_id = {other} WHERE kind = 'COMMIT'"),
            "UPDATE operations SET restore_epoch = 1 WHERE kind = 'COMMIT'".into(),
            "UPDATE operations SET fencing_token = 9 WHERE kind = 'COMMIT'".into(),
            "UPDATE operations SET exact_request_bytes = CAST(x'00' || exact_request_bytes AS BLOB)
               WHERE kind = 'COMMIT'"
                .into(),
            format!("UPDATE operations SET server_instance_id = {other} WHERE kind = 'FINALIZE'"),
            "UPDATE operations SET restore_epoch = 1 WHERE kind = 'FINALIZE'".into(),
            format!("UPDATE upload_sessions SET server_instance_id = {other}"),
            "UPDATE upload_sessions SET restore_epoch = 1".into(),
            "UPDATE upload_sessions SET snapshot_id = zeroblob(16)".into(),
            "UPDATE upload_sessions SET manifest_replay_id = zeroblob(16)".into(),
            "SPOOL".into(),
        ] {
            let w = world();
            w.fake().skip.push("finalize");
            w.push().unwrap_err();
            if sql == "SPOOL" {
                let dir = spool("x").unwrap().parent().unwrap().to_path_buf();
                for f in std::fs::read_dir(dir).unwrap() {
                    std::fs::write(f.unwrap().path(), b"not the ciphertext").unwrap();
                }
            } else {
                // Foreign keys off, as a fixture bypassing them.
                let raw = rusqlite::Connection::open(Db::path().unwrap()).unwrap();
                raw.pragma_update(None, "foreign_keys", false).unwrap();
                assert_eq!(raw.execute(&sql, []).unwrap(), 1, "{sql}");
            }
            let before = w.fake().log.len();
            let err = w.push().unwrap_err();
            assert!(has(&err, "sync.storedRequestMismatch"), "{sql}: {err:#}");
            assert_eq!(w.fake().log.len(), before, "{sql}: nothing was sent");
            let err = w.push().unwrap_err();
            assert!(has(&err, "sync.bindingQuarantined"), "{sql}: {err:#}");
            assert_eq!(w.fake().log.len(), before, "{sql}");
        }
    }

    /// A fleet key collected before the kept records (schema version 3) is
    /// refused with the named error that asks for it to be collected again
    /// in Settings: no sync files its record. The lease is released and
    /// nothing is uploaded.
    #[test]
    fn a_key_without_its_kept_record_asks_to_be_collected_again() {
        let w = world();
        w.db()
            .conn
            .execute("DELETE FROM signed_authorization_records", [])
            .unwrap();
        for _ in 0..2 {
            let err = w.push().unwrap_err();
            assert!(has(&err, "sync.fleetKeyRecollect"), "{err:#}");
            assert!(w.fake().lease.is_none(), "the server released it");
        }
        assert!(w.sent("POST", "/uploads").is_empty());
    }

    /// G2-34: a release whose reply was lost stays stored, and the next push
    /// sends it again byte for byte before anything else. Without a verified
    /// key for the generation the checkout names, push never falls back to
    /// the passphrase: it releases the lease and uploads nothing.
    #[test]
    fn a_release_whose_reply_was_lost_is_replayed_byte_for_byte() {
        let w = world();
        {
            let mut f = w.fake();
            f.generation = Some(2);
            f.lose.push("release");
        }
        let err = w.push().unwrap_err();
        assert!(has(&err, "sync.noVerifiedFleetKey"), "{err:#}");
        assert!(w.fake().lease.is_none(), "the server released it");
        assert_eq!(
            w.count("SELECT count(*) FROM operations WHERE kind = 'RELEASE' AND state = 'PENDING'"),
            1
        );
        let err = w.push().unwrap_err();
        assert!(has(&err, "sync.noVerifiedFleetKey"), "{err:#}");
        let sent = w.sent("POST", "/release");
        assert_eq!(sent.len(), 3, "lost, replayed, then a new lease's");
        assert_eq!(sent[0], sent[1]);
        assert_ne!(sent[1], sent[2]);
        assert_eq!(
            w.count(
                "SELECT count(*) FROM operations WHERE kind = 'RELEASE' AND state = 'COMPLETED'
                   AND exact_receipt_bytes = exact_response_bytes"
            ),
            2
        );
        assert!(w.sent("POST", "/uploads").is_empty());
        assert_eq!(
            w.count("SELECT count(*) FROM profile_bindings WHERE lease_id IS NULL"),
            1
        );
    }

    /// G2-36: an upload cut off after two chunks resumes from the offset
    /// `HEAD` reports; no accepted chunk is sent again.
    #[test]
    fn an_interrupted_upload_resumes_at_the_offset_head_reports() {
        let w = world();
        w.fake().patch_budget = Some(2);
        let err = w.push().unwrap_err();
        assert!(has(&err, "fleet.refusedSync"), "{err:#}");
        assert_eq!(
            w.count("SELECT committed_offset FROM upload_sessions"),
            2 * CHUNK as i64
        );
        assert_eq!(w.push().unwrap().version, 1);
        let object = w.fake().objects[&1].clone();
        let chunks = object.len().div_ceil(CHUNK);
        assert!(chunks > 3, "{chunks}");
        let patches = w.sent("PATCH", "");
        assert_eq!(patches.len(), chunks + 1, "only the dropped chunk again");
        assert_eq!(patches[2], patches[3]);
        assert_eq!(patches[..2].concat(), object[..2 * CHUNK]);
        assert_eq!(w.sent("HEAD", "").len(), 2);
    }

    /// G2-38: a receipt that does not bind the stored request is not kept,
    /// nor a pushed head whose manifest reads back otherwise; the retry
    /// replays the same commit bytes and keeps the server's exact receipt.
    #[test]
    fn a_receipt_or_readback_that_does_not_match_is_never_kept() {
        let w = world();
        w.fake().tamper = Some("receipt");
        let err = w.push().unwrap_err();
        assert!(has(&err, "sync.badReplySync"), "{err:#}");
        assert_eq!(
            w.count(
                "SELECT count(*) FROM operations WHERE kind = 'COMMIT' AND state = 'PENDING'
                   AND exact_receipt_bytes IS NULL"
            ),
            1
        );
        assert_eq!(
            w.count("SELECT count(*) FROM upload_sessions WHERE state = 'READY'"),
            1
        );
        w.fake().tamper = Some("manifest");
        let err = w.push().unwrap_err();
        assert!(has(&err, "sync.readbackMismatch"), "{err:#}");
        assert_eq!(
            w.count("SELECT count(*) FROM profile_bindings WHERE remote_version = 0"),
            1,
            "nothing pinned"
        );
        w.fake().tamper = None;
        assert_eq!(w.push().unwrap().version, 1);
        let sent = w.sent("POST", "/commit");
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0], sent[1]);
        assert_eq!(w.fake().commits, 1);
        let request = CommitRequestV2::parse(&sent[0]).unwrap();
        let kept: Vec<u8> = w
            .db()
            .conn
            .query_row(
                "SELECT exact_commit_receipt_binding_bytes FROM upload_sessions",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(kept, w.fake().stored[request.idempotency_key()].2);
    }

    /// Pull uses only a key whose grant reverifies now: none held, or one
    /// whose issuer this device distrusts, refuses with no passphrase
    /// fallback; push then releases its lease and uploads nothing.
    #[test]
    fn a_missing_or_withdrawn_fleet_key_is_refused() {
        let w = world();
        w.push().unwrap();
        let distrust =
            || ledger::distrust_key(&w.db(), &w.dev.pin.0, &w.me.to.signing_key_id, NOW).unwrap();
        distrust();
        let err = w.push().unwrap_err();
        assert!(has(&err, "sync.noVerifiedFleetKey"), "{err:#}");
        assert_eq!(w.sent("POST", "/release").len(), 1);
        assert_eq!(w.sent("POST", "/uploads").len(), 1, "only the first push");

        let other = tempfile::tempdir().unwrap();
        w.enroll(other.path());
        let out = other.path().join("out");
        let keys = crate::fleet_keys::load().unwrap();
        crate::fleet_keys::save(&crate::fleet_keys::FleetKeyStore::default()).unwrap();
        let err = w.pull(&out).unwrap_err();
        assert!(has(&err, "sync.noVerifiedFleetKey"), "{err:#}");
        crate::fleet_keys::save(&keys).unwrap();
        distrust();
        let err = w.pull(&out).unwrap_err();
        assert!(has(&err, "sync.signerUntrusted"), "{err:#}");
        assert!(!out.exists());
    }

    /// Rule 6: a listed head behind the pinned one, another head at the
    /// pinned version, or an epoch other than the accepted one quarantines
    /// the binding, and nothing syncs until it is reconciled. A later epoch
    /// with no transition filed for it stays quarantined.
    #[test]
    fn a_rolled_back_head_or_epoch_quarantines_the_binding() {
        for (listed, fake_epoch, accepted, code, then) in [
            (
                Some((0, None)),
                0,
                0,
                "sync.headRollback",
                "sync.bindingQuarantined",
            ),
            (
                Some((1, Some([9; 32]))),
                0,
                0,
                "sync.headRollback",
                "sync.bindingQuarantined",
            ),
            (None, 0, 1, "sync.headRollback", "sync.bindingQuarantined"),
            (
                None,
                1,
                0,
                "sync.epochTransitionMissing",
                "sync.epochTransitionMissing",
            ),
        ] {
            let w = world();
            w.push().unwrap();
            {
                let mut f = w.fake();
                f.listed = listed;
                f.epoch = fake_epoch;
            }
            w.db()
                .conn
                .execute(
                    "UPDATE profile_bindings SET accepted_restore_epoch = ?1",
                    [accepted],
                )
                .unwrap();
            let out = w.udd.with_file_name("out");
            let err = w.pull(&out).unwrap_err();
            assert!(has(&err, code), "{err:#}");
            assert!(!out.exists());
            for err in [w.pull(&out).unwrap_err(), w.push().unwrap_err()] {
                assert!(has(&err, then), "{err:#}");
            }
            assert_eq!(
                w.count("SELECT count(*) FROM profile_bindings WHERE sync_state = 'QUARANTINED'"),
                1
            );
        }
    }

    /// Q-18: a counted `compromised` revocation blocks commits under a
    /// generation it exposes (verified no later than the revocation was
    /// counted, or granted to the revoked key); the lease is released. A
    /// `retired` one, or a generation verified after it and never granted to
    /// that key, does not block.
    #[test]
    fn a_compromised_revocation_blocks_commits_under_an_exposed_generation() {
        // Sealed to this device's HPKE key: only the subject matters here.
        let revoked = Recipient {
            device_id: [0x77; 16],
            signing_key_id: [0x77; 32],
            ..me().to
        };
        let to_revoked = vec![grant_to(&me(), &revoked, GEN, &FKEK, 41)];
        for (reason, counted, extra, blocked) in [
            (DeviceRevocationReason::Compromised, 1, vec![], true),
            (DeviceRevocationReason::Retired, 1, vec![], false),
            (DeviceRevocationReason::Compromised, 0, vec![], false),
            (DeviceRevocationReason::Compromised, 0, to_revoked, true),
        ] {
            let w = world_with(extra);
            let revocation = DeviceRevocationV2 {
                common: common(30),
                subject_account_id: [6; 16],
                subject_device_id: [0x77; 16],
                subject_signing_key_id: [0x77; 32],
                subject_hpke_key_id: [0x78; 32],
                reason_code: reason,
            };
            let container = build_record(&w.me.sk, DOMAIN_DEVICE_REVOCATION, &revocation.encode());
            w.db()
                .conn
                .execute(
                    "INSERT INTO trust_proven_revocations
                     VALUES (?1, ?2, ?3, 'DEVICE_REVOCATION', ?4, 0, ?5)",
                    params![
                        hex(&INSTANCE),
                        hex(&TENANT),
                        hex(&[0x77; 32]),
                        counted,
                        container
                    ],
                )
                .unwrap();
            let pushed = w.push();
            if blocked {
                let err = pushed.unwrap_err();
                assert!(has(&err, "sync.commitBlockedCompromised"), "{err:#}");
                assert_eq!(w.sent("POST", "/release").len(), 1);
                assert!(w.sent("POST", "/uploads").is_empty());
            } else {
                assert_eq!(pushed.unwrap().version, 1, "{reason:?} {counted}");
            }
        }
    }

    /// Rule 6, first acceptance: a new head is restored only while its
    /// signer holds, now, an approval and a device-scoped `profile.commit`
    /// covering the profile or its fleet.
    #[test]
    fn a_head_whose_signer_may_not_commit_is_not_restored() {
        for (ev, trusted) in [
            (
                Ev {
                    commit: None,
                    ..Ev::default()
                },
                false,
            ),
            (
                Ev {
                    approval_ends: T0 + DAY / 2,
                    ..Ev::default()
                },
                false,
            ),
            (
                Ev {
                    commit: Some(CapabilityScopeKind::Fleet),
                    ..Ev::default()
                },
                true,
            ),
        ] {
            let w = world();
            w.push().unwrap();
            w.fake().pages = pages(&w.me, &w.grant, &ev)[0].encode();
            let other = tempfile::tempdir().unwrap();
            w.enroll(other.path());
            let out = other.path().join("out");
            let pulled = w.pull(&out);
            let pinned = w.count("SELECT remote_version FROM profile_bindings");
            if trusted {
                assert!(pulled.is_ok() && pinned == 1, "{:?}", ev.commit);
            } else {
                let err = pulled.unwrap_err();
                assert!(has(&err, "sync.signerUntrusted"), "{err:#}");
                assert!(!out.exists() && pinned == 0);
            }
        }
    }

    /// A push from behind the listed head is refused before any lease is
    /// taken: pull first.
    #[test]
    fn a_push_behind_the_listed_head_is_refused() {
        let w = world();
        w.fake().listed = Some((1, Some([9; 32])));
        let err = w.push().unwrap_err();
        assert!(has(&err, "sync.remoteAhead"), "{err:#}");
        assert!(w.sent("POST", "/checkout").is_empty());
    }

    /// Rule 6 epoch: after a restore to epoch 1 the list agrees with the
    /// binding, but a head committed at epoch 0 is a rolled-back one.
    #[test]
    fn a_new_head_from_an_earlier_epoch_is_a_rollback() {
        let w = world();
        w.push().unwrap();
        let other = tempfile::tempdir().unwrap();
        w.enroll(other.path());
        w.db()
            .conn
            .execute("UPDATE profile_bindings SET accepted_restore_epoch = 1", [])
            .unwrap();
        w.fake().epoch = 1;
        let out = other.path().join("out");
        let err = w.pull(&out).unwrap_err();
        assert!(has(&err, "sync.headRollback"), "{err:#}");
        assert!(!out.exists());
        let err = w.pull(&out).unwrap_err();
        assert!(has(&err, "sync.bindingQuarantined"), "{err:#}");
    }

    /// Push seals only under the key the checkout names, at a generation no
    /// lower than the highest this device verified: another key ID, or an
    /// older generation, releases the lease and uploads nothing.
    #[test]
    fn a_key_the_checkout_does_not_name_is_never_used() {
        let w = world();
        w.fake().fkek_key_id = Some([0x11; 32]);
        let err = w.push().unwrap_err();
        assert!(has(&err, "sync.noVerifiedFleetKey"), "{err:#}");
        drop(w);

        let w = world();
        let newer = [0x5b; 32];
        let second = grant_to(&w.me, &w.me.to, GEN + 1, &newer, 42);
        let ev = Ev {
            extra: vec![second.clone()],
            ..Ev::default()
        };
        let mut db = w.db();
        let opened = crate::open_fleet_grant(
            &second,
            &pages(&w.me, &w.grant, &ev),
            &w.dev.pin,
            &w.me.to,
            &FLEET,
            GEN + 1,
            &w.me.hpke_sk,
            NOW,
            &mut db,
            "https://fleet.test",
        )
        .unwrap()
        .expect("generation 2 verifies");
        assert!(crate::fleet_keys::collect(&hex(&FLEET), GEN + 1, &opened).unwrap());
        let err = w.push().unwrap_err();
        assert!(has(&err, "sync.noVerifiedFleetKey"), "{err:#}");
        assert!(w.sent("POST", "/uploads").is_empty());
        assert_eq!(w.sent("POST", "/release").len(), 1);
    }

    /// A refused request is never resent: the next push stores a new one. A
    /// stored response that names another request is not kept.
    #[test]
    fn a_refused_or_mismatched_reply_is_never_kept() {
        let w = world();
        w.fake().refuse.push(("checkout", 409));
        let err = w.push().unwrap_err();
        assert!(has(&err, "fleet.refusedSync"), "{err:#}");
        assert_eq!(
            w.count("SELECT count(*) FROM operations WHERE kind = 'CHECKOUT' AND state = 'FAILED'"),
            1
        );
        w.fake().tamper = Some("checkout");
        let err = w.push().unwrap_err();
        assert!(has(&err, "sync.badReplySync"), "{err:#}");
        assert_eq!(
            w.count(
                "SELECT count(*) FROM profile_bindings WHERE lease_id IS NULL
                   AND sync_state = 'AVAILABLE'"
            ),
            1
        );
        w.fake().tamper = None;
        assert_eq!(w.push().unwrap().version, 1);
        let sent = w.sent("POST", "/checkout");
        assert_eq!(sent.len(), 3);
        assert_ne!(sent[0], sent[1], "the refused request is not resent");
        assert_eq!(sent[1], sent[2], "the unkept one is");
    }

    /// A head another device committed on top of this push, after its
    /// receipt was kept, does not strand it: the readback of its own version
    /// is pinned and the lease the commit released is dropped. A listed head
    /// behind the receipt still fails.
    #[test]
    fn a_head_committed_on_top_does_not_strand_the_push() {
        let w = world();
        w.fake().tamper = Some("manifest");
        let err = w.push().unwrap_err();
        assert!(has(&err, "sync.readbackMismatch"), "{err:#}");
        {
            let mut f = w.fake();
            f.tamper = None;
            f.listed = Some((0, None));
        }
        let err = w.push().unwrap_err();
        assert!(has(&err, "sync.readbackMismatch"), "{err:#}");
        w.fake().listed = Some((2, Some([9; 32])));
        assert_eq!(w.push().unwrap().version, 1);
        assert_eq!(
            w.count(
                "SELECT count(*) FROM profile_bindings WHERE remote_version = 1
                   AND lease_id IS NULL AND sync_state = 'AVAILABLE'"
            ),
            1
        );
        let err = w.push().unwrap_err();
        assert!(has(&err, "sync.remoteAhead"), "{err:#}");
        assert_eq!(w.fake().commits, 1);
    }

    /// Plan 8.2: a 401 only ends the session and 408/429 ask to resend, so
    /// none of them fails the stored request or drops the lease. 408/429 are
    /// resent as they were; after a 401 the next push sends the same commit,
    /// or release, byte for byte.
    #[test]
    fn a_lost_session_or_rate_limit_keeps_the_stored_request() {
        let w = world();
        w.fake().refuse.extend([
            ("checkout", 429),
            ("checkout", 408),
            ("head", 401),
            ("commit", 401),
        ]);
        let err = w.push().unwrap_err();
        assert!(has(&err, "sync.authRequired"), "{err:#}");
        let checkouts = w.sent("POST", "/checkout");
        assert_eq!(checkouts.len(), 3);
        assert!(checkouts.windows(2).all(|p| p[0] == p[1]));
        assert_eq!(
            w.count("SELECT count(*) FROM upload_sessions WHERE state = 'OPEN'"),
            1
        );
        let err = w.push().unwrap_err();
        assert!(has(&err, "sync.authRequired"), "{err:#}");
        assert_eq!(
            w.count("SELECT count(*) FROM operations WHERE kind = 'COMMIT' AND state = 'PENDING'"),
            1
        );
        assert_eq!(
            w.count("SELECT count(*) FROM profile_bindings WHERE lease_id IS NOT NULL"),
            1
        );
        assert_eq!(w.push().unwrap().version, 1);
        let commits = w.sent("POST", "/commit");
        assert_eq!(commits.len(), 2);
        assert_eq!(commits[0], commits[1]);
        assert_eq!(w.fake().commits, 1);
        drop(w);

        let w = world();
        {
            let mut f = w.fake();
            f.generation = Some(2);
            f.refuse.push(("release", 401));
        }
        let err = w.push().unwrap_err();
        assert!(has(&err, "sync.noVerifiedFleetKey"), "{err:#}");
        assert_eq!(
            w.count("SELECT count(*) FROM operations WHERE kind = 'RELEASE' AND state = 'PENDING'"),
            1
        );
        assert_eq!(
            w.count("SELECT count(*) FROM profile_bindings WHERE lease_id IS NOT NULL"),
            1
        );
        w.push().unwrap_err();
        let sent = w.sent("POST", "/release");
        assert_eq!(sent.len(), 3);
        assert_eq!(sent[0], sent[1]);
        assert!(w.fake().lease.is_none());
    }

    /// A checkout replayed after the binding moved on to a newer head holds a
    /// lease on the old one: it is released as stored, the checkout is
    /// failed, and the push takes a fresh lease at the new head.
    #[test]
    fn a_replayed_checkout_on_an_old_head_is_released_and_taken_again() {
        let w = world();
        w.fake().lose.push("checkout");
        w.push().unwrap_err();
        let head = [9u8; 32];
        {
            let mut f = w.fake();
            f.version = 1;
            f.head = Some(head);
        }
        w.db()
            .conn
            .execute(
                "UPDATE profile_bindings SET remote_version = 1, last_observed_head_hash = ?1",
                [head.to_vec()],
            )
            .unwrap();
        assert_eq!(w.push().unwrap().version, 2);
        let checkouts = w.sent("POST", "/checkout");
        assert_eq!(checkouts.len(), 3);
        assert_eq!(checkouts[0], checkouts[1]);
        assert_ne!(checkouts[1], checkouts[2]);
        assert_eq!(w.sent("POST", "/release").len(), 1);
        assert_eq!(
            w.count("SELECT count(*) FROM operations WHERE kind = 'CHECKOUT' AND state = 'FAILED'"),
            1
        );
    }

    /// A pull never writes over a profile whose push is in flight: one with
    /// a stored request pending, or a lease still held.
    #[test]
    fn a_pull_waits_for_a_push_in_flight() {
        for lose in [true, false] {
            let w = world();
            if lose {
                w.fake().lose.push("checkout");
            } else {
                w.fake().tamper = Some("manifest");
            }
            w.push().unwrap_err();
            let out = w.udd.with_file_name("out");
            let err = w.pull(&out).unwrap_err();
            assert!(has(&err, "sync.pushPending"), "{lose}: {err:#}");
            assert!(!out.exists());
        }
    }

    /// A 2xx release reply that does not parse is a protocol error: each
    /// push reports it and the release stays stored, replayed as it was
    /// until a readable reply completes it.
    #[test]
    fn an_unreadable_release_reply_is_reported_and_replayed() {
        let w = world();
        {
            let mut f = w.fake();
            f.generation = Some(2);
            f.tamper = Some("release");
        }
        let err = w.push().unwrap_err();
        assert!(has(&err, "sync.noVerifiedFleetKey"), "{err:#}");
        let err = w.push().unwrap_err();
        assert!(has(&err, "sync.badReplySync"), "{err:#}");
        w.fake().tamper = None;
        let err = w.push().unwrap_err();
        assert!(has(&err, "sync.noVerifiedFleetKey"), "{err:#}");
        let sent = w.sent("POST", "/release");
        assert_eq!(sent.len(), 4);
        assert!(sent[0] == sent[1] && sent[1] == sent[2]);
        assert_eq!(
            w.count(
                "SELECT count(*) FROM operations WHERE kind = 'RELEASE' AND state = 'COMPLETED'"
            ),
            2
        );
    }

    /// A reply larger than any the client asks for is not held.
    #[test]
    fn a_reply_too_large_to_hold_is_refused() {
        let w = world();
        w.fake().tamper = Some("huge");
        let err = w.push().unwrap_err();
        assert!(has(&err, "sync.badReplySync"), "{err:#}");
        assert!(format!("{err:#}").contains("body-size"), "{err:#}");
        assert!(w.sent("POST", "/checkout").is_empty());
    }

    /// The origin `enroll` filed the fleet key's records under.
    const SERVER: &str = "https://fleet.test";

    /// The local ID at request and now, request hash, exact request, receipt
    /// and receipt hash of the stored unbind.
    type UnbindRow = (String, Option<String>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

    fn unbind_op(w: &World) -> UnbindRow {
        w.db()
            .conn
            .query_row(
                "SELECT local_profile_id_at_request, local_profile_id, canonical_request_hash,
                   exact_request_bytes, exact_receipt_bytes, receipt_sha256
                 FROM operations WHERE kind = 'UNBIND' AND state = 'COMPLETED'",
                [],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                },
            )
            .unwrap()
    }

    /// Probe 1 (L2036), G2-26, G2-33: the unbind stores the completed
    /// `UNBIND` with its exact response and D-7 tombstone and deletes the
    /// binding, with no server call. Its context, request hash and receipt
    /// outlive the binding across reopen; a retry returns the same bytes, and
    /// no push, pull or listing brings the binding back.
    #[test]
    fn an_unbind_tombstone_outlives_its_binding_and_replays_exactly() {
        let w = world();
        w.push().unwrap();
        let sent = w.fake().log.len();
        let reply = unbind(LOCAL, SERVER, NOW).unwrap();
        assert_eq!(w.fake().log.len(), sent, "no server call");

        let stored = IdempotentStoredResponseV2::parse(&reply).unwrap();
        assert_eq!(stored.operation_kind, OperationKind::LocalUnbind);
        assert_eq!(stored.response_record_type, RECORD_TYPE_LOCAL_UNBOUND);
        let done = LocalUnboundV2::parse(&stored.canonical_response_payload_bytes).unwrap();
        let server_id: String = w
            .db()
            .conn
            .query_row(
                "SELECT server_id FROM server_origins WHERE origin = 'https://fleet.test:443'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let expected = UnboundBinding {
            server_id,
            server_instance_id: INSTANCE,
            restore_epoch: 0,
            tenant_id: TENANT,
            fleet_id: FLEET,
            remote_profile_id: PROFILE,
            local_profile_id: LOCAL.into(),
            remote_version: 1,
            expected_signed_head_hash: w.fake().head,
        };
        assert_eq!(done.binding, expected);
        assert_eq!(done.completed_at_ms, NOW);

        let (at_request, local, canonical, request, receipt, receipt_sha) = unbind_op(&w);
        assert_eq!((at_request.as_str(), local), (LOCAL, None));
        let req = IdempotentMutationRequestV2::parse(&request).unwrap();
        assert_eq!(canonical, req.canonical_request_hash());
        assert_eq!(stored.exact_request_hash, req.canonical_request_hash());
        assert_eq!(
            LocalUnbindV2::parse(&req.canonical_payload_bytes)
                .unwrap()
                .binding,
            expected
        );
        let tombstone = LocalBindingTombstoneV2::parse(&receipt).unwrap();
        assert_eq!(tombstone.binding, expected);
        assert_eq!(tombstone.unbind_idempotency_key, req.idempotency_key);
        assert_eq!(tombstone.hash(), done.binding_tombstone_sha256);
        assert_eq!(receipt_sha, sha256(&receipt));
        for (sql, n) in [
            ("SELECT count(*) FROM profile_bindings", 0),
            (
                "SELECT count(*) FROM operations WHERE local_profile_id IS NOT NULL",
                0,
            ),
            (
                "SELECT count(*) FROM operations WHERE kind = 'UNBIND' AND remote_profile_id =
                   'c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1' AND exact_response_bytes_sha256 IS NOT NULL",
                1,
            ),
        ] {
            assert_eq!(w.count(sql), n, "{sql}");
        }

        // Every call below reopens the database file.
        assert_eq!(unbind(LOCAL, SERVER, NOW + DAY).unwrap(), reply);
        assert_eq!(unbind(LOCAL, SERVER, NOW + DAY).unwrap(), reply);
        assert_eq!(
            w.count("SELECT count(*) FROM operations WHERE kind = 'UNBIND'"),
            1
        );
        assert!(!is_published(LOCAL).unwrap());
        let err = w.push().unwrap_err();
        assert!(has(&err, "sync.profileNotListed"), "{err:#}");
        let err = w.pull(&w._dir.path().join("pulled")).unwrap_err();
        assert!(has(&err, "sync.profileNotListed"), "{err:#}");
        assert_eq!(w.fake().log.len(), sent, "nothing was sent or listed");
        assert_eq!(w.count("SELECT count(*) FROM profile_bindings"), 0);
        assert_eq!(unbind_op(&w).4, receipt);
    }

    /// A version 0 binding names no head, and its tombstone omits it.
    #[test]
    fn an_unbind_at_version_zero_omits_the_head() {
        let _w = world();
        let reply = unbind(LOCAL, SERVER, NOW).unwrap();
        let stored = IdempotentStoredResponseV2::parse(&reply).unwrap();
        let done = LocalUnboundV2::parse(&stored.canonical_response_payload_bytes).unwrap();
        assert_eq!(
            (
                done.binding.remote_version,
                done.binding.expected_signed_head_hash
            ),
            (0, None)
        );
    }

    /// Probe 1 crash points: a failure at each write of the unbind, or at
    /// its readback, rolls the whole transaction back. After reopen the
    /// binding is whole, no `UNBIND` is stored, and the unbind then runs once.
    #[test]
    fn an_unbind_cut_off_at_any_write_leaves_the_binding_whole() {
        for trigger in [
            "BEFORE INSERT ON operations BEGIN SELECT RAISE(ABORT, 'crash'); END",
            "BEFORE UPDATE ON operations BEGIN SELECT RAISE(ABORT, 'crash'); END",
            "BEFORE DELETE ON profile_bindings BEGIN SELECT RAISE(ABORT, 'crash'); END",
            // The readback fails after every write is made.
            "AFTER UPDATE OF state ON operations BEGIN
               UPDATE operations SET receipt_sha256 = zeroblob(32) WHERE op_id = NEW.op_id; END",
        ] {
            let w = world();
            let origins = w.count("SELECT count(*) FROM server_origins");
            w.db()
                .conn
                .execute_batch(&format!("CREATE TRIGGER crash {trigger}"))
                .unwrap();
            unbind(LOCAL, SERVER, NOW).unwrap_err();
            w.db().conn.execute_batch("DROP TRIGGER crash").unwrap();
            for (sql, n) in [
                (
                    "SELECT count(*) FROM profile_bindings WHERE local_profile_id = 'local-profile'",
                    1,
                ),
                ("SELECT count(*) FROM operations", 0),
                ("SELECT count(*) FROM server_origins", origins),
            ] {
                assert_eq!(w.count(sql), n, "{trigger}: {sql}");
            }
            let reply = unbind(LOCAL, SERVER, NOW).unwrap();
            assert_eq!(unbind(LOCAL, SERVER, NOW).unwrap(), reply, "{trigger}");
            assert_eq!(w.count("SELECT count(*) FROM operations"), 1, "{trigger}");
        }
    }

    /// L953 `require_no_lease`/`require_no_pending_operation`, and probe 9's
    /// journal: each refuses the unbind, and nothing is stored or deleted.
    #[test]
    fn an_unbind_is_refused_while_a_lease_request_or_journal_is_open() {
        let w = world();
        let err = unbind("never-bound", SERVER, NOW).unwrap_err();
        assert!(has(&err, "sync.unbindNotBound"), "{err:#}");
        w.fake().skip.push("finalize");
        w.push().unwrap_err();
        let unchanged = |w: &World| {
            assert_eq!(w.count("SELECT count(*) FROM profile_bindings"), 1);
            assert_eq!(
                w.count("SELECT count(*) FROM operations WHERE kind = 'UNBIND'"),
                0
            );
        };
        let err = unbind(LOCAL, SERVER, NOW).unwrap_err();
        assert!(has(&err, "sync.unbindLeaseHeld"), "{err:#}");
        unchanged(&w);
        w.db()
            .conn
            .execute(
                "UPDATE profile_bindings SET lease_id = NULL, fencing_token = NULL",
                [],
            )
            .unwrap();
        let err = unbind(LOCAL, SERVER, NOW).unwrap_err();
        assert!(has(&err, "sync.unbindPending"), "{err:#}");
        unchanged(&w);
        for state in ["RUNNING", "AWAITING_RETRY"] {
            w.db()
                .conn
                .execute(
                    "UPDATE operations SET state = ?1 WHERE state NOT IN ('COMPLETED', 'FAILED')",
                    [state],
                )
                .unwrap();
            let err = unbind(LOCAL, SERVER, NOW).unwrap_err();
            assert!(has(&err, "sync.unbindPending"), "{state}: {err:#}");
        }
        w.db()
            .conn
            .execute(
                "UPDATE operations SET state = 'FAILED' WHERE state <> 'COMPLETED'",
                [],
            )
            .unwrap();
        w.db()
            .conn
            .execute(
                "INSERT INTO restore_journals(local_profile_id, journal_id, phase, staged_path,
                   backup_path, old_binding_json, target_version, target_head_hash,
                   created_at, updated_at)
                 VALUES ('local-profile', 'j', 'CREATED', 's', 'b', '{}', 1, zeroblob(32), 'now',
                   'now')",
                [],
            )
            .unwrap();
        unbind(LOCAL, SERVER, NOW).unwrap_err();
        unchanged(&w);
        w.db()
            .conn
            .execute("DELETE FROM restore_journals", [])
            .unwrap();
        unbind(LOCAL, SERVER, NOW).unwrap();
        assert_eq!(w.count("SELECT count(*) FROM profile_bindings"), 0);
    }

    /// ADR 0002 D-7: after delete and reopen, a stored unbind whose columns,
    /// response or receipt no longer recompute from its request is never
    /// returned, even with foreign keys bypassed.
    #[test]
    fn a_tombstone_that_no_longer_recomputes_is_never_returned() {
        let other = format!("'{}'", "99".repeat(16));
        let later = |w: &World| {
            let (.., receipt, _) = unbind_op(w);
            let mut t = LocalBindingTombstoneV2::parse(&receipt).unwrap();
            t.completed_at_ms += 1;
            (t.encode(), sha256(&t.encode()).to_vec())
        };
        for (field, sql) in [
            (
                "exact_receipt_bytes",
                "UPDATE operations SET exact_receipt_bytes = ?1, receipt_sha256 = ?2".to_string(),
            ),
            (
                "exact_receipt_bytes",
                "UPDATE operations SET exact_receipt_bytes = CAST(x'00' || exact_receipt_bytes AS BLOB)"
                    .into(),
            ),
            (
                "receipt_sha256",
                "UPDATE operations SET receipt_sha256 = zeroblob(32)".into(),
            ),
            (
                "exact_response_bytes",
                "UPDATE operations SET exact_response_bytes = CAST(x'00' || exact_response_bytes AS BLOB)"
                    .into(),
            ),
            (
                "exact_response_bytes_sha256",
                "UPDATE operations SET exact_response_bytes_sha256 = zeroblob(32)".into(),
            ),
            (
                "remote_profile_id",
                format!("UPDATE operations SET remote_profile_id = {other}"),
            ),
            (
                "server_instance_id",
                format!("UPDATE operations SET server_instance_id = {other}"),
            ),
            ("restore_epoch", "UPDATE operations SET restore_epoch = 1".into()),
            (
                "exact_request_bytes",
                "UPDATE operations SET exact_request_bytes = CAST(x'00' || exact_request_bytes AS BLOB)"
                    .into(),
            ),
        ] {
            let w = world();
            unbind(LOCAL, SERVER, NOW).unwrap();
            let (receipt, sha) = later(&w);
            let raw = rusqlite::Connection::open(Db::path().unwrap()).unwrap();
            raw.pragma_update(None, "foreign_keys", false).unwrap();
            let n = if sql.contains("?1") {
                raw.execute(&sql, params![receipt, sha])
            } else {
                raw.execute(&sql, [])
            };
            assert_eq!(n.unwrap(), 1, "{sql}");
            drop(raw);
            let err = unbind(LOCAL, SERVER, NOW).unwrap_err();
            assert!(has(&err, "sync.unbindTombstoneMismatch"), "{sql}: {err:#}");
            let named = format!("field={field}]]");
            assert!(format!("{err:#}").contains(&named), "{field}: {err:#}");
        }

        // A response naming another tombstone hash, every hash over it
        // consistent; then the request filed under another local ID.
        let w = world();
        unbind(LOCAL, SERVER, NOW).unwrap();
        let response: Vec<u8> = w
            .db()
            .conn
            .query_row("SELECT exact_response_bytes FROM operations", [], |r| {
                r.get(0)
            })
            .unwrap();
        let mut stored = IdempotentStoredResponseV2::parse(&response).unwrap();
        let mut done = LocalUnboundV2::parse(&stored.canonical_response_payload_bytes).unwrap();
        done.binding_tombstone_sha256 = [0; 32];
        stored.canonical_response_payload_bytes = done.encode();
        let forged = stored.encode();
        let set = "UPDATE operations SET exact_response_bytes = ?1,
                     exact_response_bytes_sha256 = ?2, local_profile_id_at_request = ?3";
        for (bytes, local, field) in [
            (&forged, LOCAL, "binding_tombstone_sha256"),
            (&response, "other", "local_profile_id"),
        ] {
            w.db()
                .conn
                .execute(set, params![bytes, sha256(bytes).to_vec(), local])
                .unwrap();
            let err = unbind(local, SERVER, NOW).unwrap_err();
            let named = format!("field={field}]]");
            assert!(format!("{err:#}").contains(&named), "{field}: {err:#}");
        }
    }

    // ------------------------------------------------- restore epochs ----

    const PROFILE2: [u8; 16] = [0xc2; 16];
    const PROFILE3: [u8; 16] = [0xc3; 16];
    const OTHER_TENANT: [u8; 16] = [0x12; 16];

    fn leaf(profile: [u8; 16], previous: [u8; 32], new: [u8; 32]) -> RestoreEpochLeafV2 {
        RestoreEpochLeafV2 {
            tenant_id: TENANT,
            profile_id: profile,
            previous_signed_head_hash: previous,
            new_signed_head_hash: new,
        }
    }

    /// The `previous -> previous + 1` transition of the sorted `leaves`, as
    /// this device signs it at `NOW`.
    fn transition(
        me: &Me,
        previous: u64,
        leaves: &[RestoreEpochLeafV2],
    ) -> RestoreEpochTransitionV2 {
        let tenant = leaves[0].tenant_id;
        RestoreEpochTransitionV2 {
            transition_replay_id: [0x21; 16],
            server_instance_id: INSTANCE,
            tenant_id: tenant,
            previous_epoch: previous,
            new_epoch: previous + 1,
            mapping_count: leaves.len() as u64,
            profile_head_mapping_root: mapping_root(&tenant, leaves).unwrap(),
            reason_code: RestoreReason::OperatorRestore,
            approver_account_id: me.to.account_id,
            approver_device_id: me.to.device_id,
            approver_signing_key_id: me.to.signing_key_id,
            issued_at_ms: NOW,
            nonce: [0x22; 16],
        }
    }

    /// Where the fake serves `TENANT`'s `previous -> previous + 1` files.
    fn epoch_path(previous: u64) -> String {
        format!("{}/{previous}/{}", hex(&TENANT), previous + 1)
    }

    fn proof_path(previous: u64, profile: &[u8; 16]) -> String {
        format!("{}/proofs/{}", epoch_path(previous), hex(profile))
    }

    fn other(profile: [u8; 16], version: u64, head: [u8; 32]) -> FleetProfileHeadV2 {
        FleetProfileHeadV2 {
            profile_id: profile,
            current_version: version,
            current_signed_head_hash: Some(head),
            key_generation: GEN,
            label_ciphertext: vec![1],
        }
    }

    /// Pushes versions 1 and 2, then restores the fake to version 1 at
    /// epoch 1. Their heads.
    fn restored(w: &World) -> ([u8; 32], [u8; 32]) {
        w.push().unwrap();
        w.push().unwrap();
        let heads = (w.head_of(1), w.head_of(2));
        w.fake().restore(1);
        heads
    }

    impl World {
        fn head_of(&self, version: u64) -> [u8; 32] {
            SignedSnapshotManifestV2::parse(&self.fake().manifests[&version])
                .unwrap()
                .head_hash()
        }

        /// Serves `t`, signed by `sk`, at `TENANT`'s `previous` path, with
        /// the proofs of `prove` out of `leaves`.
        fn file(
            &self,
            sk: &Ed25519SigningKey,
            t: &RestoreEpochTransitionV2,
            leaves: &[RestoreEpochLeafV2],
            prove: &[[u8; 16]],
            previous: u64,
        ) {
            let mut f = self.fake();
            f.epoch_files
                .insert(epoch_path(previous), build_signed_transition(sk, t));
            for p in prove {
                let i = leaves.iter().position(|l| &l.profile_id == p).unwrap();
                let proof = RestoreEpochInclusionProofV2::build(t, leaves, i).unwrap();
                f.epoch_files
                    .insert(proof_path(previous, p), proof.encode());
            }
        }

        /// Binds `local` to `profile`, pinned at `version` and `head`.
        fn bind(&self, local: &str, profile: [u8; 16], version: u64, head: [u8; 32]) {
            self.db()
                .conn
                .execute(
                    "INSERT INTO profile_bindings(local_profile_id, server_instance_id, tenant_id,
                       fleet_id, remote_profile_id, remote_version, last_observed_head_hash,
                       accepted_restore_epoch, sync_state)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, 'AVAILABLE')",
                    params![
                        local,
                        hex(&INSTANCE),
                        hex(&TENANT),
                        hex(&FLEET),
                        hex(&profile),
                        version as i64,
                        head.to_vec()
                    ],
                )
                .unwrap();
        }

        fn pull_of(&self, local: &str, udd: &Path) -> Result<u64> {
            self.rt
                .block_on(pull(&self.client, "t", &self.dev, local, udd, NOW))
        }

        /// `local`'s state, reason, accepted epoch, version and head.
        fn state(&self, local: &str) -> (String, Option<String>, i64, i64, Option<Vec<u8>>) {
            self.db()
                .conn
                .query_row(
                    "SELECT sync_state, last_error_code, accepted_restore_epoch, remote_version,
                       last_observed_head_hash
                     FROM profile_bindings WHERE local_profile_id = ?1",
                    [local],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                )
                .unwrap()
        }

        fn filed(&self) -> i64 {
            self.count("SELECT count(*) FROM restore_epoch_transitions")
                + self.count("SELECT count(*) FROM restore_epoch_binding_proofs")
        }
    }

    /// Probe 7 (L2042), G2-39: after a restore to epoch 1, a pull sees the
    /// epoch, verifies the custodian-signed transition and the binding's own
    /// proof in an n=3 set, files their exact bytes and pins the leaf's new
    /// head at its signed version. Another binding with a leaf moves too,
    /// even after a later commit moved the listed head; one with no leaf
    /// stays quarantined. Reopened, the database holds exactly that, and the
    /// moved binding pushes at the new epoch.
    #[test]
    fn a_verified_transition_moves_only_the_bindings_it_covers() {
        let w = world();
        let (h1, h2) = restored(&w);
        for (local, profile) in [("local-2", PROFILE2), ("local-3", PROFILE3)] {
            w.bind(local, profile, 1, h1);
            w.fake().others.push(other(profile, 1, h1));
        }
        let leaves = [
            leaf(PROFILE, h2, h1),
            leaf(PROFILE3, h1, h1),
            leaf([0xc4; 16], [7; 32], [8; 32]),
        ];
        let t = transition(&w.me, 0, &leaves);
        w.file(&w.me.sk, &t, &leaves, &[PROFILE, PROFILE3], 0);

        let out = w.udd.with_file_name("out");
        assert!(w.pull_of(LOCAL, &out).unwrap() > 0);
        assert_eq!(
            std::fs::read(out.join("Default").join("noise.bin")).unwrap(),
            std::fs::read(w.udd.join("Default").join("noise.bin")).unwrap()
        );
        assert_eq!(w.push().unwrap().version, 2, "a commit at the new epoch");
        let h3 = w.head_of(2);
        w.fake().others[1] = other(PROFILE3, 2, h3);
        // The fake keeps one profile's manifests, so the pull of the head
        // listed above stops at its profile ID; the binding moved first.
        let err = w
            .pull_of("local-3", &w.udd.with_file_name("out3"))
            .unwrap_err();
        assert!(format!("{err:#}").contains("field=profile_id"), "{err:#}");
        let err = w
            .pull_of("local-2", &w.udd.with_file_name("out2"))
            .unwrap_err();
        assert!(has(&err, "sync.epochProofMissing"), "{err:#}");

        let reopened = Db::open().unwrap();
        let (transition, proofs): (Vec<u8>, i64) = reopened
            .conn
            .query_row(
                "SELECT exact_signed_transition_bytes,
                   (SELECT count(*) FROM restore_epoch_binding_proofs)
                 FROM restore_epoch_transitions",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(transition, w.fake().epoch_files[&epoch_path(0)]);
        assert_eq!(proofs, 2);
        for profile in [PROFILE, PROFILE3] {
            let kept: Vec<u8> = reopened
                .conn
                .query_row(
                    "SELECT canonical_inclusion_proof_bytes FROM restore_epoch_binding_proofs
                     WHERE remote_profile_id = ?1",
                    [hex(&profile)],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(kept, w.fake().epoch_files[&proof_path(0, &profile)]);
        }
        assert_eq!(
            w.state(LOCAL),
            ("AVAILABLE".into(), None, 1, 2, Some(h3.to_vec()))
        );
        let (state, _, epoch, version, head) = w.state("local-3");
        assert_eq!(
            (state.as_str(), epoch, version, head),
            ("AVAILABLE", 1, 1, Some(h1.to_vec())),
            "the leaf's head at its own version, not the listed one's"
        );
        let (state, reason, epoch, ..) = w.state("local-2");
        assert_eq!(
            (state.as_str(), reason.as_deref(), epoch),
            ("QUARANTINED", Some("RESTORE_EPOCH_PROOF_MISSING"), 0)
        );
        assert_eq!(
            w.count(
                "SELECT last_restore_epoch FROM server_origins
                 WHERE host = '127.0.0.1'"
            ),
            1
        );
    }

    /// Probe 7, G2-39: a transition or proof that does not verify keeps the
    /// binding quarantined under its named reason and files nothing, and
    /// only a transition not served yet is asked for again: none served, no proof, tampered bytes, a signer the evidence lacks, one
    /// not a custodian when it signed, one distrusted since, another
    /// instance, another epoch step, another tenant's transition or proof,
    /// another profile's proof, a wrong sibling, and a leaf that neither
    /// starts nor ends at the pinned head.
    #[test]
    fn a_transition_that_does_not_verify_keeps_the_binding_quarantined() {
        type Setup = Box<dyn Fn(&World, [u8; 32], [u8; 32])>;
        let invalid = "RESTORE_EPOCH_TRANSITION_INVALID";
        let stranger = Ed25519SigningKey::from_bytes(&[0x33; 32]);
        let plain = |w: &World, t: RestoreEpochTransitionV2, l: &[RestoreEpochLeafV2]| {
            w.file(&w.me.sk, &t, l, &[PROFILE], 0)
        };
        let cases: Vec<(&str, &str, Setup)> = vec![
            (
                TRANSITION_REQUIRED,
                "sync.epochTransitionMissing",
                Box::new(|_, _, _| {}),
            ),
            (
                "RESTORE_EPOCH_PROOF_MISSING",
                "sync.epochProofMissing",
                Box::new(|w, h1, h2| {
                    let l = [leaf(PROFILE, h2, h1)];
                    w.file(&w.me.sk, &transition(&w.me, 0, &l), &l, &[], 0);
                }),
            ),
            (
                invalid,
                "sync.epochTransitionInvalid",
                Box::new(move |w, h1, h2| {
                    let l = [leaf(PROFILE, h2, h1)];
                    plain(w, transition(&w.me, 0, &l), &l);
                    let mut f = w.fake();
                    let bytes = f.epoch_files.get_mut(&epoch_path(0)).unwrap();
                    *bytes.last_mut().unwrap() ^= 1;
                }),
            ),
            (
                invalid,
                "sync.epochTransitionInvalid",
                Box::new(move |w, h1, h2| {
                    let l = [leaf(PROFILE, h2, h1)];
                    let t = RestoreEpochTransitionV2 {
                        approver_signing_key_id: shardx_core::keys::signing_key_id(
                            stranger.verifying_key().as_bytes(),
                        ),
                        ..transition(&w.me, 0, &l)
                    };
                    w.file(&stranger, &t, &l, &[PROFILE], 0);
                }),
            ),
            (
                invalid,
                "sync.epochTransitionInvalid",
                Box::new(move |w, h1, h2| {
                    let l = [leaf(PROFILE, h2, h1)];
                    let t = RestoreEpochTransitionV2 {
                        issued_at_ms: T0 + 400 * DAY,
                        ..transition(&w.me, 0, &l)
                    };
                    plain(w, t, &l);
                }),
            ),
            (
                invalid,
                "sync.epochTransitionInvalid",
                Box::new(move |w, h1, h2| {
                    let l = [leaf(PROFILE, h2, h1)];
                    plain(w, transition(&w.me, 0, &l), &l);
                    ledger::distrust_key(&w.db(), &w.dev.pin.0, &w.me.to.signing_key_id, NOW)
                        .unwrap();
                }),
            ),
            (
                invalid,
                "sync.epochTransitionInvalid",
                Box::new(move |w, h1, h2| {
                    let l = [leaf(PROFILE, h2, h1)];
                    let t = RestoreEpochTransitionV2 {
                        server_instance_id: [0x44; 16],
                        ..transition(&w.me, 0, &l)
                    };
                    plain(w, t, &l);
                }),
            ),
            (
                invalid,
                "sync.epochTransitionInvalid",
                Box::new(move |w, h1, h2| {
                    let l = [leaf(PROFILE, h2, h1)];
                    plain(w, transition(&w.me, 1, &l), &l);
                }),
            ),
            (
                "RESTORE_EPOCH_CROSS_TENANT",
                "sync.epochCrossTenant",
                Box::new(move |w, h1, h2| {
                    let l = [RestoreEpochLeafV2 {
                        tenant_id: OTHER_TENANT,
                        ..leaf(PROFILE, h2, h1)
                    }];
                    plain(w, transition(&w.me, 0, &l), &l);
                }),
            ),
            (
                "RESTORE_EPOCH_CROSS_TENANT",
                "sync.epochCrossTenant",
                Box::new(move |w, h1, h2| {
                    let l = [leaf(PROFILE, h2, h1)];
                    w.file(&w.me.sk, &transition(&w.me, 0, &l), &l, &[], 0);
                    let theirs = [RestoreEpochLeafV2 {
                        tenant_id: OTHER_TENANT,
                        ..leaf(PROFILE, h2, h1)
                    }];
                    let t = transition(&w.me, 0, &theirs);
                    let proof = RestoreEpochInclusionProofV2::build(&t, &theirs, 0).unwrap();
                    w.fake()
                        .epoch_files
                        .insert(proof_path(0, &PROFILE), proof.encode());
                }),
            ),
            (
                invalid,
                "sync.epochTransitionInvalid",
                Box::new(move |w, h1, h2| {
                    let l = [leaf(PROFILE, h2, h1), leaf(PROFILE3, h1, h1)];
                    let t = transition(&w.me, 0, &l);
                    w.file(&w.me.sk, &t, &l, &[], 0);
                    let proof = RestoreEpochInclusionProofV2::build(&t, &l, 1).unwrap();
                    w.fake()
                        .epoch_files
                        .insert(proof_path(0, &PROFILE), proof.encode());
                }),
            ),
            (
                invalid,
                "sync.epochTransitionInvalid",
                Box::new(move |w, h1, h2| {
                    let l = [leaf(PROFILE, h2, h1), leaf(PROFILE3, h1, h1)];
                    let t = transition(&w.me, 0, &l);
                    w.file(&w.me.sk, &t, &l, &[], 0);
                    let mut proof = RestoreEpochInclusionProofV2::build(&t, &l, 0).unwrap();
                    proof.steps[0].1 = Some([0; 32]);
                    w.fake()
                        .epoch_files
                        .insert(proof_path(0, &PROFILE), proof.encode());
                }),
            ),
            (
                invalid,
                "sync.epochTransitionInvalid",
                Box::new(move |w, h1, _| {
                    let l = [leaf(PROFILE, [9; 32], h1)];
                    plain(w, transition(&w.me, 0, &l), &l);
                }),
            ),
        ];
        for (i, (reason, key, setup)) in cases.into_iter().enumerate() {
            let w = world();
            let (h1, h2) = restored(&w);
            setup(&w, h1, h2);
            let out = w.udd.with_file_name("out");
            let checkouts = w.sent("POST", "/checkout").len();
            let err = w.pull(&out).unwrap_err();
            assert!(has(&err, key), "{i}: {err:#}");
            // Only a transition not served yet is asked for again.
            let again = if reason == TRANSITION_REQUIRED {
                key
            } else {
                "sync.bindingQuarantined"
            };
            let err = w.push().unwrap_err();
            assert!(has(&err, again), "{i}: {err:#}");
            let (state, error, epoch, version, _) = w.state(LOCAL);
            assert_eq!(
                (state.as_str(), error.as_deref(), epoch, version),
                ("QUARANTINED", Some(reason), 0, 2),
                "{i}"
            );
            assert_eq!(w.filed(), 0, "{i}: nothing filed");
            assert!(!out.exists(), "{i}");
            assert_eq!(w.sent("POST", "/checkout").len(), checkouts, "{i}");
        }
    }

    /// A binding quarantined for a restore whose server no longer reports
    /// a later epoch has seen it go back: that is a rollback.
    #[test]
    fn a_restore_epoch_that_goes_back_is_a_rollback() {
        let w = world();
        w.push().unwrap();
        w.db()
            .conn
            .execute(
                "UPDATE profile_bindings SET sync_state = 'QUARANTINED', last_error_code = ?1",
                [TRANSITION_REQUIRED],
            )
            .unwrap();
        let err = w.push().unwrap_err();
        assert!(has(&err, "sync.headRollback"), "{err:#}");
        let err = w.push().unwrap_err();
        assert!(has(&err, "sync.bindingQuarantined"), "{err:#}");
        assert_eq!(w.filed(), 0);
    }

    /// Probe 7 crash points: a failure at the proof row, the origin mirror
    /// or the binding row, or a binding row that no longer matches, rolls
    /// the whole acceptance back and leaves the binding quarantined;
    /// reopened, the next push accepts and commits at the new epoch. A
    /// transition filed already is never replaced: another binding served
    /// other bytes for the same epochs stays quarantined.
    #[test]
    fn a_cut_off_acceptance_leaves_the_binding_quarantined_until_reopen() {
        let w = world();
        let (h1, h2) = restored(&w);
        let leaves = [leaf(PROFILE, h2, h1), leaf(PROFILE3, h1, h1)];
        let t = transition(&w.me, 0, &leaves);
        w.file(&w.me.sk, &t, &leaves, &[PROFILE, PROFILE3], 0);
        let out = w.udd.with_file_name("out");
        for (trigger, key) in [
            (
                "AFTER INSERT ON restore_epoch_binding_proofs BEGIN SELECT RAISE(ABORT, 'crash')",
                None,
            ),
            (
                "BEFORE UPDATE ON server_origins BEGIN SELECT RAISE(ABORT, 'crash')",
                None,
            ),
            (
                "BEFORE UPDATE OF accepted_restore_epoch ON profile_bindings
                 BEGIN SELECT RAISE(ABORT, 'crash')",
                None,
            ),
            (
                "BEFORE UPDATE OF accepted_restore_epoch ON profile_bindings
                 BEGIN SELECT RAISE(IGNORE)",
                Some("sync.bindingChanged"),
            ),
        ] {
            w.db()
                .conn
                .execute_batch(&format!("CREATE TRIGGER crash {trigger}; END"))
                .unwrap();
            let err = w.pull(&out).unwrap_err();
            if let Some(key) = key {
                assert!(has(&err, key), "{err:#}");
            }
            w.db().conn.execute_batch("DROP TRIGGER crash").unwrap();
            let (state, reason, epoch, ..) = w.state(LOCAL);
            assert_eq!(
                (state.as_str(), reason.as_deref(), epoch),
                ("QUARANTINED", Some(TRANSITION_REQUIRED), 0),
                "{trigger}"
            );
            assert_eq!(w.filed(), 0, "{trigger}");
            assert!(!out.exists());
        }
        assert_eq!(w.push().unwrap().version, 2);
        assert_eq!(w.state(LOCAL).2, 1);

        w.bind("local-3", PROFILE3, 1, h1);
        w.fake().others.push(other(PROFILE3, 1, h1));
        let original = w.fake().epoch_files[&epoch_path(0)].clone();
        let resigned = RestoreEpochTransitionV2 {
            transition_replay_id: [0x23; 16],
            nonce: [0x24; 16],
            ..t
        };
        w.fake()
            .epoch_files
            .insert(epoch_path(0), build_signed_transition(&w.me.sk, &resigned));
        let out3 = w.udd.with_file_name("out3");
        let err = w.pull_of("local-3", &out3).unwrap_err();
        assert!(has(&err, "sync.epochTransitionInvalid"), "{err:#}");
        assert!(format!("{err:#}").contains("field=readback"), "{err:#}");
        assert_eq!(
            w.state("local-3").1.as_deref(),
            Some("RESTORE_EPOCH_TRANSITION_INVALID")
        );
        // Refused once, it waits for an operator even when the filed bytes
        // are served again.
        w.fake().epoch_files.insert(epoch_path(0), original.clone());
        let err = w.pull_of("local-3", &out3).unwrap_err();
        assert!(has(&err, "sync.bindingQuarantined"), "{err:#}");
        assert_eq!(w.state("local-3").2, 0);
        assert_eq!(w.count("SELECT count(*) FROM restore_epoch_transitions"), 1);
        assert_eq!(
            w.count("SELECT count(*) FROM restore_epoch_binding_proofs"),
            1
        );
    }

    /// Q-34 (ADR 0002 D-1), probe 11: a stored commit, finalize or
    /// create-upload whose reply was lost before a restore rolled it back
    /// is replayed byte for byte and answered as superseded. It ends at
    /// once with a named error, failed, its upload aborted and its lease
    /// dropped; a commit naming a later epoch goes straight to the
    /// transition. The profile on disk is untouched, and the next push
    /// accepts the transition, whose leaf ends at the pinned head, and
    /// commits afresh.
    #[test]
    fn a_superseded_replay_ends_cleanly_and_the_next_push_starts_fresh() {
        for (lost, route, key, quarantined) in [
            ("commit", "/commit", "sync.commitSuperseded", true),
            ("finalize", "/finalize", "sync.uploadSuperseded", false),
            ("upload", "/uploads", "sync.uploadSuperseded", false),
        ] {
            let w = world();
            w.push().unwrap();
            let h1 = w.head_of(1);
            w.fake().lose.push(lost);
            w.push().unwrap_err();
            let live = w.fake().head.unwrap();
            w.fake().restore(1);
            let leaves = [leaf(PROFILE, live, h1)];
            w.file(
                &w.me.sk,
                &transition(&w.me, 0, &leaves),
                &leaves,
                &[PROFILE],
                0,
            );
            let noise = std::fs::read(w.udd.join("Default").join("noise.bin")).unwrap();

            let err = w.push().unwrap_err();
            assert!(has(&err, key), "{route}: {err:#}");
            let sent = w.sent("POST", route);
            assert_eq!(
                sent.len(),
                3,
                "{route}: the first push's, the lost one, its replay"
            );
            assert_eq!(sent[1], sent[2], "{route}: replayed as stored");
            let (state, reason, ..) = w.state(LOCAL);
            assert_eq!(state == "QUARANTINED", quarantined, "{route}");
            if quarantined {
                assert_eq!(reason.as_deref(), Some(TRANSITION_REQUIRED));
            }
            for sql in [
                "SELECT count(*) FROM operations WHERE state = 'PENDING'",
                "SELECT count(*) FROM upload_sessions WHERE state IN ('OPEN', 'READY')",
                "SELECT count(*) FROM profile_bindings WHERE lease_id IS NOT NULL",
            ] {
                assert_eq!(w.count(sql), 0, "{route}: {sql}");
            }

            assert_eq!(w.push().unwrap().version, 2, "{route}");
            assert_eq!(w.state(LOCAL).2, 1, "{route}");
            assert_eq!(w.sent("POST", route).len(), 4, "{route}: a new request");
            assert_eq!(
                std::fs::read(w.udd.join("Default").join("noise.bin")).unwrap(),
                noise
            );
        }
    }

    /// Probe 11 (L2046): a checkout replayed after its stored expiry returns
    /// the original expired lease; it is released, and the new lease is
    /// taken under a new key. A checkout stored before a restore is replayed
    /// only after the listing showed the restore and its transition was
    /// accepted, and is released the same way. A fresh lease is used
    /// whatever its expiry says.
    #[test]
    fn a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key() {
        let w = world();
        {
            let mut f = w.fake();
            f.expires = Some(T0);
            f.lose.push("checkout");
        }
        w.push().unwrap_err();
        assert_eq!(w.push().unwrap().version, 1);
        let checkouts = w.sent("POST", "/checkout");
        assert_eq!(checkouts.len(), 3);
        assert_eq!(checkouts[0], checkouts[1], "the stored request");
        assert_ne!(checkouts[1], checkouts[2], "a new key");
        assert_eq!(w.sent("POST", "/release").len(), 1);
        drop(w);

        let w = world();
        w.push().unwrap();
        let h1 = w.head_of(1);
        w.fake().lose.push("checkout");
        w.push().unwrap_err();
        w.fake().restore(1);
        let leaves = [leaf(PROFILE, h1, h1)];
        w.file(
            &w.me.sk,
            &transition(&w.me, 0, &leaves),
            &leaves,
            &[PROFILE],
            0,
        );
        assert_eq!(w.push().unwrap().version, 2);
        let checkouts = w.sent("POST", "/checkout");
        assert_eq!(checkouts.len(), 4);
        assert_eq!(checkouts[1], checkouts[2], "the stored request");
        assert_ne!(checkouts[2], checkouts[3], "a new key");
        assert_eq!(
            w.count("SELECT count(*) FROM operations WHERE kind = 'CHECKOUT' AND state = 'FAILED'"),
            1
        );
    }

    /// A manifest signed by `sk` over version 1's payload as `edit` changes
    /// it, served as version 1.
    fn forge(
        w: &World,
        sk: &Ed25519SigningKey,
        edit: impl FnOnce(&mut SnapshotManifestV2),
    ) -> [u8; 32] {
        let mut f = w.fake();
        let m = SignedSnapshotManifestV2::parse(&f.manifests[&1]).unwrap();
        let mut p = SnapshotManifestV2::parse(m.canonical_manifest_payload_bytes()).unwrap();
        p.signer_signing_key_id = shardx_core::keys::signing_key_id(sk.verifying_key().as_bytes());
        edit(&mut p);
        let forged = SignedSnapshotManifestV2::sign(sk, &p).unwrap();
        f.manifests.insert(1, forged.exact_bytes().to_vec());
        forged.head_hash()
    }

    impl World {
        fn pull_at(&self, udd: &Path, now: u64) -> Result<u64> {
            self.rt
                .block_on(pull(&self.client, "t", &self.dev, LOCAL, udd, now))
        }
    }

    /// Rule 6 for the head a transition's leaf ends at, the one new head it
    /// lets in (review probe): it is pinned only once its signature verifies
    /// under a key the evidence holds, it names the binding's tenant, fleet,
    /// profile and instance at the version it was found at and an epoch
    /// before the new one, and its signer may commit now. Otherwise the
    /// binding stays quarantined and nothing is filed or pulled.
    #[test]
    fn a_leaf_head_is_accepted_only_as_a_new_head_is() {
        type Edit = Box<dyn Fn(&mut SnapshotManifestV2)>;
        let stranger = Ed25519SigningKey::from_bytes(&[0x33; 32]);
        let cases: Vec<(&str, bool, Edit)> = vec![
            (
                "signer_signing_key_id",
                true,
                Box::new(|p| {
                    p.server_instance_id = [0x44; 16];
                    p.restore_epoch = 99;
                }),
            ),
            ("tenant_id", false, Box::new(|p| p.tenant_id = OTHER_TENANT)),
            ("fleet_id", false, Box::new(|p| p.fleet_id = [0x45; 16])),
            ("profile_id", false, Box::new(|p| p.profile_id = PROFILE3)),
            (
                "server_instance_id",
                false,
                Box::new(|p| p.server_instance_id = [0x44; 16]),
            ),
            (
                "target_version",
                false,
                Box::new(|p| {
                    p.base_version = 4;
                    p.target_version = 5;
                    p.previous_signed_head_hash = Some([0x46; 32]);
                }),
            ),
            ("restore_epoch", false, Box::new(|p| p.restore_epoch = 1)),
            ("signer_signing_key_id", false, Box::new(|_| {})),
        ];
        for (i, (field, by_stranger, edit)) in cases.into_iter().enumerate() {
            let w = world();
            let (_, h2) = restored(&w);
            let sk = if by_stranger { &stranger } else { &w.me.sk };
            let new = forge(&w, sk, edit);
            if i == 7 {
                // Its own manifest, but the signer holds no `profile.commit`.
                let ev = Ev {
                    commit: None,
                    ..Ev::default()
                };
                w.fake().pages = pages(&w.me, &w.grant, &ev)[0].encode();
            }
            let leaves = [leaf(PROFILE, h2, new)];
            w.file(
                &w.me.sk,
                &transition(&w.me, 0, &leaves),
                &leaves,
                &[PROFILE],
                0,
            );
            let out = w.udd.with_file_name("out");
            let err = w.pull(&out).unwrap_err();
            assert!(has(&err, "sync.epochTransitionInvalid"), "{i}: {err:#}");
            assert!(
                format!("{err:#}").contains(&format!("field={field}]]")),
                "{i}: {err:#}"
            );
            let (state, reason, epoch, version, head) = w.state(LOCAL);
            assert_eq!(
                (state.as_str(), reason.as_deref(), epoch, version, head),
                (
                    "QUARANTINED",
                    Some("RESTORE_EPOCH_TRANSITION_INVALID"),
                    0,
                    2,
                    Some(h2.to_vec())
                ),
                "{i}"
            );
            assert_eq!(w.filed(), 0, "{i}");
            assert!(!out.exists(), "{i}");
        }
    }

    /// A pinned head is read back without its signer or epoch checked again,
    /// but only as the binding's own: one naming another instance is not
    /// restored.
    #[test]
    fn a_pinned_head_is_read_back_only_as_the_bindings_own() {
        let w = world();
        w.push().unwrap();
        let me = Ed25519SigningKey::from_bytes(&[1; 32]);
        let forged = forge(&w, &me, |p| p.server_instance_id = [0x44; 16]);
        w.fake().head = Some(forged);
        w.db()
            .conn
            .execute(
                "UPDATE profile_bindings SET last_observed_head_hash = ?1",
                [forged.to_vec()],
            )
            .unwrap();
        let out = w.udd.with_file_name("out");
        let err = w.pull(&out).unwrap_err();
        assert!(
            format!("{err:#}").contains("field=server_instance_id"),
            "{err:#}"
        );
        assert!(!out.exists());
    }

    /// Rule 6's issuer test for the transition signer (review probe, Q-25):
    /// a custodian key this device holds as lapsed signs nothing it accepts,
    /// whatever date it puts on it, and one that is no longer a custodian
    /// when this device first sees the transition does not either, though
    /// it was one when it signed.
    #[test]
    fn a_lapsed_or_former_custodian_signs_no_transition() {
        let w = world();
        let (h1, h2) = restored(&w);
        let held = w
            .db()
            .conn
            .execute(
                "UPDATE trust_custodian_keys
                 SET lapsed_evaluation = (SELECT max(evaluation_id) FROM trust_evaluations),
                     observed_lapsed_at_ms = ?2
                 WHERE signing_key_id = ?1",
                params![hex(&w.me.to.signing_key_id), NOW as i64],
            )
            .unwrap();
        assert_eq!(held, 1);
        let leaves = [leaf(PROFILE, h2, h1)];
        let t = RestoreEpochTransitionV2 {
            issued_at_ms: NOW - 1_000,
            ..transition(&w.me, 0, &leaves)
        };
        w.file(&w.me.sk, &t, &leaves, &[PROFILE], 0);
        let err = w.pull(&w.udd.with_file_name("out")).unwrap_err();
        assert!(has(&err, "sync.epochTransitionInvalid"), "{err:#}");
        assert_eq!(w.state(LOCAL).2, 0);
        assert_eq!(w.filed(), 0);
        drop(w);

        // The custody window ended before now; the leaf keeps the pinned
        // head, so only the signer decides.
        let w = world();
        let (_, h2) = restored(&w);
        let leaves = [leaf(PROFILE, h2, h2)];
        w.file(
            &w.me.sk,
            &transition(&w.me, 0, &leaves),
            &leaves,
            &[PROFILE],
            0,
        );
        let later = T0 + 301 * DAY;
        let err = w.pull_at(&w.udd.with_file_name("out"), later).unwrap_err();
        assert!(has(&err, "sync.epochTransitionInvalid"), "{err:#}");
        assert_eq!(w.state(LOCAL).2, 0);
        assert_eq!(w.filed(), 0);
    }

    /// L1422, L2239 (review probe): once a transition was accepted, the
    /// unbind still succeeds and its retry replays the same reply; the
    /// transition and the proof outlive the binding with every key intact,
    /// and no proof can be filed for a binding that does not exist.
    #[test]
    fn an_unbind_after_an_accepted_transition_keeps_its_evidence() {
        let w = world();
        let (h1, h2) = restored(&w);
        let leaves = [leaf(PROFILE, h2, h1)];
        w.file(
            &w.me.sk,
            &transition(&w.me, 0, &leaves),
            &leaves,
            &[PROFILE],
            0,
        );
        assert!(w.pull(&w.udd.with_file_name("out")).unwrap() > 0);
        assert_eq!(w.filed(), 2);
        let server = w.client.base_url().to_string();
        let reply = unbind(LOCAL, &server, NOW).unwrap();
        assert_eq!(unbind(LOCAL, &server, NOW).unwrap(), reply, "retry replays");
        assert_eq!(w.count("SELECT count(*) FROM profile_bindings"), 0);
        assert_eq!(
            w.count(
                "SELECT count(*) FROM operations WHERE kind = 'UNBIND' AND state = 'COMPLETED'"
            ),
            1
        );
        assert_eq!(w.filed(), 2, "transition and proof outlive the binding");
        assert_eq!(w.count("SELECT count(*) FROM pragma_foreign_key_check"), 0);
        let orphan = w.db().conn.execute(
            "INSERT INTO restore_epoch_binding_proofs
             SELECT server_id, tenant_id, server_instance_id, previous_epoch, new_epoch,
               'ffffffffffffffffffffffffffffffff', previous_signed_head_hash,
               new_signed_head_hash, leaf_index, leaf_count, canonical_leaf_bytes, leaf_hash,
               expected_root, canonical_inclusion_proof_bytes, proof_sha256, verified_at
             FROM restore_epoch_binding_proofs",
            [],
        );
        assert!(orphan.is_err());
    }

    /// The binding moves only as it was read: another writer that changes
    /// its reason, version, head or lease while the transition is being
    /// verified leaves it where that writer put it, and nothing is filed.
    #[test]
    fn a_binding_changed_during_acceptance_is_not_moved() {
        for sql in [
            "UPDATE profile_bindings SET last_error_code = 'HEAD_ROLLBACK_DETECTED'",
            "UPDATE profile_bindings SET remote_version = 1",
            "UPDATE profile_bindings SET last_observed_head_hash = randomblob(32)",
            "UPDATE profile_bindings SET lease_id = 'x', fencing_token = 1",
        ] {
            let w = world();
            let (h1, h2) = restored(&w);
            let leaves = [leaf(PROFILE, h2, h1)];
            w.file(
                &w.me.sk,
                &transition(&w.me, 0, &leaves),
                &leaves,
                &[PROFILE],
                0,
            );
            w.fake().on_proof = Some(sql.into());
            let err = w.pull(&w.udd.with_file_name("out")).unwrap_err();
            assert!(has(&err, "sync.bindingChanged"), "{sql}: {err:#}");
            assert_eq!(w.state(LOCAL).2, 0, "{sql}");
            assert_eq!(w.filed(), 0, "{sql}");
            assert!(w.fake().on_proof.is_none(), "{sql}: it ran");
        }
    }

    /// The leaf's new head is looked for within `LEAF_SEARCH` versions at or
    /// below the pinned one and never past it, however many commits follow
    /// the restore; a pin the leaf keeps is not looked for at all.
    #[test]
    fn the_leaf_head_search_is_bounded_and_skipped_for_an_unchanged_pin() {
        let w = world();
        w.push().unwrap();
        w.push().unwrap();
        let (h1, h2) = (w.head_of(1), w.head_of(2));
        let decoy = w.fake().manifests[&2].clone();
        {
            let mut f = w.fake();
            f.restore(1);
            for v in 2..=LEAF_SEARCH + 1 {
                f.manifests.insert(v, decoy.clone());
            }
            f.listed = Some((LEAF_SEARCH + 1, Some(h2)));
        }
        w.db()
            .conn
            .execute(
                "UPDATE profile_bindings SET remote_version = ?1",
                [(LEAF_SEARCH + 1) as i64],
            )
            .unwrap();
        let leaves = [leaf(PROFILE, h2, h1)];
        w.file(
            &w.me.sk,
            &transition(&w.me, 0, &leaves),
            &leaves,
            &[PROFILE],
            0,
        );
        let err = w.pull(&w.udd.with_file_name("out")).unwrap_err();
        assert!(
            format!("{err:#}").contains("field=new_signed_head_hash"),
            "{err:#}"
        );
        assert_eq!(w.state(LOCAL).2, 0);
        drop(w);

        // More than `LEAF_SEARCH` commits after the restore: the leaf's head,
        // one below the pin, is still found.
        let w = world();
        let (h1, h2) = restored(&w);
        {
            let mut f = w.fake();
            // Signed manifests that are not the leaf's head.
            let m = SignedSnapshotManifestV2::parse(&f.manifests[&1]).unwrap();
            let mut p = SnapshotManifestV2::parse(m.canonical_manifest_payload_bytes()).unwrap();
            p.manifest_replay_id = [0x48; 16];
            let decoy = SignedSnapshotManifestV2::sign(&w.me.sk, &p)
                .unwrap()
                .exact_bytes()
                .to_vec();
            for v in 2..=LEAF_SEARCH + 6 {
                f.manifests.insert(v, decoy.clone());
            }
            f.listed = Some((LEAF_SEARCH + 6, Some([0x47; 32])));
        }
        let leaves = [leaf(PROFILE, h2, h1)];
        w.file(
            &w.me.sk,
            &transition(&w.me, 0, &leaves),
            &leaves,
            &[PROFILE],
            0,
        );
        // The pull then walks the decoys, which do not chain.
        let _ = w.pull(&w.udd.with_file_name("out"));
        let (_, _, epoch, version, head) = w.state(LOCAL);
        assert_eq!((epoch, version, head), (1, 1, Some(h1.to_vec())));
        drop(w);

        let w = world();
        let (_, h2) = restored(&w);
        {
            let mut f = w.fake();
            f.manifests.clear();
            f.listed = Some((2, Some(h2)));
        }
        let leaves = [leaf(PROFILE, h2, h2)];
        w.file(
            &w.me.sk,
            &transition(&w.me, 0, &leaves),
            &leaves,
            &[PROFILE],
            0,
        );
        // The pull then reads the pinned head back, which this fake lost.
        let _ = w.pull(&w.udd.with_file_name("out"));
        let (state, _, epoch, version, head) = w.state(LOCAL);
        assert_eq!(
            (state.as_str(), epoch, version, head),
            ("AVAILABLE", 1, 2, Some(h2.to_vec()))
        );
    }

    /// A lease the binding still holds from before the restore (D-1 released
    /// them all) is released through the stored release, with what is
    /// pending under it, before the binding moves; the push then starts
    /// afresh at the new epoch.
    #[test]
    fn a_lease_from_before_the_restore_is_released_before_the_binding_moves() {
        let w = world();
        w.push().unwrap();
        let h1 = w.head_of(1);
        w.fake().lose.push("upload");
        w.push().unwrap_err();
        w.fake().restore(1);
        let leaves = [leaf(PROFILE, h1, h1)];
        w.file(
            &w.me.sk,
            &transition(&w.me, 0, &leaves),
            &leaves,
            &[PROFILE],
            0,
        );
        w.db()
            .conn
            .execute(
                "UPDATE profile_bindings SET sync_state = 'QUARANTINED', last_error_code = ?1",
                [TRANSITION_REQUIRED],
            )
            .unwrap();
        assert_eq!(w.push().unwrap().version, 2);
        assert_eq!(w.sent("POST", "/release").len(), 1);
        assert_eq!(w.sent("POST", "/uploads").len(), 3, "never replayed");
        assert_eq!(
            w.count("SELECT count(*) FROM operations WHERE kind = 'UPLOAD' AND state = 'FAILED'"),
            1
        );
        assert_eq!(
            w.count("SELECT count(*) FROM operations WHERE state = 'PENDING'"),
            0
        );
        assert_eq!(w.state(LOCAL).2, 1);
    }

    /// Adds custodian `seed` to the evidence the fake serves: approved by
    /// this device under its `device.approve`, and appointed by it once per
    /// `(issued, not_before, not_after)` in `grants`. Its key.
    fn custodian(w: &World, seed: u8, grants: &[(u64, u64, u64)]) -> Ed25519SigningKey {
        let k = Ed25519SigningKey::from_bytes(&[seed; 32]);
        let kid = shardx_core::keys::signing_key_id(k.verifying_key().as_bytes());
        let approval = DeviceApprovalV2 {
            common: common(seed),
            subject_account_id: [seed; 16],
            subject_device_id: [seed + 1; 16],
            subject_signing_key_id: kid,
            subject_hpke_key_id: [seed; 32],
            approval_scope_kind: ApprovalScopeKind::Tenant,
            approval_scope_id: TENANT,
        };
        let approve = TenantCapabilityGrantV2 {
            common: common(seed + 1),
            subject: device_subject(&w.me),
            scope_kind: CapabilityScopeKind::Tenant,
            scope_id: TENANT,
            capability: Capability::DeviceApprove,
        };
        let mut extra = vec![
            build_record(&w.me.sk, DOMAIN_DEVICE_APPROVAL, &approval.encode()),
            build_record(&w.me.sk, DOMAIN_TENANT_CAPABILITY_GRANT, &approve.encode()),
        ];
        for (i, &(issued, nb, na)) in grants.iter().enumerate() {
            let root = TenantRootKeyGrantV2 {
                common: CommonFields {
                    issued_at_ms: issued,
                    not_before_ms: nb,
                    not_after_ms: na,
                    ..common(seed + 2 + i as u8)
                },
                variant: RootGrantVariant::ExistingRootGrant,
                root_key_id: [8; 32],
                root_generation: 0,
                subject_account_id: [seed; 16],
                subject_device_id: [seed + 1; 16],
                subject_signing_key_id: kid,
                recipient_hpke_key_id: [seed; 32],
                subject_device_approval_replay_id: [seed; 16],
                hpke_encapped_key_bytes: [3; 32],
                hpke_wrapped_trk_bytes: [4; 48],
            };
            extra.push(build_record(
                &w.me.sk,
                DOMAIN_TENANT_ROOT_KEY_GRANT,
                &root.encode(),
            ));
        }
        let ev = Ev {
            extra,
            ..Ev::default()
        };
        let mut p = pages(&w.me, &w.grant, &ev);
        p[0].signing_public_keys.push(k.verifying_key().to_bytes());
        w.fake().pages = p[0].encode();
        k
    }

    /// Files the `0 -> 1` transition custodian `seed` signs at `issued`, its
    /// leaf rolling the pinned h2 back to h1.
    fn file_by(
        w: &World,
        k: &Ed25519SigningKey,
        seed: u8,
        issued: u64,
        (h1, h2): ([u8; 32], [u8; 32]),
    ) {
        let leaves = [leaf(PROFILE, h2, h1)];
        let t = RestoreEpochTransitionV2 {
            approver_account_id: [seed; 16],
            approver_device_id: [seed + 1; 16],
            approver_signing_key_id: shardx_core::keys::signing_key_id(
                k.verifying_key().as_bytes(),
            ),
            issued_at_ms: issued,
            ..transition(&w.me, 0, &leaves)
        };
        w.file(k, &t, &leaves, &[PROFILE], 0);
    }

    impl World {
        /// Since when custodian `k` is held lapsed here, if it is.
        fn lapse_of(&self, k: &Ed25519SigningKey) -> Option<i64> {
            let kid = shardx_core::keys::signing_key_id(k.verifying_key().as_bytes());
            self.db()
                .conn
                .query_row(
                    "SELECT observed_lapsed_at_ms FROM trust_custodian_keys
                     WHERE signing_key_id = ?1",
                    [hex(&kid)],
                    |r| r.get(0),
                )
                .optional()
                .unwrap()
                .flatten()
        }
    }

    /// Rule 2 for the transition signer: a second custodian whose custody
    /// starts in ten days signs a transition dated inside it (+20 days);
    /// it was a custodian "when it signed" but is not one now, and holds no
    /// lapse, so only that check refuses it.
    #[test]
    fn a_custodian_not_yet_appointed_signs_no_transition() {
        let w = world();
        let heads = restored(&w);
        let k = custodian(&w, 0x50, &[(T0, NOW + 10 * DAY, NOW + 100 * DAY)]);
        file_by(&w, &k, 0x50, NOW + 20 * DAY, heads);
        let err = w.pull(&w.udd.with_file_name("out")).unwrap_err();
        assert!(has(&err, "sync.epochTransitionInvalid"), "{err:#}");
        assert_eq!(w.lapse_of(&k), None, "only custodian_now can refuse");
        assert_eq!(w.state(LOCAL).2, 0);
        assert_eq!(w.filed(), 0);
    }

    /// Q-26 for the transition signer: a second custodian, current and not
    /// lapsed, signs a transition this device accepts, unless this device
    /// distrusts it.
    #[test]
    fn a_custodian_distrusted_here_signs_no_transition() {
        for distrust in [false, true] {
            let w = world();
            let heads = restored(&w);
            let k = custodian(&w, 0x60, &[(T0, T0, T0 + 300 * DAY)]);
            if distrust {
                let kid = shardx_core::keys::signing_key_id(k.verifying_key().as_bytes());
                ledger::distrust_key(&w.db(), &w.dev.pin.0, &kid, NOW).unwrap();
            }
            file_by(&w, &k, 0x60, NOW, heads);
            let pulled = w.pull(&w.udd.with_file_name("out"));
            assert_eq!(w.lapse_of(&k), None, "{distrust}");
            assert_eq!(w.state(LOCAL).2, i64::from(!distrust), "{distrust}");
            if distrust {
                let err = pulled.unwrap_err();
                assert!(has(&err, "sync.epochTransitionInvalid"), "{err:#}");
            }
        }
    }

    /// A second custodian whose custody ends at NOW + 1 day, seen only while
    /// transitions are being accepted: at NOW, before any is served, and at
    /// NOW + 2 days, when it is held lapsed. Then it is re-appointed from
    /// NOW + 3 days. Its key.
    fn lapsed_then_reappointed(w: &World, seed: u8) -> Ed25519SigningKey {
        let out = w.udd.with_file_name("out");
        let first = (T0, T0, NOW + DAY);
        let k = custodian(w, seed, &[first]);
        let missing = w.pull_at(&out, NOW).unwrap_err();
        assert!(has(&missing, "sync.epochTransitionMissing"), "{missing:#}");
        assert_eq!(w.lapse_of(&k), None);
        let lapse = NOW + 2 * DAY;
        w.pull_at(&out, lapse).unwrap_err();
        assert_eq!(w.lapse_of(&k), Some(lapse as i64), "kept by acceptance");
        let again = NOW + 3 * DAY;
        custodian(w, seed, &[first, (again, again, NOW + 100 * DAY)]);
        k
    }

    /// Q-25: a lapse refuses only what is dated at or before it. A custodian
    /// held lapsed and re-appointed after the lapse signs a transition this
    /// device accepts, and the evaluation accepting it is recorded once,
    /// with it.
    #[test]
    fn a_custodian_reappointed_after_its_lapse_signs_again() {
        let w = world();
        let heads = restored(&w);
        let k = lapsed_then_reappointed(&w, 0x70);
        file_by(&w, &k, 0x70, NOW + 4 * DAY, heads);
        let evaluations = || w.count("SELECT count(*) FROM trust_evaluations");
        let before = evaluations();
        w.pull_at(&w.udd.with_file_name("out"), NOW + 4 * DAY)
            .unwrap();
        assert_eq!(w.state(LOCAL).2, 1);
        assert_eq!(evaluations(), before + 1);
    }

    /// A refused acceptance whose evaluation cannot be recorded leaves no
    /// part of it behind, and still answers with its refusal.
    #[test]
    fn a_failed_record_leaves_no_evaluation_and_keeps_the_refusal() {
        let w = world();
        restored(&w);
        w.db()
            .conn
            .execute_batch(
                "CREATE TRIGGER crash BEFORE INSERT ON trust_custodian_keys
                 BEGIN SELECT RAISE(ABORT, 'crash'); END",
            )
            .unwrap();
        let evaluations = || w.count("SELECT count(*) FROM trust_evaluations");
        let before = evaluations();
        let err = w.pull(&w.udd.with_file_name("out")).unwrap_err();
        assert!(has(&err, "sync.epochTransitionMissing"), "{err:#}");
        assert_eq!(evaluations(), before);
        let (_, reason, epoch, ..) = w.state(LOCAL);
        assert_eq!((reason.as_deref(), epoch), (Some(TRANSITION_REQUIRED), 0));
    }

    /// A lapse observed only while accepting transitions is kept (no fleet
    /// key was collected meanwhile), so a later transition the same key
    /// backdates into its old custody is refused, though it is a custodian
    /// again by then.
    #[test]
    fn a_lapse_seen_while_accepting_refuses_a_backdated_transition() {
        let w = world();
        let heads = restored(&w);
        let k = lapsed_then_reappointed(&w, 0x80);
        file_by(&w, &k, 0x80, NOW + DAY / 2, heads);
        let err = w
            .pull_at(&w.udd.with_file_name("out"), NOW + 4 * DAY)
            .unwrap_err();
        assert!(has(&err, "sync.epochTransitionInvalid"), "{err:#}");
        assert_eq!(w.state(LOCAL).2, 0);
        assert_eq!(w.filed(), 0);
    }

    /// A lease release that fails before the server sees it is retried as
    /// the one stored RELEASE, byte for byte, until it goes through.
    #[test]
    fn a_failed_release_of_an_old_lease_is_retried_as_stored() {
        let w = world();
        w.push().unwrap();
        let h1 = w.head_of(1);
        w.fake().lose.push("upload");
        w.push().unwrap_err();
        {
            let mut f = w.fake();
            f.restore(1);
            f.skip.extend(["release", "release"]);
        }
        let leaves = [leaf(PROFILE, h1, h1)];
        w.file(
            &w.me.sk,
            &transition(&w.me, 0, &leaves),
            &leaves,
            &[PROFILE],
            0,
        );
        w.db()
            .conn
            .execute(
                "UPDATE profile_bindings SET sync_state = 'QUARANTINED', last_error_code = ?1",
                [TRANSITION_REQUIRED],
            )
            .unwrap();
        w.push().unwrap_err();
        w.push().unwrap_err();
        assert_eq!(w.push().unwrap().version, 2);
        let sent = w.sent("POST", "/release");
        assert_eq!(sent.len(), 3);
        assert!(sent.iter().all(|s| *s == sent[0]), "the stored bytes");
        assert_eq!(
            w.count("SELECT count(*) FROM operations WHERE kind = 'RELEASE'"),
            1
        );
        assert_eq!(w.state(LOCAL).2, 1);
    }
}
