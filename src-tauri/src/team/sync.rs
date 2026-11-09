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
    ProfilePublishCreateV2, ProfileRef, ReleaseLeaseV2, ReleaseReason, UnboundBinding,
    UploadCreatedV2, UploadFinalizedV2, RECORD_TYPE_CHECKED_OUT, RECORD_TYPE_LEASE_RELEASED,
    RECORD_TYPE_LOCAL_UNBOUND, RECORD_TYPE_PUBLISH_CREATED, RECORD_TYPE_UPLOAD_CREATED,
    RECORD_TYPE_UPLOAD_FINALIZED,
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
use crate::fleet_custody::{FleetCustodyState, ResealRun};

/// The pilot lease TTL (plan 10.1 L1398 proposes 90 s; uploads renew).
const LEASE_TTL_SECONDS: u32 = 300;
/// How far past `now` plus one TTL a lease expiry the server grants may lie.
// shortcut: a fixed allowance for clock skew between this device and the
// server; make it configurable when a fleet needs a different one.
const LEASE_SKEW_MS: u64 = 60_000;
/// PATCH chunk size; the server takes up to 8 MiB.
#[cfg(not(test))]
const CHUNK: usize = 4 << 20;
#[cfg(test)]
const CHUNK: usize = 64 << 10;
const COMMIT_RECORD: &str = "CommitReceiptBindingV2";
const SIGNER_REVOKED: &str = "SIGNER_REVOKED";

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
    /// The `server_origins` row of the instance.
    server: String,
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
    server: String,
    scope: String,
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
    /// The operation precedes its binding (a publish): `local_profile_id` stays
    /// NULL, as an unbind leaves it, and the binding adopts the row.
    unbound: bool,
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
    if !Db::path()?.try_exists()? {
        return Ok(false);
    }
    is_bound(&Db::open()?.conn, local)
}

/// One binding as `team_profiles_status` reports it. A profile with none is
/// local.
#[derive(Debug, serde::Serialize)]
pub struct ProfileStatus {
    pub profile_id: String,
    pub sync_state: String,
    pub remote_version: i64,
    pub dirty: bool,
    pub lease_expires_at: Option<String>,
    pub last_error_code: Option<String>,
    /// `LEASE_AT_RISK`, or a lease whose expiry has passed.
    pub lease_at_risk: bool,
    /// Any unresolved proven-revoked run: `revert()` re-walks to decide.
    pub revert_available: bool,
    /// A lease held while the binding is quarantined `SIGNER_REVOKED`, which
    /// only `revert()` checks out.
    pub revert_in_progress: bool,
}

/// A `trust_custodian_alerts` row.
#[derive(Debug, serde::Serialize)]
pub struct CustodianAlert {
    pub kind: String,
    pub signing_key_id: String,
    pub raised_at_ms: i64,
}

#[derive(Debug, Default, serde::Serialize)]
pub struct Statuses {
    pub profiles: Vec<ProfileStatus>,
    /// Tenant-wide, newest first.
    pub alerts: Vec<CustodianAlert>,
}

/// A bound profile whose head here is sealed under an older fleet key.
#[derive(Debug, PartialEq, serde::Serialize)]
pub struct OlderKeyProfile {
    pub profile_id: String,
    pub key_generation: u64,
}

/// The bindings of `pin`'s tenant whose pinned or pushed head names a
/// generation below the highest this device verified for its fleet, read
/// from the team database alone. Only a binding with `base_version > 0`
/// counts: its `key_generation` came from that head's manifest (`pin`, a
/// commit), as [`walk`]'s floor does, while a join's version-0 row holds the
/// highest verified generation. A restore transition keeps the previous
/// head's generation until the next pin.
pub(crate) fn under_older_key(pin: &Binding) -> Result<Vec<OlderKeyProfile>> {
    if !Db::path()?.try_exists()? {
        return Ok(Vec::new());
    }
    let db = Db::open()?;
    let rows: Vec<(String, String, i64)> = db
        .conn
        .prepare(
            "SELECT local_profile_id, fleet_id, key_generation FROM profile_bindings
             WHERE server_instance_id = ?1 AND tenant_id = ?2 AND base_version > 0
               AND local_profile_id NOT GLOB 'reseal:*'
             ORDER BY local_profile_id",
        )?
        .query_map(
            params![hex(&pin.server_instance_id), hex(&pin.tenant_id)],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?
        .collect::<rusqlite::Result<_>>()?;
    let mut out = Vec::new();
    for (profile_id, fleet, generation) in rows {
        let fleet = decode_hex16(&fleet, "fleet_id")?;
        let generation = generation as u64;
        if ledger::highest_generation(&db, pin, &fleet)?.is_some_and(|h| generation < h) {
            out.push(OlderKeyProfile {
                profile_id,
                key_generation: generation,
            });
        }
    }
    Ok(out)
}

/// Every binding's state and every custodian alert, read from the team
/// database alone: no network, and no pending revert swap is settled here
/// (one shows as the pinned head, `AVAILABLE`). No team database means none.
pub(crate) fn statuses(now: u64) -> Result<Statuses> {
    if !Db::path()?.try_exists()? {
        return Ok(Statuses::default());
    }
    let db = Db::open()?;
    let profiles = db
        .conn
        .prepare(
            "SELECT b.local_profile_id, b.sync_state, b.remote_version, b.dirty,
               b.lease_expires_at, b.last_error_code,
               b.sync_state = 'LEASE_AT_RISK' OR (b.lease_expires_at IS NOT NULL
                 AND b.lease_expires_at < strftime('%Y-%m-%dT%H:%M:%fZ', ?1 / 1000.0, 'unixepoch')),
               EXISTS (SELECT 1 FROM skipped_heads s
                 WHERE s.server_instance_id = b.server_instance_id AND s.tenant_id = b.tenant_id
                   AND s.remote_profile_id = b.remote_profile_id AND s.resolution IS NULL),
               b.lease_id IS NOT NULL AND b.last_error_code IS 'SIGNER_REVOKED'
             FROM profile_bindings b WHERE b.local_profile_id NOT GLOB 'reseal:*'
             ORDER BY b.local_profile_id",
        )?
        .query_map([wire(now)?], |r| {
            Ok(ProfileStatus {
                profile_id: r.get(0)?,
                sync_state: r.get(1)?,
                remote_version: r.get(2)?,
                dirty: r.get(3)?,
                lease_expires_at: r.get(4)?,
                last_error_code: r.get(5)?,
                lease_at_risk: r.get(6)?,
                revert_available: r.get(7)?,
                revert_in_progress: r.get(8)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    let alerts = db
        .conn
        .prepare(
            "SELECT kind, signing_key_id, raised_at_ms FROM trust_custodian_alerts
             ORDER BY raised_at_ms DESC, signing_key_id",
        )?
        .query_map([], |r| {
            Ok(CustodianAlert {
                kind: r.get(0)?,
                signing_key_id: r.get(1)?,
                raised_at_ms: r.get(2)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok(Statuses { profiles, alerts })
}

fn bound(db: &Db, local: &str) -> Result<Bound> {
    let row = db
        .conn
        .query_row(
            "SELECT server_instance_id, tenant_id, fleet_id, remote_profile_id, remote_version,
                    last_observed_head_hash, accepted_restore_epoch, lease_id, fencing_token,
                    sync_state, last_error_code, server_id
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
                    r.get::<_, String>(11)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| anyhow!(code("sync.profileNotListed")))?;
    let (
        [instance, tenant, fleet, profile],
        version,
        head,
        epoch,
        lease_id,
        fence,
        state,
        error,
        server,
    ) = row;
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
        server,
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

/// Rule 6, "Revoked signer": quarantines `b` with `SIGNER_REVOKED`.
fn signer_revoked(db: &Db, b: &Bound) -> anyhow::Error {
    let err = anyhow!(code("sync.signerRevoked"));
    quarantine(db, &b.local, SIGNER_REVOKED, err)
}

/// `err` for a head [`walk`] refuses; once the walk met a proven-revoked
/// head, [`signer_revoked`] instead, as that head alone did before the revert
/// rule. No audit row either way.
fn refused_in_walk(db: &Db, b: &Bound, w: &Walked, err: anyhow::Error) -> anyhow::Error {
    if w.open.is_empty() && w.accepted.is_empty() {
        err
    } else {
        signer_revoked(db, b)
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
    signed_manifest_container_bytes_sha256, exact_receipt_bytes, server_id, operation_scope";

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
        server: r.get(22)?,
        scope: r.get(23)?,
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
        "INSERT INTO operations(op_id, local_profile_id, local_profile_id_at_request, server_id,
           server_instance_id, restore_epoch, tenant_id, fleet_id, remote_profile_id,
           snapshot_id, manifest_replay_id, operation_scope, kind, idempotency_key,
           canonical_request_hash, exact_request_bytes, exact_request_bytes_sha256,
           remote_upload_id, lease_id, fencing_token, base_version, intent_hash,
           ciphertext_sha256, signed_manifest_container_bytes, signed_manifest_container_hash,
           signed_manifest_container_bytes_sha256, state, created_at, updated_at)
         VALUES (?1, ?25, ?2, ?26, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
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
            (!c.unbound).then_some(&b.local),
            b.server,
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
        "PUBLISH" => OperationKind::ProfilePublishCreate,
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
            OperationKind::ProfilePublishCreate => {
                let ok = ProfilePublishCreateV2::parse(p)
                    .is_ok_and(|c| text(&op.remote_profile, &c.profile.profile_id));
                checks.push(("remote_profile_id", ok));
            }
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
            ("upload.server_id", s.server == op.server),
            ("upload.operation_scope", s.scope == op.scope),
            ("upload.idempotency_key", s.key == op.key),
            ("upload.canonical_request_hash", s.canonical == op.canonical),
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
    let filed: i64 = db.conn.query_row(
        "SELECT count(*) FROM server_origins WHERE server_id = ?1 AND server_instance_id = ?2",
        [&op.server, &op.instance],
        |r| r.get(0),
    )?;
    checks.push(("server_id", filed == 1));
    Ok(checks.into_iter().find(|(_, ok)| !ok).map(|(f, _)| f))
}

/// `op`'s exact stored bytes, once its columns still match them; otherwise
/// the binding is quarantined and nothing is sent.
fn stored<'a>(db: &Db, b: &Bound, op: &'a Op) -> Result<&'a [u8]> {
    stored_for(db, &b.local, op)
}

/// [`stored`] for the profile `local`, whose binding may not exist yet.
fn stored_for<'a>(db: &Db, local: &str, op: &'a Op) -> Result<&'a [u8]> {
    if let Some(field) = first_drift(db, op)? {
        let _ = db.conn.execute(
            "UPDATE operations SET state = 'QUARANTINED' WHERE op_id = ?1",
            [&op.op_id],
        );
        return Err(quarantine(
            db,
            local,
            "STORED_REQUEST_MISMATCH",
            anyhow!(code_with("sync.storedRequestMismatch", &[("field", field)])),
        ));
    }
    Ok(&op.exact)
}

/// A reply to a stored request: the body on success. A refusal fails the
/// operation, so it is never resent; anything else (a lost reply, 401, 408,
/// 429, 5xx) leaves it PENDING for the next attempt to resend as it is.
fn settle(
    client: &FleetClient,
    access: &str,
    db: &Db,
    op: &Op,
    reply: Exact,
) -> Result<std::result::Result<Vec<u8>, anyhow::Error>> {
    if (200..300).contains(&reply.status) {
        return Ok(Ok(reply.body));
    }
    let err = refused(client, access, &reply);
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

/// Whether a lease expiry the server granted is plausible at `now`: still
/// ahead, and no further than one TTL and the skew allowance.
fn lease_expiry_ok(expires_at_ms: u64, now: u64) -> bool {
    expires_at_ms > now
        && expires_at_ms <= now + u64::from(LEASE_TTL_SECONDS) * 1000 + LEASE_SKEW_MS
}

/// `access`, the bearer every sync request sends, is hidden should the
/// server or a proxy echo it, as is any token marker and every password
/// `client` logged in with.
fn refused(client: &FleetClient, access: &str, reply: &Exact) -> anyhow::Error {
    if reply.status == 401 {
        return anyhow!(code("sync.authRequired"));
    }
    // A request under a generation a rotation retired: Collect fetches N+1.
    if reply.status == 409 && refusal_of(reply).0.as_deref() == Some("FLEET_GENERATION_NOT_ACTIVE")
    {
        return anyhow!(code("sync.fleetKeyRotated"));
    }
    let detail: String = client
        .hide(&String::from_utf8_lossy(&reply.body), &[access])
        .chars()
        .take(300)
        .collect();
    anyhow!(code_with(
        "fleet.refusedSync",
        &[("status", &reply.status.to_string()), ("detail", &detail)]
    ))
}

/// A reply that is not a stored request's: success or an error.
fn ok(client: &FleetClient, access: &str, reply: Exact) -> Result<Exact> {
    if (200..300).contains(&reply.status) {
        Ok(reply)
    } else {
        Err(refused(client, access, &reply))
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
fn complete(conn: &rusqlite::Connection, op: &Op, record_type: &str, body: &[u8]) -> Result<usize> {
    let receipt = matches!(op.kind.as_str(), "COMMIT" | "RELEASE");
    Ok(conn.execute(
        "UPDATE operations SET state = 'COMPLETED', response_record_type = ?2,
           exact_response_bytes = ?3, exact_response_bytes_sha256 = ?4,
           exact_receipt_bytes = CASE WHEN ?5 THEN ?3 END,
           receipt_sha256 = CASE WHEN ?5 THEN ?4 END,
           updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
         WHERE op_id = ?1 AND state = 'PENDING'",
        params![op.op_id, record_type, body, sha256(body).to_vec(), receipt],
    )?)
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
    server: String,
    scope: String,
    key: String,
    canonical: Vec<u8>,
}

fn session(db: &Db, commit_op: &str) -> Result<Session> {
    Ok(db.conn.query_row(
        "SELECT upload_local_id, server_instance_id, restore_epoch, remote_upload_id, snapshot_id,
                manifest_replay_id, intent_hash, preamble_sha256, dek_slot_sha256, fkek_key_id,
                key_generation, expected_ciphertext_sha256, expected_ciphertext_size, spool_ref,
                state, server_id, operation_scope, idempotency_key, canonical_request_hash
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
                server: r.get(15)?,
                scope: r.get(16)?,
                key: r.get(17)?,
                canonical: r.get(18)?,
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
    let mut found = None;
    let epoch = fleet_pages(client, access, b, |p| {
        if p.profile_id == b.profile {
            found = Some(p.clone());
        }
        found.is_none()
    })
    .await?;
    Ok((epoch, found))
}

/// The server's restore epoch, from the fleet listing pages of `b`'s fleet,
/// handing each listed profile to `more` until it returns `false`. Every
/// page names `b`'s instance, tenant and fleet, at one epoch.
async fn fleet_pages(
    client: &FleetClient,
    access: &str,
    b: &Bound,
    mut more: impl FnMut(&FleetProfileHeadV2) -> bool,
) -> Result<u64> {
    let mut after: Option<[u8; 16]> = None;
    let mut epoch = None;
    loop {
        let reply = ok(
            client,
            access,
            client
                .list_fleet_profiles(access, &b.fleet, after.as_ref())
                .await?,
        )?;
        let page = FleetProfilePageV2::parse(&reply.body).map_err(|_| bad("FleetProfilePageV2"))?;
        if (page.server_instance_id, page.tenant_id, page.fleet_id)
            != (b.instance, b.tenant, b.fleet)
        {
            return Err(bad("server_instance_id"));
        }
        if *epoch.get_or_insert(page.restore_epoch) != page.restore_epoch {
            return Err(bad("restore_epoch"));
        }
        if !page.profiles.iter().all(&mut more) {
            return Ok(page.restore_epoch);
        }
        match page.next_after {
            Some(a) if after.is_none_or(|x| a > x) => after = Some(a),
            Some(_) => return Err(bad("next_after")),
            None => return Ok(page.restore_epoch),
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
/// How many heads above the leaf a binding with no pin follows back. Each
/// one is verified, so this only stops a server that lists an endless chain
/// from holding the pull forever.
const LEAF_WALK: u64 = 1 << 20;

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
                None => get_op(
                    db,
                    &release_op(&db.conn, b, lease, ReleaseReason::UserRelease)?,
                )?,
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
    // shortcut: no `signer` is named here, so a leaf head signed by a device
    // that is no root grant subject is refused, fail-closed, as
    // RESTORE_EPOCH_TRANSITION_INVALID; name the leaf's signer when restore
    // transitions come into scope after the v0.2.2a slice.
    let (pages, closure) =
        ledger::closure_evidence(client, access, &hex(&b.tenant), db, &dev.pin, &[], now).await?;
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
                        let body = ok(client, access, reply)?.body;
                        verify_transition(db, dev, b, chain, &keys, epochs, &body, now)
                    }
                };
                let checked = match checked {
                    Ok(t) => {
                        let reply = get(Some(&b.profile)).await?;
                        match reply.status {
                            404 => Err(refusal("RESTORE_EPOCH_PROOF_MISSING", "")),
                            _ => {
                                let body = ok(client, access, reply)?.body;
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
            // versions at or below the pinned one (a restore only goes back) or,
            // with no pin, on the chain below the listed head, and
            // accepted as a new head is (rule 6) except for its earlier epoch.
            let (version, signer) = if head == b.head {
                (b.version, None)
            } else {
                let missing =
                    || refusal("RESTORE_EPOCH_TRANSITION_INVALID", "new_signed_head_hash");
                let found = match b.head {
                    Some(_) => {
                        let top = b.version.min(listed.current_version);
                        let low = top.saturating_sub(LEAF_SEARCH - 1).max(1);
                        let mut found = None;
                        for v in (low..=top).rev() {
                            let reply = ok(
                                client,
                                access,
                                client.snapshot_manifest(access, &b.profile, v).await?,
                            )?;
                            let m = SignedSnapshotManifestV2::parse(&reply.body)
                                .map_err(|_| bad("SignedSnapshotManifestV2"))?;
                            if Some(m.head_hash()) == head {
                                found = Some((v, m));
                                break;
                            }
                        }
                        found.ok_or_else(missing)
                    }
                    // No pin (a binding that joined at version 0): back from the
                    // listed head along the chain to the leaf, each head above it
                    // verified ([`above_leaf`]), so no bound is needed.
                    None => {
                        let (mut v, mut next) =
                            (listed.current_version, listed.current_signed_head_hash);
                        loop {
                            if v == 0 || listed.current_version - v >= LEAF_WALK {
                                break Err(missing());
                            }
                            let m = manifest(client, access, b, v).await?;
                            if Some(m.head_hash()) != next {
                                break Err(refusal(
                                    "RESTORE_EPOCH_TRANSITION_INVALID",
                                    "previous_signed_head_hash",
                                ));
                            }
                            if next == head {
                                break Ok((v, m));
                            }
                            match above_leaf(b, &keys, m, (v, epoch)) {
                                Ok(previous) => (v, next) = (v - 1, previous),
                                Err(r) => break Err(r),
                            }
                        }
                    }
                };
                let checked = found.and_then(|(v, m)| {
                    let signer = *m.signer_signing_key_id();
                    verify_leaf_head(db, dev, b, chain, &keys, m, (v, epoch), now)
                        .map(|()| (v, Some(signer)))
                });
                match checked {
                    Ok(v) => v,
                    Err((reason, err)) => return Err(quarantine(db, &b.local, reason, err)),
                }
            };
            Ok::<_, anyhow::Error>((steps, version, head, signer))
        }
    }
    .await;
    let refused = match accepted.and_then(|(steps, version, head, signer)| {
        // Rule 6: the leaf's signer is judged again right before its pin,
        // against the revocations this same evaluation counts.
        let record = |tx: &rusqlite::Connection| -> Result<bool> {
            if let Some((seen, c)) = &evaluated {
                ledger::record_in(tx, &dev.pin.0, seen, c, None, closure, now)?;
            }
            match signer {
                Some(s) => Ok(!ledger::withdrawn_in(tx, &dev.pin.0, &s)?),
                None => Ok(true),
            }
        };
        let url = client.base_url();
        store_transitions(db, url, b, &steps, (epoch, version, head), record, now)
    }) {
        Ok(None) => return Ok(()),
        Ok(Some(field)) => {
            let (reason, err) = refusal("RESTORE_EPOCH_TRANSITION_INVALID", field);
            quarantine(db, &b.local, reason, err)
        }
        Err(e) => e,
    };
    // In its own transaction, and never in place of the refusal: a record
    // that fails leaves nothing behind, and the next evaluation records.
    if let Some((seen, c)) = &evaluated {
        if let Err(e) = ledger::record(db, &dev.pin.0, seen, c, None, closure, now) {
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
    // A transition is first seen with this evaluation, so only revocations
    // already held apply to its approver (rule 6 "Order"); the leaf, a head,
    // is judged on acceptance, re-checked after `record_in` counts.
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

/// A head above the leaf that a binding with no pin follows back to: its
/// signature verifies under a key the evidence holds, it names `b`'s tenant,
/// fleet, profile and instance at `version`, and it was committed at the new
/// `epoch` (an older one, as the leaf's rolled-back child, is a rollback).
/// Its previous head. Its signer is judged by the pull's walk over it.
fn above_leaf(
    b: &Bound,
    keys: &std::collections::BTreeMap<[u8; 32], [u8; 32]>,
    m: SignedSnapshotManifestV2,
    (version, epoch): (u64, u64),
) -> std::result::Result<Option<[u8; 32]>, Refused> {
    let invalid = |field| refusal("RESTORE_EPOCH_TRANSITION_INVALID", field);
    let pk = keys
        .get(m.signer_signing_key_id())
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
        (
            "target_version",
            p.target_version == version && p.base_version + 1 == version,
        ),
    ];
    if let Some((field, _)) = checks.iter().find(|(_, ok)| !ok) {
        return Err(invalid(field));
    }
    if p.restore_epoch < epoch {
        return Err(("HEAD_ROLLBACK_DETECTED", anyhow!(code("sync.headRollback"))));
    }
    if p.restore_epoch != epoch {
        return Err(invalid("restore_epoch"));
    }
    Ok(p.previous_signed_head_hash)
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
    // No head yet (a device that joined at version 0) takes its leaf as its
    // first head: ADR 0002 rule 6 extends the leaf exception to a new device.
    if head.is_some_and(|h| h != leaf.previous_signed_head_hash && h != leaf.new_signed_head_hash) {
        return Err(invalid("previous_signed_head_hash"));
    }
    Ok((proof, body))
}

/// Files `steps` exactly (L1967-L2029), or finds them filed with the same
/// bytes, then reads them back and moves `b` to `epoch` at `version` and
/// `head`, superseding its open skip audit rows, in one transaction, once
/// `record` keeps the leaf's signer standing. The field refused, and nothing
/// stored, when what is filed differs or `record` refuses that signer.
fn store_transitions(
    db: &mut Db,
    server_url: &str,
    b: &Bound,
    steps: &[Step],
    (epoch, version, head): (u64, u64, Option<[u8; 32]>),
    record: impl FnOnce(&rusqlite::Connection) -> Result<bool>,
    now: u64,
) -> Result<Option<&'static str>> {
    // Immediate: this one reads before it writes, and a deferred transaction
    // that must upgrade while another handle commits is refused at once
    // ("database is locked") instead of waiting out the busy timeout.
    let tx = db
        .conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
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
            return Ok(Some("readback"));
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
    supersede(&tx, b, None, now)?;
    if !record(&tx)? {
        return Ok(Some("signer_signing_key_id"));
    }
    tx.commit()?;
    Ok(None)
}

/// The FKEK of `generation` naming `fkek_key_id` (any, for `None`), from a grant that
/// reverifies now (G2-35, Q-25, Q-26). A generation below the highest this
/// device verified is refused ("Fleet generation freshness"). Never a
/// passphrase.
fn verified_key(
    db: &Db,
    dev: &Device,
    fleet: &[u8; 16],
    generation: u64,
    fkek_key_id: Option<&[u8; 32]>,
    now: u64,
) -> Result<Zeroizing<[u8; 32]>> {
    if ledger::highest_generation(db, &dev.pin.0, fleet)?.is_some_and(|h| generation < h) {
        return Err(anyhow!(code("sync.noVerifiedFleetKey")));
    }
    readable_key(db, dev, fleet, generation, fkek_key_id, now)
}

/// Whether this device holds the key a publish would seal under, and Q-18
/// lets it seal: [`verified_key_blocked`] is `Some(false)`, as `has_fleet_key`
/// reads it (`team_config::status`).
#[cfg(test)]
pub(crate) fn holds_verified_key(dev: &Device, fleet: &[u8; 16], now: u64) -> Result<bool> {
    Ok(verified_key_blocked(dev, fleet, now)? == Some(false))
}

/// `None` unless this device holds the key a publish would seal under: the
/// highest generation it verified, from a grant that reverifies now
/// ([`verified_key`]). A key cached by 2.4.2, never verified, does not count.
/// Else whether Q-18 blocks sealing under it, as push checks it.
pub(crate) fn verified_key_blocked(
    dev: &Device,
    fleet: &[u8; 16],
    now: u64,
) -> Result<Option<bool>> {
    let db = Db::open()?;
    let Some(generation) = ledger::highest_generation(&db, &dev.pin.0, fleet)? else {
        return Ok(None);
    };
    if verified_key(&db, dev, fleet, generation, None, now).is_err() {
        return Ok(None);
    }
    Ok(Some(ledger::commit_blocked(
        &db, &dev.pin.0, &dev.pin.1, fleet, generation,
    )?))
}

/// [`verified_key`] without "Fleet generation freshness", for every restore:
/// a head may be of a generation a rotation since replaced (lazy re-seal,
/// ADR 0002 amendment of 2026-11-08), as may rule 6's anchor `P`, past the
/// pin (owner decision B) or what a revert seals again under the lease's
/// generation. Its grant still reverifies now (Q-26 drops a withdrawn
/// issuer's). Never for sealing; [`walk`]'s generation floor keeps a trusted
/// chain from going back. A fleet listing's labels ([`labels`]) are opened
/// through it too. No usable key for a generation below the highest this
/// device verified is `sync.headUnderRetiredKey`.
fn readable_key(
    db: &Db,
    dev: &Device,
    fleet: &[u8; 16],
    generation: u64,
    fkek_key_id: Option<&[u8; 32]>,
    now: u64,
) -> Result<Zeroizing<[u8; 32]>> {
    let none = || anyhow!(code("sync.noVerifiedFleetKey"));
    let store = crate::fleet_keys::load()?;
    store
        .keys_newest_first(&hex(fleet), |_, _| true)
        .into_iter()
        .find(|(k, g)| {
            *g == generation
                && fkek_key_id.is_none_or(|id| shardx_core::fleet_grants::fkek_key_id(k) == *id)
                && crate::fleet_key_verifies(db, &dev.pin, &dev.me, fleet, *g, k, now)
                    .unwrap_or(false)
        })
        .map(|(k, _)| Zeroizing::new(k))
        .ok_or_else(|| {
            if crate::fleet_key_needs_recollect(db, &dev.pin, fleet, generation) {
                anyhow!(code("sync.fleetKeyRecollect"))
            // A ledger error only picks the code: the read is refused either way.
            } else if matches!(
                ledger::highest_generation(db, &dev.pin.0, fleet),
                Ok(Some(h)) if generation < h
            ) {
                anyhow!(code("sync.headUnderRetiredKey"))
            } else {
                none()
            }
        })
}

// ---------------------------------------------------------------- push ----

/// Pushes the published profile `local` from `udd`, resuming whatever
/// operation an earlier attempt left (plan L1137-L1215). `clock` is the time
/// since the push began, which decides when the lease is renewed.
pub(crate) async fn push(
    client: &FleetClient,
    access: &str,
    dev: &Device,
    local: &str,
    udd: &Path,
    now: u64,
    clock: &(dyn Fn() -> std::time::Duration + Sync),
) -> Result<Pushed> {
    settle_revert_swap(local, udd)?;
    push_inner(
        client,
        access,
        dev,
        local,
        Plain::Folder(udd),
        now,
        clock,
        None,
    )
    .await
}

/// Whether the signer of `b`'s pinned head is proven revoked (rule 6): a
/// commit on top of it is a revert, never an ordinary push. The manifest is
/// read only once this tenant holds any proven revocation.
async fn pin_withdrawn(
    client: &FleetClient,
    access: &str,
    db: &mut Db,
    dev: &Device,
    b: &Bound,
) -> Result<bool> {
    let any: bool = db.conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM trust_proven_revocations
           WHERE server_instance_id = ?1 AND tenant_id = ?2)",
        params![
            hex(&dev.pin.0.server_instance_id),
            hex(&dev.pin.0.tenant_id)
        ],
        |r| r.get(0),
    )?;
    if b.version == 0 || !any {
        return Ok(false);
    }
    let m = manifest(client, access, b, b.version).await?;
    if Some(m.head_hash()) != b.head {
        return Err(bad("current_signed_head_hash"));
    }
    ledger::withdrawn(db, &dev.pin.0, m.signer_signing_key_id())
}

/// Rule 6: whether the signer of a revert's `P` is now withdrawn, `P` being
/// the anchor the walk filed with the lowest open audit row of `b`'s run,
/// so a resumed upload is judged by the `P` it was sealed from. Without such
/// a row nothing names that `P`, so it counts as withdrawn and the next
/// revert walks again.
async fn source_withdrawn(
    client: &FleetClient,
    access: &str,
    db: &mut Db,
    dev: &Device,
    b: &Bound,
) -> Result<bool> {
    let anchor: Option<(i64, Option<Vec<u8>>)> = db
        .conn
        .query_row(
            "SELECT anchor_version, anchor_head_hash FROM skipped_heads
             WHERE server_instance_id = ?1 AND tenant_id = ?2 AND remote_profile_id = ?3
               AND resolution IS NULL
             ORDER BY target_version LIMIT 1",
            params![hex(&b.instance), hex(&b.tenant), hex(&b.profile)],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((v, Some(head))) = anchor else {
        return Ok(true);
    };
    let m = manifest(client, access, b, v as u64).await?;
    if m.head_hash().as_slice() != head.as_slice() {
        return Err(bad("anchor_head_hash"));
    }
    ledger::withdrawn(db, &dev.pin.0, m.signer_signing_key_id())
}

/// What a seal packs: a profile folder, or the plaintext of a head opened
/// from its ciphertext ([`opened`]), which needs no folder (v2.10 re-seal).
#[derive(Clone, Copy)]
enum Plain<'a> {
    Folder(&'a Path),
    Opened(&'a [u8]),
}

/// [`push`], or with `revert` the commit of `R` on that base (`Jn`'s version
/// and head) from the staged `P` in `src`: only then may a `SIGNER_REVOKED`
/// quarantine check out, and only then is a revert lease continued.
#[allow(clippy::too_many_arguments)]
async fn push_inner(
    client: &FleetClient,
    access: &str,
    dev: &Device,
    local: &str,
    src: Plain<'_>,
    now: u64,
    clock: &(dyn Fn() -> std::time::Duration + Sync),
    revert: Option<(u64, [u8; 32])>,
) -> Result<Pushed> {
    let mut db = Db::open()?;
    retry_unbound_releases(client, access, &mut db).await;
    loop {
        let mut b = bound(&db, local)?;
        if awaits_transition(&b) {
            accept_transitions(client, access, dev, &mut db, &b, now).await?;
            continue;
        }
        let revoked = b.error.as_deref() == Some(SIGNER_REVOKED);
        if revert.is_none() || !revoked {
            refuse_quarantined(&b)?;
        }
        // A revert lease: any lease held under `SIGNER_REVOKED`. Only
        // `revert` continues it, a lost release of it included.
        if revert.is_none() && revoked && b.lease.is_some() {
            bail!(code("sync.revertInProgress"));
        }
        if let Some((version, head)) = revert {
            b.version = version;
            b.head = Some(head);
            if let Some(l) = b.lease.as_mut() {
                l.base_version = version;
            }
        }
        // G2-34: a release whose reply was lost is replayed first.
        if let Some(op) = find(&db, local, "RELEASE", None, Some("PENDING"))? {
            release_reply(client, access, &mut db, &b, &op).await?;
            continue;
        }
        let Some(lease) = b.lease else {
            if revert.is_none() && pin_withdrawn(client, access, &mut db, dev, &b).await? {
                return Err(signer_revoked(&db, &b));
            }
            // Q-18: refused before checkout, under the highest generation
            // this device verified; the checkout re-checks the one it names.
            if let Some(g) = ledger::highest_generation(&db, &dev.pin.0, &b.fleet)? {
                if ledger::commit_blocked(&db, &dev.pin.0, &dev.pin.1, &b.fleet, g)? {
                    mark_blocked(&db, local, false)?;
                    bail!(code("sync.commitBlockedCompromised"));
                }
            }
            // Q-18 "Release": the block no longer holds, so its code goes.
            db.conn.execute(
                "UPDATE profile_bindings SET last_error_code = NULL
                 WHERE local_profile_id = ?1 AND last_error_code = ?2",
                params![local, COMPROMISED],
            )?;
            // Only a transition moves the pin and not `base_version`, which a
            // restore or a commit sets: a joined binding whose first pull did
            // not restore the leaf it pinned holds none of that data yet. A
            // revert seals from its staging, not from `udd`.
            let behind: bool = revert.is_none()
                && db.conn.query_row(
                    "SELECT base_version < remote_version FROM profile_bindings
                     WHERE local_profile_id = ?1",
                    [local],
                    |r| r.get(0),
                )?;
            // A listing that shows a restore quarantines; the loop accepts it.
            if let Err(e) = checkout(client, access, &mut db, &b, behind, now).await {
                if !awaits_transition(&bound(&db, local)?) {
                    return Err(e);
                }
            }
            continue;
        };
        let Some(commit_op) = find(&db, local, "COMMIT", Some(&lease), None)? else {
            match find(&db, local, "UPLOAD", Some(&lease), None)? {
                // A revocation recorded since the checkout: never sealed on that pin.
                None if revert.is_none()
                    && pin_withdrawn(client, access, &mut db, dev, &b).await? =>
                {
                    let e = signer_revoked(&db, &b);
                    return Err(abandon(client, access, &mut db, &b, lease, e).await);
                }
                None => seal_snapshot(client, access, &mut db, dev, &b, lease, src, now).await?,
                Some(op) if op.state == "PENDING" => {
                    create_upload(client, access, &mut db, &b, lease, &op).await?
                }
                Some(op) => prepare_commit(&mut db, dev, &b, &op)?,
            }
            continue;
        };
        if commit_op.state == "COMPLETED" {
            // Rule 6: `R`, a lost reply's replay included, is accepted here
            // only while its signer stands. Otherwise nothing is pinned and
            // the quarantine stays; the lease its commit used is dropped, so
            // a later revert walks over `R` as one more proven-revoked head.
            if revert.is_some() && dropped_withdrawn_r(&db.conn, dev, local, &commit_op)? {
                return Err(signer_revoked(&db, &b));
            }
            return finish(
                client,
                access,
                &mut db,
                dev,
                &b,
                &commit_op,
                revert.is_some(),
                now,
            )
            .await;
        }
        let s = session(&db, &commit_op.op_id)?;
        // Rule 6: a device whose own key is withdrawn commits no `R`.
        let own_withdrawn =
            revert.is_some() && ledger::withdrawn(&db, &dev.pin.0, &dev.me.signing_key_id)?;
        match s.state.as_str() {
            "OPEN" => {
                // Q-18 "In-flight commits": an upload still OPEN here never
                // reached READY, so once a compromise is counted it is
                // aborted and nothing more is sent, a stored finalize included.
                if ledger::commit_blocked(&db, &dev.pin.0, &dev.pin.1, &b.fleet, s.key_generation)?
                {
                    return Err(abort_compromised(
                        client, access, &mut db, &b, lease, &commit_op, &s,
                    )
                    .await);
                }
                if find(&db, local, "FINALIZE", Some(&lease), Some("PENDING"))?.is_none() {
                    transfer(
                        client,
                        access,
                        &mut db,
                        dev,
                        &b,
                        lease,
                        &commit_op,
                        &s,
                        (now, clock),
                    )
                    .await?;
                }
                finalize(client, access, &mut db, &b, lease, &commit_op).await?;
            }
            // A revocation recorded since the seal: no COMMIT on that pin, nor
            // a revert's `R` signed by a withdrawn device or with the content
            // of a withdrawn `P`. A head past the pin may be this COMMIT
            // landed with its reply lost, so the stored request is replayed
            // (G2-37, G2-38).
            "READY"
                if match revert {
                    None => pin_withdrawn(client, access, &mut db, dev, &b).await?,
                    Some(_) => {
                        own_withdrawn || source_withdrawn(client, access, &mut db, dev, &b).await?
                    }
                } && {
                    let head = listed(client, access, &mut db, &b).await?;
                    head.current_version == b.version && head.current_signed_head_hash == b.head
                } =>
            {
                let e = if own_withdrawn {
                    anyhow!(code("sync.revertDeviceWithdrawn"))
                } else {
                    signer_revoked(&db, &b)
                };
                return Err(fail_upload(client, access, &mut db, &b, lease, &commit_op, e).await);
            }
            "READY" => commit(client, access, &mut db, &b, lease, &commit_op).await?,
            _ => return Err(bad("upload_sessions.state")),
        }
    }
}

// -------------------------------------------------------------- revert ----

/// `udd` with `suffix` appended to its name: a sibling, so a rename between
/// the two stays on one volume.
pub(crate) fn beside(udd: &Path, suffix: &str) -> std::path::PathBuf {
    let mut p = udd.as_os_str().to_owned();
    p.push(suffix);
    p.into()
}

/// Completes the swap a revert's `finish` left in `revert_swaps`: the `P`
/// staged in `<udd>.revert-staging` replaces the user's data in `udd`, which
/// goes through `<udd>.revert-old`. Each step checks the disk first, so a
/// crash anywhere resumes; a row whose profile is gone from the disk is
/// dropped and nothing is created. Without a row nothing happens, so a
/// staging dir a revert left before `finish` is never swapped in.
pub(crate) fn settle_revert_swap(local: &str, udd: &Path) -> Result<()> {
    if !Db::path()?.try_exists()? {
        return Ok(());
    }
    let db = Db::open()?;
    let pending: bool = db.conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM revert_swaps WHERE local_profile_id = ?1)",
        [local],
        |r| r.get(0),
    )?;
    if !pending {
        return Ok(());
    }
    let (staging, old) = (beside(udd, REVERT_STAGING), beside(udd, REVERT_OLD));
    let swapped = (|| -> std::io::Result<()> {
        if staging.try_exists()? {
            if udd.try_exists()? {
                if old.try_exists()? {
                    std::fs::remove_dir_all(&old)?;
                }
                std::fs::rename(udd, &old)?;
            }
            std::fs::rename(&staging, udd)?;
        }
        if old.try_exists()? {
            std::fs::remove_dir_all(&old)?;
        }
        Ok(())
    })();
    if let Err(e) = swapped {
        // A running browser holds the profile directory on Windows.
        eprintln!("[sync] revert swap: {e}");
        bail!(code("sync.revertSwapPending"));
    }
    db.conn.execute(
        "DELETE FROM revert_swaps WHERE local_profile_id = ?1",
        [local],
    )?;
    Ok(())
}

/// Deletes the `P` a revert staged in `<udd>.revert-staging` (and a swap's
/// `<udd>.revert-old`), unless a pending swap or a resumable upload (`R`
/// sealed under the held lease, no release pending) still needs it; the
/// `unpack` leftovers beside the staging always go. An abandoned lease keeps
/// no plaintext, its lost release included: the revert that resumes it
/// restores `P` again.
pub(crate) fn discard_revert_staging(local: &str, udd: &Path) -> Result<()> {
    remove_beside(udd, &UNPACK_LEFTOVERS)?;
    let mut swap_left = false;
    for suffix in SWAP_DIRS {
        swap_left |= beside(udd, suffix).try_exists()?;
    }
    if !swap_left {
        return Ok(());
    }
    if Db::path()?.try_exists()? {
        let needed: bool = Db::open()?.conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM profile_bindings b JOIN operations o
               ON o.local_profile_id = b.local_profile_id AND o.lease_id = b.lease_id
               WHERE b.local_profile_id = ?1 AND o.kind = 'UPLOAD'
                 AND NOT EXISTS (SELECT 1 FROM operations r
                   WHERE r.local_profile_id = ?1 AND r.kind = 'RELEASE'
                     AND r.state = 'PENDING' AND r.lease_id = b.lease_id))
             OR EXISTS (SELECT 1 FROM revert_swaps WHERE local_profile_id = ?1)",
            [local],
            |r| r.get(0),
        )?;
        if needed {
            return Ok(());
        }
    }
    remove_beside(udd, &SWAP_DIRS)
}

const REVERT_STAGING: &str = ".revert-staging";
const REVERT_OLD: &str = ".revert-old";
/// The staged `P` and the data a swap replaces, both beside `udd`.
const SWAP_DIRS: [&str; 2] = [REVERT_STAGING, REVERT_OLD];

/// `unpack`'s crash leftovers beside the staging: a partial `.incoming`, and
/// a `.backup` of a staging that is always built afresh, so nothing needs them.
const UNPACK_LEFTOVERS: [&str; 2] = [".revert-staging.incoming", ".revert-staging.backup"];

fn remove_beside(udd: &Path, suffixes: &[&str]) -> Result<()> {
    for suffix in suffixes {
        let dir = beside(udd, suffix);
        if dir.try_exists()? {
            std::fs::remove_dir_all(&dir)?;
        }
    }
    Ok(())
}

/// Every profile deletion runs this first: a pending swap lands, so the
/// trash keeps `R`, then the staged `P` is deleted, never trashed, even under
/// a held revert lease (a revert that still has to seal stages `P` again).
pub(crate) fn discard_revert_for_deletion(local: &str, udd: &Path) -> Result<()> {
    settle_revert_swap(local, udd)?;
    remove_beside(udd, &SWAP_DIRS)?;
    remove_beside(udd, &UNPACK_LEFTOVERS)
}

/// A profile deleted for good keeps no staging, and needs no team database
/// for it: with the profile gone, a swap still pending no longer matters.
pub(crate) fn discard_revert_for_removal(udd: &Path) -> Result<()> {
    remove_beside(udd, &SWAP_DIRS)?;
    remove_beside(udd, &UNPACK_LEFTOVERS)
}

/// ADR 0002 rule 6, "Committer side": commits `R` on top of `Jn`, the last
/// head of the run of proven-revoked heads open at the listed head, with
/// the content of `P`, the newest head below it whose signer is valid and
/// not proven revoked. `P` is restored into `<udd>.revert-staging` under its
/// own generation's key and sealed from there; only once `R` is pinned does
/// it replace the user's data. A refused or abandoned revert discards the
/// staging dir and leaves the user's data as it was.
pub(crate) async fn revert(
    client: &FleetClient,
    access: &str,
    dev: &Device,
    local: &str,
    udd: &Path,
    now: u64,
    clock: &(dyn Fn() -> std::time::Duration + Sync),
) -> Result<Pushed> {
    settle_revert_swap(local, udd)?;
    match revert_inner(client, access, dev, local, udd, now, clock).await {
        Ok(pushed) => {
            settle_revert_swap(local, udd)?;
            Ok(pushed)
        }
        Err(e) => {
            if let Err(d) = discard_revert_staging(local, udd) {
                eprintln!("[sync] revert staging: {d:#}");
            }
            Err(e)
        }
    }
}

/// Rule 6: no `R` this device signs is accepted once its own key is
/// withdrawn, so a revert checks out and commits none and stops with
/// `sync.revertDeviceWithdrawn`. A revert lease with no COMMIT is released
/// on the base its checkout took (`granted`), so unbind stays a way out; a
/// stored COMMIT may have landed, so it goes on (`None`): `push_inner`
/// abandons it while the listed head is still `Jn`, and otherwise replays
/// it and refuses its `R`.
async fn withdrawn_device(
    client: &FleetClient,
    access: &str,
    db: &mut Db,
    dev: &Device,
    b: &Bound,
    revoked: bool,
) -> Result<Option<anyhow::Error>> {
    if !ledger::withdrawn(db, &dev.pin.0, &dev.me.signing_key_id)? {
        return Ok(None);
    }
    let e = anyhow!(code("sync.revertDeviceWithdrawn"));
    match b.lease {
        None => Ok(Some(e)),
        Some(lease) if revoked && find(db, &b.local, "COMMIT", Some(&lease), None)?.is_none() => {
            let lease = granted(db, b, &lease)?.lease;
            Ok(Some(abandon(client, access, db, b, lease, e).await))
        }
        Some(_) => Ok(None),
    }
}

/// [`revert`] up to and including `finish`, the swap still pending.
async fn revert_inner(
    client: &FleetClient,
    access: &str,
    dev: &Device,
    local: &str,
    udd: &Path,
    now: u64,
    clock: &(dyn Fn() -> std::time::Duration + Sync),
) -> Result<Pushed> {
    let mut db = Db::open()?;
    let mut b = bound(&db, local)?;
    let revoked = b.error.as_deref() == Some(SIGNER_REVOKED);
    if !revoked {
        refuse_quarantined(&b)?;
    }
    // G2-34: a revert lease's lost release is replayed first, never resumed
    // over a run another device closed; its staged `P` went with the
    // abandonment, so the walk below restores it again.
    if b.lease.is_some() && revoked {
        if let Some(op) = find(&db, local, "RELEASE", None, Some("PENDING"))? {
            release_reply(client, access, &mut db, &b, &op).await?;
            b = bound(&db, local)?;
        }
    }
    if let Some(e) = withdrawn_device(client, access, &mut db, dev, &b, revoked).await? {
        return Err(e);
    }
    // A revert lease resumes on the base its checkout took; any other
    // lease is an ordinary push's, which a revert never continues.
    let base = match b.lease {
        Some(_) if !revoked => bail!(code("sync.pushPending")),
        Some(lease) => {
            let g = granted(&db, &b, &lease)?;
            let head = g
                .current_signed_head_hash
                .ok_or_else(|| bad("current_signed_head_hash"))?;
            Some((g.lease.base_version, head))
        }
        None => None,
    };
    let uploaded = match b.lease {
        Some(lease) => find(&db, local, "UPLOAD", Some(&lease), None)?.is_some(),
        None => false,
    };
    let staging = beside(udd, REVERT_STAGING);
    // An upload resumes only over its staged `P`; one gone (a profile
    // deleted under the lease) is restored again, byte for byte, by the walk.
    let base = match base {
        Some(base) if uploaded && staging.try_exists()? => base,
        _ => {
            let walk = async {
                let head = listed(client, access, &mut db, &b).await?;
                let w = walked(client, access, &mut db, dev, &b, &head, now).await?;
                if w.open.is_empty() {
                    bail!(code("sync.revertUnavailable"));
                }
                if w.anchor.is_none() {
                    bail!(code("sync.revertNoValidSnapshot"));
                }
                Ok(w)
            };
            // A revert lease with nothing uploaded whose run is gone (another
            // device committed over it, or the walk quarantined it) is
            // released; the quarantine stays.
            let w = match (walk.await, b.lease) {
                (Ok(w), _) => w,
                (Err(e), Some(lease)) => {
                    let lease = granted(&db, &b, &lease)?.lease;
                    return Err(abandon(client, access, &mut db, &b, lease, e).await);
                }
                (Err(e), None) => return Err(e),
            };
            let (Some(jn), Some((_, p))) = (w.open.last(), &w.anchor) else {
                unreachable!("the walk above checked both");
            };
            // The walk records the evidence it fetched: a withdrawal of this
            // device it showed for the first time stops the revert as well.
            if let Some(e) = withdrawn_device(client, access, &mut db, dev, &b, revoked).await? {
                return Err(e);
            }
            if b.lease.is_none() {
                hold_open(&mut db, &b, &w, &w.accepted, now)?;
                // Q-18: a compromised revocation waits for rotation, and the
                // quarantine keeps its code (no `mark_blocked`).
                if let Some(g) = ledger::highest_generation(&db, &dev.pin.0, &b.fleet)? {
                    if ledger::commit_blocked(&db, &dev.pin.0, &dev.pin.1, &b.fleet, g)? {
                        bail!(code("sync.commitBlockedCompromised"));
                    }
                }
            }
            let fkek = readable_key(
                &db,
                dev,
                &b.fleet,
                p.key_generation,
                Some(&p.fkek_key_id),
                now,
            )?;
            fresh_staging(udd, &staging)?;
            restore(client, access, &b, p, fkek, &staging).await?;
            base.unwrap_or((jn.version, jn.hash))
        }
    };
    push_inner(
        client,
        access,
        dev,
        local,
        Plain::Folder(&staging),
        now,
        clock,
        Some(base),
    )
    .await
}

// ------------------------------------------------------------- publish ----

/// The server a fleet key was filed under (G2-36): the one `fleet_key_state`
/// row of `b`'s fleet that holds `generation` as `fkek_key_id`.
fn key_server(db: &Db, b: &Bound, generation: u64, fkek_key_id: &[u8; 32]) -> Result<String> {
    let rows = db
        .conn
        .prepare(
            "SELECT server_id FROM fleet_key_state
             WHERE server_instance_id = ?1 AND tenant_id = ?2 AND fleet_id = ?3
               AND generation = ?4 AND fkek_key_id = ?5",
        )?
        .query_map(
            params![
                hex(&b.instance),
                hex(&b.tenant),
                hex(&b.fleet),
                wire(generation)?,
                hex(fkek_key_id)
            ],
            |r| r.get::<_, String>(0),
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    match <[String; 1]>::try_from(rows) {
        Ok([server]) => Ok(server),
        Err(_) => bail!(code("sync.fleetKeyRecollect")),
    }
}

/// A finished publish: the version-0 profile and the first lease.
#[derive(Debug)]
pub(crate) struct Published {
    pub profile: [u8; 16],
    pub lease: LeaseRef,
    pub expires_at_ms: u64,
}

/// `PROFILE_PUBLISH_CREATE` of `local` as the new profile `profile` of
/// `fleet`, labelled `label` (sealed under the verified fleet key), or the
/// replay of the one an earlier attempt stored (plan L300, L1137, L1422,
/// L2048). The request is stored as exact bytes before it is sent; a lost
/// reply is answered by the server's stored response, so no second profile
/// or lease exists. The binding is written only with the complete response
/// (L2233), in the transaction that completes the operation.
// A pending publish of another fleet is refused rather than replayed into
// the wrong fleet, and `profile` only names a new request.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn publish(
    client: &FleetClient,
    access: &str,
    dev: &Device,
    local: &str,
    label: &str,
    fleet: [u8; 16],
    profile: [u8; 16],
    now: u64,
) -> Result<Published> {
    let mut db = Db::open()?;
    retry_unbound_releases(client, access, &mut db).await;
    if is_bound(&db.conn, local)? {
        bail!(code("sync.alreadyPublished"));
    }
    let op = match pending_publish(&db, local)? {
        Some(op) => op,
        None => {
            store_publish(
                client, access, &mut db, dev, local, label, fleet, profile, now,
            )
            .await?
        }
    };
    send_publish(client, access, &mut db, dev, local, fleet, &op, now).await
}

fn is_bound(conn: &rusqlite::Connection, local: &str) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM profile_bindings WHERE local_profile_id = ?1)",
        [local],
        |r| r.get(0),
    )?)
}

/// The newest PENDING `PUBLISH` requested for `local`. Its binding does not
/// exist yet, so it is found by the name it was requested under.
fn pending_publish(db: &Db, local: &str) -> Result<Option<Op>> {
    Ok(db
        .conn
        .query_row(
            &format!(
                "SELECT {OP_COLUMNS} FROM operations
                 WHERE kind = 'PUBLISH' AND local_profile_id_at_request = ?1 AND state = 'PENDING'
                 ORDER BY rowid DESC LIMIT 1"
            ),
            [local],
            op_row,
        )
        .optional()?)
}

/// `local` as it is before a binding to `fleet`'s `profile` under this
/// device's pinned instance and tenant exists.
fn unbound(local: &str, dev: &Device, fleet: [u8; 16], profile: [u8; 16]) -> Bound {
    Bound {
        local: local.to_string(),
        server: String::new(),
        instance: dev.pin.0.server_instance_id,
        tenant: dev.pin.0.tenant_id,
        fleet,
        profile,
        version: 0,
        head: None,
        epoch: 0,
        lease: None,
        state: "LOCAL".into(),
        error: None,
    }
}

/// One profile a fleet lists, as `team_fleet_profiles` reports it.
#[derive(Debug, serde::Serialize)]
pub struct FleetProfile {
    pub remote_profile_id: String,
    pub current_version: u64,
    /// Opened under this device's key of its generation; `None` when no key
    /// this device holds opens it.
    pub label: Option<String>,
    /// The local profile bound to it here, if any.
    pub bound_to: Option<String>,
}

/// Every profile `fleet` lists, with its label opened and its binding here,
/// if any. Nothing is written, here or on the server.
pub(crate) async fn labels(
    client: &FleetClient,
    access: &str,
    dev: &Device,
    fleet: [u8; 16],
    now: u64,
) -> Result<Vec<FleetProfile>> {
    let db = Db::open()?;
    let b = unbound("", dev, fleet, [0; 16]);
    let mut listed = Vec::new();
    fleet_pages(client, access, &b, |p| {
        listed.push(p.clone());
        true
    })
    .await?;
    let bound: std::collections::HashMap<String, String> = db
        .conn
        .prepare(
            "SELECT remote_profile_id, local_profile_id FROM profile_bindings
             WHERE server_instance_id = ?1 AND tenant_id = ?2
               AND local_profile_id NOT GLOB 'reseal:*'",
        )?
        .query_map(params![hex(&b.instance), hex(&b.tenant)], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    // A label is read, never sealed: the key of its own generation, as `P`'s.
    let mut keys = std::collections::HashMap::new();
    Ok(listed
        .into_iter()
        .map(|p| {
            let key = keys.entry(p.key_generation).or_insert_with(|| {
                readable_key(&db, dev, &fleet, p.key_generation, None, now).ok()
            });
            let label = key.as_ref().and_then(|k| {
                let l = shardx_core::keys::open_label(
                    k,
                    &b.tenant,
                    &fleet,
                    &p.profile_id,
                    p.key_generation,
                    &p.label_ciphertext,
                )
                .ok()?;
                String::from_utf8(l.to_vec()).ok()
            });
            let id = hex(&p.profile_id);
            FleetProfile {
                bound_to: bound.get(&id).cloned(),
                remote_profile_id: id,
                current_version: p.current_version,
                label,
            }
        })
        .collect())
}

/// Binds the local profile `local`, which has no binding, to `fleet`'s
/// listed `profile` on this device, then pulls it into `udd` (Team UI S3b).
/// The binding starts at version 0 with no lease, `AVAILABLE` and clean,
/// under the verified key `store_publish` would seal with. Its epoch is the
/// server's, or the one before it when the profile's first snapshot predates
/// it, so the pull accepts the restore transition whose leaf it then pins
/// (ADR 0002 rule 6: the leaf exception covers a new device). A refusal
/// before the insert leaves no binding. A failed pull keeps the binding,
/// possibly quarantined awaiting the transition or pinned at the leaf, and
/// pull can be retried; until one restores its pin, push refuses it
/// (`base_version` stays below `remote_version`).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn join(
    client: &FleetClient,
    access: &str,
    dev: &Device,
    local: &str,
    fleet: [u8; 16],
    profile: [u8; 16],
    udd: &Path,
    now: u64,
) -> Result<u64> {
    // A re-seal's leftover row for this profile goes first (v2.10 4.S).
    drop_reseal_row(&profile)?;
    let mut db = Db::open()?;
    // A local profile with an unfinished publish is bound by finishing it.
    if is_bound(&db.conn, local)? || pending_publish(&db, local)?.is_some() {
        bail!(code("sync.alreadyPublished"));
    }
    bind(client, access, dev, &mut db, local, fleet, profile, now).await?;
    drop(db);
    pull(client, access, dev, local, udd, now).await
}

/// Binds `local` to `fleet`'s listed `profile` at version 0, as [`join`]
/// describes, without pulling: a join's row, or a re-seal's (4.S).
#[allow(clippy::too_many_arguments)]
async fn bind(
    client: &FleetClient,
    access: &str,
    dev: &Device,
    db: &mut Db,
    local: &str,
    fleet: [u8; 16],
    profile: [u8; 16],
    now: u64,
) -> Result<()> {
    let mut b = unbound(local, dev, fleet, profile);
    // Checked before the server is asked, and again with the insert, so the
    // UNIQUE constraint is never the error shown. A re-seal row is no binding
    // here; a join removes a leftover one first.
    let taken = |c: &rusqlite::Connection| -> Result<()> {
        let taken: bool = c.query_row(
            "SELECT EXISTS (SELECT 1 FROM profile_bindings
               WHERE server_instance_id = ?1 AND tenant_id = ?2 AND remote_profile_id = ?3
                 AND local_profile_id NOT GLOB 'reseal:*')",
            params![
                hex(&dev.pin.0.server_instance_id),
                hex(&dev.pin.0.tenant_id),
                hex(&profile)
            ],
            |r| r.get(0),
        )?;
        if taken {
            bail!(code("sync.remoteAlreadyBound"));
        }
        Ok(())
    };
    taken(&db.conn)?;
    let generation = ledger::highest_generation(db, &dev.pin.0, &fleet)?
        .ok_or_else(|| anyhow!(code("sync.noVerifiedFleetKey")))?;
    let fkek = verified_key(db, dev, &fleet, generation, None, now)?;
    let fkek_key_id = shardx_core::fleet_grants::fkek_key_id(&fkek);
    b.server = key_server(db, &b, generation, &fkek_key_id)?;
    let (epoch, listed) = listing(client, access, &b).await?;
    let listed = listed.ok_or_else(|| anyhow!(code("sync.profileNotListed")))?;
    let accepted: Option<i64> = db
        .conn
        .query_row(
            "SELECT last_restore_epoch FROM server_origins WHERE server_instance_id = ?1",
            [hex(&b.instance)],
            |r| r.get(0),
        )
        .optional()?;
    if accepted.is_some_and(|e| epoch < e as u64) {
        bail!(code("sync.headRollback"));
    }
    // Only a start epoch: the pull verifies every manifest it accepts, so a
    // server that misreports this one fails closed there.
    let mut start = epoch;
    if epoch > 0 && listed.current_version > 0 {
        let first = manifest(client, access, &b, 1).await?;
        let p = SnapshotManifestV2::parse(first.canonical_manifest_payload_bytes())
            .map_err(|_| bad("manifest"))?;
        if p.restore_epoch < epoch {
            start = epoch - 1;
        }
    }
    {
        let tx = db
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        taken(&tx)?;
        tx.execute(
            "INSERT INTO profile_bindings(local_profile_id, server_id, server_instance_id, tenant_id,
               account_id, device_id, fleet_id, remote_profile_id, remote_version, base_version,
               accepted_restore_epoch, fkek_key_id, key_generation, sync_state, dirty)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, 0, ?9, ?10, ?11, 'AVAILABLE', 0)",
            params![
                b.local,
                b.server,
                hex(&b.instance),
                hex(&b.tenant),
                hex(&dev.me.account_id),
                hex(&dev.me.device_id),
                hex(&b.fleet),
                hex(&b.profile),
                wire(start)?,
                hex(&fkek_key_id),
                wire(generation)?
            ],
        )?;
        tx.commit()?;
    }
    Ok(())
}

/// Builds the request of a new publish and stores it, PENDING, unsent.
#[allow(clippy::too_many_arguments)]
async fn store_publish(
    client: &FleetClient,
    access: &str,
    db: &mut Db,
    dev: &Device,
    local: &str,
    label: &str,
    fleet: [u8; 16],
    profile: [u8; 16],
    now: u64,
) -> Result<Op> {
    let mut b = unbound(local, dev, fleet, profile);
    // The listing names the server's instance and epoch (it must be the
    // pinned instance) and shows whether the ID is taken.
    let (epoch, listed) = listing(client, access, &b).await?;
    if listed.is_some() {
        bail!(code("sync.publishProfileTaken"));
    }
    // A new profile has no history to roll back, so an epoch ahead of the one
    // this device accepted is taken as it is; one behind it is a rollback.
    let accepted: Option<i64> = db
        .conn
        .query_row(
            "SELECT last_restore_epoch FROM server_origins WHERE server_instance_id = ?1",
            [hex(&b.instance)],
            |r| r.get(0),
        )
        .optional()?;
    if accepted.is_some_and(|e| epoch < e as u64) {
        bail!(code("sync.headRollback"));
    }
    b.epoch = epoch;
    let generation = ledger::highest_generation(db, &dev.pin.0, &fleet)?
        .ok_or_else(|| anyhow!(code("sync.noVerifiedFleetKey")))?;
    let fkek = verified_key(db, dev, &fleet, generation, None, now)?;
    b.server = key_server(
        db,
        &b,
        generation,
        &shardx_core::fleet_grants::fkek_key_id(&fkek),
    )?;
    if ledger::commit_blocked(db, &dev.pin.0, &dev.pin.1, &fleet, generation)? {
        bail!(code("sync.commitBlockedCompromised"));
    }
    let label_ciphertext = shardx_core::keys::seal_label(
        &fkek,
        &random()?,
        &b.tenant,
        &fleet,
        &profile,
        generation,
        label.trim().as_bytes(),
    )
    .map_err(|_| anyhow!(code("sync.badProfileLabel")))?;
    let request = ProfilePublishCreateV2 {
        profile: b.pref(),
        label_ciphertext,
        requested_lease_ttl_seconds: LEASE_TTL_SECONDS,
        fkek_key_id: shardx_core::fleet_grants::fkek_key_id(&fkek),
        key_generation: generation,
    };
    let kind = OperationKind::ProfilePublishCreate;
    let (key, exact, canonical) = mutation(kind, request.encode(), &b)?;
    let op_id = hex(&random::<16>()?);
    let scope = format!("{} /v2/fleets/{}/profiles", kind.scope(), hex(&fleet));
    let columns = Columns {
        unbound: true,
        ..Default::default()
    };
    insert_op(
        &db.conn, &b, &op_id, "PUBLISH", &scope, &key, &canonical, &exact, &columns,
    )?;
    get_op(db, &op_id)
}

/// Sends the stored `PUBLISH`, checks the stored response names exactly what
/// was asked, and files the binding with the operation's completion.
#[allow(clippy::too_many_arguments)]
async fn send_publish(
    client: &FleetClient,
    access: &str,
    db: &mut Db,
    dev: &Device,
    local: &str,
    fleet: [u8; 16],
    op: &Op,
    now: u64,
) -> Result<Published> {
    let me = &dev.me;
    let exact = stored_for(db, local, op)?;
    let asked = IdempotentMutationRequestV2::parse(exact)
        .ok()
        .and_then(|r| ProfilePublishCreateV2::parse(&r.canonical_payload_bytes).ok())
        .ok_or_else(|| bad("ProfilePublishCreateV2"))?;
    if asked.profile.fleet_id != fleet {
        bail!(code("sync.publishPendingElsewhere"));
    }
    let b = Bound {
        local: local.to_string(),
        server: op.server.clone(),
        instance: decode_hex16(&op.instance, "server_instance_id")?,
        tenant: asked.profile.tenant_id,
        fleet,
        profile: asked.profile.profile_id,
        version: 0,
        head: None,
        epoch: op.epoch,
        lease: None,
        state: "LOCAL".into(),
        error: None,
    };
    // Every send, a replay included, needs the key still verified and not
    // blocked: a compromise counted or a key withdrawn since it was stored
    // keeps it unsent (cancel it with `cancel_publish`).
    verified_key(
        db,
        dev,
        &fleet,
        asked.key_generation,
        Some(&asked.fkek_key_id),
        now,
    )?;
    if ledger::commit_blocked(db, &dev.pin.0, &dev.pin.1, &fleet, asked.key_generation)? {
        bail!(code("sync.commitBlockedCompromised"));
    }
    let reply = client.publish_profile(access, &fleet, exact).await?;
    let body = settle(client, access, db, op, reply)??;
    let accepted = || -> Result<ProfileLeaseV2> {
        let payload = stored_response(op, RECORD_TYPE_PUBLISH_CREATED, &body)?;
        let g = ProfileLeaseV2::parse(LeaseOrigin::PublishCreate, &payload)
            .map_err(|_| bad("ProfileLeaseV2"))?;
        let checks = [
            ("profile", g.profile == b.pref()),
            ("server_instance_id", g.server_instance_id == b.instance),
            ("restore_epoch", g.restore_epoch == op.epoch),
            ("fkek_key_id", g.fkek_key_id == asked.fkek_key_id),
            ("key_generation", g.key_generation == asked.key_generation),
            // The first fence of a new profile.
            ("fencing_token", g.lease.fencing_token == 1),
        ];
        match checks.iter().find(|(_, ok)| !ok) {
            Some((field, _)) => Err(bad(field)),
            None => Ok(g),
        }
    };
    let g = match accepted() {
        Ok(g) => g,
        Err(e) => return Err(refuse_publish(client, access, db, &b, op, &body, e).await),
    };
    // The profile exists whatever its lease says, so a reply that names it
    // is always bound (plan L2048). A lease already over is not held; one
    // further ahead than a TTL and the skew allowance is held at risk, for
    // one TTL from now.
    let held = g.expires_at_ms > now;
    let at_risk = held && !lease_expiry_ok(g.expires_at_ms, now);
    let expiry = if at_risk {
        now + u64::from(LEASE_TTL_SECONDS) * 1000
    } else {
        g.expires_at_ms
    };
    let state = match (held, at_risk) {
        (false, _) => "AVAILABLE",
        (true, true) => "LEASE_AT_RISK",
        (true, false) => "CHECKED_OUT",
    };
    let lease = hex(&g.lease.lease_id);
    {
        let tx = db.conn.transaction()?;
        // Another process may have cancelled the publish since it was read:
        // the binding is filed only with the completion of this very operation.
        if complete(&tx, op, RECORD_TYPE_PUBLISH_CREATED, &body)? != 1 {
            bail!(code("sync.publishChanged"));
        }
        tx.execute(
        "INSERT INTO profile_bindings(local_profile_id, server_id, server_instance_id, tenant_id,
           account_id, device_id, fleet_id, remote_profile_id, remote_version, base_version,
           accepted_restore_epoch, fencing_token, lease_id, lease_expires_at, fkek_key_id,
           key_generation, sync_state, dirty)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, 0, ?9, ?10, ?11, strftime('%Y-%m-%dT%H:%M:%fZ', ?12 / 1000.0, 'unixepoch'), ?13, ?14,
           ?15, 1)",
        params![
            b.local,
            b.server,
            hex(&b.instance),
            hex(&b.tenant),
            hex(&me.account_id),
            hex(&me.device_id),
            hex(&b.fleet),
            hex(&b.profile),
            wire(op.epoch)?,
            held.then(|| wire(g.lease.fencing_token)).transpose()?,
            held.then_some(&lease),
            held.then(|| wire(expiry)).transpose()?,
            hex(&g.fkek_key_id),
            wire(g.key_generation)?,
            state
        ],
    )?;
        tx.execute(
            "UPDATE operations SET local_profile_id = ?2, lease_id = ?3, fencing_token = ?4,
           base_version = ?5 WHERE op_id = ?1",
            params![
                op.op_id,
                b.local,
                lease,
                wire(g.lease.fencing_token)?,
                wire(g.lease.base_version)?
            ],
        )?;
        tx.commit()?;
    }
    if !held {
        // Over already: the stored lease is let go, best effort. The binding
        // exists now, so a push replays the release if this one is lost.
        let sent = async {
            let release = release_op(&db.conn, &b, g.lease, ReleaseReason::UserRelease)?;
            let release = get_op(db, &release)?;
            release_reply(client, access, db, &b, &release).await
        };
        if let Err(e) = sent.await {
            eprintln!("[sync] release of an ended first lease: {e:#}");
        }
    }
    Ok(Published {
        profile: b.profile,
        lease: g.lease,
        expires_at_ms: expiry,
    })
}

/// A 2xx reply to a stored publish that cannot be accepted ends it: the
/// operation is QUARANTINED under `err`'s named reason and never replayed
/// (the server would answer the same). If the reply still names a lease of this
/// profile in a stored response that verifies, that lease is released with
/// `cancel_publish`, once and best effort: it lapses at its TTL otherwise.
async fn refuse_publish(
    client: &FleetClient,
    access: &str,
    db: &mut Db,
    b: &Bound,
    op: &Op,
    body: &[u8],
    err: anyhow::Error,
) -> anyhow::Error {
    let _ = db.conn.execute(
        "UPDATE operations SET state = 'QUARANTINED', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
         WHERE op_id = ?1 AND state = 'PENDING'",
        [&op.op_id],
    );
    let lease = stored_response(op, RECORD_TYPE_PUBLISH_CREATED, body)
        .ok()
        .and_then(|p| ProfileLeaseV2::parse(LeaseOrigin::PublishCreate, &p).ok())
        .filter(|g| g.profile == b.pref())
        .map(|g| g.lease);
    if let Some(lease) = lease {
        let sent = async {
            let release = release_op(&db.conn, b, lease, ReleaseReason::CancelPublish)?;
            let release = get_op(db, &release)?;
            release_reply(client, access, db, b, &release).await
        };
        if let Err(e) = sent.await {
            eprintln!("[sync] cancel_publish release: {e:#}");
        }
    }
    err
}

/// How long an unbound release is worth sending: the lease it names, asked for
/// one TTL, cannot be live after that and the skew allowance.
const UNBOUND_RELEASE_SECONDS: u64 = LEASE_TTL_SECONDS as u64 + LEASE_SKEW_MS / 1000;

/// SQL for an unbound release that is past it, which is given up unsent and no
/// longer counts as work in flight (the downgrade readiness uses it too).
pub(crate) fn given_up_unbound_release() -> String {
    format!(
        "(kind = 'RELEASE' AND local_profile_id IS NULL
          AND created_at <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-{UNBOUND_RELEASE_SECONDS} seconds'))"
    )
}

/// Ends the unbound releases too old to matter and returns the rest.
fn due_unbound_releases(db: &Db) -> Result<Vec<Op>> {
    db.conn.execute(
        &format!(
            "UPDATE operations SET state = 'FAILED', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE state = 'PENDING' AND {}",
            given_up_unbound_release()
        ),
        [],
    )?;
    let mut stmt = db.conn.prepare(&format!(
        "SELECT {OP_COLUMNS} FROM operations
         WHERE kind = 'RELEASE' AND state = 'PENDING' AND local_profile_id IS NULL
         ORDER BY rowid"
    ))?;
    let ops = stmt
        .query_map([], op_row)?
        .collect::<rusqlite::Result<_>>()?;
    Ok(ops)
}

/// Retries the `cancel_publish` releases an earlier attempt left PENDING: they
/// name no binding, so nothing else would. One older than a TTL and the skew
/// allowance (the lease it names cannot be live any more) is ended FAILED
/// without a request; the rest are sent as stored. Best effort: a failure is
/// logged and the release waits for the next publish, push or pull.
async fn retry_unbound_releases(client: &FleetClient, access: &str, db: &mut Db) {
    let ops = match due_unbound_releases(db) {
        Ok(ops) => ops,
        Err(e) => {
            eprintln!("[sync] unbound releases: {e:#}");
            return;
        }
    };
    for op in ops {
        let sent = async {
            let request = IdempotentMutationRequestV2::parse(&op.exact)
                .map_err(|_| bad("IdempotentMutationRequestV2"))?;
            let release = ReleaseLeaseV2::parse(&request.canonical_payload_bytes)
                .map_err(|_| bad("ReleaseLeaseV2"))?;
            let b = Bound {
                local: String::new(),
                server: op.server.clone(),
                instance: decode_hex16(&op.instance, "server_instance_id")?,
                tenant: release.profile.tenant_id,
                fleet: release.profile.fleet_id,
                profile: release.profile.profile_id,
                version: 0,
                head: None,
                epoch: op.epoch,
                lease: None,
                state: "LOCAL".into(),
                error: None,
            };
            release_reply(client, access, db, &b, &op).await
        };
        if let Err(e) = sent.await {
            eprintln!("[sync] cancel_publish release retried: {e:#}");
        }
    }
}

/// Ends the pending publish of `local` without sending it: the way out of a
/// stored request that `publish` keeps refusing (a key withdrawn or a
/// compromise counted since it was stored). Nothing is sent, so a request
/// that had already reached the server leaves its first lease to lapse at its
/// TTL and the empty profile listed; the next publish names a new profile.
pub(crate) fn cancel_publish(local: &str) -> Result<()> {
    let db = Db::open()?;
    let op = pending_publish(&db, local)?.ok_or_else(|| anyhow!(code("sync.noPublishPending")))?;
    db.conn.execute(
        "UPDATE operations SET state = 'FAILED', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
         WHERE op_id = ?1 AND state = 'PENDING'",
        [&op.op_id],
    )?;
    Ok(())
}

/// `PROFILE_CHECKOUT` at the pinned head, or the replay of a stored one.
/// `behind`: the local data never received the pinned head, so nothing is
/// checked out until a pull restores it (a replayed lease is released).
async fn checkout(
    client: &FleetClient,
    access: &str,
    db: &mut Db,
    b: &Bound,
    behind: bool,
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
            if behind || head.current_version > b.version {
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
    let body = settle(client, access, db, &op, reply)??;
    let payload = stored_response(&op, RECORD_TYPE_CHECKED_OUT, &body)?;
    let g = ProfileLeaseV2::parse(LeaseOrigin::Checkout, &payload)
        .map_err(|_| bad("ProfileLeaseV2"))?;
    let checks = [
        ("profile", g.profile == b.pref()),
        ("server_instance_id", g.server_instance_id == b.instance),
        ("restore_epoch", g.restore_epoch == op.epoch),
        // A replay may return a lease that has ended since (released below).
        (
            "expires_at_ms",
            lease_expiry_ok(g.expires_at_ms, now) || (replayed && g.expires_at_ms <= now),
        ),
    ];
    if let Some((field, _)) = checks.iter().find(|(_, ok)| !ok) {
        return Err(bad(field));
    }
    // A replayed checkout from before the binding moved on holds a lease on an
    // old head or epoch, and one replayed after its stored expiry a lease that
    // ended (probe 11, L2046): it is released as stored, and the next one
    // starts afresh under a new key. So is one over data that is `behind`.
    if (g.lease.base_version, g.current_signed_head_hash) != (b.version, b.head)
        || op.epoch != b.epoch
        || (replayed && g.expires_at_ms <= now)
        || behind
    {
        let release = {
            let tx = db.conn.transaction()?;
            tx.execute(
                "UPDATE operations SET state = 'FAILED', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE op_id = ?1",
                [&op.op_id],
            )?;
            let release = release_op(&tx, b, g.lease, ReleaseReason::UserRelease)?;
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
        "UPDATE profile_bindings SET lease_id = ?2, fencing_token = ?3, sync_state = 'CHECKED_OUT',
           lease_expires_at = strftime('%Y-%m-%dT%H:%M:%fZ', ?4 / 1000.0, 'unixepoch')
         WHERE local_profile_id = ?1",
        params![
            b.local,
            hex(&g.lease.lease_id),
            wire(g.lease.fencing_token)?,
            wire(g.expires_at_ms)?
        ],
    )?;
    tx.commit()?;
    Ok(())
}

/// The lease the completed checkout, or else the completed publish, of
/// `lease` granted.
fn granted(db: &Db, b: &Bound, lease: &LeaseRef) -> Result<ProfileLeaseV2> {
    let (op, origin) = match find(db, &b.local, "CHECKOUT", Some(lease), Some("COMPLETED"))? {
        Some(op) => (op, LeaseOrigin::Checkout),
        None => (
            find(db, &b.local, "PUBLISH", Some(lease), Some("COMPLETED"))?
                .ok_or_else(|| bad("lease_id"))?,
            LeaseOrigin::PublishCreate,
        ),
    };
    let body: Vec<u8> = db.conn.query_row(
        "SELECT exact_response_bytes FROM operations WHERE op_id = ?1",
        [&op.op_id],
        |r| r.get(0),
    )?;
    let payload = stored_response(&op, origin.record_type(), &body)?;
    ProfileLeaseV2::parse(origin, &payload).map_err(|_| bad("ProfileLeaseV2"))
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
    src: Plain<'_>,
    now: u64,
) -> Result<()> {
    let g = granted(db, b, &lease)?;
    let generation = g.key_generation;
    let fkek = match verified_key(db, dev, &b.fleet, generation, Some(&g.fkek_key_id), now) {
        Ok(k) => k,
        Err(e) => return Err(abandon(client, access, db, b, lease, e).await),
    };
    if ledger::commit_blocked(db, &dev.pin.0, &dev.pin.1, &b.fleet, generation)? {
        mark_blocked(db, &b.local, true)?;
        let e = anyhow!(code("sync.commitBlockedCompromised"));
        return Err(abandon(client, access, db, b, lease, e).await);
    }
    let packed;
    let plaintext: &[u8] = match src {
        Plain::Folder(udd) => {
            let owned = udd.to_path_buf();
            packed = tokio::task::spawn_blocking(move || shardx_core::snapshot::pack(&owned))
                .await
                .map_err(|e| {
                    anyhow!(code_with(
                        "sync.sealTaskFailed",
                        &[("error", &e.to_string())]
                    ))
                })??;
            &packed
        }
        Plain::Opened(plaintext) => plaintext,
    };
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
    let d = seal(&mut &*plaintext, &mut object, &dek, &intent, &slot).map_err(|e| {
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
    let body = match settle(client, access, db, op, reply)? {
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
        ..Default::default()
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
           server_id, operation_scope, idempotency_key, canonical_request_hash, retry_state,
           state, created_at, updated_at)
         SELECT ?1, ?2, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17,
           ?18, ?19, ?20, operation_scope, idempotency_key, canonical_request_hash, 'NONE', 'OPEN',
           strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
         FROM operations WHERE op_id = ?3",
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
            b.server,
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

/// Q-18 "Local state": the client-local `last_error_code` of a binding whose
/// commit is blocked, never sent; cleared once the block is released.
const COMPROMISED: &str = "ROTATION_REQUIRED_COMPROMISED";

/// Marks `local` blocked; `dirty` when its lease goes without a commit, so
/// the binding ends AVAILABLE with `dirty = 1` once the release lands. A
/// `SIGNER_REVOKED` quarantine keeps its code, and a revert lease, which
/// seals from staging and never the user's data, leaves `dirty` as it was.
fn mark_blocked(db: &Db, local: &str, dirty: bool) -> Result<()> {
    db.conn.execute(
        "UPDATE profile_bindings SET
           last_error_code = CASE WHEN last_error_code = 'SIGNER_REVOKED'
             THEN last_error_code ELSE ?2 END,
           dirty = CASE WHEN last_error_code = 'SIGNER_REVOKED' THEN dirty ELSE max(dirty, ?3) END
         WHERE local_profile_id = ?1",
        params![local, COMPROMISED, dirty],
    )?;
    Ok(())
}

/// Q-18 "In-flight commits": aborts the OPEN upload `s` of `commit_op` on
/// the server while the lease is still held, then gives it up here.
async fn abort_compromised(
    client: &FleetClient,
    access: &str,
    db: &mut Db,
    b: &Bound,
    lease: LeaseRef,
    commit_op: &Op,
    s: &Session,
) -> anyhow::Error {
    let aborted = async {
        let upload = decode_hex16(&s.upload, "upload_id")?;
        ok(client, access, client.upload_abort(access, &upload).await?)
    };
    if let Err(e) = aborted.await {
        eprintln!("[sync] abort: {e:#}");
    }
    let _ = mark_blocked(db, &b.local, true);
    let err = anyhow!(code("sync.commitBlockedCompromised"));
    fail_upload(client, access, db, b, lease, commit_op, err).await
}

/// G2-36: sends the spooled ciphertext from the offset `HEAD` reports, never
/// a guessed one; an offset conflict asks `HEAD` again. The lease is renewed
/// once a third of its TTL has passed on `clock`, which counts from `now`; the
/// expiry the server then grants must be a plausible one. A compromise
/// counted meanwhile (Q-18) aborts the upload before the next chunk or the
/// finalize.
#[allow(clippy::too_many_arguments)]
async fn transfer(
    client: &FleetClient,
    access: &str,
    db: &mut Db,
    dev: &Device,
    b: &Bound,
    lease: LeaseRef,
    commit_op: &Op,
    s: &Session,
    (now, clock): (u64, &(dyn Fn() -> std::time::Duration + Sync)),
) -> Result<()> {
    stored(db, b, commit_op)?;
    let object = std::fs::read(spool(&s.spool)?)?;
    let upload = decode_hex16(&s.upload, "upload_id")?;
    let mut renewed = clock();
    for _ in 0..3 {
        let reply = client.upload_head(access, &upload).await?;
        if terminal(reply.status) {
            let e = refused(client, access, &reply);
            return Err(fail_upload(client, access, db, b, lease, commit_op, e).await);
        }
        let reply = ok(client, access, reply)?;
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
            if ledger::commit_blocked(db, &dev.pin.0, &dev.pin.1, &b.fleet, s.key_generation)? {
                return Err(abort_compromised(client, access, db, b, lease, commit_op, s).await);
            }
            if at == s.size {
                return Ok(());
            }
            if clock().saturating_sub(renewed).as_secs() > u64::from(LEASE_TTL_SECONDS / 3) {
                let expires = renew(client, access, b, lease).await?;
                if !lease_expiry_ok(expires, now + clock().as_millis() as u64) {
                    return Err(bad("expires_at_ms"));
                }
                keep_expiry(&db.conn, &b.local, &lease, expires)?;
                renewed = clock();
            }
            let end = (at + CHUNK as u64).min(s.size);
            let chunk = &object[at as usize..end as usize];
            let reply = client.upload_patch(access, &upload, at, chunk).await?;
            if reply.status == 409 {
                break;
            }
            let reply = ok(client, access, reply)?;
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

/// `LeaseRenewV2` for the lease this push holds (L1139); returns the
/// server's new expiry.
async fn renew(client: &FleetClient, access: &str, b: &Bound, lease: LeaseRef) -> Result<u64> {
    let body = LeaseRenewV2 {
        profile: b.pref(),
        lease,
        requested_lease_ttl_seconds: LEASE_TTL_SECONDS,
    }
    .encode();
    let reply = ok(
        client,
        access,
        client
            .renew_lease_v2(access, &b.profile, &lease.lease_id, &body)
            .await?,
    )?;
    let r = LeaseRenewedV2::parse(&reply.body).map_err(|_| bad("LeaseRenewedV2"))?;
    if (r.profile, r.lease) != (b.pref(), lease) {
        return Err(bad("lease_id"));
    }
    Ok(r.expires_at_ms)
}

/// The server's expiry of `lease`, on the binding that holds it.
fn keep_expiry(
    conn: &rusqlite::Connection,
    local: &str,
    lease: &LeaseRef,
    expires_at_ms: u64,
) -> Result<()> {
    conn.execute(
        "UPDATE profile_bindings SET lease_expires_at = strftime('%Y-%m-%dT%H:%M:%fZ', ?3 / 1000.0, 'unixepoch')
         WHERE local_profile_id = ?1 AND lease_id = ?2",
        params![local, hex(&lease.lease_id), wire(expires_at_ms)?],
    )?;
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
    let body = match settle(client, access, db, &op, reply)? {
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
    let body = match settle(client, access, db, op, reply)? {
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

/// Rule 6: whether the signer of the `R` that `op` commits is withdrawn, in
/// which case the lease that commit used is dropped, so a later revert walks
/// over `R` as one more proven-revoked head.
fn dropped_withdrawn_r(
    conn: &rusqlite::Connection,
    dev: &Device,
    local: &str,
    op: &Op,
) -> Result<bool> {
    let request = CommitRequestV2::parse(&op.exact).map_err(|_| bad("CommitRequestV2"))?;
    if !ledger::withdrawn_in(conn, &dev.pin.0, request.manifest().signer_signing_key_id())? {
        return Ok(false);
    }
    conn.execute(
        "UPDATE profile_bindings SET lease_id = NULL, fencing_token = NULL,
           lease_expires_at = NULL
         WHERE local_profile_id = ?1",
        [local],
    )?;
    Ok(true)
}

/// Reads the committed snapshot back (G2-38): the exact manifest, the
/// object's hash, and the listed head the receipt names. Then the binding
/// pins that head and drops the lease the commit released. A `revert`
/// commit is `R` in the same transaction: the open run below it is accepted
/// and the staged `P` waits in `revert_swaps` to replace the user's data.
#[allow(clippy::too_many_arguments)]
async fn finish(
    client: &FleetClient,
    access: &str,
    db: &mut Db,
    dev: &Device,
    b: &Bound,
    op: &Op,
    revert: bool,
    now: u64,
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
    let manifest = ok(
        client,
        access,
        client
            .snapshot_manifest(access, &b.profile, version)
            .await?,
    )?;
    if manifest.body != request.manifest().exact_bytes() {
        return Err(mismatch("manifest"));
    }
    let object = ok(
        client,
        access,
        client
            .snapshot_range(access, &b.profile, version, 0, 0)
            .await?,
    )?;
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
    let r = receipt.resulting_head_hash.to_vec();
    let tx = db
        .conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    // Judged again under the pin: the readback above awaited the network.
    if revert && dropped_withdrawn_r(&tx, dev, &b.local, op)? {
        tx.commit()?;
        return Err(signer_revoked(db, b));
    }
    tx.execute(
        "UPDATE profile_bindings SET remote_version = ?2, base_version = ?2, dirty = 0,
           last_observed_head_hash = ?3, fkek_key_id = ?4, key_generation = ?5,
           lease_id = NULL, fencing_token = NULL, lease_expires_at = NULL, sync_state = 'AVAILABLE',
           last_error_code = NULL
         WHERE local_profile_id = ?1",
        params![
            b.local,
            wire(version)?,
            r,
            s.fkek_key_id,
            wire(s.key_generation)?
        ],
    )?;
    if revert {
        tx.execute(
            "UPDATE skipped_heads SET resolution = 'ACCEPTED', accepted_head_hash = ?5,
               resolved_at_ms = ?6
             WHERE server_instance_id = ?1 AND tenant_id = ?2 AND remote_profile_id = ?3
               AND resolution IS NULL AND target_version <= ?4",
            params![
                hex(&b.instance),
                hex(&b.tenant),
                hex(&b.profile),
                wire(p.base_version)?,
                r,
                wire(now)?
            ],
        )?;
        tx.execute(
            "INSERT INTO revert_swaps(local_profile_id, accepted_version, accepted_head_hash,
               recorded_at_ms) VALUES (?1, ?2, ?3, ?4)",
            params![b.local, wire(version)?, r, wire(now)?],
        )?;
    }
    tx.commit()?;
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
        let op_id = release_op(&db.conn, b, lease, ReleaseReason::UserRelease)?;
        let op = get_op(db, &op_id)?;
        release_reply(client, access, db, b, &op).await
    };
    if let Err(e) = released.await {
        eprintln!("[sync] release: {e:#}");
    }
    err
}

/// Stores a `RELEASE_LEASE` of `lease` and returns its operation ID.
fn release_op(
    conn: &rusqlite::Connection,
    b: &Bound,
    lease: LeaseRef,
    reason: ReleaseReason,
) -> Result<String> {
    let kind = OperationKind::ReleaseLease;
    let payload = ReleaseLeaseV2 {
        profile: b.pref(),
        lease,
        reason_code: reason,
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
    // A cancelled publish has no binding for the operation to name.
    let columns = Columns {
        lease: Some(lease),
        unbound: reason == ReleaseReason::CancelPublish,
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
    let released = match settle(client, access, db, op, reply)? {
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
    // A revert lease released without its `R` keeps the quarantine (rule 6:
    // only a revert commits on top of `Jn`), as does any quarantined binding.
    tx.execute(
        "UPDATE profile_bindings SET lease_id = NULL, fencing_token = NULL, lease_expires_at = NULL,
           sync_state = CASE WHEN last_error_code = 'SIGNER_REVOKED'
             OR sync_state = 'QUARANTINED' THEN 'QUARANTINED' ELSE 'AVAILABLE' END
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
    if !is_bound(&tx, local)? {
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
    supersede(&tx, &b, None, now)?;
    tx.execute(
        "DELETE FROM profile_bindings WHERE local_profile_id = ?1",
        [local],
    )?;
    // The readback: what a retry would return, from the stored bytes alone.
    let reply = unbound_reply(&db, local)?;
    tx.commit()?;
    Ok(reply)
}

/// The [`unbind`] of a profile removed for good (a trash purge, a delete
/// that bypasses the trash; a move to the trash keeps the binding). A flow or
/// a pending operation refuses it, as it refuses an unbind, so nothing is
/// removed. A held lease, which no session is open to release, is stored as
/// a release that names no binding (with any release already pending), sent
/// best effort by the next publish, push or pull, and lapses at its TTL
/// otherwise; the binding then drops it as a sent release would. No team
/// database, or one that does not open, has no binding this could drop; one
/// whose existence cannot be checked refuses the removal
/// (`team.trustLedgerUnreadable`), so nothing is removed.
pub(crate) fn unbind_removed(local: &str) -> Result<()> {
    // An unknown existence may hide a readable binding, so it fails closed as
    // the v2.8.1 state checks do; a database that exists but does not open
    // holds no binding this launcher could read or release, as before.
    if !Db::path()?
        .try_exists()
        .context(code("team.trustLedgerUnreadable"))?
    {
        return Ok(());
    }
    let mut db = match Db::open() {
        Ok(db) => db,
        Err(e) => {
            eprintln!("[sync] binding of a removed profile: {e:#}");
            return Ok(());
        }
    };
    if !is_published(local)? {
        return Ok(());
    }
    if super::journal::flow_taken(&db, local)? {
        bail!(code("downgrade.flowTaken"));
    }
    let b = bound(&db, local)?;
    // The base its checkout or publish took, as `abandon` releases it.
    let lease = b.lease.map(|l| granted(&db, &b, &l).map_or(l, |g| g.lease));
    let release_pending = match &lease {
        Some(l) => find(&db, local, "RELEASE", Some(l), Some("PENDING"))?.is_some(),
        None => true,
    };
    let server_url: String = db.conn.query_row(
        "SELECT origin FROM server_origins WHERE server_id = ?1",
        [&b.server],
        |r| r.get(0),
    )?;
    let tx = db
        .conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let pending: bool = tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM operations WHERE local_profile_id = ?1
           AND state IN ('PENDING', 'RUNNING', 'AWAITING_RETRY')
           AND NOT (kind = 'RELEASE' AND state = 'PENDING'))",
        [local],
        |r| r.get(0),
    )?;
    if pending {
        bail!(code("sync.unbindPending"));
    }
    if let (Some(lease), false) = (lease, release_pending) {
        release_op(&tx, &b, lease, ReleaseReason::UserRelease)?;
    }
    tx.execute(
        "UPDATE operations SET local_profile_id = NULL
         WHERE local_profile_id = ?1 AND kind = 'RELEASE' AND state = 'PENDING'",
        [local],
    )?;
    tx.execute(
        "UPDATE upload_sessions SET state = 'ABORTED' WHERE local_profile_id = ?1
           AND state IN ('OPEN', 'READY')",
        [local],
    )?;
    tx.execute(
        "UPDATE profile_bindings SET lease_id = NULL, fencing_token = NULL,
           lease_expires_at = NULL WHERE local_profile_id = ?1",
        [local],
    )?;
    tx.execute(
        "DELETE FROM revert_swaps WHERE local_profile_id = ?1",
        [local],
    )?;
    tx.commit()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    unbind(local, &server_url, now).map(|_| ())
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
                    r.get::<_, Vec<u8>>(24)?,
                    r.get::<_, Vec<u8>>(25)?,
                    r.get::<_, Vec<u8>>(26)?,
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

/// One manifest of the chain as rule 6 sees it: where it sits and how its
/// signer stands.
#[derive(Clone, Debug, PartialEq)]
struct Link {
    version: u64,
    hash: [u8; 32],
    base: u64,
    previous: Option<[u8; 32]>,
    signer: [u8; 32],
    standing: Standing,
}

/// A head's signer, checked in this order (ADR 0002 rule 6): proven revoked
/// first, so a head both proven and reported revoked is a run member.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Standing {
    /// `ledger::withdrawn`: a counted `DeviceRevocationV2` or local distrust.
    Withdrawn,
    /// Only the server's unsigned report.
    Reported,
    /// No approval or `profile.commit` now, as for a lapsed signer.
    Untrusted,
    Valid,
}

/// What the revert acceptance rule makes of the next manifest.
#[derive(Debug, PartialEq)]
enum Rule {
    /// A withdrawn signer: the manifest joins the run.
    Join,
    /// A valid head with no run open: ordinary acceptance.
    Advance,
    /// A valid head `R` closing the run `J1..Jn`, which is skipped.
    Accept(Vec<Link>),
    Refuse(Refusal),
}

#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    /// A reported-only revocation: `SIGNER_REVOKED`, never a skip.
    Revoked,
    Untrusted,
    /// The manifest does not chain on what is below it.
    Gap,
}

/// ADR 0002 rule 6, "Revert acceptance rule", for `next` above the run `run`
/// (`J1..Jn`, maybe empty), itself above `anchor` (`P`, or `None` below the
/// first manifest). It does no I/O.
fn revert_rule(anchor: Option<&Link>, run: &[Link], next: &Link) -> Rule {
    let below = run.last().or(anchor);
    if next.version != below.map_or(1, |l| l.version + 1)
        || next.base + 1 != next.version
        || next.previous != below.map(|l| l.hash)
    {
        return Rule::Refuse(Refusal::Gap);
    }
    match next.standing {
        Standing::Withdrawn => Rule::Join,
        Standing::Reported => Rule::Refuse(Refusal::Revoked),
        Standing::Untrusted => Rule::Refuse(Refusal::Untrusted),
        Standing::Valid if run.is_empty() => Rule::Advance,
        Standing::Valid => Rule::Accept(run.to_vec()),
    }
}

/// A run `J1..Jn` of proven-revoked heads above its anchor `P` (version and
/// head; `None` for none), and the `R` that closed it once accepted.
struct Run {
    anchor: Option<(u64, [u8; 32])>,
    heads: Vec<Link>,
    by: Option<[u8; 32]>,
}

/// What [`walk`] found from the pin to the listed head.
#[derive(Default)]
struct Walked {
    /// `P`: the newest head accepted, or the pin while its signer is not
    /// withdrawn, or the head below a withdrawn pin (which only a revert
    /// restores), with the payload a restore needs.
    anchor: Option<(Link, SnapshotManifestV2)>,
    /// The run open at the listed head, if any.
    open: Vec<Link>,
    /// Every run skipped, with its `R`.
    accepted: Vec<Run>,
    /// Each version read, with its head.
    read: Vec<(u64, [u8; 32])>,
}

async fn manifest(
    client: &FleetClient,
    access: &str,
    b: &Bound,
    v: u64,
) -> Result<SignedSnapshotManifestV2> {
    let reply = ok(
        client,
        access,
        client.snapshot_manifest(access, &b.profile, v).await?,
    )?;
    SignedSnapshotManifestV2::parse(&reply.body).map_err(|_| bad("SignedSnapshotManifestV2"))
}

/// Rule 6 over every manifest from the pin of `b` to `head`, one forward
/// walk handing each new head to [`revert_rule`]. A pin whose signer was
/// withdrawn since it was pinned starts the run (ADR 0002 rule 6: treated
/// as a rejected head), and the walk first goes back from it to `P`, the
/// newest head below whose signer is neither withdrawn nor reported revoked.
/// A refusal writes no audit row.
#[allow(clippy::too_many_arguments)]
async fn walk(
    client: &FleetClient,
    access: &str,
    db: &mut Db,
    dev: &Device,
    chain: &shardx_core::trust_chain::TrustChain,
    keys: &std::collections::BTreeMap<[u8; 32], [u8; 32]>,
    b: &Bound,
    head: &FleetProfileHeadV2,
    now: u64,
) -> Result<Walked> {
    let untrusted = || anyhow!(code("sync.signerUntrusted"));
    let mut w = Walked::default();
    let mut prev = b.head;
    for v in b.version.max(1)..=head.current_version {
        let m = manifest(client, access, b, v).await?;
        let (hash, signer) = (m.head_hash(), *m.signer_signing_key_id());
        let withdrawn = ledger::withdrawn(db, &dev.pin.0, &signer)?;
        w.read.push((v, hash));
        if v == b.version {
            // The pinned head: its bytes were verified when they were
            // pinned (rule 6, "Pinning"), so neither its signer's grants nor
            // its epoch are re-checked, only a revocation of its signer; it
            // must still be this binding's at `v`.
            if Some(hash) != b.head {
                return Err(bad("current_signed_head_hash"));
            }
            if !withdrawn && chain.reported_revoked_at(&signer, now) {
                return Err(signer_revoked(db, b));
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
            let link = Link {
                version: v,
                hash,
                base: p.base_version,
                previous: p.previous_signed_head_hash,
                signer,
                standing: Standing::Valid,
            };
            if !withdrawn {
                w.anchor = Some((link, p));
                continue;
            }
            w.open.push(Link {
                standing: Standing::Withdrawn,
                ..link
            });
            // Only the chain and each signer's revocation matter below the
            // pin: those heads were accepted, or skipped, when first met.
            for u in (1..v).rev() {
                let m = manifest(client, access, b, u).await?;
                if Some(m.head_hash()) != w.open[0].previous {
                    return Err(bad("previous_signed_head_hash"));
                }
                w.read.push((u, m.head_hash()));
                let p = SnapshotManifestV2::parse(m.canonical_manifest_payload_bytes())
                    .map_err(|_| bad("manifest"))?;
                if p.target_version != u {
                    return Err(bad("target_version"));
                }
                let signer = *m.signer_signing_key_id();
                let mut link = Link {
                    version: u,
                    hash: m.head_hash(),
                    base: p.base_version,
                    previous: p.previous_signed_head_hash,
                    signer,
                    standing: Standing::Valid,
                };
                if ledger::withdrawn(db, &dev.pin.0, &signer)? {
                    link.standing = Standing::Withdrawn;
                    w.open.insert(0, link);
                } else if chain.reported_revoked_at(&signer, now) {
                    return Err(signer_revoked(db, b));
                } else {
                    w.anchor = Some((link, p));
                    break;
                }
            }
            if w.anchor.is_none() && w.open[0].previous.is_some() {
                return Err(bad("previous_signed_head_hash"));
            }
            continue;
        }
        let pk = keys
            .get(&signer)
            .ok_or_else(|| refused_in_walk(db, b, &w, untrusted()))?;
        let p = m
            .verify_signature(pk)
            .map_err(|_| refused_in_walk(db, b, &w, untrusted()))?
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
            return Err(refused_in_walk(db, b, &w, bad(field)));
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
            return Err(quarantine(db, &b.local, reason, anyhow!(code(key))));
        }
        let commits = |scope| chain.capability_at(&signer, Capability::ProfileCommit, scope, now);
        let standing = if withdrawn {
            Standing::Withdrawn
        } else if chain.reported_revoked_at(&signer, now) {
            Standing::Reported
        } else if !chain.approval_valid_at(&signer, Scope::Fleet(b.fleet), now)
            || !(commits(Scope::Profile(b.profile)) || commits(Scope::Fleet(b.fleet)))
        {
            Standing::Untrusted
        } else {
            Standing::Valid
        };
        let link = Link {
            version: v,
            hash,
            base: p.base_version,
            previous: p.previous_signed_head_hash,
            signer,
            standing,
        };
        let rule = revert_rule(w.anchor.as_ref().map(|(l, _)| l), &w.open, &link);
        // Generations never decrease along the trusted chain (ADR 0002
        // amendment of 2026-11-08): a head that would advance or be accepted
        // is refused below the anchor's generation, nothing pinned or
        // quarantined. A head joining the run stays revertable; the pinned
        // head and the search below a withdrawn pin are not checked here.
        if matches!(rule, Rule::Advance | Rule::Accept(_))
            && w.anchor
                .as_ref()
                .is_some_and(|(_, a)| p.key_generation < a.key_generation)
        {
            return Err(anyhow!(code_with(
                "sync.headBelowKeyGeneration",
                &[("profile", &b.local), ("signer", &hex(&signer))]
            )));
        }
        match rule {
            Rule::Join => w.open.push(link),
            Rule::Advance => w.anchor = Some((link, p)),
            Rule::Accept(heads) => {
                w.accepted.push(Run {
                    anchor: w.anchor.as_ref().map(|(l, _)| (l.version, l.hash)),
                    heads,
                    by: Some(hash),
                });
                w.open.clear();
                w.anchor = Some((link, p));
            }
            Rule::Refuse(Refusal::Revoked) => return Err(signer_revoked(db, b)),
            Rule::Refuse(Refusal::Untrusted) => {
                return Err(refused_in_walk(db, b, &w, untrusted()))
            }
            Rule::Refuse(Refusal::Gap) => {
                return Err(refused_in_walk(db, b, &w, bad("previous_signed_head_hash")))
            }
        }
        prev = Some(hash);
    }
    if prev != head.current_signed_head_hash {
        return Err(refused_in_walk(db, b, &w, bad("current_signed_head_hash")));
    }
    Ok(w)
}

/// [`walk`] from `b`'s pin to `head` under the trust evidence of `b`'s
/// tenant, recorded first so a revocation it carries counts in the walk.
async fn walked(
    client: &FleetClient,
    access: &str,
    db: &mut Db,
    dev: &Device,
    b: &Bound,
    head: &FleetProfileHeadV2,
    now: u64,
) -> Result<Walked> {
    let untrusted = || anyhow!(code("sync.signerUntrusted"));
    // The evidence holds a device's approvals and capability grants only
    // when it is a root grant subject or a signer asked for (`v2_trust`):
    // ask for the signer of every head the walk reads.
    // shortcut: each manifest is read twice; pass them to `walk` if a long
    // walk shows up in profiling.
    // shortcut: the server takes at most 64 signers (`MAX_SIGNERS`), so a
    // walk naming more fails closed here, and a page at most
    // `MAX_PAGE_CONTAINERS` (1024) keys, refused fail-closed; fetch the
    // evidence in batches of signers once a walk can span more (v2.11).
    let mut signers = std::collections::BTreeSet::new();
    for v in b.version.max(1)..=head.current_version {
        signers.insert(
            *manifest(client, access, b, v)
                .await?
                .signer_signing_key_id(),
        );
    }
    if signers.len() > crate::fleet_custody::MAX_SIGNERS {
        bail!(code("sync.walkTooManySigners"));
    }
    let signers: Vec<[u8; 32]> = signers.into_iter().collect();
    // D12: a closure this walk triggers names its head signers too.
    let (pages, closure) =
        ledger::closure_evidence(client, access, &hex(&b.tenant), db, &dev.pin, &signers, now)
            .await?;
    let (seen, chain) =
        ledger::evaluate(db, &dev.pin.0, &dev.pin.1, &pages, now)?.ok_or_else(untrusted)?;
    ledger::record(db, &dev.pin.0, &seen, &chain, None, closure, now)?;
    let keys: std::collections::BTreeMap<[u8; 32], [u8; 32]> = pages
        .iter()
        .flat_map(|p| &p.signing_public_keys)
        .map(|pk| (shardx_core::keys::signing_key_id(pk), *pk))
        .collect();
    walk(client, access, db, dev, &chain, &keys, b, head, now).await
}

/// Files the run `w` left open at the listed head, unresolved above its
/// `P`, with the runs `accepted` below it (a revert pins past them), and
/// quarantines `b` with `SIGNER_REVOKED`, in one transaction.
fn hold_open(db: &mut Db, b: &Bound, w: &Walked, accepted: &[Run], now: u64) -> Result<()> {
    let open = Run {
        anchor: w.anchor.as_ref().map(|(l, _)| (l.version, l.hash)),
        heads: w.open.clone(),
        by: None,
    };
    let tx = db
        .conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    for run in accepted {
        skip(&tx, b, run, now)?;
    }
    skip(&tx, b, &open, now)?;
    supersede(&tx, b, Some(&w.read), now)?;
    tx.execute(
        "UPDATE profile_bindings SET sync_state = 'QUARANTINED', last_error_code = 'SIGNER_REVOKED'
         WHERE local_profile_id = ?1",
        [&b.local],
    )?;
    tx.commit()?;
    Ok(())
}

/// Files each head of `run` in the skip audit (ADR 0002 rule 6): open, or
/// accepted by its `R`, which also resolves the open row it may have.
fn skip(tx: &rusqlite::Connection, b: &Bound, run: &Run, now: u64) -> Result<()> {
    let (instance, tenant, profile) = (hex(&b.instance), hex(&b.tenant), hex(&b.profile));
    let (anchor, anchor_head) = match run.anchor {
        Some((v, h)) => (v, Some(h.to_vec())),
        None => (0, None),
    };
    let by = run.by.map(|h| h.to_vec());
    for j in &run.heads {
        let resolved = tx.execute(
            "UPDATE skipped_heads SET resolution = 'ACCEPTED', accepted_head_hash = ?6,
               resolved_at_ms = ?7
             WHERE server_instance_id = ?1 AND tenant_id = ?2 AND remote_profile_id = ?3
               AND target_version = ?4 AND head_hash = ?5 AND resolution IS NULL
               AND ?6 IS NOT NULL",
            params![
                instance,
                tenant,
                profile,
                wire(j.version)?,
                j.hash.to_vec(),
                by,
                wire(now)?
            ],
        )?;
        if resolved == 1 {
            continue;
        }
        // Not ON CONFLICT: the insert-once trigger refuses an open head. A
        // head whose earlier row was resolved opens a new one, unless it was
        // accepted by this same `R` (a retried revert crosses it again).
        tx.execute(
            "INSERT INTO skipped_heads(server_instance_id, tenant_id, remote_profile_id,
               local_profile_id, target_version, head_hash, signer_signing_key_id,
               anchor_version, anchor_head_hash, resolution, accepted_head_hash,
               recorded_at_ms, resolved_at_ms)
             SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
               CASE WHEN ?10 IS NULL THEN NULL ELSE 'ACCEPTED' END, ?10, ?11,
               CASE WHEN ?10 IS NULL THEN NULL ELSE ?11 END
             WHERE NOT EXISTS (SELECT 1 FROM skipped_heads
               WHERE server_instance_id = ?1 AND tenant_id = ?2 AND remote_profile_id = ?3
                 AND target_version = ?5 AND head_hash = ?6 AND (resolution IS NULL
                   OR (?10 IS NOT NULL AND resolution = 'ACCEPTED'
                     AND accepted_head_hash = ?10)))",
            params![
                instance,
                tenant,
                profile,
                b.local,
                wire(j.version)?,
                j.hash.to_vec(),
                hex(&j.signer),
                wire(anchor)?,
                anchor_head,
                by,
                wire(now)?
            ],
        )?;
    }
    Ok(())
}

/// Supersedes the open audit rows of `b`'s remote profile, once: at every
/// version for `None` (a restore epoch transition or an unbind ends them),
/// or where the walk read another head at the row's version.
fn supersede(
    tx: &rusqlite::Connection,
    b: &Bound,
    read: Option<&[(u64, [u8; 32])]>,
    now: u64,
) -> Result<()> {
    let (instance, tenant, profile) = (hex(&b.instance), hex(&b.tenant), hex(&b.profile));
    let sql = "UPDATE skipped_heads SET resolution = 'SUPERSEDED', resolved_at_ms = ?4
         WHERE server_instance_id = ?1 AND tenant_id = ?2 AND remote_profile_id = ?3
           AND resolution IS NULL AND (?5 IS NULL OR (target_version = ?5 AND head_hash != ?6))";
    let Some(read) = read else {
        tx.execute(
            sql,
            params![
                instance,
                tenant,
                profile,
                wire(now)?,
                None::<i64>,
                None::<Vec<u8>>
            ],
        )?;
        return Ok(());
    };
    for (v, h) in read {
        tx.execute(
            sql,
            params![instance, tenant, profile, wire(now)?, wire(*v)?, h.to_vec()],
        )?;
    }
    Ok(())
}

/// Pins `p` (head `hash`) over the version `b` pinned, with the runs
/// `accepted` filed as skipped, stale open rows superseded and the swap of
/// the staged `p` in `revert_swaps`, in one transaction. `lift` ends a
/// `SIGNER_REVOKED` quarantine: a run was accepted and the walk ended on an
/// accepted head. A binding no longer at `b`'s version refuses with
/// `sync.bindingChanged`; a `signer` withdrawn since the walk pins nothing
/// and quarantines with `SIGNER_REVOKED`.
#[allow(clippy::too_many_arguments)]
fn pin(
    db: &mut Db,
    dev: &Device,
    b: &Bound,
    (hash, signer): ([u8; 32], [u8; 32]),
    p: &SnapshotManifestV2,
    accepted: &[Run],
    read: &[(u64, [u8; 32])],
    lift: bool,
    now: u64,
) -> Result<()> {
    let tx = db
        .conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    // Rule 6: the head's signer is judged again under the pin, since another
    // ledger writer may have withdrawn it while the snapshot downloaded.
    if ledger::withdrawn_in(&tx, &dev.pin.0, &signer)? {
        drop(tx);
        return Err(signer_revoked(db, b));
    }
    let moved = tx.execute(
        "UPDATE profile_bindings SET remote_version = ?2, base_version = ?2, dirty = 0,
           last_observed_head_hash = ?3, fkek_key_id = ?5, key_generation = ?6,
           sync_state = CASE WHEN ?7 AND last_error_code IS 'SIGNER_REVOKED'
             THEN 'AVAILABLE' ELSE sync_state END,
           last_error_code = CASE WHEN ?7 AND last_error_code IS 'SIGNER_REVOKED'
             THEN NULL ELSE last_error_code END
         WHERE local_profile_id = ?1 AND remote_version = ?4",
        params![
            b.local,
            wire(p.target_version)?,
            hash.to_vec(),
            wire(b.version)?,
            hex(&p.fkek_key_id),
            wire(p.key_generation)?,
            lift
        ],
    )?;
    if moved == 0 {
        bail!(code("sync.bindingChanged"));
    }
    for run in accepted {
        skip(&tx, b, run, now)?;
    }
    supersede(&tx, b, Some(read), now)?;
    tx.execute(
        "INSERT INTO revert_swaps(local_profile_id, accepted_version, accepted_head_hash,
           recorded_at_ms) VALUES (?1, ?2, ?3, ?4)",
        params![b.local, wire(p.target_version)?, hash.to_vec(), wire(now)?],
    )?;
    tx.commit()?;
    Ok(())
}

/// Empties `staging` and seeds it with `udd`'s `Local State`, which no
/// snapshot carries: `unpack` keeps the os_crypt key and the browser-level
/// state only from the directory it unpacks over, and the swap replaces `udd`.
fn fresh_staging(udd: &Path, staging: &Path) -> Result<()> {
    if staging.try_exists()? {
        std::fs::remove_dir_all(staging)?;
    }
    std::fs::create_dir_all(staging)?;
    let live = udd.join("Local State");
    if live.try_exists()? {
        std::fs::copy(&live, staging.join("Local State"))?;
    }
    Ok(())
}

/// Restores `p` into `<udd>.revert-staging`, then `pin`s it, then swaps it
/// into `udd` as a revert does ([`settle_revert_swap`], also at launch): a
/// restore or pin that fails leaves `udd` as it was and the staging gone.
#[allow(clippy::too_many_arguments)]
async fn restore_then_pin(
    client: &FleetClient,
    access: &str,
    db: &mut Db,
    b: &Bound,
    p: &SnapshotManifestV2,
    fkek: Zeroizing<[u8; 32]>,
    udd: &Path,
    pin_to: impl FnOnce(&mut Db) -> Result<()>,
) -> Result<u64> {
    let staging = beside(udd, REVERT_STAGING);
    let staged = async {
        // No swap is pending (settled first) and no lease held: a leftover.
        fresh_staging(udd, &staging)?;
        let restored = restore(client, access, b, p, fkek, &staging).await?;
        pin_to(db)?;
        Ok::<_, anyhow::Error>(restored)
    }
    .await;
    match staged {
        Ok(restored) => {
            settle_revert_swap(&b.local, udd)?;
            Ok(restored)
        }
        Err(e) => {
            if let Err(d) = discard_revert_staging(&b.local, udd) {
                eprintln!("[sync] pull staging: {d:#}");
            }
            Err(e)
        }
    }
}

/// Fetches the ciphertext of `p` by `Range`, opens it under `fkek` and
/// unpacks it into `udd`. The plaintext size.
async fn restore(
    client: &FleetClient,
    access: &str,
    b: &Bound,
    p: &SnapshotManifestV2,
    fkek: Zeroizing<[u8; 32]>,
    udd: &Path,
) -> Result<u64> {
    let plaintext = opened(client, access, b, p, fkek).await?;
    let target = udd.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<u64> {
        shardx_core::snapshot::unpack(&plaintext, &target)?;
        Ok(plaintext.len() as u64)
    })
    .await
    .map_err(|e| {
        anyhow!(code_with(
            "sync.restoreTaskFailed",
            &[("error", &e.to_string())]
        ))
    })?
}

/// Fetches the ciphertext of `p` by `Range` and opens it under `fkek`: the
/// plaintext a restore unpacks, or a re-seal seals again.
async fn opened(
    client: &FleetClient,
    access: &str,
    b: &Bound,
    p: &SnapshotManifestV2,
    fkek: Zeroizing<[u8; 32]>,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut object = Vec::with_capacity(p.ciphertext_size as usize);
    let etag = format!("\"{}\"", hex(&p.ciphertext_sha256));
    while (object.len() as u64) < p.ciphertext_size {
        let start = object.len() as u64;
        let end = (start + CHUNK as u64).min(p.ciphertext_size) - 1;
        let reply = ok(
            client,
            access,
            client
                .snapshot_range(access, &b.profile, p.target_version, start, end)
                .await?,
        )?;
        if reply.headers.get("etag").and_then(|h| h.to_str().ok()) != Some(etag.as_str())
            || reply.body.len() as u64 != end - start + 1
        {
            return Err(bad("range"));
        }
        object.extend_from_slice(&reply.body);
    }
    let p = p.clone();
    tokio::task::spawn_blocking(move || -> Result<Zeroizing<Vec<u8>>> {
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
        Ok(plaintext)
    })
    .await
    .map_err(|e| {
        anyhow!(code_with(
            "sync.restoreTaskFailed",
            &[("error", &e.to_string())]
        ))
    })?
}

/// Pulls the listed head of the published profile `local` into `udd`: every
/// manifest since the pinned head verified (rule 6), the ciphertext fetched
/// by `Range`, opened under a key that reverifies now, and the head pinned.
/// A run of heads whose signers are proven revoked is skipped once a valid
/// `R` follows it; a run still open at the listed head quarantines the
/// binding with `SIGNER_REVOKED`, after the pin advances to `P`.
pub(crate) async fn pull(
    client: &FleetClient,
    access: &str,
    dev: &Device,
    local: &str,
    udd: &Path,
    now: u64,
) -> Result<u64> {
    settle_revert_swap(local, udd)?;
    let mut db = Db::open()?;
    retry_unbound_releases(client, access, &mut db).await;
    let mut b = bound(&db, local)?;
    if awaits_transition(&b) {
        accept_transitions(client, access, dev, &mut db, &b, now).await?;
        b = bound(&db, local)?;
    }
    // A revoked signer's quarantine is walked again: rule 6 accepts a revert
    // over it, or advances the pin to `P`.
    if b.error.as_deref() != Some(SIGNER_REVOKED) {
        refuse_quarantined(&b)?;
    }
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
    let w = walked(client, access, &mut db, dev, &b, &head, now).await?;
    if !w.open.is_empty() {
        // Owner decision B: the open run and the quarantine are kept first;
        // then a `P` past the pin is pulled as any valid head is (rule 6:
        // advance over valid heads first). `P` may be of a generation a
        // rotation since replaced, so its key is read through `readable_key`.
        // `pin` files the accepted runs, with `P`.
        hold_open(&mut db, &b, &w, &[], now)?;
        if let Some((at, p)) = &w.anchor {
            if at.version > b.version {
                let fkek = readable_key(
                    &db,
                    dev,
                    &b.fleet,
                    p.key_generation,
                    Some(&p.fkek_key_id),
                    now,
                )?;
                restore_then_pin(client, access, &mut db, &b, p, fkek, udd, |db| {
                    let head = (at.hash, at.signer);
                    pin(db, dev, &b, head, p, &w.accepted, &w.read, false, now)
                })
                .await?;
                // The user is told the profile now holds `P`.
                bail!(code("sync.signerRevokedAtP"));
            }
        }
        bail!(code("sync.signerRevoked"));
    }
    if b.error.as_deref() == Some(SIGNER_REVOKED) && w.accepted.is_empty() {
        // Only an accepted `R` lifts the quarantine (ADR 0002 rule 6: a
        // reported-only revocation has no acceptance path); nothing moves.
        let tx = db
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        supersede(&tx, &b, Some(&w.read), now)?;
        tx.commit()?;
        bail!(code("sync.signerRevoked"));
    }
    let Some((at, p)) = w.anchor else {
        return Err(bad("manifest"));
    };
    // A head sealed before a rotation is still read; `walk` refused any
    // generation below the anchor's.
    let fkek = readable_key(
        &db,
        dev,
        &b.fleet,
        p.key_generation,
        Some(&p.fkek_key_id),
        now,
    )?;
    let lift = !w.accepted.is_empty();
    restore_then_pin(client, access, &mut db, &b, &p, fkek, udd, |db| {
        let head = (at.hash, at.signer);
        pin(db, dev, &b, head, &p, &w.accepted, &w.read, lift, now)
    })
    .await
}

// ------------------------------------------------------------- re-seal ----

/// The binding a re-seal makes for a listed profile no binding here names
/// (v2.10 4.S): walked and pinned without a restore, removed once its
/// outcome is final. Every reader that lists profiles leaves it out
/// (`NOT GLOB 'reseal:*'`).
fn reseal_row(profile: &[u8; 16]) -> String {
    format!("reseal:{}", hex(profile))
}

/// The binding of `profile` under `dev`'s pinned instance and tenant, a
/// re-seal row included: the UNIQUE constraint allows one.
fn local_of(db: &Db, dev: &Device, profile: &[u8; 16]) -> Result<Option<String>> {
    Ok(db
        .conn
        .query_row(
            "SELECT local_profile_id FROM profile_bindings
             WHERE server_instance_id = ?1 AND tenant_id = ?2 AND remote_profile_id = ?3",
            params![
                hex(&dev.pin.0.server_instance_id),
                hex(&dev.pin.0.tenant_id),
                hex(profile)
            ],
            |r| r.get(0),
        )
        .optional()?)
}

/// Whether `local` holds a lease or a pending operation: a push in flight.
fn in_flight(db: &Db, local: &str) -> Result<bool> {
    Ok(db.conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM profile_bindings
             WHERE local_profile_id = ?1 AND lease_id IS NOT NULL)
           OR EXISTS (SELECT 1 FROM operations
             WHERE local_profile_id = ?1 AND state = 'PENDING')",
        [local],
        |r| r.get(0),
    )?)
}

/// Removes the re-seal row of `profile` a run left, unless a push of it is
/// in flight (`sync.resealInProgress`).
fn drop_reseal_row(profile: &[u8; 16]) -> Result<()> {
    let row = reseal_row(profile);
    if !is_published(&row)? {
        return Ok(());
    }
    if in_flight(&Db::open()?, &row)? {
        bail!(code("sync.resealInProgress"));
    }
    unbind_removed(&row)
}

/// Removes every re-seal row whose profile has no pending outcome in `run`.
fn drop_final_rows(run: &ResealRun) -> Result<()> {
    let rows: Vec<String> = Db::open()?
        .conn
        .prepare(
            "SELECT local_profile_id FROM profile_bindings
             WHERE local_profile_id GLOB 'reseal:*'",
        )?
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    for row in rows {
        let id = row.trim_start_matches("reseal:");
        if run.profiles.get(id).is_some_and(|o| reseal_pending(o)) {
            continue;
        }
        if let Err(e) = unbind_removed(&row) {
            eprintln!("[reseal] profile {id}: row kept ({})", first_code(&e));
        }
    }
    Ok(())
}

/// An outcome a later run resumes: `walking`, or `sealing:<version>:<head>`
/// saved right before the head at `version` is sealed again.
pub(crate) fn reseal_pending(outcome: &str) -> bool {
    outcome == "walking" || outcome.starts_with("sealing:")
}

/// The version and head a `sealing:` outcome saved.
fn sealing_base(outcome: &str) -> Option<(u64, [u8; 32])> {
    let (v, h) = outcome.strip_prefix("sealing:")?.split_once(':')?;
    Some((
        v.parse().ok()?,
        crate::fleet_client::decode_hex32(h, "head").ok()?,
    ))
}

/// The first error code `e` carries, for a `skipped:error:<code>` outcome
/// and the `[reseal]` log: a code, never the message.
fn first_code(e: &anyhow::Error) -> String {
    let text = format!("{e:#}");
    text.split("[[shardx:")
        .nth(1)
        .and_then(|r| r.split(['|', ']']).next())
        .unwrap_or("unknown")
        .to_string()
}

const IN_USE: &str = "skipped:in-use";
const QUARANTINED: &str = "skipped:quarantined";

/// Re-seal all profiles (v2.10 4.S) as the tenant's root custodian, or
/// resume the run: every head this fleet lists or this device binds that is
/// sealed under a generation below the highest verified one, `G`, or signed
/// by `outgoing` (a hand-over's outgoing custodian) is opened from its
/// ciphertext and committed again under `G` through the ops journal, with no
/// profile folder; never a second commit for one profile, on resume either.
/// A bound profile is held by `claim` for its step (`None`: running); one in
/// use, in error or quarantined, or whose head no key here opens, is skipped
/// and listed. Each outcome is saved through `save` before its step.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn reseal_all(
    client: &FleetClient,
    access: &str,
    dev: &Device,
    fleet: [u8; 16],
    outgoing: Option<[u8; 32]>,
    claim: &(dyn Fn(&str) -> Option<Box<dyn Send>> + Sync),
    now: u64,
    save: &mut (dyn FnMut(&FleetCustodyState) -> Result<()> + Send),
) -> Result<ResealRun> {
    let started = std::time::Instant::now();
    let root = crate::root_bootstrap::load()?;
    let custodian = root.activated
        && root
            .tenant_id
            .eq_ignore_ascii_case(&hex(&dev.pin.0.tenant_id))
        && root.device_id.eq_ignore_ascii_case(&hex(&dev.me.device_id))
        && crate::root_bootstrap::current_root_grant(&root, &dev.signer).is_ok();
    if !custodian {
        bail!(code("sync.resealNotCustodian"));
    }
    let mut state = crate::fleet_custody::load()?;
    if !state.handed_over_to.is_empty() {
        bail!(code("fleet.custodyHandedOver"));
    }
    let g = {
        let db = Db::open()?;
        let g = ledger::highest_generation(&db, &dev.pin.0, &fleet)?
            .ok_or_else(|| anyhow!(code("sync.noVerifiedFleetKey")))?;
        verified_key(&db, dev, &fleet, g, None, now)?;
        if ledger::commit_blocked(&db, &dev.pin.0, &dev.pin.1, &fleet, g)? {
            bail!(code("sync.commitBlockedCompromised"));
        }
        g
    };
    // A run of `G` with pending outcomes resumes its list; a new run lists
    // what the fleet lists and this device binds, keeping what an earlier
    // run left pending, and saves that list once.
    let mut run = match state.reseal.take() {
        Some(r) if r.generation == g && r.profiles.values().any(|o| reseal_pending(o)) => r,
        previous => {
            let mut ids = std::collections::BTreeSet::new();
            fleet_pages(client, access, &unbound("", dev, fleet, [0; 16]), |p| {
                ids.insert(hex(&p.profile_id));
                true
            })
            .await?;
            let db = Db::open()?;
            let bound: Vec<String> = db
                .conn
                .prepare(
                    "SELECT remote_profile_id FROM profile_bindings
                     WHERE server_instance_id = ?1 AND tenant_id = ?2 AND fleet_id = ?3
                       AND local_profile_id NOT GLOB 'reseal:*'",
                )?
                .query_map(
                    params![
                        hex(&dev.pin.0.server_instance_id),
                        hex(&dev.pin.0.tenant_id),
                        hex(&fleet)
                    ],
                    |r| r.get(0),
                )?
                .collect::<rusqlite::Result<_>>()?;
            ids.extend(bound);
            let mut profiles: std::collections::BTreeMap<String, String> = previous
                .map(|r| r.profiles)
                .unwrap_or_default()
                .into_iter()
                .filter(|(_, o)| reseal_pending(o))
                .collect();
            for id in ids {
                profiles.entry(id).or_insert_with(|| "walking".into());
            }
            ResealRun {
                generation: g,
                outgoing: outgoing.map(|k| hex(&k)).unwrap_or_default(),
                started_ms: now,
                ended_ms: None,
                profiles,
            }
        }
    };
    run.ended_ms = None;
    // A resumed run keeps the outgoing custodian it started with.
    let outgoing = (!run.outgoing.is_empty())
        .then(|| crate::fleet_client::decode_hex32(&run.outgoing, "outgoing"))
        .transpose()?;
    let ids: Vec<String> = run
        .profiles
        .iter()
        .filter(|(_, o)| reseal_pending(o))
        .map(|(id, _)| id.clone())
        .collect();
    eprintln!("[reseal] generation {g}: {} profiles to check", ids.len());
    drop_final_rows(&run)?;
    state.reseal = Some(run);
    save(&state)?;
    for id in ids {
        let profile = decode_hex16(&id, "remote_profile_id")?;
        let outcome_now = |s: &FleetCustodyState| {
            s.reseal
                .as_ref()
                .and_then(|r| r.profiles.get(&id).cloned())
                .unwrap_or_default()
        };
        let saved = outcome_now(&state);
        let mut mark = |o: &str| -> Result<()> {
            if let Some(r) = state.reseal.as_mut() {
                r.profiles.insert(id.clone(), o.to_string());
            }
            save(&state)
        };
        let step = reseal_one(
            client, access, dev, fleet, profile, g, outgoing, claim, &saved, now, &mut mark,
        )
        .await;
        let outcome = match step {
            Ok(o) => o,
            Err(e) => {
                let pending = outcome_now(&state);
                let db = Db::open()?;
                let flying = match local_of(&db, dev, &profile)? {
                    Some(local) => in_flight(&db, &local)?,
                    None => false,
                };
                eprintln!("[reseal] profile {id}: {}", first_code(&e));
                // A push the journal resumes stays pending: the next run
                // resends its stored requests.
                if pending.starts_with("sealing:") && flying {
                    pending
                } else {
                    format!("skipped:error:{}", first_code(&e))
                }
            }
        };
        eprintln!("[reseal] profile {id}: {outcome}");
        if let Some(r) = state.reseal.as_mut() {
            r.profiles.insert(id.clone(), outcome);
        }
        save(&state)?;
    }
    let mut run = state.reseal.clone().unwrap_or_default();
    drop_final_rows(&run)?;
    run.ended_ms = Some(now + started.elapsed().as_millis() as u64);
    let left = run.profiles.values().filter(|o| reseal_pending(o)).count();
    eprintln!("[reseal] generation {g}: done, {left} pending");
    state.reseal = Some(run.clone());
    save(&state)?;
    Ok(run)
}

/// One profile of [`reseal_all`]: its outcome. An error before its push, or
/// a push left in flight, is the caller's to file.
#[allow(clippy::too_many_arguments)]
async fn reseal_one(
    client: &FleetClient,
    access: &str,
    dev: &Device,
    fleet: [u8; 16],
    profile: [u8; 16],
    g: u64,
    outgoing: Option<[u8; 32]>,
    claim: &(dyn Fn(&str) -> Option<Box<dyn Send>> + Sync),
    saved: &str,
    now: u64,
    mark: &mut (dyn FnMut(&str) -> Result<()> + Send),
) -> Result<String> {
    let mut db = Db::open()?;
    let ours = saved.starts_with("sealing:");
    let mut _held = None;
    let local = match local_of(&db, dev, &profile)? {
        Some(local) if !local.starts_with("reseal:") => {
            let Some(guard) = claim(&local) else {
                return Ok(IN_USE.into());
            };
            _held = Some(guard);
            let b = bound(&db, &local)?;
            let flying = in_flight(&db, &local)?;
            if !(ours && flying) {
                if b.state == "QUARANTINED" {
                    return Ok(QUARANTINED.into());
                }
                if let Some(e) = &b.error {
                    return Ok(format!("skipped:error:{e}"));
                }
                let changed: bool = db.conn.query_row(
                    "SELECT dirty OR base_version < remote_version FROM profile_bindings
                     WHERE local_profile_id = ?1",
                    [&local],
                    |r| r.get(0),
                )?;
                if flying || changed {
                    return Ok(IN_USE.into());
                }
            }
            local
        }
        Some(row) => row,
        None => {
            let row = reseal_row(&profile);
            bind(client, access, dev, &mut db, &row, fleet, profile, now).await?;
            row
        }
    };
    let mut b = bound(&db, &local)?;
    let plaintext = if ours && in_flight(&db, &local)? {
        // A crash mid-push: the journal resumes as stored. The head it seals
        // is still the pin, opened again for an upload not yet sealed.
        let m = manifest(client, access, &b, b.version).await?;
        if Some(m.head_hash()) != b.head {
            return Err(bad("current_signed_head_hash"));
        }
        let p = SnapshotManifestV2::parse(m.canonical_manifest_payload_bytes())
            .map_err(|_| bad("manifest"))?;
        let fkek = readable_key(
            &db,
            dev,
            &fleet,
            p.key_generation,
            Some(&p.fkek_key_id),
            now,
        )?;
        opened(client, access, &b, &p, fkek).await?
    } else {
        if awaits_transition(&b) {
            accept_transitions(client, access, dev, &mut db, &b, now).await?;
            b = bound(&db, &local)?;
        }
        if b.state == "QUARANTINED" {
            return Ok(QUARANTINED.into());
        }
        let head = match listed(client, access, &mut db, &b).await {
            // A listing that shows a restore quarantines; it is accepted at once.
            Err(_) if awaits_transition(&bound(&db, &local)?) => {
                b = bound(&db, &local)?;
                accept_transitions(client, access, dev, &mut db, &b, now).await?;
                b = bound(&db, &local)?;
                listed(client, access, &mut db, &b).await?
            }
            head => head?,
        };
        if head.current_version == 0 {
            return Ok("current".into());
        }
        let w = match walked(client, access, &mut db, dev, &b, &head, now).await {
            Ok(w) => w,
            Err(_) if bound(&db, &local)?.state == "QUARANTINED" => return Ok(QUARANTINED.into()),
            Err(e) => return Ok(format!("skipped:error:{}", first_code(&e))),
        };
        // Rule 6: an open run is a revert's to close, never a re-seal's.
        if !w.open.is_empty() {
            return Ok(QUARANTINED.into());
        }
        let Some((at, p)) = w.anchor else {
            return Err(bad("manifest"));
        };
        // 4.S step 4: this run's commit, whose reply or state write was lost.
        if let Some((v, h)) = sealing_base(saved) {
            if at.version == v + 1
                && at.previous == Some(h)
                && at.signer == dev.me.signing_key_id
                && p.key_generation == g
            {
                return Ok(format!("resealed:{}", at.version));
            }
        }
        if p.key_generation >= g && outgoing != Some(at.signer) {
            return Ok("current".into());
        }
        let Ok(fkek) = readable_key(
            &db,
            dev,
            &fleet,
            p.key_generation,
            Some(&p.fkek_key_id),
            now,
        ) else {
            return Ok("skipped:older-key-not-held".into());
        };
        if at.version != b.version {
            // A bound copy behind the head holds data a pull would replace.
            if !local.starts_with("reseal:") {
                return Ok(IN_USE.into());
            }
            let lift = !w.accepted.is_empty();
            pin(
                &mut db,
                dev,
                &b,
                (at.hash, at.signer),
                &p,
                &w.accepted,
                &w.read,
                lift,
                now,
            )?;
            // No restore follows, so no swap is pending.
            db.conn.execute(
                "DELETE FROM revert_swaps WHERE local_profile_id = ?1",
                [&local],
            )?;
            b = bound(&db, &local)?;
        }
        // A restore transition accepted above moves the pin and not
        // `base_version`: the copy is then behind the head, and a commit on
        // it would clear the mark that makes the next push ask for a Pull.
        let behind: bool = db.conn.query_row(
            "SELECT base_version < remote_version FROM profile_bindings
             WHERE local_profile_id = ?1",
            [&local],
            |r| r.get(0),
        )?;
        if behind && !local.starts_with("reseal:") {
            return Ok(IN_USE.into());
        }
        mark(&format!("sealing:{}:{}", at.version, hex(&at.hash)))?;
        opened(client, access, &b, &p, fkek).await?
    };
    drop(db);
    let started = std::time::Instant::now();
    let clock = || started.elapsed();
    let src = Plain::Opened(&plaintext);
    match push_inner(client, access, dev, &local, src, now, &clock, None).await {
        Ok(pushed) => Ok(format!("resealed:{}", pushed.version)),
        Err(e) if in_flight(&Db::open()?, &local)? => Err(e),
        Err(e) => {
            let text = format!("{e:#}");
            if text.contains("LEASE_HELD") || crate::errcode::has_code(&text, "sync.remoteAhead") {
                Ok(IN_USE.into())
            } else {
                Ok(format!("skipped:error:{}", first_code(&e)))
            }
        }
    }
}

/// Checks out the published `local` as a push does and keeps the lease: a
/// lease another device holds, for the real-server tests.
#[cfg(test)]
pub(crate) async fn check_out(client: &FleetClient, access: &str, local: &str) -> Result<()> {
    let mut db = Db::open()?;
    let b = bound(&db, local)?;
    let now = crate::root_bootstrap::now_ms();
    checkout(client, access, &mut db, &b, false, now).await
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
    use shardx_core::trust_evidence::{RevokedDevice, TenantTrustEvidencePageV2};
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

    /// A signer's public key and the containers served for it.
    type Named = ([u8; 32], Vec<Vec<u8>>);

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
        /// The body of a refused reply, when not `refused`.
        refused_body: Option<Vec<u8>>,
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
        /// The `expires_at_ms` a renewal grants, when not `T0`.
        renewed: Option<u64>,
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
        /// SQL another writer runs on the launcher's database when the next
        /// PATCH is served.
        on_patch: Option<String>,
        /// SQL another writer runs on the launcher's database when the next
        /// checkout is served.
        on_checkout: Option<String>,
        /// `PROFILE` is not yet published: the listing omits it until a
        /// publish-create makes it.
        fresh: bool,
        /// The profiles publish-create made, in order.
        published: Vec<[u8; 16]>,
        /// The label publish-create sealed for `PROFILE`, which the list reports.
        label: Option<Vec<u8>>,
        /// SQL another writer runs on the launcher's database when the next
        /// fleet listing is served.
        on_list: Option<String>,
        /// SQL another ledger writer runs when a snapshot object is served.
        on_snapshot: Option<String>,
        /// Trust evidence served only to a request naming its signer: the
        /// signer's public key and containers, by signing key ID.
        named: HashMap<[u8; 32], Named>,
        /// The signers each trust evidence request named, while `named` is set.
        asked: Vec<Vec<[u8; 32]>>,
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
                        profiles: (!self.fresh)
                            .then_some(FleetProfileHeadV2 {
                                profile_id: PROFILE,
                                current_version: version,
                                current_signed_head_hash: head,
                                key_generation: GEN,
                                label_ciphertext: self.label.clone().unwrap_or(vec![1]),
                            })
                            .into_iter()
                            .chain(self.others.iter().cloned())
                            .collect(),
                        next_after: None,
                    };
                    reply(200, &[], page.encode())
                }
                ("GET", ["v2", "tenants", _, "trust-evidence"]) => {
                    reply(200, &[], self.pages.clone())
                }
                ("POST", ["v2", "fleets", _, "profiles"]) => {
                    let (st, out) =
                        self.mutation(body, 201, RECORD_TYPE_PUBLISH_CREATED, |f, p| {
                            let c = ProfilePublishCreateV2::parse(p).map_err(|_| 422u16)?;
                            let active = (
                                f.generation.unwrap_or(GEN),
                                f.fkek_key_id.unwrap_or_else(|| {
                                    shardx_core::fleet_grants::fkek_key_id(&FKEK)
                                }),
                            );
                            if (c.key_generation, c.fkek_key_id) != active {
                                return Err(409);
                            }
                            if c.profile.profile_id == PROFILE && !f.fresh {
                                return Err(409);
                            }
                            f.fresh = false;
                            if c.profile.profile_id == PROFILE {
                                f.label = Some(c.label_ciphertext.clone());
                            }
                            f.published.push(c.profile.profile_id);
                            f.fence = 1;
                            let lease = LeaseRef {
                                lease_id: random().unwrap(),
                                fencing_token: 1,
                                base_version: 0,
                            };
                            f.lease = Some(lease);
                            Ok(ProfileLeaseV2 {
                                profile: c.profile,
                                lease,
                                expires_at_ms: f.expires.unwrap_or(NOW + 300_000),
                                fkek_key_id: c.fkek_key_id,
                                key_generation: c.key_generation,
                                current_signed_head_hash: None,
                                server_instance_id: INSTANCE,
                                restore_epoch: f.epoch,
                            }
                            .encode(LeaseOrigin::PublishCreate))
                        });
                    if let Some(t) = self.tamper.filter(|t| t.starts_with("publish-")) {
                        if st == 201 {
                            let mut r = IdempotentStoredResponseV2::parse(&out).unwrap();
                            let mut g = ProfileLeaseV2::parse(
                                LeaseOrigin::PublishCreate,
                                &r.canonical_response_payload_bytes,
                            )
                            .unwrap();
                            match t {
                                "publish-profile" => g.profile.profile_id = [0xee; 16],
                                "publish-tenant" => g.profile.tenant_id = [0xee; 16],
                                "publish-fleet" => g.profile.fleet_id = [0xee; 16],
                                "publish-key" => g.fkek_key_id = [0xee; 32],
                                "publish-generation" => g.key_generation += 1,
                                "publish-fence" => g.lease.fencing_token = 2,
                                "publish-instance" => g.server_instance_id = [0xee; 16],
                                "publish-epoch" => g.restore_epoch += 1,
                                "publish-hash" => r.exact_request_hash = [0; 32],
                                _ => unreachable!("{t}"),
                            }
                            r.canonical_response_payload_bytes =
                                g.encode(LeaseOrigin::PublishCreate);
                            return reply(st, &[], r.encode());
                        }
                    }
                    reply(st, &[], out)
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
                    if let Some(t) = self.tamper.filter(|t| t.starts_with("checkout-")) {
                        if st == 201 {
                            let mut r = IdempotentStoredResponseV2::parse(&out).unwrap();
                            let mut g = ProfileLeaseV2::parse(
                                LeaseOrigin::Checkout,
                                &r.canonical_response_payload_bytes,
                            )
                            .unwrap();
                            match t {
                                "checkout-tenant" => g.profile.tenant_id = [0xee; 16],
                                "checkout-fleet" => g.profile.fleet_id = [0xee; 16],
                                "checkout-late" => g.expires_at_ms = NOW + 3_600_000,
                                "checkout-past" => g.expires_at_ms = 1,
                                _ => unreachable!("{t}"),
                            }
                            r.canonical_response_payload_bytes = g.encode(LeaseOrigin::Checkout);
                            return reply(st, &[], r.encode());
                        }
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
                        expires_at_ms: self.renewed.unwrap_or(T0),
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
                ("DELETE", ["v2", "uploads", u]) => {
                    let lease = self.lease;
                    let up = self.uploads.get_mut(&id(u)).unwrap();
                    match up.state {
                        "ABORTED" => {}
                        "OPEN" | "READY" if lease == Some(up.terms.lease) => up.state = "ABORTED",
                        _ => return reply(409, &[], b"UPLOAD_STATE_CONFLICT".to_vec()),
                    }
                    reply(204, &[], Vec::new())
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
        // An account login, so the client holds a password as a sync
        // command's does.
        match path.as_str() {
            "/v2/auth/login" => {
                let ticket = serde_json::json!({
                    "ticket": "v2t.0123456789abcdef0123", "ticket_id": hex(&[1; 16]),
                    "account_id": hex(&[2; 16]), "server_instance_id": hex(&[3; 16]),
                    "restore_epoch": 0,
                });
                return reply(200, &[], serde_json::to_vec(&ticket).unwrap());
            }
            "/v2/me" => return reply(200, &[], br#"{"devices":[]}"#.to_vec()),
            "/v2/auth/logout" => return reply(204, &[], Vec::new()),
            _ => {}
        }
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        let tag = match (method.as_str(), parts.last().copied()) {
            ("PATCH", _) => "patch",
            ("HEAD", _) => "head",
            ("POST", Some("profiles")) => "publish",
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
            if let Some(sql) = f.on_patch.take() {
                let c = rusqlite::Connection::open(Db::path().unwrap()).unwrap();
                assert_eq!(c.execute(&sql, []).unwrap(), 1, "{sql}");
            }
        }
        if tag == "profiles" && method == Method::GET {
            if let Some(sql) = f.on_list.take() {
                let c = rusqlite::Connection::open(Db::path().unwrap()).unwrap();
                assert_eq!(c.execute(&sql, []).unwrap(), 1, "{sql}");
            }
        }
        if tag == "checkout" {
            if let Some(sql) = f.on_checkout.take() {
                let c = rusqlite::Connection::open(Db::path().unwrap()).unwrap();
                assert_eq!(c.execute(&sql, []).unwrap(), 1, "{sql}");
            }
        }
        if method == Method::GET && parts.len() == 5 && parts[3] == "snapshots" {
            if let Some(sql) = f.on_snapshot.take() {
                let c = rusqlite::Connection::open(Db::path().unwrap()).unwrap();
                assert_eq!(c.execute(&sql, []).unwrap(), 1);
            }
        }
        if take(&mut f.skip, tag) {
            return reply(503, &[], Vec::new());
        }
        if let Some(i) = f.refuse.iter().position(|(t, _)| *t == tag) {
            let (_, status) = f.refuse.remove(i);
            let body = f.refused_body.clone().unwrap_or(b"refused".to_vec());
            return reply(status, &[("retry-after", "0".into())], body);
        }
        if tag == "trust-evidence" && !f.named.is_empty() {
            let asked: Vec<[u8; 32]> = uri
                .query()
                .unwrap_or("")
                .split('&')
                .filter_map(|kv| kv.strip_prefix("signer="))
                .map(|s| crate::fleet_client::decode_hex32(s, "signer").unwrap())
                .collect();
            let mut page = TenantTrustEvidencePageV2::parse(&f.pages).unwrap();
            for s in &asked {
                if let Some((pk, more)) = f.named.get(s) {
                    page.signing_public_keys.push(*pk);
                    page.containers.extend(more.iter().cloned());
                }
            }
            f.asked.push(asked);
            return reply(200, &[], page.encode());
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
        /// Whether `enroll` binds `LOCAL` to `PROFILE`.
        bound: bool,
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

    #[test]
    fn a_refused_sync_reply_hides_an_echoed_token() {
        let token = format!("v2a.{}", "7d".repeat(32));
        let reply = Exact {
            status: 400,
            headers: Default::default(),
            body: format!("{{\"error\":\"bad\",\"auth\":\"Bearer {token}\"}}").into_bytes(),
        };
        let client = FleetClient::new("http://127.0.0.1:9", "").unwrap();
        let error = refused(&client, "", &reply).to_string();
        assert!(error.contains("fleet.refusedSync"), "{error}");
        assert!(!error.contains(&token), "an echoed token reached the error");
    }

    #[test]
    fn a_refused_sync_reply_hides_the_bare_access_token_body() {
        let body = "7e".repeat(32);
        let access = format!("v2a.{body}");
        let reply = Exact {
            status: 403,
            headers: Default::default(),
            body: format!("{{\"error\":\"{body}\"}}").into_bytes(),
        };
        let client = FleetClient::new("http://127.0.0.1:9", "").unwrap();
        let error = refused(&client, &access, &reply).to_string();
        assert!(error.contains("fleet.refusedSync|status=403|"), "{error}");
        assert!(
            !error.to_ascii_lowercase().contains(&body),
            "the bearer token body reached the error"
        );
    }

    /// A sync command logs in on the client it syncs with: a refused push
    /// reply that echoes the account password never returns it.
    #[test]
    fn a_refused_push_hides_the_echoed_login_password() {
        let w = world();
        // No `t`: the fixture's access token is `t`, which is hidden too.
        let password = format!("pw-{}", crate::fleet_client::random_id_hex());
        let login = crate::fleet_client::AccountLogin {
            tenant_id: &hex(&[4; 16]),
            username: "owner",
            password: &password,
        };
        w.rt.block_on(w.client.account_device_status(&login, &hex(&[5; 16])))
            .unwrap();
        w.fake().refused_body = Some(format!(r#"{{"error":"{password}"}}"#).into_bytes());
        w.fake().refuse.push(("checkout", 409));
        let err = w.push().unwrap_err();
        assert!(
            has(&err, "fleet.refusedSync"),
            "another error than the refused checkout"
        );
        assert!(
            !format!("{err:#}").contains(&password),
            "the account password reached a refused push's error"
        );
    }

    #[test]
    fn key_status_and_push_agree_after_the_fleet_key_is_lost() {
        let w = world();
        assert!(holds_verified_key(&w.dev, &FLEET, NOW).unwrap());
        assert_eq!(w.push().unwrap().version, 1);
        crate::fleet_keys::save(&crate::fleet_keys::FleetKeyStore::default()).unwrap();
        assert!(!holds_verified_key(&w.dev, &FLEET, NOW).unwrap());
        let error = w.push().unwrap_err();
        assert!(
            has(&error, "sync.noVerifiedFleetKey"),
            "push must also reject the missing key"
        );
    }

    #[test]
    fn key_status_agrees_with_a_compromise_blocked_push() {
        let w = world();
        w.db().conn.execute_batch(&a_compromise(&w)).unwrap();
        let error = w.push().unwrap_err();
        assert!(has(&error, "sync.commitBlockedCompromised"));
        assert!(w.sent("POST", "/uploads").is_empty());
        assert!(
            !holds_verified_key(&w.dev, &FLEET, NOW).unwrap(),
            "the UI reports a usable fleet key while push is blocked"
        );
        // Held but blocked, so the UI shows the notice, not the join steps.
        assert_eq!(
            verified_key_blocked(&w.dev, &FLEET, NOW).unwrap(),
            Some(true)
        );
    }

    /// `world` with `extra` containers in its trust evidence.
    fn world_with(extra: Vec<Vec<u8>>) -> World {
        world_of(extra, true)
    }

    /// This device holding `FKEK` with `LOCAL` not yet published: the server
    /// does not list `PROFILE`.
    fn world_unbound() -> World {
        let w = world_of(Vec::new(), false);
        w.fake().fresh = true;
        w
    }

    fn world_of(extra: Vec<Vec<u8>>, bound: bool) -> World {
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
            bound,
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
                true,
            )
            .unwrap()
            .expect("the grant verifies");
            assert_eq!(*fkek, FKEK);
            assert!(crate::fleet_keys::collect(&hex(&FLEET), GEN, &fkek).unwrap());
            if !self.bound {
                return;
            }
            db.conn
                .execute(
                    "INSERT INTO profile_bindings(local_profile_id, server_id, server_instance_id,
                       tenant_id, account_id, device_id, fleet_id, remote_profile_id,
                       remote_version, base_version, accepted_restore_epoch, fkek_key_id,
                       key_generation, sync_state, dirty)
                     SELECT ?1, k.server_id, k.server_instance_id, k.tenant_id, d.account_id,
                       k.device_id, k.fleet_id, ?2, 0, 0, 0, k.fkek_key_id, k.generation,
                       'AVAILABLE', 0
                     FROM fleet_key_state k
                     JOIN device_state d USING (server_id, tenant_id, device_id)
                     WHERE k.state = 'ACTIVE'",
                    params![LOCAL, hex(&PROFILE)],
                )
                .unwrap();
        }

        fn push(&self) -> Result<Pushed> {
            self.rt.block_on(push(
                &self.client,
                "t",
                &self.dev,
                LOCAL,
                &self.udd,
                NOW,
                &|| std::time::Duration::ZERO,
            ))
        }

        /// Publishes `LOCAL` as `PROFILE`, labelled "Work profile".
        fn publish(&self) -> Result<Published> {
            self.publish_as(PROFILE, "Work profile")
        }

        fn publish_as(&self, profile: [u8; 16], label: &str) -> Result<Published> {
            self.publish_by(&self.dev, FLEET, profile, label)
        }

        fn publish_by(
            &self,
            dev: &Device,
            fleet: [u8; 16],
            profile: [u8; 16],
            label: &str,
        ) -> Result<Published> {
            self.rt.block_on(publish(
                &self.client,
                "t",
                dev,
                LOCAL,
                label,
                fleet,
                profile,
                NOW,
            ))
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
            "UPDATE operations SET server_id = 'elsewhere' WHERE kind = 'COMMIT'".into(),
            "UPDATE operations SET server_id = 'elsewhere' WHERE kind = 'FINALIZE'".into(),
            "UPDATE upload_sessions SET server_id = 'elsewhere'".into(),
            "UPDATE upload_sessions SET operation_scope = 'elsewhere'".into(),
            "UPDATE upload_sessions SET idempotency_key = 'elsewhere'".into(),
            "UPDATE upload_sessions SET canonical_request_hash = zeroblob(32)".into(),
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
            .execute_batch("PRAGMA foreign_keys = OFF; DELETE FROM signed_authorization_records")
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

    /// WP-11 (G2-31, G2-43): a local profile is published as a version-0
    /// profile with its first lease and fence. The request is stored as exact
    /// bytes and sent once, the label is sealed under the fleet key, the
    /// server's exact stored response is kept, and the binding is written
    /// with it. The next push uses that lease: no checkout.
    #[test]
    fn a_profile_is_published_with_its_first_lease_and_then_pushed() {
        let w = world_unbound();
        assert!(!is_published(LOCAL).unwrap());
        let done = w.publish().unwrap();
        assert!(is_published(LOCAL).unwrap());
        assert_eq!(done.profile, PROFILE);
        assert_eq!((done.lease.fencing_token, done.lease.base_version), (1, 0));
        assert_eq!(w.fake().lease, Some(done.lease));
        let (request, kept): (Vec<u8>, Vec<u8>) = w
            .db()
            .conn
            .query_row(
                "SELECT exact_request_bytes, exact_response_bytes FROM operations
                 WHERE kind = 'PUBLISH' AND state = 'COMPLETED' AND local_profile_id = ?1",
                [LOCAL],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        let req = IdempotentMutationRequestV2::parse(&request).unwrap();
        assert_eq!(
            w.fake().stored[&req.idempotency_key].2,
            kept,
            "the exact response the server stored"
        );
        assert_eq!(w.sent("POST", "/profiles"), vec![request.clone()]);
        let asked = ProfilePublishCreateV2::parse(&req.canonical_payload_bytes).unwrap();
        assert_eq!(
            asked.profile,
            ProfileRef {
                tenant_id: TENANT,
                fleet_id: FLEET,
                profile_id: PROFILE
            }
        );
        assert_eq!(
            (asked.key_generation, asked.fkek_key_id),
            (GEN, shardx_core::fleet_grants::fkek_key_id(&FKEK))
        );
        assert!(!asked.label_ciphertext.windows(4).any(|x| x == b"Work"));
        let label = shardx_core::keys::open_label(
            &FKEK,
            &TENANT,
            &FLEET,
            &PROFILE,
            GEN,
            &asked.label_ciphertext,
        )
        .unwrap();
        assert_eq!(*label, b"Work profile");
        let (version, head, epoch, fence, lease, state): (
            i64,
            Option<Vec<u8>>,
            i64,
            i64,
            String,
            String,
        ) = w
            .db()
            .conn
            .query_row(
                "SELECT remote_version, last_observed_head_hash, accepted_restore_epoch,
                            fencing_token, lease_id, sync_state FROM profile_bindings",
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
            .unwrap();
        assert_eq!(
            (version, head, epoch, fence, lease, state.as_str()),
            (0, None, 0, 1, hex(&done.lease.lease_id), "CHECKED_OUT")
        );
        assert_eq!(
            w.count("SELECT count(*) FROM operations WHERE kind = 'PUBLISH' AND fencing_token = 1 AND base_version = 0"),
            1
        );

        assert_eq!(w.push().unwrap().version, 1);
        assert!(
            w.sent("POST", "/checkout").is_empty(),
            "the publish's lease was used"
        );
        assert_eq!(w.fake().published, [PROFILE]);
    }

    /// WP-11 probe 11 (L2048): at each crash point of a publish-create, with
    /// the database closed and reopened, the next attempt sends the exact
    /// stored bytes again, and the server has made one profile with one
    /// lease and one fence. The stored request wins over any new arguments.
    #[test]
    fn every_publish_crash_point_resumes_with_the_exact_stored_bytes() {
        for point in ["before send", "reply lost", "binding not written"] {
            let w = world_unbound();
            match point {
                "before send" => w.fake().skip.push("publish"),
                "reply lost" => w.fake().lose.push("publish"),
                _ => w
                    .db()
                    .conn
                    .execute_batch(
                        "CREATE TRIGGER crash BEFORE INSERT ON profile_bindings
                         BEGIN SELECT RAISE(ABORT, 'crash'); END",
                    )
                    .unwrap(),
            }
            let err = w.publish().expect_err(point);
            if point == "binding not written" {
                assert!(format!("{err:#}").contains("crash"), "{err:#}");
            } else {
                assert!(has(&err, "fleet.refusedSync"), "{point}: {err:#}");
            }
            assert_eq!(
                w.fake().published.len(),
                usize::from(point != "before send"),
                "{point}"
            );
            // Reopened: the request is stored, nothing else is.
            let stored: Vec<u8> = w
                .db()
                .conn
                .query_row(
                    "SELECT exact_request_bytes FROM operations
                     WHERE kind = 'PUBLISH' AND state = 'PENDING' AND local_profile_id IS NULL
                       AND exact_response_bytes IS NULL",
                    [],
                    |r| r.get(0),
                )
                .expect(point);
            assert_eq!(
                w.count("SELECT count(*) FROM profile_bindings"),
                0,
                "{point}"
            );
            if point == "binding not written" {
                w.db().conn.execute_batch("DROP TRIGGER crash").unwrap();
            }

            let done = w.publish_as([0x77; 16], "ignored").expect(point);
            assert_eq!(done.profile, PROFILE, "{point}: the stored request wins");
            let sent = w.sent("POST", "/profiles");
            assert_eq!(sent.len(), 2, "{point}");
            assert_eq!((&sent[0], &sent[1]), (&stored, &stored), "{point}");
            assert_eq!(w.fake().published, [PROFILE], "{point}: one profile");
            assert_eq!(w.fake().fence, 1, "{point}: one fence");
            assert_eq!(w.fake().lease, Some(done.lease), "{point}: one lease");
            let key = IdempotentMutationRequestV2::parse(&stored)
                .unwrap()
                .idempotency_key;
            let kept: Vec<u8> = w
                .db()
                .conn
                .query_row(
                    "SELECT exact_response_bytes FROM operations
                     WHERE kind = 'PUBLISH' AND state = 'COMPLETED'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(w.fake().stored[&key].2, kept, "{point}: exact stored bytes");
            assert_eq!(
                w.count("SELECT count(*) FROM operations WHERE kind = 'PUBLISH'"),
                1
            );
            assert_eq!(
                w.count("SELECT count(*) FROM profile_bindings"),
                1,
                "{point}"
            );
        }
    }

    /// WP-12 (G2-32, G2-35, G2-36): a binding, its operations and its upload
    /// session name the `server_origins` row, the account and device, and the
    /// `fleet_key_state` row of the key they were made under. The lease's
    /// server expiry is kept with the lease and dropped with it, `dirty` is
    /// set by a publish and cleared by a push or a pull, and the pinned base
    /// version follows the head.
    #[test]
    fn a_binding_and_its_rows_name_the_servers_account_and_key() {
        let expiry = |ms: u64| {
            format!("lease_expires_at = strftime('%Y-%m-%dT%H:%M:%fZ', {ms} / 1000.0, 'unixepoch')")
        };
        let w = world_unbound();
        w.publish().unwrap();
        let named = "SELECT count(*) FROM profile_bindings b
             JOIN server_origins o ON o.server_id = b.server_id
              AND o.server_instance_id = b.server_instance_id
             JOIN accounts a ON a.server_id = b.server_id AND a.tenant_id = b.tenant_id
              AND a.account_id = b.account_id AND a.device_id = b.device_id
              AND a.role = 'member' AND a.status = 'ACTIVE'
             JOIN device_state d ON d.server_id = b.server_id AND d.tenant_id = b.tenant_id
              AND d.device_id = b.device_id
              AND d.signing_credential_ref = 'device-signing.' || b.device_id
              AND d.hpke_credential_ref = 'device-hpke.' || b.device_id
             JOIN fleet_key_state k ON k.server_id = b.server_id
              AND k.server_instance_id = b.server_instance_id AND k.tenant_id = b.tenant_id
              AND k.fleet_id = b.fleet_id AND k.generation = b.key_generation
              AND k.fkek_key_id = b.fkek_key_id AND k.state = 'ACTIVE'
              AND k.fkek_credential_ref = 'fleet-key.' || b.fleet_id || '.' || b.key_generation
             WHERE b.account_id = ?1 AND b.device_id = ?2 AND b.fkek_key_id = ?3
               AND b.key_generation = 1 AND b.local_profile_id = 'local-profile'";
        let me = me();
        let check = |w: &World, extra: &str| {
            w.db()
                .conn
                .query_row(
                    &format!("{named} AND {extra}"),
                    params![
                        hex(&me.to.account_id),
                        hex(&me.to.device_id),
                        hex(&shardx_core::fleet_grants::fkek_key_id(&FKEK))
                    ],
                    |r| r.get::<_, i64>(0),
                )
                .unwrap()
        };
        let lease = expiry(NOW + 300_000);
        // Published: the first lease, a dirty profile, base version 0.
        assert_eq!(
            check(
                &w,
                &format!("b.dirty = 1 AND b.base_version = 0 AND b.{lease}")
            ),
            1
        );
        assert_eq!(
            w.count(
                "SELECT count(*) FROM operations o JOIN profile_bindings b
                 ON b.local_profile_id = o.local_profile_id AND b.server_id = o.server_id"
            ),
            w.count("SELECT count(*) FROM operations"),
        );
        // Pushed: the head moves, the profile is clean, the lease is gone.
        w.push().unwrap();
        assert_eq!(
            check(
                &w,
                "b.dirty = 0 AND b.base_version = 1 AND b.remote_version = 1
                 AND b.lease_id IS NULL AND b.lease_expires_at IS NULL"
            ),
            1
        );
        let sessions = "SELECT count(*) FROM upload_sessions u
             JOIN operations o ON o.op_id = u.commit_op_id
             WHERE u.server_id = o.server_id AND u.operation_scope = o.operation_scope
               AND u.idempotency_key = o.idempotency_key
               AND u.canonical_request_hash = o.canonical_request_hash
               AND u.retry_state = 'NONE' AND u.fkek_key_id = ?1 AND u.key_generation = 1";
        let kept: i64 = w
            .db()
            .conn
            .query_row(
                sessions,
                [hex(&shardx_core::fleet_grants::fkek_key_id(&FKEK))],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(kept, 1);
        // A pull of a profile edited since is clean again.
        w.db()
            .conn
            .execute("UPDATE profile_bindings SET dirty = 1", [])
            .unwrap();
        w.pull(&w._dir.path().join("pulled")).unwrap();
        assert_eq!(
            check(&w, "b.dirty = 0 AND b.base_version = b.remote_version"),
            1
        );
        // A checkout that is not finished keeps the lease with its expiry.
        drop(w);
        let w2 = world();
        w2.fake().skip.push("finalize");
        w2.push().unwrap_err();
        assert_eq!(
            w2.count(&format!(
                "SELECT count(*) FROM profile_bindings WHERE lease_id IS NOT NULL AND {lease}"
            )),
            1
        );
    }

    /// WP-11 probe 11: a publish the server refuses is failed and never
    /// resent; the next one is a new request under a new key.
    #[test]
    fn a_refused_publish_is_not_replayed_and_the_next_one_starts_afresh() {
        let w = world_unbound();
        w.fake().refuse.push(("publish", 403));
        let err = w.publish().unwrap_err();
        assert!(has(&err, "fleet.refusedSync"), "{err:#}");
        assert_eq!(
            w.count("SELECT count(*) FROM operations WHERE kind = 'PUBLISH' AND state = 'FAILED'"),
            1
        );
        assert_eq!(w.count("SELECT count(*) FROM profile_bindings"), 0);
        assert!(w.fake().published.is_empty());
        w.publish().unwrap();
        let sent = w.sent("POST", "/profiles");
        assert_eq!(sent.len(), 2);
        assert_ne!(sent[0], sent[1], "a new request, not a replay");
        assert_eq!(w.fake().published, [PROFILE]);
    }

    /// WP-11, L-4: a 2xx reply that does not name exactly what was asked
    /// (L-5: the tenant and the fleet among it) is never kept: no binding, and
    /// the operation is QUARANTINED under the named field instead of being
    /// replayed for good. When the reply still names a lease of the profile
    /// in a stored response that verifies, that lease is released with
    /// `cancel_publish`; the next publish is a new request.
    #[test]
    fn a_publish_reply_that_does_not_name_the_request_is_never_kept() {
        for (tamper, field, released) in [
            ("publish-hash", "exact_request_hash", false),
            ("publish-profile", "profile", false),
            ("publish-tenant", "profile", false),
            ("publish-fleet", "profile", false),
            ("publish-instance", "server_instance_id", true),
            ("publish-epoch", "restore_epoch", true),
            ("publish-key", "fkek_key_id", true),
            ("publish-generation", "key_generation", true),
            ("publish-fence", "fencing_token", true),
        ] {
            let w = world_unbound();
            w.fake().tamper = Some(tamper);
            let err = w.publish().unwrap_err();
            assert!(has(&err, "sync.badReplySync"), "{tamper}: {err:#}");
            assert!(format!("{err:#}").contains(field), "{tamper}: {err:#}");
            assert_eq!(
                w.count("SELECT count(*) FROM profile_bindings"),
                0,
                "{tamper}"
            );
            assert_eq!(
                w.count(
                    "SELECT count(*) FROM operations WHERE kind = 'PUBLISH' AND state = 'QUARANTINED'
                       AND exact_response_bytes IS NULL"
                ),
                1,
                "{tamper}"
            );
            let releases = w.sent("POST", "/release");
            assert_eq!(releases.len(), usize::from(released), "{tamper}");
            for sent in releases {
                let request = IdempotentMutationRequestV2::parse(&sent).unwrap();
                let release = ReleaseLeaseV2::parse(&request.canonical_payload_bytes).unwrap();
                assert_eq!(
                    release.reason_code,
                    ReleaseReason::CancelPublish,
                    "{tamper}"
                );
            }
            assert_eq!(
                w.count("SELECT count(*) FROM operations WHERE kind = 'RELEASE' AND local_profile_id IS NOT NULL"),
                0,
                "{tamper}: the release names no binding"
            );
            // Not replayed: the next publish is a new request.
            w.fake().tamper = None;
            w.publish_as(PROFILE2, "Work profile").unwrap();
            let sent = w.sent("POST", "/profiles");
            assert_eq!(sent.len(), 2, "{tamper}");
            assert_ne!(sent[0], sent[1], "{tamper}: not a replay");
        }
    }

    /// A compromised revocation of a key the fleet's devices hold, counted.
    fn count_a_compromise(w: &World) {
        assert_eq!(w.db().conn.execute(&a_compromise(w), []).unwrap(), 1);
    }

    /// The SQL that counts [`count_a_compromise`]'s revocation.
    fn a_compromise(w: &World) -> String {
        let revocation = DeviceRevocationV2 {
            common: common(30),
            subject_account_id: [6; 16],
            subject_device_id: [0x77; 16],
            subject_signing_key_id: [0x77; 32],
            subject_hpke_key_id: [0x78; 32],
            reason_code: DeviceRevocationReason::Compromised,
        };
        let container = build_record(&w.me.sk, DOMAIN_DEVICE_REVOCATION, &revocation.encode());
        format!(
            "INSERT INTO trust_proven_revocations
             VALUES ('{}', '{}', '{}', 'DEVICE_REVOCATION', 1, 0, x'{}')",
            hex(&INSTANCE),
            hex(&TENANT),
            hex(&[0x77; 32]),
            hex(&container)
        )
    }

    /// M-1: a stored publish is re-checked at every send, replays included. A
    /// compromise counted, or the key withdrawn by local distrust, since it
    /// was stored keeps it unsent under a named code, still PENDING; the
    /// cancel path ends it, and what is left of the key stops a new request.
    #[test]
    fn a_stored_publish_is_not_sent_once_its_key_is_blocked_or_withdrawn() {
        for (name, code) in [
            ("compromise", "sync.commitBlockedCompromised"),
            ("withdrawn", "sync.noVerifiedFleetKey"),
        ] {
            let w = world_unbound();
            w.fake().skip.push("publish");
            w.publish().unwrap_err();
            assert_eq!(
                w.sent("POST", "/profiles").len(),
                1,
                "{name}: stored and tried"
            );
            if name == "compromise" {
                count_a_compromise(&w);
            } else {
                ledger::distrust_key(&w.db(), &w.dev.pin.0, &w.me.to.signing_key_id, NOW).unwrap();
            }
            let err = w.publish().unwrap_err();
            assert!(has(&err, code), "{name}: {err:#}");
            assert_eq!(
                w.sent("POST", "/profiles").len(),
                1,
                "{name}: not sent again"
            );
            assert!(w.fake().published.is_empty(), "{name}");
            assert_eq!(
                w.count(
                    "SELECT count(*) FROM operations WHERE kind = 'PUBLISH' AND state = 'PENDING'"
                ),
                1,
                "{name}: kept, unsent"
            );
            assert_eq!(
                w.count("SELECT count(*) FROM profile_bindings"),
                0,
                "{name}"
            );

            cancel_publish(LOCAL).unwrap();
            assert_eq!(
                w.count(
                    "SELECT count(*) FROM operations WHERE kind = 'PUBLISH' AND state = 'FAILED'"
                ),
                1,
                "{name}"
            );
            let err = cancel_publish(LOCAL).unwrap_err();
            assert!(has(&err, "sync.noPublishPending"), "{name}: {err:#}");
            let err = w.publish_as(PROFILE2, "Work").unwrap_err();
            assert!(
                has(&err, code),
                "{name}: a new request needs a good key: {err:#}"
            );
            assert_eq!(w.sent("POST", "/profiles").len(), 1, "{name}");
        }
    }

    /// M-1: with the key good, the stored publish goes out as before.
    #[test]
    fn a_stored_publish_goes_out_while_its_key_holds() {
        let w = world_unbound();
        w.fake().skip.push("publish");
        w.publish().unwrap_err();
        w.publish().unwrap();
        assert_eq!(w.fake().published, [PROFILE]);
        let sent = w.sent("POST", "/profiles");
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0], sent[1], "the stored request, replayed");
    }

    impl World {
        fn publish_at(&self, profile: [u8; 16], now: u64) -> Result<Published> {
            self.rt.block_on(publish(
                &self.client,
                "t",
                &self.dev,
                LOCAL,
                "Work profile",
                FLEET,
                profile,
                now,
            ))
        }
    }

    /// The row the one binding of a publish is: its lease, expiry and state.
    fn publish_row(w: &World) -> (Option<String>, Option<String>, String, i64) {
        w.db()
            .conn
            .query_row(
                "SELECT lease_id, lease_expires_at, sync_state, dirty FROM profile_bindings",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap()
    }

    /// NEW-1: a reply that names the request on every identity field is bound
    /// at version 0 whatever its lease expiry says (plan L2048): one server
    /// profile, one binding. Inside the window the lease is held as given; a
    /// lease already over is not held and is released, best effort; one
    /// further ahead than a TTL and the skew allowance is held at risk for one
    /// TTL from now.
    #[test]
    fn a_publish_is_bound_whatever_its_lease_expiry_says() {
        for ms in [
            NOW + 1,
            NOW + 300_000 + 60_000,
            NOW,
            1,
            NOW + 300_000 + 60_000 + 1,
            9_000_000_000_000,
        ] {
            let w = world_unbound();
            w.fake().expires = Some(ms);
            if ms <= NOW {
                // The release is lost: the binding must not hold the lease.
                w.fake().refuse.push(("release", 503));
            }
            let done = w.publish().unwrap();
            assert_eq!(w.fake().published, [PROFILE], "{ms}");
            let (lease, expiry, state, dirty) = publish_row(&w);
            assert_eq!(dirty, 1, "{ms}");
            let releases = w.sent("POST", "/release");
            if ms <= NOW {
                assert_eq!(
                    (lease, expiry, state.as_str()),
                    (None, None, "AVAILABLE"),
                    "{ms}"
                );
                assert_eq!(releases.len(), 1, "{ms}: the ended lease is let go");
                assert_eq!(
                    w.count(
                        "SELECT count(*) FROM operations WHERE kind = 'RELEASE'
                           AND state = 'PENDING' AND local_profile_id = 'local-profile'"
                    ),
                    1,
                    "{ms}: kept for a push to replay"
                );
                let request = IdempotentMutationRequestV2::parse(&releases[0]).unwrap();
                let release = ReleaseLeaseV2::parse(&request.canonical_payload_bytes).unwrap();
                assert_eq!(release.lease, done.lease, "{ms}");
                assert_eq!(release.reason_code, ReleaseReason::UserRelease, "{ms}");
                assert_eq!(done.expires_at_ms, ms, "{ms}");
            } else if ms <= NOW + 360_000 {
                assert_eq!(state, "CHECKED_OUT", "{ms}");
                assert_eq!(expiry, Some(w.stored_as(ms)), "{ms}");
                assert!(lease.is_some() && releases.is_empty(), "{ms}");
                assert_eq!(done.expires_at_ms, ms, "{ms}");
            } else {
                assert_eq!(state, "LEASE_AT_RISK", "{ms}");
                assert_eq!(expiry, Some(w.stored_as(NOW + 300_000)), "{ms}");
                assert!(lease.is_some() && releases.is_empty(), "{ms}");
                assert_eq!(done.expires_at_ms, NOW + 300_000, "{ms}");
            }
            assert_eq!(
                w.count("SELECT count(*) FROM operations WHERE kind = 'PUBLISH' AND state = 'COMPLETED'"),
                1,
                "{ms}"
            );
        }
    }

    /// P6: the reply is lost and the device comes back after the lease's
    /// TTL. The replay returns the stored first lease, long over: the profile
    /// is bound without a lease and nothing is made twice.
    #[test]
    fn a_publish_replayed_after_its_lease_ended_binds_the_one_profile() {
        let w = world_unbound();
        w.fake().lose.push("publish");
        w.publish_at(PROFILE, NOW).unwrap_err();
        assert_eq!(w.fake().published, [PROFILE]);
        w.publish_at(PROFILE2, NOW + 600_000).unwrap();
        assert_eq!(w.fake().published, [PROFILE], "no second profile");
        assert_eq!(w.count("SELECT count(*) FROM profile_bindings"), 1);
        assert_eq!(
            w.count(&format!(
                "SELECT count(*) FROM profile_bindings WHERE remote_profile_id = '{}'
                   AND lease_id IS NULL",
                hex(&PROFILE)
            )),
            1
        );
        assert_eq!(
            w.count(
                "SELECT count(*) FROM operations WHERE kind = 'PUBLISH' AND state <> 'COMPLETED'"
            ),
            0
        );
        // The next push takes a lease as any bound profile does.
        assert_eq!(w.push().unwrap().version, 1);
    }

    /// P7: a device clock more than the skew allowance behind the server:
    /// the first lease looks too far ahead, and is bound at risk, once.
    #[test]
    fn a_device_clock_behind_the_server_still_binds_one_profile() {
        let w = world_unbound();
        w.fake().expires = Some(NOW + 300_000 + 61_000);
        w.publish().unwrap();
        assert_eq!(w.fake().published, [PROFILE]);
        assert_eq!(w.count("SELECT count(*) FROM profile_bindings"), 1);
        let err = w.publish_as(PROFILE2, "Work").unwrap_err();
        assert!(has(&err, "sync.alreadyPublished"), "{err:#}");
        assert_eq!(w.fake().published, [PROFILE], "no profile per attempt");
        assert_eq!(publish_row(&w).2, "LEASE_AT_RISK");
    }

    /// NEW-2: a `cancel_publish` release that fails stays PENDING with no
    /// binding. The next publish, push or pull sends it again; once its lease
    /// can no longer be live (older than a TTL and the skew allowance) it is
    /// ended FAILED without a request.
    #[test]
    fn an_unsent_cancel_release_is_retried_and_then_given_up() {
        let unbound_pending = |w: &World| {
            w.count(
                "SELECT count(*) FROM operations WHERE kind = 'RELEASE' AND state = 'PENDING'
                   AND local_profile_id IS NULL",
            )
        };
        for age in [false, true] {
            let w = world_unbound();
            w.fake().tamper = Some("publish-fence");
            w.fake().refuse.push(("release", 503));
            w.publish().unwrap_err();
            assert_eq!(unbound_pending(&w), 1, "{age}");
            assert_eq!(w.sent("POST", "/release").len(), 1, "{age}");
            if age {
                w.db()
                    .conn
                    .execute(
                        "UPDATE operations SET created_at = '2020-01-01T00:00:00.000Z'
                         WHERE kind = 'RELEASE'",
                        [],
                    )
                    .unwrap();
            }
            w.fake().tamper = None;
            w.publish_as(PROFILE2, "Work").unwrap();
            assert_eq!(unbound_pending(&w), 0, "{age}");
            assert_eq!(
                w.sent("POST", "/release").len(),
                if age { 1 } else { 2 },
                "{age}: sent again only while the lease may be live"
            );
            assert_eq!(
                w.count("SELECT count(*) FROM operations WHERE kind = 'RELEASE' AND state = 'FAILED'"),
                1,
                "{age}: the release ends, FAILED (the fence the tampered reply named was never the server's)"
            );
        }
        // A push and a pull retry it too.
        for pull in [false, true] {
            let w = world();
            w.push().unwrap();
            let b = bound(&w.db(), LOCAL).unwrap();
            let db = w.db();
            let lease = LeaseRef {
                lease_id: [0x42; 16],
                fencing_token: 1,
                base_version: 0,
            };
            let op = release_op(&db.conn, &b, lease, ReleaseReason::CancelPublish).unwrap();
            db.conn
                .execute(
                    "UPDATE operations SET local_profile_id = NULL WHERE op_id = ?1",
                    [&op],
                )
                .unwrap();
            drop(db);
            let before = w.sent("POST", "/release").len();
            if pull {
                w.pull(&w.udd.with_file_name("out")).unwrap();
            } else {
                w.push().unwrap();
            }
            assert_eq!(w.sent("POST", "/release").len(), before + 1, "{pull}");
            assert_eq!(unbound_pending(&w), 0, "{pull}");
        }
    }

    /// NEW-5: a publish whose operation another process ended (a cancel) between
    /// the read and the send binds nothing: the completion must update exactly
    /// the one pending row, in the transaction that files the binding.
    #[test]
    fn a_publish_whose_operation_was_cancelled_meanwhile_binds_nothing() {
        let w = world_unbound();
        w.fake().skip.push("publish");
        w.publish().unwrap_err();
        let mut db = w.db();
        let op = pending_publish(&db, LOCAL).unwrap().unwrap();
        cancel_publish(LOCAL).unwrap();
        let err =
            w.rt.block_on(send_publish(
                &w.client, "t", &mut db, &w.dev, LOCAL, FLEET, &op, NOW,
            ))
            .unwrap_err();
        assert!(has(&err, "sync.publishChanged"), "{err:#}");
        assert_eq!(w.count("SELECT count(*) FROM profile_bindings"), 0);
        assert_eq!(
            w.count("SELECT count(*) FROM operations WHERE kind = 'PUBLISH' AND state = 'FAILED'"),
            1
        );
    }

    /// NEW-3: a publish M-1 keeps unsent blocks a downgrade by a name that
    /// points at the cancel; the cancel command ends it and the blocker goes.
    #[test]
    fn a_blocked_publish_is_cancelled_by_its_command_and_stops_blocking_a_downgrade() {
        let blocked = |key: &str| {
            crate::team::downgrade::readiness()
                .unwrap()
                .blockers
                .iter()
                .any(|b| b.code == key)
        };
        let w = world_unbound();
        w.fake().skip.push("publish");
        w.publish().unwrap_err();
        count_a_compromise(&w);
        let err = w.publish().unwrap_err();
        assert!(has(&err, "sync.commitBlockedCompromised"), "{err:#}");
        assert!(blocked("downgrade.blockPendingPublish"));
        assert!(blocked("downgrade.blockOperation"));
        w.rt.block_on(crate::sync_cmd::profile_sync_cancel_publish(LOCAL.into()))
            .unwrap();
        assert!(!blocked("downgrade.blockPendingPublish"));
        assert!(!blocked("downgrade.blockOperation"));
        let err =
            w.rt.block_on(crate::sync_cmd::profile_sync_cancel_publish(LOCAL.into()))
                .unwrap_err();
        assert!(
            crate::errcode::has_code(&err, "sync.noPublishPending"),
            "{err}"
        );
    }

    /// L-5, L-3: a checkout reply that names another tenant or fleet, or a
    /// lease that ends outside the window (a fresh one that has already
    /// ended included), is never kept: refused by name, no lease on the
    /// binding.
    #[test]
    fn a_checkout_reply_for_another_tenant_fleet_or_expiry_is_never_kept() {
        for (tamper, field) in [
            ("checkout-tenant", "profile"),
            ("checkout-fleet", "profile"),
            ("checkout-late", "expires_at_ms"),
            ("checkout-past", "expires_at_ms"),
        ] {
            let w = world();
            w.fake().tamper = Some(tamper);
            let err = w.push().unwrap_err();
            assert!(has(&err, "sync.badReplySync"), "{tamper}: {err:#}");
            assert!(format!("{err:#}").contains(field), "{tamper}: {err:#}");
            assert_eq!(
                w.count(
                    "SELECT count(*) FROM profile_bindings
                     WHERE lease_id IS NOT NULL OR lease_expires_at IS NOT NULL"
                ),
                0,
                "{tamper}"
            );
            assert_eq!(
                w.count(
                    "SELECT count(*) FROM operations WHERE kind = 'CHECKOUT' AND state = 'PENDING'"
                ),
                1,
                "{tamper}"
            );
        }
    }

    /// WP-11: a publish that cannot be trusted is neither stored nor sent.
    #[test]
    fn a_publish_that_cannot_be_trusted_stores_and_sends_nothing() {
        let nothing = |w: &World, what: &str| {
            assert!(w.sent("POST", "/profiles").is_empty(), "{what}");
            assert_eq!(w.count("SELECT count(*) FROM operations"), 0, "{what}");
        };
        // Already published.
        let w = world();
        let err = w.publish().unwrap_err();
        assert!(has(&err, "sync.alreadyPublished"), "{err:#}");
        assert!(w.fake().log.is_empty());

        // The ID is taken.
        drop(w);
        let w = world_unbound();
        w.fake().fresh = false;
        let err = w.publish().unwrap_err();
        assert!(has(&err, "sync.publishProfileTaken"), "{err:#}");
        nothing(&w, "taken");

        // Another server than the one this device pinned.
        drop(w);
        let w = world_unbound();
        let mut other = device(&w.me);
        other.pin.0.server_instance_id = [9; 16];
        let err = w.publish_by(&other, FLEET, PROFILE, "Work").unwrap_err();
        assert!(has(&err, "sync.badReplySync"), "{err:#}");
        nothing(&w, "instance");

        // A name the label cannot hold.
        drop(w);
        for label in ["", "   ", &"x".repeat(1025)] {
            let w = world_unbound();
            let err = w.publish_as(PROFILE, label).unwrap_err();
            assert!(has(&err, "sync.badProfileLabel"), "{err:#}");
            nothing(&w, "label");
        }

        // No fleet key, or one whose grant no longer verifies.
        let w = world_unbound();
        crate::fleet_keys::save(&crate::fleet_keys::FleetKeyStore::default()).unwrap();
        let err = w.publish().unwrap_err();
        assert!(has(&err, "sync.noVerifiedFleetKey"), "{err:#}");
        nothing(&w, "no key");
        drop(w);
        let w = world_unbound();
        ledger::distrust_key(&w.db(), &w.dev.pin.0, &w.me.to.signing_key_id, NOW).unwrap();
        let err = w.publish().unwrap_err();
        assert!(has(&err, "sync.noVerifiedFleetKey"), "{err:#}");
        nothing(&w, "withdrawn");

        // A server epoch behind the one this device accepted is a rollback.
        drop(w);
        let w = world_unbound();
        w.db()
            .conn
            .execute("UPDATE server_origins SET last_restore_epoch = 3", [])
            .unwrap();
        let err = w.publish().unwrap_err();
        assert!(has(&err, "sync.headRollback"), "{err:#}");
        nothing(&w, "rollback");

        // A generation a compromised device may hold.
        drop(w);
        let w = world_unbound();
        let revocation = DeviceRevocationV2 {
            common: common(30),
            subject_account_id: [6; 16],
            subject_device_id: [0x77; 16],
            subject_signing_key_id: [0x77; 32],
            subject_hpke_key_id: [0x78; 32],
            reason_code: DeviceRevocationReason::Compromised,
        };
        let container = build_record(&w.me.sk, DOMAIN_DEVICE_REVOCATION, &revocation.encode());
        w.db()
            .conn
            .execute(
                "INSERT INTO trust_proven_revocations
                 VALUES (?1, ?2, ?3, 'DEVICE_REVOCATION', 1, 0, ?4)",
                params![hex(&INSTANCE), hex(&TENANT), hex(&[0x77; 32]), container],
            )
            .unwrap();
        let err = w.publish().unwrap_err();
        assert!(has(&err, "sync.commitBlockedCompromised"), "{err:#}");
        nothing(&w, "compromised");

        // A pending publish is not replayed into another fleet.
        drop(w);
        let w = world_unbound();
        w.fake().skip.push("publish");
        w.publish().unwrap_err();
        let err = w.publish_by(&w.dev, [8; 16], PROFILE, "Work").unwrap_err();
        assert!(has(&err, "sync.publishPendingElsewhere"), "{err:#}");
        assert_eq!(w.sent("POST", "/profiles").len(), 1);
    }

    /// The `NOW` a push sees `JUMP` seconds after its first look at the clock:
    /// the first renewal is due and the clock then stands still.
    const JUMP: u64 = 101;

    fn jump() -> impl Fn() -> std::time::Duration + Sync {
        let looks = std::sync::atomic::AtomicU64::new(0);
        move || {
            let n = looks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::time::Duration::from_secs(if n == 0 { 0 } else { JUMP })
        }
    }

    impl World {
        fn push_at(&self, clock: &(dyn Fn() -> std::time::Duration + Sync)) -> Result<Pushed> {
            self.rt.block_on(push(
                &self.client,
                "t",
                &self.dev,
                LOCAL,
                &self.udd,
                NOW,
                clock,
            ))
        }

        fn expiry(&self) -> Option<String> {
            self.db()
                .conn
                .query_row(
                    "SELECT lease_expires_at FROM profile_bindings WHERE local_profile_id = ?1",
                    [LOCAL],
                    |r| r.get(0),
                )
                .unwrap()
        }

        /// `lease_expires_at` as the binding stores `ms`.
        fn stored_as(&self, ms: u64) -> String {
            self.db()
                .conn
                .query_row(
                    "SELECT strftime('%Y-%m-%dT%H:%M:%fZ', ?1 / 1000.0, 'unixepoch')",
                    [ms as i64],
                    |r| r.get(0),
                )
                .unwrap()
        }
    }

    /// WP-12: a lease renewed mid-upload keeps the expiry the server granted.
    /// The clock jumps past a third of the TTL once, so the first chunk
    /// renews; the binding's `lease_expires_at` is read each time the clock
    /// is, and moves from the checkout's grant to the renewal's.
    #[test]
    fn a_renewed_lease_moves_the_bindings_expiry_forward() {
        let w = world();
        let (granted, renewed) = (NOW + 300_000, NOW + JUMP * 1000 + 300_000);
        w.fake().renewed = Some(renewed);
        let seen = Mutex::new(Vec::new());
        let clock = jump();
        let watching = || {
            seen.lock().unwrap().push(w.expiry());
            clock()
        };
        w.push_at(&watching).unwrap();
        assert_eq!(w.sent("POST", "/renew").len(), 1);
        let seen = seen.into_inner().unwrap();
        assert_eq!(seen[0], Some(w.stored_as(granted)), "before any renewal");
        assert!(
            seen.contains(&Some(w.stored_as(renewed))),
            "a renewal moved the expiry forward: {seen:?}"
        );
        assert!(
            !seen.contains(&Some(w.stored_as(T0))),
            "never to the stale one: {seen:?}"
        );
    }

    /// L-3: an expiry the server grants is kept only when it lies ahead of
    /// now and within one TTL and the skew allowance; at the edges it is kept,
    /// one millisecond outside it is refused by name and the row is unchanged.
    #[test]
    fn a_lease_expiry_outside_the_ttl_is_refused_by_name() {
        let now = NOW + JUMP * 1000;
        let last = now + 300_000 + 60_000;
        for (ms, kept) in [
            (now + 1, true),
            (last, true),
            (now, false),
            (last + 1, false),
            (1, false),
        ] {
            let w = world();
            w.fake().renewed = Some(ms);
            let result = w.push_at(&jump());
            if kept {
                result.unwrap();
                continue;
            }
            let err = result.unwrap_err();
            assert!(has(&err, "sync.badReplySync"), "{ms}: {err:#}");
            assert!(
                format!("{err:#}").contains("expires_at_ms"),
                "{ms}: {err:#}"
            );
            assert_eq!(w.expiry(), Some(w.stored_as(NOW + 300_000)), "{ms}");
        }
    }

    /// WP-11: a server epoch ahead of the accepted one is where a new profile
    /// starts; its binding and operation carry that epoch.
    #[test]
    fn a_profile_published_after_a_restore_starts_at_the_servers_epoch() {
        let w = world_unbound();
        w.fake().epoch = 1;
        w.publish().unwrap();
        assert_eq!(
            w.count("SELECT count(*) FROM profile_bindings WHERE accepted_restore_epoch = 1"),
            1
        );
        assert_eq!(
            w.count("SELECT count(*) FROM operations WHERE kind = 'PUBLISH' AND restore_epoch = 1"),
            1
        );
    }

    /// G2-37 for a publish: a stored column that no longer matches the exact
    /// bytes it describes is never sent.
    #[test]
    fn a_stored_publish_that_drifts_from_its_bytes_is_never_sent() {
        let other = format!("'{}'", "99".repeat(16));
        for sql in [
            format!("UPDATE operations SET remote_profile_id = {other} WHERE kind = 'PUBLISH'"),
            format!("UPDATE operations SET server_instance_id = {other} WHERE kind = 'PUBLISH'"),
            "UPDATE operations SET restore_epoch = 1 WHERE kind = 'PUBLISH'".into(),
            format!("UPDATE operations SET idempotency_key = {other} WHERE kind = 'PUBLISH'"),
            "UPDATE operations SET canonical_request_hash = zeroblob(32) WHERE kind = 'PUBLISH'"
                .into(),
            "UPDATE operations SET exact_request_bytes = CAST(x'00' || exact_request_bytes AS BLOB)
               WHERE kind = 'PUBLISH'"
                .into(),
        ] {
            let w = world_unbound();
            w.fake().skip.push("publish");
            w.publish().unwrap_err();
            let raw = rusqlite::Connection::open(Db::path().unwrap()).unwrap();
            raw.pragma_update(None, "foreign_keys", false).unwrap();
            assert_eq!(raw.execute(&sql, []).unwrap(), 1, "{sql}");
            let before = w.fake().log.len();
            let err = w.publish().unwrap_err();
            assert!(has(&err, "sync.storedRequestMismatch"), "{sql}: {err:#}");
            assert_eq!(w.fake().log.len(), before, "{sql}: nothing was sent");
            assert_eq!(
                w.count("SELECT count(*) FROM operations WHERE kind = 'PUBLISH' AND state = 'QUARANTINED'"),
                1,
                "{sql}"
            );
            assert_eq!(w.count("SELECT count(*) FROM profile_bindings"), 0, "{sql}");
        }
    }

    /// WP-11 probe 11 (L2048), G2-43: a CREATE_UPLOAD whose reply is lost
    /// with no restore in between (not the post-restore superseded case) is
    /// answered by the server's exact stored response when its stored bytes
    /// are sent again: one upload, at each crash point, across a reopen.
    #[test]
    fn a_create_upload_whose_reply_was_lost_is_replayed_byte_for_byte() {
        for point in ["before send", "reply lost", "reply not kept"] {
            let w = world();
            match point {
                "before send" => w.fake().skip.push("upload"),
                "reply lost" => w.fake().lose.push("upload"),
                _ => w
                    .db()
                    .conn
                    .execute_batch(
                        "CREATE TRIGGER crash BEFORE UPDATE OF state ON operations
                         WHEN NEW.kind = 'UPLOAD' AND NEW.state = 'COMPLETED'
                         BEGIN SELECT RAISE(ABORT, 'crash'); END",
                    )
                    .unwrap(),
            }
            let err = w.push().expect_err(point);
            if point == "reply not kept" {
                assert!(format!("{err:#}").contains("crash"), "{err:#}");
            } else {
                assert!(has(&err, "fleet.refusedSync"), "{point}: {err:#}");
            }
            assert_eq!(
                w.fake().uploads.len(),
                usize::from(point != "before send"),
                "{point}"
            );
            let stored: Vec<u8> = w
                .db()
                .conn
                .query_row(
                    "SELECT exact_request_bytes FROM operations
                     WHERE kind = 'UPLOAD' AND state = 'PENDING'",
                    [],
                    |r| r.get(0),
                )
                .expect(point);
            assert_eq!(
                w.count("SELECT count(*) FROM upload_sessions"),
                0,
                "{point}: nothing is kept before the reply is"
            );
            if point == "reply not kept" {
                w.db().conn.execute_batch("DROP TRIGGER crash").unwrap();
            }

            assert_eq!(w.push().expect(point).version, 1, "{point}");
            let sent = w.sent("POST", "/uploads");
            assert_eq!(sent.len(), 2, "{point}");
            assert_eq!((&sent[0], &sent[1]), (&stored, &stored), "{point}");
            assert_eq!(w.fake().uploads.len(), 1, "{point}: no second upload");
            assert_eq!(w.fake().commits, 1, "{point}");
            let (kept, upload): (Vec<u8>, String) = w
                .db()
                .conn
                .query_row(
                    "SELECT exact_response_bytes, remote_upload_id FROM operations
                     WHERE kind = 'UPLOAD' AND state = 'COMPLETED'",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            let key = IdempotentMutationRequestV2::parse(&stored)
                .unwrap()
                .idempotency_key;
            assert_eq!(w.fake().stored[&key].2, kept, "{point}: exact stored bytes");
            let held = w.fake().uploads.keys().map(|k| hex(k)).collect::<Vec<_>>();
            assert_eq!(held, [upload], "{point}: the one upload");
        }
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

    /// Pull uses only a key whose grant reverifies now: none held refuses
    /// with no passphrase fallback; a head whose signer this device
    /// distrusts is refused as revoked (rule 6) and quarantines. Push then
    /// releases its lease and uploads nothing; over a pinned head that key
    /// signed it refuses before any request (owner decision 2026-11-02).
    #[test]
    fn a_missing_or_withdrawn_fleet_key_is_refused() {
        {
            let w = world();
            ledger::distrust_key(&w.db(), &w.dev.pin.0, &w.me.to.signing_key_id, NOW).unwrap();
            let err = w.push().unwrap_err();
            assert!(has(&err, "sync.noVerifiedFleetKey"), "{err:#}");
            assert_eq!(w.sent("POST", "/release").len(), 1);
            assert!(w.sent("POST", "/uploads").is_empty());
        }
        let w = world();
        w.push().unwrap();
        let distrust =
            || ledger::distrust_key(&w.db(), &w.dev.pin.0, &w.me.to.signing_key_id, NOW).unwrap();
        distrust();
        let err = w.push().unwrap_err();
        assert!(has(&err, "sync.signerRevoked"), "{err:#}");
        assert!(w.sent("POST", "/release").is_empty());
        assert_eq!(w.sent("POST", "/checkout").len(), 1, "only the first push");

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
        assert!(has(&err, "sync.signerRevoked"), "{err:#}");
        assert_eq!(w.state(LOCAL).1.as_deref(), Some("SIGNER_REVOKED"));
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
    /// counted, granted to the revoked key, or without activation evidence),
    /// before a lease is taken (ADR 0002 Q-18 "Refusal"). A `retired` one, or a generation verified after
    /// it, activated under a root the key never held and never granted to
    /// that key, does not block.
    #[test]
    fn a_compromised_revocation_blocks_commits_under_an_exposed_generation() {
        // Sealed to this device's HPKE key: only the subject matters here.
        let revoked = Recipient {
            device_id: [0x77; 16],
            signing_key_id: [0x77; 32],
            ..me().to
        };
        // The generation's activation evidence under root 0, which the
        // revoked key never held (C-1's root clause).
        let mut activated = vec![key_rotate(&me())];
        activated.extend(activation(&me(), GEN, &FKEK, 0, 61, None));
        let mut to_revoked = activated.clone();
        to_revoked.push(grant_to(&me(), &revoked, GEN, &FKEK, 41));
        for (reason, counted, extra, blocked) in [
            (DeviceRevocationReason::Compromised, 1, vec![], true),
            (DeviceRevocationReason::Retired, 1, vec![], false),
            (DeviceRevocationReason::Compromised, 0, vec![], true),
            (DeviceRevocationReason::Compromised, 0, activated, false),
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
                assert!(w.sent("POST", "/checkout").is_empty(), "before checkout");
                assert!(w.sent("POST", "/release").is_empty());
                assert!(w.sent("POST", "/uploads").is_empty());
            } else {
                assert_eq!(pushed.unwrap().version, 1, "{reason:?} {counted}");
            }
        }
    }

    /// The revoked custodian or member of the Q-18 tests, by its key alone.
    const REVOKED: [u8; 32] = [0x77; 32];

    /// This device's `key.rotate` over the tenant.
    fn key_rotate(me: &Me) -> Vec<u8> {
        let g = TenantCapabilityGrantV2 {
            common: common(14),
            subject: device_subject(me),
            scope_kind: CapabilityScopeKind::Tenant,
            scope_id: TENANT,
            capability: Capability::KeyRotate,
        };
        build_record(&me.sk, DOMAIN_TENANT_CAPABILITY_GRANT, &g.encode())
    }

    /// The activation evidence of `generation` of `FLEET` (key `fkek`), by
    /// this device: its `RecoveryGrant` under root `root_generation` and the
    /// `RotationGrant` that binds it, or names `bound` instead when given.
    fn activation(
        me: &Me,
        generation: u64,
        fkek: &[u8; 32],
        root_generation: u64,
        replay: u8,
        bound: Option<[u8; 32]>,
    ) -> Vec<Vec<u8>> {
        let fkek_key_id = shardx_core::fleet_grants::fkek_key_id(fkek);
        let recovery = RecoveryGrantV2 {
            common: common(replay),
            fleet_id: FLEET,
            fkek_key_id,
            generation,
            recipient_root_key_id: [8; 32],
            recipient_root_generation: root_generation,
            root_wrap_nonce_bytes: [1; 12],
            wrapped_fleet_key_bytes: [2; 48],
        };
        let recovery = build_record(&me.sk, DOMAIN_FLEET_KEY_GRANT_RECOVERY, &recovery.encode());
        let hash = *AuthorizationRecord::parse(&recovery)
            .unwrap()
            .signed_container_hash();
        let rotation = RotationGrantV2 {
            common: common(replay + 1),
            fleet_id: FLEET,
            fkek_key_id,
            generation,
            previous_fkek_key_id: [generation as u8; 32],
            previous_generation: generation - 1,
            required_device_grant_count: 1,
            required_device_grant_set_hash: [0; 32],
            recovery_grant_signed_container_hash: bound.unwrap_or(hash),
            activation_not_before_ms: T0,
        };
        let rotation = build_record(&me.sk, DOMAIN_FLEET_KEY_GRANT_ROTATION, &rotation.encode());
        vec![recovery, rotation]
    }

    /// This device's root grant of `root_generation` to `subject`: an
    /// existing-root grant, or a rotation grant from the generation before.
    fn root_grant(me: &Me, subject: [u8; 32], root_generation: u64, replay: u8) -> Vec<u8> {
        let g = TenantRootKeyGrantV2 {
            common: common(replay),
            variant: match root_generation {
                0 => RootGrantVariant::ExistingRootGrant,
                n => RootGrantVariant::RotationGrant {
                    previous_root_key_id: [8 + n as u8 - 1; 32],
                    previous_root_generation: n - 1,
                },
            },
            root_key_id: [8 + root_generation as u8; 32],
            root_generation,
            subject_account_id: [6; 16],
            subject_device_id: [0x77; 16],
            subject_signing_key_id: subject,
            recipient_hpke_key_id: [0x78; 32],
            subject_device_approval_replay_id: [0x79; 16],
            hpke_encapped_key_bytes: [3; 32],
            hpke_wrapped_trk_bytes: [4; 48],
        };
        build_record(&me.sk, DOMAIN_TENANT_ROOT_KEY_GRANT, &g.encode())
    }

    /// Counts a `compromised` revocation of `REVOKED` in evaluation `counted`.
    fn count_compromise_in(w: &World, counted: i64) {
        let revocation = DeviceRevocationV2 {
            common: common(30),
            subject_account_id: [6; 16],
            subject_device_id: [0x77; 16],
            subject_signing_key_id: REVOKED,
            subject_hpke_key_id: [0x78; 32],
            reason_code: DeviceRevocationReason::Compromised,
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
                    hex(&REVOKED),
                    counted,
                    container
                ],
            )
            .unwrap();
    }

    impl World {
        /// Collects `generation` of `FLEET` (key `fkek`) from evidence that
        /// holds the base tenant and `extra`, as a later evaluation.
        fn collect(&self, generation: u64, fkek: &[u8; 32], replay: u8, extra: Vec<Vec<u8>>) {
            let grant = grant_to(&self.me, &self.me.to, generation, fkek, replay);
            let ev = Ev {
                extra,
                ..Ev::default()
            };
            let mut pages = pages(&self.me, &self.grant, &ev);
            pages[0].containers.push(grant.clone());
            let mut db = self.db();
            let opened = crate::open_fleet_grant(
                &grant,
                &pages,
                &self.dev.pin,
                &self.me.to,
                &FLEET,
                generation,
                &self.me.hpke_sk,
                NOW,
                &mut db,
                "https://fleet.test",
                true,
            )
            .unwrap();
            assert!(opened.is_some(), "generation {generation} verifies");
        }

        fn blocked(&self, generation: u64) -> bool {
            ledger::commit_blocked(
                &self.db(),
                &self.dev.pin.0,
                &self.dev.pin.1,
                &FLEET,
                generation,
            )
            .unwrap()
        }
    }

    /// B1, Q-18 through the root (ADR 0002 C-1, revision 10-14 vectors):
    /// a compromised custodian D that knows root generation 0 but holds no
    /// grant of the fleet still blocks it, until the root is rotated first
    /// and the fleet after it. A fleet rotated before the root stays
    /// blocked; a root generation above the bound one that D later holds,
    /// PREPARING included, blocks again; missing or mismatched activation
    /// evidence blocks; generation 0 is checked from the first root.
    #[test]
    fn a_compromised_custodian_blocks_every_fleet_through_the_root() {
        let me = me();
        let (k2, k3, k4) = ([0x52; 32], [0x53; 32], [0x54; 32]);
        let base = |more: Vec<Vec<u8>>| {
            let mut v = vec![key_rotate(&me), root_grant(&me, REVOKED, 0, 60)];
            v.extend(activation(&me, GEN, &FKEK, 0, 61, None));
            v.extend(more);
            v
        };
        let w = world_with(base(vec![]));
        count_compromise_in(&w, 0);
        // The verifier's B1 case: D holds no grant of the fleet, which was
        // collected after the revocation was counted under exposed root 0.
        assert!(w.blocked(GEN), "generation 1 is under exposed root 0");
        let err = w.push().unwrap_err();
        assert!(has(&err, "sync.commitBlockedCompromised"), "{err:#}");

        // The fleet rotated before the root: its RecoveryGrant is under
        // root 0, so it stays blocked.
        w.collect(2, &k2, 70, base(activation(&me, 2, &k2, 0, 71, None)));
        assert!(w.blocked(2), "fleet rotated first");

        // Root rotated to 1, then the fleet to 3 under root 1: released.
        let rotated = |more: Vec<Vec<u8>>| {
            let mut v = base(activation(&me, 2, &k2, 0, 71, None));
            v.push(root_grant(&me, w.me.to.signing_key_id, 1, 80));
            v.extend(more);
            v
        };
        w.collect(3, &k3, 81, rotated(activation(&me, 3, &k3, 1, 82, None)));
        assert!(!w.blocked(3), "root first, then the fleet");

        // D later holds PREPARING root 2, above the bound root 1: blocked.
        let mut preparing = activation(&me, 3, &k3, 1, 82, None);
        preparing.push(root_grant(&me, REVOKED, 2, 85));
        w.collect(3, &k3, 84, rotated(preparing));
        assert!(w.blocked(3), "D holds a root above the bound one");

        // Generation 3 whose RotationGrant names another RecoveryGrant: the
        // evidence does not bind, so it is blocked; generation 4 has none.
        // One world at a time: each holds the config root.
        drop(w);
        let w = world_with(base(vec![]));
        count_compromise_in(&w, 0);
        w.collect(2, &k2, 70, base(activation(&me, 2, &k2, 0, 71, None)));
        w.collect(3, &k3, 81, {
            let mut v = base(activation(&me, 2, &k2, 0, 71, None));
            v.push(root_grant(&me, w.me.to.signing_key_id, 1, 80));
            v.extend(activation(&me, 3, &k3, 1, 82, Some([0xee; 32])));
            v
        });
        assert!(w.blocked(3), "mismatched activation evidence");
        w.collect(4, &k4, 90, base(vec![]));
        assert!(w.blocked(4), "missing activation evidence");
    }

    /// A key this device knows as a custodian (`trust_custodian_keys`, as a
    /// version 6 file kept it) with no root holding filed holds every root
    /// generation: missing evidence counts as flagged.
    #[test]
    fn a_known_custodian_with_no_root_holding_blocks() {
        let me = me();
        let mut extra = vec![key_rotate(&me)];
        extra.extend(activation(&me, GEN, &FKEK, 0, 61, None));
        let w = world_with(extra);
        count_compromise_in(&w, 0);
        assert!(!w.blocked(GEN), "nothing shows REVOKED as a custodian yet");
        w.db()
            .conn
            .execute(
                "INSERT INTO trust_custodian_keys
                 SELECT ?1, ?2, ?3, min(evaluation_id), 0, 0, NULL, NULL FROM trust_evaluations",
                params![hex(&INSTANCE), hex(&TENANT), hex(&REVOKED)],
            )
            .unwrap();
        assert!(w.blocked(GEN), "a custodian with no root holding");
    }

    /// N1: a `compromised` revocation of a key this device already counted
    /// as `lost` replaces the kept one, so the Q-18 block starts; a later
    /// `retired` one never replaces a kept `compromised` one.
    #[test]
    fn a_compromise_counted_after_a_lost_revocation_of_the_same_key_blocks() {
        let me = me();
        let device_revoke = TenantCapabilityGrantV2 {
            common: common(15),
            subject: device_subject(&me),
            scope_kind: CapabilityScopeKind::Tenant,
            scope_id: TENANT,
            capability: Capability::DeviceRevoke,
        };
        let device_revoke = build_record(
            &me.sk,
            DOMAIN_TENANT_CAPABILITY_GRANT,
            &device_revoke.encode(),
        );
        let revocation = |replay, reason_code| {
            let r = DeviceRevocationV2 {
                common: common(replay),
                subject_account_id: [6; 16],
                subject_device_id: [0x77; 16],
                subject_signing_key_id: REVOKED,
                subject_hpke_key_id: [0x78; 32],
                reason_code,
            };
            build_record(&me.sk, DOMAIN_DEVICE_REVOCATION, &r.encode())
        };
        // Rule 6 counts a revocation only of the device its key's approval names.
        let device_approve = TenantCapabilityGrantV2 {
            common: common(16),
            subject: device_subject(&me),
            scope_kind: CapabilityScopeKind::Tenant,
            scope_id: TENANT,
            capability: Capability::DeviceApprove,
        };
        let approval = DeviceApprovalV2 {
            common: common(0x79),
            subject_account_id: [6; 16],
            subject_device_id: [0x77; 16],
            subject_signing_key_id: REVOKED,
            subject_hpke_key_id: [0x78; 32],
            approval_scope_kind: ApprovalScopeKind::Tenant,
            approval_scope_id: TENANT,
        };
        let approved = |more: Vec<Vec<u8>>| {
            let mut v = vec![
                device_revoke.clone(),
                build_record(
                    &me.sk,
                    DOMAIN_TENANT_CAPABILITY_GRANT,
                    &device_approve.encode(),
                ),
                build_record(&me.sk, DOMAIN_DEVICE_APPROVAL, &approval.encode()),
            ];
            v.extend(more);
            v
        };
        let lost = revocation(30, DeviceRevocationReason::Lost);
        let compromised = revocation(31, DeviceRevocationReason::Compromised);
        let retired = revocation(32, DeviceRevocationReason::Retired);
        let w = world();
        let counted = || w.count("SELECT counted_evaluation FROM trust_proven_revocations");
        w.collect(2, &[0x52; 32], 70, approved(vec![lost]));
        assert!(!w.blocked(GEN), "lost stays advisory");
        let first = counted();
        w.collect(3, &[0x53; 32], 71, approved(vec![compromised.clone()]));
        assert!(w.blocked(GEN), "the compromise replaces the kept lost one");
        assert_eq!(counted(), first, "the earliest count stays");
        w.collect(4, &[0x54; 32], 72, approved(vec![compromised, retired]));
        assert!(w.blocked(GEN), "retired never replaces compromised");
    }

    /// U2 (Q-57): a member revoked as `compromised`, the reason Revoke now
    /// offers for a member row, blocks pushes under the key it held; the
    /// custodian's rotation, once this device collects the new key, lets
    /// pushes seal again.
    #[test]
    fn a_member_revoked_as_compromised_blocks_pushes_until_a_rotation_and_collect() {
        let reason = crate::fleet_custody::revoke_reason("compromised").unwrap();
        let me = me();
        let capability = |replay, capability| {
            let g = TenantCapabilityGrantV2 {
                common: common(replay),
                subject: device_subject(&me),
                scope_kind: CapabilityScopeKind::Tenant,
                scope_id: TENANT,
                capability,
            };
            build_record(&me.sk, DOMAIN_TENANT_CAPABILITY_GRANT, &g.encode())
        };
        let approval = DeviceApprovalV2 {
            common: common(0x79),
            subject_account_id: [6; 16],
            subject_device_id: [0x77; 16],
            subject_signing_key_id: REVOKED,
            subject_hpke_key_id: [0x78; 32],
            approval_scope_kind: ApprovalScopeKind::Fleet,
            approval_scope_id: TENANT,
        };
        let revocation = DeviceRevocationV2 {
            common: common(30),
            subject_account_id: [6; 16],
            subject_device_id: [0x77; 16],
            subject_signing_key_id: REVOKED,
            subject_hpke_key_id: [0x78; 32],
            reason_code: reason,
        };
        let mut evidence = vec![
            capability(15, Capability::DeviceRevoke),
            capability(16, Capability::DeviceApprove),
            build_record(&me.sk, DOMAIN_DEVICE_APPROVAL, &approval.encode()),
            build_record(&me.sk, DOMAIN_DEVICE_REVOCATION, &revocation.encode()),
        ];
        let w = world();
        w.collect(2, &[0x52; 32], 70, evidence.clone());
        assert!(w.blocked(2), "the member may hold generation 2");
        let err = w.push().unwrap_err();
        assert!(has(&err, "sync.commitBlockedCompromised"), "{err:#}");
        assert!(w.sent("POST", "/checkout").is_empty(), "before checkout");

        // The rotation: generation 3, activated under root 0, which the
        // member never held, and never granted to it.
        evidence.push(key_rotate(&me));
        evidence.extend(activation(&me, 3, &[0x53; 32], 0, 61, None));
        w.collect(3, &[0x53; 32], 72, evidence);
        assert!(!w.blocked(3), "the new key is not exposed");
        assert!(w.blocked(2), "the old one stays blocked");
        // The collect keeps the key it opened (`keep_fleet_key`), and the
        // server's checkout now names generation 3.
        assert!(crate::fleet_keys::collect(&hex(&FLEET), 3, &[0x53; 32]).unwrap());
        {
            let mut f = w.fake();
            f.generation = Some(3);
            f.fkek_key_id = Some(shardx_core::fleet_grants::fkek_key_id(&[0x53; 32]));
        }
        let pushed = w.push().unwrap();
        assert_eq!(pushed.version, 1);
    }

    /// B3, Q-18 "In-flight commits": a COMMIT persisted while its upload is
    /// still OPEN, chunks unsent, when a compromise is counted, is aborted:
    /// no chunk, finalize or commit is sent, the upload is ABORTED, the
    /// operation fails with the commit-blocked code, and the lease is let go.
    /// The next push is refused before it takes a lease.
    #[test]
    fn an_open_upload_is_aborted_once_a_compromise_is_counted() {
        let w = world();
        w.fake().refuse.push(("head", 401));
        let err = w.push().unwrap_err();
        assert!(has(&err, "sync.authRequired"), "{err:#}");
        assert_eq!(
            w.count("SELECT count(*) FROM upload_sessions WHERE state = 'OPEN'"),
            1
        );
        assert!(w.sent("PATCH", "").is_empty(), "nothing sent yet");
        count_a_compromise(&w);
        let err = w.push().unwrap_err();
        assert!(has(&err, "sync.commitBlockedCompromised"), "{err:#}");
        assert!(w.sent("PATCH", "").is_empty(), "no chunk after the count");
        assert!(w.sent("POST", "/finalize").is_empty());
        assert!(w.sent("POST", "/commit").is_empty());
        assert_eq!(
            w.count("SELECT count(*) FROM upload_sessions WHERE state = 'ABORTED'"),
            1
        );
        let server = w
            .fake()
            .uploads
            .values()
            .map(|u| u.state)
            .collect::<Vec<_>>();
        assert_eq!(server, ["ABORTED"], "aborted on the server too");
        assert_eq!(
            w.count("SELECT count(*) FROM operations WHERE kind = 'COMMIT' AND state = 'FAILED'"),
            1
        );
        assert_eq!(
            w.count("SELECT count(*) FROM profile_bindings WHERE lease_id IS NULL"),
            1
        );
        let checkouts = w.sent("POST", "/checkout").len();
        let err = w.push().unwrap_err();
        assert!(has(&err, "sync.commitBlockedCompromised"), "{err:#}");
        assert_eq!(
            w.sent("POST", "/checkout").len(),
            checkouts,
            "refused before checkout"
        );
    }

    /// B3 mid-transfer: a compromise counted while the chunks go out stops
    /// the upload before the next chunk or the finalize: it is ABORTED, no
    /// finalize or commit is sent, the operation fails with the
    /// commit-blocked code, and the lease is let go.
    #[test]
    fn a_compromise_counted_mid_transfer_aborts_the_upload() {
        let w = world();
        let sql = a_compromise(&w);
        w.fake().on_patch = Some(sql);
        let err = w.push().unwrap_err();
        assert!(has(&err, "sync.commitBlockedCompromised"), "{err:#}");
        assert!(w.fake().on_patch.is_none(), "counted during a PATCH");
        assert_eq!(w.sent("PATCH", "").len(), 1, "no chunk after the count");
        assert!(w.sent("POST", "/finalize").is_empty());
        assert!(w.sent("POST", "/commit").is_empty());
        assert_eq!(
            w.count("SELECT count(*) FROM upload_sessions WHERE state = 'ABORTED'"),
            1
        );
        let server = w
            .fake()
            .uploads
            .values()
            .map(|u| u.state)
            .collect::<Vec<_>>();
        assert_eq!(server, ["ABORTED"], "aborted on the server too");
        assert_eq!(
            w.count("SELECT count(*) FROM operations WHERE kind = 'COMMIT' AND state = 'FAILED'"),
            1
        );
        assert_eq!(
            w.count("SELECT count(*) FROM profile_bindings WHERE lease_id IS NULL"),
            1
        );
    }

    /// N2: a FINALIZE stored but dropped unprocessed leaves the upload OPEN
    /// (it never reached READY), so a compromise counted before the push
    /// resumes aborts it: the stored finalize is not sent again, and no
    /// commit is sent.
    #[test]
    fn a_stored_finalize_is_not_sent_once_a_compromise_is_counted() {
        let w = world();
        w.fake().skip.push("finalize");
        let err = w.push().unwrap_err();
        assert!(has(&err, "fleet.refusedSync"), "{err:#}");
        assert_eq!(
            w.count(
                "SELECT count(*) FROM operations WHERE kind = 'FINALIZE' AND state = 'PENDING'"
            ),
            1
        );
        count_a_compromise(&w);
        let err = w.push().unwrap_err();
        assert!(has(&err, "sync.commitBlockedCompromised"), "{err:#}");
        assert_eq!(w.sent("POST", "/finalize").len(), 1, "only the dropped one");
        assert!(w.sent("POST", "/commit").is_empty());
        assert_eq!(
            w.count("SELECT count(*) FROM upload_sessions WHERE state = 'ABORTED'"),
            1
        );
        let server = w
            .fake()
            .uploads
            .values()
            .map(|u| u.state)
            .collect::<Vec<_>>();
        assert_eq!(server, ["ABORTED"], "aborted on the server too");
        assert_eq!(
            w.count("SELECT count(*) FROM profile_bindings WHERE lease_id IS NULL"),
            1
        );
    }

    /// Q-18 "Local state": a blocked push, aborted in flight or refused
    /// before checkout, leaves the binding AVAILABLE and dirty with the
    /// client-local `ROTATION_REQUIRED_COMPROMISED`; a push past the check
    /// (the block released) drops the code, even if its checkout then fails.
    #[test]
    fn a_blocked_push_leaves_the_profile_available_and_dirty_with_the_local_code() {
        let state = |w: &World| {
            w.db()
                .conn
                .query_row(
                    "SELECT sync_state, dirty, last_error_code FROM profile_bindings",
                    [],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, i64>(1)?,
                            r.get::<_, Option<String>>(2)?,
                        ))
                    },
                )
                .unwrap()
        };
        let blocked = || ("AVAILABLE".to_string(), 1, Some(COMPROMISED.to_string()));
        let w = world();
        w.fake().on_patch = Some(a_compromise(&w));
        w.push().unwrap_err();
        assert_eq!(state(&w), blocked(), "aborted in flight");
        drop(w);
        let w = world();
        w.db()
            .conn
            .execute("UPDATE profile_bindings SET dirty = 1", [])
            .unwrap();
        count_a_compromise(&w);
        w.push().unwrap_err();
        assert_eq!(state(&w), blocked(), "refused before checkout");
        drop(w);
        let w = world();
        w.db()
            .conn
            .execute(
                "UPDATE profile_bindings SET last_error_code = ?1",
                [COMPROMISED],
            )
            .unwrap();
        w.fake().refuse.push(("checkout", 503));
        w.push().unwrap_err();
        assert_eq!(state(&w).2, None, "released");
    }

    /// B2: an exposure this device saw stays, whatever a later collection of
    /// the same generation leaves out.
    #[test]
    fn an_exposure_survives_a_recollection_that_omits_its_grant() {
        let me = me();
        let revoked = Recipient {
            device_id: [0x77; 16],
            signing_key_id: REVOKED,
            ..me.to
        };
        let mut evidence = vec![key_rotate(&me)];
        evidence.extend(activation(&me, GEN, &FKEK, 0, 61, None));
        let mut with_grant = evidence.clone();
        with_grant.push(grant_to(&me, &revoked, GEN, &FKEK, 41));
        let w = world_with(with_grant);
        count_compromise_in(&w, 1);
        assert!(w.blocked(GEN));
        // A hostile server serves the same generation again without the
        // revoked member's grant: the grant evaluation moves past the one
        // that counted the revocation.
        w.collect(GEN, &FKEK, 42, evidence);
        assert!(w.blocked(GEN), "the exposure is never forgotten");
    }

    /// Probe 10 (L2045, G2-42), the wire side of the sync tables: the
    /// conversion to a row refuses an integer past `i64::MAX` with
    /// `WIRE_INTEGER_OUT_OF_RANGE`, and a lease whose expiry is one never
    /// parses, so it reaches no row, whether it arrives in a checkout's or a
    /// publish's reply.
    #[test]
    fn a_server_integer_past_the_signed_range_is_refused_before_any_row() {
        assert_eq!(wire(i64::MAX as u64).unwrap(), i64::MAX);
        for past in [1u64 << 63, u64::MAX] {
            assert_eq!(
                wire(past).unwrap_err().to_string(),
                "WIRE_INTEGER_OUT_OF_RANGE"
            );
        }
        for publish in [false, true] {
            let w = if publish { world_unbound() } else { world() };
            w.fake().expires = Some(u64::MAX);
            let err = if publish {
                w.publish().map(|_| ()).unwrap_err()
            } else {
                w.push().map(|_| ()).unwrap_err()
            };
            assert!(has(&err, "sync.badReplySync"), "publish {publish}: {err:#}");
            let rows = |w: &World| {
                w.count(
                    "SELECT count(*) FROM profile_bindings
                     WHERE lease_id IS NOT NULL OR lease_expires_at IS NOT NULL",
                )
            };
            assert_eq!(rows(&w), 0, "publish {publish}");
            if publish {
                assert_eq!(w.count("SELECT count(*) FROM profile_bindings"), 0);
                assert!(!is_published(LOCAL).unwrap());
            }
        }
    }

    /// G2-35 (plan L2032), the launcher half of WP-14: a kept
    /// `DeviceRevocationV2` is reloaded before the Q-18 commit block reads it,
    /// with every column its row carries equal to the exact bytes: the row's
    /// key is the revoked key, and the container is a revocation of this
    /// tenant and instance. A row that does not reload makes the ledger
    /// unreadable and nothing is uploaded; one that reloads but whose signer
    /// this device cannot verify still counts as `compromised`.
    #[test]
    fn a_kept_revocation_reloads_with_every_column_equal() {
        let mut other_tenant = common(30);
        other_tenant.tenant_id = [0x55; 16];
        let mut other_instance = common(30);
        other_instance.server_instance_id = [0x56; 16];
        let revocation = |common: CommonFields, subject: [u8; 32]| DeviceRevocationV2 {
            common,
            subject_account_id: [6; 16],
            subject_device_id: [0x77; 16],
            subject_signing_key_id: subject,
            subject_hpke_key_id: [0x78; 32],
            reason_code: DeviceRevocationReason::Compromised,
        };
        let stranger = Ed25519SigningKey::from_bytes(&[9; 32]);
        for (what, container, unreadable) in [
            ("a matching revocation", None, false),
            (
                "another revoked key",
                Some(revocation(common(30), [0x79; 32])),
                true,
            ),
            (
                "another tenant",
                Some(revocation(other_tenant, [0x77; 32])),
                true,
            ),
            (
                "another instance",
                Some(revocation(other_instance, [0x77; 32])),
                true,
            ),
        ] {
            let w = world();
            let matching = revocation(common(30), [0x77; 32]);
            let container = build_record(
                &w.me.sk,
                DOMAIN_DEVICE_REVOCATION,
                &container.unwrap_or(matching).encode(),
            );
            w.db()
                .conn
                .execute(
                    "INSERT INTO trust_proven_revocations
                     VALUES (?1, ?2, ?3, 'DEVICE_REVOCATION', 1, 0, ?4)",
                    params![hex(&INSTANCE), hex(&TENANT), hex(&[0x77; 32]), container],
                )
                .unwrap();
            let err = w.push().unwrap_err();
            let key = if unreadable {
                "team.trustLedgerUnreadable"
            } else {
                "sync.commitBlockedCompromised"
            };
            assert!(has(&err, key), "{what}: {err:#}");
            assert!(w.sent("POST", "/uploads").is_empty(), "{what}");
        }
        // A kept row that is not a revocation at all, or not even a record.
        let w = world();
        let not_a_revocation = w.grant.clone();
        let mut g = DeviceHpkeGrantV2 {
            common: common(40),
            fleet_id: FLEET,
            fkek_key_id: shardx_core::fleet_grants::fkek_key_id(&FKEK),
            generation: GEN,
            subject_account_id: w.me.to.account_id,
            subject_device_id: w.me.to.device_id,
            subject_signing_key_id: w.me.to.signing_key_id,
            recipient_hpke_key_id: w.me.to.hpke_key_id,
            hpke_encapped_key_bytes: Vec::new(),
            hpke_wrapped_fleet_key_bytes: Vec::new(),
        };
        shardx_core::grants::seal_device_fkek(&w.me.hpke_pk, &mut g, &FKEK).unwrap();
        let by_stranger = build_record(&stranger, DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE, &g.encode());
        for (what, container) in [
            ("another record", not_a_revocation),
            ("another record this device cannot verify", by_stranger),
            ("bytes that are no record", vec![1, 2, 3]),
        ] {
            w.db()
                .conn
                .execute(
                    "INSERT OR REPLACE INTO trust_proven_revocations
                     VALUES (?1, ?2, ?3, 'DEVICE_REVOCATION', 1, 0, ?4)",
                    params![hex(&INSTANCE), hex(&TENANT), hex(&[0x77; 32]), container],
                )
                .unwrap();
            let err = w.push().unwrap_err();
            assert!(has(&err, "team.trustLedgerUnreadable"), "{what}: {err:#}");
            assert!(w.sent("POST", "/uploads").is_empty(), "{what}");
        }
        // Signed by a key this device has no evidence for: it cannot verify
        // the reason, so the revocation counts as `compromised` (Q-18).
        drop(w);
        let w = world();
        let unverifiable = build_record(
            &stranger,
            DOMAIN_DEVICE_REVOCATION,
            &revocation(common(30), [0x77; 32]).encode(),
        );
        w.db()
            .conn
            .execute(
                "INSERT INTO trust_proven_revocations
                 VALUES (?1, ?2, ?3, 'DEVICE_REVOCATION', 1, 0, ?4)",
                params![hex(&INSTANCE), hex(&TENANT), hex(&[0x77; 32]), unverifiable],
            )
            .unwrap();
        let err = w.push().unwrap_err();
        assert!(has(&err, "sync.commitBlockedCompromised"), "{err:#}");
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

    /// Author `A`: another device, by its key.
    fn author() -> Ed25519SigningKey {
        Ed25519SigningKey::from_bytes(&[0x70; 32])
    }

    /// Evidence where this device approved `A` and granted it `profile.commit`
    /// over the fleet, both until `ends`; with `revoked`, it also holds
    /// `device.revoke` and signed a revocation of `A`, and with `reported`,
    /// the server reports `A`'s device revoked.
    fn author_pages(
        w: &World,
        ends: u64,
        revoked: bool,
        reported: bool,
    ) -> Vec<TenantTrustEvidencePageV2> {
        let reason = revoked.then_some(DeviceRevocationReason::Compromised);
        author_pages_for(w, ends, reason, reported)
    }

    /// [`author_pages`], with `A`'s revocation for `reason` when given.
    fn author_pages_for(
        w: &World,
        ends: u64,
        reason: Option<DeviceRevocationReason>,
        reported: bool,
    ) -> Vec<TenantTrustEvidencePageV2> {
        let k = author();
        let kid = shardx_core::keys::signing_key_id(k.verifying_key().as_bytes());
        let until = |replay| CommonFields {
            not_after_ms: ends,
            ..common(replay)
        };
        let own = |replay, capability| TenantCapabilityGrantV2 {
            common: common(replay),
            subject: device_subject(&w.me),
            scope_kind: CapabilityScopeKind::Tenant,
            scope_id: TENANT,
            capability,
        };
        let approval = DeviceApprovalV2 {
            common: until(0x70),
            subject_account_id: [0x70; 16],
            subject_device_id: [0x71; 16],
            subject_signing_key_id: kid,
            subject_hpke_key_id: [0x70; 32],
            approval_scope_kind: ApprovalScopeKind::Tenant,
            approval_scope_id: TENANT,
        };
        let commit = TenantCapabilityGrantV2 {
            common: until(0x72),
            subject: GrantSubject::Device {
                account_id: [0x70; 16],
                device_id: [0x71; 16],
                signing_key_id: kid,
                hpke_key_id: [0x70; 32],
            },
            scope_kind: CapabilityScopeKind::Fleet,
            scope_id: FLEET,
            capability: Capability::ProfileCommit,
        };
        let mut extra = vec![
            build_record(&w.me.sk, DOMAIN_DEVICE_APPROVAL, &approval.encode()),
            build_record(
                &w.me.sk,
                DOMAIN_TENANT_CAPABILITY_GRANT,
                &own(0x71, Capability::DeviceApprove).encode(),
            ),
            build_record(&w.me.sk, DOMAIN_TENANT_CAPABILITY_GRANT, &commit.encode()),
        ];
        if let Some(reason_code) = reason {
            let revocation = DeviceRevocationV2 {
                common: common(0x74),
                subject_account_id: [0x70; 16],
                subject_device_id: [0x71; 16],
                subject_signing_key_id: kid,
                subject_hpke_key_id: [0x70; 32],
                reason_code,
            };
            extra.push(build_record(
                &w.me.sk,
                DOMAIN_TENANT_CAPABILITY_GRANT,
                &own(0x73, Capability::DeviceRevoke).encode(),
            ));
            extra.push(build_record(
                &w.me.sk,
                DOMAIN_DEVICE_REVOCATION,
                &revocation.encode(),
            ));
        }
        let ev = Ev {
            extra,
            ..Ev::default()
        };
        let mut p = pages(&w.me, &w.grant, &ev);
        p[0].signing_public_keys.push(k.verifying_key().to_bytes());
        if reported {
            p[0].device_revocations.push(RevokedDevice {
                device_id: [0x71; 16],
                revoked_at_ms: T0 + DAY / 2,
            });
        }
        p
    }

    /// `w` with `A`'s head pinned on a second binding, enrolled under `root`,
    /// that accepted it as a new head while `A` held grants until `ends`.
    fn pinned_by_author(w: &World, root: &Path, ends: u64) {
        w.push().unwrap();
        w.fake().pages = author_pages(w, ends, false, false)[0].encode();
        let head = forge(w, &author(), |_| {});
        w.fake().head = Some(head);
        w.enroll(root);
        w.pull(&root.join("first")).unwrap();
        assert_eq!(w.state(LOCAL).4, Some(head.to_vec()));
    }

    /// Rule 6, "Revoked signer": a pinned head whose signer is since proven
    /// revoked (a signed revocation in this pull's evidence) or reported
    /// revoked (the server's unsigned report alone) is not restored again;
    /// the binding quarantines with `SIGNER_REVOKED`.
    #[test]
    fn a_pinned_head_of_a_since_revoked_signer_is_not_restored() {
        for (revoked, reported) in [(true, false), (false, true)] {
            let w = world();
            let other = tempfile::tempdir().unwrap();
            pinned_by_author(&w, other.path(), T0 + 300 * DAY);
            w.fake().pages = author_pages(&w, T0 + 300 * DAY, revoked, reported)[0].encode();
            let out = other.path().join("out");
            let err = w.pull(&out).unwrap_err();
            assert!(has(&err, "sync.signerRevoked"), "{revoked}: {err:#}");
            let (state, reason, ..) = w.state(LOCAL);
            assert_eq!(
                (state.as_str(), reason.as_deref()),
                ("QUARANTINED", Some("SIGNER_REVOKED")),
                "{revoked}"
            );
            assert!(!out.exists(), "{revoked}");
        }
    }

    /// Rule 6, "Pinning": a pinned head stays readable after its signer's
    /// approval and `profile.commit` expire.
    #[test]
    fn a_pinned_head_stays_readable_after_its_signers_grants_expire() {
        let w = world();
        let other = tempfile::tempdir().unwrap();
        pinned_by_author(&w, other.path(), T0 + 2 * DAY);
        let out = other.path().join("out");
        assert!(w.pull_at(&out, T0 + 3 * DAY).unwrap() > 0);
        assert!(out.join("Preferences").exists());
        assert_eq!(w.state(LOCAL).0, "AVAILABLE");
    }

    /// Rule 6 and its ledger update: a signed revocation of the signer in this
    /// pull's own evidence is counted, with no unsigned report, so its new
    /// head is refused and the binding quarantines. The valid head before it
    /// is pinned first (owner decision B, ADR 0002 "advance over valid heads
    /// first"), and the refused head is kept as an open run above it.
    #[test]
    fn a_new_head_of_a_signer_revoked_in_this_pulls_evidence_is_refused() {
        let w = world();
        let heads = chain_of(&w, &[&w.me.sk, &author()]);
        w.fake().pages = author_pages(&w, T0 + 300 * DAY, true, false)[0].encode();
        let other = tempfile::tempdir().unwrap();
        w.enroll(other.path());
        let out = other.path().join("out");
        let err = w.pull(&out).unwrap_err();
        assert!(has(&err, "sync.signerRevokedAtP"), "{err:#}");
        let (state, reason, _, version, head) = w.state(LOCAL);
        assert_eq!(
            (state.as_str(), reason.as_deref(), version, head),
            (
                "QUARANTINED",
                Some("SIGNER_REVOKED"),
                1,
                Some(heads[0].to_vec())
            )
        );
        assert!(out.join("Preferences").exists());
        assert_eq!(skipped(&w), [(2, None, None, 1)]);
        let kid = shardx_core::keys::signing_key_id(author().verifying_key().as_bytes());
        assert!(ledger::withdrawn(&w.db(), &w.dev.pin.0, &kid).unwrap());
    }

    /// Rule 6 and its ledger update: an unsigned report of the signer that a
    /// pull saw is kept, so a later evaluation whose evidence omits it still
    /// holds the signer reported revoked.
    #[test]
    fn a_report_of_a_revoked_signer_a_pull_saw_is_kept() {
        let w = world();
        w.push().unwrap();
        w.fake().pages = author_pages(&w, T0 + 300 * DAY, false, true)[0].encode();
        let head = forge(&w, &author(), |_| {});
        w.fake().head = Some(head);
        let other = tempfile::tempdir().unwrap();
        w.enroll(other.path());
        let out = other.path().join("out");
        let err = w.pull(&out).unwrap_err();
        assert!(!out.exists());
        let omitted = author_pages(&w, T0 + 300 * DAY, false, false);
        let (_, chain) = ledger::evaluate(&w.db(), &w.dev.pin.0, &w.dev.pin.1, &omitted, NOW)
            .unwrap()
            .unwrap();
        let kid = shardx_core::keys::signing_key_id(author().verifying_key().as_bytes());
        assert!(chain.reported_revoked_at(&kid, NOW), "the report was kept");
        assert!(has(&err, "sync.signerRevoked"), "{err:#}");
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
            true,
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
    /// lease on the old one: it is released as stored and the checkout is
    /// failed. Moved by a restore transition (`base_version` stays 0: the
    /// data never followed), the push then stops for a pull; moved by a
    /// pull (data and head together), it takes a fresh lease at the new head.
    #[test]
    fn a_replayed_checkout_on_an_old_head_is_released_and_taken_again() {
        for base in [0, 1] {
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
                    "UPDATE profile_bindings SET remote_version = 1, base_version = ?2,
                       last_observed_head_hash = ?1",
                    params![head.to_vec(), base],
                )
                .unwrap();
            let checkouts = if base == 0 {
                let err = w.push().unwrap_err();
                assert!(has(&err, "sync.remoteAhead"), "{err:#}");
                assert_eq!(
                    w.count("SELECT count(*) FROM profile_bindings WHERE lease_id IS NULL"),
                    1
                );
                2
            } else {
                assert_eq!(w.push().unwrap().version, 2);
                3
            };
            let sent = w.sent("POST", "/checkout");
            assert_eq!(sent.len(), checkouts, "base {base}");
            assert_eq!(sent[0], sent[1]);
            assert!(sent.get(2).is_none_or(|c| c != &sent[1]));
            assert_eq!(w.sent("POST", "/release").len(), 1, "base {base}");
            assert_eq!(
                w.count(
                    "SELECT count(*) FROM operations WHERE kind = 'CHECKOUT' AND state = 'FAILED'"
                ),
                1
            );
            assert_eq!(
                w.count("SELECT count(*) FROM operations WHERE state = 'PENDING'"),
                0
            );
        }
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

    /// A lease a version 5 file carried is marked LEASE_AT_RISK, its expiry
    /// unknown: it is still held, so a pull does not write over the profile
    /// and the next push goes on with that lease.
    #[test]
    fn a_lease_at_risk_is_still_a_held_lease() {
        let w = world();
        w.fake().tamper = Some("manifest");
        w.push().unwrap_err();
        w.db()
            .conn
            .execute(
                "UPDATE profile_bindings SET sync_state = 'LEASE_AT_RISK',
                   lease_expires_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
                [],
            )
            .unwrap();
        let out = w.udd.with_file_name("out");
        let err = w.pull(&out).unwrap_err();
        assert!(has(&err, "sync.pushPending"), "{err:#}");
        assert!(!out.exists());
        w.fake().tamper = None;
        assert_eq!(w.push().unwrap().version, 1);
        assert_eq!(w.sent("POST", "/checkout").len(), 1, "the same lease");
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
                "UPDATE profile_bindings SET lease_id = NULL, fencing_token = NULL,
                   lease_expires_at = NULL",
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
                    "INSERT INTO profile_bindings(local_profile_id, server_id, server_instance_id,
                       tenant_id, account_id, device_id, fleet_id, remote_profile_id,
                       remote_version, base_version, last_observed_head_hash,
                       accepted_restore_epoch, fkek_key_id, key_generation, sync_state, dirty)
                     SELECT ?1, k.server_id, k.server_instance_id, k.tenant_id, d.account_id,
                       k.device_id, k.fleet_id, ?2, ?3, ?3, ?4, 0, k.fkek_key_id, k.generation,
                       'AVAILABLE', 0
                     FROM fleet_key_state k
                     JOIN device_state d USING (server_id, tenant_id, device_id)
                     WHERE k.state = 'ACTIVE'",
                    params![local, hex(&profile), version as i64, head.to_vec()],
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

    /// Runs `job` on its own thread, with its own runtime and client for the
    /// fake server at `base`, and waits for it: a call that never returns
    /// fails the test instead of hanging it.
    fn within<T: Send + 'static>(
        what: &str,
        base: &str,
        job: impl FnOnce(&tokio::runtime::Runtime, &FleetClient, &Device) -> T + Send + 'static,
    ) -> std::sync::mpsc::Receiver<T> {
        let (tx, rx) = std::sync::mpsc::channel();
        let base = base.to_string();
        std::thread::Builder::new()
            .name(what.into())
            .spawn(move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let client = FleetClient::new(&base, "").unwrap();
                tx.send(job(&rt, &client, &device(&me()))).ok();
            })
            .unwrap();
        rx
    }

    fn finished<T>(what: &str, rx: &std::sync::mpsc::Receiver<T>) -> T {
        rx.recv_timeout(std::time::Duration::from_secs(60))
            .unwrap_or_else(|_| panic!("{what} did not finish: a deadlock"))
    }

    /// Q-36 follow-up: a publish right after a restore epoch's acceptance, and
    /// one running while another handle on the same database accepts it, both
    /// finish. No lock is held across an `.await` and no second handle is
    /// opened inside a transaction: the only locks are SQLite's file locks
    /// (taken by single statements or by transactions that make no network
    /// call, and bounded by the 5 s busy timeout) and the profile claims,
    /// which refuse instead of waiting. A new profile starts at the epoch the
    /// server lists, whichever of the two ran first. The acceptance's own
    /// transaction reads before it writes, so it begins immediate: a deferred
    /// one that had to upgrade under a committing publish was refused with
    /// "database is locked" (3 runs in 40 before the fix).
    #[test]
    fn a_publish_at_a_restore_epoch_never_waits_on_its_acceptance() {
        // The racing case is repeated: the window it closes is a few statements wide.
        for concurrent in [false, true, true, true, true, true] {
            let w = world();
            let (h1, h2) = restored(&w);
            let leaves = [
                leaf(PROFILE, h2, h1),
                leaf([0xc4; 16], [7; 32], [8; 32]),
                leaf([0xc5; 16], [9; 32], [10; 32]),
            ];
            let t = transition(&w.me, 0, &leaves);
            w.file(&w.me.sk, &t, &leaves, &[PROFILE], 0);
            let base = w.client.base_url().to_string();
            // A second handle, open and idle for the whole test.
            let _idle = Db::open().unwrap();
            let out = w.udd.with_file_name("out");
            let accept = {
                let out = out.clone();
                move |rt: &tokio::runtime::Runtime, c: &FleetClient, d: &Device| {
                    rt.block_on(pull(c, "t", d, LOCAL, &out, NOW))
                }
            };
            let publish_new = |rt: &tokio::runtime::Runtime, c: &FleetClient, d: &Device| {
                rt.block_on(publish(
                    c,
                    "t",
                    d,
                    "local-new",
                    "Second",
                    FLEET,
                    PROFILE2,
                    NOW,
                ))
            };
            let (accepted, published) = if concurrent {
                let a = within("accept", &base, accept);
                let p = within("publish", &base, publish_new);
                (finished("accept", &a), finished("publish", &p))
            } else {
                let accepted = finished("accept", &within("accept", &base, accept));
                let p = within("publish", &base, publish_new);
                (accepted, finished("publish", &p))
            };
            assert!(accepted.unwrap() > 0, "{concurrent}");
            published.unwrap();
            assert_eq!(w.state(LOCAL).2, 1, "{concurrent}");
            assert_eq!(w.state("local-new").2, 1, "{concurrent}");
        }
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
    /// accepted, and is released the same way.
    #[test]
    fn a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key() {
        let w = world();
        {
            let mut f = w.fake();
            f.expires = Some(T0);
            f.lose.push("checkout");
        }
        w.push().unwrap_err();
        // The lease the new key takes is an ordinary one.
        w.fake().expires = None;
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
            "UPDATE profile_bindings SET lease_id = 'x', fencing_token = 1, lease_expires_at = 'x'",
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
    /// with it; the pull then records its own.
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
        assert_eq!(evaluations(), before + 2);
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

    // ------------------------------------------------------------ revert ----
    // ADR 0002 rule 6, "Revert acceptance rule": the reader side.

    fn key_id_of(sk: &Ed25519SigningKey) -> [u8; 32] {
        shardx_core::keys::signing_key_id(sk.verifying_key().as_bytes())
    }

    /// Pushes one version per signer, the profile's `marker` file reading
    /// `v1`, `v2`, ..., then re-signs version `v` by `signers[v - 1]`, each
    /// on the head below it, and lists the last. The heads, by version from 1.
    fn chain_of(w: &World, signers: &[&Ed25519SigningKey]) -> Vec<[u8; 32]> {
        for v in 1..=signers.len() {
            std::fs::write(w.udd.join("marker"), format!("v{v}")).unwrap();
            w.push().unwrap();
        }
        let mut f = w.fake();
        let mut heads: Vec<[u8; 32]> = Vec::new();
        for (i, sk) in signers.iter().enumerate() {
            let v = i as u64 + 1;
            let m = SignedSnapshotManifestV2::parse(&f.manifests[&v]).unwrap();
            let mut p = SnapshotManifestV2::parse(m.canonical_manifest_payload_bytes()).unwrap();
            p.signer_signing_key_id = key_id_of(sk);
            p.previous_signed_head_hash = heads.last().copied();
            let signed = SignedSnapshotManifestV2::sign(sk, &p).unwrap();
            heads.push(signed.head_hash());
            f.manifests.insert(v, signed.exact_bytes().to_vec());
        }
        f.head = heads.last().copied();
        heads
    }

    /// Another device's config root, enrolled: `LOCAL` bound at version 0.
    fn second(w: &World) -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        w.enroll(d.path());
        d
    }

    /// Pins `heads[k - 1]` on the enrolled device, listing only up to it.
    fn pin_at(w: &World, d: &tempfile::TempDir, heads: &[[u8; 32]], k: u64) {
        w.fake().listed = Some((k, Some(heads[k as usize - 1])));
        w.pull(&d.path().join(format!("pin-{k}"))).unwrap();
        w.fake().listed = None;
        assert_eq!(w.state(LOCAL).3, k as i64);
    }

    /// A skip audit row: version, resolution, accepted head, anchor version.
    type Skip = (i64, Option<String>, Option<Vec<u8>>, i64);

    /// The skip audit by version.
    fn skipped(w: &World) -> Vec<Skip> {
        let db = w.db();
        let mut s = db
            .conn
            .prepare(
                "SELECT target_version, resolution, accepted_head_hash, anchor_version
                 FROM skipped_heads ORDER BY target_version",
            )
            .unwrap();
        let rows = s
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        rows
    }

    fn accepted_by(version: i64, r: [u8; 32], anchor: i64) -> Skip {
        (version, Some("ACCEPTED".into()), Some(r.to_vec()), anchor)
    }

    /// `LOCAL` is pinned at `version` and `head`, available.
    fn available_at(w: &World, version: i64, head: [u8; 32]) {
        let (state, reason, _, v, h) = w.state(LOCAL);
        assert_eq!(
            (state.as_str(), reason, v, h),
            ("AVAILABLE", None, version, Some(head.to_vec()))
        );
    }

    /// `LOCAL` is quarantined with `SIGNER_REVOKED` at `version`.
    fn revoked_at(w: &World, version: i64) {
        let (state, reason, _, v, _) = w.state(LOCAL);
        assert_eq!(
            (state.as_str(), reason.as_deref(), v),
            ("QUARANTINED", Some("SIGNER_REVOKED"), version)
        );
    }

    /// Committer `seed`, approved by this device and allowed to commit to the
    /// fleet until `ends`, added to `p`. Its key.
    fn committer(
        w: &World,
        p: &mut [TenantTrustEvidencePageV2],
        seed: u8,
        ends: u64,
    ) -> Ed25519SigningKey {
        let k = Ed25519SigningKey::from_bytes(&[seed; 32]);
        let id = key_id_of(&k);
        let until = |replay| CommonFields {
            not_after_ms: ends,
            ..common(replay)
        };
        let approval = DeviceApprovalV2 {
            common: until(seed),
            subject_account_id: [seed; 16],
            subject_device_id: [seed + 1; 16],
            subject_signing_key_id: id,
            subject_hpke_key_id: [seed; 32],
            approval_scope_kind: ApprovalScopeKind::Tenant,
            approval_scope_id: TENANT,
        };
        let commit = TenantCapabilityGrantV2 {
            common: until(seed + 1),
            subject: GrantSubject::Device {
                account_id: [seed; 16],
                device_id: [seed + 1; 16],
                signing_key_id: id,
                hpke_key_id: [seed; 32],
            },
            scope_kind: CapabilityScopeKind::Fleet,
            scope_id: FLEET,
            capability: Capability::ProfileCommit,
        };
        p[0].containers.extend([
            build_record(&w.me.sk, DOMAIN_DEVICE_APPROVAL, &approval.encode()),
            build_record(&w.me.sk, DOMAIN_TENANT_CAPABILITY_GRANT, &commit.encode()),
        ]);
        p[0].signing_public_keys.push(k.verifying_key().to_bytes());
        k
    }

    /// Custodian E (`seed`) in `p`: approved and appointed by this device
    /// until `custody_ends`, holding `device.revoke` until `revoke_until`
    /// when given, and signing a revocation of author `A` dated `T0 + DAY / 4`.
    fn revoker(
        w: &World,
        p: &mut [TenantTrustEvidencePageV2],
        seed: u8,
        custody_ends: u64,
        revoke_until: Option<u64>,
    ) {
        let k = Ed25519SigningKey::from_bytes(&[seed; 32]);
        let id = key_id_of(&k);
        let approval = DeviceApprovalV2 {
            common: common(seed),
            subject_account_id: [seed; 16],
            subject_device_id: [seed + 1; 16],
            subject_signing_key_id: id,
            subject_hpke_key_id: [seed; 32],
            approval_scope_kind: ApprovalScopeKind::Tenant,
            approval_scope_id: TENANT,
        };
        let root = TenantRootKeyGrantV2 {
            common: CommonFields {
                not_after_ms: custody_ends,
                ..common(seed + 1)
            },
            variant: RootGrantVariant::ExistingRootGrant,
            root_key_id: [8; 32],
            root_generation: 0,
            subject_account_id: [seed; 16],
            subject_device_id: [seed + 1; 16],
            subject_signing_key_id: id,
            recipient_hpke_key_id: [seed; 32],
            subject_device_approval_replay_id: [seed; 16],
            hpke_encapped_key_bytes: [3; 32],
            hpke_wrapped_trk_bytes: [4; 48],
        };
        let at = T0 + DAY / 4;
        let revocation = DeviceRevocationV2 {
            common: CommonFields {
                issued_at_ms: at,
                not_before_ms: at,
                ..common(seed + 3)
            },
            subject_account_id: [0x70; 16],
            subject_device_id: [0x71; 16],
            subject_signing_key_id: key_id_of(&author()),
            subject_hpke_key_id: [0x70; 32],
            reason_code: DeviceRevocationReason::Compromised,
        };
        p[0].containers.extend([
            build_record(&w.me.sk, DOMAIN_DEVICE_APPROVAL, &approval.encode()),
            build_record(&w.me.sk, DOMAIN_TENANT_ROOT_KEY_GRANT, &root.encode()),
            build_record(&k, DOMAIN_DEVICE_REVOCATION, &revocation.encode()),
        ]);
        if let Some(until) = revoke_until {
            let g = TenantCapabilityGrantV2 {
                common: CommonFields {
                    not_after_ms: until,
                    ..common(seed + 2)
                },
                subject: GrantSubject::Device {
                    account_id: [seed; 16],
                    device_id: [seed + 1; 16],
                    signing_key_id: id,
                    hpke_key_id: [seed; 32],
                },
                scope_kind: CapabilityScopeKind::Tenant,
                scope_id: TENANT,
                capability: Capability::DeviceRevoke,
            };
            p[0].containers.push(build_record(
                &w.me.sk,
                DOMAIN_TENANT_CAPABILITY_GRANT,
                &g.encode(),
            ));
        }
        p[0].signing_public_keys.push(k.verifying_key().to_bytes());
    }

    fn serve(w: &World, p: &[TenantTrustEvidencePageV2]) {
        w.fake().pages = p[0].encode();
    }

    /// Execution note 2 (U1b): a walk whose evidence would first count a
    /// custodian's revocation reads it again as a closure listing, which
    /// names the signers of the heads it walks as well, so a head whose
    /// signer's approval the server serves only when asked for still
    /// verifies.
    #[test]
    fn a_walk_that_triggers_the_closure_still_verifies_its_new_heads() {
        let w = world();
        let mut only_named = author_pages(&w, T0 + 300 * DAY, false, false);
        let served = only_named[0].containers.len();
        let k = committer(&w, &mut only_named, 0x20, T0 + 300 * DAY);
        let k_records = only_named[0].containers.split_off(served);
        let heads = chain_of(&w, &[&w.me.sk, &k]);
        let d = second(&w);
        pin_at(&w, &d, &heads, 1);

        // The server now serves custodian E, which this device appointed and
        // then revoked, and K's approval only to a request naming K.
        let mut p = author_pages(&w, T0 + 300 * DAY, false, false);
        revoker(&w, &mut p, 0x30, T0 + 300 * DAY, None);
        let e = Ed25519SigningKey::from_bytes(&[0x30; 32]);
        let revoke = TenantCapabilityGrantV2 {
            common: common(0x40),
            subject: device_subject(&w.me),
            scope_kind: CapabilityScopeKind::Tenant,
            scope_id: TENANT,
            capability: Capability::DeviceRevoke,
        };
        let at = T0 + DAY / 2;
        let revocation = DeviceRevocationV2 {
            common: CommonFields {
                issued_at_ms: at,
                not_before_ms: at,
                ..common(0x41)
            },
            subject_account_id: [0x30; 16],
            subject_device_id: [0x31; 16],
            subject_signing_key_id: key_id_of(&e),
            subject_hpke_key_id: [0x30; 32],
            reason_code: DeviceRevocationReason::Retired,
        };
        p[0].containers.extend([
            build_record(&w.me.sk, DOMAIN_TENANT_CAPABILITY_GRANT, &revoke.encode()),
            build_record(&w.me.sk, DOMAIN_DEVICE_REVOCATION, &revocation.encode()),
        ]);
        serve(&w, &p);
        w.fake()
            .named
            .insert(key_id_of(&k), (k.verifying_key().to_bytes(), k_records));

        w.pull(&d.path().join("out")).unwrap();
        available_at(&w, 2, heads[1]);
        assert!(ledger::withdrawn(&w.db(), &w.dev.pin.0, &key_id_of(&e)).unwrap());
        let asked = w.fake().asked.clone();
        assert_eq!(asked.len(), 2, "the walk's read, then the closure");
        assert!(
            asked[1].contains(&key_id_of(&k)),
            "the closure names the walked head's signer"
        );
        assert!(
            asked[1].contains(&key_id_of(&w.me.sk)),
            "the closure names the pinned version 1's signer"
        );
    }

    /// A link at the version above `below`, chained on it.
    fn link(below: Option<&Link>, standing: Standing) -> Link {
        let version = below.map_or(1, |l| l.version + 1);
        Link {
            version,
            hash: [version as u8; 32],
            base: version - 1,
            previous: below.map(|l| l.hash),
            signer: [0x70; 32],
            standing,
        }
    }

    /// The walk's use of [`revert_rule`] over `standings` above `anchor`:
    /// the rule's answer for each link, the anchor and the open run.
    fn rule_over(anchor: Option<Link>, standings: &[Standing]) -> (Vec<Rule>, Option<Link>) {
        let (mut anchor, mut run, mut answers) = (anchor, Vec::<Link>::new(), Vec::new());
        for s in standings {
            let next = link(run.last().or(anchor.as_ref()), *s);
            let rule = revert_rule(anchor.as_ref(), &run, &next);
            match &rule {
                Rule::Join => run.push(next),
                Rule::Advance | Rule::Accept(_) => {
                    run.clear();
                    anchor = Some(next);
                }
                Rule::Refuse(_) => {}
            }
            answers.push(rule);
        }
        (answers, anchor)
    }

    #[test]
    fn revert_rule_accepts_one_proven_revoked_head() {
        let p = link(None, Standing::Valid);
        let (rules, anchor) = rule_over(Some(p.clone()), &[Standing::Withdrawn, Standing::Valid]);
        let j = link(Some(&p), Standing::Withdrawn);
        assert_eq!(rules, [Rule::Join, Rule::Accept(vec![j])]);
        assert_eq!(anchor.unwrap().version, 3);
    }

    #[test]
    fn revert_rule_accepts_two_stacked_proven_revoked_heads() {
        let p = link(None, Standing::Valid);
        let w = Standing::Withdrawn;
        let (rules, _) = rule_over(Some(p.clone()), &[w, w, Standing::Valid]);
        let j1 = link(Some(&p), w);
        let j2 = link(Some(&j1), w);
        assert_eq!(rules, [Rule::Join, Rule::Join, Rule::Accept(vec![j1, j2])]);
    }

    #[test]
    fn revert_rule_accepts_on_a_new_device_without_a_pin() {
        let (rules, anchor) = rule_over(None, &[Standing::Withdrawn, Standing::Valid]);
        let j = link(None, Standing::Withdrawn);
        assert_eq!(rules, [Rule::Join, Rule::Accept(vec![j])]);
        assert_eq!(anchor.unwrap().version, 2);
    }

    #[test]
    fn revert_rule_refuses_a_run_with_a_lapsed_unrevoked_head() {
        let p = link(None, Standing::Valid);
        let (rules, _) = rule_over(Some(p), &[Standing::Withdrawn, Standing::Untrusted]);
        assert_eq!(rules, [Rule::Join, Rule::Refuse(Refusal::Untrusted)]);
    }

    #[test]
    fn revert_rule_refuses_a_reported_only_revocation() {
        let p = link(None, Standing::Valid);
        let (rules, _) = rule_over(Some(p.clone()), &[Standing::Reported]);
        assert_eq!(rules, [Rule::Refuse(Refusal::Revoked)]);
        let (rules, _) = rule_over(Some(p), &[Standing::Withdrawn, Standing::Reported]);
        assert_eq!(rules, [Rule::Join, Rule::Refuse(Refusal::Revoked)]);
    }

    /// Rule 6.2 and 6.3: the run chains exactly on `P`, and `R` on `Jn`.
    #[test]
    fn revert_rule_refuses_a_gap_below_the_pin() {
        let p = link(None, Standing::Valid);
        let j = link(Some(&p), Standing::Withdrawn);
        let unchained = Link {
            previous: Some([0x55; 32]),
            ..j.clone()
        };
        assert_eq!(
            revert_rule(Some(&p), &[], &unchained),
            Rule::Refuse(Refusal::Gap)
        );
        let skipped_a_version = Link {
            version: 3,
            base: 2,
            ..j.clone()
        };
        assert_eq!(
            revert_rule(Some(&p), &[], &skipped_a_version),
            Rule::Refuse(Refusal::Gap)
        );
        let r = link(Some(&j), Standing::Valid);
        let off_base = Link { base: 1, ..r };
        assert_eq!(
            revert_rule(Some(&p), &[j], &off_base),
            Rule::Refuse(Refusal::Gap)
        );
    }

    #[test]
    fn revert_rule_advances_the_pin_over_a_valid_head_first() {
        let p = link(None, Standing::Valid);
        let (rules, anchor) = rule_over(
            Some(p.clone()),
            &[Standing::Valid, Standing::Withdrawn, Standing::Valid],
        );
        let l1 = link(Some(&p), Standing::Valid);
        let j = link(Some(&l1), Standing::Withdrawn);
        assert_eq!(rules, [Rule::Advance, Rule::Join, Rule::Accept(vec![j])]);
        assert_eq!(anchor.unwrap().version, 4);
    }

    #[test]
    fn revert_rule_accepts_a_head_both_proven_and_reported() {
        // Membership is `withdrawn` alone, checked first: the walk gives such
        // a head `Withdrawn`, never `Reported`.
        let (rules, _) = rule_over(None, &[Standing::Withdrawn, Standing::Valid]);
        assert!(matches!(rules[1], Rule::Accept(_)));
    }

    /// One proven-revoked head between a pinned head and a valid `R`: `R` is
    /// pinned directly, the head is skipped, never pinned, and audited.
    #[test]
    fn revert_accepts_one_proven_revoked_head() {
        let w = world();
        let heads = chain_of(&w, &[&w.me.sk, &author(), &w.me.sk]);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, true, false));
        let d = second(&w);
        pin_at(&w, &d, &heads, 1);
        let out = d.path().join("out");
        assert!(w.pull(&out).unwrap() > 0);
        assert!(out.join("Preferences").exists());
        available_at(&w, 3, heads[2]);
        assert_eq!(skipped(&w), [accepted_by(2, heads[2], 1)]);
    }

    #[test]
    fn revert_accepts_two_stacked_proven_revoked_heads() {
        let w = world();
        let heads = chain_of(&w, &[&w.me.sk, &author(), &author(), &w.me.sk]);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, true, false));
        let d = second(&w);
        pin_at(&w, &d, &heads, 1);
        w.pull(&d.path().join("out")).unwrap();
        available_at(&w, 4, heads[3]);
        assert_eq!(
            skipped(&w),
            [accepted_by(2, heads[3], 1), accepted_by(3, heads[3], 1)]
        );
    }

    #[test]
    fn revert_accepts_on_a_new_device_without_a_pin() {
        let w = world();
        let heads = chain_of(&w, &[&author(), &w.me.sk]);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, true, false));
        let d = second(&w);
        w.pull(&d.path().join("out")).unwrap();
        available_at(&w, 2, heads[1]);
        assert_eq!(skipped(&w), [accepted_by(1, heads[1], 0)]);
    }

    #[test]
    fn revert_refuses_a_run_with_a_lapsed_unrevoked_head() {
        let w = world();
        let mut p = author_pages(&w, T0 + 300 * DAY, true, false);
        let lapsed = committer(&w, &mut p, 0x20, T0 + DAY / 2);
        let heads = chain_of(&w, &[&w.me.sk, &author(), &lapsed, &w.me.sk]);
        serve(&w, &p);
        let d = second(&w);
        pin_at(&w, &d, &heads, 1);
        let err = w.pull(&d.path().join("out")).unwrap_err();
        assert!(has(&err, "sync.signerRevoked"), "{err:#}");
        revoked_at(&w, 1);
        assert!(skipped(&w).is_empty());
    }

    /// A refusal inside a run writes no audit row and quarantines as the
    /// proven-revoked head alone did before: a lapsed, reported-only or
    /// unchained head after it leaves `SIGNER_REVOKED`. A lapsed head with
    /// no run below it still refuses as untrusted, the binding unchanged.
    #[test]
    fn a_failure_inside_a_run_writes_no_unresolved_rows() {
        for case in ["lapsed", "reported", "gap", "lapsed alone"] {
            let w = world();
            let mut p = author_pages(&w, T0 + 300 * DAY, true, false);
            let ends = if case == "reported" {
                T0 + 300 * DAY
            } else {
                T0 + DAY / 2
            };
            let x = committer(&w, &mut p, 0x20, ends);
            if case == "reported" {
                p[0].device_revocations.push(RevokedDevice {
                    device_id: [0x21; 16],
                    revoked_at_ms: T0 + DAY / 2,
                });
            }
            let middle = if case == "lapsed alone" {
                w.me.sk.clone()
            } else {
                author()
            };
            let last = if case == "gap" { w.me.sk.clone() } else { x };
            let heads = chain_of(&w, &[&w.me.sk, &middle, &last]);
            if case == "gap" {
                let mut f = w.fake();
                let m = SignedSnapshotManifestV2::parse(&f.manifests[&3]).unwrap();
                let mut q =
                    SnapshotManifestV2::parse(m.canonical_manifest_payload_bytes()).unwrap();
                q.previous_signed_head_hash = Some([0x55; 32]);
                let signed = SignedSnapshotManifestV2::sign(&w.me.sk, &q).unwrap();
                f.manifests.insert(3, signed.exact_bytes().to_vec());
                f.head = Some(signed.head_hash());
            }
            serve(&w, &p);
            let d = second(&w);
            pin_at(&w, &d, &heads, 1);
            let err = w.pull(&d.path().join("out")).unwrap_err();
            if case == "lapsed alone" {
                assert!(has(&err, "sync.signerUntrusted"), "{err:#}");
                available_at(&w, 1, heads[0]);
            } else {
                assert!(has(&err, "sync.signerRevoked"), "{case}: {err:#}");
                revoked_at(&w, 1);
            }
            assert!(skipped(&w).is_empty(), "{case}");
        }
    }

    /// Architect blocking 1: a head met again after its row was superseded
    /// (an unbind, then the same remote profile bound again) opens a new
    /// row, which the `R` that follows accepts.
    #[test]
    fn a_head_met_again_after_an_unbind_reopens_its_row() {
        let w = world();
        let heads = chain_of(&w, &[&w.me.sk, &author(), &w.me.sk]);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, true, false));
        let d = second(&w);
        w.fake().listed = Some((2, Some(heads[1])));
        let err = w.pull(&d.path().join("out")).unwrap_err();
        assert!(has(&err, "sync.signerRevokedAtP"), "{err:#}");
        unbind(LOCAL, SERVER, NOW).unwrap();
        w.bind(LOCAL, PROFILE, 1, heads[0]);
        let err = w.pull(&d.path().join("again")).unwrap_err();
        assert!(has(&err, "sync.signerRevoked"), "{err:#}");
        revoked_at(&w, 1);
        let rows = || -> Vec<(i64, Option<String>, Option<Vec<u8>>)> {
            let db = w.db();
            let mut s = db
                .conn
                .prepare(
                    "SELECT target_version, resolution, accepted_head_hash
                     FROM skipped_heads ORDER BY id",
                )
                .unwrap();
            let rows = s
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            rows
        };
        let superseded = (2, Some("SUPERSEDED".to_string()), None);
        assert_eq!(rows(), [superseded.clone(), (2, None, None)]);
        w.fake().listed = None;
        w.pull(&d.path().join("last")).unwrap();
        available_at(&w, 3, heads[2]);
        assert_eq!(
            rows(),
            [
                superseded,
                (2, Some("ACCEPTED".to_string()), Some(heads[2].to_vec()))
            ]
        );
    }

    /// Architect blocking 2: a reported-only quarantine of the pinned head
    /// stays once the server hides its signer's approval, so the report no
    /// longer applies: no acceptance path, the pin never advances.
    #[test]
    fn a_reported_only_quarantine_stays_once_the_approval_is_hidden() {
        let w = world();
        let heads = chain_of(&w, &[&w.me.sk, &author(), &w.me.sk]);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, false, false));
        let d = second(&w);
        pin_at(&w, &d, &heads, 2);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, false, true));
        let err = w.pull(&d.path().join("out")).unwrap_err();
        assert!(has(&err, "sync.signerRevoked"), "{err:#}");
        revoked_at(&w, 2);
        serve(&w, &pages(&w.me, &w.grant, &Ev::default()));
        let out = d.path().join("again");
        let err = w.pull(&out).unwrap_err();
        assert!(has(&err, "sync.signerRevoked"), "{err:#}");
        revoked_at(&w, 2);
        assert_eq!(w.state(LOCAL).4, Some(heads[1].to_vec()));
        assert!(!out.exists());
        assert!(skipped(&w).is_empty());
    }

    /// The run must chain onto `P`: a manifest below a withdrawn pin that
    /// does not hash to the pin's previous head refuses, writing nothing.
    #[test]
    fn revert_refuses_a_gap_below_the_pin() {
        let w = world();
        let heads = chain_of(&w, &[&w.me.sk, &author(), &w.me.sk]);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, false, false));
        let d = second(&w);
        pin_at(&w, &d, &heads, 2);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, true, false));
        forge(&w, &Ed25519SigningKey::from_bytes(&[0x33; 32]), |_| {});
        let err = w.pull(&d.path().join("out")).unwrap_err();
        assert!(
            format!("{err:#}").contains("field=previous_signed_head_hash"),
            "{err:#}"
        );
        available_at(&w, 2, heads[1]);
        assert!(skipped(&w).is_empty());
    }

    /// Round-5 M21: a reported-only revocation never lets a head be skipped;
    /// every pull refuses and the quarantine stays.
    #[test]
    fn revert_refuses_a_reported_only_revocation() {
        let w = world();
        chain_of(&w, &[&w.me.sk, &author(), &w.me.sk]);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, false, true));
        let d = second(&w);
        for _ in 0..2 {
            let err = w.pull(&d.path().join("out")).unwrap_err();
            assert!(has(&err, "sync.signerRevoked"), "{err:#}");
            revoked_at(&w, 0);
        }
        assert!(skipped(&w).is_empty());
        assert!(!d.path().join("out").exists());
    }

    #[test]
    fn revert_accepts_a_head_both_proven_and_reported() {
        let w = world();
        let heads = chain_of(&w, &[&w.me.sk, &author(), &w.me.sk]);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, true, true));
        let d = second(&w);
        w.pull(&d.path().join("out")).unwrap();
        available_at(&w, 3, heads[2]);
        assert_eq!(skipped(&w), [accepted_by(2, heads[2], 1)]);
    }

    /// Below a pin whose signer is proven revoked, a head whose signer is
    /// only reported revoked ends the walk with the quarantine, no rows.
    #[test]
    fn revert_refuses_a_reported_only_head_below_a_revoked_pin() {
        let w = world();
        let mut p = author_pages(&w, T0 + 300 * DAY, false, false);
        let x = committer(&w, &mut p, 0x20, T0 + 300 * DAY);
        let heads = chain_of(&w, &[&w.me.sk, &x, &author()]);
        serve(&w, &p);
        let d = second(&w);
        pin_at(&w, &d, &heads, 3);
        let mut p = author_pages(&w, T0 + 300 * DAY, true, false);
        committer(&w, &mut p, 0x20, T0 + 300 * DAY);
        p[0].device_revocations.push(RevokedDevice {
            device_id: [0x21; 16],
            revoked_at_ms: T0 + DAY / 2,
        });
        serve(&w, &p);
        let err = w.pull(&d.path().join("out")).unwrap_err();
        assert!(has(&err, "sync.signerRevoked"), "{err:#}");
        revoked_at(&w, 3);
        assert!(skipped(&w).is_empty());
    }

    /// Round-5 minor 3: a valid head the pin had not reached yet is accepted
    /// first, and becomes the run's `P`.
    #[test]
    fn revert_advances_the_pin_over_a_valid_head_first() {
        let w = world();
        let heads = chain_of(&w, &[&w.me.sk, &w.me.sk, &author(), &w.me.sk]);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, true, false));
        let d = second(&w);
        pin_at(&w, &d, &heads, 1);
        w.pull(&d.path().join("out")).unwrap();
        available_at(&w, 4, heads[3]);
        assert_eq!(skipped(&w), [accepted_by(3, heads[3], 2)]);
    }

    /// Round-5 minor 4: a head pinned before its signer was proven revoked
    /// becomes skippable, `P` moves to the head below it, and `R` is
    /// accepted.
    #[test]
    fn revert_skips_a_head_pinned_before_its_signer_was_proven_revoked() {
        let w = world();
        let heads = chain_of(&w, &[&w.me.sk, &author(), &w.me.sk]);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, false, false));
        let d = second(&w);
        pin_at(&w, &d, &heads, 2);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, true, false));
        w.pull(&d.path().join("out")).unwrap();
        available_at(&w, 3, heads[2]);
        assert_eq!(skipped(&w), [accepted_by(2, heads[2], 1)]);
    }

    /// Round-6 minor 1: another custodian's revocation, obtained through the
    /// trust evidence, counts as proven.
    #[test]
    fn revert_accepts_a_revocation_another_device_filed() {
        let w = world();
        let heads = chain_of(&w, &[&w.me.sk, &author(), &w.me.sk]);
        let mut p = author_pages(&w, T0 + 300 * DAY, false, false);
        revoker(&w, &mut p, 0x50, T0 + 300 * DAY, Some(T0 + 300 * DAY));
        serve(&w, &p);
        let d = second(&w);
        w.pull(&d.path().join("out")).unwrap();
        available_at(&w, 3, heads[2]);
        assert_eq!(skipped(&w), [accepted_by(2, heads[2], 1)]);
    }

    /// The pull a revocation that does not count leaves: `A` only reported,
    /// so its head quarantines and nothing is skipped.
    fn refused_as_reported(w: &World, d: &tempfile::TempDir) {
        let err = w.pull(&d.path().join("out")).unwrap_err();
        assert!(has(&err, "sync.signerRevoked"), "{err:#}");
        revoked_at(w, 0);
        assert!(skipped(w).is_empty());
        let db = w.db();
        assert!(!ledger::withdrawn(&db, &w.dev.pin.0, &key_id_of(&author())).unwrap());
    }

    /// Round-6 minor 2: a revocation whose issuer lacked `device.revoke` is
    /// not counted (see also `a_revocation_counts_only_from_a_custodian_allowed_to_revoke`).
    #[test]
    fn revert_refuses_a_revocation_whose_issuer_lacked_device_revoke() {
        let w = world();
        chain_of(&w, &[&w.me.sk, &author(), &w.me.sk]);
        let mut p = author_pages(&w, T0 + 300 * DAY, false, true);
        revoker(&w, &mut p, 0x50, T0 + 300 * DAY, None);
        serve(&w, &p);
        refused_as_reported(&w, &second(&w));
    }

    /// Round-6 minor 2: a revocation whose issuer was no longer a custodian
    /// when this device first saw it is not counted.
    #[test]
    fn revert_refuses_a_revocation_whose_issuer_lapsed_before_first_sight() {
        let w = world();
        chain_of(&w, &[&w.me.sk, &author(), &w.me.sk]);
        let mut p = author_pages(&w, T0 + 300 * DAY, false, true);
        revoker(&w, &mut p, 0x50, T0 + DAY / 2, Some(T0 + 300 * DAY));
        serve(&w, &p);
        refused_as_reported(&w, &second(&w));
    }

    /// Revision 8: a device back after 40 days offline counts a revocation
    /// whose issuer is still a custodian, and accepts `R`.
    #[test]
    fn revert_accepts_after_forty_days_offline() {
        let w = world();
        let heads = chain_of(&w, &[&w.me.sk, &author(), &w.me.sk]);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, false, false));
        let d = second(&w);
        pin_at(&w, &d, &heads, 1);
        let mut p = author_pages(&w, T0 + 300 * DAY, false, false);
        revoker(&w, &mut p, 0x50, T0 + 300 * DAY, Some(T0 + 300 * DAY));
        serve(&w, &p);
        w.pull_at(&d.path().join("out"), NOW + 40 * DAY).unwrap();
        available_at(&w, 3, heads[2]);
        assert_eq!(skipped(&w), [accepted_by(2, heads[2], 1)]);
    }

    /// Revision 8: the original issuer lapsed, so its revocation never
    /// counts here; a current custodian files a second one, which does, and
    /// the next pull accepts `R` over the quarantine.
    #[test]
    fn revert_accepts_after_a_current_custodian_refiles() {
        let w = world();
        let heads = chain_of(&w, &[&w.me.sk, &author(), &w.me.sk]);
        let mut p = author_pages(&w, T0 + 300 * DAY, false, true);
        revoker(&w, &mut p, 0x50, T0 + DAY / 2, Some(T0 + 300 * DAY));
        serve(&w, &p);
        let d = second(&w);
        refused_as_reported(&w, &d);
        let mut p = author_pages(&w, T0 + 300 * DAY, true, true);
        revoker(&w, &mut p, 0x50, T0 + DAY / 2, Some(T0 + 300 * DAY));
        serve(&w, &p);
        w.pull(&d.path().join("out")).unwrap();
        available_at(&w, 3, heads[2]);
        assert_eq!(skipped(&w), [accepted_by(2, heads[2], 1)]);
    }

    /// The pull gate: a `SIGNER_REVOKED` quarantine is walked again, any
    /// other still refuses.
    #[test]
    fn only_a_signer_revoked_quarantine_lets_a_pull_through() {
        let w = world();
        let heads = chain_of(&w, &[&w.me.sk, &author(), &w.me.sk]);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, true, false));
        let d = second(&w);
        w.fake().listed = Some((2, Some(heads[1])));
        let err = w.pull(&d.path().join("first")).unwrap_err();
        assert!(has(&err, "sync.signerRevokedAtP"), "{err:#}");
        revoked_at(&w, 1);
        w.fake().listed = None;
        w.pull(&d.path().join("out")).unwrap();
        available_at(&w, 3, heads[2]);

        w.db()
            .conn
            .execute(
                "UPDATE profile_bindings SET sync_state = 'QUARANTINED',
                   last_error_code = 'HEAD_ROLLBACK_DETECTED'",
                [],
            )
            .unwrap();
        let err = w.pull(&d.path().join("again")).unwrap_err();
        assert!(has(&err, "sync.bindingQuarantined"), "{err:#}");
    }

    /// Should 4: when `P` cannot be restored, the open run and the
    /// quarantine stay and the pin does not move; the next pull pins `P`.
    #[test]
    fn a_failed_anchor_restore_keeps_the_quarantine_and_unresolved_rows() {
        let w = world();
        let heads = chain_of(&w, &[&w.me.sk, &author()]);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, true, false));
        let d = second(&w);
        w.fake().refuse.push(("1", 500));
        let err = w.pull(&d.path().join("out")).unwrap_err();
        assert!(!has(&err, "sync.signerRevoked"), "{err:#}");
        revoked_at(&w, 0);
        assert_eq!(skipped(&w), [(2, None, None, 1)]);
        let err = w.pull(&d.path().join("out")).unwrap_err();
        assert!(has(&err, "sync.signerRevokedAtP"), "{err:#}");
        revoked_at(&w, 1);
        assert_eq!(w.state(LOCAL).4, Some(heads[0].to_vec()));
        assert_eq!(skipped(&w), [(2, None, None, 1)]);
    }

    /// Should 4: a `P` of a generation a rotation replaced is still pulled,
    /// through `readable_key`; `verified_key` alone refuses it.
    #[test]
    fn revert_restores_an_anchor_of_an_older_generation_after_rotation() {
        let w = world();
        let heads = chain_of(&w, &[&w.me.sk, &author()]);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, true, false));
        let d = second(&w);
        w.collect(2, &[0x52; 32], 70, Vec::new());
        let gen1 = shardx_core::fleet_grants::fkek_key_id(&FKEK);
        let err = verified_key(&w.db(), &w.dev, &FLEET, GEN, Some(&gen1), NOW).unwrap_err();
        assert!(has(&err, "sync.noVerifiedFleetKey"), "{err:#}");
        let out = d.path().join("out");
        let err = w.pull(&out).unwrap_err();
        assert!(has(&err, "sync.signerRevokedAtP"), "{err:#}");
        revoked_at(&w, 1);
        assert_eq!(w.state(LOCAL).4, Some(heads[0].to_vec()));
        assert!(out.join("Preferences").exists());
    }

    // ------------------------------------------- rotation reads (A3) ----

    /// The key of generation `GEN + 1`.
    const K2: [u8; 32] = [0x52; 32];

    /// Rotates the config root's device to `GEN + 1` (key `K2`): verified,
    /// stored, and named by the fake's checkouts.
    fn rotate(w: &World) {
        w.collect(GEN + 1, &K2, 70, Vec::new());
        assert!(crate::fleet_keys::collect(&hex(&FLEET), GEN + 1, &K2).unwrap());
        let mut f = w.fake();
        f.generation = Some(GEN + 1);
        f.fkek_key_id = Some(shardx_core::fleet_grants::fkek_key_id(&K2));
    }

    /// Pushes the next version, the profile's `marker` file reading `v1`,
    /// `v2`, ...
    fn push_next(w: &World) {
        let v = w.fake().version + 1;
        std::fs::write(w.udd.join("marker"), format!("v{v}")).unwrap();
        assert_eq!(w.push().unwrap().version, v);
    }

    /// Version `v`'s manifest re-signed by `sk` as `edit` changes it, served
    /// at its target version as the listed head. Its head.
    fn resign(
        w: &World,
        v: u64,
        sk: &Ed25519SigningKey,
        edit: impl FnOnce(&mut SnapshotManifestV2),
    ) -> [u8; 32] {
        let mut f = w.fake();
        let m = SignedSnapshotManifestV2::parse(&f.manifests[&v]).unwrap();
        let mut p = SnapshotManifestV2::parse(m.canonical_manifest_payload_bytes()).unwrap();
        p.signer_signing_key_id = key_id_of(sk);
        edit(&mut p);
        let signed = SignedSnapshotManifestV2::sign(sk, &p).unwrap();
        f.manifests
            .insert(p.target_version, signed.exact_bytes().to_vec());
        f.version = f.version.max(p.target_version);
        f.head = Some(signed.head_hash());
        signed.head_hash()
    }

    /// Re-signs versions 1, 2, ... as [`chain_of`] does, `links[v - 1]`
    /// giving the signer and the generation the manifest names (key `K2` for
    /// `GEN + 1`, else `FKEK`), whatever it was sealed under. The heads.
    fn relink(w: &World, links: &[(&Ed25519SigningKey, u64)]) -> Vec<[u8; 32]> {
        let mut heads: Vec<[u8; 32]> = Vec::new();
        for (i, (sk, generation)) in links.iter().enumerate() {
            let below = heads.last().copied();
            let key = if *generation == GEN { &FKEK } else { &K2 };
            heads.push(resign(w, i as u64 + 1, sk, |p| {
                p.previous_signed_head_hash = below;
                p.key_generation = *generation;
                p.fkek_key_id = shardx_core::fleet_grants::fkek_key_id(key);
            }));
        }
        heads
    }

    /// `LOCAL` is still available at `version`, nothing pinned or skipped.
    fn untouched_at(w: &World, version: i64) {
        let (state, reason, _, v, _) = w.state(LOCAL);
        assert_eq!((state.as_str(), reason, v), ("AVAILABLE", None, version));
        assert!(skipped(w).is_empty());
    }

    /// Hidden problem 1: after collecting `GEN + 1`, a head sealed under
    /// `GEN` is still pulled, through `readable_key`.
    #[test]
    fn a_pull_restores_a_head_sealed_under_an_older_generation_after_rotation() {
        let w = world();
        push_next(&w);
        let head = w.head_of(1);
        let d = second(&w);
        rotate(&w);
        let out = d.path().join("out");
        w.pull(&out).unwrap();
        available_at(&w, 1, head);
        assert_eq!(marker(&out), "v1");
    }

    /// A join pulls through the same path; its version-0 binding gives no
    /// floor.
    #[test]
    fn a_join_first_pull_restores_a_head_of_an_older_generation() {
        let (w, d) = joinable();
        rotate(&w);
        let out = d.path().join("joined");
        assert!(w.join(LOCAL, PROFILE, &out).unwrap() > 0);
        assert_eq!(noise(&out), noise(&w.udd));
        let head = w.fake().head.unwrap();
        available_at(&w, 1, head);
    }

    /// R4: the older-key list names a binding whose pinned head is under a
    /// generation below the highest verified; a version-0 row (a join's,
    /// which carries no head) is never listed, whatever its column says.
    #[test]
    fn profiles_under_an_older_key_lists_bindings_below_the_highest_generation() {
        let w = world();
        push_next(&w);
        let older = || under_older_key(&w.dev.pin.0).unwrap();
        assert!(older().is_empty(), "the head is under the highest");
        rotate(&w);
        assert_eq!(
            older(),
            [OlderKeyProfile {
                profile_id: LOCAL.into(),
                key_generation: GEN
            }]
        );
        w.db()
            .conn
            .execute(
                "UPDATE profile_bindings SET remote_version = 0, base_version = 0,
                   last_observed_head_hash = NULL",
                [],
            )
            .unwrap();
        assert!(older().is_empty(), "a version-0 row");
    }

    /// R4's deciding test: a push with nothing changed is not short-cut; it
    /// seals a new head under the newest generation, so the older-key Push needs
    /// no forced re-seal, and the profile leaves the older-key list.
    #[test]
    fn a_clean_profile_push_reseals_under_the_newest_generation() {
        let w = world();
        push_next(&w);
        rotate(&w);
        assert_eq!(w.count("SELECT dirty FROM profile_bindings"), 0);
        assert_eq!(w.push().unwrap().version, 2);
        let m = SignedSnapshotManifestV2::parse(&w.fake().manifests[&2]).unwrap();
        let p = SnapshotManifestV2::parse(m.canonical_manifest_payload_bytes()).unwrap();
        assert_eq!(p.key_generation, GEN + 1);
        assert!(under_older_key(&w.dev.pin.0).unwrap().is_empty());
    }

    /// v2.10 U1 gate G2, the re-seal spike (RS-1): a device whose binding
    /// never restored anything (a join's version-0 row) walks to the listed
    /// head under `GEN` and pins it without a restore, opens its ciphertext
    /// through `readable_key`, and seals that plaintext under `GEN + 1`
    /// through the ops journal: one lease, one upload, one commit, pinned at
    /// the new head. No step takes a profile folder, and a third device
    /// pulls exactly the original files.
    #[test]
    fn a_head_reseals_from_its_ciphertext_without_a_profile_folder() {
        let w = world();
        push_next(&w);
        let files = (marker(&w.udd), noise(&w.udd));
        let d = second(&w);
        rotate(&w);
        let before = w.fake().log.len();
        let pushed =
            w.rt.block_on(async {
                let mut db = Db::open()?;
                let b = bound(&db, LOCAL)?;
                assert_eq!(b.version, 0, "nothing restored here");
                let head = listed(&w.client, "t", &mut db, &b).await?;
                let walk = walked(&w.client, "t", &mut db, &w.dev, &b, &head, NOW).await?;
                let (at, p) = walk.anchor.expect("the listed head");
                let signed = (at.hash, at.signer);
                pin(
                    &mut db,
                    &w.dev,
                    &b,
                    signed,
                    &p,
                    &walk.accepted,
                    &walk.read,
                    false,
                    NOW,
                )?;
                let key_id = Some(&p.fkek_key_id);
                let fkek = readable_key(&db, &w.dev, &b.fleet, p.key_generation, key_id, NOW)?;
                let plaintext = opened(&w.client, "t", &b, &p, fkek).await?;
                drop(db);
                let src = Plain::Opened(&plaintext);
                let clock = || std::time::Duration::ZERO;
                push_inner(&w.client, "t", &w.dev, LOCAL, src, NOW, &clock, None).await
            })
            .unwrap();
        assert_eq!(pushed.version, 2);
        let calls: Vec<String> = w.fake().log[before..]
            .iter()
            .map(|(c, _)| c.clone())
            .collect();
        let posts = |tail: &str| {
            calls
                .iter()
                .filter(|c| c.starts_with("POST") && c.ends_with(tail))
                .count()
        };
        assert_eq!(
            (posts("/checkout"), posts("/uploads"), posts("/commit")),
            (1, 1, 1),
            "{calls:?}"
        );
        let m = SignedSnapshotManifestV2::parse(&w.fake().manifests[&2]).unwrap();
        let p = SnapshotManifestV2::parse(m.canonical_manifest_payload_bytes()).unwrap();
        assert_eq!((p.key_generation, p.base_version), (GEN + 1, 1));
        available_at(&w, 2, m.head_hash());
        assert!(under_older_key(&w.dev.pin.0).unwrap().is_empty());

        let _third = second(&w);
        rotate(&w);
        let out = d.path().join("out");
        w.pull(&out).unwrap();
        assert_eq!((marker(&out), noise(&out)), files);
    }

    // ------------------------------------------------ re-seal (v2.10 U3) ----

    /// Makes this config root's device the tenant's root custodian: an
    /// activated root state whose first self-grant names `w.me`.
    fn make_custodian(w: &World) {
        let cx = crate::root_bootstrap::Context16 {
            tenant: TENANT,
            instance: INSTANCE,
            epoch: 0,
            account: w.me.to.account_id,
            device: w.me.to.device_id,
            signing_key_id: w.me.to.signing_key_id,
            hpke_key_id: w.me.to.hpke_key_id,
        };
        let grant = crate::root_bootstrap::self_grant(
            &cx,
            &w.me.sk,
            &w.me.hpke_pk,
            &[0x33; 32],
            [0x44; 16],
            NOW,
        )
        .unwrap();
        crate::root_bootstrap::save(&crate::root_bootstrap::BootstrapState {
            tenant_id: hex(&TENANT),
            device_id: hex(&w.me.to.device_id),
            server_instance_id: hex(&INSTANCE),
            activated: true,
            anchor: hex(&w.me.to.signing_key_id),
            self_grant: hex(&grant),
            ..Default::default()
        })
        .unwrap();
    }

    /// Lets every profile be claimed, as a stopped one is.
    fn free(_: &str) -> Option<Box<dyn Send>> {
        Some(Box::new(()))
    }

    impl World {
        fn reseal(&self, outgoing: Option<[u8; 32]>) -> Result<ResealRun> {
            self.reseal_with(outgoing, &free, &mut |s| crate::fleet_custody::save(s))
        }

        fn reseal_with(
            &self,
            outgoing: Option<[u8; 32]>,
            claim: &(dyn Fn(&str) -> Option<Box<dyn Send>> + Sync),
            save: &mut (dyn FnMut(&FleetCustodyState) -> Result<()> + Send),
        ) -> Result<ResealRun> {
            self.rt.block_on(reseal_all(
                &self.client,
                "t",
                &self.dev,
                FLEET,
                outgoing,
                claim,
                NOW,
                save,
            ))
        }

        /// How many `POST`s ending with `tail` the fake served.
        fn posts(&self, tail: &str) -> usize {
            self.sent("POST", tail).len()
        }

        /// The outcome the latest run saved for `PROFILE`.
        fn outcome(&self) -> String {
            crate::fleet_custody::load()
                .unwrap()
                .reseal
                .unwrap()
                .profiles[&hex(&PROFILE)]
                .clone()
        }

        fn manifest_at(&self, v: u64) -> (SnapshotManifestV2, [u8; 32]) {
            let m = SignedSnapshotManifestV2::parse(&self.fake().manifests[&v]).unwrap();
            let p = SnapshotManifestV2::parse(m.canonical_manifest_payload_bytes()).unwrap();
            (p, *m.signer_signing_key_id())
        }
    }

    /// A custodian device with no binding of `PROFILE`, holding `GEN` and
    /// `GEN + 1`, after `w` pushed what it holds: the config root.
    fn unbound_custodian(w: &World) -> tempfile::TempDir {
        let d = second(w);
        rotate(w);
        w.db()
            .conn
            .execute("DELETE FROM profile_bindings", [])
            .unwrap();
        make_custodian(w);
        d
    }

    /// 4.S: a head another member signed under `GEN` is committed again
    /// under `GEN + 1` by the custodian, from its ciphertext, through one
    /// checkout, upload and commit; the re-seal row and its swap are gone
    /// afterwards, and a device holding only `GEN + 1` reads the head.
    #[test]
    fn a_reseal_moves_every_listed_head_to_the_active_generation_signed_by_the_custodian() {
        let w = world();
        push_next(&w);
        let files = (marker(&w.udd), noise(&w.udd));
        relink(&w, &[(&author(), GEN)]);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, false, false));
        let _d = unbound_custodian(&w);
        let before = w.fake().log.len();
        let run = w.reseal(None).unwrap();
        assert_eq!(run.profiles[&hex(&PROFILE)], "resealed:2");
        assert_eq!(run.generation, GEN + 1);
        assert!(run.ended_ms.is_some());
        let calls: Vec<String> = w.fake().log[before..]
            .iter()
            .map(|(c, _)| c.clone())
            .collect();
        let posts = |tail: &str| {
            calls
                .iter()
                .filter(|c| c.starts_with("POST") && c.ends_with(tail))
                .count()
        };
        assert_eq!(
            (posts("/checkout"), posts("/uploads"), posts("/commit")),
            (1, 1, 1),
            "{calls:?}"
        );
        let (p, signer) = w.manifest_at(2);
        assert_eq!((p.key_generation, p.base_version), (GEN + 1, 1));
        assert_eq!(signer, w.me.to.signing_key_id);
        assert_eq!(w.count("SELECT count(*) FROM profile_bindings"), 0);
        assert_eq!(w.count("SELECT count(*) FROM revert_swaps"), 0);
        // A third device that holds only `GEN + 1`.
        let third = second(&w);
        rotate(&w);
        crate::fleet_keys::save(&crate::fleet_keys::FleetKeyStore::default()).unwrap();
        assert!(crate::fleet_keys::collect(&hex(&FLEET), GEN + 1, &K2).unwrap());
        let out = third.path().join("out");
        w.pull(&out).unwrap();
        assert_eq!((marker(&out), noise(&out)), files);
    }

    /// A bound, clean profile at the head is re-sealed through its own
    /// binding with its folder gone: nothing reads or writes it.
    #[test]
    fn a_reseal_needs_no_profile_folder() {
        let w = world();
        push_next(&w);
        rotate(&w);
        make_custodian(&w);
        std::fs::remove_dir_all(&w.udd).unwrap();
        let run = w.reseal(None).unwrap();
        assert_eq!(run.profiles[&hex(&PROFILE)], "resealed:2");
        assert!(!w.udd.exists(), "no folder was made");
        assert_eq!(w.manifest_at(2).0.key_generation, GEN + 1);
        available_at(&w, 2, w.head_of(2));
    }

    #[test]
    fn a_reseal_skips_a_quarantined_binding() {
        let w = world();
        push_next(&w);
        rotate(&w);
        make_custodian(&w);
        w.db()
            .conn
            .execute(
                "UPDATE profile_bindings SET sync_state = 'QUARANTINED',
                   last_error_code = 'HEAD_ROLLBACK_DETECTED'",
                [],
            )
            .unwrap();
        let checkouts = w.posts("/checkout");
        let run = w.reseal(None).unwrap();
        assert_eq!(run.profiles[&hex(&PROFILE)], "skipped:quarantined");
        assert_eq!(w.posts("/checkout"), checkouts);
    }

    /// Rule 6: a run of a withdrawn signer's heads open at the listed head
    /// is a revert's to close; the re-seal lists it as quarantined and
    /// commits nothing.
    #[test]
    fn a_reseal_never_closes_an_open_run() {
        let w = world();
        push_next(&w);
        push_next(&w);
        relink(&w, &[(&w.me.sk, GEN), (&author(), GEN)]);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, true, false));
        let _d = unbound_custodian(&w);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, true, false));
        let checkouts = w.posts("/checkout");
        let commits = w.posts("/commit");
        let run = w.reseal(None).unwrap();
        assert_eq!(run.profiles[&hex(&PROFILE)], "skipped:quarantined");
        assert_eq!(w.posts("/checkout"), checkouts);
        assert_eq!(w.posts("/commit"), commits);
        assert_eq!(w.count("SELECT count(*) FROM profile_bindings"), 0);
    }

    #[test]
    fn a_reseal_skips_an_untrusted_signers_head() {
        let w = world();
        push_next(&w);
        relink(&w, &[(&author(), GEN)]);
        let _d = unbound_custodian(&w);
        let checkouts = w.posts("/checkout");
        let run = w.reseal(None).unwrap();
        assert_eq!(
            run.profiles[&hex(&PROFILE)],
            "skipped:error:sync.signerUntrusted"
        );
        assert_eq!(w.posts("/checkout"), checkouts);
    }

    /// Another device's lease refuses the checkout: listed as in use, and
    /// the re-seal row goes. A lease held here skips a bound profile.
    #[test]
    fn a_leased_profile_is_skipped_and_listed() {
        let w = world();
        push_next(&w);
        let _d = unbound_custodian(&w);
        w.fake().refused_body = Some(br#"{"code":"LEASE_HELD"}"#.to_vec());
        w.fake().refuse.push(("checkout", 409));
        let commits = w.posts("/commit");
        let run = w.reseal(None).unwrap();
        assert_eq!(run.profiles[&hex(&PROFILE)], "skipped:in-use");
        assert_eq!(w.posts("/commit"), commits);
        assert_eq!(w.count("SELECT count(*) FROM profile_bindings"), 0);
        drop(w);

        let w = world();
        push_next(&w);
        rotate(&w);
        make_custodian(&w);
        w.db()
            .conn
            .execute(
                "UPDATE profile_bindings SET lease_id = ?1, fencing_token = 1,
                   lease_expires_at = '2030-01-01T00:00:00.000Z'",
                [hex(&[0xaa; 16])],
            )
            .unwrap();
        let checkouts = w.posts("/checkout");
        let run = w.reseal(None).unwrap();
        assert_eq!(run.profiles[&hex(&PROFILE)], "skipped:in-use");
        assert_eq!(w.posts("/checkout"), checkouts);
    }

    #[test]
    fn a_dirty_or_behind_bound_profile_is_skipped_and_listed() {
        let w = world();
        push_next(&w);
        rotate(&w);
        make_custodian(&w);
        let checkouts = w.posts("/checkout");
        for sql in [
            "UPDATE profile_bindings SET dirty = 1",
            "UPDATE profile_bindings SET dirty = 0, base_version = 0",
        ] {
            w.db().conn.execute(sql, []).unwrap();
            let run = w.reseal(None).unwrap();
            assert_eq!(run.profiles[&hex(&PROFILE)], "skipped:in-use", "{sql}");
        }
        assert_eq!(w.posts("/checkout"), checkouts);
    }

    #[test]
    fn a_running_profile_is_skipped() {
        let w = world();
        push_next(&w);
        rotate(&w);
        make_custodian(&w);
        let running = |local: &str| (local != LOCAL).then(|| Box::new(()) as Box<dyn Send>);
        let checkouts = w.posts("/checkout");
        let run = w
            .reseal_with(None, &running, &mut |s| crate::fleet_custody::save(s))
            .unwrap();
        assert_eq!(run.profiles[&hex(&PROFILE)], "skipped:in-use");
        assert_eq!(w.posts("/checkout"), checkouts);
    }

    #[test]
    fn a_head_already_under_the_active_generation_is_current() {
        let w = world();
        rotate(&w);
        push_next(&w);
        make_custodian(&w);
        let commits = w.fake().commits;
        let run = w.reseal(None).unwrap();
        assert_eq!(run.profiles[&hex(&PROFILE)], "current");
        assert_eq!(w.fake().commits, commits);
    }

    /// D5: during a hand-over a head the outgoing custodian signed is sealed
    /// again even under the active generation, so it no longer depends on
    /// that key; without `outgoing` the same head is current.
    #[test]
    fn a_head_signed_by_the_outgoing_custodian_is_resealed_even_under_the_active_generation() {
        let w = world();
        rotate(&w);
        push_next(&w);
        relink(&w, &[(&author(), GEN + 1)]);
        let _d = unbound_custodian(&w);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, false, false));
        assert_eq!(w.reseal(None).unwrap().profiles[&hex(&PROFILE)], "current");
        let run = w.reseal(Some(key_id_of(&author()))).unwrap();
        assert_eq!(run.profiles[&hex(&PROFILE)], "resealed:2");
        assert_eq!(run.outgoing, hex(&key_id_of(&author())));
        let (p, signer) = w.manifest_at(2);
        assert_eq!(
            (p.key_generation, signer),
            (GEN + 1, w.me.to.signing_key_id)
        );
    }

    /// U6's appointee: a head under a generation this device never held is
    /// listed, not opened.
    #[test]
    fn a_head_under_a_generation_this_device_does_not_hold_is_skipped_older_key_not_held() {
        let w = world();
        push_next(&w);
        let _d = unbound_custodian(&w);
        crate::fleet_keys::save(&crate::fleet_keys::FleetKeyStore::default()).unwrap();
        assert!(crate::fleet_keys::collect(&hex(&FLEET), GEN + 1, &K2).unwrap());
        let checkouts = w.posts("/checkout");
        let run = w.reseal(None).unwrap();
        assert_eq!(run.profiles[&hex(&PROFILE)], "skipped:older-key-not-held");
        assert_eq!(w.posts("/checkout"), checkouts);
        assert_eq!(w.count("SELECT count(*) FROM profile_bindings"), 0);
    }

    /// A walk naming more signers than one evidence request takes fails
    /// closed, before the evidence is asked for.
    #[test]
    fn a_walk_over_64_signers_is_skipped_with_its_error() {
        let w = world();
        push_next(&w);
        let template = w.fake().manifests[&1].clone();
        let mut below = None;
        for v in 1..=65u64 {
            w.fake().manifests.insert(v, template.clone());
            let sk = Ed25519SigningKey::from_bytes(&[0x80 + v as u8; 32]);
            let previous = below;
            below = Some(resign(&w, v, &sk, |p| {
                p.target_version = v;
                p.base_version = v - 1;
                p.previous_signed_head_hash = previous;
            }));
        }
        let _d = unbound_custodian(&w);
        let before = w.fake().log.len();
        let run = w.reseal(None).unwrap();
        assert_eq!(
            run.profiles[&hex(&PROFILE)],
            "skipped:error:sync.walkTooManySigners"
        );
        let evidence = w.fake().log[before..]
            .iter()
            .filter(|(c, _)| c.contains("trust-evidence"))
            .count();
        assert_eq!(evidence, 0, "no evidence was asked for");
    }

    /// Principle 3: a reply lost at each step leaves the profile pending;
    /// the next run resends the stored request, byte for byte (the fake
    /// answers a changed body under the same key `IDEMPOTENCY_MISMATCH`),
    /// and the profile ends with one commit.
    #[test]
    fn a_reseal_resumes_each_step_with_byte_identical_requests() {
        let w = world();
        push_next(&w);
        let _d = unbound_custodian(&w);
        let before = w.sent("POST", "/checkout").len();
        for lost in ["checkout", "upload", "upload", "commit"] {
            w.fake().lose.push(lost);
            let run = w.reseal(None).unwrap();
            let outcome = &run.profiles[&hex(&PROFILE)];
            assert!(outcome.starts_with("sealing:1:"), "{lost}: {outcome}");
            assert!(w.fake().lose.is_empty(), "{lost} was sent");
        }
        let run = w.reseal(None).unwrap();
        assert_eq!(run.profiles[&hex(&PROFILE)], "resealed:2");
        assert_eq!(w.fake().commits, 2, "v1 and the one re-seal");
        assert_eq!(
            w.sent("POST", "/checkout").len(),
            before + 2,
            "one, then its replay"
        );
        assert_eq!(w.count("SELECT count(*) FROM profile_bindings"), 0);
    }

    /// 4.S step 4: a crash after the commit, before its outcome is saved,
    /// resumes as re-sealed with no second commit.
    #[test]
    fn a_reseal_crash_after_commit_resumes_without_a_second_commit() {
        let w = world();
        push_next(&w);
        let _d = unbound_custodian(&w);
        let mut crash = |s: &FleetCustodyState| {
            let done = s
                .reseal
                .as_ref()
                .is_some_and(|r| r.profiles[&hex(&PROFILE)].starts_with("resealed"));
            if done {
                bail!("crash");
            }
            crate::fleet_custody::save(s)
        };
        let err = w.reseal_with(None, &free, &mut crash).unwrap_err();
        assert_eq!(err.to_string(), "crash");
        assert!(w.outcome().starts_with("sealing:1:"));
        let commits = w.fake().commits;
        let run = w.reseal(None).unwrap();
        assert_eq!(run.profiles[&hex(&PROFILE)], "resealed:2");
        assert_eq!(w.fake().commits, commits, "no second commit");
        assert_eq!(w.fake().version, 2);
        assert_eq!(w.count("SELECT count(*) FROM profile_bindings"), 0);
    }

    #[test]
    fn a_second_run_commits_nothing_new() {
        let w = world();
        push_next(&w);
        let _d = unbound_custodian(&w);
        assert_eq!(
            w.reseal(None).unwrap().profiles[&hex(&PROFILE)],
            "resealed:2"
        );
        let posts = w.sent("POST", "").len();
        let run = w.reseal(None).unwrap();
        assert_eq!(run.profiles[&hex(&PROFILE)], "current");
        assert_eq!(w.sent("POST", "").len(), posts, "nothing was written");
    }

    #[test]
    fn a_reseal_under_a_q18_block_is_refused() {
        let w = world();
        push_next(&w);
        make_custodian(&w);
        w.db().conn.execute_batch(&a_compromise(&w)).unwrap();
        let err = w.reseal(None).unwrap_err();
        assert!(has(&err, "sync.commitBlockedCompromised"), "{err:#}");
        assert!(crate::fleet_custody::load().unwrap().reseal.is_none());
    }

    #[test]
    fn a_reseal_refuses_without_the_verified_active_key() {
        let w = world();
        push_next(&w);
        make_custodian(&w);
        crate::fleet_keys::save(&crate::fleet_keys::FleetKeyStore::default()).unwrap();
        let before = w.fake().log.len();
        let err = w.reseal(None).unwrap_err();
        assert!(has(&err, "sync.noVerifiedFleetKey"), "{err:#}");
        assert_eq!(w.fake().log.len(), before, "nothing was asked");
    }

    /// Only the root custodian re-seals: a member has no root state, and a
    /// root state of another device is not this one's.
    #[test]
    fn a_member_cannot_reseal() {
        let w = world();
        push_next(&w);
        let err = w.reseal(None).unwrap_err();
        assert!(has(&err, "sync.resealNotCustodian"), "{err:#}");
        make_custodian(&w);
        let mut other = crate::root_bootstrap::load().unwrap();
        other.device_id = hex(&[0x99; 16]);
        crate::root_bootstrap::save(&other).unwrap();
        let err = w.reseal(None).unwrap_err();
        assert!(has(&err, "sync.resealNotCustodian"), "{err:#}");
        assert!(crate::fleet_custody::load().unwrap().reseal.is_none());
    }

    #[test]
    fn a_handed_over_root_cannot_reseal() {
        let w = world();
        push_next(&w);
        rotate(&w);
        make_custodian(&w);
        let state = crate::fleet_custody::FleetCustodyState {
            handed_over_to: hex(&[0x99; 16]),
            ..Default::default()
        };
        crate::fleet_custody::save(&state).unwrap();
        let err = w.reseal(None).unwrap_err();
        assert!(has(&err, "fleet.custodyHandedOver"), "{err:#}");
        assert_eq!(w.fake().commits, 1);
    }

    /// The `reseal:` row a run holds is no profile of this device: no status,
    /// no label binding, no downgrade blocker of its own and no older-key
    /// entry. Its lease still blocks a downgrade.
    #[test]
    fn reseal_rows_are_absent_from_statuses_labels_downgrade_readiness_and_the_older_key_list() {
        let w = world();
        push_next(&w);
        rotate(&w);
        let unfinished = || {
            crate::team::downgrade::readiness()
                .unwrap()
                .blockers
                .iter()
                .find(|b| b.code == "downgrade.blockUnfinishedBinding")
                .map_or(0, |b| b.count)
        };
        let before = unfinished();
        let head = w.head_of(1);
        w.fake().others = vec![other(PROFILE2, 1, head)];
        w.db()
            .conn
            .execute(
                "INSERT INTO profile_bindings(local_profile_id, server_id, server_instance_id,
                   tenant_id, account_id, device_id, fleet_id, remote_profile_id,
                   remote_version, base_version, last_observed_head_hash,
                   accepted_restore_epoch, fkek_key_id, key_generation, sync_state, dirty)
                 SELECT ?1, server_id, server_instance_id, tenant_id, account_id, device_id,
                   fleet_id, ?2, 1, 1, ?3, 0, fkek_key_id, ?4, 'AVAILABLE', 0
                 FROM profile_bindings WHERE local_profile_id = ?5",
                params![
                    reseal_row(&PROFILE2),
                    hex(&PROFILE2),
                    head.to_vec(),
                    GEN as i64,
                    LOCAL
                ],
            )
            .unwrap();
        let ids: Vec<String> = statuses(NOW)
            .unwrap()
            .profiles
            .into_iter()
            .map(|p| p.profile_id)
            .collect();
        assert_eq!(ids, [LOCAL]);
        let older: Vec<String> = under_older_key(&w.dev.pin.0)
            .unwrap()
            .into_iter()
            .map(|p| p.profile_id)
            .collect();
        assert_eq!(older, [LOCAL]);
        let bound: Vec<Option<String>> = w.labels().into_iter().map(|l| l.3).collect();
        assert_eq!(bound, [Some(LOCAL.to_string()), None]);
        assert_eq!(unfinished(), before);
        w.db()
            .conn
            .execute(
                "UPDATE profile_bindings SET lease_id = 'aa', fencing_token = 1,
                   lease_expires_at = '2030-01-01T00:00:00.000Z'
                 WHERE local_profile_id GLOB 'reseal:*'",
                [],
            )
            .unwrap();
        let leases = crate::team::downgrade::readiness()
            .unwrap()
            .blockers
            .iter()
            .find(|b| b.code == "downgrade.blockLease")
            .map_or(0, |b| b.count);
        assert_eq!(leases, 1, "a re-seal lease still blocks");
    }

    /// The UNIQUE row a crashed run left does not refuse a join of its
    /// profile: the join removes it first. One still in flight refuses.
    #[test]
    fn a_leftover_reseal_row_does_not_block_join() {
        let (w, d) = joinable();
        let leftover = |lease: bool| {
            w.db()
                .conn
                .execute(
                    "INSERT INTO profile_bindings(local_profile_id, server_id,
                       server_instance_id, tenant_id, account_id, device_id, fleet_id,
                       remote_profile_id, remote_version, base_version, accepted_restore_epoch,
                       fkek_key_id, key_generation, sync_state, dirty, lease_id, fencing_token,
                       lease_expires_at)
                     SELECT ?1, k.server_id, k.server_instance_id, k.tenant_id, d.account_id,
                       k.device_id, k.fleet_id, ?2, 0, 0, 0, k.fkek_key_id, k.generation,
                       'AVAILABLE', 0, ?3, ?4, ?5
                     FROM fleet_key_state k
                     JOIN device_state d USING (server_id, tenant_id, device_id)
                     WHERE k.state = 'ACTIVE'",
                    params![
                        reseal_row(&PROFILE),
                        hex(&PROFILE),
                        lease.then_some("aa"),
                        lease.then_some(1),
                        lease.then_some("2030-01-01T00:00:00.000Z")
                    ],
                )
                .unwrap();
        };
        leftover(true);
        let out = d.path().join("joined");
        let err = w.join(LOCAL, PROFILE, &out).unwrap_err();
        assert!(has(&err, "sync.resealInProgress"), "{err:#}");
        w.db()
            .conn
            .execute("DELETE FROM profile_bindings", [])
            .unwrap();
        leftover(false);
        assert!(w.join(LOCAL, PROFILE, &out).unwrap() > 0);
        assert_eq!(noise(&out), noise(&w.udd));
        assert_eq!(
            w.count("SELECT count(*) FROM profile_bindings WHERE local_profile_id GLOB 'reseal:*'"),
            0
        );
    }

    /// No key reaches the run's state or the spool: neither `FKEK`, `K2`
    /// nor this device's seeds, raw or hex.
    #[test]
    fn the_reseal_state_and_spool_hold_no_key_bytes() {
        let w = world();
        push_next(&w);
        let _d = unbound_custodian(&w);
        w.fake().lose.push("commit");
        w.reseal(None).unwrap();
        let mut held = vec![std::fs::read(crate::store::fleet_custody_path().unwrap()).unwrap()];
        let spool = crate::store::config_root()
            .unwrap()
            .join("team-sync")
            .join("spool");
        assert!(spool.read_dir().unwrap().count() > 0, "a spooled upload");
        for f in spool.read_dir().unwrap() {
            held.push(std::fs::read(f.unwrap().path()).unwrap());
        }
        w.reseal(None).unwrap();
        held.push(std::fs::read(crate::store::fleet_custody_path().unwrap()).unwrap());
        let secrets: Vec<Vec<u8>> = [
            FKEK.to_vec(),
            K2.to_vec(),
            [1; 32].to_vec(),
            [7; 32].to_vec(),
        ]
        .into_iter()
        .flat_map(|k| [hex(&k).into_bytes(), k])
        .collect();
        for bytes in &held {
            for s in &secrets {
                assert!(
                    !bytes.windows(s.len()).any(|x| x == s.as_slice()),
                    "a key reached the re-seal state or spool"
                );
            }
        }
    }

    /// A restore transition the re-seal accepts moves a bound pin to a head
    /// another device committed, past the data this copy holds
    /// (`base_version < remote_version`): the profile is skipped as in use
    /// before it is marked for sealing or opened, nothing is sent, and the
    /// copy stays behind so its next push asks for a Pull.
    #[test]
    fn a_bound_profile_whose_restore_transition_moves_the_pin_past_its_data_is_skipped() {
        let w = world();
        w.push().unwrap();
        w.push().unwrap();
        let (h1, h2) = (w.head_of(1), w.head_of(2));
        // A joined copy whose first pull never landed: no pin and no data.
        w.db()
            .conn
            .execute(
                "UPDATE profile_bindings SET remote_version = 0, base_version = 0,
                   last_observed_head_hash = NULL",
                [],
            )
            .unwrap();
        w.fake().restore(1);
        let leaves = [leaf(PROFILE, h2, h1)];
        let t = transition(&w.me, 0, &leaves);
        w.file(&w.me.sk, &t, &leaves, &[PROFILE], 0);
        rotate(&w);
        make_custodian(&w);
        let (checkouts, commits) = (w.posts("/checkout"), w.posts("/commit"));
        let reads = w.sent("GET", "/snapshots/1").len();
        let mut sealing = false;
        let run = w
            .reseal_with(None, &free, &mut |s| {
                let p = s.reseal.as_ref().map(|r| r.profiles.get(&hex(&PROFILE)));
                sealing |= p.flatten().is_some_and(|o| o.starts_with("sealing:"));
                crate::fleet_custody::save(s)
            })
            .unwrap();
        assert_eq!(run.profiles[&hex(&PROFILE)], "skipped:in-use");
        assert!(!sealing, "never marked for sealing");
        assert_eq!(w.sent("GET", "/snapshots/1").len(), reads, "never opened");
        assert_eq!(
            (w.posts("/checkout"), w.posts("/commit")),
            (checkouts, commits)
        );
        let (_, _, epoch, version, _) = w.state(LOCAL);
        assert_eq!((epoch, version), (1, 1), "the transition moved the pin");
        assert_eq!(
            w.count("SELECT base_version < remote_version FROM profile_bindings"),
            1,
            "still behind"
        );
    }

    /// 4.S step 4 names this device's own commit only: a head on the saved
    /// base under `G` that another device signed is current, not re-sealed.
    #[test]
    fn a_next_head_another_device_signed_on_the_saved_base_is_current() {
        let w = world();
        push_next(&w);
        rotate(&w);
        push_next(&w);
        let heads = relink(&w, &[(&w.me.sk, GEN), (&author(), GEN + 1)]);
        let _d = unbound_custodian(&w);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, false, false));
        let pending = format!("sealing:1:{}", hex(&heads[0]));
        crate::fleet_custody::save(&FleetCustodyState {
            reseal: Some(ResealRun {
                generation: GEN + 1,
                profiles: [(hex(&PROFILE), pending)].into(),
                ..Default::default()
            }),
            ..Default::default()
        })
        .unwrap();
        let commits = w.posts("/commit");
        let run = w.reseal(None).unwrap();
        assert_eq!(run.profiles[&hex(&PROFILE)], "current");
        assert_eq!(w.posts("/commit"), commits);
    }

    /// The generation floor: a valid head under `GEN` advancing over a pin
    /// under `GEN + 1` is refused, naming the profile and its signer, and
    /// nothing is pinned.
    #[test]
    fn an_advancing_head_below_the_anchor_generation_is_refused() {
        let w = world();
        rotate(&w);
        push_next(&w);
        push_next(&w);
        let heads = relink(&w, &[(&w.me.sk, GEN + 1), (&w.me.sk, GEN)]);
        let d = second(&w);
        rotate(&w);
        pin_at(&w, &d, &heads, 1);
        let out = d.path().join("out");
        let err = w.pull(&out).unwrap_err();
        assert!(has(&err, "sync.headBelowKeyGeneration"), "{err:#}");
        let text = format!("{err:#}");
        assert!(text.contains(LOCAL), "{text}");
        assert!(text.contains(&hex(&w.me.to.signing_key_id)), "{text}");
        untouched_at(&w, 1);
        assert_eq!(w.state(LOCAL).4, Some(heads[0].to_vec()));
        assert!(!out.exists());
    }

    /// The floor holds for an `R` closing a run as well: the anchor `P` is
    /// under `GEN + 1`, `R` under `GEN`. The refusal keeps its own code
    /// although a run is open, and nothing is quarantined, pinned or audited.
    #[test]
    fn an_accepted_revert_below_the_anchor_generation_is_refused() {
        let w = world();
        rotate(&w);
        for _ in 0..3 {
            push_next(&w);
        }
        relink(
            &w,
            &[(&w.me.sk, GEN + 1), (&author(), GEN + 1), (&w.me.sk, GEN)],
        );
        serve(&w, &author_pages(&w, T0 + 300 * DAY, true, false));
        let d = second(&w);
        rotate(&w);
        let out = d.path().join("out");
        let err = w.pull(&out).unwrap_err();
        assert!(has(&err, "sync.headBelowKeyGeneration"), "{err:#}");
        untouched_at(&w, 0);
        assert!(!out.exists());
    }

    /// The floor is never applied to a head that joins the open run: a
    /// withdrawn signer's head under `GEN` above `P` under `GEN + 1` still
    /// quarantines, and an `R` under `GEN + 1` over it is accepted. Before
    /// the revocation the same head stops the pull: the ADR's "stops pulls
    /// until revoked; revert then skips it".
    #[test]
    fn a_revoked_signers_lower_generation_head_still_reverts() {
        let w = world();
        rotate(&w);
        for _ in 0..3 {
            push_next(&w);
        }
        let heads = relink(
            &w,
            &[(&w.me.sk, GEN + 1), (&author(), GEN), (&w.me.sk, GEN + 1)],
        );
        serve(&w, &author_pages(&w, T0 + 300 * DAY, true, false));
        let d = second(&w);
        rotate(&w);
        // While `A` is still valid, its head under `GEN` stops the pull and
        // nothing is pinned.
        serve(&w, &author_pages(&w, T0 + 300 * DAY, false, false));
        let err = w.pull(&d.path().join("valid")).unwrap_err();
        assert!(has(&err, "sync.headBelowKeyGeneration"), "{err:#}");
        untouched_at(&w, 0);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, true, false));
        w.fake().listed = Some((2, Some(heads[1])));
        let err = w.pull(&d.path().join("first")).unwrap_err();
        assert!(has(&err, "sync.signerRevokedAtP"), "{err:#}");
        revoked_at(&w, 1);
        w.fake().listed = None;
        let out = d.path().join("out");
        w.pull(&out).unwrap();
        available_at(&w, 3, heads[2]);
        assert_eq!(skipped(&w), [accepted_by(2, heads[2], 1)]);
        assert_eq!(marker(&out), "v3");
    }

    /// The search below a withdrawn pin is exempt: the pin is under
    /// `GEN + 1`, `P` below it under `GEN`, and a revert restores `P`
    /// through `readable_key` and seals `R` under `GEN + 1`. The anchor is
    /// then `P`, so the floor is `GEN`, not the withdrawn pin's `GEN + 1`
    /// (execution note 5).
    #[test]
    fn a_p_below_a_withdrawn_pin_of_a_lower_generation_is_still_restored() {
        let w = world();
        push_next(&w);
        rotate(&w);
        push_next(&w);
        let heads = relink(&w, &[(&w.me.sk, GEN), (&author(), GEN + 1)]);
        serve(&w, &author_pages_for(&w, T0 + 300 * DAY, None, false));
        let d = second(&w);
        rotate(&w);
        pin_at(&w, &d, &heads, 2);
        let retired = Some(DeviceRevocationReason::Retired);
        serve(&w, &author_pages_for(&w, T0 + 300 * DAY, retired, false));
        let err = w.pull(&d.path().join("out")).unwrap_err();
        assert!(has(&err, "sync.signerRevoked"), "{err:#}");
        revoked_at(&w, 2);
        let udd = d.path().join("profile");
        std::fs::create_dir_all(&udd).unwrap();
        std::fs::write(udd.join("marker"), b"local").unwrap();
        assert_eq!(w.revert(&udd).unwrap().version, 3);
        let r = r_on(&w, heads[1]);
        available_at(&w, 3, r);
        assert_eq!(marker(&udd), "v1", "P, read under GEN");
        let m = SignedSnapshotManifestV2::parse(&w.fake().manifests[&3]).unwrap();
        let p = SnapshotManifestV2::parse(m.canonical_manifest_payload_bytes()).unwrap();
        assert_eq!(p.key_generation, GEN + 1, "R sealed under the newest");
    }

    /// After a restore transition the floor is the generation of the head
    /// the transition pinned, read from its manifest: the binding's
    /// `key_generation` column, which a transition does not write, is not
    /// read (set lower here, it would let the head through).
    #[test]
    fn a_pull_after_a_restore_transition_takes_the_floor_from_the_pinned_head() {
        let w = world();
        push_next(&w);
        rotate(&w);
        push_next(&w);
        push_next(&w);
        let heads = [w.head_of(1), w.head_of(2), w.head_of(3)];
        let h2 = heads[1];
        let d = second(&w);
        rotate(&w);
        pin_at(&w, &d, &heads, 3);
        w.fake().restore(2);
        // A fixture bypassing the key that ties the column to its key row.
        w.db()
            .conn
            .execute_batch(
                "PRAGMA foreign_keys = OFF; UPDATE profile_bindings SET key_generation = 1",
            )
            .unwrap();
        let leaves = [
            leaf(PROFILE, heads[2], h2),
            leaf([0xc4; 16], [7; 32], [8; 32]),
            leaf([0xc5; 16], [9; 32], [10; 32]),
        ];
        let t = transition(&w.me, 0, &leaves);
        w.file(&w.me.sk, &t, &leaves, &[PROFILE], 0);
        resign(&w, 2, &w.me.sk, |p| {
            p.target_version = 3;
            p.base_version = 2;
            p.previous_signed_head_hash = Some(h2);
            p.restore_epoch = 1;
            p.key_generation = GEN;
            p.fkek_key_id = shardx_core::fleet_grants::fkek_key_id(&FKEK);
        });
        let out = d.path().join("out");
        let err = w.pull(&out).unwrap_err();
        assert!(has(&err, "sync.headBelowKeyGeneration"), "{err:#}");
        assert_eq!(
            w.state(LOCAL),
            ("AVAILABLE".into(), None, 1, 2, Some(h2.to_vec()))
        );
        assert_eq!(
            w.count("SELECT key_generation FROM profile_bindings"),
            GEN as i64
        );
        assert!(!out.exists());
    }

    /// `readable_key` still needs a grant that reverifies now (Q-26): with
    /// the kept `GEN` grant record no longer equal to its bytes, a head
    /// under `GEN` is refused and nothing is pinned.
    #[test]
    fn a_pull_refuses_an_older_generation_whose_grant_no_longer_reverifies() {
        let w = world();
        push_next(&w);
        let d = second(&w);
        rotate(&w);
        w.db()
            .conn
            .execute(
                "UPDATE signed_authorization_records SET revoked_at_ms = issued_at_ms
                 WHERE record_kind = 'FleetKeyGrantV2::DeviceHpkeGrant' AND generation = ?1",
                [GEN as i64],
            )
            .unwrap();
        let out = d.path().join("out");
        let err = w.pull(&out).unwrap_err();
        assert!(has(&err, "sync.headUnderRetiredKey"), "{err:#}");
        untouched_at(&w, 0);
        assert!(!out.exists());
    }

    /// Cost b: once the `GEN` grant's window ends, a head under `GEN` is
    /// unreadable, while the trust evidence and its signer are still valid.
    /// The second device holds `GEN` from a grant that ends at `T0 + 2 DAY`.
    #[test]
    fn an_old_generation_head_is_unreadable_after_its_grant_window_ends() {
        let mut w = world();
        push_next(&w);
        let mut g = DeviceHpkeGrantV2 {
            common: CommonFields {
                not_after_ms: T0 + 2 * DAY,
                ..common(41)
            },
            fleet_id: FLEET,
            fkek_key_id: shardx_core::fleet_grants::fkek_key_id(&FKEK),
            generation: GEN,
            subject_account_id: w.me.to.account_id,
            subject_device_id: w.me.to.device_id,
            subject_signing_key_id: w.me.to.signing_key_id,
            recipient_hpke_key_id: w.me.to.hpke_key_id,
            hpke_encapped_key_bytes: Vec::new(),
            hpke_wrapped_fleet_key_bytes: Vec::new(),
        };
        shardx_core::grants::seal_device_fkek(&w.me.hpke_pk, &mut g, &FKEK).unwrap();
        w.grant = build_record(&w.me.sk, DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE, &g.encode());
        let d = second(&w);
        rotate(&w);
        assert!(readable_key(&w.db(), &w.dev, &FLEET, GEN, None, NOW).is_ok());
        let out = d.path().join("out");
        let err = w.pull_at(&out, T0 + 3 * DAY).unwrap_err();
        assert!(has(&err, "sync.headUnderRetiredKey"), "{err:#}");
        untouched_at(&w, 0);
        assert!(!out.exists());
    }

    /// Cost a: a device holding only `GEN + 1` cannot open a head under
    /// `GEN`, and is told so apart from a missing fleet key.
    #[test]
    fn a_device_without_the_old_key_gets_head_under_retired_key() {
        let w = world();
        push_next(&w);
        let d = second(&w);
        crate::fleet_keys::save(&crate::fleet_keys::FleetKeyStore::default()).unwrap();
        rotate(&w);
        let out = d.path().join("out");
        let err = w.pull(&out).unwrap_err();
        assert!(has(&err, "sync.headUnderRetiredKey"), "{err:#}");
        assert!(!has(&err, "sync.noVerifiedFleetKey"), "{err:#}");
        untouched_at(&w, 0);
        assert!(!out.exists());
    }

    /// Seal stays fresh-only: a checkout naming `GEN` after this device
    /// verified `GEN + 1` is released and nothing is uploaded.
    #[test]
    fn sealing_under_an_older_generation_is_still_refused() {
        let w = world();
        rotate(&w);
        {
            let mut f = w.fake();
            f.generation = None;
            f.fkek_key_id = None;
        }
        let err = w.push().unwrap_err();
        assert!(has(&err, "sync.noVerifiedFleetKey"), "{err:#}");
        assert_eq!(w.sent("POST", "/release").len(), 1);
        assert!(w.sent("POST", "/uploads").is_empty());
    }

    /// Lazy re-seal: the first push after a rotation seals under `GEN + 1`.
    #[test]
    fn a_push_after_rotation_seals_under_the_newest_generation() {
        let w = world();
        push_next(&w);
        rotate(&w);
        push_next(&w);
        let named = |v: u64| {
            let m = SignedSnapshotManifestV2::parse(&w.fake().manifests[&v]).unwrap();
            let p = SnapshotManifestV2::parse(m.canonical_manifest_payload_bytes()).unwrap();
            (p.key_generation, p.fkek_key_id)
        };
        let id = shardx_core::fleet_grants::fkek_key_id;
        assert_eq!(named(1), (GEN, id(&FKEK)));
        assert_eq!(named(2), (GEN + 1, id(&K2)));
    }

    /// Architect should 1: a pull that accepts `R1` and stops inside a later
    /// run pins `R1`, audits both runs, and keeps the quarantine. With a
    /// valid head instead of the second run it ends available.
    #[test]
    fn a_pull_crossing_an_accepted_run_into_another_keeps_the_quarantine() {
        for second_run in [true, false] {
            let w = world();
            let last = if second_run {
                author()
            } else {
                w.me.sk.clone()
            };
            let heads = chain_of(&w, &[&w.me.sk, &author(), &w.me.sk, &last]);
            serve(&w, &author_pages(&w, T0 + 300 * DAY, true, false));
            let d = second(&w);
            let pulled = w.pull(&d.path().join("out"));
            if second_run {
                let err = pulled.unwrap_err();
                assert!(has(&err, "sync.signerRevokedAtP"), "{err:#}");
                revoked_at(&w, 3);
                assert_eq!(w.state(LOCAL).4, Some(heads[2].to_vec()));
                assert_eq!(
                    skipped(&w),
                    [accepted_by(2, heads[2], 1), (4, None, None, 3)]
                );
            } else {
                pulled.unwrap();
                available_at(&w, 4, heads[3]);
                assert_eq!(skipped(&w), [accepted_by(2, heads[2], 1)]);
            }
        }
    }

    /// When each open row of `LOCAL`'s profile was superseded, if it was.
    fn superseded(w: &World) -> Vec<Option<i64>> {
        let db = w.db();
        let mut s = db
            .conn
            .prepare(
                "SELECT CASE WHEN resolution = 'SUPERSEDED' THEN resolved_at_ms END
                 FROM skipped_heads ORDER BY target_version",
            )
            .unwrap();
        let rows = s
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        rows
    }

    /// Stale open rows end once, as `SUPERSEDED`: by an unbind, by an
    /// accepted restore epoch transition, and by a walk that reads another
    /// head at the row's version.
    #[test]
    fn stale_unresolved_rows_are_superseded_once_by_a_transition_or_unbind() {
        // An unbind.
        {
            let w = world();
            chain_of(&w, &[&w.me.sk, &author()]);
            serve(&w, &author_pages(&w, T0 + 300 * DAY, true, false));
            let d = second(&w);
            w.pull(&d.path().join("out")).unwrap_err();
            assert_eq!(superseded(&w), [None]);
            unbind(LOCAL, SERVER, NOW + DAY).unwrap();
            unbind(LOCAL, SERVER, NOW + 2 * DAY).unwrap();
            assert_eq!(superseded(&w), [Some((NOW + DAY) as i64)]);
        }

        // Another head served at the row's version.
        {
            let w = world();
            let pinned = chain_of(&w, &[&w.me.sk, &author()])[0];
            serve(&w, &author_pages(&w, T0 + 300 * DAY, true, false));
            let d = second(&w);
            w.pull(&d.path().join("out")).unwrap_err();
            assert_eq!(superseded(&w), [None]);
            {
                let mut f = w.fake();
                let m = SignedSnapshotManifestV2::parse(&f.manifests[&2]).unwrap();
                let mut p =
                    SnapshotManifestV2::parse(m.canonical_manifest_payload_bytes()).unwrap();
                p.signer_signing_key_id = w.me.to.signing_key_id;
                let signed = SignedSnapshotManifestV2::sign(&w.me.sk, &p).unwrap();
                f.manifests.insert(2, signed.exact_bytes().to_vec());
                f.head = Some(signed.head_hash());
            }
            // No `R` was accepted: the quarantine and the pin stay.
            let again = d.path().join("again");
            let err = w.pull(&again).unwrap_err();
            assert!(has(&err, "sync.signerRevoked"), "{err:#}");
            assert_eq!(superseded(&w), [Some(NOW as i64)]);
            revoked_at(&w, 1);
            assert_eq!(w.state(LOCAL).4, Some(pinned.to_vec()));
            assert!(!again.exists());
        }

        // An accepted restore epoch transition.
        let w = world();
        let (h1, h2) = restored(&w);
        w.db()
            .conn
            .execute(
                "INSERT INTO skipped_heads(server_instance_id, tenant_id, remote_profile_id,
                   local_profile_id, target_version, head_hash, signer_signing_key_id,
                   anchor_version, anchor_head_hash, recorded_at_ms)
                 VALUES (?1, ?2, ?3, ?4, 2, ?5, ?6, 1, ?7, 0)",
                params![
                    hex(&INSTANCE),
                    hex(&TENANT),
                    hex(&PROFILE),
                    LOCAL,
                    h2.to_vec(),
                    hex(&key_id_of(&author())),
                    h1.to_vec()
                ],
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
        w.pull(&w.udd.with_file_name("out")).unwrap();
        assert_eq!(w.state(LOCAL).2, 1);
        assert_eq!(superseded(&w), [Some(NOW as i64)]);
    }

    // ----------------------------------------------------- revert commit ----
    // ADR 0002 rule 6, "Committer side".

    impl World {
        fn revert(&self, udd: &Path) -> Result<Pushed> {
            self.rt.block_on(revert(
                &self.client,
                "t",
                &self.dev,
                LOCAL,
                udd,
                NOW,
                &|| std::time::Duration::ZERO,
            ))
        }

        /// [`revert`] stopped right after `finish`'s transaction.
        fn revert_to_finish(&self, udd: &Path) -> Result<Pushed> {
            self.rt.block_on(revert_inner(
                &self.client,
                "t",
                &self.dev,
                LOCAL,
                udd,
                NOW,
                &|| std::time::Duration::ZERO,
            ))
        }

        fn push_from(&self, udd: &Path) -> Result<Pushed> {
            self.rt
                .block_on(push(&self.client, "t", &self.dev, LOCAL, udd, NOW, &|| {
                    std::time::Duration::ZERO
                }))
        }

        fn dirty(&self) -> i64 {
            self.count("SELECT dirty FROM profile_bindings")
        }
    }

    /// A revert's starting point: v1 (`P`) by this device, v2 (`J`) by `A`,
    /// whose revocation for `reason` a second device counted in a pull that
    /// pinned v1 and left v2 open. The heads, that device's root, and its
    /// profile, whose `marker` reads `local`.
    fn reverting(
        w: &World,
        reason: DeviceRevocationReason,
    ) -> (Vec<[u8; 32]>, tempfile::TempDir, std::path::PathBuf) {
        let heads = chain_of(w, &[&w.me.sk, &author()]);
        serve(w, &author_pages_for(w, T0 + 300 * DAY, Some(reason), false));
        let d = second(w);
        let err = w.pull(&d.path().join("pulled")).unwrap_err();
        assert!(has(&err, "sync.signerRevokedAtP"), "{err:#}");
        revoked_at(w, 1);
        let udd = d.path().join("profile");
        std::fs::create_dir_all(&udd).unwrap();
        std::fs::write(udd.join("marker"), b"local").unwrap();
        (heads, d, udd)
    }

    fn marker(udd: &Path) -> String {
        std::fs::read_to_string(udd.join("marker")).unwrap()
    }

    /// Every file under `dir` with its bytes.
    fn tree(dir: &Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                out.extend(tree(&p));
            } else {
                out.push((p.clone(), std::fs::read(&p).unwrap()));
            }
        }
        out.sort();
        out
    }

    /// No staging dir, no moved-aside data and no pending swap.
    fn settled(w: &World, udd: &Path) {
        assert!(!beside(udd, ".revert-staging").exists());
        assert!(!beside(udd, ".revert-old").exists());
        assert_eq!(w.count("SELECT count(*) FROM revert_swaps"), 0);
    }

    /// `R` at version 3: on top of `J` with this device as signer.
    fn r_on(w: &World, j: [u8; 32]) -> [u8; 32] {
        let m = SignedSnapshotManifestV2::parse(&w.fake().manifests[&3]).unwrap();
        let p = SnapshotManifestV2::parse(m.canonical_manifest_payload_bytes()).unwrap();
        assert_eq!(
            (
                p.base_version,
                p.previous_signed_head_hash,
                p.signer_signing_key_id
            ),
            (2, Some(j), w.me.to.signing_key_id)
        );
        m.head_hash()
    }

    #[test]
    fn revert_commits_the_newest_valid_snapshot_on_top_of_the_rejected_head() {
        let w = world();
        let (heads, _d, udd) = reverting(&w, DeviceRevocationReason::Retired);
        assert_eq!(w.revert(&udd).unwrap().version, 3);
        let r = r_on(&w, heads[1]);
        available_at(&w, 3, r);
        assert_eq!(skipped(&w), [accepted_by(2, r, 1)]);
        assert_eq!(marker(&udd), "v1", "P's content, swapped in");
        settled(&w, &udd);
    }

    /// Blocking 1: `Jn` is the pin, so the checkout's base is the pinned
    /// version. The run is offered (an open row) and, once checked out, the
    /// lease held under `SIGNER_REVOKED` is the revert in progress.
    #[test]
    fn revert_commits_over_a_head_pinned_before_its_signer_was_proven_revoked() {
        let w = world();
        let heads = chain_of(&w, &[&w.me.sk, &author()]);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, false, false));
        let d = second(&w);
        pin_at(&w, &d, &heads, 2);
        let retired = Some(DeviceRevocationReason::Retired);
        serve(&w, &author_pages_for(&w, T0 + 300 * DAY, retired, false));
        let err = w.pull(&d.path().join("out")).unwrap_err();
        assert!(has(&err, "sync.signerRevoked"), "{err:#}");
        revoked_at(&w, 2);
        assert_eq!(skipped(&w), [(2, None, None, 1)], "offered");
        let udd = d.path().join("profile");
        std::fs::create_dir_all(&udd).unwrap();
        w.fake().skip.push("upload");
        w.revert(&udd).unwrap_err();
        assert_eq!(
            w.count(
                "SELECT count(*) FROM profile_bindings WHERE lease_id IS NOT NULL
                   AND last_error_code = 'SIGNER_REVOKED' AND remote_version = 2"
            ),
            1,
            "in progress"
        );
        assert!(beside(&udd, ".revert-staging").exists(), "kept to resume");
        assert_eq!(w.revert(&udd).unwrap().version, 3);
        let r = r_on(&w, heads[1]);
        available_at(&w, 3, r);
        assert_eq!(skipped(&w), [accepted_by(2, r, 1)]);
        assert_eq!(marker(&udd), "v1");
        settled(&w, &udd);
    }

    #[test]
    fn an_ordinary_push_refuses_a_revert_lease_on_the_pinned_head() {
        let w = world();
        let heads = chain_of(&w, &[&w.me.sk, &author()]);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, false, false));
        let d = second(&w);
        pin_at(&w, &d, &heads, 2);
        let retired = Some(DeviceRevocationReason::Retired);
        serve(&w, &author_pages_for(&w, T0 + 300 * DAY, retired, false));
        let udd = d.path().join("profile");
        std::fs::create_dir_all(&udd).unwrap();
        w.fake().skip.push("upload");
        w.revert(&udd).unwrap_err();
        let sent = w.fake().log.len();
        let err = w.push().unwrap_err();
        assert!(has(&err, "sync.revertInProgress"), "{err:#}");
        assert_eq!(w.fake().log.len(), sent, "nothing was sent");
        assert_eq!(w.state(LOCAL).1.as_deref(), Some("SIGNER_REVOKED"));
    }

    /// Blocking 2: whichever path releases a revert lease, the binding ends
    /// quarantined with `SIGNER_REVOKED` and `dirty` as it was, so an
    /// ordinary push cannot then commit over `Jn`.
    #[test]
    fn an_abandoned_revert_keeps_the_binding_quarantined() {
        for case in [
            "seal blocked",
            "seal key",
            "upload aborted",
            "checkout replay",
        ] {
            let w = world();
            let (heads, _d, udd) = reverting(&w, DeviceRevocationReason::Retired);
            match case {
                "seal blocked" => w.fake().on_checkout = Some(a_compromise(&w)),
                "seal key" => w.fake().generation = Some(2),
                "upload aborted" => w.fake().on_patch = Some(a_compromise(&w)),
                _ => {
                    {
                        let mut f = w.fake();
                        f.expires = Some(T0);
                        f.lose.push("checkout");
                    }
                    w.revert(&udd).unwrap_err();
                    // The replay is released; the checkout after it refused.
                    let mut f = w.fake();
                    f.expires = None;
                    f.listed = Some((2, Some(heads[1])));
                    f.version = 5;
                }
            }
            w.revert(&udd).unwrap_err();
            if case == "checkout replay" {
                assert_eq!(w.sent("POST", "/release").len(), 1, "{case}");
                w.fake().version = 2;
            }
            revoked_at(&w, 1);
            assert_eq!(w.dirty(), 0, "{case}");
            let checkouts = w.sent("POST", "/checkout").len();
            let err = w.push().unwrap_err();
            assert!(has(&err, "sync.bindingQuarantined"), "{case}: {err:#}");
            assert_eq!(w.sent("POST", "/checkout").len(), checkouts, "{case}");
        }
    }

    #[test]
    fn revert_committed_here_is_accepted_by_a_second_device() {
        let w = world();
        let (heads, _d, udd) = reverting(&w, DeviceRevocationReason::Retired);
        w.revert(&udd).unwrap();
        let r = r_on(&w, heads[1]);
        let e = second(&w);
        let out = e.path().join("out");
        w.pull(&out).unwrap();
        available_at(&w, 3, r);
        assert_eq!(skipped(&w), [accepted_by(2, r, 1)]);
        assert_eq!(marker(&out), "v1");
    }

    #[test]
    fn revert_is_refused_for_a_reported_only_revocation() {
        let w = world();
        chain_of(&w, &[&w.me.sk, &author()]);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, false, true));
        let d = second(&w);
        w.pull(&d.path().join("out")).unwrap_err();
        revoked_at(&w, 0);
        let udd = d.path().join("profile");
        std::fs::create_dir_all(&udd).unwrap();
        std::fs::write(udd.join("marker"), b"local").unwrap();
        let before = tree(&udd);
        let err = w.revert(&udd).unwrap_err();
        assert!(has(&err, "sync.signerRevoked"), "{err:#}");
        assert_eq!(w.sent("POST", "/checkout").len(), 2, "only the chain's own");
        assert_eq!(tree(&udd), before);
        assert!(!beside(&udd, ".revert-staging").exists());
        assert!(skipped(&w).is_empty());
    }

    /// Q-18: a `compromised` revocation holds the revert until the fleet is
    /// rotated; the quarantine keeps `SIGNER_REVOKED`. Then `P` is read at
    /// its own generation and `R` sealed under the new one.
    #[test]
    fn revert_waits_for_rotation_after_a_compromised_revocation() {
        let w = world();
        let (heads, _d, udd) = reverting(&w, DeviceRevocationReason::Compromised);
        let checkouts = w.sent("POST", "/checkout").len();
        let err = w.revert(&udd).unwrap_err();
        assert!(has(&err, "sync.commitBlockedCompromised"), "{err:#}");
        revoked_at(&w, 1);
        assert_eq!(w.sent("POST", "/checkout").len(), checkouts);
        assert_eq!(marker(&udd), "local");

        let k2 = [0x52; 32];
        let mut extra = vec![key_rotate(&w.me)];
        extra.extend(activation(&w.me, 2, &k2, 0, 71, None));
        w.collect(2, &k2, 70, extra);
        assert!(crate::fleet_keys::collect(&hex(&FLEET), 2, &k2).unwrap());
        {
            let mut f = w.fake();
            f.generation = Some(2);
            f.fkek_key_id = Some(shardx_core::fleet_grants::fkek_key_id(&k2));
        }
        assert!(!w.blocked(2), "rotated");
        assert_eq!(w.revert(&udd).unwrap().version, 3);
        let r = r_on(&w, heads[1]);
        available_at(&w, 3, r);
        let m = SignedSnapshotManifestV2::parse(&w.fake().manifests[&3]).unwrap();
        let p = SnapshotManifestV2::parse(m.canonical_manifest_payload_bytes()).unwrap();
        assert_eq!(p.key_generation, 2, "sealed under the new generation");
        assert_eq!(marker(&udd), "v1", "read under generation 1");
    }

    #[test]
    fn revert_refuses_without_a_valid_earlier_snapshot() {
        let w = world();
        chain_of(&w, &[&author()]);
        let retired = Some(DeviceRevocationReason::Retired);
        serve(&w, &author_pages_for(&w, T0 + 300 * DAY, retired, false));
        let d = second(&w);
        w.pull(&d.path().join("out")).unwrap_err();
        revoked_at(&w, 0);
        let udd = d.path().join("profile");
        std::fs::create_dir_all(&udd).unwrap();
        let checkouts = w.sent("POST", "/checkout").len();
        let err = w.revert(&udd).unwrap_err();
        assert!(has(&err, "sync.revertNoValidSnapshot"), "{err:#}");
        assert_eq!(w.sent("POST", "/checkout").len(), checkouts);
        assert!(!beside(&udd, ".revert-staging").exists());
        assert_eq!(skipped(&w), [(1, None, None, 0)]);
    }

    /// The commit's reply is lost: the next revert resumes the stored
    /// operations on the base the checkout took (a walk would now find `R`
    /// and no run): one checkout, one commit, one version.
    #[test]
    fn revert_resumes_after_a_lost_commit_reply() {
        let w = world();
        let (heads, _d, udd) = reverting(&w, DeviceRevocationReason::Retired);
        let (checkouts, commits) = (w.sent("POST", "/checkout").len(), w.fake().commits);
        w.fake().lose.push("commit");
        w.revert(&udd).unwrap_err();
        assert_eq!(w.fake().version, 3, "committed, the reply lost");
        assert_eq!(marker(&udd), "local");
        assert_eq!(w.revert(&udd).unwrap().version, 3);
        assert_eq!(w.sent("POST", "/checkout").len(), checkouts + 1);
        assert_eq!(w.fake().commits, commits + 1);
        let r = r_on(&w, heads[1]);
        available_at(&w, 3, r);
        assert_eq!(skipped(&w), [accepted_by(2, r, 1)]);
        assert_eq!(marker(&udd), "v1");
        settled(&w, &udd);
    }

    /// A refused checkout, after `P` was staged: the user's data as it was,
    /// and the staging dir gone.
    fn refused_checkout(w: &World, udd: &Path) {
        let before = tree(udd);
        w.fake().refuse.push(("checkout", 409));
        w.revert(udd).unwrap_err();
        assert_eq!(tree(udd), before);
        assert!(!beside(udd, ".revert-staging").exists());
        revoked_at(w, 1);
    }

    #[test]
    fn a_refused_revert_checkout_keeps_the_local_profile() {
        let w = world();
        let (_, _d, udd) = reverting(&w, DeviceRevocationReason::Retired);
        refused_checkout(&w, &udd);
    }

    #[test]
    fn a_refused_revert_discards_its_staging() {
        let w = world();
        let (_, _d, udd) = reverting(&w, DeviceRevocationReason::Retired);
        std::fs::create_dir_all(beside(&udd, ".revert-staging")).unwrap();
        refused_checkout(&w, &udd);
    }

    /// Blocking 3: with `R` pinned and the swap pending, every entry point
    /// completes the swap before it reads or writes the profile.
    #[test]
    fn a_crash_after_finish_completes_the_staging_swap() {
        for entry in ["revert", "push", "pull", "launch"] {
            let w = world();
            let (heads, _d, udd) = reverting(&w, DeviceRevocationReason::Retired);
            w.revert_to_finish(&udd).unwrap();
            let r = r_on(&w, heads[1]);
            available_at(&w, 3, r);
            assert_eq!(w.count("SELECT count(*) FROM revert_swaps"), 1);
            assert_eq!(marker(&udd), "local", "{entry}: not swapped yet");
            match entry {
                "revert" => {
                    let err = w.revert(&udd).unwrap_err();
                    assert!(has(&err, "sync.revertUnavailable"), "{err:#}");
                }
                "push" => assert_eq!(w.push_from(&udd).unwrap().version, 4),
                "pull" => {
                    w.pull(&udd).unwrap();
                }
                _ => settle_revert_swap(LOCAL, &udd).unwrap(),
            }
            assert_eq!(marker(&udd), "v1", "{entry}");
            settled(&w, &udd);
        }
    }

    /// Each state the swap can stop in resumes to the same end.
    #[test]
    fn a_crash_inside_the_staging_swap_resumes() {
        let w = world();
        let (_, _d, udd) = reverting(&w, DeviceRevocationReason::Retired);
        w.revert_to_finish(&udd).unwrap();
        let (staging, old) = (beside(&udd, ".revert-staging"), beside(&udd, ".revert-old"));
        let row = "INSERT INTO revert_swaps VALUES ('local-profile', 3, zeroblob(32), 0)";
        for state in ["udd moved aside", "staging moved in", "old deleted"] {
            if w.count("SELECT count(*) FROM revert_swaps") == 0 {
                w.db().conn.execute(row, []).unwrap();
                std::fs::rename(&udd, &staging).unwrap();
                std::fs::create_dir_all(&udd).unwrap();
                std::fs::write(udd.join("marker"), b"local").unwrap();
            }
            std::fs::rename(&udd, &old).unwrap();
            if state != "udd moved aside" {
                std::fs::rename(&staging, &udd).unwrap();
            }
            if state == "old deleted" {
                std::fs::remove_dir_all(&old).unwrap();
            }
            settle_revert_swap(LOCAL, &udd).unwrap();
            assert_eq!(marker(&udd), "v1", "{state}");
            settled(&w, &udd);
        }
    }

    /// A staging dir with no swap row (a revert cut off before `finish`)
    /// never replaces the profile, and the next revert unpacks afresh.
    #[test]
    fn a_staging_dir_without_a_swap_row_is_never_swapped_in() {
        let w = world();
        let (_, _d, udd) = reverting(&w, DeviceRevocationReason::Retired);
        let staging = beside(&udd, ".revert-staging");
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join("stale"), b"stale").unwrap();
        settle_revert_swap(LOCAL, &udd).unwrap();
        w.pull(&udd).unwrap_err();
        assert_eq!(marker(&udd), "local");
        assert!(staging.join("stale").exists(), "never swapped in");
        w.revert(&udd).unwrap();
        assert_eq!(marker(&udd), "v1");
        assert!(!udd.join("stale").exists(), "unpacked afresh");
        settled(&w, &udd);
    }

    #[test]
    fn a_swap_row_for_a_deleted_profile_is_cleared() {
        let w = world();
        let row = "INSERT INTO revert_swaps VALUES ('local-profile', 3, zeroblob(32), 0)";
        let udd = w.udd.with_file_name("gone");
        w.db().conn.execute(row, []).unwrap();
        settle_revert_swap(LOCAL, &udd).unwrap();
        assert!(!udd.exists(), "nothing created");
        settled(&w, &udd);

        // Cut off between the renames: the data aside and `P` staged.
        w.db().conn.execute(row, []).unwrap();
        for (dir, text) in [(".revert-old", "old"), (".revert-staging", "new")] {
            std::fs::create_dir_all(beside(&udd, dir)).unwrap();
            std::fs::write(beside(&udd, dir).join("marker"), text).unwrap();
        }
        settle_revert_swap(LOCAL, &udd).unwrap();
        assert_eq!(marker(&udd), "new");
        settled(&w, &udd);
    }

    /// Critic S1: a revert abandoned at seal whose release reply was lost
    /// holds the lease; an ordinary push leaves it alone, and the next revert
    /// replays the release, checks out again on `Jn` and commits `R`.
    #[test]
    fn revert_resumes_after_a_lost_release_of_an_abandoned_lease() {
        let w = world();
        let (heads, _d, udd) = reverting(&w, DeviceRevocationReason::Retired);
        {
            let mut f = w.fake();
            f.generation = Some(2);
            f.lose.push("release");
        }
        w.revert(&udd).unwrap_err();
        assert_eq!(
            w.count("SELECT count(*) FROM operations WHERE kind = 'RELEASE' AND state = 'PENDING'"),
            1
        );
        let (releases, checkouts) = (
            w.sent("POST", "/release").len(),
            w.sent("POST", "/checkout").len(),
        );
        let err = w.push().unwrap_err();
        assert!(has(&err, "sync.revertInProgress"), "{err:#}");
        assert_eq!(w.sent("POST", "/release").len(), releases);
        assert_eq!(w.sent("POST", "/checkout").len(), checkouts);
        w.fake().generation = None;
        assert_eq!(w.revert(&udd).unwrap().version, 3);
        assert_eq!(w.sent("POST", "/release").len(), releases + 1, "replayed");
        assert_eq!(w.sent("POST", "/checkout").len(), checkouts + 1);
        let r = r_on(&w, heads[1]);
        available_at(&w, 3, r);
        assert_eq!(skipped(&w), [accepted_by(2, r, 1)]);
        assert_eq!(marker(&udd), "v1");
    }

    /// Architect should 2: a revert lease abandoned at seal (Q-18) takes its
    /// staging dir with it, also when the release reply is lost and the
    /// lease is still held: no decrypted `P` stays behind an abandonment, and
    /// the revert that resumes it restores `P` again.
    #[test]
    fn an_abandoned_revert_lease_discards_its_staging() {
        for lost in [false, true] {
            let w = world();
            let (_, _d, udd) = reverting(&w, DeviceRevocationReason::Retired);
            let before = tree(&udd);
            {
                let mut f = w.fake();
                f.on_checkout = Some(a_compromise(&w));
                if lost {
                    f.lose.push("release");
                }
            }
            let err = w.revert(&udd).unwrap_err();
            assert!(has(&err, "sync.commitBlockedCompromised"), "{err:#}");
            assert_eq!(tree(&udd), before);
            assert!(!beside(&udd, ".revert-staging").exists(), "{lost}");
        }
    }

    /// Architect should 2: deleting or unbinding a profile settles a pending
    /// swap and discards a staging dir left over; with none it does nothing.
    #[test]
    fn deleting_or_unbinding_a_profile_discards_its_revert_staging() {
        let w = world();
        let _lifecycle = crate::profile::lifecycle_test_guard();
        let root = crate::store::user_data_root().unwrap();
        let profile = || {
            let mut s = crate::profile::StoredProfile::default();
            crate::profile::save_raw(&mut s).unwrap();
            s.meta.id
        };
        let leftover = |id: &str| {
            let staging = beside(&root.join(id), ".revert-staging");
            std::fs::create_dir_all(&staging).unwrap();
            std::fs::write(staging.join("marker"), b"P").unwrap();
            staging
        };
        let id = profile();
        let staging = leftover(&id);
        crate::profile_delete(id).unwrap();
        assert!(!staging.exists(), "deleted with the profile");

        // Unbinding takes a canonical profile ID.
        let id = profile();
        w.bind(&id, [0xc2; 16], 1, [9; 32]);
        let staging = leftover(&id);
        crate::team::downgrade::unbind_profile(&id, SERVER, NOW).unwrap();
        assert!(!staging.exists(), "discarded by the unbind");

        // A held revert lease stays with the binding; the staged `P` goes
        // with the profile.
        let id = profile();
        w.bind(&id, [0xc3; 16], 1, [9; 32]);
        w.db()
            .conn
            .execute(
                "UPDATE profile_bindings SET lease_id = ?2, fencing_token = 1,
                   lease_expires_at = '2099-01-01T00:00:00.000Z', sync_state = 'QUARANTINED',
                   last_error_code = 'SIGNER_REVOKED'
                 WHERE local_profile_id = ?1",
                params![id, hex(&[7; 16])],
            )
            .unwrap();
        let staging = leftover(&id);
        crate::profile_delete(id).unwrap();
        assert!(!staging.exists(), "deleted under a held lease");
        assert_eq!(
            w.count("SELECT count(*) FROM profile_bindings WHERE lease_id IS NOT NULL"),
            1
        );

        let id = profile();
        crate::profile_delete(id.clone()).unwrap();
        assert!(!beside(&root.join(&id), ".revert-staging").exists(), "none");
    }

    /// The folder-delete fallback fails closed as the trash does: a pending
    /// swap that cannot land keeps the profile, its binding and the swap.
    #[test]
    fn a_folder_delete_keeps_a_profile_whose_pending_swap_cannot_land() {
        let w = world();
        let _lifecycle = crate::profile::lifecycle_test_guard();
        let mut profile = crate::profile::StoredProfile::default();
        profile.meta.folder = "swap-pending-folder".into();
        crate::profile::save_raw(&mut profile).unwrap();
        let id = profile.meta.id;
        w.bind(&id, [0xca; 16], 1, [9; 32]);
        let udd = crate::store::user_data_root().unwrap().join(&id);
        std::fs::create_dir_all(&udd).unwrap();
        std::fs::write(udd.join("marker"), b"local").unwrap();
        let staging = beside(&udd, ".revert-staging");
        std::fs::create_dir_all(&staging).unwrap();
        // A file where the swap moves the old data aside: the swap cannot land.
        std::fs::write(beside(&udd, ".revert-old"), b"in the way").unwrap();
        w.db()
            .conn
            .execute(
                "INSERT INTO revert_swaps VALUES (?1, 3, zeroblob(32), 0)",
                [&id],
            )
            .unwrap();

        let err = crate::folder_delete("swap-pending-folder".into(), true).unwrap_err();
        assert!(
            crate::errcode::has_code(&err, "profile.folderDeletePartial"),
            "{err}"
        );
        assert!(crate::profile::load_raw(&id).is_ok() && udd.exists());
        assert!(staging.exists());
        assert!(is_published(&id).unwrap(), "still bound");
        assert_eq!(w.count("SELECT count(*) FROM revert_swaps"), 1);
    }

    #[test]
    fn folder_delete_discards_decrypted_revert_staging() {
        let w = world();
        let _lifecycle = crate::profile::lifecycle_test_guard();
        let mut profile = crate::profile::StoredProfile::default();
        profile.meta.folder = "staged-revert-folder".into();
        crate::profile::save_raw(&mut profile).unwrap();
        let id = profile.meta.id;
        w.bind(&id, [0xc4; 16], 1, [9; 32]);
        let udd = crate::store::user_data_root().unwrap().join(&id);
        std::fs::create_dir_all(&udd).unwrap();
        std::fs::write(udd.join("marker"), b"local").unwrap();
        let staging = beside(&udd, ".revert-staging");
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join("marker"), b"decrypted P").unwrap();

        assert_eq!(
            crate::folder_delete("staged-revert-folder".into(), true).unwrap(),
            1
        );
        assert!(!udd.exists(), "the profile data was deleted");
        assert!(
            crate::profile::load_raw(&id).is_err(),
            "the profile record was deleted"
        );
        assert!(
            !staging.exists(),
            "folder deletion must remove the deleted profile's decrypted revert staging"
        );
    }

    #[test]
    fn deletion_unbind_and_discard_remove_the_unpack_leftovers_beside_the_staging() {
        let w = world();
        let _lifecycle = crate::profile::lifecycle_test_guard();
        let root = crate::store::user_data_root().unwrap();
        let profile = || {
            let mut s = crate::profile::StoredProfile::default();
            crate::profile::save_raw(&mut s).unwrap();
            s.meta.id
        };
        // The staging, `unpack`'s two siblings of it, and the swap's old data.
        let leftovers = |id: &str| {
            [
                ".revert-staging",
                ".revert-staging.incoming",
                ".revert-staging.backup",
                ".revert-old",
            ]
            .map(|suffix| {
                let dir = beside(&root.join(id), suffix);
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(dir.join("marker"), b"decrypted P").unwrap();
                dir
            })
        };
        let id = profile();
        let dirs = leftovers(&id);
        crate::profile_delete(id).unwrap();
        assert!(dirs.iter().all(|d| !d.exists()), "deleted with the profile");

        let id = profile();
        w.bind(&id, [0xc5; 16], 1, [9; 32]);
        let dirs = leftovers(&id);
        crate::team::downgrade::unbind_profile(&id, SERVER, NOW).unwrap();
        assert!(dirs.iter().all(|d| !d.exists()), "discarded by the unbind");

        // A pending swap keeps the staged `P` and the data it replaces; the
        // `unpack` leftovers, which nothing resumes, still go.
        let id = profile();
        let dirs = leftovers(&id);
        w.db()
            .conn
            .execute(
                "INSERT INTO revert_swaps VALUES (?1, 3, zeroblob(32), 0)",
                [&id],
            )
            .unwrap();
        discard_revert_staging(&id, &root.join(&id)).unwrap();
        assert!(
            dirs[0].exists() && dirs[3].exists(),
            "the swap still needs them"
        );
        assert!(!dirs[1].exists() && !dirs[2].exists(), "never needed");
    }

    /// A profile removed for good (a trash purge, a delete with no trash)
    /// drops its binding as an unbind does; one in the trash, or restored
    /// from it, keeps it.
    #[test]
    fn a_profile_removed_for_good_drops_its_binding() {
        let w = world();
        let _lifecycle = crate::profile::lifecycle_test_guard();
        let profile = |remote: u8| {
            let mut s = crate::profile::StoredProfile::default();
            crate::profile::save_raw(&mut s).unwrap();
            w.bind(&s.meta.id, [remote; 16], 1, [9; 32]);
            s.meta.id
        };
        let tombstones = |id: &str| {
            w.db()
                .conn
                .query_row(
                    "SELECT count(*) FROM operations WHERE kind = 'UNBIND'
                       AND state = 'COMPLETED' AND local_profile_id_at_request = ?1",
                    [id],
                    |r| r.get::<_, i64>(0),
                )
                .unwrap()
        };
        let id = profile(0xc6);
        crate::profile_delete(id.clone()).unwrap();
        assert!(is_published(&id).unwrap(), "the trash keeps the binding");
        crate::trash::purge(&id).unwrap();
        assert!(!is_published(&id).unwrap(), "purged");
        assert_eq!(tombstones(&id), 1);

        let id = profile(0xc7);
        crate::profile_delete(id.clone()).unwrap();
        crate::trash::restore(&id).unwrap();
        crate::trash::purge(&id).unwrap();
        assert!(is_published(&id).unwrap(), "restored, so still bound");
        let record = crate::store::profiles_dir()
            .unwrap()
            .join(format!("{id}.json"));
        let body = std::fs::read(&record).unwrap();
        std::fs::write(&record, b"unreadable").unwrap();
        crate::trash::purge(&id).unwrap();
        assert!(
            is_published(&id).unwrap(),
            "an unreadable record still binds"
        );
        std::fs::write(&record, body).unwrap();

        crate::profile::delete(&id).unwrap();
        assert!(!is_published(&id).unwrap(), "deleted with no trash");
        assert_eq!(tombstones(&id), 1);

        // A refused purge keeps the archive; the expiry sweep goes on.
        let (kept, gone) = (profile(0xc8), profile(0xc9));
        for id in [&kept, &gone] {
            crate::profile_delete(id.clone()).unwrap();
            let meta = crate::store::trash_dir()
                .unwrap()
                .join(format!("{id}.json"));
            let mut e: crate::trash::TrashEntry =
                serde_json::from_slice(&std::fs::read(&meta).unwrap()).unwrap();
            e.expires_at = 0;
            if id == &kept {
                // Listed first, so emptying the trash meets the refusal first.
                e.deleted_at = u64::from(u32::MAX);
            }
            std::fs::write(&meta, serde_json::to_vec(&e).unwrap()).unwrap();
        }
        w.db()
            .conn
            .execute(
                "INSERT INTO restore_journals(local_profile_id, journal_id, phase, staged_path,
                   backup_path, old_binding_json, target_version, target_head_hash,
                   created_at, updated_at)
                 VALUES (?1, 'j', 'CREATED', 's', 'b', '{}', 1, zeroblob(32), 'now', 'now')",
                [&kept],
            )
            .unwrap();
        let err = crate::trash::purge(&kept).unwrap_err();
        assert!(has(&err, "downgrade.flowTaken"), "{err:#}");
        assert_eq!(crate::trash::purge_expired().unwrap(), 1);
        let left: Vec<_> = crate::trash::list()
            .unwrap()
            .into_iter()
            .map(|e| e.id)
            .collect();
        assert_eq!(left, [kept.as_str()]);
        assert!(is_published(&kept).unwrap() && !is_published(&gone).unwrap());

        // Emptying the trash goes past a refusal too, then reports it.
        let more = profile(0xcb);
        crate::profile_delete(more.clone()).unwrap();
        let err = crate::trash_empty().unwrap_err();
        assert!(
            crate::errcode::has_code(&err, "downgrade.flowTaken"),
            "{err}"
        );
        let left: Vec<_> = crate::trash::list()
            .unwrap()
            .into_iter()
            .map(|e| e.id)
            .collect();
        assert_eq!(left, [kept.as_str()]);
        assert!(!is_published(&more).unwrap());
    }

    /// A profile removed for good under a held lease with nothing pending
    /// (a crash after checkout) stores the release with no binding, and the
    /// next pull sends it; pending work refuses the removal, as it refuses
    /// an unbind, and leaves the binding whole.
    #[test]
    fn a_profile_removed_for_good_releases_its_lease_unless_work_is_pending() {
        {
            let w = world();
            let _lifecycle = crate::profile::lifecycle_test_guard();
            w.fake().skip.push("upload");
            w.push().unwrap_err();
            let err = crate::profile::delete(LOCAL).unwrap_err();
            assert!(has(&err, "sync.unbindPending"), "{err:#}");
            assert!(is_published(LOCAL).unwrap());
            assert_eq!(local_leases(&w), 1);
        }

        let w = world();
        let _lifecycle = crate::profile::lifecycle_test_guard();
        let crash = "CREATE TRIGGER crash BEFORE INSERT ON operations
             WHEN NEW.kind = 'UPLOAD' BEGIN SELECT RAISE(ABORT, 'crash'); END";
        w.db().conn.execute(crash, []).unwrap();
        w.push().unwrap_err();
        w.db().conn.execute("DROP TRIGGER crash", []).unwrap();
        assert_eq!(local_leases(&w), 1, "held with nothing pending");
        let sent = w.fake().log.len();
        crate::profile::delete(LOCAL).unwrap();
        assert_eq!(w.fake().log.len(), sent, "no server call");
        assert!(!is_published(LOCAL).unwrap());
        let release = "SELECT count(*) FROM operations WHERE kind = 'RELEASE'
             AND local_profile_id IS NULL AND local_profile_id_at_request = 'local-profile'
             AND state = ";
        assert_eq!(w.count(&format!("{release} 'PENDING'")), 1);
        assert!(w.fake().lease.is_some());
        let err = w.pull(&w._dir.path().join("pulled")).unwrap_err();
        assert!(has(&err, "sync.profileNotListed"), "{err:#}");
        assert!(w.fake().lease.is_none(), "the server released the lease");
        assert_eq!(w.count(&format!("{release} 'COMPLETED'")), 1);
    }

    /// Architect blocking 1: a revert lease held with nothing uploaded (a
    /// crash before seal, or a release whose reply was lost) while another
    /// device commits `R'` over the run. The next revert finds no run, so it
    /// releases the lease and keeps the quarantine; the next pull accepts
    /// `R'` and lifts it.
    #[test]
    fn a_revert_lease_whose_run_was_closed_elsewhere_is_released() {
        for case in ["crash before seal", "release lost"] {
            let w = world();
            let (heads, d, udd) = reverting(&w, DeviceRevocationReason::Retired);
            let crash = "CREATE TRIGGER crash BEFORE INSERT ON operations
                 WHEN NEW.kind = 'UPLOAD' BEGIN SELECT RAISE(ABORT, 'crash'); END";
            if case == "crash before seal" {
                w.db().conn.execute(crash, []).unwrap();
            } else {
                let mut f = w.fake();
                f.generation = Some(2);
                f.lose.push("release");
            }
            w.revert(&udd).unwrap_err();
            w.db()
                .conn
                .execute("DROP TRIGGER IF EXISTS crash", [])
                .unwrap();
            w.fake().generation = None;
            assert_eq!(
                w.count("SELECT count(*) FROM profile_bindings WHERE lease_id IS NOT NULL"),
                1,
                "{case}"
            );

            // Another device commits `R'` once the lease is free.
            let e = second(&w);
            w.pull(&e.path().join("pulled")).unwrap_err();
            let other = e.path().join("profile");
            std::fs::create_dir_all(&other).unwrap();
            assert_eq!(w.revert(&other).unwrap().version, 3);
            let r = r_on(&w, heads[1]);

            crate::store::set_config_root(Some(d.path().to_path_buf()));
            let err = w.revert(&udd).unwrap_err();
            assert!(has(&err, "sync.revertUnavailable"), "{case}: {err:#}");
            assert_eq!(
                w.count("SELECT count(*) FROM profile_bindings WHERE lease_id IS NOT NULL"),
                0,
                "{case}"
            );
            revoked_at(&w, 1);
            assert!(!beside(&udd, ".revert-staging").exists(), "{case}");
            w.pull(&d.path().join("out")).unwrap();
            available_at(&w, 3, r);
            assert_eq!(skipped(&w), [accepted_by(2, r, 1)], "{case}");
        }
    }

    /// Architect blocking 2: a pull whose `P` failed to restore left the pin
    /// below an accepted run (`J1` accepted by `R1`); the revert over the
    /// open `J2` audits `J1` as accepted by `R1`, and `J2` by its own `R`.
    #[test]
    fn a_revert_audits_the_accepted_runs_it_crosses() {
        let w = world();
        let heads = chain_of(&w, &[&w.me.sk, &author(), &w.me.sk, &author()]);
        let retired = Some(DeviceRevocationReason::Retired);
        serve(&w, &author_pages_for(&w, T0 + 300 * DAY, retired, false));
        let d = second(&w);
        w.fake().refuse.push(("3", 500));
        let err = w.pull(&d.path().join("out")).unwrap_err();
        assert!(!has(&err, "sync.signerRevoked"), "{err:#}");
        revoked_at(&w, 0);
        assert_eq!(skipped(&w), [(4, None, None, 3)]);
        let udd = d.path().join("profile");
        std::fs::create_dir_all(&udd).unwrap();
        assert_eq!(w.revert(&udd).unwrap().version, 5);
        let r = SignedSnapshotManifestV2::parse(&w.fake().manifests[&5])
            .unwrap()
            .head_hash();
        available_at(&w, 5, r);
        assert_eq!(
            skipped(&w),
            [accepted_by(2, heads[2], 1), accepted_by(4, r, 3)]
        );
        assert_eq!(marker(&udd), "v3");
    }

    /// Re-review blocking: a revert that fails after filing the accepted
    /// runs, retried, files each of them once.
    #[test]
    fn a_retried_revert_files_each_accepted_run_once() {
        let w = world();
        let heads = chain_of(&w, &[&w.me.sk, &author(), &w.me.sk, &author()]);
        let retired = Some(DeviceRevocationReason::Retired);
        serve(&w, &author_pages_for(&w, T0 + 300 * DAY, retired, false));
        let d = second(&w);
        w.fake().refuse.push(("3", 500));
        w.pull(&d.path().join("out")).unwrap_err();
        let udd = d.path().join("profile");
        std::fs::create_dir_all(&udd).unwrap();
        w.fake().refuse.push(("3", 500));
        w.revert(&udd).unwrap_err();
        assert_eq!(w.revert(&udd).unwrap().version, 5);
        let r = SignedSnapshotManifestV2::parse(&w.fake().manifests[&5])
            .unwrap()
            .head_hash();
        assert_eq!(
            skipped(&w),
            [accepted_by(2, heads[2], 1), accepted_by(4, r, 3)]
        );
    }

    /// Re-review non-blocking 1: a held revert lease with nothing uploaded
    /// whose walk finds a rollback is released; the binding keeps the
    /// rollback quarantine and can then be unbound.
    #[test]
    fn a_revert_lease_held_over_a_rollback_is_released() {
        let w = world();
        let (_, _d, udd) = reverting(&w, DeviceRevocationReason::Retired);
        let crash = "CREATE TRIGGER crash BEFORE INSERT ON operations
             WHEN NEW.kind = 'UPLOAD' BEGIN SELECT RAISE(ABORT, 'crash'); END";
        w.db().conn.execute(crash, []).unwrap();
        w.revert(&udd).unwrap_err();
        w.db().conn.execute("DROP TRIGGER crash", []).unwrap();
        w.fake().listed = Some((0, None));
        let err = w.revert(&udd).unwrap_err();
        assert!(has(&err, "sync.headRollback"), "{err:#}");
        assert_eq!(
            w.count("SELECT count(*) FROM profile_bindings WHERE lease_id IS NOT NULL"),
            0
        );
        let (state, reason, _, _, _) = w.state(LOCAL);
        assert_eq!(
            (state.as_str(), reason.as_deref()),
            ("QUARANTINED", Some("HEAD_ROLLBACK_DETECTED"))
        );
        unbind(LOCAL, SERVER, NOW).unwrap();
    }

    /// The SQL that records `A`'s key as distrusted, as another writer would.
    fn distrust_author() -> String {
        let (instance, tenant) = (hex(&INSTANCE), hex(&TENANT));
        format!(
            "INSERT INTO trust_proven_revocations
             SELECT '{instance}', '{tenant}', '{}', 'LOCAL_DISTRUST',
               coalesce(max(evaluation_id), 0), 0, NULL
             FROM trust_evaluations WHERE server_instance_id = '{instance}'
               AND tenant_id = '{tenant}'",
            hex(&key_id_of(&author()))
        )
    }

    /// Architect non-blocking 2: a revocation of the pin's signer recorded
    /// after an ordinary checkout (before its seal, or during its upload)
    /// releases the lease instead of committing on top of that pin.
    #[test]
    fn a_revocation_recorded_after_checkout_abandons_an_ordinary_push() {
        for during_upload in [false, true] {
            let w = world();
            let heads = chain_of(&w, &[&w.me.sk, &author()]);
            serve(&w, &author_pages(&w, T0 + 300 * DAY, false, false));
            let d = second(&w);
            pin_at(&w, &d, &heads, 2);
            if during_upload {
                w.fake().on_patch = Some(distrust_author());
            } else {
                w.fake().on_checkout = Some(distrust_author());
            }
            let uploads = w.sent("POST", "/uploads").len();
            let sent = w.sent("POST", "/commit").len();
            let err = w.push().unwrap_err();
            assert!(has(&err, "sync.signerRevoked"), "{during_upload}: {err:#}");
            assert_eq!(w.sent("POST", "/release").len(), 1, "{during_upload}");
            let uploaded = w.sent("POST", "/uploads").len() - uploads;
            assert_eq!(uploaded, usize::from(during_upload));
            assert_eq!(w.sent("POST", "/commit").len(), sent, "{during_upload}");
            assert_eq!(w.fake().commits, 2);
            assert_eq!(
                w.count("SELECT count(*) FROM profile_bindings WHERE lease_id IS NOT NULL"),
                0
            );
            revoked_at(&w, 2);
        }
    }

    /// An ordinary commit that landed, its reply lost, then a revocation of
    /// the pin's signer: the head is no longer the pin, so the stored request
    /// is replayed byte for byte and its exact receipt kept (G2-37, G2-38).
    #[test]
    fn a_landed_commit_whose_reply_was_lost_replays_after_its_pin_signer_is_revoked() {
        let w = world();
        let heads = chain_of(&w, &[&w.me.sk, &author()]);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, false, false));
        let d = second(&w);
        pin_at(&w, &d, &heads, 2);
        let completed =
            "SELECT count(*) FROM operations WHERE kind = 'COMMIT' AND state = 'COMPLETED'";
        let (sent, done) = (w.sent("POST", "/commit").len(), w.count(completed));
        w.fake().lose.push("commit");
        w.push().unwrap_err();
        assert_eq!(w.fake().version, 3, "committed, the reply lost");
        w.db().conn.execute(&distrust_author(), []).unwrap();
        assert_eq!(w.push().unwrap().version, 3);
        let replays = &w.sent("POST", "/commit")[sent..];
        assert_eq!(replays.len(), 2);
        assert_eq!(replays[0], replays[1]);
        assert_eq!(w.fake().commits, 3);
        assert_eq!(w.count(completed), done + 1);
        let request = CommitRequestV2::parse(&replays[0]).unwrap();
        let kept: i64 = w
            .db()
            .conn
            .query_row(
                "SELECT count(*) FROM upload_sessions WHERE state = 'COMMITTED'
                   AND exact_commit_receipt_binding_bytes = ?1",
                [&w.fake().stored[request.idempotency_key()].2],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(kept, 1);
        let (state, reason, _, v, _) = w.state(LOCAL);
        assert_eq!((state.as_str(), reason, v), ("AVAILABLE", None, 3));
    }

    /// Architect non-blocking 4: the launch-time settle reads nothing
    /// without a team database, and refuses with the ledger's own code when
    /// one exists that this binary cannot read.
    #[test]
    fn the_launch_settle_needs_a_team_database_only_when_one_exists() {
        let w = world();
        let udd = w.udd.clone();
        w.db()
            .conn
            .execute("UPDATE schema_meta SET schema_version = 99", [])
            .unwrap();
        let err = settle_revert_swap(LOCAL, &udd).unwrap_err();
        assert!(has(&err, "team.trustLedgerUnsupported"), "{err:#}");
        let fresh = tempfile::tempdir().unwrap();
        crate::store::set_config_root(Some(fresh.path().to_path_buf()));
        settle_revert_swap(LOCAL, &udd).unwrap();
        assert!(!Db::path().unwrap().exists());
    }

    /// v2.8.1 leftover: a team database whose existence cannot be checked is
    /// an error, never a device with no team database.
    #[cfg(unix)]
    #[test]
    fn an_unreadable_parent_is_an_error_not_an_absent_file() {
        let _w = world();
        let fresh = tempfile::tempdir().unwrap();
        crate::store::set_config_root(Some(fresh.path().to_path_buf()));
        // `team-sync` is a regular file: `stat` of the database below it
        // fails with ENOTDIR, which `exists()` reads as absent.
        std::fs::write(fresh.path().join("team-sync"), b"not a directory").unwrap();
        assert!(is_published(LOCAL).is_err());
        assert!(statuses(T0).is_err());
        let err = unbind_removed(LOCAL).unwrap_err();
        assert!(has(&err, "team.trustLedgerUnreadable"), "{err:#}");
    }

    #[test]
    fn a_normal_push_still_refuses_a_quarantined_binding() {
        for reason in ["SIGNER_REVOKED", "HEAD_ROLLBACK_DETECTED"] {
            let w = world();
            let (_, _d, _udd) = reverting(&w, DeviceRevocationReason::Retired);
            w.db()
                .conn
                .execute("UPDATE profile_bindings SET last_error_code = ?1", [reason])
                .unwrap();
            let sent = w.fake().log.len();
            let err = w.push().unwrap_err();
            assert!(has(&err, "sync.bindingQuarantined"), "{reason}: {err:#}");
            assert_eq!(w.fake().log.len(), sent, "{reason}");
        }
    }

    /// Owner decision 2026-11-02: a refusal below a withdrawn pin leaves the
    /// binding available, but an ordinary push still never commits on top of
    /// that pin: it quarantines and sends no request that writes.
    #[test]
    fn an_ordinary_push_refuses_over_a_pinned_head_whose_signer_is_proven_revoked() {
        let w = world();
        let heads = chain_of(&w, &[&w.me.sk, &author()]);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, false, false));
        let d = second(&w);
        pin_at(&w, &d, &heads, 2);
        let retired = Some(DeviceRevocationReason::Retired);
        serve(&w, &author_pages_for(&w, T0 + 300 * DAY, retired, false));
        forge(&w, &Ed25519SigningKey::from_bytes(&[0x33; 32]), |_| {});
        w.pull(&d.path().join("out")).unwrap_err();
        available_at(&w, 2, heads[1]);
        let checkouts = w.sent("POST", "/checkout").len();
        let err = w.push().unwrap_err();
        assert!(has(&err, "sync.signerRevoked"), "{err:#}");
        assert_eq!(w.sent("POST", "/checkout").len(), checkouts);
        assert_eq!(w.fake().commits, 2);
        revoked_at(&w, 2);
    }

    // ------------------------------------------ rotation edges (A2) ----

    /// The next request to `tag` is refused as the server refuses one made
    /// under a generation that is no longer ACTIVE (`v2_uploads.rs`,
    /// `v2_profiles.rs`).
    fn not_active(w: &World, tag: &'static str) {
        let mut f = w.fake();
        f.refused_body =
            Some(br#"{"error":"conflict","code":"FLEET_GENERATION_NOT_ACTIVE"}"#.to_vec());
        f.refuse.push((tag, 409));
    }

    /// The generation version `v`'s manifest names.
    fn sealed_under(w: &World, v: u64) -> u64 {
        let m = SignedSnapshotManifestV2::parse(&w.fake().manifests[&v]).unwrap();
        SnapshotManifestV2::parse(m.canonical_manifest_payload_bytes())
            .unwrap()
            .key_generation
    }

    /// A publish stored under N and refused once N+1 is ACTIVE names the
    /// rotation, not a raw 409. It is failed, so nothing is left to cancel,
    /// and the next publish seals under the collected N+1.
    #[test]
    fn a_publish_refused_as_generation_not_active_reads_fleet_key_rotated() {
        let w = world_unbound();
        not_active(&w, "publish");
        let err = w.publish().unwrap_err();
        assert!(has(&err, "sync.fleetKeyRotated"), "{err:#}");
        assert!(!has(&err, "fleet.refusedSync"), "{err:#}");
        assert_eq!(
            w.count("SELECT count(*) FROM operations WHERE kind = 'PUBLISH' AND state = 'FAILED'"),
            1
        );
        let none = cancel_publish(LOCAL).unwrap_err();
        assert!(has(&none, "sync.noPublishPending"), "{none:#}");
        rotate(&w);
        w.publish().unwrap();
        let named = |body: &[u8]| {
            let r = IdempotentMutationRequestV2::parse(body).unwrap();
            ProfilePublishCreateV2::parse(&r.canonical_payload_bytes)
                .unwrap()
                .key_generation
        };
        let sent = w.sent("POST", "/profiles");
        assert_eq!((named(&sent[0]), named(&sent[1])), (GEN, GEN + 1));
    }

    /// An upload or commit under N refused once N+1 is ACTIVE releases its
    /// lease and names the rotation; after Collect the next push seals
    /// under N+1.
    #[test]
    fn an_upload_refused_as_generation_not_active_releases_its_lease_and_the_next_push_seals_under_the_new_generation(
    ) {
        for tag in ["upload", "commit"] {
            let w = world();
            not_active(&w, tag);
            let err = w.push().unwrap_err();
            assert!(has(&err, "sync.fleetKeyRotated"), "{tag}: {err:#}");
            assert_eq!(w.sent("POST", "/release").len(), 1, "{tag}");
            for sql in [
                "SELECT count(*) FROM operations WHERE state = 'PENDING'",
                "SELECT count(*) FROM upload_sessions WHERE state IN ('OPEN', 'READY')",
                "SELECT count(*) FROM profile_bindings WHERE lease_id IS NOT NULL",
            ] {
                assert_eq!(w.count(sql), 0, "{tag}: {sql}");
            }
            rotate(&w);
            assert_eq!(w.push().unwrap().version, 1, "{tag}");
            assert_eq!(sealed_under(&w, 1), GEN + 1, "{tag}");
        }
    }

    /// A revert lease taken under N whose upload is refused once N+1 is
    /// ACTIVE is released, the binding stays quarantined, and the next
    /// revert, after Collect, seals `R` under N+1.
    #[test]
    fn a_revert_lease_of_the_retired_generation_is_abandoned_and_the_next_revert_seals_under_the_new_one(
    ) {
        let w = world();
        let (heads, _d, udd) = reverting(&w, DeviceRevocationReason::Retired);
        let released = w.sent("POST", "/release").len();
        not_active(&w, "upload");
        let err = w.revert(&udd).unwrap_err();
        assert!(has(&err, "sync.fleetKeyRotated"), "{err:#}");
        assert_eq!(w.sent("POST", "/release").len(), released + 1);
        assert_eq!(
            w.count("SELECT count(*) FROM profile_bindings WHERE lease_id IS NOT NULL"),
            0
        );
        assert_eq!(w.state(LOCAL).1.as_deref(), Some("SIGNER_REVOKED"));
        rotate(&w);
        assert_eq!(w.revert(&udd).unwrap().version, 3);
        r_on(&w, heads[1]);
        assert_eq!(sealed_under(&w, 3), GEN + 1);
    }

    // ---------------------------------------------------------- statuses ----

    /// `LOCAL`'s status, the only binding `_w` has.
    fn status(_w: &World) -> ProfileStatus {
        let mut s = statuses(NOW).unwrap().profiles;
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].profile_id, LOCAL);
        s.remove(0)
    }

    #[test]
    fn statuses_map_each_binding_state() {
        {
            let _w = world_unbound();
            assert!(statuses(NOW).unwrap().profiles.is_empty(), "local");
        }
        let (future, past) = ("'2099-01-01T00:00:00.000Z'", "'2000-01-01T00:00:00.000Z'");
        for (state, expires, dirty, reason, at_risk) in [
            ("AVAILABLE", None, false, None, false),
            ("CHECKED_OUT", Some(future), true, None, false),
            ("CHECKED_OUT", Some(past), true, None, true),
            ("LEASE_AT_RISK", Some(future), true, None, true),
            ("UPLOADING", Some(future), true, None, false),
            (
                "QUARANTINED",
                None,
                false,
                Some("HEAD_ROLLBACK_DETECTED"),
                false,
            ),
        ] {
            let w = world();
            let lease = match expires {
                Some(at) => format!("lease_id = 'x', fencing_token = 1, lease_expires_at = {at}"),
                None => "lease_id = NULL, fencing_token = NULL, lease_expires_at = NULL".into(),
            };
            w.db()
                .conn
                .execute(
                    &format!(
                        "UPDATE profile_bindings SET {lease}, sync_state = ?1, dirty = ?2,
                           last_error_code = ?3"
                    ),
                    params![state, dirty, reason],
                )
                .unwrap();
            let s = status(&w);
            let case = format!("{state} {expires:?}");
            assert_eq!(s.sync_state, state, "{case}");
            assert_eq!(s.remote_version, 0, "{case}");
            assert_eq!(s.dirty, dirty, "{case}");
            assert_eq!(
                s.lease_expires_at.as_deref(),
                expires.map(|e| e.trim_matches('\'')),
                "{case}"
            );
            assert_eq!(s.last_error_code.as_deref(), reason, "{case}");
            assert_eq!(s.lease_at_risk, at_risk, "{case}");
            assert!(!s.revert_available && !s.revert_in_progress, "{case}");
        }
    }

    #[test]
    fn statuses_offer_revert_for_any_unresolved_proven_run() {
        // A run above the pin.
        let w = world();
        let (_, d, _) = reverting(&w, DeviceRevocationReason::Retired);
        assert_eq!(skipped(&w), [(2, None, None, 1)]);
        let s = status(&w);
        assert_eq!(
            (s.sync_state.as_str(), s.last_error_code.as_deref()),
            ("QUARANTINED", Some("SIGNER_REVOKED"))
        );
        assert!(s.revert_available && !s.revert_in_progress, "above the pin");

        // The same run once superseded is no longer offered.
        w.db()
            .conn
            .execute(
                "UPDATE skipped_heads SET resolution = 'SUPERSEDED', resolved_at_ms = ?1",
                [NOW as i64],
            )
            .unwrap();
        assert!(!status(&w).revert_available, "superseded");
        drop((d, w));

        // A run pinned before its signer was proven revoked: rows at the pin.
        let w = world();
        let heads = chain_of(&w, &[&w.me.sk, &author()]);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, false, false));
        let d = second(&w);
        pin_at(&w, &d, &heads, 2);
        let retired = Some(DeviceRevocationReason::Retired);
        serve(&w, &author_pages_for(&w, T0 + 300 * DAY, retired, false));
        w.pull(&d.path().join("out")).unwrap_err();
        revoked_at(&w, 2);
        assert_eq!(skipped(&w), [(2, None, None, 1)]);
        assert!(status(&w).revert_available, "at the pin");
        drop((d, w));

        // A reported-only quarantine: no rows, no offer.
        let w = world();
        chain_of(&w, &[&w.me.sk, &author(), &w.me.sk]);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, false, true));
        let d = second(&w);
        w.pull(&d.path().join("out")).unwrap_err();
        revoked_at(&w, 0);
        assert!(skipped(&w).is_empty());
        assert!(!status(&w).revert_available, "reported only");
    }

    #[test]
    fn statuses_flag_a_revert_in_progress() {
        // Checked out above the pin.
        let w = world();
        let (_, d, udd) = reverting(&w, DeviceRevocationReason::Retired);
        w.fake().skip.push("upload");
        w.revert(&udd).unwrap_err();
        let s = status(&w);
        assert!(s.lease_expires_at.is_some(), "held");
        assert!(s.revert_in_progress && s.revert_available, "above the pin");
        drop((d, w));

        // Checked out with its base equal to the pinned `remote_version`.
        let w = world();
        let heads = chain_of(&w, &[&w.me.sk, &author()]);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, false, false));
        let d = second(&w);
        pin_at(&w, &d, &heads, 2);
        let retired = Some(DeviceRevocationReason::Retired);
        serve(&w, &author_pages_for(&w, T0 + 300 * DAY, retired, false));
        let udd = d.path().join("profile");
        std::fs::create_dir_all(&udd).unwrap();
        w.fake().skip.push("upload");
        w.revert(&udd).unwrap_err();
        let s = status(&w);
        assert_eq!(s.remote_version, 2);
        assert!(s.lease_expires_at.is_some(), "held");
        assert!(s.revert_in_progress, "base at the pin");
        drop((d, w));

        // An ordinary held lease is not a revert.
        let w = world();
        w.fake().skip.push("upload");
        w.push().unwrap_err();
        let s = status(&w);
        assert!(s.lease_expires_at.is_some(), "held");
        assert!(!s.revert_in_progress, "ordinary");
    }

    #[test]
    fn statuses_report_renewed_after_revocation_alerts() {
        let w = world();
        assert!(statuses(NOW).unwrap().alerts.is_empty(), "none");
        let raise = |key: &str, at: u64| {
            w.db()
                .conn
                .execute(
                    "INSERT INTO trust_custodian_alerts
                     SELECT server_instance_id, tenant_id, 'custodian.renewed_after_revocation',
                       ?1, ?2, ?3 FROM trust_anchors",
                    params![key, "ab".repeat(32), at as i64],
                )
                .unwrap();
        };
        raise(&"70".repeat(32), NOW);
        let alerts = statuses(NOW).unwrap().alerts;
        assert_eq!(alerts.len(), 1);
        assert_eq!(
            (
                alerts[0].kind.as_str(),
                alerts[0].signing_key_id.as_str(),
                alerts[0].raised_at_ms
            ),
            (
                "custodian.renewed_after_revocation",
                "70".repeat(32).as_str(),
                NOW as i64
            )
        );
        raise(&"71".repeat(32), NOW + 1);
        let keys: Vec<_> = statuses(NOW)
            .unwrap()
            .alerts
            .into_iter()
            .map(|a| a.signing_key_id)
            .collect();
        assert_eq!(keys, ["71".repeat(32), "70".repeat(32)], "newest first");
    }

    #[test]
    fn statuses_without_a_database_are_empty_and_create_nothing() {
        let _lock = crate::store::config_root_test_lock()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().unwrap();
        crate::store::set_config_root(Some(dir.path().to_path_buf()));
        let s = statuses(NOW);
        crate::store::set_config_root(None);
        let s = s.unwrap();
        assert!(s.profiles.is_empty() && s.alerts.is_empty());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    impl World {
        fn join(&self, local: &str, profile: [u8; 16], udd: &Path) -> Result<u64> {
            self.rt.block_on(join(
                &self.client,
                "t",
                &self.dev,
                local,
                FLEET,
                profile,
                udd,
                NOW,
            ))
        }

        /// The fleet listing as (profile, version, label, bound to).
        fn labels(&self) -> Vec<(String, u64, Option<String>, Option<String>)> {
            self.rt
                .block_on(labels(&self.client, "t", &self.dev, FLEET, NOW))
                .unwrap()
                .into_iter()
                .map(|p| (p.remote_profile_id, p.current_version, p.label, p.bound_to))
                .collect()
        }
    }

    /// `PROFILE` published and pushed at v1 here; then a second device,
    /// enrolled with no binding, is the config root.
    fn joinable() -> (World, tempfile::TempDir) {
        let w = world_unbound();
        w.publish().unwrap();
        w.push().unwrap();
        let d = second(&w);
        (w, d)
    }

    fn noise(udd: &Path) -> Vec<u8> {
        std::fs::read(udd.join("Default").join("noise.bin")).unwrap()
    }

    #[test]
    fn join_lists_fleet_profiles_with_their_opened_labels_and_marks_bound_ones() {
        let w = world_unbound();
        w.publish().unwrap();
        let sealed = |profile: [u8; 16], generation| {
            shardx_core::keys::seal_label(
                &FKEK,
                &random().unwrap(),
                &TENANT,
                &FLEET,
                &profile,
                generation,
                b"Shop",
            )
            .unwrap()
        };
        w.fake().others = vec![
            FleetProfileHeadV2 {
                label_ciphertext: sealed(PROFILE2, GEN),
                ..other(PROFILE2, 2, [9; 32])
            },
            // Not a label any key opens, and one of a generation not held here.
            other(PROFILE3, 1, [8; 32]),
            FleetProfileHeadV2 {
                key_generation: GEN + 1,
                label_ciphertext: sealed([0xc4; 16], GEN + 1),
                ..other([0xc4; 16], 1, [7; 32])
            },
        ];
        let posts = w.sent("POST", "").len();
        let row = |p: [u8; 16], v, label: Option<&str>, to: Option<&str>| {
            (
                hex(&p),
                v,
                label.map(str::to_string),
                to.map(str::to_string),
            )
        };
        assert_eq!(
            w.labels(),
            [
                row(PROFILE, 0, Some("Work profile"), Some(LOCAL)),
                row(PROFILE2, 2, Some("Shop"), None),
                row(PROFILE3, 1, None, None),
                row([0xc4; 16], 1, None, None),
            ]
        );
        let _d = second(&w);
        assert_eq!(
            w.labels()[0],
            row(PROFILE, 0, Some("Work profile"), None),
            "bound on the first device only"
        );
        assert_eq!(w.sent("POST", "").len(), posts, "nothing was written");
        assert_eq!(w.count("SELECT count(*) FROM profile_bindings"), 0);
    }

    #[test]
    fn join_binds_and_pulls_a_remote_profile_on_a_new_device() {
        let (w, d) = joinable();
        let out = d.path().join("joined");
        assert!(w.join(LOCAL, PROFILE, &out).unwrap() > 0);
        assert_eq!(noise(&out), noise(&w.udd));
        let head = w.fake().head.unwrap();
        available_at(&w, 1, head);
        assert_eq!(
            w.count(
                "SELECT count(*) FROM profile_bindings WHERE accepted_restore_epoch = 0
                   AND lease_id IS NULL AND dirty = 0"
            ),
            1
        );
    }

    /// `PROFILE` pushed at v1 and v2 here, restored to v1 (epoch 1) with
    /// its transition filed; `old` is v2's manifest. Then `post` commits at
    /// epoch 1 from here, and a second device is the root. The leaf's head.
    fn joinable_after_restore(post: u64) -> (World, tempfile::TempDir, [u8; 32], Vec<u8>) {
        let w = world_unbound();
        w.publish().unwrap();
        w.push().unwrap();
        w.push().unwrap();
        let (h1, h2) = (w.head_of(1), w.head_of(2));
        let old = w.fake().manifests[&2].clone();
        w.fake().restore(1);
        let leaves = [
            leaf(PROFILE, h2, h1),
            leaf([0xc4; 16], [7; 32], [8; 32]),
            leaf([0xc5; 16], [9; 32], [10; 32]),
        ];
        let t = transition(&w.me, 0, &leaves);
        w.file(&w.me.sk, &t, &leaves, &[PROFILE], 0);
        if post > 0 {
            w.pull(&w.udd.with_file_name("accepted")).unwrap();
            for _ in 0..post {
                w.fake().log.clear();
                w.push().unwrap();
            }
        }
        w.fake().log.clear();
        let d = second(&w);
        (w, d, h1, old)
    }

    /// ADR 0002 rule 6: a device that joins after a restore, before any
    /// commit at the new epoch, pins the transition's leaf at its older epoch.
    #[test]
    fn join_after_a_restore_pins_the_transition_leaf_then_pulls() {
        let (w, d, h1, _) = joinable_after_restore(0);
        let out = d.path().join("joined");
        assert!(w.join(LOCAL, PROFILE, &out).unwrap() > 0);
        assert_eq!(noise(&out), noise(&w.udd));
        assert_eq!(
            w.state(LOCAL),
            ("AVAILABLE".into(), None, 1, 1, Some(h1.to_vec()))
        );
        assert_eq!(w.filed(), 2, "the transition and this profile's proof");
    }

    /// A joining device has no pin to search below: it follows the chain
    /// back from the listed head to the leaf, however many commits followed
    /// the restore, then pulls to the head.
    #[test]
    fn join_after_more_post_restore_commits_than_the_leaf_search_pins_the_leaf() {
        let post = LEAF_SEARCH + 1;
        let (w, d, _, _) = joinable_after_restore(post);
        let out = d.path().join("joined");
        assert!(w.join(LOCAL, PROFILE, &out).unwrap() > 0, "joined");
        assert_eq!(noise(&out), noise(&w.udd));
        let head = w.head_of(1 + post);
        available_at(&w, (1 + post) as i64, head);
        assert_eq!(w.state(LOCAL).2, 1, "the new epoch");
    }

    /// The rolled-back child of the leaf (ADR 0002 rule 6, "Head epoch"):
    /// v2 at the old epoch, chained onto the leaf, listed as the head.
    #[test]
    fn join_refuses_the_rolled_back_child_of_the_leaf() {
        let (w, d, _, old) = joinable_after_restore(0);
        let m_old = SignedSnapshotManifestV2::parse(&old).unwrap().head_hash();
        {
            let mut f = w.fake();
            f.manifests.insert(2, old);
            f.listed = Some((2, Some(m_old)));
        }
        let out = d.path().join("joined");
        let err = w.join(LOCAL, PROFILE, &out).unwrap_err();
        assert!(has(&err, "sync.headRollback"), "{err:#}");
        assert_eq!(
            w.state(LOCAL),
            (
                "QUARANTINED".into(),
                Some("HEAD_ROLLBACK_DETECTED".into()),
                0,
                0,
                None
            )
        );
        assert!(!out.exists());
    }

    /// A profile first committed after the restore starts at the server's
    /// epoch: no transition is asked for.
    #[test]
    fn join_of_a_profile_created_after_a_restore_starts_at_that_epoch() {
        let w = world_unbound();
        w.fake().epoch = 1;
        w.publish().unwrap();
        w.push().unwrap();
        let d = second(&w);
        let out = d.path().join("joined");
        assert!(w.join(LOCAL, PROFILE, &out).unwrap() > 0);
        let head = w.head_of(1);
        assert_eq!(
            w.state(LOCAL),
            ("AVAILABLE".into(), None, 1, 1, Some(head.to_vec()))
        );
        assert_eq!(w.filed(), 0);
        assert!(!w
            .fake()
            .log
            .iter()
            .any(|(m, _)| m.contains("restore-epoch-transitions")));
    }

    /// v1 served with another `restore_epoch`, re-signed by a key the
    /// evidence does not hold: the server cannot sign such a lie.
    fn lying_first(w: &World, epoch: u64) {
        let mut f = w.fake();
        let m = SignedSnapshotManifestV2::parse(&f.manifests[&1]).unwrap();
        let mut p = SnapshotManifestV2::parse(m.canonical_manifest_payload_bytes()).unwrap();
        p.restore_epoch = epoch;
        p.signer_signing_key_id = key_id_of(&author());
        let lie = SignedSnapshotManifestV2::sign(&author(), &p).unwrap();
        f.manifests.insert(1, lie.exact_bytes().to_vec());
    }

    /// The start epoch is read from v1 unverified; a lie either way ends in
    /// a refusal or a quarantine, with nothing pinned or restored.
    #[test]
    fn join_with_a_lying_first_snapshot_pins_nothing() {
        // Older than it is: the transition it asks for does not exist.
        let w = world_unbound();
        w.fake().epoch = 1;
        w.publish().unwrap();
        w.push().unwrap();
        lying_first(&w, 0);
        let d = second(&w);
        let out = d.path().join("joined");
        let err = w.join(LOCAL, PROFILE, &out).unwrap_err();
        assert!(has(&err, "sync.epochTransitionMissing"), "{err:#}");
        assert_eq!(
            w.state(LOCAL),
            (
                "QUARANTINED".into(),
                Some(TRANSITION_REQUIRED.into()),
                0,
                0,
                None
            )
        );
        assert!(!out.exists());
        drop((d, w));

        // Newer than it is: the pull refuses v1 itself.
        let (w, d, _, _) = joinable_after_restore(0);
        lying_first(&w, 1);
        let out = d.path().join("joined");
        let err = w.join(LOCAL, PROFILE, &out).unwrap_err();
        assert!(has(&err, "sync.signerUntrusted"), "{err:#}");
        let (_, _, epoch, version, head) = w.state(LOCAL);
        assert_eq!((epoch, version, head), (1, 0, None));
        assert!(!out.exists());
    }

    #[test]
    fn join_refuses_a_local_profile_with_an_unfinished_publish() {
        let w = world_unbound();
        w.fake().skip.push("publish");
        w.publish().unwrap_err();
        assert_eq!(
            w.count("SELECT count(*) FROM operations WHERE kind = 'PUBLISH' AND state = 'PENDING'"),
            1
        );
        let before = w.fake().log.len();
        let err = w
            .join(LOCAL, PROFILE, &w.udd.with_file_name("out"))
            .unwrap_err();
        assert!(has(&err, "sync.alreadyPublished"), "{err:#}");
        assert_eq!(w.count("SELECT count(*) FROM profile_bindings"), 0);
        assert_eq!(w.fake().log.len(), before);
    }

    /// Another join binds the same remote profile while this one waits on
    /// the server: the answer is still the localized one.
    #[test]
    fn join_refuses_a_remote_profile_bound_here_meanwhile() {
        let (w, d) = joinable();
        w.fake().on_list = Some(format!(
            "INSERT INTO profile_bindings(local_profile_id, server_id, server_instance_id,
               tenant_id, account_id, device_id, fleet_id, remote_profile_id, remote_version,
               base_version, accepted_restore_epoch, fkek_key_id, key_generation, sync_state,
               dirty)
             SELECT 'racer', k.server_id, k.server_instance_id, k.tenant_id, d.account_id,
               k.device_id, k.fleet_id, '{}', 0, 0, 0, k.fkek_key_id, k.generation,
               'AVAILABLE', 0
             FROM fleet_key_state k
             JOIN device_state d USING (server_id, tenant_id, device_id)
             WHERE k.state = 'ACTIVE'",
            hex(&PROFILE)
        ));
        let out = d.path().join("joined");
        let err = w.join(LOCAL, PROFILE, &out).unwrap_err();
        assert!(w.fake().on_list.is_none(), "it ran");
        assert!(has(&err, "sync.remoteAlreadyBound"), "{err:#}");
        assert!(!format!("{err:#}").contains("UNIQUE"), "{err:#}");
        assert_eq!(
            w.count("SELECT count(*) FROM profile_bindings WHERE local_profile_id = 'racer'"),
            1
        );
        assert_eq!(w.count("SELECT count(*) FROM profile_bindings"), 1);
        assert!(!out.exists());
    }

    #[test]
    fn join_refuses_a_bound_or_running_local_profile() {
        let w = world();
        let before = (w.state(LOCAL), w.fake().log.len());
        let err = w
            .join(LOCAL, PROFILE2, &w.udd.with_file_name("out"))
            .unwrap_err();
        assert!(has(&err, "sync.alreadyPublished"), "{err:#}");
        assert_eq!((w.state(LOCAL), w.fake().log.len()), before);
        assert_eq!(w.count("SELECT count(*) FROM profile_bindings"), 1);
        // `team_join_profile` takes this claim before anything else.
        let _running = crate::profile::begin_profile_launch("join-running").unwrap();
        let err = crate::profile::begin_user_mutation(["join-running"], "join").unwrap_err();
        assert!(has(&err, "profile.busyOne"), "{err:#}");
    }

    #[test]
    fn join_refuses_without_the_collected_fleet_key_and_creates_no_binding() {
        let (w, d) = joinable();
        w.db()
            .conn
            .execute_batch("PRAGMA foreign_keys = OFF; DELETE FROM fleet_key_state")
            .unwrap();
        let before = w.fake().log.len();
        let out = d.path().join("joined");
        let err = w.join(LOCAL, PROFILE, &out).unwrap_err();
        assert!(has(&err, "sync.fleetKeyRecollect"), "{err:#}");
        assert_eq!(w.count("SELECT count(*) FROM profile_bindings"), 0);
        assert_eq!(
            w.fake().log.len(),
            before,
            "nothing was asked of the server"
        );
        assert!(!out.exists());
    }

    /// A join whose first pull did not restore the team's data leaves a
    /// binding no push may seal from: after a lost transition fetch (the
    /// push accepts the transition and pins the leaf itself), or after a
    /// restore that failed once the leaf was pinned. A pull restores it, and
    /// pushes go on from there.
    #[test]
    fn join_then_a_push_before_the_first_pull_restores_is_refused() {
        for case in ["transition lost", "restore failed"] {
            let (w, d, h1, _) = joinable_after_restore(0);
            let good = w.fake().objects[&1].clone();
            if case == "transition lost" {
                w.fake().skip.push("1");
            } else {
                *w.fake().objects.get_mut(&1).unwrap().last_mut().unwrap() ^= 1;
            }
            let out = d.path().join("joined");
            w.join(LOCAL, PROFILE, &out).unwrap_err();
            w.fake().objects.insert(1, good);
            let mine = d.path().join("mine");
            std::fs::create_dir_all(mine.join("Default")).unwrap();
            std::fs::write(mine.join("Default").join("noise.bin"), b"never pulled").unwrap();
            let err = w.push_from(&mine).unwrap_err();
            assert!(has(&err, "sync.remoteAhead"), "{case}: {err:#}");
            assert_eq!(w.fake().version, 1, "{case}: nothing committed");
            assert!(w.sent("POST", "/checkout").is_empty(), "{case}");
            assert!(w.pull_of(LOCAL, &out).unwrap() > 0, "{case}");
            assert_eq!(noise(&out), noise(&w.udd), "{case}");
            available_at(&w, 1, h1);
            assert_eq!(w.push_from(&out).unwrap().version, 2, "{case}");
        }
    }

    /// Joined while the profile was at version 0, a push whose checkout was
    /// lost, then commits elsewhere and a restore: the replay pins the leaf
    /// and its lease is released, the push stops for a pull, and the pull
    /// and every later push go through. Nothing is left pending.
    #[test]
    fn join_then_a_lost_checkout_and_a_restore_still_pulls_and_pushes() {
        let w = world_unbound();
        w.publish().unwrap();
        let d = second(&w);
        let out = d.path().join("joined");
        w.join(LOCAL, PROFILE, &out).unwrap_err();
        let mine = d.path().join("mine");
        std::fs::create_dir_all(mine.join("Default")).unwrap();
        std::fs::write(mine.join("Default").join("noise.bin"), b"never pulled").unwrap();
        w.fake().skip.push("checkout");
        w.push_from(&mine).unwrap_err();
        let pending = "SELECT count(*) FROM operations WHERE state = 'PENDING'";
        assert_eq!(w.count(pending), 1, "the stored checkout");
        // The first device commits v1 and v2; the owner restores v1.
        crate::store::set_config_root(Some(w._dir.path().to_path_buf()));
        w.push().unwrap();
        w.push().unwrap();
        let (h1, h2) = (w.head_of(1), w.head_of(2));
        w.fake().restore(1);
        let leaves = [
            leaf(PROFILE, h2, h1),
            leaf([0xc4; 16], [7; 32], [8; 32]),
            leaf([0xc5; 16], [9; 32], [10; 32]),
        ];
        let t = transition(&w.me, 0, &leaves);
        w.file(&w.me.sk, &t, &leaves, &[PROFILE], 0);
        crate::store::set_config_root(Some(d.path().to_path_buf()));

        // The stored checkout, never processed, meets the new epoch: the
        // server refuses it for good, so it closes with no lease granted.
        let err = w.push_from(&mine).unwrap_err();
        assert!(has(&err, "fleet.refusedSync"), "{err:#}");
        assert_eq!(w.count(pending), 0);
        assert_eq!(
            w.count("SELECT count(*) FROM operations WHERE kind = 'CHECKOUT' AND state = 'FAILED'"),
            1
        );
        let (state, _, epoch, version, head) = w.state(LOCAL);
        assert_eq!(
            (state.as_str(), epoch, version, head),
            ("AVAILABLE", 1, 1, Some(h1.to_vec())),
            "the leaf pinned, its data not pulled"
        );
        let err = w.push_from(&mine).unwrap_err();
        assert!(has(&err, "sync.remoteAhead"), "{err:#}");
        assert_eq!(w.fake().version, 1, "nothing committed");
        assert!(w.fake().lease.is_none());
        assert_eq!(
            w.count("SELECT count(*) FROM profile_bindings WHERE lease_id IS NULL"),
            1
        );
        assert_eq!(w.count(pending), 0);
        assert!(w.pull_of(LOCAL, &out).unwrap() > 0);
        assert_eq!(noise(&out), noise(&w.udd));
        available_at(&w, 1, h1);
        assert_eq!(w.count(pending), 0);
        assert_eq!(w.push_from(&out).unwrap().version, 2);
    }

    #[test]
    fn join_refuses_a_remote_profile_already_bound_here() {
        let w = world();
        let before = (w.state(LOCAL), w.fake().log.len());
        let err = w
            .join("another-local", PROFILE, &w.udd.with_file_name("out"))
            .unwrap_err();
        assert!(has(&err, "sync.remoteAlreadyBound"), "{err:#}");
        assert!(!format!("{err:#}").contains("UNIQUE"), "{err:#}");
        assert_eq!((w.state(LOCAL), w.fake().log.len()), before);
        assert_eq!(w.count("SELECT count(*) FROM profile_bindings"), 1);
        for lang in ["en", "vi"] {
            let path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../src/shared/i18n/locales")
                .join(format!("{lang}.json"));
            let dict: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
            assert!(
                dict["sync.remoteAlreadyBound"]
                    .as_str()
                    .is_some_and(|s| !s.is_empty()),
                "{lang}"
            );
        }
    }

    /// Two machines through the one server: the second joins and checks in a
    /// change, and the first pulls it.
    #[test]
    fn join_then_check_in_then_pull_on_the_first_device() {
        let (w, d) = joinable();
        let out = d.path().join("joined");
        w.join(LOCAL, PROFILE, &out).unwrap();
        std::fs::write(out.join("Default").join("joined.txt"), b"second device").unwrap();
        assert_eq!(w.push_from(&out).unwrap().version, 2);
        crate::store::set_config_root(Some(w._dir.path().to_path_buf()));
        assert!(w.pull(&w.udd).unwrap() > 0);
        assert_eq!(
            std::fs::read(w.udd.join("Default").join("joined.txt")).unwrap(),
            b"second device"
        );
        let head = w.head_of(2);
        available_at(&w, 2, head);
    }

    // Rule 6 regressions found by independent verification (round 1).
    #[test]
    fn join_never_pins_a_leaf_whose_signer_its_own_evidence_revokes() {
        let (w, d, _, old) = joinable_after_restore(0);
        let revoked_leaf = forge(&w, &author(), |_| {});
        let previous = SignedSnapshotManifestV2::parse(&old).unwrap().head_hash();
        let leaves = [leaf(PROFILE, previous, revoked_leaf)];
        w.file(
            &w.me.sk,
            &transition(&w.me, 0, &leaves),
            &leaves,
            &[PROFILE],
            0,
        );
        w.fake().head = Some(revoked_leaf);
        serve(
            &w,
            &author_pages_for(
                &w,
                T0 + 300 * DAY,
                Some(DeviceRevocationReason::Retired),
                false,
            ),
        );
        assert!(!ledger::withdrawn(&w.db(), &w.dev.pin.0, &key_id_of(&author())).unwrap());
        w.join(LOCAL, PROFILE, &d.path().join("joined"))
            .unwrap_err();
        assert!(ledger::withdrawn(&w.db(), &w.dev.pin.0, &key_id_of(&author())).unwrap());
        assert_eq!(
            w.state(LOCAL).3,
            0,
            "a newly counted revoked leaf must never be pinned"
        );
    }

    #[test]
    fn a_replayed_revert_never_pins_an_r_whose_signer_is_now_revoked() {
        let w = world();
        let (_, _d, udd) = reverting(&w, DeviceRevocationReason::Retired);
        w.fake().lose.push("commit");
        w.revert(&udd).unwrap_err();
        assert_eq!(w.fake().version, 3);
        assert_eq!(w.state(LOCAL).3, 1, "R not yet locally accepted");
        ledger::distrust_key(&w.db(), &w.dev.pin.0, &w.me.to.signing_key_id, NOW).unwrap();
        assert!(ledger::withdrawn(&w.db(), &w.dev.pin.0, &w.me.to.signing_key_id).unwrap());
        let _replayed = w.revert(&udd);
        let (state, reason, _, version, _) = w.state(LOCAL);
        assert_eq!(
            (state.as_str(), reason.as_deref(), version, marker(&udd)),
            ("QUARANTINED", Some("SIGNER_REVOKED"), 1, "local".into()),
            "replay must not accept a proven-revoked R or lift quarantine"
        );
    }

    fn fail_the_pin_write(w: &World) {
        w.db()
            .conn
            .execute_batch(
                "CREATE TRIGGER pin_failure BEFORE UPDATE OF base_version ON profile_bindings
             WHEN NEW.base_version > OLD.base_version
             BEGIN SELECT RAISE(ABORT, 'injected pin write failure'); END;",
            )
            .unwrap();
    }

    #[test]
    fn a_pull_whose_pin_fails_keeps_the_local_profile() {
        let w = world();
        chain_of(&w, &[&w.me.sk]);
        let d = second(&w);
        let out = d.path().join("profile");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("marker"), b"local").unwrap();
        fail_the_pin_write(&w);
        let err = w.pull(&out).unwrap_err();
        assert!(format!("{err:#}").contains("injected pin write failure"));
        assert_eq!(w.state(LOCAL).3, 0);
        assert_eq!(
            marker(&out),
            "local",
            "a refused pull must preserve local data"
        );
    }

    #[test]
    fn a_join_whose_pin_fails_keeps_the_local_profile() {
        let (w, d, _, _) = joinable_after_restore(0);
        let out = d.path().join("profile");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("local-only"), b"unsynced local edit").unwrap();
        fail_the_pin_write(&w);
        let err = w.join(LOCAL, PROFILE, &out).unwrap_err();
        assert!(format!("{err:#}").contains("injected pin write failure"));
        assert_eq!(w.count("SELECT base_version FROM profile_bindings"), 0);
        assert!(
            out.join("local-only").exists(),
            "a refused join must preserve local data"
        );
    }

    #[test]
    fn an_abandoned_revert_with_a_lost_release_keeps_no_plaintext() {
        let w = world();
        let (_, _d, udd) = reverting(&w, DeviceRevocationReason::Retired);
        let before = tree(&udd);
        let compromise = a_compromise(&w);
        {
            let mut f = w.fake();
            f.on_checkout = Some(compromise);
            f.lose.push("release");
        }
        let err = w.revert(&udd).unwrap_err();
        assert!(has(&err, "sync.commitBlockedCompromised"));
        assert_eq!(tree(&udd), before);
        assert!(w.fake().lease.is_none(), "server has processed abandonment");
        assert_eq!(
            w.count("SELECT count(*) FROM operations WHERE kind = 'RELEASE' AND state = 'PENDING'"),
            1
        );
        assert!(
            !beside(&udd, ".revert-staging").exists(),
            "abandonment must remove decrypted P even when its reply is lost"
        );
    }

    #[test]
    fn a_failed_join_recovers_by_pull_then_push_or_by_unbind() {
        for recovery in ["pull-push", "unbind"] {
            let (w, d, _, _) = joinable_after_restore(0);
            let good = w.fake().objects[&1].clone();
            *w.fake().objects.get_mut(&1).unwrap().last_mut().unwrap() ^= 1;
            let out = d.path().join("profile");
            std::fs::create_dir_all(&out).unwrap();
            std::fs::write(out.join("local-only"), b"unsynced local edit").unwrap();
            let before = tree(&out);
            w.join(LOCAL, PROFILE, &out).unwrap_err();
            assert_eq!(tree(&out), before);
            let err = w.push_from(&out).unwrap_err();
            assert!(has(&err, "sync.remoteAhead"));
            assert!(w.sent("POST", "/checkout").is_empty());
            if recovery == "pull-push" {
                w.fake().objects.insert(1, good);
                w.pull(&out).unwrap();
                assert_eq!(noise(&out), noise(&w.udd));
                assert_eq!(w.push_from(&out).unwrap().version, 2);
            } else {
                unbind(LOCAL, SERVER, NOW).unwrap();
                assert_eq!(w.count("SELECT count(*) FROM profile_bindings"), 0);
                assert_eq!(tree(&out), before);
            }
        }
    }

    #[test]
    fn local_distrust_alone_enables_a_revert() {
        let w = world();
        let heads = chain_of(&w, &[&w.me.sk, &author()]);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, false, false));
        let d = second(&w);
        pin_at(&w, &d, &heads, 1);
        ledger::distrust_key(&w.db(), &w.dev.pin.0, &key_id_of(&author()), NOW).unwrap();
        let out = d.path().join("profile");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("marker"), b"local").unwrap();
        assert_eq!(w.revert(&out).unwrap().version, 3);
        let r = r_on(&w, heads[1]);
        available_at(&w, 3, r);
        assert_eq!(skipped(&w), [accepted_by(2, r, 1)]);
        assert_eq!(marker(&out), "v1");
        settled(&w, &out);
    }

    // Regressions found by the architect review of the round 1 fix.
    const LOCAL_STATE: &[u8] = br#"{"probe_marker":1}"#;

    fn local_state_kept(udd: &Path) -> bool {
        std::fs::read_to_string(udd.join("Local State"))
            .unwrap()
            .contains("probe_marker")
    }

    #[test]
    fn a_pull_keeps_the_devices_local_state() {
        let w = world();
        chain_of(&w, &[&w.me.sk]);
        let d = second(&w);
        let out = d.path().join("profile");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("Local State"), LOCAL_STATE).unwrap();
        w.pull(&out).unwrap();
        assert_eq!(marker(&out), "v1");
        assert!(
            local_state_kept(&out),
            "the os_crypt key and browser state stay"
        );
    }

    #[test]
    fn a_revert_keeps_the_devices_local_state() {
        let w = world();
        let (_, _d, udd) = reverting(&w, DeviceRevocationReason::Retired);
        std::fs::write(udd.join("Local State"), LOCAL_STATE).unwrap();
        assert_eq!(w.revert(&udd).unwrap().version, 3);
        assert_eq!(marker(&udd), "v1");
        assert!(
            local_state_kept(&udd),
            "the os_crypt key and browser state stay"
        );
    }

    /// A revert whose upload was under way when its staging went (a profile
    /// deleted under the lease, then restored from the trash) restores `P`
    /// again before `R` is accepted.
    #[test]
    fn a_resumed_revert_whose_staging_is_gone_restores_p_again() {
        let w = world();
        let (heads, _d, udd) = reverting(&w, DeviceRevocationReason::Retired);
        w.fake().skip.push("upload");
        w.revert(&udd).unwrap_err();
        let staging = beside(&udd, ".revert-staging");
        assert!(staging.exists(), "kept to resume");
        std::fs::remove_dir_all(&staging).unwrap();
        assert_eq!(w.revert(&udd).unwrap().version, 3);
        let r = r_on(&w, heads[1]);
        available_at(&w, 3, r);
        assert_eq!(marker(&udd), "v1", "R accepted only with P swapped in");
        settled(&w, &udd);
    }

    /// Rule 6: a device whose own key is withdrawn commits no `R`, before a
    /// checkout and after a replayed `R` was refused, and can still unbind.
    #[test]
    fn a_device_whose_own_key_is_withdrawn_sends_no_revert() {
        for case in ["no lease", "after a refused replay"] {
            let w = world();
            let (_, _d, udd) = reverting(&w, DeviceRevocationReason::Retired);
            let me = w.me.to.signing_key_id;
            if case == "no lease" {
                ledger::distrust_key(&w.db(), &w.dev.pin.0, &me, NOW).unwrap();
            } else {
                w.fake().lose.push("commit");
                w.revert(&udd).unwrap_err();
                ledger::distrust_key(&w.db(), &w.dev.pin.0, &me, NOW).unwrap();
                w.revert(&udd).unwrap_err();
            }
            let sent = w.fake().log.len();
            let version = w.fake().version;
            let before = tree(&udd);
            let err = w.revert(&udd).unwrap_err();
            assert!(has(&err, "sync.revertDeviceWithdrawn"), "{case}: {err:#}");
            assert_eq!(w.fake().log.len(), sent, "{case}: nothing was sent");
            assert_eq!(w.fake().version, version, "{case}");
            assert_eq!(tree(&udd), before, "{case}");
            assert_eq!(w.state(LOCAL).1.as_deref(), Some("SIGNER_REVOKED"));
            unbind(LOCAL, SERVER, NOW).unwrap();
            assert_eq!(w.count("SELECT count(*) FROM profile_bindings"), 0);
        }
    }

    /// Only a release of the held lease abandons it: one pending for another
    /// lease leaves the resumable upload's staged `P` in place.
    #[test]
    fn a_release_pending_for_another_lease_keeps_the_staging() {
        let w = world();
        let (_, _d, udd) = reverting(&w, DeviceRevocationReason::Retired);
        w.fake().skip.push("upload");
        w.revert(&udd).unwrap_err();
        let staging = beside(&udd, ".revert-staging");
        assert!(staging.exists(), "kept to resume");
        w.db()
            .conn
            .execute_batch(
                "CREATE TEMP TABLE other AS SELECT * FROM operations WHERE kind = 'UPLOAD';
                 UPDATE other SET op_id = 'other-' || op_id, kind = 'RELEASE', state = 'PENDING',
                   lease_id = '00000000000000000000000000000000',
                   idempotency_key = 'other-' || idempotency_key;
                 INSERT INTO operations SELECT * FROM other;",
            )
            .unwrap();
        discard_revert_staging(LOCAL, &udd).unwrap();
        assert!(staging.exists(), "another lease's release abandons nothing");
    }

    // Rule 6 at the pin: a withdrawal recorded after the walk, and a join
    // refused on an invalid transition.
    #[test]
    fn a_join_refused_on_an_invalid_transition_pins_nothing_and_can_unbind() {
        let (w, d, _, _) = joinable_after_restore(0);
        *w.fake()
            .epoch_files
            .get_mut(&epoch_path(0))
            .unwrap()
            .last_mut()
            .unwrap() ^= 1;
        let out = d.path().join("profile");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("marker"), b"local").unwrap();
        let before = tree(&out);
        let err = w.join(LOCAL, PROFILE, &out).unwrap_err();
        assert!(has(&err, "sync.epochTransitionInvalid"));
        assert_eq!(w.state(LOCAL).3, 0, "no unproven leaf pinned");
        assert!(tree(&out) == before);
        assert!(w.push_from(&out).is_err());
        assert!(w.sent("POST", "/checkout").is_empty());
        unbind(LOCAL, SERVER, NOW).unwrap();
        assert_eq!(w.count("SELECT count(*) FROM profile_bindings"), 0);
        assert!(tree(&out) == before, "unbind remains a way forward");
        assert!(!beside(&out, ".revert-staging").exists());
    }

    #[test]
    fn a_pull_never_pins_a_head_whose_signer_is_withdrawn_during_its_download() {
        let w = world();
        chain_of(&w, &[&w.me.sk, &author()]);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, false, false));
        let d = second(&w);
        let out = d.path().join("profile");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("marker"), b"local").unwrap();
        let before = tree(&out);
        w.fake().on_snapshot = Some(distrust_author());
        let result = w.pull(&out);
        assert!(w.fake().on_snapshot.is_none(), "download hook executed");
        assert!(ledger::withdrawn(&w.db(), &w.dev.pin.0, &key_id_of(&author())).unwrap());
        assert_eq!(
            (result.is_err(), w.state(LOCAL).3, tree(&out) == before),
            (true, 0, true),
            "a signer withdrawn before the pin transaction must not be pinned"
        );
        assert!(has(&result.unwrap_err(), "sync.signerRevoked"));
        assert_eq!(w.state(LOCAL).1.as_deref(), Some("SIGNER_REVOKED"));
        settled(&w, &out);
    }

    #[test]
    fn a_replayed_r_whose_signer_is_withdrawn_during_readback_is_never_pinned() {
        let w = world();
        let (_, _d, udd) = reverting(&w, DeviceRevocationReason::Retired);
        w.fake().lose.push("commit");
        w.revert(&udd).unwrap_err();
        assert_eq!(w.fake().version, 3);
        assert_eq!(w.state(LOCAL).3, 1);
        let before = tree(&udd);
        // Another local ledger writer withdraws R's signer while finish awaits
        // its final readback. Reuse the fixture's existing concurrent-writer hook.
        w.fake().on_list = Some(
            distrust_author().replace(&hex(&key_id_of(&author())), &hex(&w.me.to.signing_key_id)),
        );
        let result = w.revert(&udd);
        assert!(w.fake().on_list.is_none(), "readback hook executed");
        assert!(ledger::withdrawn(&w.db(), &w.dev.pin.0, &w.me.to.signing_key_id).unwrap());
        let (state, reason, _, version, _) = w.state(LOCAL);
        assert_eq!(
            (
                result.is_err(),
                state.as_str(),
                reason.as_deref(),
                version,
                tree(&udd) == before,
            ),
            (true, "QUARANTINED", Some("SIGNER_REVOKED"), 1, true),
            "withdrawn R must not pin, lift quarantine, or replace local data"
        );
        assert!(has(&result.unwrap_err(), "sync.signerRevoked"));
        assert_eq!(local_leases(&w), 0, "the lease R's commit used is dropped");
        settled(&w, &udd);
    }

    // The ADR's open-run exception, compared
    // with an ordinary successful pull of the exact same snapshot.
    #[test]
    fn an_open_run_restore_keeps_what_an_ordinary_pull_keeps() {
        let w = world();
        let heads = chain_of(&w, &[&w.me.sk, &author()]);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, false, false));
        let d = second(&w);
        let ordinary = d.path().join("ordinary");
        let open_run = d.path().join("open-run");
        for out in [&ordinary, &open_run] {
            std::fs::create_dir_all(out.join("Default")).unwrap();
            std::fs::write(out.join("Local State"), LOCAL_STATE).unwrap();
            std::fs::write(out.join("marker"), b"unsynced").unwrap();
            std::fs::write(out.join("Default/local-only"), b"unsynced edit").unwrap();
        }
        // Start both restores with the same complete device state. Windows
        // otherwise generates independent random os_crypt keys on first use.
        shardx_core::LocalCrypt::open(&ordinary).unwrap();
        std::fs::copy(ordinary.join("Local State"), open_run.join("Local State")).unwrap();
        w.fake().listed = Some((1, Some(heads[0])));
        w.pull(&ordinary).unwrap();
        w.db()
            .conn
            .execute_batch(
                "UPDATE profile_bindings SET remote_version = 0, base_version = 0,
             last_observed_head_hash = NULL",
            )
            .unwrap();
        w.fake().listed = None;
        serve(
            &w,
            &author_pages_for(
                &w,
                T0 + 300 * DAY,
                Some(DeviceRevocationReason::Retired),
                false,
            ),
        );
        let err = w.pull(&open_run).unwrap_err();
        assert!(has(&err, "sync.signerRevokedAtP"), "{err:#}");
        revoked_at(&w, 1);
        assert_eq!(w.state(LOCAL).4, Some(heads[0].to_vec()));
        let relative = |root: &Path| {
            tree(root)
                .into_iter()
                .map(|(p, bytes)| (p.strip_prefix(root).unwrap().to_path_buf(), bytes))
                .collect::<Vec<_>>()
        };
        assert!(
            relative(&ordinary) == relative(&open_run),
            "the open-run exception must keep exactly what an ordinary pull keeps"
        );
        assert_eq!(marker(&open_run), "v1");
        assert!(local_state_kept(&open_run));
        settled(&w, &open_run);
    }

    // A source snapshot that becomes proven revoked during its download
    // must not supply a newly committed revert's content.
    #[test]
    fn a_revert_never_commits_a_source_withdrawn_during_its_download() {
        let w = world();
        let mut evidence = author_pages(&w, T0 + 300 * DAY, false, false);
        let rejected = committer(&w, &mut evidence, 0x20, T0 + 300 * DAY);
        let heads = chain_of(&w, &[&w.me.sk, &author(), &rejected]);
        serve(&w, &evidence);
        let d = second(&w);
        pin_at(&w, &d, &heads, 1);
        ledger::distrust_key(&w.db(), &w.dev.pin.0, &key_id_of(&rejected), NOW).unwrap();
        let out = d.path().join("profile");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("marker"), b"local").unwrap();
        let before = tree(&out);
        let commits = w.fake().commits;
        w.fake().on_snapshot = Some(distrust_author());
        let result = w.revert(&out);
        assert!(
            w.fake().on_snapshot.is_none(),
            "source download hook executed"
        );
        assert!(ledger::withdrawn(&w.db(), &w.dev.pin.0, &key_id_of(&author())).unwrap());
        let err = result.unwrap_err();
        assert!(has(&err, "sync.signerRevoked"), "{err:#}");
        assert_eq!(w.fake().version, 3, "a refusal commits nothing");
        assert_eq!(w.fake().commits, commits);
        assert!(
            tree(&out) == before,
            "a refusal preserves the local profile"
        );
        assert_eq!(w.state(LOCAL).1.as_deref(), Some("SIGNER_REVOKED"));
        assert!(!beside(&out, ".revert-staging").exists());
        settled(&w, &out);
    }

    #[test]
    fn a_resumed_revert_never_commits_a_source_withdrawn_before_its_retry() {
        let w = world();
        let mut evidence = author_pages(&w, T0 + 300 * DAY, false, false);
        let rejected = committer(&w, &mut evidence, 0x20, T0 + 300 * DAY);
        let heads = chain_of(&w, &[&w.me.sk, &author(), &rejected]);
        serve(&w, &evidence);
        let d = second(&w);
        pin_at(&w, &d, &heads, 1);
        ledger::distrust_key(&w.db(), &w.dev.pin.0, &key_id_of(&rejected), NOW).unwrap();
        let out = d.path().join("profile");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("marker"), b"local").unwrap();
        let before = tree(&out);
        w.fake().skip.push("upload");
        w.revert(&out).unwrap_err();
        assert_eq!(w.fake().version, 3, "no R has landed");
        assert_eq!(marker(&beside(&out, ".revert-staging")), "v2");
        ledger::distrust_key(&w.db(), &w.dev.pin.0, &key_id_of(&author()), NOW).unwrap();
        assert!(ledger::withdrawn(&w.db(), &w.dev.pin.0, &key_id_of(&author())).unwrap());
        let commits = w.fake().commits;
        let err = w.revert(&out).unwrap_err();
        assert!(has(&err, "sync.signerRevoked"), "{err:#}");
        assert_eq!(w.fake().version, 3, "a refusal commits nothing");
        assert_eq!(w.fake().commits, commits);
        assert!(tree(&out) == before);
        assert_eq!(w.state(LOCAL).1.as_deref(), Some("SIGNER_REVOKED"));
        assert!(!beside(&out, ".revert-staging").exists());
    }

    // Regressions found by the architect review, round 2.
    #[test]
    fn a_revert_uses_the_newest_valid_content_and_reads_back_remotely() {
        let w = world();
        let heads = chain_of(&w, &[&w.me.sk, &w.me.sk, &author()]);
        serve(
            &w,
            &author_pages_for(
                &w,
                T0 + 300 * DAY,
                Some(DeviceRevocationReason::Retired),
                false,
            ),
        );
        let d = second(&w);
        pin_at(&w, &d, &heads, 1);
        let out = d.path().join("profile");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("marker"), b"unsynced local").unwrap();
        assert_eq!(w.revert(&out).unwrap().version, 4);
        assert_eq!(
            marker(&out),
            "v2",
            "P must be the newest valid earlier snapshot"
        );
        let other = second(&w);
        let readback = other.path().join("readback");
        w.pull(&readback).unwrap();
        assert_eq!(
            marker(&readback),
            "v2",
            "the encrypted committed R also carries P"
        );
        settled(&w, &readback);
    }

    #[test]
    fn an_open_run_anchor_withdrawn_during_download_is_not_pinned() {
        let w = world();
        let mut evidence = author_pages(&w, T0 + 300 * DAY, false, false);
        let rejected = committer(&w, &mut evidence, 0x20, T0 + 300 * DAY);
        let heads = chain_of(&w, &[&w.me.sk, &author(), &rejected]);
        serve(&w, &evidence);
        let d = second(&w);
        pin_at(&w, &d, &heads, 1);
        ledger::distrust_key(&w.db(), &w.dev.pin.0, &key_id_of(&rejected), NOW).unwrap();
        let out = d.path().join("profile");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("marker"), b"local").unwrap();
        let before = tree(&out);
        w.fake().on_snapshot = Some(distrust_author());
        let err = w.pull(&out).unwrap_err();
        assert!(
            w.fake().on_snapshot.is_none(),
            "anchor download hook executed"
        );
        assert!(has(&err, "sync.signerRevoked"));
        revoked_at(&w, 1);
        assert_eq!(w.state(LOCAL).4, Some(heads[0].to_vec()));
        assert_eq!(tree(&out), before);
        settled(&w, &out);
    }

    #[test]
    fn a_withdrawn_committer_sends_no_prepared_revert_commit() {
        let w = world();
        let mut evidence = author_pages(&w, T0 + 300 * DAY, false, false);
        let rejected = committer(&w, &mut evidence, 0x20, T0 + 300 * DAY);
        let heads = chain_of(&w, &[&author(), &rejected]);
        serve(&w, &evidence);
        let d = second(&w);
        pin_at(&w, &d, &heads, 1);
        ledger::distrust_key(&w.db(), &w.dev.pin.0, &key_id_of(&rejected), NOW).unwrap();
        let out = d.path().join("profile");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("marker"), b"local").unwrap();
        let before = tree(&out);
        w.fake().skip.push("commit");
        w.revert(&out).unwrap_err();
        assert_eq!(w.fake().version, 2, "R has not landed");
        assert_eq!(
            w.count("SELECT count(*) FROM operations WHERE kind = 'COMMIT' AND state = 'PENDING'"),
            1
        );
        ledger::distrust_key(&w.db(), &w.dev.pin.0, &w.me.to.signing_key_id, NOW).unwrap();
        let commits = w.fake().commits;
        let result = w.revert(&out);
        assert!(
            result.is_err(),
            "the withdrawn committer's revert is refused"
        );
        assert_eq!(tree(&out), before);
        revoked_at(&w, 1);
        assert_eq!(
            w.fake().commits,
            commits,
            "a withdrawn device must commit no new R"
        );
        assert_eq!(w.fake().version, 2);
        let err = result.unwrap_err();
        assert!(has(&err, "sync.revertDeviceWithdrawn"), "{err:#}");
        assert!(w.fake().lease.is_none(), "the server released the lease");
        assert_eq!(local_leases(&w), 0);
        assert!(!beside(&out, ".revert-staging").exists());
    }

    fn local_leases(w: &World) -> i64 {
        w.count("SELECT count(*) FROM profile_bindings WHERE lease_id IS NOT NULL")
    }

    /// A revert lease with no COMMIT, abandoned because this device's own key
    /// is withdrawn, is released on `Jn`, the base its checkout took, so the
    /// server lets it go too.
    #[test]
    fn a_withdrawn_device_releases_its_revert_lease_on_the_server() {
        let w = world();
        let (_, _d, udd) = reverting(&w, DeviceRevocationReason::Retired);
        let before = tree(&udd);
        w.fake().skip.push("upload");
        w.revert(&udd).unwrap_err();
        assert_eq!(local_leases(&w), 1, "in progress");
        ledger::distrust_key(&w.db(), &w.dev.pin.0, &w.me.to.signing_key_id, NOW).unwrap();
        let err = w.revert(&udd).unwrap_err();
        assert!(has(&err, "sync.revertDeviceWithdrawn"), "{err:#}");
        assert!(w.fake().lease.is_none(), "the server released the lease");
        assert_eq!(local_leases(&w), 0);
        assert_eq!(w.state(LOCAL).1.as_deref(), Some("SIGNER_REVOKED"));
        assert_eq!(tree(&udd), before);
        assert!(!beside(&udd, ".revert-staging").exists());
    }

    /// N2: this device's own key withdrawn only in the evidence the walk
    /// fetches, with `P` signed by a third committer that stays valid, stops
    /// the revert at the check after the walk: no checkout, nothing staged.
    #[test]
    fn a_device_withdrawn_in_the_walks_evidence_sends_no_revert() {
        let w = world();
        let mut evidence = author_pages(&w, T0 + 300 * DAY, false, false);
        let rejected = committer(&w, &mut evidence, 0x20, T0 + 300 * DAY);
        let heads = chain_of(&w, &[&author(), &rejected]);
        serve(&w, &evidence);
        let d = second(&w);
        pin_at(&w, &d, &heads, 1);
        ledger::distrust_key(&w.db(), &w.dev.pin.0, &key_id_of(&rejected), NOW).unwrap();
        let me = &w.me.to;
        let revoke = TenantCapabilityGrantV2 {
            common: common(0x40),
            subject: device_subject(&w.me),
            scope_kind: CapabilityScopeKind::Tenant,
            scope_id: TENANT,
            capability: Capability::DeviceRevoke,
        };
        let revocation = DeviceRevocationV2 {
            common: common(0x41),
            subject_account_id: me.account_id,
            subject_device_id: me.device_id,
            subject_signing_key_id: me.signing_key_id,
            subject_hpke_key_id: me.hpke_key_id,
            reason_code: DeviceRevocationReason::Retired,
        };
        evidence[0].containers.extend([
            build_record(&w.me.sk, DOMAIN_TENANT_CAPABILITY_GRANT, &revoke.encode()),
            build_record(&w.me.sk, DOMAIN_DEVICE_REVOCATION, &revocation.encode()),
        ]);
        serve(&w, &evidence);
        assert!(!ledger::withdrawn(&w.db(), &w.dev.pin.0, &me.signing_key_id).unwrap());
        let out = d.path().join("profile");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("marker"), b"local").unwrap();
        let before = tree(&out);
        let (checkouts, commits) = (w.sent("POST", "/checkout").len(), w.fake().commits);
        let err = w.revert(&out).unwrap_err();
        assert!(has(&err, "sync.revertDeviceWithdrawn"), "{err:#}");
        assert!(ledger::withdrawn(&w.db(), &w.dev.pin.0, &me.signing_key_id).unwrap());
        assert_eq!(w.sent("POST", "/checkout").len(), checkouts);
        assert_eq!(w.fake().commits, commits);
        assert_eq!(tree(&out), before);
        assert!(!beside(&out, ".revert-staging").exists());
    }

    /// A revert lease whose walk fails is released on its checkout's base.
    #[test]
    fn a_revert_lease_whose_walk_fails_is_released_on_the_server() {
        let w = world();
        let (_, _d, udd) = reverting(&w, DeviceRevocationReason::Retired);
        let crash = "CREATE TRIGGER crash BEFORE INSERT ON operations
             WHEN NEW.kind = 'UPLOAD' BEGIN SELECT RAISE(ABORT, 'crash'); END";
        w.db().conn.execute(crash, []).unwrap();
        w.revert(&udd).unwrap_err();
        w.db().conn.execute("DROP TRIGGER crash", []).unwrap();
        assert_eq!(local_leases(&w), 1, "held with nothing uploaded");
        w.fake().refuse.push(("profiles", 503));
        w.revert(&udd).unwrap_err();
        assert!(w.fake().lease.is_none(), "the server released the lease");
        assert_eq!(local_leases(&w), 0);
        assert_eq!(w.state(LOCAL).1.as_deref(), Some("SIGNER_REVOKED"));
    }

    /// `R` landed with its reply lost and its staging gone: the next revert
    /// finds no run to revert and gives the lease up with the user's data as
    /// it was; the next pull accepts `R` and installs `P`.
    #[test]
    fn a_landed_r_whose_staging_is_gone_is_accepted_by_the_next_pull() {
        let w = world();
        let (heads, _d, udd) = reverting(&w, DeviceRevocationReason::Retired);
        w.fake().lose.push("commit");
        w.revert(&udd).unwrap_err();
        assert_eq!(w.fake().version, 3, "committed, the reply lost");
        let staging = beside(&udd, ".revert-staging");
        assert!(staging.exists(), "kept to resume");
        std::fs::remove_dir_all(&staging).unwrap();
        let err = w.revert(&udd).unwrap_err();
        assert!(has(&err, "sync.revertUnavailable"), "{err:#}");
        assert_eq!(local_leases(&w), 0, "abandoned");
        assert_eq!(marker(&udd), "local");
        w.pull(&udd).unwrap();
        let r = r_on(&w, heads[1]);
        available_at(&w, 3, r);
        assert_eq!(marker(&udd), "v1");
        settled(&w, &udd);
        assert_eq!(
            w.count("SELECT count(*) FROM skipped_heads WHERE resolution IS NULL"),
            0
        );
    }
    #[test]
    fn a_revocation_naming_another_device_never_enables_a_skip() {
        let w = world();
        chain_of(&w, &[&w.me.sk, &author(), &w.me.sk]);
        let mut evidence = author_pages_for(
            &w,
            T0 + 300 * DAY,
            Some(DeviceRevocationReason::Retired),
            true,
        );
        let mut changed = false;
        for container in &mut evidence[0].containers {
            let record = AuthorizationRecord::parse(container).unwrap();
            if record.payload_domain() != DOMAIN_DEVICE_REVOCATION {
                continue;
            }
            let verified = record
                .verify_signature(&w.me.sk.verifying_key().to_bytes())
                .unwrap();
            let Payload::DeviceRevocation(revocation) = verified.payload() else {
                panic!("expected a device revocation");
            };
            let mut wrong_device = revocation.clone();
            assert_eq!(wrong_device.subject_device_id, [0x71; 16]);
            wrong_device.subject_device_id = [0x99; 16];
            *container = build_record(&w.me.sk, DOMAIN_DEVICE_REVOCATION, &wrong_device.encode());
            changed = true;
        }
        assert!(changed, "the mismatched record was actually installed");
        let d = second(&w);
        // Establish the reported-only quarantine before supplying the bad proof.
        serve(&w, &author_pages(&w, T0 + 300 * DAY, false, true));
        let out = d.path().join("profile");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("marker"), b"unsynced local").unwrap();
        let before = tree(&out);
        assert!(has(&w.pull(&out).unwrap_err(), "sync.signerRevoked"));
        revoked_at(&w, 0);
        serve(&w, &evidence);
        let result = w.pull(&out);
        let (state, reason, _, version, _) = w.state(LOCAL);
        assert_eq!(
            (
                result.is_err(),
                ledger::withdrawn(&w.db(), &w.dev.pin.0, &key_id_of(&author())).unwrap(),
                state,
                reason,
                version,
                skipped(&w).len(),
                tree(&out) == before,
            ),
            (
                true,
                false,
                "QUARANTINED".into(),
                Some("SIGNER_REVOKED".into()),
                0,
                0,
                true
            ),
            "a signed revocation for a different device is not proof against this signer"
        );
        assert!(has(&result.unwrap_err(), "sync.signerRevoked"));
        settled(&w, &out);
    }

    #[test]
    fn join_never_pins_a_leaf_withdrawn_during_the_proof_fetch() {
        let (w, d, _, _) = joinable_after_restore(0);
        let out = d.path().join("profile");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("marker"), b"unsynced local").unwrap();
        let before = tree(&out);
        w.fake().on_proof = Some(
            distrust_author().replace(&hex(&key_id_of(&author())), &hex(&w.me.to.signing_key_id)),
        );
        let result = w.join(LOCAL, PROFILE, &out);
        assert!(w.fake().on_proof.is_none(), "withdrawal hook ran");
        assert!(ledger::withdrawn(&w.db(), &w.dev.pin.0, &w.me.to.signing_key_id).unwrap());
        assert!(has(&result.unwrap_err(), "sync.epochTransitionInvalid"));
        assert_eq!(w.state(LOCAL).3, 0);
        assert!(tree(&out) == before);
        assert!(w.sent("POST", "/checkout").is_empty());
        settled(&w, &out);
        unbind(LOCAL, SERVER, NOW).unwrap();
        assert_eq!(w.count("SELECT count(*) FROM profile_bindings"), 0);
        assert!(tree(&out) == before);
    }

    #[test]
    fn revert_never_pins_an_r_withdrawn_during_the_readback() {
        let w = world();
        let (_, _d, udd) = reverting(&w, DeviceRevocationReason::Retired);
        w.fake().skip.push("commit");
        w.revert(&udd).unwrap_err();
        assert_eq!(w.fake().version, 2, "no R has landed yet");
        let before = tree(&udd);
        w.fake().on_snapshot = Some(
            distrust_author().replace(&hex(&key_id_of(&author())), &hex(&w.me.to.signing_key_id)),
        );
        let result = w.revert(&udd);
        assert!(
            w.fake().on_snapshot.is_none(),
            "readback withdrawal hook ran"
        );
        assert_eq!(w.fake().version, 3, "R landed before the readback");
        assert!(has(&result.unwrap_err(), "sync.signerRevoked"));
        revoked_at(&w, 1);
        assert!(tree(&udd) == before);
        assert_eq!(local_leases(&w), 0);
        assert_eq!(skipped(&w).len(), 1);
        assert!(skipped(&w)[0].1.is_none(), "the run is still open");
        settled(&w, &udd);
    }

    // Independent round-7 probe: a damaged P must leave the complete local
    // tree intact, remove plaintext staging, and permit a clean retry.
    #[test]
    fn a_corrupt_revert_source_preserves_data_and_retries() {
        let w = world();
        let (heads, _d, udd) = reverting(&w, DeviceRevocationReason::Retired);
        std::fs::create_dir_all(udd.join("Default")).unwrap();
        std::fs::write(udd.join("Default/local-only"), b"unsynced edit").unwrap();
        std::fs::write(udd.join("Local State"), LOCAL_STATE).unwrap();
        let before = tree(&udd);
        let good = w.fake().objects[&1].clone();
        *w.fake().objects.get_mut(&1).unwrap().last_mut().unwrap() ^= 1;
        let commits = w.fake().commits;
        let checkouts = w.sent("POST", "/checkout").len();

        let err = w.revert(&udd).unwrap_err();
        // The fixture derives ETag from the damaged object, so the response
        // is rejected at the range check before envelope authentication.
        assert!(has(&err, "sync.badReplySync"), "{err:#}");
        assert!(format!("{err:#}").contains("field=range"), "{err:#}");
        assert!(tree(&udd) == before, "every local file remains unchanged");
        assert_eq!(w.fake().commits, commits);
        assert_eq!(w.sent("POST", "/checkout").len(), checkouts);
        revoked_at(&w, 1);
        assert_eq!(w.state(LOCAL).4, Some(heads[0].to_vec()));
        for suffix in SWAP_DIRS.iter().chain(UNPACK_LEFTOVERS.iter()) {
            assert!(
                !beside(&udd, suffix).exists(),
                "plaintext leftover: {suffix}"
            );
        }
        assert_eq!(local_leases(&w), 0);

        w.fake().objects.insert(1, good);
        assert_eq!(w.revert(&udd).unwrap().version, 3);
        assert_eq!(marker(&udd), "v1");
        assert!(local_state_kept(&udd));
        assert!(!udd.join("Default/local-only").exists());
        settled(&w, &udd);
    }

    // Independent round-7 probe: the leaf search may follow a child signed
    // by a server-listed key, but that key's missing authority must stop the
    // subsequent pull and any check-in of the untouched local profile.
    #[test]
    fn a_join_past_an_untrusted_child_keeps_data_and_can_unbind() {
        let (w, d, leaf_head, _) = joinable_after_restore(1);
        let key = author();
        {
            let mut f = w.fake();
            let m = SignedSnapshotManifestV2::parse(&f.manifests[&2]).unwrap();
            let mut p = SnapshotManifestV2::parse(m.canonical_manifest_payload_bytes()).unwrap();
            p.signer_signing_key_id = key_id_of(&key);
            let child = SignedSnapshotManifestV2::sign(&key, &p).unwrap();
            f.manifests.insert(2, child.exact_bytes().to_vec());
            f.head = Some(child.head_hash());
        }
        let mut evidence = pages(&w.me, &w.grant, &Ev::default());
        evidence[0]
            .signing_public_keys
            .push(key.verifying_key().to_bytes());
        serve(&w, &evidence);
        let out = d.path().join("profile");
        std::fs::create_dir_all(out.join("Default")).unwrap();
        std::fs::write(out.join("Default/local-only"), b"unsynced edit").unwrap();
        std::fs::write(out.join("Local State"), LOCAL_STATE).unwrap();
        let before = tree(&out);

        let err = w.join(LOCAL, PROFILE, &out).unwrap_err();
        assert!(has(&err, "sync.signerUntrusted"), "{err:#}");
        assert_eq!(w.state(LOCAL).4, Some(leaf_head.to_vec()));
        assert_eq!(w.state(LOCAL).3, 1, "only the proven leaf was pinned");
        assert_eq!(w.count("SELECT base_version FROM profile_bindings"), 0);
        assert!(tree(&out) == before);
        assert!(has(&w.push_from(&out).unwrap_err(), "sync.remoteAhead"));
        assert!(w.sent("POST", "/checkout").is_empty());
        assert!(has(&w.pull(&out).unwrap_err(), "sync.signerUntrusted"));
        assert!(tree(&out) == before);
        settled(&w, &out);
        unbind(LOCAL, SERVER, NOW).unwrap();
        assert_eq!(w.count("SELECT count(*) FROM profile_bindings"), 0);
        assert!(tree(&out) == before);
    }

    // Independent round-8 probe: the committer must refuse a mixed run,
    // preserve every local file, and keep the quarantine without a checkout.
    #[test]
    fn a_revert_refuses_a_mixed_run_without_touching_local_data() {
        for reported in [false, true] {
            let w = world();
            let mut evidence = author_pages_for(
                &w,
                T0 + 300 * DAY,
                Some(DeviceRevocationReason::Retired),
                false,
            );
            let end = if reported {
                T0 + 300 * DAY
            } else {
                T0 + DAY / 2
            };
            let other = committer(&w, &mut evidence, 0x20, end);
            if reported {
                evidence[0].device_revocations.push(RevokedDevice {
                    device_id: [0x21; 16],
                    revoked_at_ms: T0 + DAY / 2,
                });
            }
            let heads = chain_of(&w, &[&w.me.sk, &author(), &other]);
            serve(&w, &evidence);
            let d = second(&w);
            pin_at(&w, &d, &heads, 1);
            let out = d.path().join("profile");
            std::fs::create_dir_all(out.join("Default")).unwrap();
            std::fs::write(out.join("marker"), b"unsynced local").unwrap();
            std::fs::write(out.join("Default/local-only"), b"keep every byte").unwrap();
            std::fs::write(out.join("Local State"), LOCAL_STATE).unwrap();
            let before = tree(&out);
            let checkouts = w.sent("POST", "/checkout").len();
            let commits = w.fake().commits;

            for _ in 0..2 {
                let err = w.revert(&out).unwrap_err();
                assert!(
                    has(&err, "sync.signerRevoked"),
                    "reported={reported}: {err:#}"
                );
                revoked_at(&w, 1);
                assert_eq!(w.state(LOCAL).4, Some(heads[0].to_vec()));
                assert!(tree(&out) == before, "reported={reported}");
                assert_eq!(w.sent("POST", "/checkout").len(), checkouts);
                assert_eq!(w.fake().commits, commits);
                assert!(skipped(&w).is_empty());
                assert_eq!(local_leases(&w), 0);
                settled(&w, &out);
            }
        }
    }

    // Independent round-6 probe: inspect every committed pin update, not
    // just the final binding, while accepting a stacked revoked run.
    #[test]
    fn a_stacked_run_never_temporarily_pins_a_rejected_head() {
        let w = world();
        let heads = chain_of(&w, &[&w.me.sk, &author(), &author(), &w.me.sk]);
        serve(&w, &author_pages(&w, T0 + 300 * DAY, true, false));
        let d = second(&w);
        pin_at(&w, &d, &heads, 1);
        w.db()
            .conn
            .execute_batch(
                "CREATE TABLE revert_pin_log(version INTEGER NOT NULL);
             CREATE TRIGGER revert_pin_observer AFTER UPDATE OF remote_version ON profile_bindings
             WHEN NEW.remote_version != OLD.remote_version
             BEGIN INSERT INTO revert_pin_log VALUES (NEW.remote_version); END;",
            )
            .unwrap();

        w.pull(&d.path().join("profile")).unwrap();
        let db = w.db();
        let pins: Vec<i64> = db
            .conn
            .prepare("SELECT version FROM revert_pin_log ORDER BY rowid")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(pins, [4], "neither rejected version may ever become a pin");
        available_at(&w, 4, heads[3]);
        assert_eq!(
            skipped(&w),
            [accepted_by(2, heads[3], 1), accepted_by(3, heads[3], 1)]
        );
    }

    // Independent round-6 probe: a server-side commit is not permission to
    // replace local data before the pin and swap-marker transaction commits.
    #[test]
    fn a_revert_pin_failure_preserves_local_data_and_retries() {
        let w = world();
        let (heads, _d, udd) = reverting(&w, DeviceRevocationReason::Retired);
        std::fs::create_dir_all(udd.join("Default")).unwrap();
        std::fs::write(udd.join("Default/local-only"), b"unsynced edit").unwrap();
        let before = tree(&udd);
        fail_the_pin_write(&w);

        let err = w.revert(&udd).unwrap_err();
        assert!(format!("{err:#}").contains("injected pin write failure"));
        assert_eq!(w.fake().version, 3, "R committed on the server");
        assert!(
            tree(&udd) == before,
            "the failed pin must preserve every local file"
        );
        let (state, reason, _, version, head) = w.state(LOCAL);
        assert_eq!(
            (state.as_str(), reason.as_deref(), version, head),
            (
                "UPLOADING",
                Some("SIGNER_REVOKED"),
                1,
                Some(heads[0].to_vec())
            )
        );
        assert!(has(
            &w.push_from(&udd).unwrap_err(),
            "sync.revertInProgress"
        ));
        assert_eq!(w.count("SELECT count(*) FROM revert_swaps"), 0);
        assert_eq!(skipped(&w), [(2, None, None, 1)]);
        assert_eq!(marker(&beside(&udd, ".revert-staging")), "v1");

        w.db()
            .conn
            .execute_batch("DROP TRIGGER pin_failure")
            .unwrap();
        assert_eq!(w.revert(&udd).unwrap().version, 3);
        assert_eq!(w.fake().version, 3, "retry does not create another commit");
        let r = r_on(&w, heads[1]);
        available_at(&w, 3, r);
        assert_eq!(skipped(&w), [accepted_by(2, r, 1)]);
        assert_eq!(marker(&udd), "v1");
        assert!(!udd.join("Default/local-only").exists());
        settled(&w, &udd);
    }
}
