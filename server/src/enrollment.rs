//! Device enrollment: register a device signing key, with proof it is held.
//!
//! A device that publishes a snapshot signs the manifest, and the server
//! records that device as the author. So registration cannot simply accept a
//! public key from whoever asks: a caller could register a key it does not
//! hold, or worse, register a key belonging to somebody else and have their
//! signatures attributed to it.
//!
//! Enrollment is therefore two round trips:
//!
//! 1. **Challenge.** The server generates 32 random bytes, stores them, and
//!    returns them. The client never chooses this value — a client-chosen
//!    challenge proves nothing, since the caller could pick one it already has
//!    a signature for.
//! 2. **Proof.** The client signs the challenge with the private key matching
//!    the public key it wants to register. The server verifies against the
//!    stored bytes and registers the device only if that check passes.
//!
//! Challenges are single-use and time-bounded, and they carry the server
//! identity they were issued under: one issued before a restore is refused
//! afterwards, because the epoch is part of what the device's later records
//! bind to.

use anyhow::{bail, Result};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use sqlx::{Row, SqlitePool};

use shared::canonical as c;
use shared::keys::signing_key_id;
use shared::signing::verify_tbs;

/// Suite identifiers recorded alongside an enrolled key.
///
/// The protocol reserves a registry for these; only the pair this build
/// actually implements is defined here, so a row can never claim an
/// algorithm the code cannot verify. Adding a suite is a deliberate change
/// here plus the verification path that honours it.
pub const SIGNING_SUITE_ED25519: i64 = 1;
pub const HPKE_SUITE_X25519_HKDF_SHA256: i64 = 1;

/// How long a challenge stays usable. Long enough to cover a slow key
/// generation on an old machine, short enough that an intercepted challenge
/// is not a lasting foothold.
pub const CHALLENGE_TTL_SECONDS: i64 = 120;

#[derive(Debug)]
pub struct Challenge {
    pub id: [u8; 16],
    pub nonce: [u8; 32],
    pub expires_at: String,
}

/// Bytes the client signs to prove possession.
///
/// Binds the domain, the challenge, the tenant and account it was issued to,
/// and both key ids. A proof is therefore valid for exactly one enrollment of
/// one key pair by one account — it cannot be lifted to a different tenant or
/// used to register a different key.
pub fn proof_tbs_bytes(
    challenge_id: &[u8; 16],
    nonce: &[u8; 32],
    tenant_id: &[u8; 16],
    account_id: &[u8; 16],
    signing_public_key: &[u8; 32],
    hpke_public_key: &[u8; 32],
) -> Vec<u8> {
    // Encoding lives in `shared` so the Launcher signs exactly what this
    // verifies; a second copy here would be free to drift.
    shared::enrollment_proof::enrollment_proof_tbs(
        &shared::enrollment_proof::EnrollmentProofFields {
            challenge_id,
            nonce,
            tenant_id,
            account_id,
            signing_public_key,
            hpke_public_key,
        },
    )
}

/// Commitment to the key pair a challenge is issued for.
///
/// The client names its keys up front, and the server stores only this hash.
/// Enrollment then has to present keys matching the commitment, so an
/// intercepted challenge cannot be redirected to a different key pair.
pub fn key_commitment(signing_public_key: &[u8; 32], hpke_public_key: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(signing_public_key);
    buf.extend_from_slice(hpke_public_key);
    c::sha256(&buf)
}

/// Issue a challenge for the keys named by `commitment`.
///
/// The nonce is returned once and never stored in the clear: the row keeps
/// only its hash, so a copy of the database does not hand an attacker the
/// values needed to precompute proofs.
#[allow(clippy::too_many_arguments)]
pub async fn issue_challenge(
    db: &SqlitePool,
    tenant_id: &[u8; 16],
    commitment: &[u8; 32],
    server_instance_id: &[u8; 16],
    restore_epoch: i64,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Challenge> {
    let mut id = [0u8; 16];
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut id);
    OsRng.fill_bytes(&mut nonce);

    let expires_at = (now + chrono::Duration::seconds(CHALLENGE_TTL_SECONDS)).to_rfc3339();

    sqlx::query(
        "INSERT INTO v2_enrollment_challenges
             (id, tenant_id, server_instance_id, restore_epoch, nonce_hash,
              key_commitment, expires_at, consumed_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, NULL)",
    )
    .bind(id.as_slice())
    .bind(tenant_id.as_slice())
    .bind(server_instance_id.as_slice())
    .bind(restore_epoch)
    .bind(c::sha256(&nonce).as_slice())
    .bind(commitment.as_slice())
    .bind(&expires_at)
    .execute(db)
    .await?;

    Ok(Challenge {
        id,
        nonce,
        expires_at,
    })
}

pub struct EnrollRequest<'a> {
    pub tenant_id: &'a [u8; 16],
    pub account_id: &'a [u8; 16],
    pub challenge_id: &'a [u8; 16],
    /// The nonce from the challenge response, echoed back. The server holds
    /// only its hash, so the client must return the value it was given.
    pub nonce: &'a [u8; 32],
    pub device_id: &'a [u8; 16],
    pub label_ciphertext: &'a [u8],
    pub signing_public_key: &'a [u8; 32],
    pub signing_suite: i64,
    pub hpke_public_key: &'a [u8; 32],
    pub hpke_suite: i64,
    pub signature: &'a [u8],
}

/// Verify a proof of possession and register the device.
///
/// Runs in one transaction: the challenge is claimed and the device inserted
/// together, so a challenge cannot be spent without a device appearing, and
/// two concurrent proofs cannot both register.
pub async fn enroll_device(
    db: &SqlitePool,
    req: EnrollRequest<'_>,
    server_instance_id: &[u8; 16],
    restore_epoch: i64,
    now: &str,
) -> Result<()> {
    let mut tx = db.begin().await?;

    let row = sqlx::query(
        "SELECT nonce_hash, key_commitment, server_instance_id, restore_epoch,
                expires_at, consumed_at
         FROM v2_enrollment_challenges
         WHERE tenant_id = ? AND id = ?",
    )
    .bind(req.tenant_id.as_slice())
    .bind(req.challenge_id.as_slice())
    .fetch_optional(&mut *tx)
    .await?;

    let Some(row) = row else {
        bail!("unknown enrollment challenge");
    };

    if row.get::<Option<String>, _>("consumed_at").is_some() {
        bail!("enrollment challenge already used");
    }

    // The challenge was issued for one specific key pair. Checking the
    // commitment stops an intercepted challenge from being spent on keys the
    // requester never named.
    let commitment: Vec<u8> = row.get("key_commitment");
    let expected = key_commitment(req.signing_public_key, req.hpke_public_key);
    if commitment != expected.as_slice() {
        bail!("enrollment proof does not match the committed key pair");
    }

    let issued_instance: Vec<u8> = row.get("server_instance_id");
    let issued_epoch: i64 = row.get("restore_epoch");
    if issued_instance != server_instance_id.as_slice() || issued_epoch != restore_epoch {
        bail!("enrollment challenge was issued under a different server identity");
    }

    let expires_at: String = row.get("expires_at");
    if now >= expires_at.as_str() {
        bail!("enrollment challenge expired");
    }

    // The row keeps only the nonce's hash, so the echoed value is checked
    // against it rather than trusted.
    let stored_hash: Vec<u8> = row.get("nonce_hash");
    if stored_hash != c::sha256(req.nonce).as_slice() {
        bail!("enrollment proof carries the wrong challenge nonce");
    }

    let tbs = proof_tbs_bytes(
        req.challenge_id,
        req.nonce,
        req.tenant_id,
        req.account_id,
        req.signing_public_key,
        req.hpke_public_key,
    );
    verify_tbs(req.signing_public_key, &tbs, req.signature)
        .map_err(|e| anyhow::anyhow!("enrollment proof rejected: {e}"))?;

    // Claim the challenge. The WHERE clause repeats the unconsumed check so a
    // concurrent proof that passed verification against the same row cannot
    // also claim it.
    let claimed = sqlx::query(
        "UPDATE v2_enrollment_challenges SET consumed_at = ?
         WHERE tenant_id = ? AND id = ? AND consumed_at IS NULL",
    )
    .bind(now)
    .bind(req.tenant_id.as_slice())
    .bind(req.challenge_id.as_slice())
    .execute(&mut *tx)
    .await?;
    if claimed.rows_affected() != 1 {
        bail!("enrollment challenge already used");
    }

    let signing_kid = signing_key_id(req.signing_public_key);
    let hpke_kid = signing_key_id(req.hpke_public_key);

    // Refuse a duplicate explicitly. Without this the unique index still
    // stops it, but the caller gets a raw SQLite message naming tables and
    // columns, which is both unhelpful and more than a client should learn.
    let existing = sqlx::query(
        "SELECT 1 FROM v2_devices
         WHERE tenant_id = ? AND (signing_key_id = ? OR hpke_key_id = ?)",
    )
    .bind(req.tenant_id.as_slice())
    .bind(signing_kid.as_slice())
    .bind(hpke_kid.as_slice())
    .fetch_optional(&mut *tx)
    .await?;
    if existing.is_some() {
        bail!("device is already enrolled in this tenant");
    }

    sqlx::query(
        "INSERT INTO v2_devices
             (id, tenant_id, account_id, label_ciphertext, signing_key_id, signing_public_key,
              signing_suite, hpke_key_id, hpke_public_key, hpke_suite, status, last_seen_at,
              created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', NULL, ?)",
    )
    .bind(req.device_id.as_slice())
    .bind(req.tenant_id.as_slice())
    .bind(req.account_id.as_slice())
    .bind(req.label_ciphertext)
    .bind(signing_kid.as_slice())
    .bind(req.signing_public_key.as_slice())
    .bind(req.signing_suite)
    .bind(hpke_kid.as_slice())
    .bind(req.hpke_public_key.as_slice())
    .bind(req.hpke_suite)
    .bind(now)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(())
}
