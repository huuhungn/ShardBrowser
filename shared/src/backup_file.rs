//! Local profile backup files: pack a profile, seal it, write one file.
//!
//! This is the glue the v0.2.x library was missing. `snapshot::pack` turns a
//! user-data dir into portable bytes and `backup::seal` encrypts them, but
//! nothing joined the two or decided what lands on disk. This module owns that
//! file format and the passphrase-derived key custody around it.
//!
//! The file is self-contained: salt, then the sealed container. Everything
//! needed to open it with the passphrase travels with it, because a backup that
//! depends on state left behind on the machine that wrote it is not a backup.
//!
//! Restore never writes into the live profile directly. `backup::open` streams
//! authenticated frames as it decrypts and can only detect a truncated
//! container when it reaches the signed head at the very end, so a partial
//! restore can reach the output before the error surfaces. Everything is
//! therefore recovered into memory and verified before `snapshot::unpack`
//! touches the profile.

use std::fs;
use std::io::{Cursor, Write};
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};

use crate::backup::{self, BackupParams, BackupSecrets};
use crate::envelope::IntentIds;
use crate::keys::{root_key_id, signing_key_id, DEK_LEN, STREAM_NONCE_PREFIX_LEN, WRAP_NONCE_LEN};
use crate::passphrase::{derive_backup_fkek, BACKUP_SALT_LEN};
use crate::signing::Ed25519SigningKey as SigningKey;
use crate::snapshot;

/// File magic. Distinct from the inner container's magic so a truncated or
/// mis-typed file is diagnosed as "not a ShardX backup" rather than as a
/// corrupt container.
const FILE_MAGIC: &[u8; 8] = b"SHXBAK01";

/// Magic for a container sealed under a fleet key (FKEK) rather than a
/// passphrase. Distinct from `FILE_MAGIC` so the two can never be confused:
/// feeding a fleet container to the passphrase path would otherwise fail as
/// "wrong passphrase", which is a misleading thing to tell someone.
const FLEET_FILE_MAGIC: &[u8; 8] = b"SHXFLT01";

/// What a completed backup produced, for the UI to show and the user to record.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BackupFileInfo {
    /// Total bytes written to disk.
    pub file_bytes: u64,
    /// SHA-256 of the file, hex. This is the digest an operator records.
    pub sha256: String,
    /// Plaintext size before sealing, for a rough progress/space estimate.
    pub plaintext_bytes: u64,
}

/// Random bytes from the OS CSPRNG.
fn os_random<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    getrandom04::fill(&mut out).map_err(|e| anyhow!("OS CSPRNG unavailable: {e}"))?;
    Ok(out)
}

/// Derive the deterministic identity fields for a local backup.
///
/// A local backup has no tenant, fleet or lease — those exist for fleet sync.
/// Rather than invent fake ids, every id is derived from the profile id so the
/// binding is stable and reproducible: reading the same profile twice produces
/// the same intent ids, and two different profiles never collide.
fn local_id(profile_id: &str, label: &str) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(b"shardx-local-backup/");
    h.update(label.as_bytes());
    h.update(b"/");
    h.update(profile_id.as_bytes());
    let full: [u8; 32] = h.finalize().into();
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

/// Pack `udd`, seal it under a key derived from `passphrase`, and write the
/// backup to `dest`.
///
/// The file is written to a temporary sibling and renamed into place, so an
/// interrupted backup cannot leave a truncated file where a valid one used to
/// be.
pub fn create(
    profile_id: &str,
    udd: &Path,
    dest: &Path,
    passphrase: &str,
) -> Result<BackupFileInfo> {
    let sealed = seal_profile(profile_id, udd, passphrase)?;
    write_atomic(dest, &sealed.bytes)
        .with_context(|| format!("write backup to {}", dest.display()))?;
    Ok(sealed.info)
}

/// A sealed profile container held in memory.
///
/// Fleet sync needs the same bytes `create` writes to disk, but must hand them
/// to an uploader instead. Both paths go through here so the wire format
/// cannot drift between a local backup and a synced snapshot.
pub struct SealedProfile {
    pub bytes: Vec<u8>,
    pub info: BackupFileInfo,
}

/// Pack and seal `udd` under a key derived from `passphrase`, returning the
/// container rather than writing it.
pub fn seal_profile(profile_id: &str, udd: &Path, passphrase: &str) -> Result<SealedProfile> {
    let salt: [u8; BACKUP_SALT_LEN] = os_random()?;
    let fkek = derive_backup_fkek(passphrase, &salt).map_err(|e| anyhow!("{e}"))?;
    seal_profile_with_fkek_and_magic(profile_id, udd, &fkek, salt, FILE_MAGIC)
}

/// Seal a profile under a fleet key.
///
/// The FKEK arrives from a fleet key grant this device opened, so there is no
/// passphrase and nothing to derive. The salt is still random and still
/// written, because the container format carries one; it just does not feed a
/// key derivation here.
///
/// The resulting file is byte-compatible with the passphrase container apart
/// from its magic, so the same reader handles both once the key is known.
pub fn seal_profile_with_fkek(
    profile_id: &str,
    udd: &Path,
    fkek: &[u8; 32],
) -> Result<SealedProfile> {
    let salt: [u8; BACKUP_SALT_LEN] = os_random()?;
    seal_profile_with_fkek_and_magic(profile_id, udd, fkek, salt, FLEET_FILE_MAGIC)
}

fn seal_profile_with_fkek_and_magic(
    profile_id: &str,
    udd: &Path,
    fkek: &[u8; 32],
    salt: [u8; BACKUP_SALT_LEN],
    magic: &[u8; 8],
) -> Result<SealedProfile> {
    let plaintext = snapshot::pack(udd).context("pack profile for backup")?;
    let fkek = *fkek;

    // Per-backup secrets, all from the OS CSPRNG. None of these are reused
    // across backups, so a repeated passphrase never repeats a keystream.
    let dek: [u8; DEK_LEN] = os_random()?;
    let wrap_nonce: [u8; WRAP_NONCE_LEN] = os_random()?;
    let stream_nonce_prefix: [u8; STREAM_NONCE_PREFIX_LEN] = os_random()?;
    let envelope_context_nonce: [u8; 16] = os_random()?;
    let signer = SigningKey::from_bytes(&os_random::<32>()?);

    let vk = signer.verifying_key().to_bytes();
    let params = BackupParams {
        ids: IntentIds {
            snapshot_id: local_id(profile_id, "snapshot"),
            tenant_id: local_id(profile_id, "tenant"),
            fleet_id: local_id(profile_id, "fleet"),
            profile_id: local_id(profile_id, "profile"),
            lease_id: local_id(profile_id, "lease"),
            manifest_replay_id: local_id(profile_id, "manifest-replay"),
            server_instance_id: local_id(profile_id, "server"),
            fkek_key_id: root_key_id(&fkek),
            intended_signer_signing_key_id: signing_key_id(&vk),
        },
        key_generation: 1,
        // A local backup is standalone: no prior version to chain from, so this
        // is always a genesis snapshot.
        target_version: 1,
        base_version: 0,
        fencing_token: 1,
        restore_epoch: 1,
        created_at_ms: now_ms(),
        envelope_context_nonce: &envelope_context_nonce,
        previous_signed_head_hash: None,
    };
    let secrets = BackupSecrets {
        fkek: &fkek,
        dek: &dek,
        wrap_nonce: &wrap_nonce,
        stream_nonce_prefix: &stream_nonce_prefix,
    };

    let mut sealed = Vec::new();
    backup::seal(&mut &plaintext[..], &mut sealed, &params, &secrets, &signer)
        .map_err(|e| anyhow!("seal backup: {e}"))?;

    // The verifying key travels with the file: a local backup has no directory
    // to look a signer up in, and `open` must be given the expected key id.
    let mut file = Vec::with_capacity(magic.len() + BACKUP_SALT_LEN + 32 + sealed.len());
    file.extend_from_slice(magic);
    file.extend_from_slice(&salt);
    file.extend_from_slice(&vk);
    file.extend_from_slice(&sealed);

    Ok(SealedProfile {
        info: BackupFileInfo {
            file_bytes: file.len() as u64,
            sha256: hex(&Sha256::digest(&file)),
            plaintext_bytes: plaintext.len() as u64,
        },
        bytes: file,
    })
}

/// Open `src` with `passphrase` and restore it over `udd`.
///
/// The whole plaintext is recovered and authenticated in memory before
/// `snapshot::unpack` runs, so a truncated or tampered file cannot leave a
/// half-written profile behind.
pub fn restore(src: &Path, udd: &Path, passphrase: &str) -> Result<u64> {
    let bytes = fs::read(src).with_context(|| format!("read backup {}", src.display()))?;
    open_profile(&bytes, udd, passphrase)
}

/// Open an in-memory container and restore it over `udd`.
///
/// This is `restore` without the file read, for containers that arrived from a
/// team server rather than from disk. Authentication and staging are identical.
pub fn open_profile(bytes: &[u8], udd: &Path, passphrase: &str) -> Result<u64> {
    let (salt, vk, body) = split_container(bytes, FILE_MAGIC)?;
    let fkek = derive_backup_fkek(passphrase, &salt).map_err(|e| anyhow!("{e}"))?;
    open_body(body, udd, &fkek, &vk)
}

/// Open a container sealed under a fleet key.
///
/// Used for profile sync, where the key comes from a fleet key grant rather
/// than from a passphrase the user typed.
pub fn open_profile_with_fkek(bytes: &[u8], udd: &Path, fkek: &[u8; 32]) -> Result<u64> {
    let (_salt, vk, body) = split_container(bytes, FLEET_FILE_MAGIC)?;
    open_body(body, udd, fkek, &vk)
}

/// Split a container into its salt, signer key and sealed body, checking the
/// magic first so the wrong kind of file is named as such.
fn split_container<'a>(
    bytes: &'a [u8],
    magic: &[u8; 8],
) -> Result<([u8; BACKUP_SALT_LEN], [u8; 32], &'a [u8])> {
    let header_len = magic.len() + BACKUP_SALT_LEN + 32;
    if bytes.len() < header_len {
        bail!("not a ShardX backup file: too short");
    }
    if &bytes[..magic.len()] != magic {
        if magic == FLEET_FILE_MAGIC && &bytes[..FILE_MAGIC.len()] == FILE_MAGIC {
            bail!("this is a passphrase-sealed backup, not a fleet snapshot");
        }
        if magic == FILE_MAGIC && &bytes[..FLEET_FILE_MAGIC.len()] == FLEET_FILE_MAGIC {
            bail!("this snapshot is sealed to a fleet key, not a passphrase");
        }
        bail!("not a ShardX backup file: bad magic");
    }

    let mut salt = [0u8; BACKUP_SALT_LEN];
    salt.copy_from_slice(&bytes[magic.len()..magic.len() + BACKUP_SALT_LEN]);
    let mut vk = [0u8; 32];
    vk.copy_from_slice(&bytes[magic.len() + BACKUP_SALT_LEN..header_len]);
    Ok((salt, vk, &bytes[header_len..]))
}

/// Decrypt a sealed body into `udd`.
fn open_body(body: &[u8], udd: &Path, fkek: &[u8; 32], vk: &[u8; 32]) -> Result<u64> {
    let fkek = *fkek;
    let vk = *vk;

    // Recover into memory. See the module note: `open` can emit plaintext
    // before it detects truncation, so nothing may touch the profile until
    // this returns Ok.
    let mut plaintext = Vec::new();
    backup::open(
        &mut Cursor::new(body),
        &mut plaintext,
        &fkek,
        &signing_key_id(&vk),
    )
    .map_err(|e| {
        anyhow!("could not open backup — wrong passphrase, or the file is damaged: {e}")
    })?;

    snapshot::unpack(&plaintext, udd).context("restore profile from backup")?;
    Ok(plaintext.len() as u64)
}

/// Inspect a backup file without a passphrase.
///
/// Only reads what is stored in the clear (magic and sizes) so the UI can
/// reject an obviously wrong file before prompting for a passphrase.
pub fn inspect(src: &Path) -> Result<BackupFileInfo> {
    let bytes = fs::read(src).with_context(|| format!("read backup {}", src.display()))?;
    let header_len = FILE_MAGIC.len() + BACKUP_SALT_LEN + 32;
    if bytes.len() < header_len || &bytes[..FILE_MAGIC.len()] != FILE_MAGIC {
        bail!("not a ShardX backup file");
    }
    Ok(BackupFileInfo {
        file_bytes: bytes.len() as u64,
        sha256: hex(&Sha256::digest(&bytes)),
        // Unknown without the passphrase; the plaintext length is authenticated
        // inside the sealed container, not exposed in the clear.
        plaintext_bytes: 0,
    })
}

fn write_atomic(dest: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = dest.with_extension("shxbak.part");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    // Windows rename fails if the destination exists.
    if dest.exists() {
        fs::remove_file(dest)?;
    }
    fs::rename(&tmp, dest)?;
    Ok(())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Write a tiny profile directory to seal.
    fn sample_profile(dir: &Path) {
        fs::create_dir_all(dir.join("Default")).expect("mkdir");
        fs::write(dir.join("Default").join("Preferences"), b"{\"k\":1}").expect("write");
    }

    /// A fleet-sealed snapshot round-trips under the same fleet key.
    #[test]
    fn a_fleet_snapshot_round_trips() {
        let tmp = std::env::temp_dir().join(format!("shx-fleet-rt-{}", std::process::id()));
        let src = tmp.join("src");
        let dst = tmp.join("dst");
        let _ = fs::remove_dir_all(&tmp);
        sample_profile(&src);

        let fkek = [0x31u8; 32];
        let sealed = seal_profile_with_fkek("p1", &src, &fkek).expect("seal");
        open_profile_with_fkek(&sealed.bytes, &dst, &fkek).expect("open");

        let restored = fs::read(dst.join("Default").join("Preferences")).expect("read");
        assert_eq!(restored, b"{\"k\":1}", "restored profile must match");
        let _ = fs::remove_dir_all(&tmp);
    }

    /// A different fleet key must not open the snapshot. This is the whole
    /// point of per-fleet keys: another fleet's key is simply a wrong key.
    #[test]
    fn another_fleet_key_cannot_open_it() {
        let tmp = std::env::temp_dir().join(format!("shx-fleet-wrong-{}", std::process::id()));
        let src = tmp.join("src");
        let dst = tmp.join("dst");
        let _ = fs::remove_dir_all(&tmp);
        sample_profile(&src);

        let sealed = seal_profile_with_fkek("p1", &src, &[0x31u8; 32]).expect("seal");
        let err = open_profile_with_fkek(&sealed.bytes, &dst, &[0x32u8; 32]);
        assert!(
            err.is_err(),
            "a foreign fleet key must not open the snapshot"
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    /// The two container kinds must not be confused for one another. Sending a
    /// passphrase file down the fleet path should say so, not report a bad key.
    #[test]
    fn the_two_container_kinds_are_told_apart() {
        let tmp = std::env::temp_dir().join(format!("shx-fleet-magic-{}", std::process::id()));
        let src = tmp.join("src");
        let dst = tmp.join("dst");
        let _ = fs::remove_dir_all(&tmp);
        sample_profile(&src);

        let by_passphrase = seal_profile("p1", &src, "correct horse").expect("seal");
        let err = open_profile_with_fkek(&by_passphrase.bytes, &dst, &[0x31u8; 32])
            .expect_err("must refuse");
        assert!(
            err.to_string().contains("passphrase-sealed"),
            "error should name the actual problem, got: {err}"
        );

        let by_fleet = seal_profile_with_fkek("p1", &src, &[0x31u8; 32]).expect("seal");
        let err = open_profile(&by_fleet.bytes, &dst, "correct horse").expect_err("must refuse");
        assert!(
            err.to_string().contains("fleet key"),
            "error should name the actual problem, got: {err}"
        );
        let _ = fs::remove_dir_all(&tmp);
    }
}
