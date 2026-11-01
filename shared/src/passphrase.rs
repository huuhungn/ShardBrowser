//! Passphrase-derived file key encryption key (FKEK) for local backups.
//!
//! A local backup has no server and no device enrolment to lean on, so the FKEK
//! comes from something the user knows. The point of a backup is that it opens
//! on a *different* machine — a key sealed into this machine's keystore would
//! make the backup worthless in the case it exists for — so nothing here is
//! persisted except a random salt, which is stored in the clear alongside the
//! container and is not secret.
//!
//! Argon2id, because the threat is an offline attacker with the backup file and
//! unlimited guesses. A fast KDF (PBKDF2 at typical iteration counts, or a bare
//! hash) would let commodity GPUs run through a human-chosen passphrase list;
//! Argon2id's memory cost is what makes that expensive per guess.

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

/// Salt length. 16 bytes is the Argon2 recommendation; it only needs to be
/// unique per backup, not secret.
pub const BACKUP_SALT_LEN: usize = 16;

/// Domain separator, so a passphrase stretched here can never collide with the
/// same passphrase stretched for some other future purpose.
pub const BACKUP_KDF_CONTEXT: &[u8] = b"SHARDX-LOCAL-BACKUP-FKEK-V1\0";

/// Argon2id cost parameters.
///
/// 64 MiB / 3 passes / 1 lane. Chosen to stay usable on the low-end laptops the
/// Launcher targets while keeping GPU cracking costly. These values are part of
/// the on-disk format: changing them makes existing backups underivable, so a
/// change needs a new format version, not an edit here.
///
/// Recorded deviation (G2-46): the plan's profile (L1375) has 4 lanes, and the
/// recovery bundle and the fallback key file use it
/// (`recovery_bundle::argon2id_kek`). v1 local backups predate it and keep 1
/// lane; a v2 backup format moves to the plan's profile.
const MEMORY_KIB: u32 = 64 * 1024;
const ITERATIONS: u32 = 3;
const LANES: u32 = 1;

#[derive(Debug)]
pub enum PassphraseError {
    /// The passphrase is empty or shorter than the minimum.
    TooShort,
    /// Argon2 rejected the parameters or failed to produce output.
    Kdf,
}

impl std::fmt::Display for PassphraseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(
                f,
                "backup passphrase must be at least {MIN_PASSPHRASE_LEN} characters"
            ),
            Self::Kdf => write!(f, "could not derive a key from the passphrase"),
        }
    }
}

impl std::error::Error for PassphraseError {}

/// Minimum passphrase length.
///
/// This is a guard against an empty or trivially short passphrase, not a claim
/// that 8 characters is sufficient. Argon2id's cost is what carries the
/// security here; length guidance belongs in the UI.
pub const MIN_PASSPHRASE_LEN: usize = 8;

/// Derive a 32-byte FKEK from a passphrase and a per-backup salt.
///
/// The result is `Zeroizing`, so it is wiped when dropped. Callers must not
/// copy it into a plain array that outlives the backup operation.
pub fn derive_backup_fkek(
    passphrase: &str,
    salt: &[u8; BACKUP_SALT_LEN],
) -> Result<Zeroizing<[u8; 32]>, PassphraseError> {
    if passphrase.chars().count() < MIN_PASSPHRASE_LEN {
        return Err(PassphraseError::TooShort);
    }

    let params =
        Params::new(MEMORY_KIB, ITERATIONS, LANES, Some(32)).map_err(|_| PassphraseError::Kdf)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Bind the derivation to this purpose by prefixing the salt with a domain
    // separator, rather than trusting every future caller to pick a distinct
    // salt space.
    let mut salted = Vec::with_capacity(BACKUP_KDF_CONTEXT.len() + BACKUP_SALT_LEN);
    salted.extend_from_slice(BACKUP_KDF_CONTEXT);
    salted.extend_from_slice(salt);

    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase.as_bytes(), &salted, out.as_mut())
        .map_err(|_| PassphraseError::Kdf)?;

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn salt(byte: u8) -> [u8; BACKUP_SALT_LEN] {
        [byte; BACKUP_SALT_LEN]
    }

    #[test]
    fn derivation_is_deterministic_for_the_same_passphrase_and_salt() {
        let a = derive_backup_fkek("correct horse battery", &salt(1)).expect("derive");
        let b = derive_backup_fkek("correct horse battery", &salt(1)).expect("derive");
        assert_eq!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn a_different_salt_yields_a_different_key() {
        // Two users with the same passphrase must not share an FKEK, which is
        // the whole reason the salt is stored per backup.
        let a = derive_backup_fkek("correct horse battery", &salt(1)).expect("derive");
        let b = derive_backup_fkek("correct horse battery", &salt(2)).expect("derive");
        assert_ne!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn a_different_passphrase_yields_a_different_key() {
        let a = derive_backup_fkek("correct horse battery", &salt(1)).expect("derive");
        let b = derive_backup_fkek("correct horse batterz", &salt(1)).expect("derive");
        assert_ne!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn a_short_passphrase_is_refused() {
        assert!(matches!(
            derive_backup_fkek("short", &salt(1)),
            Err(PassphraseError::TooShort)
        ));
        assert!(matches!(
            derive_backup_fkek("", &salt(1)),
            Err(PassphraseError::TooShort)
        ));
    }

    #[test]
    fn length_is_counted_in_characters_not_bytes() {
        // A 8-character Vietnamese passphrase is 8 characters even though it is
        // more than 8 bytes in UTF-8. Counting bytes would accept a shorter
        // passphrase than the rule claims.
        assert!(derive_backup_fkek("mậtkhẩu1", &salt(1)).is_ok());
        // Seven characters must still be refused however many bytes they take.
        assert!(matches!(
            derive_backup_fkek("mậtkhẩu", &salt(1)),
            Err(PassphraseError::TooShort)
        ));
    }

    #[test]
    fn the_domain_separator_is_part_of_the_derivation() {
        // Guards the format: deriving with the raw salt (no context prefix)
        // must not produce the same key, or the domain separation is decorative.
        let params = Params::new(MEMORY_KIB, ITERATIONS, LANES, Some(32)).expect("params");
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut raw = [0u8; 32];
        argon
            .hash_password_into(b"correct horse battery", &salt(1), &mut raw)
            .expect("hash");

        let derived = derive_backup_fkek("correct horse battery", &salt(1)).expect("derive");
        assert_ne!(derived.as_ref(), &raw);
    }
}
