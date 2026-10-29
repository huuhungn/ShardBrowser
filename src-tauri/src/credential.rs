//! Device keys in the OS credential store (ADR 0004).
//!
//! Each key is one credential: 32 raw bytes under the service
//! `shardx-launcher`, with its `credential_ref` as the user. Entries are
//! created with `persistence = Local`, because the Windows store's default,
//! `Enterprise`, roams with the profile and would put one device identity on
//! two machines. A key counts as stored only once it reads back unchanged.
//!
//! Where the OS store cannot take a key (no backend on this platform, or a
//! platform error), the key goes to the passphrase-protected key file instead
//! once the user opened it this run ([`crate::key_file`]). With neither, every
//! call fails with `credential.unavailable` and callers keep the key where it
//! was.

use anyhow::{anyhow, Result};
use zeroize::Zeroizing;

/// The service every launcher credential is filed under.
pub const SERVICE: &str = "shardx-launcher";

fn unavailable() -> anyhow::Error {
    anyhow!(crate::errcode::code("credential.unavailable"))
}

/// Sets the platform store as the default, once per process.
#[cfg(all(windows, not(test)))]
fn ensure_store() -> Result<()> {
    static STORE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let ready = *STORE.get_or_init(|| match windows_native_keyring_store::Store::new() {
        Ok(store) => {
            keyring_core::set_default_store(store);
            true
        }
        Err(_) => false,
    });
    if ready {
        Ok(())
    } else {
        Err(unavailable())
    }
}

#[cfg(all(not(windows), not(test)))]
fn ensure_store() -> Result<()> {
    Err(unavailable())
}

#[cfg(test)]
thread_local! {
    /// Makes this test thread's OS store unavailable, as on a platform
    /// without a backend.
    pub(crate) static OS_STORE_DOWN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Tests run against the in-memory mock store, on every platform.
#[cfg(test)]
fn ensure_store() -> Result<()> {
    static STORE: std::sync::Once = std::sync::Once::new();
    STORE.call_once(|| keyring_core::set_default_store(keyring_core::mock::Store::new().unwrap()));
    if OS_STORE_DOWN.with(|d| d.get()) {
        return Err(unavailable());
    }
    Ok(())
}

fn entry(credential_ref: &str) -> Result<keyring_core::Entry> {
    ensure_store()?;
    // The mock store takes no modifiers; the real one must never roam.
    #[cfg(not(test))]
    let entry = keyring_core::Entry::new_with_modifiers(
        SERVICE,
        credential_ref,
        &std::collections::HashMap::from([("persistence", "Local")]),
    );
    #[cfg(test)]
    let entry = keyring_core::Entry::new(SERVICE, credential_ref);
    entry.map_err(|_| unavailable())
}

/// Stores `key` under `credential_ref` and reads it back, in the OS store or
/// else the open key file. Only an exact read-back counts: on any failure the
/// caller keeps its own copy.
pub fn store(credential_ref: &str, key: &[u8; 32]) -> Result<()> {
    match os_store(credential_ref, key) {
        Err(_) if crate::key_file::is_open() => crate::key_file::store(credential_ref, key),
        result => result,
    }
}

fn os_store(credential_ref: &str, key: &[u8; 32]) -> Result<()> {
    let entry = entry(credential_ref)?;
    entry.set_secret(key).map_err(|_| unavailable())?;
    let back = Zeroizing::new(entry.get_secret().map_err(|_| unavailable())?);
    if back.as_slice() != key {
        return Err(anyhow!(crate::errcode::code("credential.readBackMismatch")));
    }
    Ok(())
}

/// The key under `credential_ref`, from the OS store or else the key file. A
/// missing credential is an error: a reference is only ever kept for a key
/// that was stored. A key file not yet opened this run is
/// `credential.locked`.
pub fn load(credential_ref: &str) -> Result<Zeroizing<[u8; 32]>> {
    match os_load(credential_ref) {
        Err(_) if crate::key_file::exists() => crate::key_file::load(credential_ref),
        result => result,
    }
}

fn os_load(credential_ref: &str) -> Result<Zeroizing<[u8; 32]>> {
    let secret = Zeroizing::new(match entry(credential_ref)?.get_secret() {
        Ok(secret) => secret,
        Err(keyring_core::Error::NoEntry) => {
            return Err(anyhow!(crate::errcode::code("credential.missing")))
        }
        Err(_) => return Err(unavailable()),
    });
    let mut key = Zeroizing::new([0u8; 32]);
    if secret.len() != key.len() {
        return Err(anyhow!(crate::errcode::code("credential.missing")));
    }
    key.copy_from_slice(&secret);
    Ok(key)
}

/// Deletes the credential under `credential_ref` from the OS store and the
/// open key file; one that is already gone counts as deleted.
pub fn forget(credential_ref: &str) -> Result<()> {
    // With no OS store, the key file was the only place it could be.
    let os = entry(credential_ref).map_or(Ok(()), |entry| match entry.delete_credential() {
        Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
        Err(_) => Err(unavailable()),
    });
    os.and(crate::key_file::forget(credential_ref))
}

/// Makes the next store call on `credential_ref` fail, as a locked or
/// unreachable store would.
#[cfg(test)]
pub(crate) fn fail_next_call(credential_ref: &str) {
    let entry = entry(credential_ref).unwrap();
    let mock: &keyring_core::mock::Cred = entry.as_any().downcast_ref().unwrap();
    mock.set_error(keyring_core::Error::Invalid(
        "store".into(),
        "locked".into(),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_round_trips_and_is_forgotten() {
        let key = [0xd8; 32];
        store("test-round-trip", &key).unwrap();
        assert_eq!(*load("test-round-trip").unwrap(), key);
        store("test-round-trip", &[7; 32]).unwrap();
        assert_eq!(*load("test-round-trip").unwrap(), [7; 32]);
        forget("test-round-trip").unwrap();
        let err = load("test-round-trip").unwrap_err();
        assert!(err.to_string().contains("credential.missing"), "{err}");
        forget("test-round-trip").unwrap();
    }

    #[test]
    fn references_are_separate_credentials() {
        store("test-a", &[1; 32]).unwrap();
        store("test-b", &[2; 32]).unwrap();
        assert_eq!(*load("test-a").unwrap(), [1; 32]);
        assert_eq!(*load("test-b").unwrap(), [2; 32]);
    }

    #[test]
    fn a_failed_write_or_read_back_is_reported() {
        let entry = entry("test-fail").unwrap();
        let mock: &keyring_core::mock::Cred = entry.as_any().downcast_ref().unwrap();
        mock.set_error(keyring_core::Error::Invalid(
            "store".into(),
            "locked".into(),
        ));
        assert!(store("test-fail", &[3; 32]).is_err());
        entry.set_secret(&[9; 31]).unwrap();
        let err = load("test-fail").unwrap_err();
        assert!(
            err.to_string().contains("credential.missing"),
            "a short secret is no key: {err}"
        );
    }

    // ---- G2-48 in a fresh process. The child is this test binary running an
    // ignored test (see `crate::crash_harness`); restart, a locked session and
    // a store made unavailable on the real machine are the manual check in
    // `scripts/g2-48-credential-check.ps1`.

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::Digest;
        sha2::Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn env(name: &str) -> Option<String> {
        std::env::var(name).ok()
    }

    /// The real Windows Credential Manager entry, built as `entry` builds it
    /// outside tests: service `shardx-launcher`, `persistence = Local`.
    #[cfg(windows)]
    fn real_entry(credential_ref: &str) -> keyring_core::Entry {
        use keyring_core::api::CredentialStoreApi;
        windows_native_keyring_store::Store::new()
            .unwrap()
            .build(
                SERVICE,
                credential_ref,
                Some(&std::collections::HashMap::from([("persistence", "Local")])),
            )
            .unwrap()
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "child process of the G2-48 check"]
    fn child_reads_and_deletes_the_real_credential() {
        let (Some(credential_ref), Some(digest)) =
            (env("SHARDX_G2_48_REF"), env("SHARDX_G2_48_SHA256"))
        else {
            return;
        };
        let entry = real_entry(&credential_ref);
        let secret = Zeroizing::new(entry.get_secret().unwrap());
        assert_eq!(sha256_hex(&secret), digest);
        assert_eq!(entry.get_attributes().unwrap()["persistence"], "Local");
        entry.delete_credential().unwrap();
        println!("G2-48-CHILD-OK");
    }

    /// A key stored in the real OS store by one process is read back exactly
    /// by a new process, filed as local (never roaming), and is gone for both
    /// once that process deletes it.
    #[cfg(windows)]
    #[test]
    fn a_real_os_store_key_survives_into_a_fresh_process() {
        let credential_ref = format!("g2-48-test-{}", uuid::Uuid::new_v4().simple());
        let mut key = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(&mut key[..]).unwrap();
        let entry = real_entry(&credential_ref);
        entry.set_secret(&key[..]).unwrap();
        let digest = sha256_hex(&key[..]);
        let child = crate::crash_harness::spawn(
            "credential::tests::child_reads_and_deletes_the_real_credential",
            "-",
            &[
                ("SHARDX_G2_48_REF", std::path::Path::new(&credential_ref)),
                ("SHARDX_G2_48_SHA256", std::path::Path::new(&digest)),
            ],
        );
        let read_back = crate::crash_harness::kill_after(child, "G2-48-CHILD-OK");
        let gone = matches!(entry.get_secret(), Err(keyring_core::Error::NoEntry));
        if !gone {
            let _ = entry.delete_credential();
        }
        assert!(read_back, "the fresh process did not read the key back");
        assert!(gone, "the fresh process did not delete the key");
    }

    #[test]
    #[ignore = "child process of the G2-48 check"]
    fn child_with_no_store_fails_closed() {
        let Some(root) = env("SHARDX_G2_48_ROOT") else {
            return;
        };
        crate::store::set_config_root(Some(root.into()));
        OS_STORE_DOWN.with(|d| d.set(true));
        let err = store("device-hpke.g2-48", &[5; 32]).unwrap_err();
        assert!(err.to_string().contains("credential.unavailable"), "{err}");
        let err = load("device-hpke.g2-48").unwrap_err();
        assert!(err.to_string().contains("credential.unavailable"), "{err}");
        println!("G2-48-CHILD-OK");
    }

    /// With no OS store and no key file a fresh process refuses to store or
    /// load a key, and writes nothing to disk: no insecure fallback.
    #[test]
    fn an_unavailable_store_fails_closed_in_a_fresh_process() {
        let root = tempfile::tempdir().unwrap();
        let child = crate::crash_harness::spawn(
            "credential::tests::child_with_no_store_fails_closed",
            "-",
            &[("SHARDX_G2_48_ROOT", root.path())],
        );
        assert!(crate::crash_harness::kill_after(child, "G2-48-CHILD-OK"));
        fn files(dir: &std::path::Path) -> usize {
            std::fs::read_dir(dir).map_or(0, |entries| {
                entries
                    .map(|e| e.unwrap().path())
                    .map(|p| if p.is_dir() { files(&p) } else { 1 })
                    .sum()
            })
        }
        assert_eq!(files(root.path()), 0, "something was written");
    }

    #[test]
    #[ignore = "child process of the G2-48 check"]
    fn child_unlocks_the_key_file() {
        let (Some(root), Some(digest)) = (env("SHARDX_G2_48_ROOT"), env("SHARDX_G2_48_SHA256"))
        else {
            return;
        };
        crate::store::set_config_root(Some(root.into()));
        OS_STORE_DOWN.with(|d| d.set(true));
        let err = load("device-hpke.g2-48").unwrap_err();
        assert!(err.to_string().contains("credential.locked"), "{err}");
        crate::key_file::unlock("g2-48 test passphrase").unwrap();
        assert_eq!(sha256_hex(&load("device-hpke.g2-48").unwrap()[..]), digest);
        println!("G2-48-CHILD-OK");
    }

    #[test]
    #[ignore = "child process of the G2-48 check"]
    fn child_files_a_key_in_the_key_file() {
        let Some(root) = env("SHARDX_G2_48_ROOT") else {
            return;
        };
        crate::store::set_config_root(Some(root.into()));
        OS_STORE_DOWN.with(|d| d.set(true));
        crate::key_file::create("g2-48 test passphrase").unwrap();
        store("device-hpke.g2-48", &[0x48; 32]).unwrap();
        println!("G2-48-CHILD-OK");
    }

    /// A key that went to the key file because the OS store was unavailable
    /// is there for a fresh process, locked until the passphrase opens it.
    /// Both runs are child processes: the config root and the open key file
    /// are process-global, and a locked file under the root would fail the
    /// other credential tests running beside this one.
    #[test]
    fn a_key_file_key_is_locked_then_served_in_a_fresh_process() {
        let root = tempfile::tempdir().unwrap();
        let child = crate::crash_harness::spawn(
            "credential::tests::child_files_a_key_in_the_key_file",
            "-",
            &[("SHARDX_G2_48_ROOT", root.path())],
        );
        assert!(crate::crash_harness::kill_after(child, "G2-48-CHILD-OK"));
        let child = crate::crash_harness::spawn(
            "credential::tests::child_unlocks_the_key_file",
            "-",
            &[
                ("SHARDX_G2_48_ROOT", root.path()),
                (
                    "SHARDX_G2_48_SHA256",
                    std::path::Path::new(&sha256_hex(&[0x48; 32])),
                ),
            ],
        );
        assert!(crate::crash_harness::kill_after(child, "G2-48-CHILD-OK"));
    }
}
