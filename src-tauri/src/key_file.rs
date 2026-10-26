//! The passphrase-protected key file, `keys-fallback.bin` (ADR 0002 D-5,
//! G2-48): where device keys go when the OS credential store cannot take them.
//!
//! The file is opened once per run with the passphrase the user types; the
//! keys and the passphrase then stay in this process's memory only, so a
//! later key can be added by sealing the whole file again. Every write is
//! read back and opened before it counts, as with the OS store.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use shardx_core::fallback_key_file::{self as file, FallbackEntry, KeyKind};
use zeroize::Zeroizing;

use crate::store;

struct Unlocked {
    /// The config root the file was opened under. Tests point the root at a
    /// fresh directory; keys of another root are never served.
    root: PathBuf,
    passphrase: Zeroizing<String>,
    keys: BTreeMap<String, (KeyKind, Zeroizing<[u8; 32]>)>,
}

static OPEN: Mutex<Option<Unlocked>> = Mutex::new(None);

/// Failed unlock attempts and when the next one is allowed (plan 9.5:
/// rate-limit local attempts).
static FAILURES: Mutex<(u32, Option<Instant>)> = Mutex::new((0, None));
const MAX_WAIT: Duration = Duration::from_secs(60);

fn code(c: &str) -> anyhow::Error {
    anyhow!(crate::errcode::code(c))
}

pub fn path() -> Result<PathBuf> {
    Ok(store::config_root()?
        .join("team-sync")
        .join("keys-fallback.bin"))
}

/// Whether this device has a key file.
pub fn exists() -> bool {
    path().is_ok_and(|p| p.exists())
}

/// Whether the key file of the current config root is open in this run.
pub fn is_open() -> bool {
    let root = store::config_root().ok();
    OPEN.lock()
        .unwrap_or_else(|p| p.into_inner())
        .as_ref()
        .is_some_and(|u| Some(&u.root) == root.as_ref())
}

/// What a reference holds, from its name: the key file records the kind.
fn kind_of(credential_ref: &str) -> Option<KeyKind> {
    let prefix = credential_ref.split('.').next()?;
    Some(match prefix {
        "device-signing" => KeyKind::Signing,
        "device-hpke" => KeyKind::Hpke,
        "fleet-key" => KeyKind::Fkek,
        "tenant-root" => KeyKind::Trk,
        _ => return None,
    })
}

/// Seals `keys`, writes the file durably, reads it back and checks that it
/// opens to exactly `keys`.
fn write(
    root: &std::path::Path,
    passphrase: &str,
    keys: &BTreeMap<String, (KeyKind, Zeroizing<[u8; 32]>)>,
) -> Result<()> {
    let entries: Vec<FallbackEntry> = keys
        .iter()
        .map(|(r, (kind, key))| FallbackEntry {
            credential_ref: r.clone(),
            key_kind: *kind,
            key_bytes: key.clone(),
        })
        .collect();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    let bytes = file::seal(&entries, passphrase, now).map_err(|e| anyhow!(e.to_string()))?;
    let path = root.join("team-sync").join("keys-fallback.bin");
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    crate::root_bootstrap::write_durably(&path, &bytes)?;
    let back = std::fs::read(&path)?;
    let (_, opened) =
        file::open(&back, passphrase).map_err(|_| code("credential.readBackMismatch"))?;
    if !same_keys(&opened, keys) {
        return Err(code("credential.readBackMismatch"));
    }
    Ok(())
}

/// Whether a file read back holds exactly `keys`: no key more, none less, and
/// each with its kind and bytes.
fn same_keys(
    opened: &[FallbackEntry],
    keys: &BTreeMap<String, (KeyKind, Zeroizing<[u8; 32]>)>,
) -> bool {
    opened.len() == keys.len()
        && opened.iter().all(|e| {
            keys.get(&e.credential_ref)
                .is_some_and(|(kind, key)| *kind == e.key_kind && **key == *e.key_bytes)
        })
}

/// Creates an empty key file under `passphrase` and opens it. Refused when
/// the device already has one: that file is unlocked instead.
pub fn create(passphrase: &str) -> Result<()> {
    if exists() {
        return Err(code("credential.keyFileExists"));
    }
    if passphrase.chars().count() < shardx_core::passphrase::MIN_PASSPHRASE_LEN {
        return Err(code("credential.keyFilePassphraseTooShort"));
    }
    let root = store::config_root()?;
    write(&root, passphrase, &BTreeMap::new())?;
    *OPEN.lock().unwrap_or_else(|p| p.into_inner()) = Some(Unlocked {
        root,
        passphrase: Zeroizing::new(passphrase.to_string()),
        keys: BTreeMap::new(),
    });
    Ok(())
}

/// Opens the key file with `passphrase`. A wrong passphrase doubles the wait
/// before the next attempt, up to a minute.
pub fn unlock(passphrase: &str) -> Result<()> {
    let mut failures = FAILURES.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(until) = failures.1 {
        let now = Instant::now();
        if now < until {
            let seconds = (until - now).as_secs() + 1;
            return Err(anyhow!(crate::errcode::code_with(
                "credential.keyFileWait",
                &[("seconds", &seconds.to_string())]
            )));
        }
    }
    let path = path()?;
    let bytes = std::fs::read(&path).map_err(|_| code("credential.keyFileMissing"))?;
    match file::open(&bytes, passphrase) {
        Ok((_, entries)) => {
            *failures = (0, None);
            let keys = entries
                .into_iter()
                .map(|e| (e.credential_ref, (e.key_kind, e.key_bytes)))
                .collect();
            *OPEN.lock().unwrap_or_else(|p| p.into_inner()) = Some(Unlocked {
                root: store::config_root()?,
                passphrase: Zeroizing::new(passphrase.to_string()),
                keys,
            });
            Ok(())
        }
        Err(file::FallbackKeyFileError::Decrypt) => {
            failures.0 += 1;
            let wait = Duration::from_secs(1 << (failures.0 - 1).min(6)).min(MAX_WAIT);
            failures.1 = Some(Instant::now() + wait);
            Err(code("credential.keyFileWrongPassphrase"))
        }
        Err(e) => Err(anyhow!(crate::errcode::code_with(
            "credential.keyFileUnreadable",
            &[("error", &e.to_string())]
        ))),
    }
}

/// Forgets the open file's keys and passphrase in this run.
#[cfg(test)]
pub fn close() {
    *OPEN.lock().unwrap_or_else(|p| p.into_inner()) = None;
    *FAILURES.lock().unwrap_or_else(|p| p.into_inner()) = (0, None);
}

/// Runs `f` on the open file of the current config root, or fails with
/// `credential.locked` when the file exists but is not open, and
/// `credential.unavailable` when there is none.
fn with_open<T>(f: impl FnOnce(&mut Unlocked) -> Result<T>) -> Result<T> {
    let root = store::config_root()?;
    let mut open = OPEN.lock().unwrap_or_else(|p| p.into_inner());
    match open.as_mut() {
        Some(u) if u.root == root => f(u),
        _ if exists() => Err(code("credential.locked")),
        _ => Err(code("credential.unavailable")),
    }
}

pub fn store(credential_ref: &str, key: &[u8; 32]) -> Result<()> {
    let kind = kind_of(credential_ref).ok_or_else(|| code("credential.unavailable"))?;
    with_open(|u| {
        let mut keys = u.keys.clone();
        keys.insert(credential_ref.to_string(), (kind, Zeroizing::new(*key)));
        write(&u.root, &u.passphrase, &keys)?;
        u.keys = keys;
        Ok(())
    })
}

pub fn load(credential_ref: &str) -> Result<Zeroizing<[u8; 32]>> {
    with_open(|u| {
        u.keys
            .get(credential_ref)
            .map(|(_, key)| key.clone())
            .ok_or_else(|| code("credential.missing"))
    })
}

/// Removes the key from the open file. With no file, or a locked one, there
/// is nothing this run can remove.
pub fn forget(credential_ref: &str) -> Result<()> {
    match with_open(|u| {
        if u.keys.contains_key(credential_ref) {
            let mut keys = u.keys.clone();
            keys.remove(credential_ref);
            write(&u.root, &u.passphrase, &keys)?;
            u.keys = keys;
        }
        Ok(())
    }) {
        Err(e) if e.to_string().contains("credential.unavailable") => Ok(()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::team_config::{self, TeamConfig};

    const PASS: &str = "correct horse battery";

    fn err(r: Result<impl std::fmt::Debug>) -> String {
        r.unwrap_err().to_string()
    }

    #[test]
    fn keys_the_os_store_refuses_go_to_the_key_file_once_it_is_open() {
        let _guard = store::config_root_test_lock()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().unwrap();
        store::set_config_root(Some(dir.path().to_path_buf()));
        crate::credential::OS_STORE_DOWN.with(|d| d.set(true));
        close();
        let mut c = TeamConfig {
            device_id: "ee".repeat(16),
            signing_key_seed: "66".repeat(32),
            hpke_key_seed: "77".repeat(32),
            ..Default::default()
        };
        team_config::save(&c).unwrap();

        // No store and no key file: the seeds stay, and the UI is told.
        assert!(!team_config::protect_keys(&mut c).unwrap());
        let s = team_config::status().unwrap();
        assert!(!s.keys_protected && !s.has_key_file && !s.keys_locked);

        assert!(err(create("seven77")).contains("credential.keyFilePassphraseTooShort"));
        create(PASS).unwrap();
        assert!(team_config::protect_keys(&mut c).unwrap());
        let saved = team_config::load().unwrap();
        assert!(saved.signing_key_seed.is_empty() && saved.hpke_key_seed.is_empty());
        assert_eq!(saved.signing_key().unwrap().to_bytes(), [0x66; 32]);
        let s = team_config::status().unwrap();
        assert!(s.keys_protected && s.has_key_file && !s.keys_locked);
        assert!(err(create(PASS)).contains("credential.keyFileExists"));

        // A new run starts locked; the keys come back only with the passphrase.
        close();
        assert!(team_config::status().unwrap().keys_locked);
        assert!(err(saved.signing_key().map(|_| ())).contains("credential.locked"));
        assert!(
            err(crate::credential::load(&saved.hpke_credential_ref)).contains("credential.locked")
        );
        assert!(err(unlock("wrong horse battery")).contains("credential.keyFileWrongPassphrase"));
        assert!(err(unlock(PASS)).contains("credential.keyFileWait"));
        std::thread::sleep(Duration::from_millis(1100));
        unlock(PASS).unwrap();
        assert_eq!(saved.hpke_seed().unwrap(), [0x77; 32]);

        // Forgetting a key rewrites the file without it.
        crate::credential::forget(&saved.hpke_credential_ref).unwrap();
        close();
        unlock(PASS).unwrap();
        assert!(
            err(crate::credential::load(&saved.hpke_credential_ref)).contains("credential.missing")
        );
        assert_eq!(saved.signing_key().unwrap().to_bytes(), [0x66; 32]);

        // Another config root never sees this run's open file.
        let other = tempfile::tempdir().unwrap();
        store::set_config_root(Some(other.path().to_path_buf()));
        assert!(!is_open());
        assert!(err(crate::credential::store("device-hpke.x", &[1; 32]))
            .contains("credential.unavailable"));

        close();
        crate::credential::OS_STORE_DOWN.with(|d| d.set(false));
        store::set_config_root(None);
    }

    #[test]
    fn a_read_back_counts_only_with_exactly_the_written_keys() {
        let entry = |r: &str, kind, byte| FallbackEntry {
            credential_ref: r.into(),
            key_kind: kind,
            key_bytes: Zeroizing::new([byte; 32]),
        };
        let keys = BTreeMap::from([
            ("a".to_string(), (KeyKind::Trk, Zeroizing::new([1; 32]))),
            ("b".to_string(), (KeyKind::Fkek, Zeroizing::new([2; 32]))),
        ]);
        let written = [entry("a", KeyKind::Trk, 1), entry("b", KeyKind::Fkek, 2)];
        assert!(same_keys(&written, &keys));
        assert!(!same_keys(&written[..1], &keys), "a key less");
        assert!(!same_keys(
            &[entry("a", KeyKind::Trk, 1), entry("b", KeyKind::Fkek, 3)],
            &keys
        ));
        assert!(!same_keys(
            &[entry("a", KeyKind::Hpke, 1), entry("b", KeyKind::Fkek, 2)],
            &keys
        ));
        assert!(!same_keys(
            &[entry("a", KeyKind::Trk, 1), entry("c", KeyKind::Fkek, 2)],
            &keys
        ));
    }

    #[test]
    fn a_reference_of_no_known_kind_is_not_written() {
        assert_eq!(kind_of("device-signing.ab"), Some(KeyKind::Signing));
        assert_eq!(kind_of("fleet-key.ab.2"), Some(KeyKind::Fkek));
        assert_eq!(kind_of("tenant-root.ab"), Some(KeyKind::Trk));
        assert_eq!(kind_of("device-hpke.ab"), Some(KeyKind::Hpke));
        assert_eq!(kind_of("profile.ab"), None);
    }
}
