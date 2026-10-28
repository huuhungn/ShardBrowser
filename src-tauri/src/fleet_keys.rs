//! Fleet keys this device has collected from its grants.
//!
//! A fleet key (FKEK) is what actually opens profile snapshots. It arrives
//! sealed to this device's HPKE key inside a fleet key grant; once opened it
//! is cached here so sync does not need a passphrase.
//!
//! Two deliberate choices:
//!
//! 1. **Separate from `team.json`.** That file is round-tripped by the
//!    Settings page. Key material must not sit in a struct a partial UI save
//!    could rewrite.
//! 2. **Keyed by generation.** Rotation issues a new generation; snapshots
//!    sealed under the old one must stay readable, so old keys are kept rather
//!    than replaced.
//!
//! A collected key is written to this file first, so it is durable before
//! anything else happens, and then moved into the OS credential store (ADR
//! 0004): the file keeps only its reference once the key read back. While no
//! store is usable the key stays here, and the file is as sensitive as the
//! profiles it opens: 0600 on Unix, and DPAPI-protected on Windows (see
//! `dpapi`).
//!
//! Since 2.4.3 a fleet key the team server delivers is cached only once its
//! grant verifies against the tenant trust chain, as the W6 trust ledger lets
//! this device see it (`open_fleet_grant`, `team::ledger`), and never over
//! another key held for the same generation (`collect`). Sync pull uses such
//! a key only after reverifying the exact grant the team database keeps with
//! it (G2-35, `keys_newest_first`). Keys cached by 2.4.2 still open old
//! snapshots.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::sync::Mutex;

use crate::{dpapi, store};
use zeroize::Zeroizing;

/// Serialises writes, so a migration rewrite cannot land on top of a newer
/// save with the content it read before that save.
static WRITE_LOCK: Mutex<()> = Mutex::new(());

/// One fleet's collected keys, by generation.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct FleetKeys {
    /// Generation number to hex-encoded 32-byte key.
    #[serde(default)]
    pub keys: BTreeMap<u64, String>,
    /// Generation number to the key's reference in the OS credential store,
    /// once it left `keys`.
    #[serde(default)]
    pub credential_refs: BTreeMap<u64, String>,
    /// Generation sync should seal new snapshots under. Reading still tries
    /// every generation, because an older snapshot is still valid.
    #[serde(default)]
    pub active_generation: u64,
    /// Generations collected from a verified grant (`collect`), which sync
    /// uses only while that grant still verifies (`keys_newest_first`). Keys
    /// cached by 2.4.2 are not listed and keep their use.
    #[serde(default)]
    pub verified: BTreeSet<u64>,
}

/// All fleets this device holds keys for, by hex fleet id.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FleetKeyStore {
    #[serde(default)]
    pub fleets: BTreeMap<String, FleetKeys>,
}

impl FleetKeyStore {
    /// The active generation's key. Sync no longer seals under it (push uses
    /// the passphrase), so only the tests still ask.
    #[cfg(test)]
    pub fn active_key(&self, fleet_id: &str) -> Option<([u8; 32], u64)> {
        let f = self.fleets.get(fleet_id)?;
        f.key(f.active_generation)
            .map(|k| (*k, f.active_generation))
    }

    /// Every key this device holds for a fleet, newest generation first. A
    /// key from a verified grant is listed only when `still_verifies` says
    /// its grant does now: the `verified` flag grants nothing (G2-35, plan
    /// L2056).
    ///
    /// Restore tries these in turn: a snapshot pushed before a rotation is
    /// still sealed under the older generation and must stay readable.
    pub fn keys_newest_first(
        &self,
        fleet_id: &str,
        still_verifies: impl Fn(u64, &[u8; 32]) -> bool,
    ) -> Vec<([u8; 32], u64)> {
        let Some(f) = self.fleets.get(fleet_id) else {
            return Vec::new();
        };
        let generations: std::collections::BTreeSet<u64> = f
            .keys
            .keys()
            .chain(f.credential_refs.keys())
            .copied()
            .collect();
        let mut out: Vec<_> = generations
            .into_iter()
            .filter_map(|g| f.key(g).map(|k| (*k, g)))
            .filter(|(k, g)| !f.verified.contains(g) || still_verifies(*g, k))
            .collect();
        out.sort_by_key(|(_, generation)| std::cmp::Reverse(*generation));
        out
    }

    /// Record a collected key.
    pub fn insert(&mut self, fleet_id: &str, generation: u64, key: &[u8; 32]) {
        let f = self.fleets.entry(fleet_id.to_string()).or_default();
        f.keys.insert(generation, to_hex(key));
        if generation >= f.active_generation {
            f.active_generation = generation;
        }
    }

    fn map_keys(&self, f: impl Fn(&str) -> Result<String>) -> Result<Self> {
        let mut out = self.clone();
        for keys in out.fleets.values_mut() {
            for value in keys.keys.values_mut() {
                *value = f(value)?;
            }
        }
        Ok(out)
    }

    fn has_plaintext_keys(&self) -> bool {
        self.fleets
            .values()
            .flat_map(|f| f.keys.values())
            .any(|v| dpapi::needs_protection(v))
    }
}

/// Lists generations, never key bytes (G2-47).
impl std::fmt::Debug for FleetKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FleetKeys")
            .field("keys", &self.keys.keys().collect::<Vec<_>>())
            .field("credential_refs", &self.credential_refs)
            .field("active_generation", &self.active_generation)
            .field("verified", &self.verified)
            .finish()
    }
}

impl FleetKeys {
    /// The key of `generation`: from the file while it is still there (the
    /// newer copy), else from the credential store. A key that cannot be read
    /// is treated as not held.
    fn key(&self, generation: u64) -> Option<Zeroizing<[u8; 32]>> {
        match (
            self.keys.get(&generation),
            self.credential_refs.get(&generation),
        ) {
            (Some(hex), _) => decode_key(hex).ok().map(Zeroizing::new),
            (None, Some(reference)) => crate::credential::load(reference).ok(),
            (None, None) => None,
        }
    }
}

/// Hex-encode a key for storage.
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_key(h: &str) -> Result<[u8; 32]> {
    if !h.len().is_multiple_of(2) {
        anyhow::bail!(crate::errcode::code("fleetKeys.notValidHex"));
    }
    let raw: Vec<u8> = (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16))
        .collect::<std::result::Result<_, _>>()
        .context(crate::errcode::code("fleetKeys.notValidHex"))?;
    let arr: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!(crate::errcode::code("fleetKeys.wrongLength")))?;
    Ok(arr)
}

pub fn load() -> Result<FleetKeyStore> {
    let path = store::fleet_keys_path()?;
    if !path.exists() {
        return Ok(FleetKeyStore::default());
    }
    let mut stored = read(&path)?;
    if stored.has_plaintext_keys() {
        // Written before keys were protected: rewrite it now. Re-read under
        // the lock, since a save may have landed; best effort, so a failure
        // leaves the file as it was.
        let _guard = WRITE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        stored = read(&path)?;
        if stored.has_plaintext_keys() {
            let _ = write(&stored);
        }
    }
    stored.map_keys(|v| Ok(dpapi::reveal(v)))
}

/// The file as stored: keys still in their on-disk form. A file that does
/// not parse is an error, never an empty store, so no writer replaces the
/// keys it may still hold.
fn read(path: &std::path::Path) -> Result<FleetKeyStore> {
    let body = fs::read_to_string(path)?;
    serde_json::from_str(&body).context(crate::errcode::code("sync.fleetKeyStoreUnreadable"))
}

/// Writes `s`, then moves its plaintext keys into the credential store. The
/// keys are durable once written, so the move is best effort. Only the tests
/// save a whole store; `collect` adds one key.
#[cfg(test)]
pub fn save(s: &FleetKeyStore) -> Result<()> {
    {
        let _guard = WRITE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        write(s)?;
    }
    if let Err(error) = protect() {
        eprintln!("[fleet] fleet keys stay in fleet_keys.json: {error}");
    }
    Ok(())
}

/// Keeps `key`, opened from a verified grant, as `generation` of `fleet_id`,
/// marked `verified`. Returns false, and saves nothing, when the store
/// already holds a different key for that generation, or one it cannot read
/// (ADR 0002 trust chain, rule 5: `KEY_SUBSTITUTION_DETECTED`). Reads, checks
/// and writes under one lock, and refuses a store that does not parse.
pub fn collect(fleet_id: &str, generation: u64, key: &[u8; 32]) -> Result<bool> {
    {
        let _guard = WRITE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let path = store::fleet_keys_path()?;
        let mut s = if path.exists() {
            read(&path)?.map_keys(|v| Ok(dpapi::reveal(v)))?
        } else {
            FleetKeyStore::default()
        };
        if let Some(f) = s.fleets.get(fleet_id) {
            if f.keys.contains_key(&generation) || f.credential_refs.contains_key(&generation) {
                return Ok(f.key(generation).is_some_and(|held| *held == *key));
            }
        }
        s.insert(fleet_id, generation, key);
        if let Some(f) = s.fleets.get_mut(fleet_id) {
            f.verified.insert(generation);
        }
        write(&s)?;
    }
    if let Err(error) = protect() {
        eprintln!("[fleet] fleet keys stay in fleet_keys.json: {error}");
    }
    Ok(true)
}

/// Moves every plaintext key in the saved file into the OS credential store,
/// and rewrites the file without the keys that read back. Returns whether
/// any key moved.
// shortcut: with no usable store the keys stay in plaintext `fleet_keys.json`
// until the fallback key file (ADR 0002, G2-48) lands.
pub fn protect() -> Result<bool> {
    let _guard = WRITE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let path = store::fleet_keys_path()?;
    if !path.exists() {
        return Ok(false);
    }
    let mut s = read(&path)?.map_keys(|v| Ok(dpapi::reveal(v)))?;
    let mut moved = false;
    for (fleet_id, f) in &mut s.fleets {
        for (generation, hex) in std::mem::take(&mut f.keys) {
            let name = format!("fleet-key.{fleet_id}.{generation}");
            let stored = decode_key(&hex)
                .map(Zeroizing::new)
                .is_ok_and(|key| crate::credential::store(&name, &key).is_ok());
            if stored {
                f.credential_refs.insert(generation, name);
                moved = true;
            } else {
                f.keys.insert(generation, hex);
            }
        }
    }
    if moved {
        write(&s)?;
    }
    Ok(moved)
}

/// Write `s` with its keys protected. Callers hold `WRITE_LOCK`.
fn write(s: &FleetKeyStore) -> Result<()> {
    let path = store::fleet_keys_path()?;
    let on_disk = s.map_keys(dpapi::conceal)?;
    // As with team.json: a crash mid-write must not leave a file that reads
    // back as "no keys" and silently strands the snapshots.
    crate::durable::write_private(&path, serde_json::to_string_pretty(&on_disk)?.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Newer generations take over as active, and older ones stay readable.
    #[test]
    fn a_newer_generation_becomes_active_without_dropping_the_old_key() {
        let mut s = FleetKeyStore::default();
        s.insert("ab", 1, &[0x11u8; 32]);
        s.insert("ab", 2, &[0x22u8; 32]);

        let (key, gen) = s.active_key("ab").expect("active key");
        assert_eq!(gen, 2, "newest generation must be active");
        assert_eq!(key, [0x22u8; 32]);

        let all = s.keys_newest_first("ab", |_, _| false);
        assert_eq!(all.len(), 2, "the older key must be kept for old snapshots");
        assert_eq!(all[0].1, 2, "newest first");
        assert_eq!(all[1].1, 1);
    }

    /// A late-arriving older grant must not demote the active generation.
    #[test]
    fn collecting_an_older_grant_does_not_demote_the_active_generation() {
        let mut s = FleetKeyStore::default();
        s.insert("ab", 5, &[0x55u8; 32]);
        s.insert("ab", 3, &[0x33u8; 32]);
        let (_k, gen) = s.active_key("ab").expect("active key");
        assert_eq!(gen, 5, "an older grant must not become active");
    }

    /// A store that does not parse is refused by every reader and writer and
    /// left byte for byte as it was, so no 2.4.2 key is lost.
    #[test]
    fn an_unparseable_store_is_never_overwritten() {
        let _guard = store::config_root_test_lock()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().unwrap();
        store::set_config_root(Some(dir.path().to_path_buf()));
        let path = store::fleet_keys_path().unwrap();
        let body = br#"{"fleets": {"ab": {"keys": {"1": "#;
        fs::write(&path, body).unwrap();
        let collected = collect("ab", 1, &[0x61; 32]);
        let loaded = load();
        let protected = protect();
        let after = fs::read(&path).unwrap();
        store::set_config_root(None);
        assert!(collected.is_err());
        assert!(loaded.is_err());
        assert!(protected.is_err());
        assert_eq!(after, body);
    }

    #[test]
    fn saved_keys_move_to_the_credential_store_and_still_open() {
        let _guard = store::config_root_test_lock()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().unwrap();
        store::set_config_root(Some(dir.path().to_path_buf()));
        let fleet = "ef".repeat(16);
        let mut s = FleetKeyStore::default();
        s.insert(&fleet, 1, &[0x61; 32]);
        s.insert(&fleet, 2, &[0x62; 32]);
        crate::credential::fail_next_call(&format!("fleet-key.{fleet}.1"));
        save(&s).unwrap();

        // Generation 1 was refused by the store and stays in the file.
        let saved = load().unwrap();
        let body = fs::read_to_string(store::fleet_keys_path().unwrap()).unwrap();
        assert!(!body.contains(&"62".repeat(32)), "{body}");
        // On Windows the key left in the file is a DPAPI blob, never plaintext.
        assert_eq!(body.contains(&"61".repeat(32)), !cfg!(windows), "{body}");
        let f = &saved.fleets[&fleet];
        assert_eq!(f.keys.get(&1), Some(&"61".repeat(32)), "kept in the file");
        assert_eq!(f.credential_refs.keys().collect::<Vec<_>>(), [&2]);
        assert_eq!(saved.active_key(&fleet), Some(([0x62; 32], 2)));
        let all = saved.keys_newest_first(&fleet, |_, _| false);
        assert_eq!(all, [([0x62; 32], 2), ([0x61; 32], 1)]);

        // The next save moves the rest; nothing is left to move after it.
        save(&saved).unwrap();
        let again = load().unwrap();
        assert!(again.fleets[&fleet].keys.is_empty());
        assert_eq!(again.keys_newest_first(&fleet, |_, _| false).len(), 2);
        assert!(!protect().unwrap());

        // A re-collected key in the file wins over its stored copy.
        let mut fresh = again.clone();
        fresh.insert(&fleet, 2, &[0x72; 32]);
        assert_eq!(fresh.active_key(&fleet), Some(([0x72; 32], 2)));

        // A key whose credential is gone is not held, rather than an error.
        crate::credential::forget(&again.fleets[&fleet].credential_refs[&1]).unwrap();
        assert_eq!(
            load().unwrap().keys_newest_first(&fleet, |_, _| false),
            [([0x62; 32], 2)]
        );
        store::set_config_root(None);
    }

    #[test]
    fn debug_never_prints_a_key() {
        let mut s = FleetKeyStore::default();
        s.insert("ab", 1, &[0xc3; 32]);
        let printed = format!("{s:?}");
        assert!(!printed.contains("c3c3"), "{printed}");
        assert!(printed.contains("active_generation: 1"), "{printed}");
    }

    /// A fleet this device holds nothing for yields nothing, rather than a
    /// default key.
    #[test]
    fn an_unknown_fleet_has_no_key() {
        let s = FleetKeyStore::default();
        assert!(s.active_key("nope").is_none());
        assert!(s.keys_newest_first("nope", |_, _| false).is_empty());
    }

    /// A key the store refused stays in the file DPAPI-protected, still opens,
    /// and moves out on a later pass.
    #[cfg(windows)]
    #[test]
    fn a_key_left_in_the_file_is_dpapi_protected_and_moves_later() {
        let _guard = store::config_root_test_lock()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().unwrap();
        store::set_config_root(Some(dir.path().to_path_buf()));
        let fleet = "ef".repeat(16);
        let mut s = FleetKeyStore::default();
        s.insert(&fleet, 1, &[0x5A; 32]);
        crate::credential::fail_next_call(&format!("fleet-key.{fleet}.1"));
        save(&s).unwrap();
        let path = store::fleet_keys_path().unwrap();
        let first = fs::read_to_string(&path).unwrap();
        let held = load().unwrap().keys_newest_first(&fleet, |_, _| false);
        let moved = protect().unwrap();
        let second = fs::read_to_string(&path).unwrap();
        let after = load().unwrap().keys_newest_first(&fleet, |_, _| false);
        store::set_config_root(None);

        assert!(
            first.contains("dpapi:") && !first.contains(&"5a".repeat(32)),
            "{first}"
        );
        assert_eq!(held, vec![([0x5A; 32], 1)]);
        assert!(moved);
        assert!(!second.contains("dpapi:"), "{second}");
        assert_eq!(after, vec![([0x5A; 32], 1)]);
    }
}
