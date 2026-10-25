//! Fleet keys this device collected from its grants in earlier versions.
//!
//! A fleet key (FKEK) opens profile snapshots. Earlier versions opened every
//! fleet key grant the team server delivered and cached the key here, and push
//! sealed under it. Nothing proves who issued such a grant, so a hostile
//! server could seal a key of its own choosing to this device and read every
//! later push. Until verified key distribution ships, nothing adds keys here:
//! the cache is read only by pull, so snapshots already pushed under a cached
//! key still restore.
//!
//! Two deliberate choices:
//!
//! 1. **Separate from `team.json`.** That file is round-tripped by the
//!    Settings page. Key material must not sit in a struct a partial UI save
//!    could rewrite.
//! 2. **Keyed by generation.** Snapshots sealed under an older generation must
//!    stay readable, so old keys are kept rather than replaced.
//!
//! This file is as sensitive as the profiles it opens. On Windows each key is
//! DPAPI-protected for the current user (see `dpapi`). On Unix the file is
//! written 0600.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;

use crate::{dpapi, store};

/// One fleet's collected keys, by generation.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct FleetKeys {
    /// Generation number to hex-encoded 32-byte key.
    #[serde(default)]
    pub keys: BTreeMap<u64, String>,
    /// Newest generation collected.
    #[serde(default)]
    pub active_generation: u64,
}

/// Debug that names the generations held, never the keys.
impl std::fmt::Debug for FleetKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FleetKeys")
            .field("generations", &self.keys.keys().collect::<Vec<_>>())
            .field("active_generation", &self.active_generation)
            .finish()
    }
}

/// All fleets this device holds keys for, by hex fleet id.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FleetKeyStore {
    #[serde(default)]
    pub fleets: BTreeMap<String, FleetKeys>,
}

impl FleetKeyStore {
    /// Every key this device holds for a fleet, newest generation first.
    ///
    /// Restore tries these in turn: a snapshot pushed before a rotation is
    /// still sealed under the older generation and must stay readable.
    pub fn keys_newest_first(&self, fleet_id: &str) -> Vec<([u8; 32], u64)> {
        let Some(f) = self.fleets.get(fleet_id) else {
            return Vec::new();
        };
        let mut out: Vec<_> = f
            .keys
            .iter()
            .filter_map(|(g, h)| decode_key(h).ok().map(|k| (k, *g)))
            .collect();
        out.sort_by_key(|(_, generation)| std::cmp::Reverse(*generation));
        out
    }

    /// Record a key. Test-only: production adds none until verified key
    /// distribution ships.
    #[cfg(test)]
    pub fn insert(&mut self, fleet_id: &str, generation: u64, key: &[u8; 32]) {
        let f = self.fleets.entry(fleet_id.to_string()).or_default();
        f.keys
            .insert(generation, key.iter().map(|b| format!("{b:02x}")).collect());
        if generation >= f.active_generation {
            f.active_generation = generation;
        }
    }

    /// Apply `f` to every stored key string.
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
    let body = fs::read_to_string(&path)?;
    let stored: FleetKeyStore = serde_json::from_str(&body).unwrap_or_default();
    let plain = stored.map_keys(|v| Ok(dpapi::reveal(v)))?;
    if stored.has_plaintext_keys() {
        // Written before keys were protected; nothing else writes this file
        // any more, so rewrite it now. Best effort: on failure the file keeps
        // the keys exactly as before.
        let _ = save(&plain);
    }
    Ok(plain)
}

pub fn save(s: &FleetKeyStore) -> Result<()> {
    let path = store::fleet_keys_path()?;
    let on_disk = s.map_keys(dpapi::conceal)?;
    // Write-then-rename, as with team.json: a crash mid-write must not leave a
    // file that reads back as "no keys" and silently strands the snapshots.
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_string_pretty(&on_disk)?)?;
    restrict(&tmp);
    fs::rename(&tmp, &path)?;
    Ok(())
}

/// Restrict the file to its owner where the platform expresses that in mode
/// bits. A best-effort call: failure to tighten permissions must not lose the
/// key that was just collected.
#[cfg(unix)]
fn restrict(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict(_path: &std::path::Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Newer generations come first, and older ones stay readable.
    #[test]
    fn a_newer_generation_comes_first_without_dropping_the_old_key() {
        let mut s = FleetKeyStore::default();
        s.insert("ab", 1, &[0x11u8; 32]);
        s.insert("ab", 2, &[0x22u8; 32]);

        let all = s.keys_newest_first("ab");
        assert_eq!(all.len(), 2, "the older key must be kept for old snapshots");
        assert_eq!(all[0], ([0x22u8; 32], 2), "newest first");
        assert_eq!(all[1].1, 1);
    }

    /// A late-arriving older key must not demote the newest generation.
    #[test]
    fn an_older_key_does_not_demote_the_active_generation() {
        let mut s = FleetKeyStore::default();
        s.insert("ab", 5, &[0x55u8; 32]);
        s.insert("ab", 3, &[0x33u8; 32]);
        assert_eq!(s.fleets["ab"].active_generation, 5);
    }

    /// A fleet this device holds nothing for yields nothing, rather than a
    /// default key.
    #[test]
    fn an_unknown_fleet_has_no_key() {
        let s = FleetKeyStore::default();
        assert!(s.keys_newest_first("nope").is_empty());
    }

    #[test]
    fn debug_output_carries_no_key() {
        let mut s = FleetKeyStore::default();
        s.insert("ab", 1, &[0x5Au8; 32]);
        let shown = format!("{s:?}");
        assert!(
            !shown.contains(&"5a".repeat(32)),
            "Debug leaked a key: {shown}"
        );
        assert!(shown.contains("ab"), "the fleet id is not secret");
    }

    #[cfg(windows)]
    #[test]
    fn keys_are_dpapi_protected_and_a_plaintext_file_migrates() {
        let _lock = store::config_root_test_lock()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().unwrap();
        store::set_config_root(Some(dir.path().to_path_buf()));
        let path = store::fleet_keys_path().unwrap();

        let mut s = FleetKeyStore::default();
        s.insert("ab", 1, &[0x5Au8; 32]);
        let key_hex = "5a".repeat(32);
        // A file as earlier versions wrote it: plaintext hex.
        fs::write(&path, serde_json::to_string(&s).unwrap()).unwrap();

        let loaded = load().unwrap();
        let migrated = fs::read_to_string(&path).unwrap();
        let reloaded = load().unwrap();
        save(&s).unwrap();
        let saved = fs::read_to_string(&path).unwrap();
        store::set_config_root(None);

        assert_eq!(loaded.keys_newest_first("ab"), vec![([0x5Au8; 32], 1)]);
        assert!(!migrated.contains(&key_hex), "{migrated}");
        assert!(migrated.contains("dpapi:"), "{migrated}");
        assert_eq!(reloaded.keys_newest_first("ab"), vec![([0x5Au8; 32], 1)]);
        assert!(!saved.contains(&key_hex), "{saved}");
    }
}
