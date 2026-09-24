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
//! This file is as sensitive as the profiles it opens. On Unix it is written
//! 0600. On Windows it inherits the user profile directory's ACL, which is
//! already user-only; there is no extra restriction applied here, and a device
//! whose disk is readable by others is compromised regardless.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;

use crate::store;

/// One fleet's collected keys, by generation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FleetKeys {
    /// Generation number to hex-encoded 32-byte key.
    #[serde(default)]
    pub keys: BTreeMap<u64, String>,
    /// Generation sync should seal new snapshots under. Reading still tries
    /// every generation, because an older snapshot is still valid.
    #[serde(default)]
    pub active_generation: u64,
}

/// All fleets this device holds keys for, by hex fleet id.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FleetKeyStore {
    #[serde(default)]
    pub fleets: BTreeMap<String, FleetKeys>,
}

impl FleetKeyStore {
    /// The key to seal new snapshots under, if this device has one.
    pub fn active_key(&self, fleet_id: &str) -> Option<([u8; 32], u64)> {
        let f = self.fleets.get(fleet_id)?;
        let hex = f.keys.get(&f.active_generation)?;
        decode_key(hex).ok().map(|k| (k, f.active_generation))
    }

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

    /// Record a collected key.
    pub fn insert(&mut self, fleet_id: &str, generation: u64, key: &[u8; 32]) {
        let f = self.fleets.entry(fleet_id.to_string()).or_default();
        f.keys.insert(generation, to_hex(key));
        if generation >= f.active_generation {
            f.active_generation = generation;
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
    let body = fs::read_to_string(&path)?;
    Ok(serde_json::from_str(&body).unwrap_or_default())
}

pub fn save(s: &FleetKeyStore) -> Result<()> {
    let path = store::fleet_keys_path()?;
    // Write-then-rename, as with team.json: a crash mid-write must not leave a
    // file that reads back as "no keys" and silently strands the snapshots.
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_string_pretty(s)?)?;
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

    /// Newer generations take over as active, and older ones stay readable.
    #[test]
    fn a_newer_generation_becomes_active_without_dropping_the_old_key() {
        let mut s = FleetKeyStore::default();
        s.insert("ab", 1, &[0x11u8; 32]);
        s.insert("ab", 2, &[0x22u8; 32]);

        let (key, gen) = s.active_key("ab").expect("active key");
        assert_eq!(gen, 2, "newest generation must be active");
        assert_eq!(key, [0x22u8; 32]);

        let all = s.keys_newest_first("ab");
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

    /// A fleet this device holds nothing for yields nothing, rather than a
    /// default key.
    #[test]
    fn an_unknown_fleet_has_no_key() {
        let s = FleetKeyStore::default();
        assert!(s.active_key("nope").is_none());
        assert!(s.keys_newest_first("nope").is_empty());
    }
}
