// Team server connection settings and this device's enrollment.
//
// Kept in its own `team.json` (see store::team_config_path), following the
// same rule as psapi.json: the Settings page round-trips a whole struct, and
// a partial save must not be able to wipe the device identity.
//
// The signing key is the device's identity on the fleet. It is generated
// here, never leaves this process, and is what the server verified during
// enrollment — losing the file means re-enrolling, not losing profile data.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use zeroize::Zeroizing;

use shardx_core::signing::Ed25519SigningKey;

use crate::store;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TeamConfig {
    /// Base URL of the team server, e.g. `https://team.example.com`.
    #[serde(default)]
    pub server_url: String,
    /// Session token for that server.
    #[serde(default)]
    pub token: String,
    /// Tenant this device belongs to, hex-encoded.
    #[serde(default)]
    pub tenant_id: String,
    /// Device id assigned by the server at enrollment, hex-encoded.
    #[serde(default)]
    pub device_id: String,
    /// Account the server bound this device to, hex-encoded. Fleet routes are
    /// scoped by account; the server discloses it at enrollment.
    #[serde(default)]
    pub account_id: String,
    /// Fleet this device syncs profiles into, hex-encoded.
    #[serde(default)]
    pub fleet_id: String,
    /// Ed25519 signing key seed, hex-encoded. Present once enrolled.
    #[serde(default)]
    pub signing_key_seed: String,
    /// HPKE recipient key seed, hex-encoded. Present once enrolled.
    #[serde(default)]
    pub hpke_key_seed: String,
    /// Where the signing seed lives once it left this file: its reference in
    /// the OS credential store (ADR 0004). Then `signing_key_seed` is empty.
    #[serde(default)]
    pub signing_credential_ref: String,
    /// The same for the HPKE seed.
    #[serde(default)]
    pub hpke_credential_ref: String,
}

impl TeamConfig {
    /// Whether this device has completed enrollment against `server_url`.
    pub fn is_enrolled(&self) -> bool {
        !self.device_id.is_empty()
            && !(self.signing_key_seed.is_empty() && self.signing_credential_ref.is_empty())
    }

    /// Whether this device has everything the fleet routes require. A device
    /// enrolled before `account_id` was persisted is enrolled but cannot sync,
    /// and must re-enroll rather than guess.
    pub fn can_sync(&self) -> bool {
        self.is_enrolled() && !self.account_id.is_empty() && !self.tenant_id.is_empty()
    }

    /// The device signing key, if enrolled.
    pub fn signing_key(&self) -> Result<Ed25519SigningKey> {
        let seed = seed(&self.signing_key_seed, &self.signing_credential_ref)
            .context(crate::errcode::code("teamConfig.signingKeyCorrupt"))?;
        Ok(Ed25519SigningKey::from_bytes(&seed))
    }

    /// The device HPKE seed, used to open root key grants sealed to this
    /// device. Devices enrolled before the seed was persisted have the public
    /// half registered server-side but no private half here, so they cannot
    /// open grants and must re-enroll.
    pub fn hpke_seed(&self) -> Result<[u8; 32]> {
        seed(&self.hpke_key_seed, &self.hpke_credential_ref)
            .map(|s| *s)
            .context(crate::errcode::code("teamConfig.hpkeKeyUnusable"))
    }

    /// Whether this device can open grants sealed to it.
    pub fn can_receive_custody(&self) -> bool {
        self.is_enrolled()
            && !(self.hpke_key_seed.is_empty() && self.hpke_credential_ref.is_empty())
    }
}

/// A seed from the file while it is still there, else from the credential
/// store. The file copy is the newer one: a seed leaves it only once stored.
fn seed(plaintext: &str, credential_ref: &str) -> Result<Zeroizing<[u8; 32]>> {
    if plaintext.is_empty() && !credential_ref.is_empty() {
        crate::credential::load(credential_ref)
    } else {
        decode_hex32(plaintext).map(Zeroizing::new)
    }
}

/// Moves this device's plaintext seeds into the OS credential store (ADR
/// 0004) and saves the file without them. A seed leaves the file only after
/// it read back from the store; while the store is unavailable it stays.
/// Returns whether any seed moved.
// shortcut: with no usable store the seeds stay in plaintext `team.json`
// until the fallback key file (ADR 0002, G2-48) lands.
pub fn protect_keys(c: &mut TeamConfig) -> Result<bool> {
    if c.device_id.is_empty() {
        return Ok(false);
    }
    let device = c.device_id.clone();
    let mut moved = false;
    for (plaintext, reference, kind) in [
        (
            &mut c.signing_key_seed,
            &mut c.signing_credential_ref,
            "device-signing",
        ),
        (
            &mut c.hpke_key_seed,
            &mut c.hpke_credential_ref,
            "device-hpke",
        ),
    ] {
        if plaintext.is_empty() {
            continue;
        }
        let key = Zeroizing::new(decode_hex32(plaintext)?);
        let name = format!("{kind}.{device}");
        if crate::credential::store(&name, &key).is_err() {
            continue;
        }
        *reference = name;
        plaintext.clear();
        moved = true;
    }
    if moved {
        save(c)?;
    }
    Ok(moved)
}

/// Connection status shown in Settings, with no secret in it.
///
/// The token and key seed are deliberately absent: the UI needs to say
/// whether they are set, never what they are.
#[derive(Debug, Clone, Serialize)]
pub struct TeamStatus {
    pub server_url: String,
    pub tenant_id: String,
    pub device_id: String,
    pub has_token: bool,
    pub is_enrolled: bool,
    /// Whether profile sync can run. False for a device enrolled before sync
    /// existed, which needs re-enrolling to learn its account id.
    pub can_sync: bool,
    /// Whether this device can receive key custody. False for a device
    /// enrolled before the HPKE seed was persisted: the server holds its public
    /// key, but the private half was discarded, so grants sealed to it can
    /// never be opened. Such a device must re-enroll.
    pub can_receive_custody: bool,
    /// Whether this device holds a fleet key. Once true, sync seals and opens
    /// snapshots with the fleet key and no passphrase is asked for.
    pub has_fleet_key: bool,
    /// Whether every key this device holds is in the OS credential store.
    /// False while a seed or fleet key is still in plaintext on disk because
    /// no store was usable (ADR 0004, unavailable store).
    pub keys_protected: bool,
}

pub fn load() -> Result<TeamConfig> {
    let path = store::team_config_path()?;
    if !path.exists() {
        return Ok(TeamConfig::default());
    }
    let body = fs::read_to_string(&path)?;
    Ok(serde_json::from_str(&body).unwrap_or_default())
}

pub fn save(c: &TeamConfig) -> Result<()> {
    let path = store::team_config_path()?;
    // Write-then-rename: a crash mid-write must not leave a half-written file
    // that reads back as "not enrolled" and orphans the device on the server.
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_string_pretty(c)?)?;
    fs::rename(&tmp, &path)?;
    Ok(())
}

pub fn status() -> Result<TeamStatus> {
    let c = load()?;
    Ok(TeamStatus {
        server_url: c.server_url.clone(),
        tenant_id: c.tenant_id.clone(),
        device_id: c.device_id.clone(),
        has_token: !c.token.is_empty(),
        is_enrolled: c.is_enrolled(),
        can_sync: c.can_sync(),
        can_receive_custody: c.can_receive_custody(),
        // Reading the key cache is best effort: a device with no cache yet is
        // simply a device without a fleet key, not an error to report here.
        has_fleet_key: crate::fleet_keys::load()
            .map(|s| s.active_key(&c.fleet_id).is_some())
            .unwrap_or(false),
        keys_protected: c.signing_key_seed.is_empty()
            && c.hpke_key_seed.is_empty()
            && crate::fleet_keys::load()
                .is_ok_and(|s| s.fleets.values().all(|f| f.keys.is_empty())),
    })
}

fn decode_hex32(s: &str) -> Result<[u8; 32]> {
    anyhow::ensure!(s.len() == 64, "expected 64 hex characters");
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrolled_seeds_move_to_the_credential_store_and_still_open() {
        let _guard = store::config_root_test_lock()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().unwrap();
        store::set_config_root(Some(dir.path().to_path_buf()));
        let mut c = TeamConfig {
            device_id: "ab".repeat(16),
            signing_key_seed: "11".repeat(32),
            hpke_key_seed: "22".repeat(32),
            ..Default::default()
        };
        save(&c).unwrap();
        let key_before = c.signing_key().unwrap().verifying_key().to_bytes();

        assert!(protect_keys(&mut c).unwrap());
        let saved = load().unwrap();
        let body = fs::read_to_string(store::team_config_path().unwrap()).unwrap();
        assert!(
            !body.contains(&"11".repeat(32)) && !body.contains(&"22".repeat(32)),
            "{body}"
        );
        assert_eq!(
            saved.signing_credential_ref,
            format!("device-signing.{}", "ab".repeat(16))
        );
        assert!(saved.is_enrolled() && saved.can_receive_custody());
        assert!(status().unwrap().keys_protected);
        assert_eq!(
            saved.signing_key().unwrap().verifying_key().to_bytes(),
            key_before
        );
        assert_eq!(saved.hpke_seed().unwrap(), [0x22; 32]);
        // Nothing left to move.
        let mut again = saved.clone();
        assert!(!protect_keys(&mut again).unwrap());

        // A seed written back to the file (re-enrollment) wins over the store.
        let mut fresh = saved.clone();
        fresh.signing_key_seed = "33".repeat(32);
        assert_eq!(fresh.signing_key().unwrap().to_bytes(), [0x33; 32]);

        // A reference whose credential is gone fails closed.
        crate::credential::forget(&saved.hpke_credential_ref).unwrap();
        assert!(saved.hpke_seed().is_err());
        store::set_config_root(None);
    }

    #[test]
    fn a_seed_the_store_refuses_stays_in_the_file() {
        let _guard = store::config_root_test_lock()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().unwrap();
        store::set_config_root(Some(dir.path().to_path_buf()));
        let mut c = TeamConfig {
            device_id: "cd".repeat(16),
            signing_key_seed: "44".repeat(32),
            hpke_key_seed: "55".repeat(32),
            ..Default::default()
        };
        crate::credential::fail_next_call(&format!("device-signing.{}", "cd".repeat(16)));

        assert!(protect_keys(&mut c).unwrap());
        let saved = load().unwrap();
        assert_eq!(saved.signing_key_seed, "44".repeat(32));
        assert!(
            !status().unwrap().keys_protected,
            "a plaintext seed is reported"
        );
        assert!(saved.signing_credential_ref.is_empty());
        assert!(saved.hpke_key_seed.is_empty() && !saved.hpke_credential_ref.is_empty());
        assert_eq!(saved.signing_key().unwrap().to_bytes(), [0x44; 32]);
        assert_eq!(saved.hpke_seed().unwrap(), [0x55; 32]);
        store::set_config_root(None);
    }

    #[test]
    fn a_device_without_an_identity_moves_nothing() {
        let mut c = TeamConfig {
            signing_key_seed: "11".repeat(32),
            ..Default::default()
        };
        assert!(!protect_keys(&mut c).unwrap());
        assert_eq!(c.signing_key_seed, "11".repeat(32));
    }
}
