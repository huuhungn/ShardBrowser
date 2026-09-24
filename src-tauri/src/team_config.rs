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
}

impl TeamConfig {
    /// Whether this device has completed enrollment against `server_url`.
    pub fn is_enrolled(&self) -> bool {
        !self.device_id.is_empty() && !self.signing_key_seed.is_empty()
    }

    /// Whether this device has everything the fleet routes require. A device
    /// enrolled before `account_id` was persisted is enrolled but cannot sync,
    /// and must re-enroll rather than guess.
    pub fn can_sync(&self) -> bool {
        self.is_enrolled() && !self.account_id.is_empty() && !self.tenant_id.is_empty()
    }

    /// The device signing key, if enrolled.
    pub fn signing_key(&self) -> Result<Ed25519SigningKey> {
        let seed = decode_hex32(&self.signing_key_seed)
            .context(crate::errcode::code("teamConfig.signingKeyCorrupt"))?;
        Ok(Ed25519SigningKey::from_bytes(&seed))
    }

    /// The device HPKE seed, used to open root key grants sealed to this
    /// device. Devices enrolled before the seed was persisted have the public
    /// half registered server-side but no private half here, so they cannot
    /// open grants and must re-enroll.
    pub fn hpke_seed(&self) -> Result<[u8; 32]> {
        decode_hex32(&self.hpke_key_seed)
            .context(crate::errcode::code("teamConfig.hpkeKeyUnusable"))
    }

    /// Whether this device can open grants sealed to it.
    pub fn can_receive_custody(&self) -> bool {
        self.is_enrolled() && !self.hpke_key_seed.is_empty()
    }
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
