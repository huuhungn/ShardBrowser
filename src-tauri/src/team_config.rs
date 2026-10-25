// Team server connection settings and this device's enrollment.
//
// Kept in its own `team.json` (see store::team_config_path), following the
// same rule as psapi.json: the Settings page round-trips a whole struct, and
// a partial save must not be able to wipe the device identity.
//
// The signing key is the device's identity on the fleet. It is generated
// here, never leaves this process, and is what the server verified during
// enrollment — losing the file means re-enrolling, not losing profile data.
//
// Both key seeds are DPAPI-protected on disk on Windows (see `dpapi`); in
// memory they stay plaintext hex, so callers never see the stored form.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::sync::Mutex;

use shardx_core::signing::Ed25519SigningKey;

use crate::{dpapi, store};

/// Serialises writes, so a migration rewrite cannot land on top of a newer
/// save with the content it read before that save.
static WRITE_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Serialize, Deserialize, Default)]
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

/// Debug without the token or either key seed: a config that reaches a log
/// must not carry the device identity with it.
impl std::fmt::Debug for TeamConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TeamConfig")
            .field("server_url", &self.server_url)
            .field("tenant_id", &self.tenant_id)
            .field("device_id", &self.device_id)
            .field("account_id", &self.account_id)
            .field("fleet_id", &self.fleet_id)
            .finish_non_exhaustive()
    }
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

    /// Whether a stored key seed is a DPAPI blob this Windows account cannot
    /// open: the file came from another account or machine.
    pub fn keys_unreadable(&self) -> bool {
        dpapi::unreadable(&self.signing_key_seed) || dpapi::unreadable(&self.hpke_key_seed)
    }

    /// Whether enrolling again would replace a working identity. A device
    /// whose keys this account cannot open has none to lose, so it may
    /// re-enroll; enrollment then replaces both seeds, and nothing else is
    /// cleared on the way.
    pub fn blocks_enrollment(&self) -> bool {
        self.is_enrolled() && !self.keys_unreadable()
    }

    /// The device signing key, if enrolled.
    pub fn signing_key(&self) -> Result<Ed25519SigningKey> {
        unreadable_guard(&self.signing_key_seed)?;
        let seed = decode_hex32(&self.signing_key_seed)
            .context(crate::errcode::code("teamConfig.signingKeyCorrupt"))?;
        Ok(Ed25519SigningKey::from_bytes(&seed))
    }

    /// The device HPKE seed, used to open root key grants sealed to this
    /// device. Devices enrolled before the seed was persisted have the public
    /// half registered server-side but no private half here, so they cannot
    /// open grants and must re-enroll.
    pub fn hpke_seed(&self) -> Result<[u8; 32]> {
        unreadable_guard(&self.hpke_key_seed)?;
        decode_hex32(&self.hpke_key_seed)
            .context(crate::errcode::code("teamConfig.hpkeKeyUnusable"))
    }

    /// Whether this device can open grants sealed to it.
    pub fn can_receive_custody(&self) -> bool {
        self.is_enrolled() && !self.hpke_key_seed.is_empty()
    }
}

/// Name the real cause of an unopenable seed instead of calling it corrupt.
fn unreadable_guard(seed: &str) -> Result<()> {
    if dpapi::unreadable(seed) {
        anyhow::bail!(crate::errcode::code("keyStore.otherWindowsAccount"));
    }
    Ok(())
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
    /// False when the stored keys cannot be opened (`keys_unreadable`), so the
    /// interface offers enrollment again.
    pub is_enrolled: bool,
    /// The stored keys were protected by another Windows account or machine.
    pub keys_unreadable: bool,
    /// Whether profile sync can run. False for a device enrolled before sync
    /// existed, which needs re-enrolling to learn its account id.
    pub can_sync: bool,
    /// Whether this device can receive key custody. False for a device
    /// enrolled before the HPKE seed was persisted: the server holds its public
    /// key, but the private half was discarded, so grants sealed to it can
    /// never be opened. Such a device must re-enroll.
    pub can_receive_custody: bool,
    /// Whether sync can run without a passphrase. Always false for now: push
    /// never seals under a fleet key cached from the team server, because the
    /// server cannot yet prove who issued it. Kept for the interface's shape.
    pub has_fleet_key: bool,
}

pub fn load() -> Result<TeamConfig> {
    let path = store::team_config_path()?;
    if !path.exists() {
        return Ok(TeamConfig::default());
    }
    let mut stored = read(&path)?;
    if has_plaintext_keys(&stored) {
        // Written before the seeds were protected. Rewrite it now rather than
        // at the next save, which may never come. Re-read under the lock: a
        // save may have landed since. Best effort: on failure the file still
        // holds the keys exactly as before.
        let _guard = WRITE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        stored = read(&path)?;
        if has_plaintext_keys(&stored) {
            let _ = write(&path, &stored);
        }
    }
    stored.signing_key_seed = dpapi::reveal(&stored.signing_key_seed);
    stored.hpke_key_seed = dpapi::reveal(&stored.hpke_key_seed);
    Ok(stored)
}

pub fn save(c: &TeamConfig) -> Result<()> {
    let path = store::team_config_path()?;
    let _guard = WRITE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    write(&path, c)
}

/// The file as stored: seeds still in their on-disk form.
fn read(path: &std::path::Path) -> Result<TeamConfig> {
    let body = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&body).unwrap_or_default())
}

fn has_plaintext_keys(c: &TeamConfig) -> bool {
    dpapi::needs_protection(&c.signing_key_seed) || dpapi::needs_protection(&c.hpke_key_seed)
}

/// Write `c` with its seeds protected. Callers hold `WRITE_LOCK`.
fn write(path: &std::path::Path, c: &TeamConfig) -> Result<()> {
    let mut on_disk = c.clone();
    on_disk.signing_key_seed = dpapi::conceal(&c.signing_key_seed)?;
    on_disk.hpke_key_seed = dpapi::conceal(&c.hpke_key_seed)?;
    // Write-then-rename, flushed before the rename: a crash must not leave a
    // half-written file that reads back as "not enrolled" and orphans the
    // device, and a migration rewrites the only copy of the keys. std cannot
    // flush the parent directory on Windows, so the rename itself is not
    // fsynced there.
    let tmp = path.with_extension("json.tmp");
    let mut file = fs::File::create(&tmp)?;
    file.write_all(serde_json::to_string_pretty(&on_disk)?.as_bytes())?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, path)?;
    Ok(())
}

pub fn status() -> Result<TeamStatus> {
    let c = load()?;
    Ok(TeamStatus {
        server_url: c.server_url.clone(),
        tenant_id: c.tenant_id.clone(),
        device_id: c.device_id.clone(),
        has_token: !c.token.is_empty(),
        is_enrolled: c.is_enrolled() && !c.keys_unreadable(),
        keys_unreadable: c.keys_unreadable(),
        can_sync: c.can_sync(),
        can_receive_custody: c.can_receive_custody(),
        // A cached fleet key no longer lets sync skip the passphrase: push
        // always seals under the passphrase (see `sync_cmd`).
        has_fleet_key: false,
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

    const SIGNING: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const HPKE: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn enrolled() -> TeamConfig {
        TeamConfig {
            server_url: "https://team.example.com".into(),
            token: "secret-token".into(),
            tenant_id: "aa".into(),
            device_id: "bb".into(),
            account_id: "cc".into(),
            fleet_id: "dd".into(),
            signing_key_seed: SIGNING.into(),
            hpke_key_seed: HPKE.into(),
        }
    }

    #[test]
    fn debug_output_carries_no_secret() {
        let shown = format!("{:?}", enrolled());
        for secret in [SIGNING, HPKE, "secret-token"] {
            assert!(!shown.contains(secret), "Debug leaked {secret}: {shown}");
        }
        assert!(shown.contains("team.example.com"), "non-secret fields stay");
    }

    /// A seed this Windows account cannot open says so, may be replaced by
    /// enrolling again, and is never dropped by an ordinary save.
    #[test]
    fn an_unopenable_dpapi_seed_is_named_kept_and_allows_re_enrollment() {
        let lock = store::config_root_test_lock()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().unwrap();
        store::set_config_root(Some(dir.path().to_path_buf()));
        let junk = "dpapi:AAAA";
        let mut c = enrolled();
        c.signing_key_seed = junk.into();
        c.hpke_key_seed = junk.into();
        save(&c).unwrap();
        let loaded = load().unwrap();
        let body = fs::read_to_string(store::team_config_path().unwrap()).unwrap();
        let st = status().unwrap();
        store::set_config_root(None);
        drop(lock);

        let signing = loaded.signing_key().err().map(|e| format!("{e:#}"));
        let hpke = loaded.hpke_seed().err().map(|e| format!("{e:#}"));
        for err in [signing, hpke] {
            let err = err.expect("an unopenable seed must not yield a key");
            assert!(
                crate::errcode::has_code(&err, "keyStore.otherWindowsAccount"),
                "{err}"
            );
        }
        assert!(!loaded.blocks_enrollment(), "re-enrollment must be allowed");
        assert!(
            enrolled().blocks_enrollment(),
            "a working identity still blocks"
        );
        assert!(
            st.keys_unreadable && !st.is_enrolled,
            "the interface offers enrollment"
        );
        assert_eq!(body.matches(junk).count(), 2, "the blob is kept: {body}");
    }

    #[cfg(windows)]
    fn scratch() -> (tempfile::TempDir, std::sync::MutexGuard<'static, ()>) {
        let lock = store::config_root_test_lock()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().unwrap();
        store::set_config_root(Some(dir.path().to_path_buf()));
        (dir, lock)
    }

    #[cfg(windows)]
    fn on_disk() -> String {
        fs::read_to_string(store::team_config_path().unwrap()).unwrap()
    }

    #[cfg(windows)]
    #[test]
    fn saved_seeds_are_dpapi_protected_and_load_back() {
        let (_dir, _lock) = scratch();
        save(&enrolled()).unwrap();
        let body = on_disk();
        let loaded = load().unwrap();
        store::set_config_root(None);

        assert!(!body.contains(SIGNING) && !body.contains(HPKE), "{body}");
        assert!(body.contains("dpapi:"), "{body}");
        assert_eq!(loaded.signing_key_seed, SIGNING);
        assert_eq!(loaded.hpke_key_seed, HPKE);
        assert!(loaded.signing_key().is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn a_plaintext_file_still_loads_and_is_rewritten_protected() {
        let (_dir, _lock) = scratch();
        let path = store::team_config_path().unwrap();
        fs::write(&path, serde_json::to_string(&enrolled()).unwrap()).unwrap();

        let first = load().unwrap();
        let body = on_disk();
        let second = load().unwrap();
        store::set_config_root(None);

        assert_eq!(first.signing_key_seed, SIGNING, "plaintext still loads");
        assert_eq!(first.hpke_key_seed, HPKE);
        assert!(!body.contains(SIGNING) && !body.contains(HPKE), "{body}");
        assert_eq!(second.signing_key_seed, SIGNING, "no key lost on migration");
        assert_eq!(second.hpke_key_seed, HPKE);
        assert_eq!(second.token, "secret-token", "other fields kept");
    }
}
