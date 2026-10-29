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
// Seeds move into the OS credential store (ADR 0004). A seed still in the
// file is DPAPI-protected on Windows (see `dpapi`); in memory it is plaintext
// hex, so callers never see the stored form.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::sync::Mutex;
use zeroize::Zeroizing;

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
    pub token: Zeroizing<String>,
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
    pub signing_key_seed: Zeroizing<String>,
    /// HPKE recipient key seed, hex-encoded. Present once enrolled.
    #[serde(default)]
    pub hpke_key_seed: Zeroizing<String>,
    /// Where the signing seed lives once it left this file: its reference in
    /// the OS credential store (ADR 0004). Then `signing_key_seed` is empty.
    #[serde(default)]
    pub signing_credential_ref: String,
    /// The same for the HPKE seed.
    #[serde(default)]
    pub hpke_credential_ref: String,
}

/// Never prints the token or a seed: a stray `{:?}` in a log must not leak
/// what lets anyone act as this device (G2-47).
impl std::fmt::Debug for TeamConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let held = |s: &str| if s.is_empty() { "<none>" } else { "<redacted>" };
        f.debug_struct("TeamConfig")
            .field("server_url", &self.server_url)
            .field("token", &held(&self.token))
            .field("tenant_id", &self.tenant_id)
            .field("device_id", &self.device_id)
            .field("account_id", &self.account_id)
            .field("fleet_id", &self.fleet_id)
            .field("signing_key_seed", &held(&self.signing_key_seed))
            .field("hpke_key_seed", &held(&self.hpke_key_seed))
            .field("signing_credential_ref", &self.signing_credential_ref)
            .field("hpke_credential_ref", &self.hpke_credential_ref)
            .finish()
    }
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
        self.is_enrolled()
            && !self.keys_unreadable()
            && !self.account_id.is_empty()
            && !self.tenant_id.is_empty()
    }

    /// Whether a seed still in the file is a DPAPI blob this Windows account
    /// cannot open: the file came from another account or machine.
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
        let seed = seed(
            &self.signing_key_seed,
            &self.signing_credential_ref,
            "teamConfig.signingKeyCorrupt",
        )?;
        Ok(Ed25519SigningKey::from_bytes(&seed))
    }

    /// The device HPKE seed, used to open root key grants sealed to this
    /// device. Devices enrolled before the seed was persisted have the public
    /// half registered server-side but no private half here, so they cannot
    /// open grants and must re-enroll.
    pub fn hpke_seed(&self) -> Result<[u8; 32]> {
        seed(
            &self.hpke_key_seed,
            &self.hpke_credential_ref,
            "teamConfig.hpkeKeyUnusable",
        )
        .map(|s| *s)
    }

    /// Whether this device can open grants sealed to it.
    pub fn can_receive_custody(&self) -> bool {
        self.is_enrolled()
            && !self.keys_unreadable()
            && !(self.hpke_key_seed.is_empty() && self.hpke_credential_ref.is_empty())
    }
}

/// Copy `team.json` aside before a re-enrolment replaces seeds this account
/// cannot open. "Cannot open" may be temporary (a domain master key not yet
/// fetched while offline), so the old identity is kept, not overwritten.
/// Returns the copy's path.
pub fn preserve_unreadable() -> Result<std::path::PathBuf> {
    let path = store::team_config_path()?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let copy = path.with_extension(format!("json.unreadable-{stamp}"));
    fs::copy(&path, &copy)?;
    // Flushing needs a writable handle on Windows.
    fs::OpenOptions::new().write(true).open(&copy)?.sync_all()?;
    Ok(copy)
}

/// A seed from the file while it is still there, else from the credential
/// store. The file copy is the newer one: a seed leaves it only once stored.
/// A store error is reported as it is (a locked key file is not a corrupt
/// key); only an unreadable file copy is `corrupt`.
fn seed(plaintext: &str, credential_ref: &str, corrupt: &str) -> Result<Zeroizing<[u8; 32]>> {
    if plaintext.is_empty() && !credential_ref.is_empty() {
        crate::credential::load(credential_ref)
    } else {
        // Name the real cause of an unopenable seed instead of calling it
        // corrupt.
        if dpapi::unreadable(plaintext) {
            anyhow::bail!(crate::errcode::code("keyStore.otherWindowsAccount"));
        }
        decode_hex32(plaintext)
            .map(Zeroizing::new)
            .context(crate::errcode::code(corrupt))
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
        // An unopenable seed stays as it is, for re-enrolment to replace.
        if plaintext.is_empty() || dpapi::unreadable(plaintext) {
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
    /// The stored keys were protected by another Windows account or machine.
    /// `is_enrolled` is then false, so the interface offers enrollment again.
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
    /// Whether every key this device holds is in the OS credential store.
    /// False while a seed or fleet key is still in plaintext on disk because
    /// no store was usable (ADR 0004, unavailable store).
    pub keys_protected: bool,
    /// Whether this device has a passphrase-protected key file.
    pub has_key_file: bool,
    /// Whether that file exists but was not opened in this run, so keys kept
    /// in it cannot be used until the passphrase is entered.
    pub keys_locked: bool,
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
    stored.signing_key_seed = dpapi::reveal(&stored.signing_key_seed).into();
    stored.hpke_key_seed = dpapi::reveal(&stored.hpke_key_seed).into();
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
    on_disk.signing_key_seed = dpapi::conceal(&c.signing_key_seed)?.into();
    on_disk.hpke_key_seed = dpapi::conceal(&c.hpke_key_seed)?.into();
    // A crash mid-write must not leave a half-written file that reads back as
    // "not enrolled" and orphans the device on the server.
    crate::durable::write_private(path, serde_json::to_string_pretty(&on_disk)?.as_bytes())?;
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
        keys_protected: c.signing_key_seed.is_empty()
            && c.hpke_key_seed.is_empty()
            && crate::fleet_keys::load()
                .is_ok_and(|s| s.fleets.values().all(|f| f.keys.is_empty())),
        has_key_file: crate::key_file::exists(),
        keys_locked: crate::key_file::exists() && !crate::key_file::is_open(),
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
            signing_key_seed: "11".repeat(32).into(),
            hpke_key_seed: "22".repeat(32).into(),
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
        fresh.signing_key_seed = "33".repeat(32).into();
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
            signing_key_seed: "44".repeat(32).into(),
            hpke_key_seed: "55".repeat(32).into(),
            ..Default::default()
        };
        crate::credential::fail_next_call(&format!("device-signing.{}", "cd".repeat(16)));

        assert!(protect_keys(&mut c).unwrap());
        let saved = load().unwrap();
        assert_eq!(saved.signing_key_seed.as_str(), "44".repeat(32));
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
    fn debug_never_prints_the_token_or_a_seed() {
        let c = TeamConfig {
            token: "tok-secret".to_string().into(),
            device_id: "ab".repeat(16),
            signing_key_seed: "5a".repeat(32).into(),
            hpke_key_seed: "6b".repeat(32).into(),
            ..Default::default()
        };
        let printed = format!("{c:?}");
        for secret in ["tok-secret", "5a5a", "6b6b"] {
            assert!(!printed.contains(secret), "{printed}");
        }
        assert!(printed.contains(&"ab".repeat(16)) && printed.contains("<redacted>"));
        assert!(format!("{:?}", TeamConfig::default()).contains("<none>"));
    }

    /// The token and seeds are wiped when the config is dropped (G2-47), and
    /// the wrapper changes nothing on disk: the existing format loads and
    /// writes back byte for byte.
    #[test]
    fn secrets_zeroize_on_drop_and_the_file_format_is_unchanged() {
        let c = enrolled();
        let _: [&dyn zeroize::ZeroizeOnDrop; 3] = [&c.token, &c.signing_key_seed, &c.hpke_key_seed];
        let golden = r#"{"server_url":"https://team.example.com","token":"secret-token","tenant_id":"aa","device_id":"bb","account_id":"cc","fleet_id":"dd","signing_key_seed":"S","hpke_key_seed":"H","signing_credential_ref":"","hpke_credential_ref":""}"#
            .replace("\"S\"", &format!("\"{SIGNING}\""))
            .replace("\"H\"", &format!("\"{HPKE}\""));
        assert_eq!(serde_json::to_string(&c).unwrap(), golden);
        let back: TeamConfig = serde_json::from_str(&golden).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), golden);
        assert_eq!(back.hpke_seed().unwrap(), [0x22; 32]);
    }

    #[test]
    fn a_device_without_an_identity_moves_nothing() {
        let mut c = TeamConfig {
            signing_key_seed: "11".repeat(32).into(),
            ..Default::default()
        };
        assert!(!protect_keys(&mut c).unwrap());
        assert_eq!(c.signing_key_seed.as_str(), "11".repeat(32));
    }

    const SIGNING: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const HPKE: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn enrolled() -> TeamConfig {
        TeamConfig {
            server_url: "https://team.example.com".into(),
            token: "secret-token".to_string().into(),
            tenant_id: "aa".into(),
            device_id: "bb".into(),
            account_id: "cc".into(),
            fleet_id: "dd".into(),
            signing_key_seed: SIGNING.to_string().into(),
            hpke_key_seed: HPKE.to_string().into(),
            ..Default::default()
        }
    }

    /// A seed this Windows account cannot open says so, may be replaced by
    /// enrolling again, is never moved to the credential store, and is never
    /// dropped by an ordinary save (2.4.3 wrote seeds DPAPI-protected).
    #[test]
    fn an_unopenable_dpapi_seed_is_named_kept_and_allows_re_enrollment() {
        let lock = store::config_root_test_lock()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().unwrap();
        store::set_config_root(Some(dir.path().to_path_buf()));
        let junk = "dpapi:AAAA";
        let mut c = enrolled();
        c.signing_key_seed = junk.to_string().into();
        c.hpke_key_seed = junk.to_string().into();
        save(&c).unwrap();
        let mut loaded = load().unwrap();
        let moved = protect_keys(&mut loaded).unwrap();
        let body = fs::read_to_string(store::team_config_path().unwrap()).unwrap();
        let st = status().unwrap();
        let copy = preserve_unreadable().unwrap();
        let copied = fs::read_to_string(&copy).unwrap();
        store::set_config_root(None);
        drop(lock);

        assert!(!moved, "an unopenable seed is not moved");
        assert_eq!(
            copied, body,
            "re-enrolment keeps the old file byte for byte"
        );
        assert!(!st.can_sync && !st.can_receive_custody, "{st:?}");
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

    /// A seed that has to stay in the file is DPAPI-protected there.
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
        assert_eq!(loaded.signing_key_seed.as_str(), SIGNING);
        assert_eq!(loaded.hpke_key_seed.as_str(), HPKE);
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

        assert_eq!(
            first.signing_key_seed.as_str(),
            SIGNING,
            "plaintext still loads"
        );
        assert_eq!(first.hpke_key_seed.as_str(), HPKE);
        assert!(!body.contains(SIGNING) && !body.contains(HPKE), "{body}");
        assert_eq!(
            second.signing_key_seed.as_str(),
            SIGNING,
            "no key lost on migration"
        );
        assert_eq!(second.hpke_key_seed.as_str(), HPKE);
        assert_eq!(second.token.as_str(), "secret-token", "other fields kept");
    }

    /// A 2.4.3 or 2.4.4 file holds DPAPI-protected seeds; they still move into
    /// the credential store and the file keeps only the references.
    #[cfg(windows)]
    #[test]
    fn a_dpapi_protected_seed_moves_to_the_credential_store() {
        let (_dir, _lock) = scratch();
        save(&enrolled()).unwrap();
        assert!(on_disk().contains("dpapi:"));
        let mut c = load().unwrap();
        let moved = protect_keys(&mut c).unwrap();
        let body = on_disk();
        let saved = load().unwrap();
        store::set_config_root(None);

        assert!(moved);
        assert!(
            !body.contains("dpapi:") && !body.contains(SIGNING),
            "{body}"
        );
        assert!(saved.signing_key_seed.is_empty() && !saved.signing_credential_ref.is_empty());
        assert_eq!(saved.hpke_seed().unwrap(), [0x22; 32]);
    }
}
