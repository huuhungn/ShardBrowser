// $CONFIG/shardx-launcher/: settings.json, proxies.json, bookmarks.json, and
// under data_root() — profiles/, user-data/, extensions/, trash/.
//
// data_root() is movable to another disk from Settings; the config files stay
// put, since that is where the new location is recorded.

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::{OnceLock, RwLock};

pub fn config_root() -> Result<PathBuf> {
    if let Some(root) = config_root_cell().read().ok().and_then(|g| g.clone()) {
        std::fs::create_dir_all(&root)?;
        return Ok(root);
    }
    let base = dirs::config_dir().context("OS config dir unavailable")?;
    let root = base.join("shardx-launcher");
    std::fs::create_dir_all(&root)?;
    Ok(root)
}

fn config_root_cell() -> &'static RwLock<Option<PathBuf>> {
    static CELL: OnceLock<RwLock<Option<PathBuf>>> = OnceLock::new();
    CELL.get_or_init(|| RwLock::new(None))
}

/// Serialises tests that swap the config root.
///
/// The root is process-global, so two test modules that each hold their own
/// lock still race with each other: the failure shows up as one module's
/// fixtures appearing in the other's store, which reads like a routing bug
/// rather than a test isolation one. Every test that calls
/// [`set_config_root`] must hold this, including the integration tests, which
/// are separate crates and so cannot see a `#[cfg(test)]` item.
pub fn config_root_test_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    &LOCK
}

/// Point the config dir somewhere else (None = back to the OS config dir).
///
/// Exists for tests: a test that writes automation projects into the
/// operator's real store would corrupt the profiles this machine actually
/// runs. Production never calls it.
pub fn set_config_root(root: Option<PathBuf>) {
    if let Ok(mut g) = config_root_cell().write() {
        *g = root;
    }
}

fn data_root_cell() -> &'static RwLock<Option<PathBuf>> {
    static CELL: OnceLock<RwLock<Option<PathBuf>>> = OnceLock::new();
    CELL.get_or_init(|| RwLock::new(None))
}

/// Point the heavy directories at `root` (None = back to the config dir).
pub fn set_data_root(root: Option<PathBuf>) {
    if let Ok(mut g) = data_root_cell().write() {
        *g = root;
    }
}

/// Where profiles, user-data, extensions and the trash live.
pub fn data_root() -> Result<PathBuf> {
    let over = data_root_cell().read().ok().and_then(|g| g.clone());
    match over {
        Some(p) => {
            std::fs::create_dir_all(&p)?;
            Ok(p)
        }
        None => config_root(),
    }
}

fn data_sub(name: &str) -> Result<PathBuf> {
    let p = data_root()?.join(name);
    std::fs::create_dir_all(&p)?;
    Ok(p)
}

pub fn profiles_dir() -> Result<PathBuf> {
    data_sub("profiles")
}

pub fn user_data_root() -> Result<PathBuf> {
    data_sub("user-data")
}

/// Unpacked extensions, one directory per id; `--load-extension` points here.
pub fn extensions_dir() -> Result<PathBuf> {
    data_sub("extensions")
}

/// Deleted profiles, one `<id>.zip` + `<id>.json` manifest each.
pub fn trash_dir() -> Result<PathBuf> {
    data_sub("trash")
}

pub fn fingerprints_dir() -> Result<PathBuf> {
    let p = config_root()?.join("fingerprints");
    std::fs::create_dir_all(&p)?;
    Ok(p)
}

/// Cached Widevine CDM, seeded from a host Chrome install (or downloaded from
/// the project's git LFS bucket).  Every freshly-created profile gets a
/// pre-warmed copy so a DRM page doesn't stall on the component updater.
pub fn widevine_cache_dir() -> Result<PathBuf> {
    Ok(config_root()?.join("widevine-cdm"))
}

pub fn proxies_path() -> Result<PathBuf> {
    Ok(config_root()?.join("proxies.json"))
}

pub fn settings_path() -> Result<PathBuf> {
    Ok(config_root()?.join("settings.json"))
}

/// Automation projects: blocks, run settings, export bundles.
pub fn automation_path() -> Result<PathBuf> {
    Ok(config_root()?.join("automation.json"))
}

/// Folder-scoped bookmarks, merged into each profile's Bookmarks on launch.
pub fn bookmarks_path() -> Result<PathBuf> {
    Ok(config_root()?.join("bookmarks.json"))
}

/// ProxyShard billing-API config (Bearer key). Kept in its own file so the
/// Settings page (which round-trips the whole Settings struct) can never
/// clobber the saved key.
/// Team server connection + this device's enrollment. Its own file for the
/// same reason as psapi.json: a Settings round-trip must not be able to drop
/// the device identity.
pub fn team_config_path() -> Result<PathBuf> {
    Ok(config_root()?.join("team.json"))
}

/// Where collected fleet keys are cached.
///
/// Kept out of `team.json` deliberately: that file is round-tripped by the
/// Settings page, and key material must not ride along with settings a UI
/// save could rewrite.
pub fn fleet_keys_path() -> Result<PathBuf> {
    Ok(config_root()?.join("fleet-keys.json"))
}

pub fn psapi_path() -> Result<PathBuf> {
    Ok(config_root()?.join("psapi.json"))
}
