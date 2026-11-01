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

/// Profile tag colors, `{ "<tag>": "<palette id>" }`; the tags live on each profile.
pub fn tags_path() -> Result<PathBuf> {
    Ok(config_root()?.join("tags.json"))
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

/// Where the first-device custody bootstrap keeps its exact requests between
/// attempts. The tenant root key is not here: only its credential reference.
pub fn custody_bootstrap_path() -> Result<PathBuf> {
    Ok(config_root()?.join("custody-bootstrap.json"))
}

pub fn psapi_path() -> Result<PathBuf> {
    Ok(config_root()?.join("psapi.json"))
}

/// Refuses `dir` unless it is on a local NTFS volume (ADR 0002 Q-30; plan
/// L2335: the durability harness holds on supported filesystems only, and a
/// network share fails closed). Off Windows every directory passes.
pub fn require_local_ntfs(dir: &std::path::Path) -> Result<()> {
    shardx_core::volume::require_local_ntfs(dir).map_err(|refusal| volume_error(dir, refusal))
}

fn volume_error(
    dir: &std::path::Path,
    refusal: shardx_core::volume::VolumeRefusal,
) -> anyhow::Error {
    use shardx_core::volume::VolumeRefusal;
    let path = dir.display().to_string();
    anyhow::anyhow!(match refusal {
        VolumeRefusal::Network => {
            crate::errcode::code_with("storage.networkVolume", &[("path", &path)])
        }
        VolumeRefusal::Unsupported(filesystem) => crate::errcode::code_with(
            "storage.unsupportedVolume",
            &[("path", &path), ("filesystem", &filesystem)],
        ),
        VolumeRefusal::Unreadable(detail) => crate::errcode::code_with(
            "storage.volumeUnreadable",
            &[("path", &path), ("detail", &detail)],
        ),
    })
}

/// The startup gate: the config root (settings, `team-sync.db`, key files)
/// and the data root (profiles, user data) must both be on local NTFS.
pub fn require_local_ntfs_roots() -> Result<()> {
    require_local_ntfs(&config_root()?)?;
    require_local_ntfs(&data_root()?)
}

#[cfg(test)]
mod volume_tests {
    use super::*;
    use shardx_core::volume::VolumeRefusal;

    #[test]
    fn each_refusal_is_a_named_error() {
        let dir = std::path::Path::new("D:/data");
        for (refusal, key, arg) in [
            (
                VolumeRefusal::Network,
                "storage.networkVolume",
                "path=D:/data",
            ),
            (
                VolumeRefusal::Unsupported("exFAT".into()),
                "storage.unsupportedVolume",
                "filesystem=exFAT",
            ),
            (
                VolumeRefusal::Unreadable("gone".into()),
                "storage.volumeUnreadable",
                "detail=gone",
            ),
        ] {
            let err = volume_error(dir, refusal).to_string();
            assert!(crate::errcode::has_code(&err, key), "{err}");
            assert!(err.contains(arg), "{err}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn a_local_ntfs_root_passes_and_an_smb_share_or_missing_path_does_not() {
        let dir = tempfile::tempdir().unwrap();
        require_local_ntfs(dir.path()).unwrap();
        let missing = require_local_ntfs(&dir.path().join("missing")).unwrap_err();
        assert!(crate::errcode::has_code(
            &missing.to_string(),
            "storage.volumeUnreadable"
        ));
        let share = match std::env::var_os("SHARDX_TEST_SMB_DIR") {
            Some(dir) => PathBuf::from(dir),
            None => {
                let temp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
                let local = temp.to_string_lossy().into_owned();
                let (drive, tail) = local.trim_start_matches(r"\\?\").split_once(":\\").unwrap();
                PathBuf::from(format!(r"\\localhost\{drive}$\{tail}"))
            }
        };
        if !share.exists() {
            assert!(
                std::env::var_os("SHARDX_TEST_SMB_DIR").is_none(),
                "{share:?} unreachable"
            );
            eprintln!("SKIPPED the SMB half: no reachable SMB share");
            return;
        }
        let err = require_local_ntfs(&share).unwrap_err().to_string();
        assert!(
            crate::errcode::has_code(&err, "storage.networkVolume"),
            "{err}"
        );
    }
}
