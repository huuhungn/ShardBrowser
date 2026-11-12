// $CONFIG/shardx-launcher/: settings.json, proxies.json, bookmarks.json, and
// under data_root() — profiles/, user-data/, extensions/, trash/.
//
// data_root() is movable to another disk from Settings; the config files stay
// put, since that is where the new location is recorded.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
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

fn cache_mapping_cell() -> &'static RwLock<Option<(PathBuf, PathBuf)>> {
    static CELL: OnceLock<RwLock<Option<(PathBuf, PathBuf)>>> = OnceLock::new();
    CELL.get_or_init(|| RwLock::new(None))
}

/// Exists for tests: stands in for the OS (config, cache) folders, which only macOS and Linux map.
#[cfg(test)]
pub fn set_cache_mapping(dirs: Option<(PathBuf, PathBuf)>) {
    if let Ok(mut g) = cache_mapping_cell().write() {
        *g = dirs;
    }
}

/// The OS (config, cache) folders Chromium maps a profile between; none where the cache stays
/// inside the profile folder (Windows).
fn cache_mapping() -> Option<(PathBuf, PathBuf)> {
    if let Some(dirs) = cache_mapping_cell().read().ok().and_then(|g| g.clone()) {
        return Some(dirs);
    }
    if cfg!(any(target_os = "macos", target_os = "linux")) {
        return Some((dirs::config_dir()?, dirs::cache_dir()?));
    }
    None
}

/// Where Chromium keeps the disk cache of the browser profile at `udd`. A profile under the OS
/// config folder gets it under the OS cache folder, at the same relative path; anywhere else the
/// cache is inside `udd` and goes with it.
pub fn browser_cache_twin(udd: &Path) -> Option<PathBuf> {
    let (config, cache) = cache_mapping()?;
    let rel = udd.strip_prefix(config).ok()?;
    (!rel.as_os_str().is_empty()).then(|| cache.join(rel))
}

/// Removes that cache with the profile: it is not inside the folder the profile is deleted with.
/// A symlink in its place is unlinked, never followed.
pub fn remove_browser_cache(udd: &Path) {
    if let Some(twin) = browser_cache_twin(udd) {
        let _ = std::fs::remove_dir_all(twin);
    }
}

/// Written once the orphan sweep has run, so it never runs again.
const CACHE_SWEEP_MARKER: &str = "cache-swept-v1";

/// Caches of profiles deleted before their cache went with them: folders of the cache twin of
/// `user-data/` named like a profile id that no profile record, user-data folder or trash archive
/// has. Runs once; returns how many it removed.
pub fn sweep_orphan_caches() -> usize {
    let Ok(marker) = config_root().map(|c| c.join(CACHE_SWEEP_MARKER)) else {
        return 0;
    };
    let (Ok(root), Ok(profiles), Ok(trash)) = (user_data_root(), profiles_dir(), trash_dir())
    else {
        return 0;
    };
    let Some(twin) = browser_cache_twin(&root) else {
        return 0;
    };
    if marker.exists() {
        return 0;
    }
    // A path that cannot be checked counts as present.
    let known = |id: &str| {
        [
            root.join(id),
            profiles.join(format!("{id}.json")),
            trash.join(format!("{id}.zip")),
            trash.join(format!("{id}.json")),
        ]
        .iter()
        .any(|p| p.try_exists().unwrap_or(true))
    };
    match sweep_orphans_in(&twin, known) {
        Ok(n) => {
            let _ = std::fs::write(marker, b"");
            n
        }
        Err(e) => {
            eprintln!("[launcher] cache sweep failed: {e}");
            0
        }
    }
}

/// Removes the real folders of `twin` named like a profile id that `known` does not claim.
fn sweep_orphans_in(twin: &Path, known: impl Fn(&str) -> bool) -> std::io::Result<usize> {
    let entries = match std::fs::read_dir(twin) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    let mut n = 0;
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        // `DirEntry::file_type` does not follow a symlink, so a link is never removed through.
        let is_dir = e.file_type().is_ok_and(|t| t.is_dir());
        if is_dir
            && uuid::Uuid::parse_str(&name).is_ok()
            && !known(&name)
            && std::fs::remove_dir_all(e.path()).is_ok()
        {
            n += 1;
        }
    }
    Ok(n)
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

/// Where Create fleet key keeps its exact requests between attempts. The
/// fleet key is not here: only the nonce of its credential reference.
pub fn fleet_custody_path() -> Result<PathBuf> {
    Ok(config_root()?.join("fleet-custody.json"))
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

#[cfg(test)]
mod cache_sweep_tests {
    use super::*;

    fn uuid() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    #[test]
    fn a_profile_cache_maps_to_the_cache_folder_only_under_the_config_folder() {
        let _lock = config_root_test_lock()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        set_cache_mapping(Some(("/cfg".into(), "/cache".into())));
        assert_eq!(
            browser_cache_twin(Path::new("/cfg/shardx/user-data/abc")),
            Some(PathBuf::from("/cache/shardx/user-data/abc"))
        );
        assert_eq!(
            browser_cache_twin(Path::new("/Volumes/Data/user-data/abc")),
            None
        );
        assert_eq!(browser_cache_twin(Path::new("/cfg")), None);
        set_cache_mapping(None);
    }

    #[test]
    fn the_sweep_removes_the_cache_of_a_deleted_profile_once_and_nothing_that_is_known() {
        let _lock = config_root_test_lock()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let (config, cache) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        set_config_root(Some(config.path().to_path_buf()));
        set_cache_mapping(Some((
            config.path().to_path_buf(),
            cache.path().to_path_buf(),
        )));
        let twin = cache.path().join("user-data");
        let (live, trashed, trashed_meta, with_data, orphan) =
            (uuid(), uuid(), uuid(), uuid(), uuid());
        std::fs::write(profiles_dir().unwrap().join(format!("{live}.json")), b"{}").unwrap();
        std::fs::write(trash_dir().unwrap().join(format!("{trashed}.zip")), b"z").unwrap();
        std::fs::write(
            trash_dir().unwrap().join(format!("{trashed_meta}.json")),
            b"{}",
        )
        .unwrap();
        std::fs::create_dir_all(user_data_root().unwrap().join(&with_data)).unwrap();
        for id in [
            &live,
            &trashed,
            &trashed_meta,
            &with_data,
            &orphan,
            &"Default".to_string(),
        ] {
            std::fs::create_dir_all(twin.join(id).join("Cache_Data")).unwrap();
        }
        let a_file = twin.join(uuid());
        std::fs::write(&a_file, b"not a folder").unwrap();

        assert_eq!(sweep_orphan_caches(), 1);
        assert!(!twin.join(&orphan).exists());
        for id in [
            &live,
            &trashed,
            &trashed_meta,
            &with_data,
            &"Default".to_string(),
        ] {
            assert!(twin.join(id).exists(), "{id} stays");
        }
        assert!(a_file.exists());

        let later = uuid();
        std::fs::create_dir_all(twin.join(&later)).unwrap();
        assert_eq!(sweep_orphan_caches(), 0, "it ran once");
        assert!(twin.join(&later).exists());
        set_cache_mapping(None);
    }

    #[test]
    fn the_sweep_does_nothing_where_the_cache_stays_inside_the_profile() {
        let _lock = config_root_test_lock()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let config = tempfile::tempdir().unwrap();
        set_config_root(Some(config.path().to_path_buf()));
        set_cache_mapping(None);
        if cache_mapping().is_none() {
            assert_eq!(sweep_orphan_caches(), 0);
            assert!(!config.path().join(CACHE_SWEEP_MARKER).exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_sweep_leaves_a_symlink_and_what_it_points_to_alone() {
        let (twin, outside) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        std::fs::write(outside.path().join("keep"), b"x").unwrap();
        std::os::unix::fs::symlink(outside.path(), twin.path().join(uuid())).unwrap();
        assert_eq!(sweep_orphans_in(twin.path(), |_| false).unwrap(), 0);
        assert!(outside.path().join("keep").exists());
    }
}
