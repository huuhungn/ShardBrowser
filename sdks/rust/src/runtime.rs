//! Runtime cache: download ShardX engine + Widevine CDM + fingerprint
//! library from the ProxyShard CDN, extract into a per-user cache dir, place
//! Widevine inside the engine bundle, remember etags so subsequent runs are
//! zero-network. Mirrors `src-tauri/src/runtime.rs` in the launcher and the
//! Node/Python SDK `runtime` module.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;

pub const PUB_BASE: &str = "https://pub-e57a7c60f6934eb09a6600bf2fc59cdc.r2.dev";
pub const CHROMIUM_VERSION: &str = "152.0.7977.65";
/// This SDK's own version, compared against the manifest's `min_sdk_version`.
pub const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Version manifest (GitHub raw) — one tiny GET yields every archive's current
/// etag, so we never poll R2/S3 (no per-archive HEAD).
pub const MANIFEST_URL: &str =
    "https://raw.githubusercontent.com/ProxyShard/ShardBrowser/main/runtime.json";

const FINGERPRINTS_KEY: &str = "ShardX-Fingerprints.zip";
const FINGERPRINTS_TOP_DIR: &str = "shardx-fingerprints";

/// Download-progress callback: `(label, received_bytes, total_bytes)`.
pub type ProgressCb = Arc<dyn Fn(&str, u64, u64) + Send + Sync>;

/// One downloadable archive on the CDN.
#[derive(Clone, Debug)]
pub struct Archive {
    pub key: String,
    pub label: String,
}

/// Per-host archive set + extracted paths.
#[derive(Clone, Debug)]
pub struct HostSpec {
    pub browser: Archive,
    pub widevine: Option<Archive>,
    pub binary_subpath: Vec<String>,
    pub widevine_subpath: Vec<String>,
}

fn arc(key: &str, label: &str) -> Archive {
    Archive {
        key: key.into(),
        label: label.into(),
    }
}

/// Archives + layout for the current host; errors on unsupported platforms.
#[allow(clippy::needless_return)]
pub fn host_spec() -> Result<HostSpec> {
    let p = |parts: &[&str]| parts.iter().map(|s| s.to_string()).collect::<Vec<_>>();

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        return Ok(HostSpec {
            browser: arc("ShardX-Mac-arm64.zip", "ShardX browser (macOS arm64)"),
            widevine: Some(arc("ShardX-Widevine-Mac-arm64.zip", "Widevine CDM")),
            binary_subpath: p(&[
                "ShardX-Mac-arm64",
                "ShardX.app",
                "Contents",
                "MacOS",
                "ShardX",
            ]),
            widevine_subpath: p(&[
                "ShardX-Mac-arm64",
                "ShardX.app",
                "Contents",
                "Frameworks",
                "ShardX Framework.framework",
                "Versions",
                CHROMIUM_VERSION,
                "Libraries",
                "WidevineCdm",
            ]),
        });
    }
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        return Ok(HostSpec {
            browser: arc("ShardX-Windows.zip", "ShardX browser (Windows x64)"),
            widevine: Some(arc("ShardX-Widevine-Win.zip", "Widevine CDM")),
            binary_subpath: p(&["ShardX-Windows", "chrome.exe"]),
            widevine_subpath: p(&["ShardX-Windows", "WidevineCdm"]),
        });
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        return Ok(HostSpec {
            browser: arc("ShardX-Linux.zip", "ShardX browser (Linux x64)"),
            widevine: Some(arc("ShardX-Widevine-Linux.zip", "Widevine CDM")),
            binary_subpath: p(&["ShardX-Linux", "chrome"]),
            widevine_subpath: p(&["ShardX-Linux", "WidevineCdm"]),
        });
    }
    #[allow(unreachable_code)]
    Err(anyhow!(
        "Unsupported host. ShardX ships mac-arm64, win-x64, linux-x64."
    ))
}

/// Default per-user cache dir (mirrors the Node SDK layout, `shardx-sdk`).
#[allow(clippy::needless_return)]
pub fn default_cache_dir() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    #[cfg(target_os = "macos")]
    {
        return home
            .join("Library")
            .join("Application Support")
            .join("shardx-sdk");
    }
    #[cfg(target_os = "windows")]
    {
        return std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.clone())
            .join("shardx-sdk");
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        return std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".cache"))
            .join("shardx-sdk");
    }
}

#[derive(Default, Serialize, Deserialize)]
struct Manifest {
    browser_etag: Option<String>,
    widevine_etag: Option<String>,
    fingerprints_etag: Option<String>,
    /// Chromium version of the engine last written to disk — the fallback when
    /// the on-disk version marker can't be read (e.g. Linux).
    #[serde(default)]
    installed_chromium_version: Option<String>,
    /// Build stamp of the archive last extracted; fallback when it ships none.
    #[serde(default)]
    installed_engine_build: Option<String>,
}

pub struct Runtime {
    pub root: PathBuf,
    pub spec: HostSpec,
    profiles_override: Option<PathBuf>,
    progress: Option<ProgressCb>,
    checked: AtomicBool,
    /// Engine chromium version (manifest-driven; set on install()).
    engine_version: std::sync::Mutex<String>,
    /// GREASE brand/version from the manifest (rotates per release; can't be
    /// derived from the version). `(brand, version)`, set on install().
    grease: std::sync::Mutex<(Option<String>, Option<String>)>,
    /// TLS block from the manifest (signature_algorithms / cipher_suites),
    /// applied to profiles on launch so the JA4 hash keeps matching the Chrome
    /// version the profile claims. Set on install().
    tls: std::sync::Mutex<Option<serde_json::Value>>,
}

impl Runtime {
    pub fn new(
        cache_dir: Option<PathBuf>,
        profiles_dir: Option<PathBuf>,
        progress: Option<ProgressCb>,
    ) -> Result<Self> {
        let root = cache_dir.unwrap_or_else(default_cache_dir);
        fs::create_dir_all(&root).with_context(|| format!("create cache dir {root:?}"))?;
        Ok(Self {
            root,
            spec: host_spec()?,
            profiles_override: profiles_dir,
            progress,
            checked: AtomicBool::new(false),
            engine_version: std::sync::Mutex::new(CHROMIUM_VERSION.to_string()),
            grease: std::sync::Mutex::new((None, None)),
            tls: std::sync::Mutex::new(None),
        })
    }

    /// GREASE `(brand, version)` from the manifest (set on install()).
    pub fn grease(&self) -> (Option<String>, Option<String>) {
        self.grease.lock().unwrap().clone()
    }

    /// TLS overrides from the manifest (set on install()).
    pub fn tls(&self) -> Option<serde_json::Value> {
        self.tls.lock().unwrap().clone()
    }

    /// Engine chromium version (manifest-driven; set on install()).
    pub fn chromium_version(&self) -> String {
        self.engine_version.lock().unwrap().clone()
    }

    pub fn manifest_path(&self) -> PathBuf {
        self.root.join("manifest.json")
    }

    pub fn binary_path(&self) -> PathBuf {
        let mut p = self.root.clone();
        for seg in &self.spec.binary_subpath {
            p.push(seg);
        }
        p
    }

    pub fn fingerprints_dir(&self) -> PathBuf {
        let d = self.root.join("fingerprints");
        let _ = fs::create_dir_all(&d);
        d
    }

    /// Per-profile user-data-dir root. `<cache>/profiles/` unless overridden.
    pub fn profiles_root(&self) -> PathBuf {
        let d = self
            .profiles_override
            .clone()
            .unwrap_or_else(|| self.root.join("profiles"));
        let _ = fs::create_dir_all(&d);
        d
    }

    pub fn installed(&self) -> bool {
        self.binary_path().exists()
    }

    /// Chromium version of the engine actually on disk — read from the mac
    /// Framework `Versions/<ver>/` dir or the win `<ver>.manifest` file. `None`
    /// on Linux (no on-disk version marker) or when unreadable.
    fn installed_engine_version(&self) -> Option<String> {
        #[cfg(target_os = "macos")]
        {
            let versions = self
                .root
                .join("ShardX-Mac-arm64")
                .join("ShardX.app")
                .join("Contents")
                .join("Frameworks")
                .join("ShardX Framework.framework")
                .join("Versions");
            for ent in fs::read_dir(&versions).ok()?.flatten() {
                let name = ent.file_name().to_string_lossy().into_owned();
                if name != "Current" && name.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                    return Some(name);
                }
            }
            None
        }
        #[cfg(target_os = "windows")]
        {
            // Only accept a `<version>.manifest` whose stem parses as a version,
            // so a stray/leftover manifest can't pin a bogus version.
            for ent in fs::read_dir(self.root.join("ShardX-Windows"))
                .ok()?
                .flatten()
            {
                let p = ent.path();
                if p.extension().and_then(|s| s.to_str()) == Some("manifest") {
                    if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
                        if stem.contains('.') && stem.starts_with(|c: char| c.is_ascii_digit()) {
                            return Some(stem.to_string());
                        }
                    }
                }
            }
            None
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            None
        }
    }

    /// Effective installed version. Trusts the version recorded at install time
    /// (authoritative — written only after a successful extract) over re-reading
    /// it off disk, which can carry stale files from a previous version. On-disk
    /// detection is the fallback for legacy installs with no recorded version.
    fn effective_installed_version(&self, local: &Manifest) -> Option<String> {
        local
            .installed_chromium_version
            .clone()
            .or_else(|| self.installed_engine_version())
    }

    /// Build stamp on disk: `<engine>/shardx-build` when the archive ships one,
    /// else what was recorded at install time.
    fn installed_engine_build(&self, local: &Manifest) -> Option<String> {
        self.spec
            .binary_subpath
            .first()
            .map(|dir| self.root.join(dir).join("shardx-build"))
            .and_then(|p| fs::read_to_string(p).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| local.installed_engine_build.clone())
    }

    /// Chromium version, `engine_build`, or the archive hash — any one of them
    /// means the engine moved. An unknown local value is not a mismatch.
    fn engine_outdated(&self, local: &Manifest, remote: &RemoteManifest) -> bool {
        let version_moved = remote
            .chromium_version
            .as_deref()
            .is_some_and(|rv| self.effective_installed_version(local).as_deref() != Some(rv));
        let differs = |have: Option<String>, want: Option<&str>| match (have, want) {
            (Some(h), Some(w)) => !h.is_empty() && h != w,
            _ => false,
        };
        let build_moved = differs(
            self.installed_engine_build(local),
            remote.engine_build.as_deref(),
        );
        let hash_moved = differs(
            local.browser_etag.clone(),
            remote
                .archives
                .get(&self.spec.browser.key)
                .map(|s| s.as_str()),
        );
        version_moved || build_moved || hash_moved
    }

    fn load_manifest(&self) -> Manifest {
        fs::read_to_string(self.manifest_path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    fn save_manifest(&self, m: &Manifest) -> Result<()> {
        fs::write(self.manifest_path(), serde_json::to_string_pretty(m)?)?;
        Ok(())
    }

    /// Ensure the engine + Widevine + fingerprints are present and current.
    /// Cheap no-op after the first successful call in-process unless `force`.
    pub async fn install(&self, force: bool) -> Result<()> {
        if self.checked.load(Ordering::Relaxed) && !force {
            return Ok(());
        }
        let mut local = self.load_manifest();
        let remote = fetch_manifest().await;
        // Remember the engine version + grease so launch can normalise profiles.
        *self.engine_version.lock().unwrap() = remote
            .chromium_version
            .clone()
            .unwrap_or_else(|| CHROMIUM_VERSION.to_string());
        *self.grease.lock().unwrap() = (remote.grease_brand.clone(), remote.grease_version.clone());
        *self.tls.lock().unwrap() = remote.tls.clone();

        // Refused rather than installed: this SDK could not configure it.
        if let Some(min) = remote.min_sdk_version.as_deref() {
            if version_lt(SDK_VERSION, min) {
                anyhow::bail!(
                    "this engine build needs shardx {min} or newer — you are on {SDK_VERSION}; \
                     upgrade the SDK first"
                );
            }
        }
        // Unknown is never a mismatch, so adopt a stamp once or the first bump
        // never lands.
        if self.installed()
            && remote.engine_build.is_some()
            && self.installed_engine_build(&local).is_none()
        {
            local.installed_engine_build = remote.engine_build.clone();
        }
        // A None manifest (unreachable) forces nothing.
        let need_browser = force || !self.installed() || self.engine_outdated(&local, &remote);
        if need_browser {
            // Wipe the old engine tree first so a leftover `<old>.manifest` /
            // stale libs can't linger beside the new ones (that pinned the
            // detected version → endless re-download). binary_subpath[0] is the
            // engine root dir.
            if let Some(engine_dir) = self.spec.binary_subpath.first() {
                let _ = fs::remove_dir_all(self.root.join(engine_dir));
            }
            let etag = self
                .download_and_extract(&self.spec.browser, &self.root)
                .await?;
            local.browser_etag = Some(etag);
            if remote.engine_build.is_some() {
                local.installed_engine_build = remote.engine_build.clone();
            }
        }

        if let Some(wv) = self.spec.widevine.clone() {
            if need_browser || local.widevine_etag.is_none() {
                let etag = self.download_and_extract(&wv, &self.root).await?;
                self.place_widevine();
                local.widevine_etag = Some(etag);
            }
        }

        let remote_fp = remote.archives.get(FINGERPRINTS_KEY);
        let fp_has_json = fs::read_dir(self.fingerprints_dir())
            .map(|it| {
                it.flatten()
                    .any(|e| e.path().extension().and_then(|s| s.to_str()) == Some("json"))
            })
            .unwrap_or(false);
        let need_fp = force
            || !fp_has_json
            || remote_fp
                .map(|rf| local.fingerprints_etag.as_deref() != Some(rf.as_str()))
                .unwrap_or(false);
        if need_fp {
            self.install_fingerprints().await?;
            if let Some(rf) = remote_fp {
                local.fingerprints_etag = Some(rf.clone());
            }
        }

        // Authoritative: we just extracted exactly this version (old tree wiped
        // first). Recording the known value beats re-reading it off disk.
        local.installed_chromium_version = Some(self.chromium_version());

        self.save_manifest(&local)?;

        #[cfg(unix)]
        fix_unix_exec_bits(&self.root);

        self.checked.store(true, Ordering::Relaxed);
        Ok(())
    }

    async fn download_and_extract(&self, archive: &Archive, dest: &Path) -> Result<String> {
        let url = format!("{PUB_BASE}/{}", archive.key);
        fs::create_dir_all(dest)?;
        let tmp = dest.join(format!(".{}.tmp", archive.key));

        let mut resp = reqwest::Client::new()
            .get(&url)
            .send()
            .await?
            .error_for_status()
            .with_context(|| format!("download {}", archive.key))?;
        let total = resp.content_length().unwrap_or(0);
        let etag = resp
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim_matches('"').to_string())
            .unwrap_or_default();

        {
            let mut out = tokio::fs::File::create(&tmp).await?;
            let mut received: u64 = 0;
            while let Some(chunk) = resp.chunk().await? {
                out.write_all(&chunk).await?;
                received += chunk.len() as u64;
                if let Some(cb) = &self.progress {
                    cb(&archive.label, received, total);
                }
            }
            out.flush().await?;
        }

        let zip_path = tmp.clone();
        let dest = dest.to_path_buf();
        tokio::task::spawn_blocking(move || extract_zip(&zip_path, &dest)).await??;
        let _ = fs::remove_file(&tmp);
        Ok(etag)
    }

    async fn install_fingerprints(&self) -> Result<()> {
        let dir = self.fingerprints_dir();
        let staging = dir.join(".staging");
        let _ = fs::remove_dir_all(&staging);
        fs::create_dir_all(&staging)?;
        let archive = Archive {
            key: FINGERPRINTS_KEY.into(),
            label: "Fingerprint library".into(),
        };
        self.download_and_extract(&archive, &staging).await?;

        let src = staging.join(FINGERPRINTS_TOP_DIR);
        let walk = if src.exists() { src } else { staging.clone() };
        for ent in fs::read_dir(&walk)? {
            let ent = ent?;
            let p = ent.path();
            if p.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            // Always overwrite bundled templates so engine-version bumps reach
            // existing libraries; user-added files (other names) are untouched.
            let dst = dir.join(p.file_name().unwrap());
            fs::copy(&p, &dst)?;
        }
        let _ = fs::remove_dir_all(&staging);
        Ok(())
    }

    fn place_widevine(&self) {
        let Some(wv) = &self.spec.widevine else {
            return;
        };
        let wrapper = wv.key.trim_end_matches(".zip");
        let src = self.root.join(wrapper).join("WidevineCdm");
        if !src.exists() {
            return;
        }
        let mut dst = self.root.clone();
        for seg in &self.spec.widevine_subpath {
            dst.push(seg);
        }
        if dst.exists() {
            let _ = fs::remove_dir_all(&dst);
        }
        if let Some(parent) = dst.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::rename(&src, &dst);
        let _ = fs::remove_dir_all(self.root.join(wrapper));
    }
}

#[derive(Default)]
struct RemoteManifest {
    archives: std::collections::HashMap<String, String>,
    chromium_version: Option<String>,
    /// GREASE brand/version (rotates per release; travels in the manifest as
    /// data since it can't be derived from the version number).
    grease_brand: Option<String>,
    grease_version: Option<String>,
    /// TLS overrides; only the keys present here are applied to a profile.
    tls: Option<serde_json::Value>,
    /// Which build of the engine archive this is, apart from its Chromium
    /// version. Not the manifest-wide `revision`, which also moves for a TLS
    /// or GREASE edit.
    engine_build: Option<String>,
    /// Lowest SDK version this engine build can be driven by.
    min_sdk_version: Option<String>,
}

/// Dotted-numeric compare; non-numeric parts count as 0.
fn version_lt(a: &str, b: &str) -> bool {
    let parts = |s: &str| -> Vec<u32> {
        s.split(['.', '-', '+'])
            .map(|p| p.parse::<u32>().unwrap_or(0))
            .collect()
    };
    let (va, vb) = (parts(a), parts(b));
    for i in 0..va.len().max(vb.len()) {
        let (x, y) = (
            va.get(i).copied().unwrap_or(0),
            vb.get(i).copied().unwrap_or(0),
        );
        if x != y {
            return x < y;
        }
    }
    false
}

/// Fetch the version manifest (GitHub raw) — one request that yields every
/// archive's current etag + the chromium version, replacing per-archive HEADs
/// against R2/S3. Empty/None when unreachable.
async fn fetch_manifest() -> RemoteManifest {
    async fn inner() -> Option<RemoteManifest> {
        let resp = reqwest::Client::new().get(MANIFEST_URL).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let v: serde_json::Value = resp.json().await.ok()?;
        let archives = v
            .get("archives")
            .and_then(|a| a.as_object())
            .map(|o| {
                o.iter()
                    .filter_map(|(k, val)| val.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();
        let str_field = |k: &str| v.get(k).and_then(|s| s.as_str()).map(String::from);
        Some(RemoteManifest {
            archives,
            chromium_version: str_field("chromium_version"),
            grease_brand: str_field("grease_brand"),
            grease_version: str_field("grease_version"),
            tls: v.get("tls").filter(|t| t.is_object()).cloned(),
            // Written as a number or a string; both mean the same thing.
            engine_build: v.get("engine_build").and_then(|b| match b {
                serde_json::Value::String(s) => Some(s.clone()),
                serde_json::Value::Number(n) => Some(n.to_string()),
                _ => None,
            }),
            min_sdk_version: str_field("min_sdk_version"),
        })
    }
    inner().await.unwrap_or_default()
}

/// Extract `zip_path` into `dest`. On Unix shell out to system `unzip`
/// (preserves symlinks + exec bits the `zip` crate drops); on Windows use
/// the `zip` crate (no symlinks/exec bits to preserve there).
fn extract_zip(zip_path: &Path, dest: &Path) -> Result<()> {
    fs::create_dir_all(dest)?;
    #[cfg(unix)]
    {
        use std::process::Command;
        let out = Command::new("unzip")
            .arg("-q")
            .arg("-o")
            .arg(zip_path)
            .arg("-d")
            .arg(dest)
            .output()
            .map_err(|e| {
                anyhow!("system `unzip` not found ({e}); install via `apt install unzip` / `brew install unzip`")
            })?;
        let code = out.status.code().unwrap_or(-1);
        if code > 1 {
            anyhow::bail!(
                "unzip failed for {} (exit {}): {}",
                zip_path.display(),
                code,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let f = fs::File::open(zip_path)?;
        let mut archive = zip::ZipArchive::new(f)?;
        archive.extract(dest)?;
        Ok(())
    }
}

/// Add +x to every ELF/Mach-O file under `root` (Windows zip producers drop
/// Unix exec bits, so chrome + its helpers come out non-executable).
#[cfg(unix)]
fn fix_unix_exec_bits(root: &Path) {
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;
    const MAGIC: &[[u8; 4]] = &[
        [0x7f, b'E', b'L', b'F'],
        [0xfe, 0xed, 0xfa, 0xcf],
        [0xcf, 0xfa, 0xed, 0xfe],
        [0xfe, 0xed, 0xfa, 0xce],
        [0xce, 0xfa, 0xed, 0xfe],
        [0xca, 0xfe, 0xba, 0xbe],
        [0xbe, 0xba, 0xfe, 0xca],
    ];
    fn walk(dir: &Path) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for ent in entries.flatten() {
            let p = ent.path();
            let Ok(ft) = ent.file_type() else { continue };
            if ft.is_symlink() {
                continue;
            }
            if ft.is_dir() {
                walk(&p);
                continue;
            }
            if !ft.is_file() {
                continue;
            }
            let mut head = [0u8; 4];
            let Ok(mut f) = fs::File::open(&p) else {
                continue;
            };
            if f.read_exact(&mut head).is_err() {
                continue;
            }
            if !MAGIC.contains(&head) {
                continue;
            }
            if let Ok(meta) = fs::metadata(&p) {
                let mut perm = meta.permissions();
                perm.set_mode(perm.mode() | 0o111);
                let _ = fs::set_permissions(&p, perm);
            }
        }
    }
    walk(root);
}

#[cfg(test)]
mod tests {
    use super::*;

    // host_spec() is the per-platform archive/layout table. Each runner must
    // get its own entry, so assert the contract that holds for the host we
    // are compiled for rather than a lowest common denominator.
    #[test]
    fn host_spec_describes_this_platform() {
        let spec = host_spec().expect("host_spec must support the CI runners");

        assert!(!spec.browser.key.is_empty());
        assert!(spec.browser.key.ends_with(".zip"));
        assert!(!spec.binary_subpath.is_empty());

        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        {
            assert_eq!(spec.browser.key, "ShardX-Windows.zip");
            // The launcher joins these parts, so the executable name matters.
            assert_eq!(spec.binary_subpath.last().unwrap(), "chrome.exe");
            assert!(spec.widevine.is_some(), "Windows ships a Widevine CDM");
        }

        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            assert_eq!(spec.browser.key, "ShardX-Mac-arm64.zip");
            assert!(spec.binary_subpath.contains(&"ShardX.app".to_string()));
            assert!(spec.widevine.is_some(), "macOS ships a Widevine CDM");
        }

        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            assert_eq!(spec.browser.key, "ShardX-Linux.zip");
        }
    }

    // A Widevine archive without a destination (or the reverse) would extract
    // into the wrong place, so the pair must always agree.
    #[test]
    fn widevine_archive_and_subpath_agree() {
        let spec = host_spec().expect("host_spec must support the CI runners");
        if spec.widevine.is_some() {
            assert!(
                !spec.widevine_subpath.is_empty(),
                "a Widevine archive needs a destination subpath"
            );
        }
    }

    // Path components are joined by the caller; an embedded separator would
    // silently escape the extraction root.
    #[test]
    fn subpath_components_are_single_segments() {
        let spec = host_spec().expect("host_spec must support the CI runners");
        for part in spec
            .binary_subpath
            .iter()
            .chain(spec.widevine_subpath.iter())
        {
            assert!(!part.is_empty(), "empty path component");
            assert!(
                !part.contains('/') && !part.contains('\\'),
                "component {part:?} must not embed a separator"
            );
            assert_ne!(part, "..", "component must not traverse upwards");
        }
    }

    // default_cache_dir() picks a different root per OS; all we can assert
    // everywhere is that it is absolute and namespaced to this SDK.
    #[test]
    fn default_cache_dir_is_absolute_and_namespaced() {
        let dir = default_cache_dir();
        assert!(dir.is_absolute(), "cache dir {dir:?} must be absolute");
        assert_eq!(dir.file_name().unwrap(), "shardx-sdk");

        #[cfg(target_os = "windows")]
        if let Some(local) = std::env::var_os("LOCALAPPDATA") {
            assert!(dir.starts_with(std::path::PathBuf::from(local)));
        }

        #[cfg(target_os = "macos")]
        assert!(dir.to_string_lossy().contains("Application Support"));
    }
}
