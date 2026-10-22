//! Self-bootstrapping runtime: download ShardX browser + Widevine from R2.
//! Emits `runtime:progress` and `runtime:done` events to the Tauri frontend.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use tauri::{Emitter, Window};
use tokio::io::AsyncWriteExt;

const PUB_BASE: &str = "https://pub-e57a7c60f6934eb09a6600bf2fc59cdc.r2.dev";
/// Version manifest (GitHub raw) — one tiny GET yields every archive's current
/// etag, so install/status checks never poll R2/S3 per-archive.
/// Pinned to this fork, not upstream: the manifest carries the engine version,
/// the grease brand and the TLS/JA4 parameters, so an upstream push would
/// otherwise re-target every installed custom Launcher without review. Our
/// runtime.json is updated deliberately, after the launcher can honour it.
const MANIFEST_URL: &str =
    "https://raw.githubusercontent.com/huuhungn/ShardBrowser/main/runtime.json";
/// Chromium version baked into the current bundle (used for Mac Framework path).
pub const CHROMIUM_VERSION: &str = "156.0.8078.48";

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ArchiveSpec {
    pub key: String,
    pub label: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PlatformSpec {
    pub browser: ArchiveSpec,
    pub widevine: Option<ArchiveSpec>,
}

/// Archives required for this host; None on unsupported platforms.
pub fn host_spec() -> Option<PlatformSpec> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    return Some(PlatformSpec {
        browser: ArchiveSpec {
            key: "ShardX-Mac-arm64.zip".into(),
            label: "ShardX browser (macOS arm64)".into(),
        },
        widevine: Some(ArchiveSpec {
            key: "ShardX-Widevine-Mac-arm64.zip".into(),
            label: "Widevine CDM".into(),
        }),
    });
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    return Some(PlatformSpec {
        browser: ArchiveSpec {
            key: "ShardX-Windows.zip".into(),
            label: "ShardX browser (Windows x64)".into(),
        },
        widevine: Some(ArchiveSpec {
            key: "ShardX-Widevine-Win.zip".into(),
            label: "Widevine CDM".into(),
        }),
    });
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    return Some(PlatformSpec {
        browser: ArchiveSpec {
            key: "ShardX-Linux.zip".into(),
            label: "ShardX browser (Linux x64)".into(),
        },
        widevine: Some(ArchiveSpec {
            key: "ShardX-Widevine-Linux.zip".into(),
            label: "Widevine CDM".into(),
        }),
    });
    #[allow(unreachable_code)]
    None
}

/// Runtime dir under the platform data dir; kept outside the launcher bundle.
pub fn runtime_dir() -> Result<PathBuf> {
    Ok(dirs::data_dir()
        .context(crate::errcode::code("runtime.noPlatformDataDir"))?
        .join("shardx-launcher")
        .join("runtime"))
}

/// Path to the chrome binary inside the extracted runtime.
pub fn binary_path() -> Result<PathBuf> {
    Ok(runtime_dir()?.join(binary_rel()))
}

/// The chrome binary relative to the runtime dir (or to a staging dir).
fn binary_rel() -> PathBuf {
    #[cfg(target_os = "macos")]
    return Path::new("ShardX-Mac-arm64")
        .join("ShardX.app")
        .join("Contents")
        .join("MacOS")
        .join("ShardX");
    #[cfg(target_os = "windows")]
    return Path::new("ShardX-Windows").join("chrome.exe");
    #[cfg(target_os = "linux")]
    return Path::new("ShardX-Linux").join("chrome");
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    return Path::new(engine_root_dir()).join("chrome");
}

fn manifest_path() -> Result<PathBuf> {
    Ok(runtime_dir()?.join("manifest.json"))
}

/// Top-level dir (under runtime_dir) the engine archive extracts into. Wiped
/// before a re-extract so stale files from the previous version can't linger.
fn engine_root_dir() -> &'static str {
    #[cfg(target_os = "macos")]
    return "ShardX-Mac-arm64";
    #[cfg(target_os = "windows")]
    return "ShardX-Windows";
    #[cfg(target_os = "linux")]
    return "ShardX-Linux";
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    return "ShardX-Engine";
}

/// A new engine is extracted here, beside the one in use, and swapped in only
/// once it is complete. The previous engine waits in `ENGINE_OLD` until the new
/// one is in place, so a broken download never leaves the host without one.
const ENGINE_STAGING: &str = ".engine-staging";
const ENGINE_OLD: &str = ".engine-old";

// Bundled fingerprint library (cross-platform); seeds fingerprints dir on first run.
const FINGERPRINTS_ARCHIVE_KEY: &str = "ShardX-Fingerprints.zip";
const FINGERPRINTS_TOP_DIR: &str = "shardx-fingerprints";

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
struct Manifest {
    browser_etag: Option<String>,
    widevine_etag: Option<String>,
    fingerprints_etag: Option<String>,
    /// Chromium version the *already-created* profiles were last migrated to.
    /// Lets us bump saved profiles' UA + client_hints when the engine updates,
    /// independent of the fingerprint-library seed.
    #[serde(default)]
    applied_chromium_version: Option<String>,
    /// Signature (`<version>|<grease_brand>|<grease_version>`) of the engine
    /// descriptor the profiles/fingerprints were last migrated against. Migration
    /// re-runs whenever this changes — so adding grease (or any future field) to
    /// the manifest auto-triggers a re-migration even for users already on the
    /// current `applied_chromium_version`. No bump-the-constant ceremony.
    #[serde(default)]
    applied_signature: Option<String>,
    /// Build stamp of the archive currently extracted; the fallback for
    /// archives that carry no `shardx-build` file.
    #[serde(default)]
    installed_engine_build: Option<String>,
    /// Chromium version of the engine binary currently extracted on disk.
    /// The engine update is detected by comparing THIS to the manifest's
    /// `chromium_version` — robust where the etag check failed (e.g. a user who
    /// updated the app but whose stored etag already matched).
    #[serde(default)]
    installed_chromium_version: Option<String>,
}

/// Chromium version of the engine actually on disk (ground truth), read from
/// the bundle layout: the macOS Framework `Versions/<ver>/` dir, the Windows
/// `<ver>.manifest` file. Returns `None` on Linux (no on-disk marker) — callers
/// fall back to the stored `installed_chromium_version`.
fn installed_engine_version() -> Option<String> {
    let base = runtime_dir().ok()?;
    #[cfg(target_os = "macos")]
    {
        let versions = base
            .join("ShardX-Mac-arm64")
            .join("ShardX.app")
            .join("Contents")
            .join("Frameworks")
            .join("ShardX Framework.framework")
            .join("Versions");
        for ent in fs::read_dir(&versions).ok()?.flatten() {
            let name = ent.file_name().to_string_lossy().to_string();
            if name != "Current" && name.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                return Some(name);
            }
        }
        None
    }
    #[cfg(target_os = "windows")]
    {
        let dir = base.join("ShardX-Windows");
        // Marker is the `<version>.manifest` sidecar next to chrome.exe. Require
        // the stem to parse as a dotted version so a stray/leftover file can't
        // feed a bogus version into the update check.
        let looks_like_version =
            |s: &str| s.split('.').count() >= 2 && s.starts_with(|c: char| c.is_ascii_digit());
        for ent in fs::read_dir(&dir).ok()?.flatten() {
            let p = ent.path();
            if p.extension().and_then(|s| s.to_str()) == Some("manifest") {
                if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
                    if looks_like_version(stem) {
                        return Some(stem.to_string());
                    }
                }
            }
        }
        None
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = base;
        None
    }
}

/// Effective installed engine version. Trusts the version recorded at install
/// time (authoritative — written only after a successful download+extract) over
/// re-reading it off disk, whose layout varies per-OS and can carry stale files
/// from a previous version (a leftover `<old>.manifest` made Windows re-download
/// forever). On-disk detection is the fallback for legacy installs that predate
/// `installed_chromium_version`.
/// Build stamp on disk: `<engine>/shardx-build` when the archive ships one,
/// else what was recorded at install time.
fn installed_engine_build(local: &Manifest) -> Option<String> {
    let from_disk = runtime_dir()
        .ok()
        .map(|base| base.join(engine_root_dir()).join("shardx-build"))
        .and_then(|p| fs::read_to_string(p).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    from_disk.or_else(|| local.installed_engine_build.clone())
}

fn effective_installed_version(local: &Manifest) -> Option<String> {
    local
        .installed_chromium_version
        .clone()
        .or_else(installed_engine_version)
}

/// Engine version the GPU-capability cache is keyed against. A Chromium bump can
/// move ANGLE, which changes the extension list, so a probe result is only valid
/// for the engine build it ran on.
pub fn engine_version() -> Option<String> {
    effective_installed_version(&load_manifest())
}

fn load_manifest() -> Manifest {
    let Ok(p) = manifest_path() else {
        return Manifest::default();
    };
    fs::read_to_string(p)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_manifest(m: &Manifest) -> Result<()> {
    let p = manifest_path()?;
    fs::create_dir_all(p.parent().unwrap())?;
    fs::write(p, serde_json::to_string_pretty(m)?)?;
    Ok(())
}

#[derive(Serialize, Clone, Debug)]
pub struct RuntimeStatus {
    pub installed: bool,
    pub binary_path: Option<PathBuf>,
    pub installed_browser_etag: Option<String>,
    pub remote_browser_etag: Option<String>,
    pub update_available: bool,
    pub spec: Option<PlatformSpec>,
    /// True once the fingerprint library bundle has been extracted.
    pub fingerprints_installed: bool,
    /// The published engine wants a newer launcher than this one. No engine
    /// update is offered while this is true — update the app first.
    pub needs_newer_launcher: bool,
    /// What the manifest asks for, when it asks for anything.
    pub min_launcher_version: Option<String>,
    pub launcher_version: String,
}

#[derive(Default)]
struct RemoteManifest {
    archives: std::collections::HashMap<String, String>,
    chromium_version: Option<String>,
    /// GREASE brand/version the engine emits in `sec-ch-ua`. Not derivable from
    /// the version number (it rotates per major release), so it travels in the
    /// manifest as data — migration writes it into every profile/fingerprint.
    grease_brand: Option<String>,
    grease_version: Option<String>,
    /// TLS ClientHello shape for this engine build — currently
    /// `signature_algorithms` / `cipher_suites`.  Travels as data for the same
    /// reason GREASE does: it changes with the Chromium major (152 added the
    /// ML-DSA post-quantum signature schemes 0x0904-0x0906) and cannot be
    /// derived from the version number.  A profile still advertising the
    /// previous release's list under the new user agent is a JA4 mismatch a
    /// detector reads straight out of `ja4_r`.
    tls: Option<serde_json::Value>,
    /// Which build of the engine archive this is, apart from its Chromium
    /// version. Not the manifest-wide `revision`, which also moves for a TLS
    /// or GREASE edit — those want a migration, not a fresh download.
    engine_build: Option<String>,
    /// Lowest launcher version this engine build can be driven by; absent means
    /// any. An older launcher gets a browser it cannot configure.
    min_launcher_version: Option<String>,
}

/// Fetch the version manifest (GitHub raw) — one request yielding every
/// archive's current etag + the chromium version, so install/status never poll
/// R2/S3 per-archive. Empty/None when unreachable.
async fn fetch_manifest() -> RemoteManifest {
    fetch_manifest_from(MANIFEST_URL).await
}

async fn fetch_manifest_from(url: &str) -> RemoteManifest {
    async fn inner(url: &str) -> Option<RemoteManifest> {
        // Bounded: the first-run gate waits on this, and a network that accepts
        // and never answers would otherwise keep the window blank (#114).
        let resp = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(4))
            .timeout(std::time::Duration::from_secs(8))
            .build()
            .ok()?
            .get(url)
            .send()
            .await
            .ok()?;
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
            min_launcher_version: str_field("min_launcher_version"),
        })
    }
    inner(url).await.unwrap_or_default()
}

/// Migrate every `*.json` in `dir` to a new engine descriptor: bump
/// `navigator.user_agent` (Chrome/<major>.0.0.0) and the version fields in
/// `client_hints` — `brand_version` / `brand_full_version` / `chrome_build` /
/// `chrome_patch` (derived from the version), plus `grease_brand` /
/// `grease_version` / `grease_full_version` (from the manifest, since GREASE
/// can't be derived from the version number). Leaves platform_version,
/// architecture, webgl, etc. intact. Returns the number of files changed.
fn migrate_dir_to(
    dir: &Path,
    chromium_version: &str,
    grease_brand: Option<&str>,
    grease_version: Option<&str>,
    tls: Option<&serde_json::Value>,
) -> Result<usize> {
    let parts: Vec<&str> = chromium_version.split('.').collect();
    if parts.len() != 4 {
        return Ok(0);
    }
    let major = parts[0];
    let build: i64 = parts[2].parse().unwrap_or(0);
    let patch: i64 = parts[3].parse().unwrap_or(0);

    let mut n = 0usize;
    for ent in fs::read_dir(dir)?.flatten() {
        let p = ent.path();
        if p.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let Ok(text) = fs::read_to_string(&p) else {
            continue;
        };
        let Ok(mut cfg) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        let mut changed = false;

        // navigator.user_agent: replace the Chrome/<ver> token with major.0.0.0.
        if let Some(ua) = cfg
            .pointer("/navigator/user_agent")
            .and_then(|v| v.as_str())
            .map(String::from)
        {
            if let Some(idx) = ua.find("Chrome/") {
                let rest = &ua[idx + 7..];
                let end = rest.find(' ').unwrap_or(rest.len());
                let new_ua = format!("{}Chrome/{}.0.0.0{}", &ua[..idx], major, &rest[end..]);
                if new_ua != ua {
                    if let Some(slot) = cfg.pointer_mut("/navigator/user_agent") {
                        *slot = serde_json::Value::String(new_ua);
                        changed = true;
                    }
                }
            }
        }

        if let Some(ch) = cfg.get_mut("client_hints").and_then(|v| v.as_object_mut()) {
            let mut wants: Vec<(&str, serde_json::Value)> = vec![
                ("brand_version", serde_json::json!(major)),
                ("brand_full_version", serde_json::json!(chromium_version)),
                ("chrome_build", serde_json::json!(build)),
                ("chrome_patch", serde_json::json!(patch)),
            ];
            // GREASE — only when the manifest carries it (rotates per release).
            if let Some(gb) = grease_brand {
                wants.push(("grease_brand", serde_json::json!(gb)));
            }
            if let Some(gv) = grease_version {
                wants.push(("grease_version", serde_json::json!(gv)));
                wants.push((
                    "grease_full_version",
                    serde_json::json!(format!("{gv}.0.0.0")),
                ));
            }
            for (k, want) in wants {
                if ch.get(k) != Some(&want) {
                    ch.insert(k.to_string(), want);
                    changed = true;
                }
            }
        }

        // TLS: overwrite only the keys the manifest actually carries, so a
        // profile's own `shuffle_extensions` (or any field we don't ship) is
        // preserved.  A profile with no `tls` block at all is left alone —
        // absent means "use the engine default", not "stale".
        if let (Some(want_tls), Some(cfg_tls)) = (
            tls.and_then(|t| t.as_object()),
            cfg.get_mut("tls").and_then(|v| v.as_object_mut()),
        ) {
            for (k, want) in want_tls {
                if cfg_tls.get(k) != Some(want) {
                    cfg_tls.insert(k.clone(), want.clone());
                    changed = true;
                }
            }
        }

        if changed {
            fs::write(&p, serde_json::to_string_pretty(&cfg)?)?;
            n += 1;
        }
    }
    Ok(n)
}

/// Migrate both the saved profiles AND the fingerprint library (bundled +
/// user-added) to `chromium_version`. Bundled templates are already at the new
/// version after the seed; user-added fingerprints get their UA + client_hints
/// bumped here (their custom fields are preserved).
fn migrate_all_to(
    chromium_version: &str,
    grease_brand: Option<&str>,
    grease_version: Option<&str>,
    tls: Option<&serde_json::Value>,
) -> usize {
    let mut n = 0;
    if let Ok(d) = crate::store::profiles_dir() {
        n += migrate_dir_to(&d, chromium_version, grease_brand, grease_version, tls).unwrap_or(0);
    }
    if let Ok(d) = crate::store::fingerprints_dir() {
        n += migrate_dir_to(&d, chromium_version, grease_brand, grease_version, tls).unwrap_or(0);
    }
    n
}

/// Startup hook: migrate saved profiles + the fingerprint library (bundled +
/// user-added) to the manifest's engine descriptor when not already done. One
/// GitHub-manifest GET (never S3). Guarded by a signature of
/// `<version>|<grease_brand>|<grease_version>`, so a change to the grease (or any
/// future manifest field) re-triggers migration even for users already on the
/// current version — no version bump or constant needed. Also covers users
/// whose engine auto-updated via the etag path without an explicit install.
pub async fn ensure_profiles_migrated() {
    let m = fetch_manifest().await;
    let Some(target) = m.chromium_version.clone() else {
        return;
    };
    // TLS is part of the signature: without it a manifest that changes only
    // the ClientHello shape would be a no-op for anyone already on this
    // version, and their profiles would keep the previous release's JA4.
    let sig = format!(
        "{target}|{}|{}|{}",
        m.grease_brand.as_deref().unwrap_or(""),
        m.grease_version.as_deref().unwrap_or(""),
        m.tls.as_ref().map(|t| t.to_string()).unwrap_or_default(),
    );
    let mut local = load_manifest();
    if local.applied_signature.as_deref() == Some(sig.as_str()) {
        return;
    }
    let n = migrate_all_to(
        &target,
        m.grease_brand.as_deref(),
        m.grease_version.as_deref(),
        m.tls.as_ref(),
    );
    if n > 0 {
        eprintln!("[runtime] migrated {n} profile/fingerprint file(s) to {sig}");
    }
    local.applied_chromium_version = Some(target);
    local.applied_signature = Some(sig);
    let _ = save_manifest(&local);
}

/// Dotted-numeric comparison. Non-numeric parts compare as 0, which is what
/// makes "2.0.2-rc1" sort with "2.0.2" rather than below every release.
fn version_lt(a: &str, b: &str) -> bool {
    let part = |s: &str| -> Vec<u32> {
        s.split(['.', '-', '+'])
            .map(|p| p.parse::<u32>().unwrap_or(0))
            .collect()
    };
    let (va, vb) = (part(a), part(b));
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

/// This launcher's own version, as published.
fn launcher_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Whether this launcher is new enough for the engine build the manifest
/// describes.
fn engine_needs_newer_launcher(m: &RemoteManifest) -> bool {
    m.min_launcher_version
        .as_deref()
        .is_some_and(|min| version_lt(launcher_version(), min))
}

/// Whether the published engine differs from the one on disk: Chromium version,
/// `engine_build`, or the archive hash. Any one of them is enough, and an
/// unknown local value is not a mismatch.
fn engine_outdated(local: &Manifest, remote: &RemoteManifest, browser_key: &str) -> bool {
    let version_moved = remote
        .chromium_version
        .as_deref()
        .is_some_and(|rv| effective_installed_version(local).as_deref() != Some(rv));
    let differs = |have: Option<String>, want: Option<&str>| match (have, want) {
        (Some(h), Some(w)) => !h.is_empty() && h != w,
        _ => false,
    };
    let build_moved = differs(
        installed_engine_build(local),
        remote.engine_build.as_deref(),
    );
    let hash_moved = differs(
        local.browser_etag.clone(),
        remote.archives.get(browser_key).map(|s| s.as_str()),
    );
    version_moved || build_moved || hash_moved
}

#[tauri::command]
pub async fn runtime_status() -> Result<RuntimeStatus, String> {
    if let Ok(base) = runtime_dir() {
        recover_interrupted_swap(&base);
    }
    let spec = host_spec();
    let installed = binary_path().map(|p| p.exists()).unwrap_or(false);
    let mut m = load_manifest();
    let manifest = fetch_manifest().await;
    let remote = spec
        .as_ref()
        .and_then(|s| manifest.archives.get(&s.browser.key).cloned());
    // Manifest unreachable → everything reads None and we assume up to date.
    let needs_newer_launcher = engine_needs_newer_launcher(&manifest);

    // An engine installed before build stamps has none recorded, and unknown is
    // never a mismatch — so adopt one once, or the first bump never lands.
    if installed && manifest.engine_build.is_some() && installed_engine_build(&m).is_none() {
        let mut adopt = m.clone();
        adopt.installed_engine_build = manifest.engine_build.clone();
        if save_manifest(&adopt).is_ok() {
            m = adopt;
        }
    }

    let update_available = installed
        && !needs_newer_launcher
        && spec
            .as_ref()
            .is_some_and(|s| engine_outdated(&m, &manifest, &s.browser.key));
    // Stamp present AND dir has ≥1 .json (catches user-nuked dir).
    let fingerprints_installed = m.fingerprints_etag.is_some()
        && crate::store::fingerprints_dir()
            .map(|d| {
                fs::read_dir(&d)
                    .map(|it| {
                        it.flatten()
                            .any(|e| e.path().extension().and_then(|s| s.to_str()) == Some("json"))
                    })
                    .unwrap_or(false)
            })
            .unwrap_or(false);

    Ok(RuntimeStatus {
        installed,
        binary_path: if installed { binary_path().ok() } else { None },
        installed_browser_etag: m.browser_etag,
        remote_browser_etag: remote,
        update_available,
        spec,
        fingerprints_installed,
        needs_newer_launcher,
        min_launcher_version: manifest.min_launcher_version,
        launcher_version: launcher_version().to_string(),
    })
}

/// Why the engine cannot be replaced right now, or `None` when it is free.
///
/// Swapping the engine deletes the tree a running profile executes from. On
/// Windows that fails partway with os error 32 and leaves a half-deleted
/// install; elsewhere it yanks files from under a live browser. Naming the
/// profiles is the difference between a fixable message and a mystery.
fn engine_busy_message(running: &[String]) -> Option<String> {
    if running.is_empty() {
        return None;
    }
    Some(format!(
        "Stop the {} running profile(s) before updating the engine: {}",
        running.len(),
        running.join(", "),
    ))
}

#[tauri::command]
pub async fn runtime_install(window: Window, force: bool) -> Result<RuntimeStatus, String> {
    let spec = host_spec().ok_or("Host platform has no published ShardX archive")?;
    let base = runtime_dir().map_err(|e| e.to_string())?;
    fs::create_dir_all(&base).map_err(|e| e.to_string())?;

    let installed_now = binary_path().map(|p| p.exists()).unwrap_or(false);
    let local = load_manifest();
    let manifest = fetch_manifest().await;

    // Refused rather than installed: this build could not configure it.
    if engine_needs_newer_launcher(&manifest) {
        return Err(crate::errcode::code_with(
            "runtime.launcherTooOld",
            &[
                (
                    "required",
                    manifest.min_launcher_version.as_deref().unwrap_or("?"),
                ),
                ("current", launcher_version()),
            ],
        ));
    }

    // Manifest unreachable → don't force a re-download.
    let need_browser =
        force || !installed_now || engine_outdated(&local, &manifest, &spec.browser.key);

    // Replacing the engine deletes the tree a running profile is executing from.
    // On Windows that fails outright (os error 32) partway through, leaving a
    // half-deleted engine; on Unix it silently pulls the files out from under a
    // live browser. Either way the operator loses the session, so refuse while
    // any profile is up and name them.
    if need_browser {
        let running: Vec<String> = crate::process::Tracker::shared()
            .running()
            .into_iter()
            .map(|r| r.profile_id)
            .collect();
        if let Some(message) = engine_busy_message(&running) {
            return Err(message);
        }
    }

    recover_interrupted_swap(&base);
    let browser_etag = if need_browser {
        // A clean tree, never an extract over the old one: that would keep files
        // the new version dropped -- above all the previous `<version>.manifest`,
        // which poisons version detection into an endless re-download. The new
        // tree is built in staging and swapped in, so the old engine survives a
        // download or extract that fails.
        install_engine(&window, &spec.browser, &base)
            .await
            .map_err(|e| e.to_string())?
    } else {
        local.browser_etag.clone().unwrap_or_default()
    };

    let widevine_etag = if let Some(wv) = &spec.widevine {
        // Re-download Widevine only when browser changed or manifest lacks a stamp.
        if need_browser || local.widevine_etag.is_none() {
            let etag = download_and_extract(&window, wv, &base)
                .await
                .map_err(|e| e.to_string())?;
            place_widevine(&base).map_err(|e| e.to_string())?;
            Some(etag)
        } else {
            local.widevine_etag.clone()
        }
    } else {
        None
    };

    // Fingerprint seed: overwrites bundled templates, leaves user-added files;
    // skipped when the etag matches. User-added FP get version-migrated below.
    let fp_remote = manifest
        .archives
        .get(FINGERPRINTS_ARCHIVE_KEY)
        .map(|s| s.as_str());
    let fp_etag = install_fingerprints(
        &window,
        force,
        local.fingerprints_etag.as_deref(),
        fp_remote,
    )
    .await
    .map_err(|e| e.to_string())?
    .or(local.fingerprints_etag);

    // Migrate already-created profiles AND the fingerprint library (incl.
    // user-added) to the new engine descriptor (UA + client_hints incl. grease).
    // Runs only when the version-or-grease signature changed since last time.
    let target_ver = manifest
        .chromium_version
        .clone()
        .unwrap_or_else(|| CHROMIUM_VERSION.to_string());
    let sig = format!(
        "{target_ver}|{}|{}|{}",
        manifest.grease_brand.as_deref().unwrap_or(""),
        manifest.grease_version.as_deref().unwrap_or(""),
        manifest
            .tls
            .as_ref()
            .map(|t| t.to_string())
            .unwrap_or_default(),
    );
    if local.applied_signature.as_deref() != Some(sig.as_str()) {
        let n = migrate_all_to(
            &target_ver,
            manifest.grease_brand.as_deref(),
            manifest.grease_version.as_deref(),
            manifest.tls.as_ref(),
        );
        if n > 0 {
            eprintln!("[runtime] migrated {n} profile/fingerprint file(s) to {sig}");
        }
    }

    save_manifest(&Manifest {
        browser_etag: Some(browser_etag),
        widevine_etag,
        fingerprints_etag: fp_etag,
        applied_chromium_version: Some(target_ver.clone()),
        applied_signature: Some(sig),
        // Authoritative: we just successfully extracted exactly target_ver (the
        // old tree was wiped first). Recording the known value beats re-reading
        // it off disk, which is what let a leftover `<old>.manifest` keep the
        // version "stuck" and re-download every launch.
        installed_chromium_version: Some(target_ver),
        // Carried through when nothing was downloaded.
        installed_engine_build: if need_browser {
            manifest.engine_build.clone()
        } else {
            local.installed_engine_build.clone()
        },
    })
    .map_err(|e| e.to_string())?;

    let _ = window.emit("runtime:done", ());
    runtime_status().await
}

/// Download + seed fingerprint library. Bundled templates are always
/// overwritten (so version bumps propagate); user-added files are left in place.
async fn install_fingerprints(
    window: &Window,
    force: bool,
    local_etag: Option<&str>,
    remote_etag: Option<&str>,
) -> Result<Option<String>> {
    if !force {
        if let (Some(local), Some(remote)) = (local_etag, remote_etag) {
            if local == remote {
                return Ok(None);
            }
        }
    }

    let dir = crate::store::fingerprints_dir()?;
    let spec = ArchiveSpec {
        key: FINGERPRINTS_ARCHIVE_KEY.into(),
        label: "Fingerprint library".into(),
    };
    // Stage outside fingerprints_dir to keep the zip wrapper dir out of the library.
    let staging = dir.join(".staging");
    let _ = fs::remove_dir_all(&staging);
    fs::create_dir_all(&staging)?;
    let etag = download_and_extract(window, &spec, &staging).await?;

    let src = staging.join(FINGERPRINTS_TOP_DIR);
    let walk = if src.exists() { src } else { staging.clone() };
    let mut added = 0;
    let mut overwritten = 0;
    for ent in fs::read_dir(&walk)? {
        let ent = ent?;
        let p = ent.path();
        if p.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        // Always overwrite bundled templates so engine-version bumps reach
        // existing libraries. User-added fingerprints (names not in the bundle)
        // are never iterated here, so they stay untouched.
        let dst = dir.join(p.file_name().unwrap());
        let existed = dst.exists();
        fs::copy(&p, &dst)?;
        if existed {
            overwritten += 1;
        } else {
            added += 1;
        }
    }
    let _ = fs::remove_dir_all(&staging);
    eprintln!("[runtime] fingerprints sync: added={added} overwritten={overwritten}");
    Ok(Some(etag))
}

/// Download and extract the engine into staging, then swap it in.
async fn install_engine(window: &Window, spec: &ArchiveSpec, base: &Path) -> Result<String> {
    let staging = base.join(ENGINE_STAGING);
    let _ = fs::remove_dir_all(&staging);
    fs::create_dir_all(&staging)?;
    let result = match download_and_extract(window, spec, &staging).await {
        Ok(etag) => swap_engine(base, &staging).map(|()| etag),
        Err(e) => Err(e),
    };
    let _ = fs::remove_dir_all(&staging);
    result
}

/// Replace the live engine with the one extracted in `staging`, by rename.
/// Refuses an extract that holds no browser binary, and puts the old engine
/// back when the second rename fails, so every failure leaves a working engine.
fn swap_engine(base: &Path, staging: &Path) -> Result<()> {
    if !staging.join(binary_rel()).is_file() {
        anyhow::bail!(crate::errcode::code("runtime.archiveIncomplete"));
    }
    let live = base.join(engine_root_dir());
    let old = base.join(ENGINE_OLD);
    let _ = fs::remove_dir_all(&old);
    let had_old = live.exists();
    if had_old {
        // On Windows a still-running engine refuses here (os error 32), before
        // anything has moved.
        fs::rename(&live, &old)?;
    }
    if let Err(e) = fs::rename(staging.join(engine_root_dir()), &live) {
        if had_old {
            let _ = fs::rename(&old, &live);
        }
        return Err(e.into());
    }
    // Whatever else the archive holds at its top level lands beside the engine,
    // as the old extract-in-place did.
    for ent in fs::read_dir(staging)?.flatten() {
        if ent.path().extension().and_then(|e| e.to_str()) == Some("tmp") {
            continue;
        }
        let dst = base.join(ent.file_name());
        if dst.is_dir() {
            let _ = fs::remove_dir_all(&dst);
        }
        fs::rename(ent.path(), &dst)?;
    }
    let _ = fs::remove_dir_all(&old);
    Ok(())
}

/// A launcher that died between the two renames of `swap_engine` leaves the
/// old engine parked in `ENGINE_OLD` and none live; put it back.
fn recover_interrupted_swap(base: &Path) {
    let live = base.join(engine_root_dir());
    let old = base.join(ENGINE_OLD);
    let inside = binary_rel()
        .strip_prefix(engine_root_dir())
        .map(Path::to_path_buf)
        .unwrap_or_default();
    if !live.exists() && old.join(inside).is_file() {
        let _ = fs::rename(&old, &live);
    }
}

/// Stream archive → temp file → extract; emits `runtime:progress` events.
async fn download_and_extract(window: &Window, spec: &ArchiveSpec, base: &Path) -> Result<String> {
    let url = format!("{PUB_BASE}/{}", spec.key);
    // No total timeout -- the archive is hundreds of megabytes on any link --
    // but a stalled connection fails instead of hanging the setup screen.
    let mut resp = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .read_timeout(std::time::Duration::from_secs(60))
        .build()?
        .get(&url)
        .send()
        .await?
        .error_for_status()?;
    let total = resp.content_length().unwrap_or(0);
    let etag = resp
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim_matches('"').to_string())
        .unwrap_or_default();

    let tmp = base.join(format!("{}.tmp", spec.key));
    {
        let mut out = tokio::fs::File::create(&tmp).await?;
        let mut received: u64 = 0;
        let mut last_pct: u64 = u64::MAX;
        while let Some(chunk) = resp.chunk().await? {
            out.write_all(&chunk).await?;
            received += chunk.len() as u64;
            // Emit once per integer percent.
            let pct = received.saturating_mul(100).checked_div(total).unwrap_or(0);
            if pct != last_pct {
                last_pct = pct;
                let _ = window.emit(
                    "runtime:progress",
                    serde_json::json!({
                        "label": spec.label,
                        "phase": "download",
                        "received": received,
                        "total": total,
                        "percent": pct,
                    }),
                );
            }
        }
        out.flush().await?;
    }

    let _ = window.emit(
        "runtime:progress",
        serde_json::json!({
            "label": spec.label,
            "phase": "extract",
            "received": total,
            "total": total,
            "percent": 100,
        }),
    );

    let zip_path = tmp.clone();
    let dest = base.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<()> {
        // On macOS / Linux shell out to the system `unzip`: the Rust `zip`
        // crate's `extract()` does not restore symlinks (rewrites them as
        // text files) or +x bits, and Linux archives that store entries
        // out-of-order vs. their parent dirs trip its file-create with
        // ENOENT ("os error 2") before the parent dir entry is processed.
        // `unzip` handles all three correctly.
        #[cfg(unix)]
        {
            use std::process::Command;
            fs::create_dir_all(&dest)?;
            let out = Command::new("unzip")
                .arg("-q")
                .arg("-o")
                .arg(&zip_path)
                .arg("-d")
                .arg(&dest)
                .output()
                .map_err(|e| {
                    anyhow::anyhow!(crate::errcode::code_with(
                        "runtime.unzipMissing",
                        &[("detail", &e.to_string())]
                    ))
                })?;
            // unzip exit codes: 0 = clean, 1 = warnings (e.g. archives
            // zipped on Windows have backslashes; extraction still
            // completes correctly), 2+ = real fatal errors per unzip(1).
            let code = out.status.code().unwrap_or(-1);
            if code > 1 {
                let stderr = String::from_utf8_lossy(&out.stderr);
                anyhow::bail!(crate::errcode::code_with(
                    "runtime.unzipFailed",
                    &[
                        ("path", &zip_path.display().to_string()),
                        ("code", &code.to_string()),
                        ("detail", stderr.trim())
                    ]
                ));
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let f = fs::File::open(&zip_path)?;
            let mut archive = zip::ZipArchive::new(f)?;
            archive.extract(&dest)?;
            Ok(())
        }
    })
    .await??;

    let _ = fs::remove_file(&tmp);

    // Linux/mac archives produced on Windows lose every Unix exec bit;
    // restore +x on every ELF/Mach-O file under the runtime tree (not
    // just the main binary — chrome spawns chrome_crashpad_handler,
    // chrome_sandbox, etc., and they all need the exec bit).
    #[cfg(unix)]
    {
        if let Ok(root) = runtime_dir() {
            fix_unix_exec_bits(&root);
        }
    }

    Ok(etag)
}

/// First-4-bytes magic check; matches ELF + every Mach-O flavour.
#[cfg(unix)]
fn fix_unix_exec_bits(root: &Path) {
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;
    const MAGIC: &[[u8; 4]] = &[
        [0x7f, b'E', b'L', b'F'], // ELF
        [0xfe, 0xed, 0xfa, 0xcf],
        [0xcf, 0xfa, 0xed, 0xfe], // Mach-O 64 BE/LE
        [0xfe, 0xed, 0xfa, 0xce],
        [0xce, 0xfa, 0xed, 0xfe], // Mach-O 32 BE/LE
        [0xca, 0xfe, 0xba, 0xbe],
        [0xbe, 0xba, 0xfe, 0xca], // Mach-O universal
    ];
    fn walk(dir: &Path, magic: &[[u8; 4]]) {
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
                walk(&p, magic);
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
            if !magic.contains(&head) {
                continue;
            }
            if let Ok(meta) = fs::metadata(&p) {
                let mut perm = meta.permissions();
                perm.set_mode(perm.mode() | 0o111);
                let _ = fs::set_permissions(&p, perm);
            }
        }
    }
    walk(root, MAGIC);
}

/// Move Widevine to `<Framework>.framework/Versions/<ver>/Libraries/WidevineCdm/`.
#[cfg(target_os = "macos")]
fn place_widevine(base: &Path) -> Result<()> {
    let src = base.join("ShardX-Widevine-Mac-arm64").join("WidevineCdm");
    if !src.exists() {
        return Ok(());
    }
    let dst = base
        .join("ShardX-Mac-arm64")
        .join("ShardX.app")
        .join("Contents")
        .join("Frameworks")
        .join("ShardX Framework.framework")
        .join("Versions")
        .join(CHROMIUM_VERSION)
        .join("Libraries")
        .join("WidevineCdm");
    if dst.exists() {
        let _ = fs::remove_dir_all(&dst);
    }
    fs::create_dir_all(
        dst.parent()
            .context(crate::errcode::code("runtime.noWidevineParent"))?,
    )?;
    fs::rename(&src, &dst)?;
    let _ = fs::remove_dir(base.join("ShardX-Widevine-Mac-arm64"));
    Ok(())
}

/// Windows flat layout: WidevineCdm/ sits beside chrome.exe.
#[cfg(target_os = "windows")]
fn place_widevine(base: &Path) -> Result<()> {
    let src = base.join("ShardX-Widevine-Win").join("WidevineCdm");
    if !src.exists() {
        return Ok(());
    }
    let dst = base.join("ShardX-Windows").join("WidevineCdm");
    if dst.exists() {
        let _ = fs::remove_dir_all(&dst);
    }
    fs::rename(&src, &dst)?;
    let _ = fs::remove_dir(base.join("ShardX-Widevine-Win"));
    Ok(())
}

/// Linux: WidevineCdm/ next to chrome binary (flat layout).
#[cfg(target_os = "linux")]
fn place_widevine(base: &Path) -> Result<()> {
    let src = base.join("ShardX-Widevine-Linux").join("WidevineCdm");
    if !src.exists() {
        return Ok(());
    }
    let dst = base.join("ShardX-Linux").join("WidevineCdm");
    if dst.exists() {
        let _ = fs::remove_dir_all(&dst);
    }
    fs::rename(&src, &dst)?;
    let _ = fs::remove_dir(base.join("ShardX-Widevine-Linux"));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #114: a network that accepts the connection and never answers used to
    /// hold the first-run gate, and with it the whole window, indefinitely.
    #[tokio::test]
    async fn a_manifest_host_that_never_answers_gives_up() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/runtime.json", listener.local_addr().unwrap());
        let _held = std::thread::spawn(move || {
            let conns: Vec<_> = listener.incoming().take(1).collect();
            std::thread::sleep(std::time::Duration::from_secs(60));
            drop(conns);
        });

        let started = std::time::Instant::now();
        let got = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            fetch_manifest_from(&url),
        )
        .await
        .expect("fetch_manifest must give up on its own");

        assert!(got.archives.is_empty());
        assert!(started.elapsed() < std::time::Duration::from_secs(15));
    }

    #[test]
    fn a_complete_engine_replaces_the_old_one() {
        let base = tempfile::tempdir().unwrap();
        let staging = base.path().join(ENGINE_STAGING);
        plant(base.path(), "old");
        plant(&staging, "new");

        swap_engine(base.path(), &staging).unwrap();

        assert_eq!(read_bin(base.path()), "new");
        assert!(!base.path().join(ENGINE_OLD).exists());
    }

    #[test]
    fn an_extract_without_a_browser_leaves_the_old_engine() {
        let base = tempfile::tempdir().unwrap();
        let staging = base.path().join(ENGINE_STAGING);
        plant(base.path(), "old");
        fs::create_dir_all(staging.join(engine_root_dir())).unwrap();

        let err = swap_engine(base.path(), &staging).unwrap_err();

        assert!(err.to_string().contains("runtime.archiveIncomplete"));
        assert_eq!(read_bin(base.path()), "old");
    }

    #[test]
    fn a_swap_cut_short_is_undone_on_the_next_check() {
        let base = tempfile::tempdir().unwrap();
        plant(base.path(), "old");
        fs::rename(
            base.path().join(engine_root_dir()),
            base.path().join(ENGINE_OLD),
        )
        .unwrap();

        recover_interrupted_swap(base.path());

        assert_eq!(read_bin(base.path()), "old");
    }

    fn plant(root: &Path, body: &str) {
        let bin = root.join(binary_rel());
        fs::create_dir_all(bin.parent().unwrap()).unwrap();
        fs::write(bin, body).unwrap();
    }

    fn read_bin(root: &Path) -> String {
        fs::read_to_string(root.join(binary_rel())).unwrap()
    }

    #[test]
    fn a_free_engine_has_no_complaint() {
        assert_eq!(engine_busy_message(&[]), None);
    }

    #[test]
    fn a_busy_engine_names_every_profile_holding_it() {
        let msg = engine_busy_message(&["alpha".to_string(), "beta".to_string()])
            .expect("running profiles must block the install");
        assert!(msg.contains("alpha"), "{msg}");
        assert!(msg.contains("beta"), "{msg}");
        // The count tells the operator how many tabs to go close.
        assert!(msg.contains('2'), "{msg}");
    }
}
