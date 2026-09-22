// ShardX Launcher — Tauri backend.

pub mod api;
pub mod automation;
mod backup_cmd;
mod bookmarks;
pub mod cdp;
mod codex_mcp;
mod cookies;
pub mod db;
mod extensions;
pub mod files;
mod fingerprints;
pub mod fleet_client;
mod fleet_keys;
pub mod gpu_caps;
mod hermes_mcp;
pub mod http_session;
mod launch;
mod profile_icon;
pub mod runner;
pub mod traffic;

/// Where the engine binary lives, for integration tests that need to know
/// whether a runtime is installed before probing it. The `runtime` module
/// itself stays private; only this one fact is worth exposing.
pub fn runtime_binary_path_for_tests() -> anyhow::Result<std::path::PathBuf> {
    runtime::binary_path()
}

mod mcp_setup;
mod migrate;
mod process;
mod profile;
mod proxy;
mod psapi;
mod runtime;
mod settings;
mod speech;
mod startup;
/// Where the launcher keeps its files.
///
/// Public so the integration tests, which are separate crates, can point the
/// config root at a scratch directory instead of the real profile store.
pub mod store;
mod sync_bus;
mod sync_cmd;
mod team_config;
mod trash;
mod updater;

use serde_json::Value;

/// App handle set in `run()` setup; lets the axum API reach a webview window.
static APP_HANDLE: std::sync::OnceLock<tauri::AppHandle> = std::sync::OnceLock::new();

pub fn app_handle() -> Option<&'static tauri::AppHandle> {
    APP_HANDLE.get()
}

/// Launcher's own webview window (for monitor queries); None when headless.
pub fn main_window() -> Option<tauri::WebviewWindow> {
    use tauri::Manager;
    let app = APP_HANDLE.get()?;
    app.get_webview_window("main")
        .or_else(|| app.webview_windows().into_values().next())
}

/// Tell any open UI window that the on-disk store changed out-of-band — i.e. a
/// profile/proxy created or removed through the automation API or MCP, which
/// writes straight to disk without the React state ever knowing.  The view
/// listens for `store-changed` and reloads, so the new items appear without an
/// app restart.  `kind` ("profiles" | "proxies") is informational; the UI
/// reloads both lists regardless.  No-op when headless (no window).
pub fn notify_store_changed(kind: &str) {
    use tauri::Emitter;
    if let Some(w) = main_window() {
        let _ = w.emit("store-changed", kind);
    }
}

// ---- MCP server download ----

/// Download MCP server source into `<dir>/mcp`; user manages registration.
#[tauri::command]
async fn mcp_download(dir: String) -> Result<String, String> {
    let path = mcp_setup::download_mcp(std::path::Path::new(&dir))
        .await
        .map_err(|e| e.to_string())?;
    let path_string = path.display().to_string();
    let mut s = settings::load().map_err(|e| e.to_string())?;
    s.mcp_path = Some(path_string.clone());
    settings::save(&s).map_err(|e| e.to_string())?;
    notify_store_changed("settings");
    Ok(path_string)
}

#[tauri::command]
async fn mcp_set_path(dir: String) -> Result<Value, String> {
    let path = mcp_setup::resolve_mcp_dir(std::path::Path::new(&dir))
        .ok_or_else(|| "Selected folder is not a ShardX MCP server folder.".to_string())?;
    let path = path.display().to_string();
    let mut s = settings::load().map_err(|e| e.to_string())?;
    s.mcp_path = Some(path.clone());
    settings::save(&s).map_err(|e| e.to_string())?;
    notify_store_changed("settings");
    mcp_status().await
}

async fn automation_api_reachable() -> bool {
    let runtime = api::runtime_status();
    let Some(port) = runtime.port else {
        return false;
    };
    if !runtime.running {
        return false;
    }
    let Ok(client) = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(750))
        .build()
    else {
        return false;
    };
    match client
        .get(format!("http://127.0.0.1:{port}/health"))
        .send()
        .await
    {
        Ok(response) => response.status().is_success(),
        Err(_) => false,
    }
}

/// Named MCP readiness flags. Grouped into a struct so call sites cannot
/// silently transpose two adjacent booleans.
struct McpStatusFlags {
    files_downloaded: bool,
    lockfile_present: bool,
    version_current: bool,
    dependencies_installed: bool,
    api_reachable: bool,
    missing_saved_path: bool,
    discovered: bool,
}

fn mcp_status_value(path: Option<String>, version: Option<String>, flags: McpStatusFlags) -> Value {
    let McpStatusFlags {
        files_downloaded,
        lockfile_present,
        version_current,
        dependencies_installed,
        api_reachable,
        missing_saved_path,
        discovered,
    } = flags;
    let ready = files_downloaded && version_current && dependencies_installed && api_reachable;
    let (state, message) = if ready {
        (
            "ready",
            (if discovered {
                "Found an existing MCP install; files, dependencies, and Automation API are ready."
            } else {
                "MCP files, dependencies, and Automation API are ready."
            })
            .to_string(),
        )
    } else if !files_downloaded && missing_saved_path {
        (
            "missing",
            "Saved MCP folder is missing index.js or package.json.".to_string(),
        )
    } else if !files_downloaded {
        (
            "not_downloaded",
            "MCP server files have not been downloaded yet.".to_string(),
        )
    } else if !version_current {
        (
            "update_available",
            match version.as_deref() {
                Some(v) => format!(
                    "MCP files are v{v}; download/repair them for Launcher v{}.",
                    env!("CARGO_PKG_VERSION")
                ),
                None => format!(
                    "MCP file version is unknown; download/repair them for Launcher v{}.",
                    env!("CARGO_PKG_VERSION")
                ),
            },
        )
    } else if !dependencies_installed {
        (
            "dependencies_missing",
            if lockfile_present {
                "MCP files are downloaded; run npm ci in the selected folder."
            } else {
                "This legacy MCP folder has no package-lock.json; run npm install in the selected folder."
            }
            .to_string(),
        )
    } else {
        (
            "api_unavailable",
            "MCP files and dependencies are ready, but the Automation API is unreachable."
                .to_string(),
        )
    };

    serde_json::json!({
        "path": path,
        // Keep `installed` for compatibility with the v0.1.11 UI/API shape.
        "installed": files_downloaded,
        "files_downloaded": files_downloaded,
        "lockfile_present": lockfile_present,
        "version": version,
        "version_current": version_current,
        "required_version": env!("CARGO_PKG_VERSION"),
        "dependencies_installed": dependencies_installed,
        "api_reachable": api_reachable,
        "ready": ready,
        "state": state,
        "message": message,
    })
}

#[cfg(test)]
mod mcp_status_tests {
    use super::{devtools_frontend_url, mcp_status_value, select_devtools_target, McpStatusFlags};
    use serde_json::json;

    #[test]
    fn version_mismatch_needs_update_not_ready() {
        let status = mcp_status_value(
            Some("C:\\MCP\\ShardBrowser\\mcp".into()),
            Some("0.1.11".into()),
            McpStatusFlags {
                files_downloaded: true,
                lockfile_present: true,
                version_current: false,
                dependencies_installed: true,
                api_reachable: true,
                missing_saved_path: false,
                discovered: false,
            },
        );

        assert_eq!(status["state"].as_str(), Some("update_available"));
        assert_eq!(status["ready"].as_bool(), Some(false));
        assert_eq!(status["version"].as_str(), Some("0.1.11"));
        assert_eq!(status["lockfile_present"].as_bool(), Some(true));
        assert_eq!(
            status["required_version"].as_str(),
            Some(env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn missing_dependencies_use_lockfile_aware_install_guidance() {
        let locked = mcp_status_value(
            Some("C:\\MCP\\ShardBrowser\\mcp".into()),
            Some(env!("CARGO_PKG_VERSION").into()),
            McpStatusFlags {
                files_downloaded: true,
                lockfile_present: true,
                version_current: true,
                dependencies_installed: false,
                api_reachable: true,
                missing_saved_path: false,
                discovered: false,
            },
        );
        let legacy = mcp_status_value(
            Some("C:\\MCP\\Legacy\\mcp".into()),
            Some(env!("CARGO_PKG_VERSION").into()),
            McpStatusFlags {
                files_downloaded: true,
                lockfile_present: false,
                version_current: true,
                dependencies_installed: false,
                api_reachable: true,
                missing_saved_path: false,
                discovered: false,
            },
        );

        assert_eq!(locked["state"].as_str(), Some("dependencies_missing"));
        assert!(locked["message"].as_str().unwrap().contains("npm ci"));
        assert!(legacy["message"].as_str().unwrap().contains("npm install"));
    }

    #[test]
    fn devtools_frontend_url_joins_relative_path() {
        assert_eq!(
            devtools_frontend_url("http://127.0.0.1:9222", "/devtools/inspector.html?ws=x"),
            "http://127.0.0.1:9222/devtools/inspector.html?ws=x"
        );
    }

    #[test]
    fn devtools_target_prefers_cloudflare_challenge_page() {
        let targets = vec![
            json!({ "id": "normal", "type": "page", "title": "WordPress", "url": "https://example.com/wp-admin/" }),
            json!({ "id": "challenge", "type": "page", "title": "Just a moment...", "url": "https://example.com/?__cf_chl_rt_tk=x" }),
        ];

        assert_eq!(
            select_devtools_target(&targets).and_then(|target| target["id"].as_str()),
            Some("challenge")
        );
    }
}

#[tauri::command]
async fn mcp_status() -> Result<Value, String> {
    let mut s = settings::load().map_err(|e| e.to_string())?;
    let saved_path = s.mcp_path.clone();
    let mut discovered = false;
    let resolved = saved_path
        .as_deref()
        .and_then(|path| mcp_setup::resolve_mcp_dir(std::path::Path::new(path)))
        .or_else(|| {
            let found = mcp_setup::find_existing_mcp();
            discovered = found.is_some();
            found
        });

    if discovered {
        if let Some(path) = &resolved {
            s.mcp_path = Some(path.display().to_string());
            settings::save(&s).map_err(|e| e.to_string())?;
            notify_store_changed("settings");
        }
    }

    let api_reachable = automation_api_reachable().await;
    if let Some(path) = resolved {
        let version = mcp_setup::package_version(&path);
        let version_current = version.as_deref() == Some(env!("CARGO_PKG_VERSION"));
        let lockfile_present = path.join("package-lock.json").is_file();
        let dependencies_installed = mcp_setup::dependencies_installed(&path);
        let path = path.display().to_string();
        return Ok(mcp_status_value(
            Some(path),
            version,
            McpStatusFlags {
                files_downloaded: true,
                lockfile_present,
                version_current,
                dependencies_installed,
                api_reachable,
                missing_saved_path: false,
                discovered,
            },
        ));
    }

    let missing_saved_path = saved_path.is_some();
    Ok(mcp_status_value(
        saved_path,
        None,
        McpStatusFlags {
            files_downloaded: false,
            lockfile_present: false,
            version_current: false,
            dependencies_installed: false,
            api_reachable,
            missing_saved_path,
            discovered: false,
        },
    ))
}

#[tauri::command]
async fn codex_mcp_status() -> Result<Value, String> {
    codex_mcp::status().await
}

#[tauri::command]
async fn hermes_mcp_status() -> Result<Value, String> {
    hermes_mcp::status().await
}

// ---- Profiles ----

#[tauri::command]
fn profile_list() -> Result<Vec<profile::ProfileMeta>, String> {
    profile::list_all().map_err(|e| e.to_string())
}

#[tauri::command]
fn profile_get(id: String) -> Result<Value, String> {
    let mut stored = profile::load_raw(&id).map_err(|e| e.to_string())?;
    // Backfill gpu_preset_id for legacy profiles by matching webgl.renderer.
    if stored.meta.gpu_preset_id.is_none() {
        if let Some(gid) = infer_gpu_preset_id(&stored.config) {
            if let Ok(_claim) = profile::begin_user_mutation([&id], "backfill profile metadata") {
                if let Ok(mut current) = profile::load_raw(&id) {
                    if current.meta.gpu_preset_id.is_none() {
                        current.meta.gpu_preset_id = Some(gid);
                        if profile::save_raw(&mut current).is_ok() {
                            stored = current;
                        }
                    } else {
                        stored = current;
                    }
                }
            }
        }
    }
    serde_json::to_value(stored).map_err(|e| e.to_string())
}

#[tauri::command]
fn profile_validate_name(name: String, id: Option<String>) -> Result<String, String> {
    profile::validate_profile_name_for_mutation(&name, id.as_deref())
        .map_err(|error| error.to_string())
}

/// Recover library fingerprint id by matching webgl.renderer (+ screen if ambiguous).
fn infer_gpu_preset_id(config: &serde_json::Map<String, Value>) -> Option<String> {
    let renderer = config.get("webgl")?.get("renderer")?.as_str()?;
    let scr = config.get("screen");
    let sw = scr.and_then(|s| s.get("width")).and_then(|v| v.as_i64());
    let sh = scr.and_then(|s| s.get("height")).and_then(|v| v.as_i64());

    let entries = fingerprints::list_all().ok()?;
    let mut renderer_match: Option<String> = None;
    for e in &entries {
        let er = e
            .payload
            .get("webgl")
            .and_then(|w| w.get("renderer"))
            .and_then(|v| v.as_str());
        if er != Some(renderer) {
            continue;
        }
        let es = e.payload.get("screen");
        let ew = es.and_then(|s| s.get("width")).and_then(|v| v.as_i64());
        let eh = es.and_then(|s| s.get("height")).and_then(|v| v.as_i64());
        if sw.is_some() && ew == sw && eh == sh {
            return Some(e.id.clone());
        }
        renderer_match.get_or_insert_with(|| e.id.clone());
    }
    renderer_match
}

// ---- Realistic Sec-CH-UA-Platform-Version pools (spread per profile) ----

// macOS Sonoma 14.x, Sequoia 15.x, Tahoe 26.x.
const MACOS_PLATFORM_VERSIONS: &[&str] = &[
    "14.6.1", "14.7", "14.7.1", "14.7.2", "15.4", "15.4.1", "15.5", "15.6", "15.6.1", "15.7",
    "26.0", "26.0.1", "26.1",
];

// Win 10 21H1+ ("10.0.0"), Win 11 21H2..25H2 ("13"–"17"); weighted to 22H2/23H2/24H2.
const WINDOWS_PLATFORM_VERSIONS: &[&str] = &[
    "10.0.0", "13.0.0", "14.0.0", "14.0.0", "14.0.0", "15.0.0", "15.0.0", "15.0.0", "15.0.0",
    "16.0.0", "16.0.0", "16.0.0", "17.0.0",
];

// LTS kernels + current mainline.
const LINUX_PLATFORM_VERSIONS: &[&str] = &[
    "5.15.0", "6.1.0", "6.5.0", "6.6.0", "6.8.0", "6.10.0", "6.11.0", "6.12.0", "6.14.0", "6.15.0",
    "6.16.0",
];

/// Write a random platform_version into navigator + client_hints; unknown platforms left alone.
pub(crate) fn randomize_platform_version(payload: &mut serde_json::Map<String, Value>) {
    let platform = payload
        .get("navigator")
        .and_then(|n| n.get("platform"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let pool: &[&str] = match platform {
        "macOS" => MACOS_PLATFORM_VERSIONS,
        "Windows" => WINDOWS_PLATFORM_VERSIONS,
        "Linux" => LINUX_PLATFORM_VERSIONS,
        _ => return,
    };
    let pick_idx = (uuid::Uuid::new_v4().as_bytes()[0] as usize) % pool.len();
    let version = pool[pick_idx].to_string();

    if let Some(nav) = payload.get_mut("navigator").and_then(|v| v.as_object_mut()) {
        nav.insert("platform_version".into(), Value::String(version.clone()));
    }
    if let Some(ch) = payload
        .get_mut("client_hints")
        .and_then(|v| v.as_object_mut())
    {
        ch.insert("platform_version".into(), Value::String(version));
    }
}

/// Realistic (hardware_concurrency, deviceMemory) combos per Mac model id.
fn mac_hw_configs(model: &str) -> Option<&'static [(u32, u32)]> {
    Some(match model {
        "mac-m1-air13" | "mac-m1-mbp13" | "mac-m1-imac24" => &[(8, 8), (8, 16)],
        "mac-m1-pro-mbp14" | "mac-m1-pro-mbp16" => &[(8, 16), (10, 16), (10, 32)],
        "mac-m1-max-mbp14" | "mac-m1-max-mbp16" => &[(10, 32)],
        "mac-m2-air13" | "mac-m2-air15" | "mac-m2-mbp13" => &[(8, 8), (8, 16)],
        "mac-m2-pro-mbp14" | "mac-m2-pro-mbp16" => &[(10, 16), (12, 16), (12, 32)],
        "mac-m2-max-mbp14" | "mac-m2-max-mbp16" => &[(12, 32)],
        "mac-m3-air13" | "mac-m3-air15" | "mac-m3-mbp14" | "mac-m3-imac24" => &[(8, 8), (8, 16)],
        "mac-m3-pro-mbp14" | "mac-m3-pro-mbp16" => &[(11, 16), (12, 16), (12, 32)],
        "mac-m3-max-mbp14" | "mac-m3-max-mbp16" => &[(14, 32), (16, 32)],
        "mac-m4-air13" | "mac-m4-air15" | "mac-m4-mbp14" | "mac-m4-imac24" => &[(10, 16), (10, 32)],
        "mac-m4-pro-mbp14" | "mac-m4-pro-mbp16" => &[(12, 16), (14, 16), (14, 32)],
        "mac-m4-max-mbp14" | "mac-m4-max-mbp16" => &[(14, 32), (16, 32)],
        "mac-m5-mbp14" => &[(10, 16), (10, 32)],
        _ => return None,
    })
}

/// Host logical CPU count (counts SMT threads); fallback 8.
fn host_logical_cores() -> u32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(8)
}

/// Host physical RAM in GiB, best-effort per OS.
fn host_ram_gb() -> Option<u32> {
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("sysctl")
            .args(["-n", "hw.memsize"])
            .output()
            .ok()?;
        let bytes: u64 = String::from_utf8_lossy(&out.stdout).trim().parse().ok()?;
        return Some((bytes / (1024 * 1024 * 1024)) as u32);
    }
    #[cfg(target_os = "linux")]
    {
        let s = std::fs::read_to_string("/proc/meminfo").ok()?;
        let kb: u64 = s
            .lines()
            .find(|l| l.starts_with("MemTotal:"))?
            .split_whitespace()
            .nth(1)?
            .parse()
            .ok()?;
        return Some((kb / (1024 * 1024)) as u32);
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        // 0x08000000 = CREATE_NO_WINDOW — suppress the brief console flash a GUI
        // app gets when shelling out to a console-subsystem binary.
        let out = std::process::Command::new("wmic")
            .args(["ComputerSystem", "get", "TotalPhysicalMemory"])
            .creation_flags(0x08000000)
            .output()
            .ok()?;
        let txt = String::from_utf8_lossy(&out.stdout);
        let bytes: u64 = txt
            .lines()
            .filter_map(|l| l.trim().parse::<u64>().ok())
            .next()?;
        return Some((bytes / (1024 * 1024 * 1024)) as u32);
    }
    #[allow(unreachable_code)]
    None
}

/// Physical RAM rounded to Chrome's {8,16,32} deviceMemory bucket; unknown → 16.
fn host_ram_bucket_gb() -> u32 {
    match host_ram_gb() {
        Some(gb) if gb >= 32 => 32,
        Some(gb) if gb >= 16 => 16,
        Some(_) => 8,
        None => 16,
    }
}

/// Pick (hardware_concurrency, device_memory): Mac → curated table, Win/Linux → host-bracketed.
pub(crate) fn randomize_hardware(payload: &mut serde_json::Map<String, Value>) {
    let model = payload
        .get("_meta")
        .and_then(|m| m.get("gpu_preset_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let platform = payload
        .get("navigator")
        .and_then(|n| n.get("platform"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let pick8 = || uuid::Uuid::new_v4().as_bytes()[0] as usize;

    let (cores, mem): (u32, u32) = if let Some(pool) = mac_hw_configs(model) {
        pool[pick8() % pool.len()]
    } else if platform == "Windows" || platform == "Linux" {
        let c = host_logical_cores();
        // Real x86 logical-core counts (SMT + Intel hybrid); bracket host within [C-4, C+2].
        const X86_CORES: [u32; 9] = [4, 6, 8, 12, 16, 20, 24, 28, 32];
        let lo = c.saturating_sub(4);
        let hi = c + 2;
        let cand: Vec<u32> = X86_CORES
            .into_iter()
            .filter(|&n| n >= lo && n <= hi)
            .collect();
        let cores = if cand.is_empty() {
            X86_CORES
                .into_iter()
                .min_by_key(|&n| (n as i64 - c as i64).abs())
                .unwrap()
        } else {
            cand[pick8() % cand.len()]
        };
        // deviceMemory: core-tied floor and host-RAM ceiling.
        let real = host_ram_bucket_gb();
        let floor = if cores >= 12 { 16 } else { 8 };
        let mem_cand: Vec<u32> = [8u32, 16, 32]
            .into_iter()
            .filter(|&m| m >= floor && m <= real)
            .collect();
        let mem = if mem_cand.is_empty() {
            real
        } else {
            mem_cand[pick8() % mem_cand.len()]
        };
        (cores, mem)
    } else {
        return;
    };

    if let Some(nav) = payload.get_mut("navigator").and_then(|v| v.as_object_mut()) {
        nav.insert("hardware_concurrency".into(), Value::from(cores));
        nav.insert("device_memory".into(), Value::from(mem));
    }
}

/// Clamp profile.screen to the real display when it's smaller than the FP claim.
/// On Win/Linux always use the real display (presets rarely match user monitors).
fn clamp_screen_to_real_display(
    window: &tauri::WebviewWindow,
    payload: &mut serde_json::Map<String, Value>,
) {
    let Some(monitor) = window
        .primary_monitor()
        .ok()
        .flatten()
        .or_else(|| window.current_monitor().ok().flatten())
    else {
        eprintln!("[launcher] display: no monitor info — screen clamp skipped");
        return;
    };
    let scale = monitor.scale_factor();
    if scale <= 0.0 {
        eprintln!("[launcher] display: bad scale_factor {scale} — screen clamp skipped");
        return;
    }
    let phys = monitor.size();
    let real_w = (phys.width as f64 / scale).round() as i64;
    let real_h = (phys.height as f64 / scale).round() as i64;
    eprintln!(
        "[launcher] display: name={:?} physical={}x{} scale={} -> logical={}x{}",
        monitor.name(),
        phys.width,
        phys.height,
        scale,
        real_w,
        real_h
    );
    if real_w <= 0 || real_h <= 0 {
        return;
    }

    let Some(scr) = payload.get("screen").and_then(|v| v.as_object()) else {
        eprintln!("[launcher] display: profile has no `screen` block — clamp skipped");
        return;
    };
    let fp_w = scr.get("width").and_then(|v| v.as_i64()).unwrap_or(0);
    let fp_h = scr.get("height").and_then(|v| v.as_i64()).unwrap_or(0);
    eprintln!("[launcher] display: fingerprint screen={fp_w}x{fp_h}");
    if fp_w <= 0 || fp_h <= 0 {
        return;
    }
    // macOS keeps curated FP unless real display smaller; Win/Linux always uses real.
    if cfg!(target_os = "macos") && real_w >= fp_w && real_h >= fp_h {
        eprintln!(
            "[launcher] display: real {real_w}x{real_h} >= fp {fp_w}x{fp_h} — keeping FP screen (macOS)"
        );
        return;
    }

    // Preserve FP menubar/dock insets for avail_*.
    let fp_avail_w = scr
        .get("avail_width")
        .and_then(|v| v.as_i64())
        .unwrap_or(fp_w);
    let fp_avail_h = scr
        .get("avail_height")
        .and_then(|v| v.as_i64())
        .unwrap_or(fp_h);
    let chrome_w = (fp_w - fp_avail_w).max(0);
    let chrome_h = (fp_h - fp_avail_h).max(0);
    let avail_w = (real_w - chrome_w).max(1);
    let avail_h = (real_h - chrome_h).max(1);

    if let Some(scr_mut) = payload.get_mut("screen").and_then(|v| v.as_object_mut()) {
        scr_mut.insert("width".into(), Value::from(real_w));
        scr_mut.insert("height".into(), Value::from(real_h));
        scr_mut.insert("avail_width".into(), Value::from(avail_w));
        scr_mut.insert("avail_height".into(), Value::from(avail_h));
        scr_mut.insert("device_pixel_ratio".into(), Value::from(scale));
    }
    // Keep window inside the avail area.
    if let Some(win) = payload.get_mut("window").and_then(|v| v.as_object_mut()) {
        win.insert("outer_width".into(), Value::from(avail_w));
        win.insert("inner_width".into(), Value::from(avail_w));
        let outer_h = (avail_h - 1).max(1);
        win.insert("outer_height".into(), Value::from(outer_h));
        win.insert("inner_height".into(), Value::from((outer_h - 87).max(1)));
    }
    eprintln!(
        "[launcher] display: CLAMPED screen to real {real_w}x{real_h} \
         (avail {avail_w}x{avail_h}, dpr {scale}) — FP claimed {fp_w}x{fp_h}"
    );
}

#[tauri::command]
fn profile_save(
    window: tauri::WebviewWindow,
    payload: Value,
) -> Result<profile::ProfileMeta, String> {
    // UI saves enrich new profiles; the API persists verbatim.
    save_profile_core(Some(&window), payload, true)
}

/// Enrich a new profile in place: platform_version, hardware, screen clamp.
pub fn enrich_new_config(
    window: Option<&tauri::WebviewWindow>,
    obj: &mut serde_json::Map<String, Value>,
) {
    randomize_platform_version(obj);
    randomize_hardware(obj);
    if let Some(w) = window {
        clamp_screen_to_real_display(w, obj);
    }
}

/// Core of `profile_save` callable without Tauri context; `enrich=false` stores verbatim.
pub fn save_profile_core(
    window: Option<&tauri::WebviewWindow>,
    payload: Value,
    enrich: bool,
) -> Result<profile::ProfileMeta, String> {
    persist_profile_core(window, payload, enrich).map_err(|error| error.to_string())
}

pub fn persist_profile_core(
    window: Option<&tauri::WebviewWindow>,
    payload: Value,
    enrich: bool,
) -> anyhow::Result<profile::ProfileMeta> {
    let is_new = payload
        .get("_meta")
        .and_then(|m| m.get("id"))
        .and_then(|v| v.as_str())
        .map(|s| s.is_empty())
        .unwrap_or(true);
    let _claim = if is_new {
        profile::begin_profile_creation("create a profile")
    } else {
        let id = payload
            .get("_meta")
            .and_then(|meta| meta.get("id"))
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        profile::begin_user_mutation([id], "modify this profile")
    }?;

    persist_profile_core_claimed(window, payload, enrich)
}

/// Persist after the caller has acquired the appropriate lifecycle claim.
/// API create flows use this to keep validation, proxy setup, and profile write
/// inside one claim without trying to acquire the same claim twice.
pub(crate) fn persist_profile_core_claimed(
    window: Option<&tauri::WebviewWindow>,
    payload: Value,
    enrich: bool,
) -> anyhow::Result<profile::ProfileMeta> {
    let mut payload = payload;
    let is_new = payload
        .get("_meta")
        .and_then(|m| m.get("id"))
        .and_then(|v| v.as_str())
        .map(|s| s.is_empty())
        .unwrap_or(true);

    if is_new && enrich {
        if let Some(obj) = payload.as_object_mut() {
            enrich_new_config(window, obj);
        }
    }

    let mut stored: profile::StoredProfile = serde_json::from_value(payload)?;
    profile::prepare_profile_name_for_save(&mut stored)?;
    profile::save_raw(&mut stored)?;
    let name = stored
        .config
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("(unnamed)")
        .to_string();
    let notes = stored
        .config
        .get("notes")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    Ok(profile::ProfileMeta {
        id: stored.meta.id,
        name,
        notes,
        proxy_id: stored.meta.proxy_id,
        last_launched_at: stored.meta.last_launched_at,
        created_at: stored.meta.created_at,
        pinned: stored.meta.pinned,
        folder: stored.meta.folder,
        total_runtime_ms: stored.meta.total_runtime_ms,
        color: stored.meta.color,
        extensions: stored.meta.extensions,
    })
}

/// Into the trash for a week; only the files carrying the account are kept.
#[tauri::command]
fn profile_delete(id: String) -> Result<(), String> {
    let _claim = profile::begin_user_mutation([&id], "delete this profile")
        .map_err(|error| error.to_string())?;
    trash::move_to_trash(&id)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

// ---- Trash ----

#[tauri::command]
fn trash_list() -> Result<Vec<trash::TrashEntry>, String> {
    trash::list().map_err(|e| e.to_string())
}

#[tauri::command]
fn trash_restore(id: String) -> Result<profile::ProfileMeta, String> {
    trash::restore(&id).map_err(|e| e.to_string())
}

#[tauri::command]
fn trash_purge(id: String) -> Result<(), String> {
    trash::purge(&id).map_err(|e| e.to_string())
}

/// Empties the trash for good; returns how many went.
#[tauri::command]
fn trash_empty() -> Result<usize, String> {
    let entries = trash::list().map_err(|e| e.to_string())?;
    let n = entries.len();
    for e in entries {
        trash::purge(&e.id).map_err(|e| e.to_string())?;
    }
    Ok(n)
}

// ---- Extensions ----

#[tauri::command]
fn extension_list() -> Result<Vec<extensions::ExtensionEntry>, String> {
    extensions::list().map_err(|e| e.to_string())
}

/// Returns what went in, so one bad file in a multi-select loses only itself.
#[tauri::command]
fn extension_import(paths: Vec<String>) -> Result<Vec<extensions::ExtensionEntry>, String> {
    let mut out = Vec::new();
    let mut errs = Vec::new();
    for p in &paths {
        match extensions::import(std::path::Path::new(p)) {
            Ok(e) => out.push(e),
            Err(e) => errs.push(format!("{p}: {e}")),
        }
    }
    if out.is_empty() && !errs.is_empty() {
        return Err(errs.join("; "));
    }
    Ok(out)
}

/// Import from a Web Store link, a bare extension id, or a direct .crx / .zip
/// URL — the launcher fetches the file itself.
#[tauri::command]
async fn extension_import_url(url: String) -> Result<extensions::ExtensionEntry, String> {
    extensions::import_url(&url)
        .await
        .map_err(|e| format!("{e:#}"))
}

#[tauri::command]
fn extension_delete(id: String) -> Result<(), String> {
    extensions::delete(&id).map_err(|e| e.to_string())
}

// ---- Automation ----

#[tauri::command]
fn automation_list() -> Result<Vec<automation::Project>, String> {
    automation::list().map_err(|e| e.to_string())
}

#[tauri::command]
fn automation_get(id: String) -> Result<automation::Project, String> {
    automation::get(&id).map_err(|e| e.to_string())
}

#[tauri::command]
fn automation_save(project: automation::Project) -> Result<automation::Project, String> {
    automation::save(project).map_err(|e| e.to_string())
}

#[tauri::command]
fn automation_delete(id: String) -> Result<(), String> {
    automation::delete(&id).map_err(|e| e.to_string())
}

/// Run a saved project against a running profile.
///
/// Guards live in the runner, so this path and the HTTP API enforce the same
/// rules rather than drifting apart.
#[tauri::command]
async fn automation_run(
    project_id: String,
    profile_id: String,
    variables: std::collections::HashMap<String, String>,
) -> Result<runner::RunReport, String> {
    runner::run_saved(&project_id, &profile_id, variables)
        .await
        .map_err(|e| e.to_string())
}

// ---- Bookmarks ----

#[tauri::command]
fn bookmark_list() -> Result<Vec<bookmarks::Bookmark>, String> {
    bookmarks::list().map_err(|e| e.to_string())
}

#[tauri::command]
fn bookmark_save(entry: bookmarks::Bookmark) -> Result<bookmarks::Bookmark, String> {
    bookmarks::save(entry).map_err(|e| e.to_string())
}

#[tauri::command]
fn bookmark_delete(id: String) -> Result<(), String> {
    bookmarks::delete(&id).map_err(|e| e.to_string())
}

// ---- Data root ----

#[derive(serde::Serialize)]
struct DataRootInfo {
    path: String,
    /// False while the data still lives in the config dir.
    custom: bool,
    migrating: bool,
}

#[tauri::command]
fn data_root_get() -> Result<DataRootInfo, String> {
    let s = settings::load().map_err(|e| e.to_string())?;
    let path = store::data_root().map_err(|e| e.to_string())?;
    Ok(DataRootInfo {
        path: path.display().to_string(),
        custom: s.data_root.is_some(),
        migrating: migrate::in_progress(),
    })
}

/// Progress goes out as `data-migration` events; nothing launches until done.
#[tauri::command]
async fn data_root_migrate(app: tauri::AppHandle, path: String) -> Result<u64, String> {
    if !process::Tracker::shared().running().is_empty() {
        return Err("close every running profile first".into());
    }
    let dst = std::path::PathBuf::from(&path);
    tauri::async_runtime::spawn_blocking(move || migrate::run(&app, &dst))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn profile_bind_proxy(profile_id: String, proxy_id: Option<String>) -> Result<(), String> {
    let _claim = profile::begin_user_mutation([&profile_id], "change this profile's proxy")
        .map_err(|error| error.to_string())?;
    let mut p = profile::load_raw(&profile_id).map_err(|e| e.to_string())?;
    p.meta.proxy_id = proxy_id;
    profile::save_raw(&mut p).map_err(|e| e.to_string())
}

#[tauri::command]
fn profile_clone(id: String) -> Result<profile::ProfileMeta, String> {
    let _claim = profile::begin_clone_mutation(&id).map_err(|error| error.to_string())?;
    profile::clone_profile(&id).map_err(|e| e.to_string())
}

/// Import profiles verbatim under fresh ids; returns the count.
#[tauri::command]
fn profile_import(payloads: Vec<Value>) -> Result<usize, String> {
    let _claim =
        profile::begin_profile_creation("import profiles").map_err(|error| error.to_string())?;
    let mut stored_profiles: Vec<profile::StoredProfile> = payloads
        .into_iter()
        .map(|payload| serde_json::from_value(payload).map_err(|error| error.to_string()))
        .collect::<Result<_, _>>()?;
    profile::prepare_import_batch(&mut stored_profiles).map_err(|error| error.to_string())?;
    for stored in &mut stored_profiles {
        profile::save_raw(stored).map_err(|error| error.to_string())?;
    }
    Ok(stored_profiles.len())
}

// ---- Clipboard (via tauri-plugin-clipboard-manager; webview navigator.clipboard throws) ----

#[tauri::command]
fn clipboard_write(app: tauri::AppHandle, text: String) -> Result<(), String> {
    use tauri_plugin_clipboard_manager::ClipboardExt;
    app.clipboard().write_text(text).map_err(|e| e.to_string())
}

#[tauri::command]
fn clipboard_read(app: tauri::AppHandle) -> Result<String, String> {
    use tauri_plugin_clipboard_manager::ClipboardExt;
    app.clipboard().read_text().map_err(|e| e.to_string())
}

#[tauri::command]
fn profile_set_pin(id: String, pinned: bool) -> Result<(), String> {
    let _claim = profile::begin_user_mutation([&id], "change this profile's pin")
        .map_err(|error| error.to_string())?;
    profile::set_pin(&id, pinned).map_err(|e| e.to_string())
}

#[tauri::command]
fn profile_set_folder(id: String, folder: String) -> Result<(), String> {
    let _claim = profile::begin_user_mutation([&id], "move this profile")
        .map_err(|error| error.to_string())?;
    profile::set_folder(&id, &folder).map_err(|e| e.to_string())
}

/// Rename folder (retag profiles); returns count.
#[tauri::command]
fn folder_rename(old: String, new: String) -> Result<usize, String> {
    profile::rename_folder(&old, &new).map_err(|e| e.to_string())
}

/// Delete folder; `delete_profiles` true → remove, false → unfile.
#[tauri::command]
fn folder_delete(folder: String, delete_profiles: bool) -> Result<usize, String> {
    profile::delete_folder(&folder, delete_profiles).map_err(|e| e.to_string())
}

/// Host OS in fingerprint-library vocabulary (macOS/Windows/Linux).
#[tauri::command]
fn host_platform() -> String {
    match std::env::consts::OS {
        "macos" => "macOS",
        "windows" => "Windows",
        "linux" => "Linux",
        other => other,
    }
    .to_string()
}

#[tauri::command]
fn profile_create_from_template(
    window: tauri::WebviewWindow,
    template_id: String,
) -> Result<profile::ProfileMeta, String> {
    create_from_fingerprint_core(Some(&window), &template_id)
}

/// Merge library fingerprint into fresh profile map; tz/lang/geo set to "auto" sentinel.
pub fn merge_library_fingerprint(
    template_id: &str,
) -> Result<serde_json::Map<String, Value>, String> {
    let entry = fingerprints::get(template_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("unknown fingerprint id: {template_id}"))?;

    let mut merged = serde_json::Map::new();
    merged.insert(
        "_meta".into(),
        serde_json::json!({
            "id": "",
            "proxy_id": null,
            "last_launched_at": null,
            "gpu_preset_id": entry.id,
        }),
    );
    if let Some(o) = entry.payload.as_object() {
        for (k, v) in o {
            if k == "_meta" {
                continue;
            }
            merged.insert(k.clone(), v.clone());
        }
    }

    // launch-time resolver fills tz/lang/geo from the bound proxy
    merged.insert("timezone".into(), Value::String("auto".into()));
    if let Some(nav) = merged.get_mut("navigator").and_then(|v| v.as_object_mut()) {
        nav.insert("language".into(), Value::String("auto".into()));
        nav.remove("accept_language");
        nav.remove("languages");
    }
    merged.insert("geolocation".into(), serde_json::json!({ "mode": "auto" }));
    Ok(merged)
}

/// Build + persist a profile from a library fingerprint id (UI template path).
pub fn create_from_fingerprint_core(
    window: Option<&tauri::WebviewWindow>,
    template_id: &str,
) -> Result<profile::ProfileMeta, String> {
    let merged = merge_library_fingerprint(template_id)?;
    save_profile_core(window, Value::Object(merged), true)
}

/// Produce uniquified fingerprint config WITHOUT persisting (API get-new-fingerprint).
pub fn build_fingerprint_config(
    window: Option<&tauri::WebviewWindow>,
    template_id: &str,
) -> Result<serde_json::Map<String, Value>, String> {
    let mut merged = merge_library_fingerprint(template_id)?;
    enrich_new_config(window, &mut merged);
    ensure_default_noise(&mut merged);
    Ok(merged)
}

/// Add the UI's default noise block (every vector present, disabled, seed 0 —
/// the sentinel `save_raw` fills per-profile) when a config carries none, so
/// API/SDK profiles match UI profiles and get a unique seed instead of none.
pub fn ensure_default_noise(cfg: &mut serde_json::Map<String, Value>) {
    if cfg.contains_key("noise") {
        return;
    }
    cfg.insert(
        "noise".into(),
        serde_json::json!({
            "canvas":       { "enabled": false, "seed": 0 },
            "webgl":        { "enabled": false, "seed": 0, "intensity": 0 },
            "audio":        { "enabled": false, "seed": 0 },
            "client_rects": { "enabled": false, "seed": 0, "max_offset": 0 },
            "sensors":      { "enabled": false, "seed": 0 },
            "fonts":        { "enabled": false, "seed": 0 }
        }),
    );
}

#[derive(serde::Serialize)]
pub struct PresetEnrichPicks {
    pub hardware_concurrency: u32,
    pub device_memory: u32,
    pub platform_version: Option<String>,
}

/// Editor preview: draw a fresh hw + platform_version triple from the same tables save uses.
#[tauri::command]
fn enrich_picks_for_preset(preset_id: String) -> Result<PresetEnrichPicks, String> {
    let entry = fingerprints::get(&preset_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("unknown fingerprint id: {preset_id}"))?;
    let platform = entry
        .payload
        .get("navigator")
        .and_then(|n| n.get("platform"))
        .and_then(|v| v.as_str())
        .unwrap_or("macOS")
        .to_string();
    let mut payload = serde_json::Map::new();
    payload.insert(
        "_meta".into(),
        serde_json::json!({ "gpu_preset_id": preset_id }),
    );
    payload.insert(
        "navigator".into(),
        serde_json::json!({ "platform": platform }),
    );
    // Mirror enrich_new_config order: platform_version first, then hardware.
    randomize_platform_version(&mut payload);
    randomize_hardware(&mut payload);
    let nav = payload
        .get("navigator")
        .and_then(|v| v.as_object())
        .ok_or("internal: navigator missing after randomize")?;
    let cores = nav
        .get("hardware_concurrency")
        .and_then(|v| v.as_u64())
        .ok_or("internal: hardware_concurrency missing")? as u32;
    let mem = nav
        .get("device_memory")
        .and_then(|v| v.as_u64())
        .ok_or("internal: device_memory missing")? as u32;
    let pv = nav
        .get("platform_version")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    Ok(PresetEnrichPicks {
        hardware_concurrency: cores,
        device_memory: mem,
        platform_version: pv,
    })
}

// ---- Fingerprint library ----

#[tauri::command]
fn fingerprint_list() -> Result<Vec<fingerprints::LibraryEntry>, String> {
    fingerprints::list_all().map_err(|e| e.to_string())
}

#[tauri::command]
fn fingerprint_get(id: String) -> Result<Option<fingerprints::LibraryEntry>, String> {
    fingerprints::get(&id).map_err(|e| e.to_string())
}

#[tauri::command]
fn fingerprint_import(
    json_text: String,
    id_hint: Option<String>,
) -> Result<fingerprints::LibraryEntry, String> {
    fingerprints::import(&json_text, id_hint).map_err(|e| e.to_string())
}

#[tauri::command]
fn fingerprint_delete(id: String) -> Result<(), String> {
    fingerprints::delete(&id).map_err(|e| e.to_string())
}

/// What this machine's GPU can actually do. Cached; `force` re-asks the engine.
/// Slow on the first call — it starts the engine off-screen — so the UI asks once.
#[tauri::command]
async fn gpu_caps(force: bool) -> Result<gpu_caps::HostGlCaps, String> {
    gpu_caps::probe(force).await.map_err(|e| e.to_string())
}

/// Whether the machine can wear each library fingerprint, keyed by id. Kept out of
/// fingerprint_list() so that stays fast; an empty map means "not known", not "all fine".
#[tauri::command]
async fn gpu_caps_compat() -> Result<std::collections::HashMap<String, gpu_caps::Compat>, String> {
    let caps = match gpu_caps::probe(false).await {
        Ok(c) => c,
        Err(_) => return Ok(Default::default()),
    };
    let entries = fingerprints::list_all().map_err(|e| e.to_string())?;
    Ok(entries
        .into_iter()
        .map(|e| (e.id, gpu_caps::compat(&e.payload, &caps)))
        .collect())
}

/// Path to fingerprint library dir (UI "Open library folder").
#[tauri::command]
fn fingerprint_dir() -> Result<String, String> {
    store::fingerprints_dir()
        .map(|p| p.display().to_string())
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn read_text_file(path: String) -> Result<String, String> {
    std::fs::read_to_string(&path).map_err(|e| e.to_string())
}

// ---- Process tracker ----

#[tauri::command]
fn process_list() -> Vec<process::RunningProfile> {
    process::Tracker::shared().running()
}

fn devtools_frontend_url(cdp_http_url: &str, path: &str) -> String {
    if path.starts_with("http://")
        || path.starts_with("https://")
        || path.starts_with("devtools://")
    {
        return path.to_string();
    }
    format!(
        "{}{}{}",
        cdp_http_url.trim_end_matches('/'),
        if path.starts_with('/') { "" } else { "/" },
        path
    )
}

fn devtools_target_summary(cdp: &process::CdpInfo, target: &Value) -> Value {
    let frontend = target
        .get("devtoolsFrontendUrl")
        .and_then(Value::as_str)
        .map(|path| devtools_frontend_url(&cdp.http_url, path));
    serde_json::json!({
        "id": target.get("id").and_then(Value::as_str).unwrap_or(""),
        "type": target.get("type").and_then(Value::as_str).unwrap_or(""),
        "title": target.get("title").and_then(Value::as_str).unwrap_or(""),
        "url": target.get("url").and_then(Value::as_str).unwrap_or(""),
        "attached": target.get("attached").and_then(Value::as_bool).unwrap_or(false),
        "web_socket_debugger_url": target.get("webSocketDebuggerUrl").and_then(Value::as_str),
        "devtools_frontend_url": frontend,
    })
}

fn select_devtools_target(targets: &[Value]) -> Option<&Value> {
    let is_challenge = |target: &&Value| {
        let title = target
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_ascii_lowercase();
        let url = target
            .get("url")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_ascii_lowercase();
        title.contains("just a moment")
            || title.contains("chờ một chút")
            || url.contains("__cf_chl")
            || url.contains("challenges.cloudflare.com")
    };
    targets.iter().find(is_challenge).or_else(|| {
        targets.iter().find(|target| {
            target
                .get("url")
                .and_then(Value::as_str)
                .is_some_and(|url| !url.is_empty() && !url.starts_with("devtools://"))
        })
    })
}

#[tauri::command]
async fn devtools_context(profile_id: String) -> Result<Value, String> {
    let cdp = process::Tracker::shared()
        .cdp(&profile_id)
        .ok_or_else(|| "Profile is running without CDP. Start it through Automation API or MCP to enable DevTools.".to_string())?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .map_err(|e| e.to_string())?;
    let targets: Value = client
        .get(format!("{}/json/list", cdp.http_url.trim_end_matches('/')))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())?;
    let targets: Vec<Value> = match targets.as_array() {
        Some(targets) => targets
            .iter()
            .filter(|target| target.get("type").and_then(Value::as_str) == Some("page"))
            .map(|target| devtools_target_summary(&cdp, target))
            .collect(),
        None => Vec::new(),
    };
    let current = select_devtools_target(&targets).cloned();
    Ok(serde_json::json!({
        "profile_id": profile_id,
        "cdp": cdp,
        "targets": targets,
        "current": current,
    }))
}

#[tauri::command]
async fn devtools_activate(profile_id: String) -> Result<Value, String> {
    let context = devtools_context(profile_id.clone()).await?;
    let target = context
        .get("current")
        .filter(|target| !target.is_null())
        .cloned()
        .ok_or_else(|| "No page target is available for this profile.".to_string())?;
    let target_id = target
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| "The selected page target has no id.".to_string())?;
    let cdp_http_url = context
        .get("cdp")
        .and_then(|cdp| cdp.get("http_url"))
        .and_then(Value::as_str)
        .ok_or_else(|| "The profile has no CDP HTTP URL.".to_string())?;
    let mut activate_url = url::Url::parse(cdp_http_url).map_err(|e| e.to_string())?;
    activate_url.set_path(&format!("/json/activate/{target_id}"));
    activate_url.set_query(None);

    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .map_err(|e| e.to_string())?
        .get(activate_url)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?;

    Ok(serde_json::json!({
        "profile_id": profile_id,
        "activated": true,
        "target": target,
    }))
}

#[tauri::command]
async fn process_kill(profile_id: String) -> Result<bool, String> {
    process::Tracker::shared()
        .kill(&profile_id)
        .await
        .map_err(|e| e.to_string())
}

// ---- Proxies ----

#[tauri::command]
fn proxy_list() -> Result<Vec<proxy::ProxyEntry>, String> {
    // Newest-first display order; internal paths still read raw on-disk order.
    let mut list = proxy::list().map_err(|e| e.to_string())?;
    list.reverse();
    Ok(list)
}

#[tauri::command]
fn proxy_save(entry: proxy::ProxyEntry) -> Result<proxy::ProxyEntry, String> {
    proxy::upsert(entry).map_err(|e| e.to_string())
}

#[tauri::command]
fn proxy_delete(id: String) -> Result<(), String> {
    proxy::delete(&id).map_err(|e| e.to_string())
}

#[tauri::command]
async fn proxy_check(entry: proxy::ProxyEntry) -> Result<u128, String> {
    proxy::probe(&entry).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn proxy_check_udp(entry: proxy::ProxyEntry) -> Result<u128, String> {
    proxy::probe_udp(&entry).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn proxy_geo(
    entry: proxy::ProxyEntry,
    provider: Option<String>,
) -> Result<proxy::GeoInfo, String> {
    proxy::geo_check(&entry, provider)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn proxy_full_test(entry: proxy::ProxyEntry) -> Result<proxy::TestSnapshot, String> {
    proxy::full_test(&entry).await.map_err(|e| e.to_string())
}

#[tauri::command]
fn proxy_history(id: String) -> Result<Vec<proxy::TestSnapshot>, String> {
    proxy::history(&id).map_err(|e| e.to_string())
}

#[tauri::command]
fn proxy_last_test(id: String) -> Option<proxy::TestSnapshot> {
    proxy::latest_test(&id)
}

#[tauri::command]
fn proxy_bulk_import(text: String, kind: String) -> Result<usize, String> {
    let default_kind = match kind.as_str() {
        "http" => proxy::ProxyKind::Http,
        "https" => proxy::ProxyKind::Https,
        _ => proxy::ProxyKind::Socks5,
    };
    let parsed = proxy::parse_bulk(&text, default_kind);
    proxy::bulk_save(parsed).map_err(|e| e.to_string())
}

/// Parse bulk-import text without saving (preview list with per-row test).
#[tauri::command]
fn proxy_bulk_parse(text: String, kind: String) -> Vec<proxy::ProxyEntry> {
    let default_kind = match kind.as_str() {
        "http" => proxy::ProxyKind::Http,
        "https" => proxy::ProxyKind::Https,
        _ => proxy::ProxyKind::Socks5,
    };
    proxy::parse_bulk(&text, default_kind)
}

/// Persist pre-tested proxies (bulk dialog).
#[tauri::command]
fn proxy_bulk_save(entries: Vec<proxy::ProxyEntry>) -> Result<usize, String> {
    proxy::bulk_save(entries).map_err(|e| e.to_string())
}

// ---- Launcher ----

#[tauri::command]
async fn launch(profile_id: String) -> Result<u32, String> {
    // UI launches: no CDP, headed. The bus goes along even with no group so the
    // page helper has somewhere to report.
    if migrate::in_progress() {
        return Err("profiles are being moved — try again when that finishes".into());
    }
    let b = bus().await?;
    launch::launch_profile_synced(&profile_id, false, false, None, b.port, &b.token)
        .await
        .map(|o| o.pid)
        .map_err(|e| e.to_string())
}

// ---- Window synchronisation ----

/// The synchronisation bus, started lazily and shared: the port stays closed
/// for a user who never groups profiles.
static BUS: tokio::sync::OnceCell<std::sync::Arc<sync_bus::Bus>> =
    tokio::sync::OnceCell::const_new();

async fn bus() -> Result<std::sync::Arc<sync_bus::Bus>, String> {
    BUS.get_or_try_init(|| async {
        // Fresh per run: tells a browser this launcher started it rather than
        // anything else on the machine.
        let token = uuid::Uuid::new_v4().simple().to_string();
        sync_bus::Bus::start(token).await.map_err(|e| e.to_string())
    })
    .await
    .cloned()
}

/// Opens (or re-focuses) the floating control panel for a group. Same bundle,
/// addressed by hash — a 60px strip does not warrant its own vite entry point.
fn open_sync_panel(app: &tauri::AppHandle, group: &str) {
    use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};

    if let Some(w) = app.get_webview_window("sync-panel") {
        let _ = w.set_focus();
        return;
    }
    let url = format!("index.html#/?syncPanel={group}");
    let built = WebviewWindowBuilder::new(app, "sync-panel", WebviewUrl::App(url.into()))
        .title("ShardX Sync")
        .inner_size(360.0, 168.0)
        .resizable(true)
        .min_inner_size(280.0, 120.0)
        .resizable(false)
        .always_on_top(true)
        .decorations(false)
        .skip_taskbar(true)
        .build();
    if let Err(e) = built {
        // Not fatal — the group is synchronising, it just has no panel.
        eprintln!("[launcher] sync panel unavailable: {e}");
    }
}

#[tauri::command]
async fn sync_launch(
    app: tauri::AppHandle,
    profile_ids: Vec<String>,
    group: Option<String>,
) -> Result<String, String> {
    if profile_ids.len() < 2 {
        return Err("a group needs at least two profiles".into());
    }
    let group = group.unwrap_or_else(|| "fleet".to_string());
    let b = bus().await?;

    let mut failed: Vec<String> = Vec::new();
    for id in &profile_ids {
        if let Err(e) =
            launch::launch_profile_synced(id, false, false, Some(&group), b.port, &b.token).await
        {
            failed.push(format!("{id}: {e}"));
        }
    }
    if failed.len() == profile_ids.len() {
        return Err(format!("nothing launched — {}", failed.join("; ")));
    }
    // A partial launch is still a usable group; just say what did not make it.
    if !failed.is_empty() {
        eprintln!(
            "[launcher] sync group '{group}': {} failed — {}",
            failed.len(),
            failed.join("; ")
        );
    }
    open_sync_panel(&app, &group);
    Ok(group)
}

#[tauri::command]
async fn sync_status(group: String) -> Result<sync_bus::GroupStatus, String> {
    Ok(bus().await?.status(&group))
}

#[tauri::command]
async fn sync_set_paused(group: String, paused: bool) -> Result<(), String> {
    bus().await?.set_paused(&group, paused);
    Ok(())
}

/// Lays the group's windows out on the primary display's work area — under the
/// menu bar or behind the dock means moving them by hand anyway.
#[tauri::command]
async fn sync_arrange(
    app: tauri::AppHandle,
    group: String,
    layout: sync_bus::Layout,
) -> Result<(), String> {
    let monitor = app
        .primary_monitor()
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "no display".to_string())?;
    let scale = monitor.scale_factor();
    let pos = monitor.position().to_logical::<i32>(scale);
    let size = monitor.size().to_logical::<i32>(scale);
    // Margin for the menu bar; browsers report logical pixels, as SetBounds wants.
    let top = if cfg!(target_os = "macos") { 28 } else { 0 };
    bus().await?.arrange(
        &group,
        layout,
        (pos.x, pos.y + top, size.width, size.height - top),
    );
    Ok(())
}

/// Asks every window in the group to close; the panel goes with them.
#[tauri::command]
async fn sync_stop(group: String) -> Result<(), String> {
    bus().await?.stop(&group);
    Ok(())
}

/// Holds one profile out of the group — a captcha, a different password.
#[tauri::command]
async fn sync_set_excluded(group: String, profile: String, excluded: bool) -> Result<(), String> {
    bus().await?.set_excluded(&group, &profile, excluded);
    Ok(())
}

/// Every profile whose current page has something the helper could fill.
#[tauri::command]
async fn helper_profiles() -> Result<Vec<String>, String> {
    let s = settings::load().map_err(|e| e.to_string())?;
    if !s.helper_enabled {
        return Ok(Vec::new());
    }
    Ok(bus().await?.helper_profiles(&s.helper_triggers))
}

/// What the helper found in one profile.
#[tauri::command]
async fn helper_fields(profile: String) -> Result<serde_json::Value, String> {
    Ok(bus()
        .await?
        .helper_fields(&profile)
        .unwrap_or(serde_json::Value::Null))
}

/// The operator accepted the offer; nothing fills without this. In a group every
/// member fills with its own person — the command travels, the data does not.
#[tauri::command]
async fn helper_fill(profile: String) -> Result<usize, String> {
    let b = bus().await?;
    match b.group_of(&profile) {
        Some(group) => Ok(b.fill_group(&group)),
        None => {
            b.fill(&profile);
            Ok(1)
        }
    }
}

/// Opens (or re-focuses) the helper panel for one profile.
fn open_helper_panel(app: &tauri::AppHandle, profile: &str) {
    use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};
    if let Some(w) = app.get_webview_window("helper-panel") {
        let _ = w.set_focus();
        return;
    }
    let url = format!("index.html#/?helperPanel={profile}");
    if let Err(e) = WebviewWindowBuilder::new(app, "helper-panel", WebviewUrl::App(url.into()))
        .title("Shard Helper")
        .inner_size(300.0, 150.0)
        .resizable(false)
        .always_on_top(true)
        .decorations(false)
        .skip_taskbar(true)
        // Unfocused: it appears mid-form, and stealing the keyboard then is
        // worse than not appearing.
        .focused(false)
        .build()
    {
        eprintln!("[launcher] helper panel unavailable: {e}");
    }
}

/// `async` is load-bearing. A sync command runs on the main thread, and building
/// a webview there deadlocks on Windows: WebView2 needs the message loop this
/// command is sitting on, so the panel comes up white and the whole launcher
/// stops answering. An async command runs off that thread and the builder hands
/// the work to the loop properly.
#[tauri::command]
async fn helper_show(app: tauri::AppHandle, profile: String) -> Result<(), String> {
    open_helper_panel(&app, &profile);
    Ok(())
}

#[tauri::command]
fn helper_close(app: tauri::AppHandle) -> Result<(), String> {
    use tauri::Manager;
    if let Some(w) = app.get_webview_window("helper-panel") {
        let _ = w.close();
    }
    Ok(())
}

/// The operator closed the panel themselves — a refusal about this page.
/// `helper_close` is the other case: the page moved on, which silences nothing.
#[tauri::command]
async fn helper_dismiss(app: tauri::AppHandle, profile: String) -> Result<(), String> {
    use tauri::Manager;
    bus().await?.helper_dismiss(&profile);
    if let Some(w) = app.get_webview_window("helper-panel") {
        let _ = w.close();
    }
    Ok(())
}

/// Closes the floating panel; the panel calls it once the group is empty.
#[tauri::command]
fn sync_close_panel(app: tauri::AppHandle) -> Result<(), String> {
    use tauri::Manager;
    if let Some(w) = app.get_webview_window("sync-panel") {
        let _ = w.close();
    }
    Ok(())
}

// ---- Cookies ----

/// True if profile has a running browser process.
pub fn is_profile_running(profile_id: &str) -> bool {
    process::Tracker::shared()
        .running()
        .iter()
        .any(|r| r.profile_id == profile_id)
}

#[tauri::command]
fn cookies_export(profile_id: String) -> Result<Vec<cookies::Cookie>, String> {
    cookies::export(&profile_id).map_err(|e| e.to_string())
}

/// Export cookies to a user-picked path; returns count written.
#[tauri::command]
fn cookies_export_to_file(profile_id: String, path: String) -> Result<usize, String> {
    let cookies = cookies::export(&profile_id).map_err(|e| e.to_string())?;
    let json = serde_json::to_string_pretty(&cookies).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| e.to_string())?;
    Ok(cookies.len())
}

#[tauri::command]
fn cookies_import(profile_id: String, cookies: Vec<cookies::Cookie>) -> Result<usize, String> {
    let _claim = profile::begin_user_mutation([&profile_id], "import cookies")
        .map_err(|error| error.to_string())?;
    cookies::import(&profile_id, &cookies).map_err(|e| e.to_string())
}

// ---- Settings ----

#[tauri::command]
fn settings_get() -> Result<settings::Settings, String> {
    settings::load().map_err(|e| e.to_string())
}

#[tauri::command]
fn settings_save(app: tauri::AppHandle, mut value: settings::Settings) -> Result<(), String> {
    // Owned by the migration, not the form — which round-trips the whole struct
    // and would reset it while the data sits on another disk.
    if let Ok(cur) = settings::load() {
        value.data_root = cur.data_root;
        if value.api_secret.is_empty() {
            value.api_secret = cur.api_secret;
        }
        // Startup registration is a desktop-integration fact, not a form field.
        // A client that omits these (an older UI, or a partial save) must not
        // silently unregister the launcher from login.
        if !value.startup_fields_present {
            value.launch_at_login = cur.launch_at_login;
            value.start_minimized = cur.start_minimized;
        }
    }
    // `startup::save` persists the settings and reconciles the login entry.
    startup::save(&app, &value)?;
    notify_store_changed("settings");
    Ok(())
}

#[tauri::command]
fn startup_status(app: tauri::AppHandle) -> Result<startup::StartupStatus, String> {
    startup::status(&app)
}

// ---- Automation API ----

fn api_info_value(s: &settings::Settings, token: String) -> Value {
    let runtime = api::runtime_status();
    let runtime_base_url = runtime.port.map(|port| format!("http://127.0.0.1:{port}"));
    let restart_required =
        s.api_enabled != runtime.enabled || (s.api_enabled && runtime.port != Some(s.api_port));
    serde_json::json!({
        "enabled": s.api_enabled,
        "port": s.api_port,
        "base_url": format!("http://127.0.0.1:{}", s.api_port),
        "token": token,
        "running": runtime.running,
        "runtime_enabled": runtime.enabled,
        "runtime_port": runtime.port,
        "runtime_base_url": runtime_base_url,
        "error": runtime.error,
        "restart_required": restart_required,
    })
}

/// Saved API connection info plus the listener's actual runtime state.
#[tauri::command]
fn api_info() -> Result<Value, String> {
    let s = settings::ensure_secret().map_err(|e| e.to_string())?;
    let token = api::long_lived_token(&s.api_secret)?;
    Ok(api_info_value(&s, token))
}

/// Rotate API secret; live-swap on running server invalidates prior tokens.
#[tauri::command]
fn api_regenerate_token() -> Result<Value, String> {
    let mut s = settings::load().map_err(|e| e.to_string())?;
    s.api_secret = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    settings::save(&s).map_err(|e| e.to_string())?;
    api::set_secret(&s.api_secret);
    let token = api::long_lived_token(&s.api_secret)?;
    Ok(api_info_value(&s, token))
}

// ---- Team server (v2 fleet) ----

/// Connection status for the Settings page. Never returns the token or key.
#[tauri::command]
fn team_status() -> Result<team_config::TeamStatus, String> {
    team_config::status().map_err(|e| e.to_string())
}

/// Save the server URL, token and tenant.
///
/// Changing the server clears the enrollment: a device id and signing key are
/// only meaningful to the server that issued them, and keeping them would
/// leave the UI claiming an enrollment that server never made.
#[tauri::command]
fn team_set_connection(
    server_url: String,
    token: String,
    tenant_id: String,
) -> Result<team_config::TeamStatus, String> {
    let mut c = team_config::load().map_err(|e| e.to_string())?;

    let url = server_url.trim().trim_end_matches('/').to_string();
    if !url.is_empty() && !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err("server URL must start with http:// or https://".into());
    }

    let server_changed = url != c.server_url || tenant_id.trim() != c.tenant_id;
    c.server_url = url;
    c.token = token.trim().to_string();
    c.tenant_id = tenant_id.trim().to_string();
    if server_changed {
        c.device_id.clear();
        c.signing_key_seed.clear();
        c.hpke_key_seed.clear();
    }

    team_config::save(&c).map_err(|e| e.to_string())?;
    team_config::status().map_err(|e| e.to_string())
}

/// Check the saved connection by asking the server who it is.
#[tauri::command]
async fn team_test_connection() -> Result<String, String> {
    let c = team_config::load().map_err(|e| e.to_string())?;
    if c.server_url.is_empty() || c.token.is_empty() {
        return Err("set the server URL and token first".into());
    }
    let client =
        fleet_client::FleetClient::new(&c.server_url, &c.token).map_err(|e| e.to_string())?;
    let id = client.server_identity().await.map_err(|e| e.to_string())?;
    Ok(id.server_instance_id)
}

/// Enroll this device: generate a signing key, prove possession, store the id.
///
/// The key is generated locally and only its public half is sent. Enrolling
/// again replaces the previous identity, so the command refuses when this
/// device is already enrolled rather than silently orphaning the old one.
#[tauri::command]
async fn team_enroll_device(label: String) -> Result<team_config::TeamStatus, String> {
    let mut c = team_config::load().map_err(|e| e.to_string())?;
    if c.server_url.is_empty() || c.token.is_empty() {
        return Err("set the server URL and token first".into());
    }
    if c.tenant_id.is_empty() {
        return Err("set the tenant id first".into());
    }
    if c.is_enrolled() {
        return Err("this device is already enrolled".into());
    }

    // Fresh signing key for this device. `getrandom` is a Windows-only
    // dependency in this crate, so go through shared, which has it on every
    // platform — enrollment is not Windows-only.
    let mut seed = [0u8; 32];
    shardx_core::keys::fill_random(&mut seed).map_err(|e| e.to_string())?;
    let signer = shardx_core::signing::Ed25519SigningKey::from_bytes(&seed);

    // HPKE recipient key: enrollment records it, and fleet key grants will be
    // sealed to it. Generated with the signing key so one enrollment covers
    // both, rather than needing a second round trip later.
    let mut hpke_seed = [0u8; 32];
    shardx_core::keys::fill_random(&mut hpke_seed).map_err(|e| e.to_string())?;
    let (_hpke_secret, hpke_public) = shardx_core::grants::derive_keypair(&hpke_seed);
    let hpke_public: [u8; 32] = hpke_public
        .as_slice()
        .try_into()
        .map_err(|_| "HPKE public key must be 32 bytes".to_string())?;

    let client =
        fleet_client::FleetClient::new(&c.server_url, &c.token).map_err(|e| e.to_string())?;
    let enrolled = client
        .enroll_device(&c.tenant_id, &signer, &hpke_public, label.trim().as_bytes())
        .await
        .map_err(|e| e.to_string())?;

    c.device_id = enrolled.device_id;
    // Fleet routes are account-scoped, and the server is the only source for
    // this id. Storing it here is what lets sync run without a second call.
    c.account_id = enrolled.account_id;
    c.signing_key_seed = seed.iter().map(|b| format!("{b:02x}")).collect();
    // Without the HPKE seed the device can never open a root key grant sealed
    // to it: the public half is registered with the server, but the private
    // half only exists here. Discarding it would make enrollment permanently
    // unable to receive custody.
    c.hpke_key_seed = hpke_seed.iter().map(|b| format!("{b:02x}")).collect();
    c.hpke_key_seed = hpke_seed.iter().map(|b| format!("{b:02x}")).collect();
    team_config::save(&c).map_err(|e| e.to_string())?;

    // Read the key back before reporting success. The server now trusts this
    // public key; if the file did not round-trip, the failure should surface
    // here and not at the first publish, when a snapshot is already staged.
    let stored = team_config::load()
        .and_then(|s| s.signing_key())
        .map_err(|e| format!("device key did not round-trip: {e}"))?;
    if stored.verifying_key().to_bytes() != signer.verifying_key().to_bytes() {
        return Err("device key did not round-trip: key mismatch".into());
    }

    team_config::status().map_err(|e| e.to_string())
}

// ---- ProxyShard billing API ----

/// Saved billing-API key (empty string when unset).
#[tauri::command]
fn ps_get_key() -> Result<String, String> {
    psapi::get_key().map_err(|e| e.to_string())
}

#[tauri::command]
fn ps_set_key(key: String) -> Result<(), String> {
    psapi::set_key(key).map_err(|e| e.to_string())
}

/// Account profile (email, active_orders, wallet_balance cents) — also acts
/// as the "is the key valid?" probe.
#[tauri::command]
async fn ps_me() -> Result<Value, String> {
    psapi::call("GET", "/user/api/me", &[], None)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn ps_orders(
    status: String,
    offset: Option<i64>,
    limit: Option<i64>,
) -> Result<Value, String> {
    let mut q = vec![("status".to_string(), status)];
    if let Some(o) = offset {
        q.push(("offset".into(), o.to_string()));
    }
    if let Some(l) = limit {
        q.push(("limit".into(), l.to_string()));
    }
    psapi::call("GET", "/user/api/orders", &q, None)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn ps_order(id: i64) -> Result<Value, String> {
    psapi::call("GET", &format!("/user/api/orders/{id}"), &[], None)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn ps_active(order_id: i64) -> Result<Value, String> {
    psapi::call(
        "GET",
        "/user/api/proxies/active",
        &[("order_id".into(), order_id.to_string())],
        None,
    )
    .await
    .map_err(|e| e.to_string())
}

/// Pull an order's active proxies into the local proxy list. Returns count added.
#[tauri::command]
async fn ps_import_order(order_id: i64, kind: String) -> Result<usize, String> {
    psapi::import_order_proxies(order_id, kind)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn ps_products() -> Result<Value, String> {
    psapi::call("GET", "/user/api/proxies/products", &[], None)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn ps_available_count() -> Result<Value, String> {
    psapi::call("GET", "/user/api/proxies/available-count", &[], None)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn ps_calculate(
    product: String,
    location: Option<String>,
    cycle: Option<String>,
    quantity: Option<i64>,
    promo_code: Option<String>,
    addons_json: Option<String>,
) -> Result<Value, String> {
    let mut q = vec![("product".to_string(), product)];
    if let Some(v) = location.filter(|s| !s.is_empty()) {
        q.push(("location".into(), v));
    }
    if let Some(v) = cycle.filter(|s| !s.is_empty()) {
        q.push(("cycle".into(), v));
    }
    if let Some(v) = quantity {
        q.push(("quantity".into(), v.to_string()));
    }
    if let Some(v) = promo_code.filter(|s| !s.is_empty()) {
        q.push(("promo_code".into(), v));
    }
    // JSON array of add-ons, e.g. [{"addon_key":"p0f_slots","qty":5}].
    // reqwest URL-encodes the value.
    if let Some(v) = addons_json.filter(|s| !s.is_empty()) {
        q.push(("addons_json".into(), v));
    }
    psapi::call("GET", "/user/api/orders/calculate", &q, None)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn ps_purchase(body: Value) -> Result<Value, String> {
    psapi::call("POST", "/user/api/orders/purchase", &[], Some(body))
        .await
        .map_err(|e| e.to_string())
}

/// Buy extra GB of residential traffic for an order.
#[tauri::command]
async fn ps_add_bandwidth(
    id: i64,
    amount: i64,
    promo_code: Option<String>,
) -> Result<Value, String> {
    let mut body = serde_json::json!({ "amount": amount });
    if let Some(p) = promo_code.filter(|s| !s.is_empty()) {
        body["promo_code"] = Value::String(p);
    }
    psapi::call(
        "POST",
        &format!("/user/api/orders/{id}/add-bandwidth"),
        &[],
        Some(body),
    )
    .await
    .map_err(|e| e.to_string())
}

/// Account-owner traffic for a residential proxy type ("standart" | "premium").
#[tauri::command]
async fn ps_profile_traffic(proxy_type: String) -> Result<Value, String> {
    psapi::call(
        "GET",
        "/user/api/proxies/profile",
        &[("proxy_type".into(), proxy_type)],
        None,
    )
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
async fn ps_renew(id: i64) -> Result<Value, String> {
    psapi::call("POST", &format!("/user/api/orders/{id}/renew"), &[], None)
        .await
        .map_err(|e| e.to_string())
}

/// Residential location reference data (for the proxy generator).
#[tauri::command]
async fn ps_countries(proxy_type: String) -> Result<Value, String> {
    psapi::call(
        "GET",
        "/user/api/proxies/countries",
        &[("proxy_type".into(), proxy_type)],
        None,
    )
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
async fn ps_regions(proxy_type: String, country_code: String) -> Result<Value, String> {
    psapi::call(
        "GET",
        "/user/api/proxies/regions",
        &[
            ("proxy_type".into(), proxy_type),
            ("country_code".into(), country_code),
        ],
        None,
    )
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
async fn ps_cities(
    proxy_type: String,
    country_code: String,
    region_code: String,
) -> Result<Value, String> {
    psapi::call(
        "GET",
        "/user/api/proxies/cities",
        &[
            ("proxy_type".into(), proxy_type),
            ("country_code".into(), country_code),
            ("region_code".into(), region_code),
        ],
        None,
    )
    .await
    .map_err(|e| e.to_string())
}

/// Assign OS-fingerprint signatures to proxy IPs (consumes p0f slots).
/// `items` is an array of `{ ip, signature }`.
#[tauri::command]
async fn ps_signature_set(order_id: i64, items: Value) -> Result<Value, String> {
    psapi::call(
        "POST",
        &format!("/user/api/orders/{order_id}/signature/set"),
        &[],
        Some(serde_json::json!({ "items": items })),
    )
    .await
    .map_err(|e| e.to_string())
}

/// Set/clear an order's tag.
#[tauri::command]
async fn ps_set_tag(id: i64, tag: String) -> Result<Value, String> {
    psapi::call(
        "POST",
        &format!("/user/api/orders/{id}/tag"),
        &[],
        Some(serde_json::json!({ "tag": tag })),
    )
    .await
    .map_err(|e| e.to_string())
}

/// Collect the root key grants issued to this device and report what opened.
///
/// The tenant root key itself is never returned to the caller: this reports
/// whether custody is in place, not the key. A grant that fails to open is
/// reported rather than skipped, because silently ignoring it would hide a
/// device that cannot actually decrypt anything.
#[tauri::command]
async fn team_collect_custody() -> Result<serde_json::Value, String> {
    let c = team_config::load().map_err(|e| e.to_string())?;
    if !c.can_sync() {
        return Err("this device is not enrolled for fleet operations".into());
    }
    let seed = c.hpke_seed().map_err(|e| e.to_string())?;
    let (device_sk, _pk) = shardx_core::grants::derive_keypair(&seed);

    let client =
        fleet_client::FleetClient::new(&c.server_url, &c.token).map_err(|e| e.to_string())?;
    let grants = client
        .root_key_grants(&c.tenant_id, &c.device_id)
        .await
        .map_err(|e| e.to_string())?;

    let mut opened = 0usize;
    let mut failed = 0usize;
    let mut newest_generation: Option<i64> = None;
    for g in &grants {
        let info = hex_bytes(&g.hpke_info_hex)?;
        let encapped = hex_bytes(&g.hpke_encapped_key_hex)?;
        let wrapped = hex_bytes(&g.hpke_wrapped_trk_hex)?;
        match shardx_core::grants::open_trk_with_info(&device_sk, &info, &encapped, &wrapped) {
            Ok(_trk) => {
                // The key is dropped here: it is zeroized on drop, and holding
                // it would mean deciding where to store it, which is the
                // custody question this command does not answer.
                opened += 1;
                newest_generation = Some(match newest_generation {
                    Some(n) if n >= g.root_generation => n,
                    _ => g.root_generation,
                });
            }
            Err(_) => failed += 1,
        }
    }

    // Fleet keys. These are the ones sync actually needs: the root key
    // authorises custody, the fleet key opens snapshots. Collected keys are
    // cached so a push or pull no longer needs a passphrase.
    let mut fleet_opened = 0usize;
    let mut fleet_failed = 0usize;
    let mut newest_fleet_generation: Option<i64> = None;
    if !c.fleet_id.is_empty() {
        let fleet_grants = client
            .fleet_key_grants(&c.tenant_id, &c.device_id)
            .await
            .map_err(|e| e.to_string())?;

        let mut store = fleet_keys::load().map_err(|e| e.to_string())?;
        for g in &fleet_grants {
            let info = hex_bytes(&g.hpke_info_hex)?;
            let encapped = hex_bytes(&g.hpke_encapped_key_hex)?;
            let wrapped = hex_bytes(&g.hpke_wrapped_fkek_hex)?;
            let sealed = shardx_core::grants::SealedGrant {
                hpke_info_bytes: info,
                encapped_key_bytes: encapped,
                ciphertext_bytes: wrapped,
            };
            match shardx_core::fleet_grants::open_fkek_with_info(&device_sk, &sealed) {
                Ok(fkek) => {
                    let generation = u64::try_from(g.fleet_generation).unwrap_or(0);
                    store.insert(&g.fleet_id, generation, &fkek);
                    fleet_opened += 1;
                    newest_fleet_generation = Some(match newest_fleet_generation {
                        Some(n) if n >= g.fleet_generation => n,
                        _ => g.fleet_generation,
                    });
                }
                Err(_) => fleet_failed += 1,
            }
        }
        if fleet_opened > 0 {
            fleet_keys::save(&store).map_err(|e| e.to_string())?;
        }
    }

    Ok(serde_json::json!({
        "grants": grants.len(),
        "opened": opened,
        "failed": failed,
        "newest_generation": newest_generation,
        "fleet_opened": fleet_opened,
        "fleet_failed": fleet_failed,
        "newest_fleet_generation": newest_fleet_generation,
        "can_sync_without_passphrase": fleet_opened > 0,
    }))
}

/// Decode a hex string from the server into bytes.
fn hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("malformed hex from server".into());
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
/// Bring the main window back from the tray / minimized state and focus it.
fn show_main_window(app: &tauri::AppHandle) {
    use tauri::Manager;
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

#[cfg(test)]
mod profile_mutation_boundary_tests {
    use super::*;

    fn assert_running_blocked<T>(result: Result<T, String>) {
        let error = result.err().expect("running profile mutation must fail");
        assert!(
            error.contains("Stop the running browser"),
            "expected actionable running-profile error, got: {error}"
        );
    }

    #[test]
    fn every_tauri_profile_mutation_entry_point_checks_running_state_first() {
        // The lifecycle claim map is process-wide; without this lock a claim
        // held by a profile::tests case can surface as a Busy error here.
        let _lifecycle = profile::lifecycle_test_guard();
        let profile_id = "tauri-running-mutation-boundary-test";
        let tracker = process::Tracker::shared();
        tracker.set_running_for_test(profile_id, true);

        assert_running_blocked(save_profile_core(
            None,
            serde_json::json!({
                "name": "Running profile",
                "_meta": { "id": profile_id }
            }),
            false,
        ));
        assert_running_blocked(profile_delete(profile_id.to_string()));
        assert_running_blocked(profile_bind_proxy(profile_id.to_string(), None));
        assert_running_blocked(profile_clone(profile_id.to_string()));
        assert_running_blocked(profile_set_pin(profile_id.to_string(), true));
        assert_running_blocked(profile_set_folder(
            profile_id.to_string(),
            "folder".to_string(),
        ));
        assert_running_blocked(cookies_import(profile_id.to_string(), Vec::new()));

        // Sync reads and writes the profile directory exactly as backup and
        // restore do, so it must refuse a running profile for the same reason:
        // Chromium holds SQLite handles open.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        assert_running_blocked(rt.block_on(sync_cmd::profile_sync_push(
            profile_id.to_string(),
            "passphrase".to_string(),
            0,
        )));
        assert_running_blocked(rt.block_on(sync_cmd::profile_sync_pull(
            profile_id.to_string(),
            "passphrase".to_string(),
        )));

        tracker.set_running_for_test(profile_id, false);
    }
}

pub fn run() {
    tauri::Builder::default()
        // Must be the first plugin: a second launch focuses the running window.
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            if !startup::args_request_autostart(&argv) {
                show_main_window(app);
            }
        }))
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec![startup::AUTOSTART_ARG]),
        ))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(updater::PendingUpdate::default())
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let to_tray = settings::load().map(|s| s.minimize_to_tray).unwrap_or(true);
                if window.label() == "main" && to_tray {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            sync_launch,
            sync_status,
            sync_set_paused,
            sync_arrange,
            sync_stop,
            sync_set_excluded,
            sync_close_panel,
            helper_profiles,
            helper_fields,
            helper_fill,
            helper_show,
            helper_close,
            helper_dismiss,
            profile_list,
            profile_get,
            profile_validate_name,
            profile_save,
            profile_delete,
            team_status,
            team_collect_custody,
            team_set_connection,
            team_test_connection,
            team_enroll_device,
            backup_cmd::profile_backup_create,
            sync_cmd::profile_sync_push,
            sync_cmd::profile_sync_pull,
            sync_cmd::profile_sync_status,
            backup_cmd::profile_backup_restore,
            backup_cmd::profile_backup_inspect,
            trash_list,
            trash_restore,
            trash_purge,
            trash_empty,
            extension_list,
            extension_import,
            extension_import_url,
            extension_delete,
            automation_list,
            automation_get,
            automation_save,
            automation_delete,
            automation_run,
            bookmark_list,
            bookmark_save,
            bookmark_delete,
            data_root_get,
            data_root_migrate,
            profile_bind_proxy,
            profile_clone,
            profile_import,
            clipboard_write,
            clipboard_read,
            profile_set_pin,
            profile_set_folder,
            folder_rename,
            folder_delete,
            host_platform,
            profile_create_from_template,
            enrich_picks_for_preset,
            fingerprint_list,
            fingerprint_get,
            fingerprint_import,
            fingerprint_delete,
            gpu_caps,
            gpu_caps_compat,
            fingerprint_dir,
            read_text_file,
            process_list,
            devtools_context,
            devtools_activate,
            process_kill,
            proxy_list,
            proxy_save,
            proxy_delete,
            proxy_check,
            proxy_check_udp,
            proxy_geo,
            proxy_full_test,
            proxy_history,
            proxy_last_test,
            proxy_bulk_import,
            proxy_bulk_parse,
            proxy_bulk_save,
            launch,
            settings_get,
            settings_save,
            startup_status,
            api_info,
            api_regenerate_token,
            ps_get_key,
            ps_set_key,
            ps_me,
            ps_orders,
            ps_order,
            ps_active,
            ps_import_order,
            ps_products,
            ps_available_count,
            ps_calculate,
            ps_purchase,
            ps_add_bandwidth,
            ps_profile_traffic,
            ps_renew,
            ps_set_tag,
            ps_countries,
            ps_regions,
            ps_cities,
            ps_signature_set,
            cookies_export,
            cookies_export_to_file,
            cookies_import,
            mcp_download,
            mcp_set_path,
            mcp_status,
            codex_mcp_status,
            hermes_mcp_status,
            runtime::runtime_status,
            runtime::runtime_install,
            updater::launcher_update_check,
            updater::launcher_update_download,
            updater::launcher_update_install,
            updater::launcher_update_restart,
        ])
        .setup(|app| {
            let _ = APP_HANDLE.set(app.handle().clone());

            // The window is created hidden to avoid a login-time flash. Normal
            // launches show it immediately; a configured startup launch keeps
            // it in the tray while the embedded Automation API comes online.
            let autostart_launch = startup::launched_for_autostart();
            match settings::load() {
                Ok(configured) => {
                    if let Err(error) =
                        startup::refresh_registration_path(app.handle(), &configured)
                    {
                        eprintln!("[launcher] startup registration refresh failed: {error}");
                    }
                    if !startup::should_start_hidden(&configured, autostart_launch) {
                        show_main_window(app.handle());
                    }
                }
                Err(error) => {
                    eprintln!("[launcher] startup settings load failed: {error}");
                    show_main_window(app.handle());
                }
            }

            {
                use tauri::menu::{Menu, MenuItem};
                use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
                let show =
                    MenuItem::with_id(app, "tray_show", "Show Launcher", true, None::<&str>)?;
                let quit = MenuItem::with_id(app, "tray_quit", "Quit", true, None::<&str>)?;
                let menu = Menu::with_items(app, &[&show, &quit])?;
                if let Some(icon) = app.default_window_icon().cloned() {
                    TrayIconBuilder::with_id("main")
                        .icon(icon)
                        .tooltip("ShardX Launcher")
                        .menu(&menu)
                        .show_menu_on_left_click(false)
                        .on_menu_event(|app, e| match e.id.as_ref() {
                            "tray_show" => show_main_window(app),
                            "tray_quit" => app.exit(0),
                            _ => {}
                        })
                        .on_tray_icon_event(|tray, e| {
                            if let TrayIconEvent::Click {
                                button: MouseButton::Left,
                                button_state: MouseButtonState::Up,
                                ..
                            } = e
                            {
                                show_main_window(tray.app_handle());
                            }
                        })
                        .build(app)?;
                }
            }

            // Win/Linux: strip native caption since macOS-only titleBarStyle:Overlay leaves it.
            #[cfg(not(target_os = "macos"))]
            {
                use tauri::Manager;
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.set_decorations(false);
                }
            }

            // Migrate already-created profiles' UA + client_hints to the
            // current engine version (independent of the fingerprint seed).
            tauri::async_runtime::spawn(async {
                runtime::ensure_profiles_migrated().await;
            });

            // Point the heavy directories wherever the operator moved them,
            // before anything reads a profile.
            if let Ok(s) = settings::load() {
                if let Some(root) = s.data_root.as_deref().filter(|r| !r.is_empty()) {
                    store::set_data_root(Some(std::path::PathBuf::from(root)));
                }
            }

            // Trash older than its week.
            match trash::purge_expired() {
                Ok(n) if n > 0 => eprintln!("[launcher] trash: {n} expired profile(s) removed"),
                Ok(_) => {}
                Err(e) => eprintln!("[launcher] trash sweep failed: {e}"),
            }

            // Clean up temporary profiles from crashed runs.
            match profile::purge_temporary() {
                Ok(n) if n > 0 => eprintln!("[launcher] purged {n} stale temporary profile(s)"),
                Ok(_) => {}
                Err(e) => eprintln!("[launcher] temporary purge failed: {e}"),
            }

            // API task on the shared tokio runtime.
            match settings::ensure_secret() {
                Ok(s) if s.api_enabled => {
                    let (secret, port) = (s.api_secret.clone(), s.api_port);
                    tauri::async_runtime::spawn(async move {
                        api::serve(secret, port).await;
                    });
                }
                Ok(_) => {
                    api::mark_disabled();
                    eprintln!("[launcher] automation API disabled in settings");
                }
                Err(e) => eprintln!("[launcher] API secret init failed: {e}"),
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
