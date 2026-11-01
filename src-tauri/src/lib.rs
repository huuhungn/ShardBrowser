// ShardX Launcher — Tauri backend.

pub mod api;
pub mod automation;
mod backup_cmd;
mod bookmarks;
pub mod cdp;
mod codex_mcp;
mod cookies;
#[cfg(test)]
mod crash_harness;
mod credential;
pub mod db;
mod dpapi;
mod durable;
pub mod errcode;
mod extensions;
pub mod files;
mod fingerprints;
pub mod fleet_client;
mod fleet_keys;
pub mod gpu_caps;
mod hermes_mcp;
pub mod http_session;
mod key_file;
mod launch;
mod profile_icon;
pub mod root_bootstrap;
pub mod runner;
pub mod traffic;

/// Where the engine binary lives, for integration tests that need to know
/// whether a runtime is installed before probing it. The `runtime` module
/// itself stays private; only this one fact is worth exposing.
pub fn runtime_binary_path_for_tests() -> anyhow::Result<std::path::PathBuf> {
    // Lets the engine probes run against a candidate engine before it replaces
    // the installed one.
    if let Some(bin) = std::env::var_os("SHARDX_TEST_ENGINE") {
        return Ok(bin.into());
    }
    runtime::binary_path()
}

/// The switches the launcher adds when CDP is on, so the engine probe tests
/// exactly what a launch passes.
pub fn cdp_launch_args_for_tests() -> &'static [&'static str] {
    &launch::CDP_ARGS
}

mod mcp_setup;
mod migrate;
mod process;
mod profile;
mod proxy;
#[cfg(test)]
mod proxy_auth_engine_tests;
mod proxy_relay;
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
/// Public so its ledger API is reachable before the Team settings UI calls it.
pub mod team;
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
        .ok_or_else(|| crate::errcode::code("mcp.notAServerFolder"))?;
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
            if let Ok(_claim) = profile::begin_user_mutation(
                [&id],
                &crate::errcode::code("profile.actionBackfillMetadata"),
            ) {
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
/// A claim the display can hold is kept on every platform: replacing it with
/// the host's monitor made every profile on one machine report the same screen
/// (upstream 6c3f65a, "screen kept when it fits").
pub(crate) fn clamp_screen_to_real_display(
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
    if real_w >= fp_w && real_h >= fp_h {
        eprintln!(
            "[launcher] display: real {real_w}x{real_h} >= fp {fp_w}x{fp_h} — keeping FP screen"
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
        profile::begin_profile_creation(&crate::errcode::code("profile.actionCreateProfile"))
    } else {
        let id = payload
            .get("_meta")
            .and_then(|meta| meta.get("id"))
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        profile::begin_user_mutation([id], &crate::errcode::code("profile.actionModifyProfile"))
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
        tags: stored.meta.tags,
    })
}

/// Into the trash for a week; only the files carrying the account are kept.
#[tauri::command]
fn profile_delete(id: String) -> Result<(), String> {
    let _claim =
        profile::begin_user_mutation([&id], &crate::errcode::code("profile.actionDeleteProfile"))
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
        return Err(crate::errcode::code("fleet.closeProfilesFirst"));
    }
    let dst = std::path::PathBuf::from(&path);
    tauri::async_runtime::spawn_blocking(move || migrate::run(&app, &dst))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn profile_bind_proxy(profile_id: String, proxy_id: Option<String>) -> Result<(), String> {
    let _claim = profile::begin_user_mutation(
        [&profile_id],
        &crate::errcode::code("profile.actionChangeProxy"),
    )
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
        profile::begin_profile_creation(&crate::errcode::code("profile.actionImportProfiles"))
            .map_err(|error| error.to_string())?;
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
    // An empty clipboard is an empty string, not a failure. The platform
    // reports "nothing to read" as an error (a bare "unknown error" on macOS),
    // and callers already say "the clipboard is empty" in the operator's
    // language for "" (upstream 081770c, "clipboard-empty").
    Ok(app.clipboard().read_text().unwrap_or_default())
}

#[tauri::command]
fn profile_set_pin(id: String, pinned: bool) -> Result<(), String> {
    let _claim =
        profile::begin_user_mutation([&id], &crate::errcode::code("profile.actionChangePin"))
            .map_err(|error| error.to_string())?;
    profile::set_pin(&id, pinned).map_err(|e| e.to_string())
}

#[tauri::command]
fn profile_set_folder(id: String, folder: String) -> Result<(), String> {
    let _claim =
        profile::begin_user_mutation([&id], &crate::errcode::code("profile.actionMoveProfile"))
            .map_err(|error| error.to_string())?;
    profile::set_folder(&id, &folder).map_err(|e| e.to_string())
}

/// Replace a profile's tags; returns them normalized.
#[tauri::command]
fn profile_set_tags(id: String, tags: Vec<String>) -> Result<Vec<String>, String> {
    let _claim =
        profile::begin_user_mutation([&id], &crate::errcode::code("profile.actionChangeTags"))
            .map_err(|error| error.to_string())?;
    profile::set_tags(&id, &tags).map_err(|e| e.to_string())
}

#[tauri::command]
fn tags_list() -> Result<Vec<profile::TagInfo>, String> {
    profile::list_tags().map_err(|e| e.to_string())
}

/// Rename a tag on every profile; returns count.
#[tauri::command]
fn tag_rename(old: String, new: String) -> Result<usize, String> {
    profile::rename_tag(&old, &new).map_err(|e| e.to_string())
}

/// `color` None clears it.
#[tauri::command]
fn tag_recolor(name: String, color: Option<String>) -> Result<(), String> {
    profile::recolor_tag(&name, color.as_deref()).map_err(|e| e.to_string())
}

/// Remove a tag from every profile; returns count.
#[tauri::command]
fn tag_delete(name: String) -> Result<usize, String> {
    profile::delete_tag(&name).map_err(|e| e.to_string())
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
        .ok_or_else(|| crate::errcode::code_with("fp.unknownId", &[("id", template_id)]))?;

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
        .ok_or_else(|| crate::errcode::code_with("fp.unknownId", &[("id", &preset_id)]))?;
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
        .ok_or_else(|| crate::errcode::code("profile.runningWithoutCdp"))?;
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
        .ok_or_else(|| crate::errcode::code("profile.noPageTarget"))?;
    let target_id = target
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| crate::errcode::code("profile.pageTargetHasNoId"))?;
    let cdp_http_url = context
        .get("cdp")
        .and_then(|cdp| cdp.get("http_url"))
        .and_then(Value::as_str)
        .ok_or_else(|| crate::errcode::code("profile.noCdpHttpUrl"))?;
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

/// Cancel a launch still on its way: the pending `launch` call fails with
/// `launch.cancelled` and no browser starts.
#[tauri::command]
fn launch_cancel(profile_id: String) {
    launch::cancel(&profile_id);
}

#[tauri::command]
async fn launch(profile_id: String) -> Result<u32, String> {
    // UI launches: no CDP, headed. The bus goes along even with no group so the
    // page helper has somewhere to report.
    if migrate::in_progress() {
        return Err(crate::errcode::code("profile.beingMovedRetry"));
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
        return Err(crate::errcode::code("profile.groupNeedsTwo"));
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
        return Err(crate::errcode::code_with(
            "launch.nothingLaunched",
            &[("reasons", &failed.join("; "))],
        ));
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
    let _claim = profile::begin_user_mutation(
        [&profile_id],
        &crate::errcode::code("profile.actionImportCookies"),
    )
    .map_err(|error| error.to_string())?;
    cookies::import(&profile_id, &cookies).map_err(|e| e.to_string())
}

// ---- Settings ----

#[tauri::command]
fn settings_get() -> Result<settings::Settings, String> {
    settings::load().map_err(|e| e.to_string())
}

/// Why the settings file could not be read, for the Settings banner.
#[tauri::command]
fn settings_load_error() -> Option<String> {
    settings::load_error()
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

/// Moves every key still in plaintext into whatever now takes it: run after
/// the key file opens, so keys the OS store refused land there.
fn protect_all_keys() {
    if let Ok(mut team) = team_config::load() {
        if let Err(error) = team_config::protect_keys(&mut team) {
            eprintln!("[team] device keys stay in team.json: {error}");
        }
    }
    if let Err(error) = fleet_keys::protect() {
        eprintln!("[team] fleet keys stay in fleet_keys.json: {error}");
    }
}

/// Creates the passphrase-protected key file for a device whose OS
/// credential store cannot hold its keys, and moves them into it.
#[tauri::command]
async fn team_keys_create_file(passphrase: String) -> Result<team_config::TeamStatus, String> {
    tauri::async_runtime::spawn_blocking(move || {
        key_file::create(&passphrase).map_err(|e| e.to_string())?;
        protect_all_keys();
        team_config::status().map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Opens the key file for this run.
#[tauri::command]
async fn team_keys_unlock(passphrase: String) -> Result<team_config::TeamStatus, String> {
    tauri::async_runtime::spawn_blocking(move || {
        key_file::unlock(&passphrase).map_err(|e| e.to_string())?;
        protect_all_keys();
        team_config::status().map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
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
        return Err(crate::errcode::code("fleet.serverUrlScheme"));
    }

    let server_changed = url != c.server_url || tenant_id.trim() != c.tenant_id;
    c.server_url = url;
    c.token = token.trim().to_string().into();
    c.tenant_id = tenant_id.trim().to_string();
    let mut stale_refs = Vec::new();
    if server_changed {
        c.device_id.clear();
        c.signing_key_seed.clear();
        c.hpke_key_seed.clear();
        stale_refs.push(std::mem::take(&mut c.signing_credential_ref));
        stale_refs.push(std::mem::take(&mut c.hpke_credential_ref));
    }

    team_config::save(&c).map_err(|e| e.to_string())?;
    // The identity is gone from the file; its keys go with it. Best effort:
    // a credential left behind names a device no config refers to.
    for reference in stale_refs.iter().filter(|r| !r.is_empty()) {
        let _ = credential::forget(reference);
    }
    team_config::status().map_err(|e| e.to_string())
}

/// Check the saved connection by asking the server who it is.
#[tauri::command]
async fn team_test_connection() -> Result<String, String> {
    let c = team_config::load().map_err(|e| e.to_string())?;
    if c.server_url.is_empty() || c.token.is_empty() {
        return Err(crate::errcode::code("fleet.setServerAndTokenFirst"));
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
///
/// `username` and `password` are the operator's v2 account in the tenant: the
/// server enrolls a device only under that account's pre-device ticket. The
/// password is used for that one login and never stored.
#[tauri::command]
async fn team_enroll_device(
    label: String,
    username: String,
    password: String,
) -> Result<team_config::TeamStatus, String> {
    let mut c = team_config::load().map_err(|e| e.to_string())?;
    if c.server_url.is_empty() || c.token.is_empty() {
        return Err(crate::errcode::code("fleet.setServerAndTokenFirst"));
    }
    if c.tenant_id.is_empty() {
        return Err(crate::errcode::code("fleet.setTenantFirst"));
    }
    // A device whose stored keys this Windows account cannot open may enroll
    // again: there is no working identity left to orphan.
    if c.blocks_enrollment() {
        return Err(crate::errcode::code("fleet.deviceAlreadyEnrolled"));
    }
    if username.trim().is_empty() || password.is_empty() {
        return Err(crate::errcode::code("fleet.setAccountFirst"));
    }
    // Before anything is registered server-side: if the copy fails, nothing
    // has changed anywhere.
    if c.keys_unreadable() {
        team_config::preserve_unreadable().map_err(|e| e.to_string())?;
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
        .map_err(|_| crate::errcode::code("fleet.hpkeKeyLength"))?;

    let client =
        fleet_client::FleetClient::new(&c.server_url, &c.token).map_err(|e| e.to_string())?;
    let enrolled = client
        .enroll_device(
            &fleet_client::AccountLogin {
                tenant_id: &c.tenant_id,
                username: username.trim(),
                password: &password,
            },
            &signer,
            &hpke_public,
            label.trim().as_bytes(),
        )
        .await
        .map_err(|e| e.to_string())?;

    c.device_id = enrolled.device_id;
    // Fleet routes are account-scoped, and the server is the only source for
    // this id. Storing it here is what lets sync run without a second call.
    c.account_id = enrolled.account_id;
    c.signing_key_seed = seed
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
        .into();
    // Without the HPKE seed the device can never open a root key grant sealed
    // to it: the public half is registered with the server, but the private
    // half only exists here. Discarding it would make enrollment permanently
    // unable to receive custody.
    c.hpke_key_seed = hpke_seed
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
        .into();
    let old_refs = [
        std::mem::take(&mut c.signing_credential_ref),
        std::mem::take(&mut c.hpke_credential_ref),
    ];
    team_config::save(&c).map_err(|e| e.to_string())?;
    // Best effort: while the OS store is unavailable the seeds stay in the
    // file, and the read-back below still proves them.
    if let Err(error) = team_config::protect_keys(&mut c) {
        eprintln!("[team] device keys stay in team.json: {error}");
    }
    // A re-enrollment under a new device id leaves the old keys unreferenced.
    for reference in old_refs.iter().filter(|r| {
        !r.is_empty() && **r != c.signing_credential_ref && **r != c.hpke_credential_ref
    }) {
        let _ = credential::forget(reference);
    }

    // Read the key back before reporting success. The server now trusts this
    // public key; if the file did not round-trip, the failure should surface
    // here and not at the first publish, when a snapshot is already staged.
    let stored = team_config::load()
        .and_then(|s| s.signing_key())
        .map_err(|e| {
            crate::errcode::code_with("fleet.deviceKeyRoundTrip", &[("error", &e.to_string())])
        })?;
    if stored.verifying_key().to_bytes() != signer.verifying_key().to_bytes() {
        return Err(crate::errcode::code("fleet.deviceKeyMismatch"));
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

/// How far this device's first-device custody bootstrap got.
#[tauri::command]
fn team_custody_bootstrap_status() -> Result<root_bootstrap::BootstrapStatus, String> {
    root_bootstrap::status().map_err(|e| e.to_string())
}

/// Bootstrap root custody as the tenant's first device, or resume it.
///
/// The operator confirms this device first (`tenant confirm-first-device`).
/// The recovery bundle goes to `recovery_path`, sealed under `passphrase`;
/// a resumed run keeps the path of the bundle it already wrote and needs the
/// same passphrase. The password is used for one login and never stored.
#[tauri::command]
async fn team_bootstrap_custody(
    username: String,
    password: String,
    recovery_path: String,
    passphrase: String,
) -> Result<root_bootstrap::BootstrapStatus, String> {
    let c = team_config::load().map_err(|e| e.to_string())?;
    if !c.can_sync() {
        return Err(crate::errcode::code("fleet.deviceNotEnrolled"));
    }
    if !c.can_receive_custody() {
        return Err(crate::errcode::code("teamConfig.hpkeKeyUnusable"));
    }
    if username.trim().is_empty() || password.is_empty() {
        return Err(crate::errcode::code("fleet.setAccountFirst"));
    }
    let signer = c.signing_key().map_err(|e| e.to_string())?;
    let hpke_seed = c.hpke_seed().map_err(|e| e.to_string())?;
    let client =
        fleet_client::FleetClient::new(&c.server_url, &c.token).map_err(|e| e.to_string())?;
    let device = root_bootstrap::BootstrapDevice {
        login: fleet_client::AccountLogin {
            tenant_id: &c.tenant_id,
            username: username.trim(),
            password: &password,
        },
        device_id: &c.device_id,
        account_id: &c.account_id,
        signer: &signer,
        hpke_seed: &hpke_seed,
        trk_store: &root_bootstrap::CredentialTrkStore,
    };
    root_bootstrap::run(
        &client,
        &device,
        std::path::Path::new(&recovery_path),
        &passphrase,
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
///
/// A fleet grant is read through this device's own session (ADR 0002 D-9), so
/// a fleet with an ACTIVE generation needs the account login; the password is
/// used for one login and never stored.
#[tauri::command]
async fn team_collect_custody(
    username: String,
    password: String,
) -> Result<serde_json::Value, String> {
    let c = team_config::load().map_err(|e| e.to_string())?;
    if !c.can_sync() {
        return Err(crate::errcode::code("fleet.deviceNotEnrolled"));
    }
    let seed = c.hpke_seed().map_err(|e| e.to_string())?;
    let (device_sk, _pk) = shardx_core::grants::derive_keypair(&seed);

    let client =
        fleet_client::FleetClient::new(&c.server_url, &c.token).map_err(|e| e.to_string())?;
    let grants = client
        .root_key_grants(&c.tenant_id, &c.device_id)
        .await
        .map_err(|e| e.to_string())?;

    // A fleet grant is opened only once it verifies: see `custody_report`.
    let fleet = if c.fleet_id.is_empty() {
        FleetGrant::None
    } else {
        collect_fleet_grant(&client, &c, username.trim(), &password, &device_sk).await?
    };

    custody_report(&device_sk, &grants, fleet)
}

/// What became of this device's D-9 `DeviceHpkeGrant` of the fleet's ACTIVE
/// generation: the readback holds at most one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FleetGrant {
    /// No ACTIVE generation, no grant filed, or a revoked one.
    None,
    /// Filed, but this device pins no anchor to verify it against.
    Waiting,
    /// Verified, opened and in the fleet key store, for this generation.
    Opened(u64),
    /// Filed, but the evidence could not be fetched, or the grant did not
    /// verify or open.
    Failed,
    /// Verified and opened, but the store holds another key, or one it
    /// cannot read, for its generation (rule 5, `KEY_SUBSTITUTION_DETECTED`).
    Substituted,
}

/// Reads this device's grant and, when this device pinned an anchor, the
/// tenant trust evidence, and keeps the FKEK only if rule 5 accepts it.
async fn collect_fleet_grant(
    client: &fleet_client::FleetClient,
    c: &team_config::TeamConfig,
    username: &str,
    password: &str,
    device_sk: &[u8],
) -> Result<FleetGrant, String> {
    let Some(generation) = client
        .active_fleet_generation(&c.tenant_id, &c.fleet_id)
        .await
        .map_err(|e| e.to_string())?
    else {
        return Ok(FleetGrant::None);
    };
    if username.is_empty() || password.is_empty() {
        return Err(crate::errcode::code("fleet.setAccountFirst"));
    }
    // An unreadable or newer team database disables this before any key is
    // read (plan L2032).
    let mut ledger = team::db::Db::open().map_err(|e| e.to_string())?;
    let signer = c.signing_key().map_err(|e| e.to_string())?;
    let hpke_seed = c.hpke_seed().map_err(|e| e.to_string())?;
    let login = fleet_client::AccountLogin {
        tenant_id: &c.tenant_id,
        username,
        password,
    };
    let session = client
        .open_device_session(&login, &c.device_id, &signer, &hpke_seed)
        .await
        .map_err(|e| e.to_string())?;
    let access = session.access_token.as_str();
    let grant = match client
        .read_fleet_device_grant(access, &c.fleet_id, generation, &c.device_id)
        .await
    {
        Ok(Some(d)) => live_fleet_grant(&d, &c.fleet_id, generation, &c.device_id),
        Ok(None) => Ok(None),
        Err(e) => Err(e.to_string()),
    };
    let pin = pinned_anchor(c);
    let pages = match (&grant, &pin) {
        (Ok(Some(_)), Some(_)) => Some(client.trust_evidence(access, &c.tenant_id).await),
        _ => None,
    };
    client.end_session(access).await;
    let Some(container) = grant? else {
        return Ok(FleetGrant::None);
    };
    let (Some(pin), Some(pages)) = (pin, pages) else {
        return Ok(FleetGrant::Waiting);
    };
    // Root custody is still reported when only the evidence fetch failed.
    let Ok(pages) = pages else {
        return Ok(FleetGrant::Failed);
    };
    let me = recipient(c).map_err(|e| e.to_string())?;
    let fleet = fleet_client::decode_hex16(&c.fleet_id, "fleet_id").map_err(|e| e.to_string())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    let fkek = open_fleet_grant(
        &container,
        &pages,
        &pin,
        &me,
        &fleet,
        generation,
        device_sk,
        now,
        &mut ledger,
        &c.server_url,
    )?;
    keep_fleet_key(&c.fleet_id, generation, fkek)
}

/// Keeps the FKEK `open_fleet_grant` accepted, unless the store holds
/// another key for its generation. A store that does not parse is an error.
fn keep_fleet_key(
    fleet_id: &str,
    generation: u64,
    fkek: Option<zeroize::Zeroizing<[u8; 32]>>,
) -> Result<FleetGrant, String> {
    let Some(fkek) = fkek else {
        return Ok(FleetGrant::Failed);
    };
    if !fleet_keys::collect(fleet_id, generation, &fkek).map_err(|e| e.to_string())? {
        return Ok(FleetGrant::Substituted);
    }
    Ok(FleetGrant::Opened(generation))
}

/// The binding and anchor `A0` this device pinned: only the device that
/// bootstrapped the tenant's custody has them, and `open_fleet_grant` keeps
/// the first one in the W6 ledger. A joining device pins its own in the join
/// ceremony (ADR 0002 Q-12), which has not shipped.
fn pinned_anchor(
    c: &team_config::TeamConfig,
) -> Option<(shardx_core::trust_chain::Binding, [u8; 32])> {
    let s = root_bootstrap::load().ok()?;
    if !s.activated
        || !s.tenant_id.eq_ignore_ascii_case(&c.tenant_id)
        || !s.device_id.eq_ignore_ascii_case(&c.device_id)
    {
        return None;
    }
    let binding = shardx_core::trust_chain::Binding {
        server_instance_id: fleet_client::decode_hex16(&s.server_instance_id, "server_instance_id")
            .ok()?,
        tenant_id: fleet_client::decode_hex16(&s.tenant_id, "tenant_id").ok()?,
    };
    Some((
        binding,
        fleet_client::decode_hex(&s.anchor)?.try_into().ok()?,
    ))
}

/// ADR 0002 trust chain, rule 5: the FKEK of the `DeviceHpkeGrant` whose
/// exact container is `container`, once the evidence verifies to the pinned
/// anchor and accepts the grant for this device, fleet and generation, opened
/// with this device's HPKE key and checked against `fkek_key_id`. `None`
/// refuses it, and a refused key is wiped on drop.
///
/// The W6 ledger (`team::ledger`) holds the anchor this device pinned first,
/// refuses a generation other than the highest one verified or the next, and evaluates the
/// evidence as this device's history lets it see it: sticky revocations,
/// local distrust, sticky lapse taken from history first (Q-25) and the
/// cached key age. Each evaluation that
/// reaches the anchor is recorded, with the grant it opened (G2-35).
#[allow(clippy::too_many_arguments)]
fn open_fleet_grant(
    container: &[u8],
    pages: &[shardx_core::trust_evidence::TenantTrustEvidencePageV2],
    (binding, anchor): &(shardx_core::trust_chain::Binding, [u8; 32]),
    me: &shardx_core::trust_chain::Recipient,
    fleet_id: &[u8; 16],
    generation: u64,
    device_sk: &[u8],
    now: u64,
    ledger: &mut team::db::Db,
    server_url: &str,
) -> Result<Option<zeroize::Zeroizing<[u8; 32]>>, String> {
    use team::ledger;
    let failed = |e: anyhow::Error| {
        eprintln!("[fleet] trust ledger: {e:#}");
        crate::errcode::code("team.trustLedgerUnreadable")
    };
    // Rotation steps one generation at a time (plan L824, L1642; ADR 0002
    // L1311), so a grant below the highest verified generation, or past the
    // next one, is refused: one stolen key cannot poison the ledger forward.
    let highest = ledger::highest_generation(ledger, binding, fleet_id).map_err(failed)?;
    if !ledger::pin_anchor(ledger, binding, anchor, now).map_err(failed)?
        || highest.is_some_and(|h| generation < h || generation > h.saturating_add(1))
    {
        return Ok(None);
    }
    let Some((seen, chain)) =
        ledger::evaluate(ledger, binding, anchor, pages, now).map_err(failed)?
    else {
        return Ok(None);
    };
    let grant = chain.device_hpke_grant(container, me, fleet_id, generation, now);
    let fkek = grant.and_then(|g| shardx_core::grants::open_device_fkek(device_sk, g).ok());
    let opened = grant.filter(|_| fkek.is_some()).map(|g| ledger::Opened {
        server_url,
        fleet_id,
        generation,
        fkek_key_id: g.fkek_key_id,
        container,
        pages,
    });
    ledger::record(ledger, binding, &seen, &chain, opened, now).map_err(failed)?;
    Ok(fkek)
}

/// This device as a fleet key grant must name it (rule 5).
fn recipient(c: &team_config::TeamConfig) -> anyhow::Result<shardx_core::trust_chain::Recipient> {
    let signer = c.signing_key()?;
    let (_, hpke_public) = shardx_core::grants::derive_keypair(&c.hpke_seed()?);
    Ok(shardx_core::trust_chain::Recipient {
        account_id: fleet_client::decode_hex16(&c.account_id, "account_id")?,
        device_id: fleet_client::decode_hex16(&c.device_id, "device_id")?,
        signing_key_id: shardx_core::keys::signing_key_id(signer.verifying_key().as_bytes()),
        hpke_key_id: shardx_core::keys::hpke_key_id(&hpke_public),
    })
}

/// G2-35 (plan L2056): whether `key`, cached as `generation` of `fleet_id`
/// from a verified grant, may be used at `now`. The cache grants nothing: the
/// exact grant the team database keeps with it is reparsed and reverified
/// against the pages it was accepted from, as the W6 ledger lets this device
/// see them now (the revocation reports, distrust, lapses and key ages
/// learned since, lapses first, Q-25), to the same pinned anchor, for this
/// device, fleet and generation, in force now, and it must name `key`. Its
/// issuer must not be proven revoked or distrusted now, even though the grant
/// was first seen before (Q-26: the one exception to Q-19 (A), for key
/// material only).
///
/// Only the delivering grant's direct issuer is checked, as the ADR words it:
/// a custodian D' that a distrusted or revoked X appointed before that keeps
/// its standing, so grants D' issues stay usable and D' can re-file the same
/// FKEK. The D-6 (a) custodian change events, pending the Q-17 UX review, are
/// what reveal D' to the user.
fn fleet_key_verifies(
    ledger: &team::db::Db,
    (binding, anchor): &(shardx_core::trust_chain::Binding, [u8; 32]),
    me: &shardx_core::trust_chain::Recipient,
    fleet_id: &[u8; 16],
    generation: u64,
    key: &[u8; 32],
    now: u64,
) -> anyhow::Result<bool> {
    use team::ledger;
    let Some((container, pages)) =
        ledger::fleet_key_grant(ledger, binding, anchor, fleet_id, generation)?
    else {
        return Ok(false);
    };
    let Ok(record) = shardx_core::authz_record::AuthorizationRecord::parse(&container) else {
        return Ok(false);
    };
    // Plan L2032: the kept record reloads with every column equal to the
    // exact bytes, or the key is refused.
    let kept = team::records::load(
        &ledger.conn,
        team::records::SIGNED,
        record.signed_container_hash(),
    );
    if kept.ok().as_deref() != Some(container.as_slice()) {
        return Ok(false);
    }
    if ledger::withdrawn(ledger, binding, record.issuer_signing_key_id())? {
        return Ok(false);
    }
    let Some((_, chain)) = ledger::evaluate(ledger, binding, anchor, &pages, now)? else {
        return Ok(false);
    };
    Ok(chain
        .device_hpke_grant(&container, me, fleet_id, generation, now)
        .is_some_and(|g| g.fkek_key_id == shardx_core::fleet_grants::fkek_key_id(key)))
}

/// Whether the ledger keeps the grant of `generation` of `fleet_id` but no
/// signed authorization record for it: a fleet key collected under schema
/// version 3, which kept none. No sync collects it again; only collecting the
/// fleet key in Settings (`team_collect_custody`) does.
fn fleet_key_needs_recollect(
    ledger: &team::db::Db,
    (binding, anchor): &(shardx_core::trust_chain::Binding, [u8; 32]),
    fleet_id: &[u8; 16],
    generation: u64,
) -> bool {
    let Ok(Some((container, _))) =
        team::ledger::fleet_key_grant(ledger, binding, anchor, fleet_id, generation)
    else {
        return false;
    };
    let Ok(record) = shardx_core::authz_record::AuthorizationRecord::parse(&container) else {
        return false;
    };
    let kept = ledger.conn.query_row(
        "SELECT count(*) FROM signed_authorization_records WHERE signed_container_hash = ?1",
        [&record.signed_container_hash()[..]],
        |r| r.get::<_, i64>(0),
    );
    matches!(kept, Ok(0))
}

/// Whether sync pull may use `key`, collected as `generation` of this
/// device's fleet from a verified grant: only while `fleet_key_verifies`
/// passes at `now`, against the anchor this device pinned. Anything
/// unreadable refuses the key and leaves the passphrase.
fn fleet_key_usable(
    c: &team_config::TeamConfig,
    generation: u64,
    key: &[u8; 32],
    now: u64,
) -> bool {
    let Some(pin) = pinned_anchor(c) else {
        return false;
    };
    let verifies = || {
        let ledger = team::db::Db::open()?;
        let fleet = fleet_client::decode_hex16(&c.fleet_id, "fleet_id")?;
        fleet_key_verifies(&ledger, &pin, &recipient(c)?, &fleet, generation, key, now)
    };
    verifies().unwrap_or_else(|e| {
        eprintln!("[fleet] trust ledger: {e:#}");
        false
    })
}

/// The exact grant container of the descriptor when it is an unrevoked
/// `DeviceHpkeGrant` of exactly this fleet, generation and device, `None`
/// when it is revoked. A descriptor naming anything else is a bad reply.
/// Nothing here is trusted: the container is verified against the trust
/// evidence (`open_fleet_grant`).
fn live_fleet_grant(
    descriptor: &[u8],
    fleet_id: &str,
    generation: u64,
    device_id: &str,
) -> Result<Option<Vec<u8>>, String> {
    use shardx_core::canonical::{decode, Value};
    let bad = || crate::errcode::code("fleet.badReplyTeamKeys");
    let Ok(Value::Map(fields)) = decode(descriptor) else {
        return Err(bad());
    };
    let field = |name: &str| fields.iter().find(|(k, _)| k == name).map(|(_, v)| v);
    let text = |name: &str| match field(name) {
        Some(Value::Text(t)) => Some(t.as_str()),
        _ => None,
    };
    let names = |name: &str, want: &str| matches!(field(name), Some(Value::Bytes(b)) if fleet_client::hex(b) == want);
    if text("domain") != Some(shardx_core::mutation::DOMAIN_FLEET_DEVICE_GRANT_DESCRIPTOR)
        || text("payload_domain")
            != Some(shardx_core::authz_record::DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE)
        || !names("fleet_id", &fleet_id.to_ascii_lowercase())
        || !names("subject_device_id", &device_id.to_ascii_lowercase())
        || !matches!(field("generation"), Some(Value::Uint(g)) if *g == generation)
    {
        return Err(bad());
    }
    let live = match text("grant_state") {
        Some("PENDING_ACK" | "ACKNOWLEDGED") => true,
        Some("REVOKED") => false,
        _ => return Err(bad()),
    };
    match field("exact_signed_container_bytes") {
        Some(Value::Bytes(container)) => Ok(live.then(|| container.clone())),
        _ => Err(bad()),
    }
}

/// Open the root key grants and report counts.
///
/// The team server delivers the fleet key grant, so a hostile server could
/// seal a key of its own choosing to this device. Its FKEK reaches the fleet
/// key store only once the grant verifies against the trust chain rooted at
/// the anchor this device pinned (`open_fleet_grant`); a device that pinned
/// none reports it in `fleet_grants_waiting`, as does a grant that failed.
/// Push still seals under the team passphrase, so the report never claims
/// sync without it.
fn custody_report(
    device_sk: &[u8],
    grants: &[fleet_client::RootKeyGrant],
    fleet: FleetGrant,
) -> Result<serde_json::Value, String> {
    let mut opened = 0usize;
    let mut failed = 0usize;
    let mut newest_generation: Option<i64> = None;
    for g in grants {
        let info = hex_bytes(&g.hpke_info_hex)?;
        let encapped = hex_bytes(&g.hpke_encapped_key_hex)?;
        let wrapped = hex_bytes(&g.hpke_wrapped_trk_hex)?;
        match shardx_core::grants::open_trk_with_info(device_sk, &info, &encapped, &wrapped) {
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

    let (fleet_opened, fleet_failed, newest_fleet_generation) = match fleet {
        FleetGrant::Opened(g) => (1, 0, Some(g)),
        FleetGrant::Failed | FleetGrant::Substituted => (0, 1, None),
        FleetGrant::None | FleetGrant::Waiting => (0, 0, None),
    };
    let fleet_grants_waiting = usize::from(matches!(
        fleet,
        FleetGrant::Waiting | FleetGrant::Failed | FleetGrant::Substituted
    ));
    let fleet_refusal = (fleet == FleetGrant::Substituted).then_some("KEY_SUBSTITUTION_DETECTED");
    Ok(serde_json::json!({
        "grants": grants.len(),
        "opened": opened,
        "failed": failed,
        "newest_generation": newest_generation,
        "fleet_opened": fleet_opened,
        "fleet_failed": fleet_failed,
        "newest_fleet_generation": newest_fleet_generation,
        "fleet_grants_waiting": fleet_grants_waiting,
        "fleet_refusal": fleet_refusal,
        "can_sync_without_passphrase": false,
    }))
}

/// Decode a hex string from the server into bytes.
fn hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err(crate::errcode::code("fleet.malformedHexFromServer"));
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
/// Bring the main window back from the tray / minimized state and focus it.
/// Refuse a real exit while a browser this launcher started is still open
/// (CarterLeeAlt 031fdee): quitting would orphan its proxy relay and leave the
/// profile looking idle to the next start. The backend tracker decides, not the
/// window's two-second poll. Shows the window and tells it why.
fn block_exit_if_browsers_running(app: &tauri::AppHandle) -> bool {
    use tauri::Emitter;
    let running_count = process::Tracker::shared().running().len();
    if running_count == 0 {
        return false;
    }
    show_main_window(app);
    let _ = app.emit(
        "launcher:exit-blocked",
        serde_json::json!({ "running_count": running_count }),
    );
    true
}

/// Ends the run before it writes anything. The interface is not up yet, so
/// the operator reads the English sentence of the code in a system dialog.
fn refuse_to_start(code: &str) -> ! {
    let message = crate::errcode::resolve_to_english(code);
    eprintln!("[launcher] refusing to start: {message}");
    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};
        let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
        let (text, title) = (wide(&message), wide("ShardX Launcher"));
        // SAFETY: both strings are NUL-terminated and outlive the call.
        unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                text.as_ptr(),
                title.as_ptr(),
                MB_OK | MB_ICONERROR,
            )
        };
    }
    std::process::exit(1)
}

fn show_main_window(app: &tauri::AppHandle) {
    use tauri::Manager;
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

#[cfg(test)]
mod custody_tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// A fleet grant this device cannot verify is only counted: the server
    /// delivered it, and nothing proves who issued it.
    #[test]
    fn a_server_delivered_fleet_key_is_counted_but_never_cached() {
        let _config = store::config_root_test_lock()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().unwrap();
        store::set_config_root(Some(dir.path().to_path_buf()));

        let (device_sk, _) = shardx_core::grants::derive_keypair(&[7u8; 32]);
        let report = custody_report(&device_sk, &[], FleetGrant::Waiting).unwrap();
        let cached = store::fleet_keys_path().unwrap().exists();
        store::set_config_root(None);

        assert!(!cached, "the fleet key store must not be written");
        assert_eq!(report["fleet_opened"], 0);
        assert_eq!(report["fleet_grants_waiting"], 1);
        assert_eq!(report["can_sync_without_passphrase"], false);

        let report = |fleet| custody_report(&device_sk, &[], fleet).unwrap();
        let opened = report(FleetGrant::Opened(3));
        assert_eq!(opened["fleet_opened"], 1);
        assert_eq!(opened["newest_fleet_generation"], 3);
        assert_eq!(opened["fleet_grants_waiting"], 0);
        assert_eq!(opened["can_sync_without_passphrase"], false);
        let failed = report(FleetGrant::Failed);
        assert_eq!(failed["fleet_failed"], 1);
        assert_eq!(failed["fleet_opened"], 0);
        assert_eq!(failed["fleet_grants_waiting"], 1, "not accepted");
        assert_eq!(failed["fleet_refusal"], serde_json::Value::Null);
        let substituted = report(FleetGrant::Substituted);
        assert_eq!(substituted["fleet_failed"], 1);
        assert_eq!(substituted["fleet_grants_waiting"], 1);
        assert_eq!(substituted["fleet_refusal"], "KEY_SUBSTITUTION_DETECTED");
        assert_eq!(report(FleetGrant::None)["fleet_grants_waiting"], 0);
    }

    const T0: u64 = 1_800_000_000_000;
    const DAY: u64 = 86_400_000;
    const TENANT: [u8; 16] = [2; 16];
    const INSTANCE: [u8; 16] = [3; 16];
    const FLEET: [u8; 16] = [4; 16];

    /// The tenant's bootstrap device, which is this device: its signing key,
    /// HPKE key pair and the identity a grant must name.
    struct Me {
        sk: shardx_core::signing::Ed25519SigningKey,
        hpke_sk: zeroize::Zeroizing<Vec<u8>>,
        hpke_pk: Vec<u8>,
        to: shardx_core::trust_chain::Recipient,
    }

    fn me() -> Me {
        let sk = shardx_core::signing::Ed25519SigningKey::from_bytes(&[1; 32]);
        let (hpke_sk, hpke_pk) = shardx_core::grants::derive_keypair(&[7; 32]);
        let to = shardx_core::trust_chain::Recipient {
            account_id: [6; 16],
            device_id: [5; 16],
            signing_key_id: shardx_core::keys::signing_key_id(sk.verifying_key().as_bytes()),
            hpke_key_id: shardx_core::keys::hpke_key_id(&hpke_pk),
        };
        Me {
            sk,
            hpke_sk,
            hpke_pk,
            to,
        }
    }

    fn common(replay: u8) -> shardx_core::authz_record::CommonFields {
        shardx_core::authz_record::CommonFields {
            replay_id: [replay; 16],
            tenant_id: TENANT,
            issued_at_ms: T0,
            not_before_ms: T0,
            not_after_ms: T0 + 300 * DAY,
            server_instance_id: INSTANCE,
            restore_epoch: 0,
        }
    }

    /// This device's grant of `FLEET` generation 1, naming `fkek_key_id` and
    /// sealing `fkek` to its HPKE key.
    fn fleet_grant(me: &Me, fkek_key_id: [u8; 32], fkek: &[u8; 32]) -> Vec<u8> {
        grant_by(&me.sk, me, 1, 40, fkek_key_id, fkek)
    }

    /// `issuer`'s grant to this device of `FLEET` `generation`.
    fn grant_by(
        issuer: &shardx_core::signing::Ed25519SigningKey,
        me: &Me,
        generation: u64,
        replay: u8,
        fkek_key_id: [u8; 32],
        fkek: &[u8; 32],
    ) -> Vec<u8> {
        grant_at(issuer, me, generation, common(replay), fkek_key_id, fkek)
    }

    /// `grant_by` with the common fields `common`.
    fn grant_at(
        issuer: &shardx_core::signing::Ed25519SigningKey,
        me: &Me,
        generation: u64,
        common: shardx_core::authz_record::CommonFields,
        fkek_key_id: [u8; 32],
        fkek: &[u8; 32],
    ) -> Vec<u8> {
        use shardx_core::authz_record::*;
        let mut g = DeviceHpkeGrantV2 {
            common,
            fleet_id: FLEET,
            fkek_key_id,
            generation,
            subject_account_id: me.to.account_id,
            subject_device_id: me.to.device_id,
            subject_signing_key_id: me.to.signing_key_id,
            recipient_hpke_key_id: me.to.hpke_key_id,
            hpke_encapped_key_bytes: Vec::new(),
            hpke_wrapped_fleet_key_bytes: Vec::new(),
        };
        shardx_core::grants::seal_device_fkek(&me.hpke_pk, &mut g, fkek).unwrap();
        build_record(issuer, DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE, &g.encode())
    }

    /// The trust evidence of a tenant this device bootstrapped: its D1
    /// approval, its first root self-grant, its own `fleet.manage`, and
    /// `grant`.
    fn evidence(
        me: &Me,
        grant: Vec<u8>,
    ) -> Vec<shardx_core::trust_evidence::TenantTrustEvidencePageV2> {
        use shardx_core::authz_record::*;
        let approval = DeviceApprovalV2 {
            common: common(10),
            subject_account_id: me.to.account_id,
            subject_device_id: me.to.device_id,
            subject_signing_key_id: me.to.signing_key_id,
            subject_hpke_key_id: me.to.hpke_key_id,
            approval_scope_kind: ApprovalScopeKind::Tenant,
            approval_scope_id: TENANT,
        };
        let root = TenantRootKeyGrantV2 {
            common: common(11),
            variant: RootGrantVariant::FirstRootSelfGrant,
            root_key_id: [8; 32],
            root_generation: 0,
            subject_account_id: me.to.account_id,
            subject_device_id: me.to.device_id,
            subject_signing_key_id: me.to.signing_key_id,
            recipient_hpke_key_id: me.to.hpke_key_id,
            subject_device_approval_replay_id: [10; 16],
            hpke_encapped_key_bytes: [3; 32],
            hpke_wrapped_trk_bytes: [4; 48],
        };
        let fleet_manage = TenantCapabilityGrantV2 {
            common: common(12),
            subject: GrantSubject::Device {
                account_id: me.to.account_id,
                device_id: me.to.device_id,
                signing_key_id: me.to.signing_key_id,
                hpke_key_id: me.to.hpke_key_id,
            },
            scope_kind: CapabilityScopeKind::Tenant,
            scope_id: TENANT,
            capability: Capability::FleetManage,
        };
        vec![shardx_core::trust_evidence::TenantTrustEvidencePageV2 {
            server_instance_id: INSTANCE,
            tenant_id: TENANT,
            server_now_ms: T0,
            page_index: 0,
            next_cursor: Vec::new(),
            signing_public_keys: vec![me.sk.verifying_key().to_bytes()],
            containers: vec![
                build_record(&me.sk, DOMAIN_DEVICE_APPROVAL, &approval.encode()),
                build_record(&me.sk, DOMAIN_TENANT_ROOT_KEY_GRANT, &root.encode()),
                build_record(
                    &me.sk,
                    DOMAIN_TENANT_CAPABILITY_GRANT,
                    &fleet_manage.encode(),
                ),
                grant,
            ],
            revocations: Vec::new(),
            device_revocations: Vec::new(),
        }]
    }

    /// The FKEK opens only from a grant the trust chain rooted at the pinned
    /// anchor accepts for this device, fleet and generation, and only when it
    /// hashes to the grant's `fkek_key_id`.
    #[test]
    fn a_verified_fleet_grant_opens_and_nothing_else_does() {
        let me = me();
        let fkek = [0x5a; 32];
        let grant = fleet_grant(&me, shardx_core::fleet_grants::fkek_key_id(&fkek), &fkek);
        let pages = evidence(&me, grant.clone());
        let binding = shardx_core::trust_chain::Binding {
            server_instance_id: INSTANCE,
            tenant_id: TENANT,
        };
        let pin = (binding, me.to.signing_key_id);
        let now = T0 + DAY;
        type Pages = [shardx_core::trust_evidence::TenantTrustEvidencePageV2];
        type Pin = (shardx_core::trust_chain::Binding, [u8; 32]);
        type To = shardx_core::trust_chain::Recipient;
        // Each attempt on a device without history.
        let open = |container: &[u8], pages: &Pages, pin: &Pin, to: &To, generation, sk: &[u8]| {
            let dir = tempfile::tempdir().unwrap();
            let mut ledger = team::db::Db::open_at(&dir.path().join("t.db")).unwrap();
            open_fleet_grant(
                container,
                pages,
                pin,
                to,
                &FLEET,
                generation,
                sk,
                now,
                &mut ledger,
                "https://fleet.test",
            )
            .unwrap()
        };
        assert_eq!(
            open(&grant, &pages, &pin, &me.to, 1, &me.hpke_sk).as_deref(),
            Some(&fkek)
        );
        // Another anchor, tenant or instance than the pinned one.
        for pin in [
            (binding, [9; 32]),
            (
                shardx_core::trust_chain::Binding {
                    tenant_id: [9; 16],
                    ..binding
                },
                me.to.signing_key_id,
            ),
            (
                shardx_core::trust_chain::Binding {
                    server_instance_id: [9; 16],
                    ..binding
                },
                me.to.signing_key_id,
            ),
        ] {
            assert!(open(&grant, &pages, &pin, &me.to, 1, &me.hpke_sk).is_none());
        }
        // Another generation, or a grant the chain does not accept for this
        // device.
        assert!(open(&grant, &pages, &pin, &me.to, 2, &me.hpke_sk).is_none());
        let other = shardx_core::trust_chain::Recipient {
            device_id: [9; 16],
            ..me.to
        };
        assert!(open(&grant, &pages, &pin, &other, 1, &me.hpke_sk).is_none());
        // A grant the evidence does not hold.
        assert!(open(
            &grant,
            &evidence(&me, Vec::new()),
            &pin,
            &me.to,
            1,
            &me.hpke_sk
        )
        .is_none());
        // Another HPKE key.
        let (other_sk, _) = shardx_core::grants::derive_keypair(&[8; 32]);
        assert!(open(&grant, &pages, &pin, &me.to, 1, &other_sk).is_none());
        // A verified grant whose sealed key is not the one it names.
        let lying = fleet_grant(&me, shardx_core::fleet_grants::fkek_key_id(&[1; 32]), &fkek);
        let pages = evidence(&me, lying.clone());
        assert!(open(&lying, &pages, &pin, &me.to, 1, &me.hpke_sk).is_none());
        // A grant that did not open raises no generation and is not kept.
        let (_dir, path) = ledger_at();
        assert_eq!(collect(&path, &pages, &lying, 1), None);
        let db = team::db::Db::open_at(&path).unwrap();
        let highest = team::ledger::highest_generation(&db, &binding, &FLEET).unwrap();
        let kept = team::ledger::fleet_key_grant(&db, &binding, &pin.1, &FLEET, 1).unwrap();
        assert_eq!((highest, kept.is_none()), (None, true));
    }

    /// A collected key is pinned for its generation: the same key again is
    /// fine, another one is refused and leaves the store as it was.
    #[test]
    fn a_collected_fleet_key_is_never_replaced() {
        let _config = store::config_root_test_lock()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().unwrap();
        store::set_config_root(Some(dir.path().to_path_buf()));
        let fleet = hex(&FLEET);
        assert!(fleet_keys::collect(&fleet, 1, &[0x5a; 32]).unwrap());
        assert!(fleet_keys::collect(&fleet, 1, &[0x5a; 32]).unwrap());
        assert!(!fleet_keys::collect(&fleet, 1, &[0x5b; 32]).unwrap());
        assert!(fleet_keys::collect(&fleet, 2, &[0x5b; 32]).unwrap());
        assert!(!fleet_keys::collect(&fleet, 2, &[0x5a; 32]).unwrap());
        let held = fleet_keys::load().unwrap();
        // An entry whose key cannot be read is held all the same.
        let mut keys = fleet_keys::load().unwrap();
        keys.fleets
            .get_mut(&fleet)
            .unwrap()
            .keys
            .insert(3, "zz".to_string().into());
        fleet_keys::save(&keys).unwrap();
        let unreadable = fleet_keys::collect(&fleet, 3, &[0x5c; 32]).unwrap();
        let kept = [
            keep_fleet_key(&fleet, 4, Some(zeroize::Zeroizing::new([0x5d; 32]))),
            keep_fleet_key(&fleet, 4, Some(zeroize::Zeroizing::new([0x5e; 32]))),
            keep_fleet_key(&fleet, 5, None),
        ];
        store::set_config_root(None);
        assert_eq!(
            kept,
            [
                Ok(FleetGrant::Opened(4)),
                Ok(FleetGrant::Substituted),
                Ok(FleetGrant::Failed)
            ]
        );
        // Marked as from a verified grant, so pull uses them only reverified.
        assert_eq!(held.fleets[&fleet].verified, [1, 2].into());
        assert!(held.keys_newest_first(&fleet, |_, _| false).is_empty());
        assert_eq!(held.keys_newest_first(&fleet, |g, _| g == 2).len(), 1);
        assert!(!unreadable);
    }

    type Page = shardx_core::trust_evidence::TenantTrustEvidencePageV2;
    const BINDING: shardx_core::trust_chain::Binding = shardx_core::trust_chain::Binding {
        server_instance_id: INSTANCE,
        tenant_id: TENANT,
    };
    const D_DEVICE: [u8; 16] = [12; 16];

    /// Custodian D, whom this device appoints.
    fn d_key() -> shardx_core::signing::Ed25519SigningKey {
        shardx_core::signing::Ed25519SigningKey::from_bytes(&[2; 32])
    }

    fn d_id() -> [u8; 32] {
        shardx_core::keys::signing_key_id(d_key().verifying_key().as_bytes())
    }

    /// `pages` plus what makes D a custodian holding `fleet.manage`, this
    /// device's `device.approve`, its `device.revoke` until `revoke_until`
    /// unless `None`, and `extra`.
    fn with_d(
        me: &Me,
        mut pages: Vec<Page>,
        revoke_until: Option<u64>,
        extra: Vec<Vec<u8>>,
    ) -> Vec<Page> {
        use shardx_core::authz_record::*;
        let grant = |subject: GrantSubject, capability, c: CommonFields| {
            let g = TenantCapabilityGrantV2 {
                common: c,
                subject,
                scope_kind: CapabilityScopeKind::Tenant,
                scope_id: TENANT,
                capability,
            };
            build_record(&me.sk, DOMAIN_TENANT_CAPABILITY_GRANT, &g.encode())
        };
        let mine = GrantSubject::Device {
            account_id: me.to.account_id,
            device_id: me.to.device_id,
            signing_key_id: me.to.signing_key_id,
            hpke_key_id: me.to.hpke_key_id,
        };
        let d = GrantSubject::Device {
            account_id: [6; 16],
            device_id: D_DEVICE,
            signing_key_id: d_id(),
            hpke_key_id: [13; 32],
        };
        let approval = DeviceApprovalV2 {
            common: common(20),
            subject_account_id: [6; 16],
            subject_device_id: D_DEVICE,
            subject_signing_key_id: d_id(),
            subject_hpke_key_id: [13; 32],
            approval_scope_kind: ApprovalScopeKind::Tenant,
            approval_scope_id: TENANT,
        };
        let root = TenantRootKeyGrantV2 {
            common: common(21),
            variant: RootGrantVariant::ExistingRootGrant,
            root_key_id: [8; 32],
            root_generation: 0,
            subject_account_id: [6; 16],
            subject_device_id: D_DEVICE,
            subject_signing_key_id: d_id(),
            recipient_hpke_key_id: [13; 32],
            subject_device_approval_replay_id: [20; 16],
            hpke_encapped_key_bytes: [3; 32],
            hpke_wrapped_trk_bytes: [4; 48],
        };
        let p = &mut pages[0];
        p.signing_public_keys
            .push(d_key().verifying_key().to_bytes());
        p.containers.extend([
            grant(mine.clone(), Capability::DeviceApprove, common(13)),
            build_record(&me.sk, DOMAIN_DEVICE_APPROVAL, &approval.encode()),
            build_record(&me.sk, DOMAIN_TENANT_ROOT_KEY_GRANT, &root.encode()),
            grant(d, Capability::FleetManage, common(22)),
        ]);
        if let Some(na) = revoke_until {
            let c = CommonFields {
                not_after_ms: na,
                ..common(14)
            };
            p.containers.push(grant(mine, Capability::DeviceRevoke, c));
        }
        p.containers.extend(extra);
        pages
    }

    /// This device's signed revocation of D, with `edit` applied.
    fn revoke_d(me: &Me, edit: fn(&mut shardx_core::authz_record::CommonFields)) -> Vec<u8> {
        use shardx_core::authz_record::*;
        let mut r = DeviceRevocationV2 {
            common: common(30),
            subject_account_id: [6; 16],
            subject_device_id: D_DEVICE,
            subject_signing_key_id: d_id(),
            subject_hpke_key_id: [13; 32],
            reason_code: DeviceRevocationReason::Compromised,
        };
        edit(&mut r.common);
        build_record(&me.sk, DOMAIN_DEVICE_REVOCATION, &r.encode())
    }

    /// One fleet grant collection on the device whose ledger is `path`,
    /// opened afresh, so every call is a reopen.
    fn collect_at(
        path: &std::path::Path,
        pages: &[Page],
        grant: &[u8],
        generation: u64,
        now: u64,
    ) -> Option<[u8; 32]> {
        let me = me();
        let mut ledger = team::db::Db::open_at(path).unwrap();
        let pin = (BINDING, me.to.signing_key_id);
        open_fleet_grant(
            grant,
            pages,
            &pin,
            &me.to,
            &FLEET,
            generation,
            &me.hpke_sk,
            now,
            &mut ledger,
            "https://fleet.test",
        )
        .unwrap()
        .map(|k| *k)
    }

    fn collect(
        path: &std::path::Path,
        pages: &[Page],
        grant: &[u8],
        generation: u64,
    ) -> Option<[u8; 32]> {
        collect_at(path, pages, grant, generation, T0 + DAY)
    }

    fn ledger_at() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("team-sync.db");
        (dir, path)
    }

    fn proven(path: &std::path::Path) -> Vec<(String, String)> {
        let db = team::db::Db::open_at(path).unwrap();
        let mut s = db
            .conn
            .prepare("SELECT signing_key_id, source FROM trust_proven_revocations")
            .unwrap();
        let rows = s.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        rows.collect::<rusqlite::Result<_>>().unwrap()
    }

    /// D-6 (e) across reopens: once this device counts a signed revocation of
    /// custodian D, a grant D signs that it first sees later is refused, even
    /// after the server stops listing the revocation. A device without that
    /// history accepts the same evidence (the D-6 limit), and a grant seen no
    /// later than the counting evaluation keeps its standing ("Order").
    #[test]
    fn a_counted_revocation_outlives_the_server_omitting_it() {
        let me = me();
        let fkek = [0x5a; 32];
        let from_d = grant_by(
            &d_key(),
            &me,
            1,
            41,
            shardx_core::fleet_grants::fkek_key_id(&fkek),
            &fkek,
        );
        let revocation = revoke_d(&me, |_| {});
        let base = || evidence(&me, Vec::new());
        let later = with_d(&me, base(), Some(T0 + 300 * DAY), vec![from_d.clone()]);

        let (_dir, path) = ledger_at();
        let first = with_d(&me, base(), Some(T0 + 300 * DAY), vec![revocation.clone()]);
        assert_eq!(collect(&path, &first, &from_d, 1), None);
        assert_eq!(proven(&path), [(hex(&d_id()), "DEVICE_REVOCATION".into())]);
        assert_eq!(
            collect(&path, &later, &from_d, 1),
            None,
            "first seen after the count"
        );
        assert_eq!(
            collect(&path, &later, &from_d, 1),
            None,
            "and on every later reopen"
        );

        let (_fresh, fresh) = ledger_at();
        assert_eq!(
            collect(&fresh, &later, &from_d, 1),
            Some(fkek),
            "no history"
        );

        let (_early, early) = ledger_at();
        let both = with_d(
            &me,
            base(),
            Some(T0 + 300 * DAY),
            vec![from_d.clone(), revocation.clone()],
        );
        assert_eq!(
            collect(&early, &both, &from_d, 1),
            Some(fkek),
            "same evaluation"
        );
        assert_eq!(
            collect(&early, &later, &from_d, 1),
            Some(fkek),
            "seen before the count"
        );
    }

    /// Rule 6: a revocation of tenant-approved D counts only when its issuer
    /// was a custodian with a tenant-scoped `device.revoke` when it was
    /// issued, is still one when this device first sees it, and it names this
    /// tenant and instance.
    #[test]
    fn a_revocation_counts_only_from_a_custodian_allowed_to_revoke() {
        let me = me();
        let counts = |revoke_from: Option<u64>,
                      edit: fn(&mut shardx_core::authz_record::CommonFields),
                      now: u64| {
            let (_dir, path) = ledger_at();
            let pages = with_d(
                &me,
                evidence(&me, Vec::new()),
                revoke_from,
                vec![revoke_d(&me, edit)],
            );
            collect_at(&path, &pages, &[], 1, now);
            !proven(&path).is_empty()
        };
        let now = T0 + DAY;
        let (until, long) = (Some(T0 + 300 * DAY), Some(T0 + 400 * DAY));
        assert!(counts(until, |_| {}, now));
        assert!(!counts(None, |_| {}, now), "no device.revoke");
        // Still allowed to revoke, but no longer a custodian when issued.
        assert!(counts(long, |_| {}, now));
        let after_custody = |c: &mut shardx_core::authz_record::CommonFields| {
            (c.issued_at_ms, c.not_before_ms) = (T0 + 350 * DAY, T0 + 350 * DAY);
            c.not_after_ms = T0 + 400 * DAY;
        };
        assert!(!counts(long, after_custody, now));
        // No longer a custodian when first seen.
        assert!(!counts(until, |_| {}, T0 + 400 * DAY));
        assert!(!counts(until, |c| c.tenant_id = [9; 16], now));
        assert!(!counts(until, |c| c.server_instance_id = [9; 16], now));
    }

    /// G2-64 B4 (ADR 0002 Q-13 issuer rule, as `v2_device_revoke` accepts
    /// it): a revocation of a member whose every approval names fleet F counts
    /// from a custodian holding `device.revoke` scoped to F, not from one
    /// scoped to another fleet; a member also approved for the tenant needs a
    /// tenant-scoped `device.revoke`.
    #[test]
    fn a_fleet_scoped_device_revoke_counts_for_a_member_of_that_fleet() {
        use shardx_core::authz_record::*;
        let me = me();
        let m_key = [0x6d; 32];
        let mine = GrantSubject::Device {
            account_id: me.to.account_id,
            device_id: me.to.device_id,
            signing_key_id: me.to.signing_key_id,
            hpke_key_id: me.to.hpke_key_id,
        };
        let capability = |capability, scope_kind, scope_id, replay| {
            let g = TenantCapabilityGrantV2 {
                common: common(replay),
                subject: mine.clone(),
                scope_kind,
                scope_id,
                capability,
            };
            build_record(&me.sk, DOMAIN_TENANT_CAPABILITY_GRANT, &g.encode())
        };
        let approval = |kind, scope_id, replay| {
            let a = DeviceApprovalV2 {
                common: common(replay),
                subject_account_id: [6; 16],
                subject_device_id: [0x6e; 16],
                subject_signing_key_id: m_key,
                subject_hpke_key_id: [0x6f; 32],
                approval_scope_kind: kind,
                approval_scope_id: scope_id,
            };
            build_record(&me.sk, DOMAIN_DEVICE_APPROVAL, &a.encode())
        };
        let revocation = DeviceRevocationV2 {
            common: common(30),
            subject_account_id: [6; 16],
            subject_device_id: [0x6e; 16],
            subject_signing_key_id: m_key,
            subject_hpke_key_id: [0x6f; 32],
            reason_code: DeviceRevocationReason::Compromised,
        };
        let revocation = build_record(&me.sk, DOMAIN_DEVICE_REVOCATION, &revocation.encode());
        let other_fleet = [0x0f; 16];
        let counts = |revoke_scope: (CapabilityScopeKind, [u8; 16]), tenant_approved: bool| {
            let mut pages = evidence(&me, Vec::new());
            let p = &mut pages[0];
            p.containers.extend([
                capability(
                    Capability::DeviceApprove,
                    CapabilityScopeKind::Tenant,
                    TENANT,
                    13,
                ),
                capability(Capability::DeviceRevoke, revoke_scope.0, revoke_scope.1, 14),
                approval(ApprovalScopeKind::Fleet, FLEET, 20),
                revocation.clone(),
            ]);
            if tenant_approved {
                p.containers
                    .push(approval(ApprovalScopeKind::Tenant, TENANT, 21));
            }
            let (_dir, path) = ledger_at();
            collect_at(&path, &pages, &[], 1, T0 + DAY);
            proven(&path) == [(hex(&m_key), "DEVICE_REVOCATION".into())]
        };
        assert!(counts((CapabilityScopeKind::Fleet, FLEET), false));
        assert!(!counts((CapabilityScopeKind::Fleet, other_fleet), false));
        assert!(!counts((CapabilityScopeKind::Fleet, FLEET), true));
        assert!(counts((CapabilityScopeKind::Tenant, TENANT), true));
    }

    /// A server report is kept at its earliest time and reported again after
    /// the server drops it, across reopens.
    #[test]
    fn a_reported_revocation_outlives_the_server_omitting_it() {
        let me = me();
        let fkek = [0x5b; 32];
        let from_d = grant_by(
            &d_key(),
            &me,
            1,
            41,
            shardx_core::fleet_grants::fkek_key_id(&fkek),
            &fkek,
        );
        let later = with_d(
            &me,
            evidence(&me, Vec::new()),
            Some(T0 + 300 * DAY),
            vec![from_d.clone()],
        );
        // D's device, or D's root grant, reported revoked at `at`.
        let reported = |device: bool, at: u64| {
            let mut pages = later.clone();
            if device {
                pages[0]
                    .device_revocations
                    .push(shardx_core::trust_evidence::RevokedDevice {
                        device_id: D_DEVICE,
                        revoked_at_ms: at,
                    });
            } else {
                pages[0]
                    .revocations
                    .push(shardx_core::trust_evidence::RevokedRecord {
                        payload_domain: shardx_core::authz_record::DOMAIN_TENANT_ROOT_KEY_GRANT
                            .into(),
                        replay_id: [21; 16],
                        revoked_at_ms: at,
                    });
            }
            pages
        };

        for device in [true, false] {
            let (_dir, path) = ledger_at();
            assert_eq!(collect(&path, &reported(device, T0), &from_d, 1), None);
            assert_eq!(
                collect(&path, &reported(device, T0 + 9 * DAY), &from_d, 1),
                None,
                "never later"
            );
            assert_eq!(
                collect(&path, &later, &from_d, 1),
                None,
                "after the server drops it"
            );
            let (_fresh, fresh) = ledger_at();
            assert_eq!(collect(&fresh, &later, &from_d, 1), Some(fkek));
            let never = reported(device, u64::MAX);
            assert_eq!(collect(&fresh, &never, &from_d, 1), Some(fkek));
        }
    }

    /// The highest verified generation of a fleet never goes back or jumps,
    /// across reopens, and only a grant that opened raises it.
    #[test]
    fn a_fleet_generation_never_goes_back() {
        let me = me();
        let key = |n: u8| [n; 32];
        let grant = |generation: u64| {
            let k = key(generation as u8);
            grant_by(
                &me.sk,
                &me,
                generation,
                40 + generation as u8,
                shardx_core::fleet_grants::fkek_key_id(&k),
                &k,
            )
        };
        // Sealing is randomised: build each grant once.
        let (one, two, three) = (grant(1), grant(2), grant(3));
        let mut pages = evidence(&me, one.clone());
        pages[0].containers.push(two.clone());
        let (_dir, path) = ledger_at();
        assert_eq!(
            collect(&path, &pages, &three, 3),
            None,
            "not in the evidence"
        );
        assert_eq!(collect(&path, &pages, &two, 2), Some(key(2)));
        assert_eq!(
            collect(&path, &pages, &two, 2),
            Some(key(2)),
            "the same again"
        );
        assert_eq!(collect(&path, &pages, &one, 1), None, "lower than verified");
        let (_fresh, fresh) = ledger_at();
        assert_eq!(collect(&fresh, &pages, &one, 1), Some(key(1)));
        // Rotation steps by one: a jump past the next generation is refused
        // and leaves the next one collectable.
        pages[0].containers.push(three.clone());
        assert_eq!(collect(&fresh, &pages, &three, 3), None, "a jump");
        assert_eq!(collect(&fresh, &pages, &two, 2), Some(key(2)));
        assert_eq!(collect(&fresh, &pages, &three, 3), Some(key(3)));
    }

    /// D-6 (d): a distrusted key's records first seen after the distrust are
    /// ignored, and a key distrusted with no history is ignored entirely.
    #[test]
    fn local_distrust_ignores_what_is_first_seen_after_it() {
        let me = me();
        let fkek = [0x5c; 32];
        let kid = shardx_core::fleet_grants::fkek_key_id(&fkek);
        let from_d = grant_by(&d_key(), &me, 1, 41, kid, &fkek);
        let newer = grant_by(&d_key(), &me, 2, 42, kid, &fkek);
        let pages = with_d(
            &me,
            evidence(&me, Vec::new()),
            Some(T0 + 300 * DAY),
            vec![from_d.clone(), newer.clone()],
        );
        let distrust = |path: &std::path::Path| {
            let db = team::db::Db::open_at(path).unwrap();
            assert!(team::ledger::pin_anchor(&db, &BINDING, &me.to.signing_key_id, T0).unwrap());
            team::ledger::distrust_key(&db, &BINDING, &d_id(), T0).unwrap();
        };

        let (_dir, unseen) = ledger_at();
        distrust(&unseen);
        assert_eq!(
            collect(&unseen, &pages, &from_d, 1),
            None,
            "no history of D"
        );
        assert_eq!(proven(&unseen), [(hex(&d_id()), "LOCAL_DISTRUST".into())]);

        let (_dir2, seen) = ledger_at();
        let only_first = with_d(
            &me,
            evidence(&me, Vec::new()),
            Some(T0 + 300 * DAY),
            vec![from_d.clone()],
        );
        assert_eq!(collect(&seen, &only_first, &from_d, 1), Some(fkek));
        distrust(&seen);
        assert_eq!(
            collect(&seen, &pages, &from_d, 1),
            Some(fkek),
            "seen before"
        );
        assert_eq!(collect(&seen, &pages, &newer, 2), None, "first seen after");
    }

    /// The first anchor pinned for a binding stays: another one is refused
    /// after a reopen.
    #[test]
    fn the_pinned_anchor_never_changes() {
        let (_dir, path) = ledger_at();
        let pin = |anchor: [u8; 32]| {
            let db = team::db::Db::open_at(&path).unwrap();
            team::ledger::pin_anchor(&db, &BINDING, &anchor, T0).unwrap()
        };
        assert!(pin([1; 32]));
        assert!(!pin([9; 32]));
        assert!(pin([1; 32]));
        // A grant that verifies to another anchor than the pinned one.
        let me = me();
        let fkek = [0x5a; 32];
        let grant = fleet_grant(&me, shardx_core::fleet_grants::fkek_key_id(&fkek), &fkek);
        let pages = evidence(&me, grant.clone());
        assert_eq!(collect(&path, &pages, &grant, 1), None);
        let (_fresh, fresh) = ledger_at();
        assert_eq!(collect(&fresh, &pages, &grant, 1), Some(fkek));
    }

    /// The end of the records `custody` builds.
    const LONG: u64 = T0 + 3000 * DAY;

    /// `common(replay)` in force over `[from, until)`, issued at `from`.
    fn lasting(replay: u8, from: u64, until: u64) -> shardx_core::authz_record::CommonFields {
        shardx_core::authz_record::CommonFields {
            issued_at_ms: from,
            not_before_ms: from,
            not_after_ms: until,
            ..common(replay)
        }
    }

    /// `issuer`'s root grant making D a custodian over `[from, until)`.
    fn d_root(
        issuer: &shardx_core::signing::Ed25519SigningKey,
        replay: u8,
        from: u64,
        until: u64,
    ) -> Vec<u8> {
        use shardx_core::authz_record::*;
        let root = TenantRootKeyGrantV2 {
            common: lasting(replay, from, until),
            variant: RootGrantVariant::ExistingRootGrant,
            root_key_id: [8; 32],
            root_generation: 0,
            subject_account_id: [6; 16],
            subject_device_id: D_DEVICE,
            subject_signing_key_id: d_id(),
            recipient_hpke_key_id: [13; 32],
            subject_device_approval_replay_id: [20; 16],
            hpke_encapped_key_bytes: [3; 32],
            hpke_wrapped_trk_bytes: [4; 48],
        };
        build_record(issuer, DOMAIN_TENANT_ROOT_KEY_GRANT, &root.encode())
    }

    /// A tenant this device bootstrapped, its records in force until `LONG`
    /// (so its own custody ends at the 1095-day clip), in which D holds an
    /// approval and `fleet.manage` until `LONG`, custody through `d_roots`,
    /// and `extra`.
    fn custody(me: &Me, d_roots: &[Vec<u8>], extra: &[Vec<u8>]) -> Vec<Page> {
        use shardx_core::authz_record::*;
        let mine = GrantSubject::Device {
            account_id: me.to.account_id,
            device_id: me.to.device_id,
            signing_key_id: me.to.signing_key_id,
            hpke_key_id: me.to.hpke_key_id,
        };
        let d = GrantSubject::Device {
            account_id: [6; 16],
            device_id: D_DEVICE,
            signing_key_id: d_id(),
            hpke_key_id: [13; 32],
        };
        let grant = |subject: GrantSubject, capability, replay| {
            let g = TenantCapabilityGrantV2 {
                common: lasting(replay, T0, LONG),
                subject,
                scope_kind: CapabilityScopeKind::Tenant,
                scope_id: TENANT,
                capability,
            };
            build_record(&me.sk, DOMAIN_TENANT_CAPABILITY_GRANT, &g.encode())
        };
        let approval = |replay, account, device, signing, hpke| {
            let a = DeviceApprovalV2 {
                common: lasting(replay, T0, LONG),
                subject_account_id: account,
                subject_device_id: device,
                subject_signing_key_id: signing,
                subject_hpke_key_id: hpke,
                approval_scope_kind: ApprovalScopeKind::Tenant,
                approval_scope_id: TENANT,
            };
            build_record(&me.sk, DOMAIN_DEVICE_APPROVAL, &a.encode())
        };
        let root = TenantRootKeyGrantV2 {
            common: lasting(11, T0, LONG),
            variant: RootGrantVariant::FirstRootSelfGrant,
            root_key_id: [8; 32],
            root_generation: 0,
            subject_account_id: me.to.account_id,
            subject_device_id: me.to.device_id,
            subject_signing_key_id: me.to.signing_key_id,
            recipient_hpke_key_id: me.to.hpke_key_id,
            subject_device_approval_replay_id: [10; 16],
            hpke_encapped_key_bytes: [3; 32],
            hpke_wrapped_trk_bytes: [4; 48],
        };
        let mut containers = vec![
            approval(
                10,
                me.to.account_id,
                me.to.device_id,
                me.to.signing_key_id,
                me.to.hpke_key_id,
            ),
            build_record(&me.sk, DOMAIN_TENANT_ROOT_KEY_GRANT, &root.encode()),
            grant(mine.clone(), Capability::FleetManage, 12),
            grant(mine, Capability::DeviceApprove, 13),
            approval(20, [6; 16], D_DEVICE, d_id(), [13; 32]),
            grant(d, Capability::FleetManage, 22),
        ];
        containers.extend(d_roots.iter().chain(extra).cloned());
        let mut pages = evidence(me, Vec::new());
        pages[0].containers = containers;
        pages[0]
            .signing_public_keys
            .push(d_key().verifying_key().to_bytes());
        pages
    }

    /// The custodian keys whose lapse the ledger at `path` observed, and when.
    fn lapsed(path: &std::path::Path) -> Vec<(String, i64)> {
        let db = team::db::Db::open_at(path).unwrap();
        let mut s = db
            .conn
            .prepare(
                "SELECT signing_key_id, observed_lapsed_at_ms FROM trust_custodian_keys
                 WHERE lapsed_evaluation IS NOT NULL",
            )
            .unwrap();
        let rows = s.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        rows.collect::<rusqlite::Result<_>>().unwrap()
    }

    /// D-6 (b) against the attack it exists for: custodian D's custody ends,
    /// this device observes the lapse, then a hostile server serves a fleet
    /// grant with a key of its choosing, signed by D's stolen key and dated
    /// inside D's old window, alone or with a self-extension dated there too.
    /// A device with that history refuses it across reopens; one without
    /// accepts it (the D-6 limit). A re-appointment by another custodian
    /// after the lapse restores D.
    #[test]
    fn a_lapsed_custodians_backdated_grant_is_refused_with_history() {
        let me = me();
        let (stolen, honest) = ([0x66; 32], [0x67; 32]);
        let kid = shardx_core::fleet_grants::fkek_key_id;
        let first = d_root(&me.sk, 21, T0, T0 + 30 * DAY);
        let extension = d_root(&d_key(), 23, T0 + 10 * DAY, LONG);
        let c = lasting(41, T0 + 10 * DAY, LONG);
        let backdated = grant_at(&d_key(), &me, 1, c, kid(&stolen), &stolen);
        let alone = custody(
            &me,
            std::slice::from_ref(&first),
            std::slice::from_ref(&backdated),
        );
        let extended = custody(
            &me,
            &[first.clone(), extension],
            std::slice::from_ref(&backdated),
        );
        let at = T0 + 41 * DAY;
        for pages in [&alone, &extended] {
            let (_fresh, fresh) = ledger_at();
            let got = collect_at(&fresh, pages, &backdated, 1, at);
            assert_eq!(got, Some(stolen), "no history");
        }

        let (_dir, path) = ledger_at();
        let before = custody(&me, std::slice::from_ref(&first), &[]);
        assert_eq!(collect_at(&path, &before, &[], 1, T0 + DAY), None);
        assert!(lapsed(&path).is_empty(), "both are custodians");
        assert_eq!(collect_at(&path, &before, &[], 1, T0 + 40 * DAY), None);
        let observed = (T0 + 40 * DAY) as i64;
        assert_eq!(lapsed(&path), [(hex(&d_id()), observed)]);
        for pages in [&alone, &extended, &alone] {
            let got = collect_at(&path, pages, &backdated, 1, at);
            assert_eq!(got, None, "with history");
        }
        assert_eq!(lapsed(&path), [(hex(&d_id()), observed)], "sticky");

        let again = d_root(&me.sk, 24, T0 + 42 * DAY, LONG);
        let c = lasting(42, T0 + 43 * DAY, LONG);
        let renewed = grant_at(&d_key(), &me, 1, c, kid(&honest), &honest);
        let reappointed = custody(&me, &[first, again], std::slice::from_ref(&renewed));
        let got = collect_at(&path, &reappointed, &renewed, 1, T0 + 44 * DAY);
        assert_eq!(got, Some(honest), "re-appointed after the lapse");
    }

    /// D-6 (c): the clip starts from the earliest root grant of a key this
    /// device ever saw. A server that omits D's first root grant stretches
    /// D's 1095 days on a device without history (the D-6 limit), never on
    /// one that saw it.
    #[test]
    fn an_omitted_first_root_grant_never_stretches_the_key_age_with_history() {
        let me = me();
        let fkek = [0x68; 32];
        let kid = shardx_core::fleet_grants::fkek_key_id(&fkek);
        let first = d_root(&me.sk, 21, T0, T0 + 30 * DAY);
        let later = d_root(&me.sk, 24, T0 + 500 * DAY, LONG);
        let c = lasting(41, T0 + 1100 * DAY, LONG);
        let grant = grant_at(&d_key(), &me, 1, c, kid, &fkek);
        let omitted = custody(
            &me,
            std::slice::from_ref(&later),
            std::slice::from_ref(&grant),
        );
        let full = custody(&me, &[first.clone(), later], std::slice::from_ref(&grant));
        let at = T0 + 1101 * DAY;

        let (_full, full_path) = ledger_at();
        assert_eq!(collect_at(&full_path, &full, &grant, 1, at), None);
        let (_dir, path) = ledger_at();
        let seen_first = custody(&me, std::slice::from_ref(&first), &[]);
        assert_eq!(collect_at(&path, &seen_first, &[], 1, T0 + DAY), None);
        let got = collect_at(&path, &omitted, &grant, 1, at);
        assert_eq!(got, None, "with history");

        let (_fresh, fresh) = ledger_at();
        let got = collect_at(&fresh, &omitted, &grant, 1, at);
        assert_eq!(got, Some(fkek), "no history");
    }

    /// G2-35: a key from a verified grant is used only while the exact grant
    /// kept with it reverifies for this device, fleet, generation, key and
    /// anchor, in force now, as the ledger sees it now. A revocation report
    /// learned since that ends the issuer's custody before the grant ends
    /// its use.
    #[test]
    fn a_kept_grant_is_reverified_before_its_key_is_used() {
        let me = me();
        let fkek = [0x69; 32];
        let kid = shardx_core::fleet_grants::fkek_key_id(&fkek);
        let from_d = grant_by(&d_key(), &me, 1, 41, kid, &fkek);
        // Pages as the server sends them: no empty container.
        let pages = with_d(
            &me,
            evidence(&me, from_d.clone()),
            Some(T0 + 300 * DAY),
            Vec::new(),
        );
        let (_dir, path) = ledger_at();
        let pin = (BINDING, me.to.signing_key_id);
        let now = T0 + 2 * DAY;
        type To = shardx_core::trust_chain::Recipient;
        type Pin = (shardx_core::trust_chain::Binding, [u8; 32]);
        let verifies = |pin: &Pin, generation, key: &[u8; 32], to: &To, now| {
            let db = team::db::Db::open_at(&path).unwrap();
            fleet_key_verifies(&db, pin, to, &FLEET, generation, key, now).unwrap()
        };
        assert!(!verifies(&pin, 1, &fkek, &me.to, now), "nothing kept yet");
        assert_eq!(collect(&path, &pages, &from_d, 1), Some(fkek));
        assert!(verifies(&pin, 1, &fkek, &me.to, now));
        assert!(!verifies(&pin, 1, &[0x6a; 32], &me.to, now), "another key");
        assert!(!verifies(&pin, 2, &fkek, &me.to, now), "another generation");
        let other = To {
            device_id: [9; 16],
            ..me.to
        };
        assert!(!verifies(&pin, 1, &fkek, &other, now), "another device");
        assert!(!verifies(&(BINDING, [9; 32]), 1, &fkek, &me.to, now));
        // A verified grant of another key for the generation never replaces
        // the kept one (rule 5, `KEY_SUBSTITUTION_DETECTED`).
        let swap = [0x6d; 32];
        let swapped = grant_by(
            &d_key(),
            &me,
            1,
            42,
            shardx_core::fleet_grants::fkek_key_id(&swap),
            &swap,
        );
        let mut both = pages.clone();
        both[0].containers.push(swapped.clone());
        assert_eq!(collect(&path, &both, &swapped, 1), Some(swap));
        assert!(
            verifies(&pin, 1, &fkek, &me.to, now),
            "still the kept grant"
        );
        assert!(!verifies(&pin, 1, &swap, &me.to, now));
        // Last: reverifying at a time records the lapses history shows then.
        let ended = T0 + 301 * DAY;
        assert!(!verifies(&pin, 1, &fkek, &me.to, ended), "the grant ended");
        assert!(
            verifies(&pin, 1, &fkek, &me.to, now),
            "seen before the lapses"
        );

        let mut reported = pages.clone();
        reported[0]
            .device_revocations
            .push(shardx_core::trust_evidence::RevokedDevice {
                device_id: D_DEVICE,
                revoked_at_ms: T0,
            });
        assert_eq!(collect(&path, &reported, &[], 1), None);
        assert!(!verifies(&pin, 1, &fkek, &me.to, now), "reported since");
    }

    /// G2-35 (plan L2032): collecting a grant also keeps it as a signed
    /// authorization record, and its key is used only while that record
    /// reloads with every column equal to its bytes and the same bytes as
    /// the ledger's grant; a missing or changed record refuses the key.
    #[test]
    fn a_key_is_used_only_while_its_kept_record_reloads_exactly() {
        let me = me();
        let fkek = [0x71; 32];
        let kid = shardx_core::fleet_grants::fkek_key_id(&fkek);
        let from_d = grant_by(&d_key(), &me, 1, 41, kid, &fkek);
        let pages = with_d(
            &me,
            evidence(&me, from_d.clone()),
            Some(T0 + 300 * DAY),
            Vec::new(),
        );
        let (_dir, path) = ledger_at();
        let pin = (BINDING, me.to.signing_key_id);
        let now = T0 + 2 * DAY;
        assert_eq!(collect(&path, &pages, &from_d, 1), Some(fkek));
        let verifies = || {
            let db = team::db::Db::open_at(&path).unwrap();
            fleet_key_verifies(&db, &pin, &me.to, &FLEET, 1, &fkek, now).unwrap()
        };
        assert!(verifies());
        let db = team::db::Db::open_at(&path).unwrap();
        let kept: Vec<u8> = db
            .conn
            .query_row(
                "SELECT exact_signed_container_bytes FROM signed_authorization_records",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(kept, from_d);
        db.conn
            .execute_batch(
                "PRAGMA ignore_check_constraints = ON;
                 CREATE TABLE saved AS SELECT * FROM signed_authorization_records;",
            )
            .unwrap();
        let pin_now = (BINDING, me.to.signing_key_id);
        assert!(!fleet_key_needs_recollect(&db, &pin_now, &FLEET, 1));
        // A fixture bypassing the keys that hold the record.
        db.conn.pragma_update(None, "foreign_keys", false).unwrap();
        for (sql, undo) in [
            (
                "UPDATE signed_authorization_records SET generation = 2",
                "UPDATE signed_authorization_records SET generation = 1",
            ),
            (
                "UPDATE signed_authorization_records SET revoked_at_ms = 0",
                "UPDATE signed_authorization_records SET revoked_at_ms = NULL",
            ),
            (
                "DELETE FROM signed_authorization_records",
                "INSERT INTO signed_authorization_records SELECT * FROM saved",
            ),
        ] {
            db.conn.execute_batch(sql).unwrap();
            assert!(!verifies(), "{sql}");
            // Only a missing record asks for the key to be collected again.
            let missing = sql.starts_with("DELETE");
            assert_eq!(
                fleet_key_needs_recollect(&db, &pin_now, &FLEET, 1),
                missing,
                "{sql}"
            );
            db.conn.execute_batch(undo).unwrap();
            assert!(verifies(), "{undo}");
        }
    }

    /// Q-25 against the D-6 (b) attack with no evaluation between the end of
    /// D's custody and the attack: the lapse is taken from history before the
    /// evidence is accepted, so D's backdated grant is refused, alone or after
    /// a self-extension, and D lapses at that evaluation. The cost: a valid
    /// renewal by another custodian that this device first sees after D's
    /// window ended is refused like a forged one, while a device that saw it
    /// in time keeps D; only a re-appointment dated after the lapse restores
    /// D.
    #[test]
    fn a_lapse_from_history_refuses_a_backdated_grant_with_no_evaluation_between() {
        let me = me();
        let (stolen, honest) = ([0x66; 32], [0x67; 32]);
        let kid = shardx_core::fleet_grants::fkek_key_id;
        let first = d_root(&me.sk, 21, T0, T0 + 30 * DAY);
        let extension = d_root(&d_key(), 23, T0 + 10 * DAY, LONG);
        let c = lasting(41, T0 + 10 * DAY, LONG);
        let backdated = grant_at(&d_key(), &me, 1, c, kid(&stolen), &stolen);
        let alone = custody(
            &me,
            std::slice::from_ref(&first),
            std::slice::from_ref(&backdated),
        );
        let extended = custody(
            &me,
            &[first.clone(), extension],
            std::slice::from_ref(&backdated),
        );
        let before = custody(&me, std::slice::from_ref(&first), &[]);
        let at = T0 + 41 * DAY;
        for pages in [&alone, &extended] {
            let (_ledger, path) = ledger_at();
            assert_eq!(collect_at(&path, &before, &[], 1, T0 + DAY), None);
            let got = collect_at(&path, pages, &backdated, 1, at);
            assert_eq!(got, None, "lapsed from history");
            assert_eq!(lapsed(&path), [(hex(&d_id()), at as i64)]);
        }

        let renewal = d_root(&me.sk, 24, T0 + 25 * DAY, LONG);
        let c = lasting(42, T0 + 35 * DAY, LONG);
        let renewed = grant_at(&d_key(), &me, 1, c, kid(&honest), &honest);
        let late = custody(
            &me,
            &[first.clone(), renewal.clone()],
            std::slice::from_ref(&renewed),
        );
        let (_fresh, fresh) = ledger_at();
        let got = collect_at(&fresh, &late, &renewed, 1, at);
        assert_eq!(got, Some(honest), "a valid renewal");
        let (_timely, timely) = ledger_at();
        assert_eq!(collect_at(&timely, &before, &[], 1, T0 + DAY), None);
        let in_time = custody(&me, &[first.clone(), renewal], &[]);
        assert_eq!(collect_at(&timely, &in_time, &[], 1, T0 + 26 * DAY), None);
        let got = collect_at(&timely, &late, &renewed, 1, at);
        assert_eq!(got, Some(honest), "seen before the window ended");
        let (_dir, path) = ledger_at();
        assert_eq!(collect_at(&path, &before, &[], 1, T0 + DAY), None);
        let got = collect_at(&path, &late, &renewed, 1, at);
        assert_eq!(got, None, "first seen after the window ended");
        let known = (T0 as i64, (T0 + 30 * DAY) as i64);
        assert_eq!(custodian(&path, &d_id()), known, "the renewal never counts");

        let again = d_root(&me.sk, 26, T0 + 42 * DAY, LONG);
        let c = lasting(43, T0 + 43 * DAY, LONG);
        let after = grant_at(&d_key(), &me, 1, c, kid(&honest), &honest);
        let reappointed = custody(&me, &[first, again], std::slice::from_ref(&after));
        let got = collect_at(&path, &reappointed, &after, 1, T0 + 44 * DAY);
        assert_eq!(got, Some(honest), "re-appointed by another custodian");
    }

    /// The documented D-6 no-history limit of Q-25: when the server withheld
    /// D's root grant for all of D's window, this device never counted D, so
    /// the root grant sent later with a grant backdated from D's stolen key
    /// is accepted, D lapses only in that accepting evaluation, and the key
    /// still reverifies for pull.
    #[test]
    fn limit_a_backdated_grant_from_a_never_counted_custodian_is_accepted() {
        let me = me();
        let stolen = [0x71; 32];
        let kid = shardx_core::fleet_grants::fkek_key_id(&stolen);
        let first = d_root(&me.sk, 21, T0, T0 + 30 * DAY);
        let c = lasting(41, T0 + 10 * DAY, LONG);
        let backdated = grant_at(&d_key(), &me, 1, c, kid, &stolen);
        let late = custody(
            &me,
            std::slice::from_ref(&first),
            std::slice::from_ref(&backdated),
        );
        let (_dir, path) = ledger_at();
        let withheld = custody(&me, &[], &[]);
        assert_eq!(collect_at(&path, &withheld, &[], 1, T0 + DAY), None);
        let at = T0 + 41 * DAY;
        assert_eq!(collect_at(&path, &late, &backdated, 1, at), Some(stolen));
        assert_eq!(lapsed(&path), [(hex(&d_id()), at as i64)]);
        let db = team::db::Db::open_at(&path).unwrap();
        let pin = (BINDING, me.to.signing_key_id);
        let used = fleet_key_verifies(&db, &pin, &me.to, &FLEET, 1, &stolen, at + DAY);
        assert!(used.unwrap(), "pull would use it");
    }

    /// Q-25 at use: reverifying a kept key first records the lapse history
    /// shows at that moment, and the grant, first seen before the lapse,
    /// keeps its standing (Q-19 (A)).
    #[test]
    fn reverifying_a_kept_key_records_the_lapse_history_shows() {
        let me = me();
        let fkek = [0x70; 32];
        let kid = shardx_core::fleet_grants::fkek_key_id(&fkek);
        let first = d_root(&me.sk, 21, T0, T0 + 30 * DAY);
        let c = lasting(41, T0 + 3 * DAY, LONG);
        let grant = grant_at(&d_key(), &me, 1, c, kid, &fkek);
        let pages = custody(
            &me,
            std::slice::from_ref(&first),
            std::slice::from_ref(&grant),
        );
        let (_dir, path) = ledger_at();
        let got = collect_at(&path, &pages, &grant, 1, T0 + 5 * DAY);
        assert_eq!(got, Some(fkek));
        assert!(lapsed(&path).is_empty());
        let at = T0 + 41 * DAY;
        let db = team::db::Db::open_at(&path).unwrap();
        let pin = (BINDING, me.to.signing_key_id);
        let used = fleet_key_verifies(&db, &pin, &me.to, &FLEET, 1, &fkek, at).unwrap();
        drop(db);
        assert!(used, "first seen before the lapse");
        assert_eq!(lapsed(&path), [(hex(&d_id()), at as i64)]);
    }

    /// Sync pull uses a key from a verified grant only through
    /// `fleet_key_verifies` at use: a clean one is tried, and once its
    /// issuer is distrusted or proven revoked (rule 6) after collection it is
    /// dropped, though its grant was first seen before (Q-26).
    #[test]
    fn pull_uses_a_verified_key_only_while_its_issuer_stands() {
        let _config = store::config_root_test_lock()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let me = me();
        let fkek = [0x6f; 32];
        let kid = shardx_core::fleet_grants::fkek_key_id(&fkek);
        let from_d = grant_by(&d_key(), &me, 1, 41, kid, &fkek);
        let pages = with_d(
            &me,
            evidence(&me, from_d.clone()),
            Some(T0 + 300 * DAY),
            Vec::new(),
        );
        let revoking = with_d(
            &me,
            evidence(&me, Vec::new()),
            Some(T0 + 300 * DAY),
            vec![revoke_d(&me, |_| {})],
        );
        let c = team_config::TeamConfig {
            tenant_id: hex(&TENANT),
            account_id: hex(&me.to.account_id),
            device_id: hex(&me.to.device_id),
            fleet_id: hex(&FLEET),
            signing_key_seed: hex(&[1; 32]).into(),
            hpke_key_seed: hex(&[7; 32]).into(),
            ..Default::default()
        };
        let now = T0 + 2 * DAY;
        // This device bootstrapped the tenant and collected D's grant, then
        // `after` ran on its ledger.
        let pulled = |after: &dyn Fn(&std::path::Path)| {
            let dir = tempfile::tempdir().unwrap();
            store::set_config_root(Some(dir.path().to_path_buf()));
            let s = root_bootstrap::BootstrapState {
                tenant_id: hex(&TENANT),
                device_id: hex(&me.to.device_id),
                server_instance_id: hex(&INSTANCE),
                activated: true,
                anchor: hex(&me.to.signing_key_id),
                ..Default::default()
            };
            std::fs::write(
                store::custody_bootstrap_path().unwrap(),
                serde_json::to_string(&s).unwrap(),
            )
            .unwrap();
            let path = dir.path().join("team-sync");
            std::fs::create_dir_all(&path).unwrap();
            let path = path.join("team-sync.db");
            let collected = collect(&path, &pages, &from_d, 1);
            let kept = fleet_keys::collect(&hex(&FLEET), 1, &fkek).unwrap();
            after(&path);
            let got = sync_cmd::pull_candidates(&c, now);
            store::set_config_root(None);
            assert_eq!((collected, kept), (Some(fkek), true));
            got
        };
        assert_eq!(pulled(&|_| {}), [(fkek, 1)], "a clean verified key");
        let distrusted = pulled(&|path| {
            let db = team::db::Db::open_at(path).unwrap();
            team::ledger::distrust_key(&db, &BINDING, &d_id(), now).unwrap();
        });
        assert!(distrusted.is_empty(), "distrusted since");
        let revoked = pulled(&|path| {
            assert_eq!(collect(path, &revoking, &[], 1), None);
            assert_eq!(proven(path), [(hex(&d_id()), "DEVICE_REVOCATION".into())]);
        });
        assert!(revoked.is_empty(), "proven revoked since");
    }

    /// The custodian ledger row of `key`: cached first window and known end.
    fn custodian(path: &std::path::Path, key: &[u8; 32]) -> (i64, i64) {
        let db = team::db::Db::open_at(path).unwrap();
        db.conn
            .query_row(
                "SELECT first_not_before_ms, latest_not_after_ms FROM trust_custodian_keys
                 WHERE signing_key_id = ?1",
                [hex(key)],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap()
    }

    /// A server cannot make D's lapse or key age worse for good: leaving out
    /// every root grant of D records no lapse while D's known custody runs,
    /// and a root grant for D from a key with no custody, dated 1094 days
    /// back, is never cached. Each refuses only in its own evaluation; the
    /// next honest one accepts D's grant.
    #[test]
    fn a_server_cannot_lapse_a_custodian_or_age_its_key_for_good() {
        let me = me();
        let fkek = [0x6e; 32];
        let kid = shardx_core::fleet_grants::fkek_key_id(&fkek);
        let first = d_root(&me.sk, 21, T0, T0 + 30 * DAY);
        let c = lasting(41, T0 + 3 * DAY, LONG);
        let grant = grant_at(&d_key(), &me, 1, c, kid, &fkek);
        let junk = shardx_core::signing::Ed25519SigningKey::from_bytes(&[9; 32]);
        let early = T0 + 2 * DAY - shardx_core::trust_chain::MAX_CUSTODIAN_KEY_AGE_MS;
        let forged = d_root(&junk, 25, early, T0 + 5 * DAY);
        let honest = custody(
            &me,
            std::slice::from_ref(&first),
            std::slice::from_ref(&grant),
        );
        let omitted = custody(&me, &[], std::slice::from_ref(&grant));
        let mut aged = custody(&me, std::slice::from_ref(&first), &[grant.clone(), forged]);
        aged[0]
            .signing_public_keys
            .push(junk.verifying_key().to_bytes());

        let (_dir, path) = ledger_at();
        let before = custody(&me, std::slice::from_ref(&first), &[]);
        assert_eq!(collect_at(&path, &before, &[], 1, T0 + DAY), None);
        let at = T0 + 5 * DAY;
        assert_eq!(
            collect_at(&path, &omitted, &grant, 1, at),
            None,
            "no custody"
        );
        assert_eq!(collect_at(&path, &aged, &grant, 1, at), None, "clipped");
        assert!(lapsed(&path).is_empty());
        let known = ((T0) as i64, (T0 + 30 * DAY) as i64);
        assert_eq!(custodian(&path, &d_id()), known);
        assert_eq!(collect_at(&path, &honest, &grant, 1, at), Some(fkek));
    }

    /// A lapse is recorded once D's known custody ends, within the clock
    /// tolerance: at its counted end, or at its key age when that is sooner.
    #[test]
    fn a_lapse_is_the_known_end_of_custody_clipped_at_the_key_age() {
        let me = me();
        let lapses_at = |until: u64, now: u64| {
            let (_dir, path) = ledger_at();
            let pages = custody(&me, &[d_root(&me.sk, 21, T0, until)], &[]);
            assert_eq!(collect_at(&path, &pages, &[], 1, now), None);
            lapsed(&path).contains(&(hex(&d_id()), now as i64))
        };
        let end = T0 + 30 * DAY;
        let tolerance = shardx_core::trust_chain::CLOCK_TOLERANCE_MS;
        assert!(!lapses_at(end, end + tolerance - 1), "within the tolerance");
        assert!(lapses_at(end, end + tolerance));
        let age = T0 + shardx_core::trust_chain::MAX_CUSTODIAN_KEY_AGE_MS;
        assert!(!lapses_at(LONG, age - DAY));
        assert!(lapses_at(LONG, age + tolerance), "at the key age");
    }

    /// Only the device that bootstrapped this tenant's custody, with the
    /// generation active, has an anchor pinned.
    #[test]
    fn only_the_bootstrapped_device_has_a_pinned_anchor() {
        let _config = store::config_root_test_lock()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().unwrap();
        store::set_config_root(Some(dir.path().to_path_buf()));
        let c = team_config::TeamConfig {
            tenant_id: hex(&TENANT),
            device_id: hex(&[5; 16]),
            ..Default::default()
        };
        let pinned = |edit: fn(&mut root_bootstrap::BootstrapState)| {
            let mut s = root_bootstrap::BootstrapState {
                tenant_id: hex(&TENANT).to_uppercase(),
                device_id: hex(&[5; 16]),
                server_instance_id: hex(&INSTANCE),
                activated: true,
                anchor: hex(&[1; 32]),
                ..Default::default()
            };
            edit(&mut s);
            std::fs::write(
                store::custody_bootstrap_path().unwrap(),
                serde_json::to_string(&s).unwrap(),
            )
            .unwrap();
            pinned_anchor(&c)
        };
        let got = pinned(|_| {});
        let none: [fn(&mut root_bootstrap::BootstrapState); 3] = [
            |s| s.activated = false,
            |s| s.tenant_id = hex(&[9; 16]),
            |s| s.device_id = hex(&[9; 16]),
        ];
        let refused: Vec<bool> = none.into_iter().map(|e| pinned(e).is_none()).collect();
        store::set_config_root(None);
        let (binding, anchor) = got.unwrap();
        assert_eq!(
            (binding.tenant_id, binding.server_instance_id),
            (TENANT, INSTANCE)
        );
        assert_eq!(anchor, [1; 32]);
        assert_eq!(refused, [true; 3]);
    }

    /// The D-9 readback counts only an unrevoked grant of exactly this fleet,
    /// generation and device; one naming anything else is a bad reply.
    #[test]
    fn a_fleet_descriptor_counts_only_for_this_device_and_generation() {
        use shardx_core::authz_record::{
            build_record, AuthorizationRecord, CommonFields, DeviceHpkeGrantV2,
            DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE,
        };
        use shardx_core::mutation::{
            FleetDeviceGrantDescriptorV2, RootGenerationState, RootGrantState,
        };

        let sk = shardx_core::signing::Ed25519SigningKey::from_bytes(&[9; 32]);
        let grant = DeviceHpkeGrantV2 {
            common: CommonFields {
                replay_id: [1; 16],
                tenant_id: [2; 16],
                issued_at_ms: 1_700_000_000_000,
                not_before_ms: 1_700_000_000_000,
                not_after_ms: 1_700_086_400_000,
                server_instance_id: [3; 16],
                restore_epoch: 0,
            },
            fleet_id: [4; 16],
            fkek_key_id: [5; 32],
            generation: 1,
            subject_account_id: [6; 16],
            subject_device_id: [7; 16],
            subject_signing_key_id: [8; 32],
            recipient_hpke_key_id: [9; 32],
            hpke_encapped_key_bytes: vec![3; 32],
            hpke_wrapped_fleet_key_bytes: vec![4; 48],
        };
        let container = build_record(&sk, DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE, &grant.encode());
        let descriptor = |state| {
            let record = AuthorizationRecord::parse(&container)
                .unwrap()
                .verify_signature(sk.verifying_key().as_bytes())
                .unwrap();
            FleetDeviceGrantDescriptorV2::new(record, state, RootGenerationState::Active)
                .unwrap()
                .encode()
        };
        let (fleet, device) = (hex(&[4; 16]), hex(&[7; 16]));
        let live = descriptor(RootGrantState::Acknowledged);
        assert_eq!(
            live_fleet_grant(&live, &fleet, 1, &device),
            Ok(Some(container.clone()))
        );
        assert_eq!(
            live_fleet_grant(&live, &fleet.to_uppercase(), 1, &device),
            Ok(Some(container.clone()))
        );
        let revoked = descriptor(RootGrantState::Revoked);
        assert_eq!(live_fleet_grant(&revoked, &fleet, 1, &device), Ok(None));
        for (fleet, generation, device) in [
            (hex(&[0; 16]), 1, device.clone()),
            (fleet.clone(), 2, device.clone()),
            (fleet.clone(), 1, hex(&[0; 16])),
        ] {
            assert!(live_fleet_grant(&live, &fleet, generation, &device).is_err());
        }
        assert!(live_fleet_grant(b"not cbor", &fleet, 1, &device).is_err());
    }
}

#[cfg(test)]
mod profile_mutation_boundary_tests {
    use super::*;

    fn assert_running_blocked<T>(result: Result<T, String>) {
        let error = result.err().expect("running profile mutation must fail");
        // The message now travels as an error code, and the action label
        // inside it as a nested one. Resolve before asserting: the point of
        // the test is that the operator is told to stop the browser and which
        // action was refused, which is only legible after resolution.
        let resolved = crate::errcode::resolve_to_english(&error);
        assert!(
            resolved.contains("Stop the running browser"),
            "expected actionable running-profile error, got: {resolved}"
        );
        assert!(
            !resolved.contains("[[shardx:"),
            "the action label was left unresolved: {resolved}"
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
        assert_running_blocked(profile_set_tags(
            profile_id.to_string(),
            vec!["tag".to_string()],
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
            None,
            None,
        )));
        assert_running_blocked(rt.block_on(sync_cmd::profile_sync_pull(
            profile_id.to_string(),
            "passphrase".to_string(),
            None,
            None,
        )));
        assert_running_blocked(rt.block_on(sync_cmd::profile_sync_publish(
            profile_id.to_string(),
            None,
            None,
            None,
        )));
        assert_running_blocked(rt.block_on(sync_cmd::profile_sync_cancel_publish(
            profile_id.to_string(),
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
                } else if window.label() == "main"
                    && block_exit_if_browsers_running(tauri::Manager::app_handle(window))
                {
                    // Without minimize-to-tray, closing the window quits.
                    api.prevent_close();
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
            team_keys_create_file,
            team_keys_unlock,
            team_collect_custody,
            team_custody_bootstrap_status,
            team_bootstrap_custody,
            team_set_connection,
            team_test_connection,
            team_enroll_device,
            backup_cmd::profile_backup_create,
            sync_cmd::profile_sync_push,
            sync_cmd::profile_sync_publish,
            sync_cmd::profile_sync_cancel_publish,
            sync_cmd::profile_sync_pull,
            sync_cmd::profile_sync_status,
            sync_cmd::team_unbind_profile,
            sync_cmd::team_downgrade_status,
            sync_cmd::team_downgrade_clone,
            sync_cmd::team_downgrade_resume,
            sync_cmd::team_downgrade_rollback,
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
            profile_set_tags,
            tags_list,
            tag_rename,
            tag_recolor,
            tag_delete,
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
            settings_load_error,
            launch_cancel,
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

            // Point the heavy directories wherever the operator moved them,
            // before anything reads a profile.
            if let Ok(s) = settings::load() {
                if let Some(root) = s.data_root.as_deref().filter(|r| !r.is_empty()) {
                    store::set_data_root(Some(std::path::PathBuf::from(root)));
                }
            }

            // Before the first write: state lives on local NTFS only (ADR 0002
            // Q-30, plan L2335).
            if let Err(refusal) = store::require_local_ntfs_roots() {
                refuse_to_start(&refusal.to_string());
            }

            // Devices enrolled before ADR 0004 still hold their seeds in
            // team.json and their fleet keys in fleet_keys.json; move both
            // into the OS credential store.
            protect_all_keys();

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
                    let builder = TrayIconBuilder::with_id("main").icon(icon);
                    // The macOS menu bar wants a stencil drawn from the icon's
                    // shape alone, so it is dark on a light bar and light on a
                    // dark one instead of staying purple (upstream 6c3f65a).
                    #[cfg(target_os = "macos")]
                    let builder = builder.icon_as_template(true);
                    builder
                        .tooltip("ShardX Launcher")
                        .menu(&menu)
                        .show_menu_on_left_click(false)
                        .on_menu_event(|app, e| match e.id.as_ref() {
                            "tray_show" => show_main_window(app),
                            "tray_quit" if !block_exit_if_browsers_running(app) => app.exit(0),
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

            // Trash older than its week.
            match trash::purge_expired() {
                Ok(n) if n > 0 => eprintln!("[launcher] trash: {n} expired profile(s) removed"),
                Ok(_) => {}
                Err(e) => eprintln!("[launcher] trash sweep failed: {e}"),
            }

            // Finish, or undo, a downgrade a crash cut off (plan L2240).
            tauri::async_runtime::spawn_blocking(|| match team::downgrade::resume_open() {
                Ok(resumed) => {
                    for r in resumed.iter().filter(|r| r.error.is_some()) {
                        eprintln!(
                            "[launcher] downgrade {} stays at {}: {}",
                            r.journal_id,
                            r.phase,
                            r.error.as_deref().unwrap_or_default()
                        );
                    }
                }
                Err(e) => eprintln!("[launcher] downgrade resume failed: {e:#}"),
            });

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
