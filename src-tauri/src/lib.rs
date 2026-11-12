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
#[cfg(test)]
mod custodian_it;
pub mod db;
mod dpapi;
mod durable;
pub mod errcode;
mod extensions;
pub mod files;
mod fingerprints;
pub mod fleet_client;
pub mod fleet_custody;
mod fleet_keys;
pub mod gpu_caps;
mod hermes_mcp;
pub mod http_session;
mod key_file;
mod launch;
mod platform_version;
mod profile_icon;
mod recovery_import;
pub mod root_bootstrap;
mod root_rotation;
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
mod open_link;
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

pub(crate) use platform_version::{randomize_platform_version, settle_platform_version};

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
    // A refused purge (a Team binding with pending work) keeps its entry;
    // the rest still go, then the first refusal is reported.
    let mut first = None;
    for e in entries {
        if let Err(err) = trash::purge(&e.id) {
            first.get_or_insert(err.to_string());
        }
    }
    first.map_or(Ok(n), Err)
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
    // The claimed Apple chip bounds the macOS it can report.
    if let Some(webgl) = entry.payload.get("webgl") {
        payload.insert("webgl".into(), webgl.clone());
    }
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
    // G13: the change would wipe the root custodian. Only one whose seeds
    // are both lost may go, its file copied and its credentials kept: a
    // recovery import is its way back. A root state that does not load
    // fails closed, as Enroll again does. A bootstrap with a saved create
    // request counts too: it is saved before it is sent, and the server may
    // have activated the generation before the local flag was saved. A
    // self-grant alone is saved before the create request, so the server
    // has seen no root generation yet (`root_bootstrap.rs` step 2 saves the
    // self-grant, step 4 saves the create request, then sends it).
    let root_custodian = server_changed && {
        let root = root_bootstrap::load().map_err(|e| e.to_string())?;
        (root.activated || !root.create_request.is_empty())
            && root.tenant_id.eq_ignore_ascii_case(&c.tenant_id)
            && root.device_id.eq_ignore_ascii_case(&c.device_id)
    };
    if root_custodian
        && !(c.signing_key().is_err_and(|e| team_config::seed_lost(&e))
            && c.hpke_seed().is_err_and(|e| team_config::seed_lost(&e)))
    {
        return Err(crate::errcode::code("fleet.rootCustodianKeepsConnection"));
    }
    if root_custodian {
        let copy = team_config::preserve_unreadable().map_err(|e| e.to_string())?;
        eprintln!(
            "[recovery] lost root custodian leaves its server; team.json copied to {}",
            copy.display()
        );
    }
    c.server_url = url;
    c.token = token.trim().to_string().into();
    c.tenant_id = tenant_id.trim().to_string();
    let stale_refs = if server_changed {
        fleet_custody::forget_device_acks().map_err(|e| e.to_string())?;
        clear_identity(&mut c)
    } else {
        Default::default()
    };

    team_config::save(&c).map_err(|e| e.to_string())?;
    // The identity is gone from the file; its keys go with it. Best effort:
    // a credential left behind names a device no config refers to.
    for reference in stale_refs
        .iter()
        .filter(|r| !r.is_empty() && !root_custodian)
    {
        let _ = credential::forget(reference);
    }
    team_config::status().map_err(|e| e.to_string())
}

/// Drops this device's id and seeds from `c`, returning the credential
/// references that held its keys.
fn clear_identity(c: &mut team_config::TeamConfig) -> [String; 2] {
    c.device_id.clear();
    c.fleet_id.clear();
    c.signing_key_seed.clear();
    c.hpke_key_seed.clear();
    [
        std::mem::take(&mut c.signing_credential_ref),
        std::mem::take(&mut c.hpke_credential_ref),
    ]
}

/// Check the saved connection by asking the server who it is, with a ticket
/// of `username`'s account. The password is used for one login and never
/// stored.
#[tauri::command]
async fn team_test_connection(username: String, password: String) -> Result<String, String> {
    let c = team_config::load().map_err(|e| e.to_string())?;
    if c.server_url.is_empty() {
        return Err(crate::errcode::code("fleet.setServerFirst"));
    }
    if c.tenant_id.is_empty() {
        return Err(crate::errcode::code("fleet.setTenantFirst"));
    }
    if username.trim().is_empty() || password.is_empty() {
        return Err(crate::errcode::code("fleet.setAccountFirst"));
    }
    let client =
        fleet_client::FleetClient::new(&c.server_url, &c.token).map_err(|e| e.to_string())?;
    let id = client
        .server_identity_with_login(&fleet_client::AccountLogin {
            tenant_id: &c.tenant_id,
            username: username.trim(),
            password: &password,
        })
        .await
        .map_err(|e| e.to_string())?;
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
    if c.server_url.is_empty() {
        return Err(crate::errcode::code("fleet.setServerFirst"));
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
    let tenant_id = c.tenant_id.clone();
    let login = fleet_client::AccountLogin {
        tenant_id: &tenant_id,
        username: username.trim(),
        password: &password,
    };
    let enrolled = client
        .enroll_device(&login, &signer, &hpke_public, label.trim().as_bytes())
        .await
        .map_err(|e| e.to_string())?;

    c.device_id = enrolled.device_id;
    // The default fleet has the tenant's ID, so no second call is needed.
    c.fleet_id = c.tenant_id.clone();
    // The join window runs from here, by this device's clock.
    c.enrolled_at_ms = root_bootstrap::now_ms();
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
    if let Err(error) = forget_revoked_identities(&client, &login, &c).await {
        eprintln!("[team] old credentials stay: {error}");
    }

    team_config::status().map_err(|e| e.to_string())
}

/// Forgets the `device-signing`/`device-hpke` credentials of an old identity
/// that a `team.json.unreadable-*` copy names, only while `login`'s `/v2/me`
/// lists that device `revoked`: the server's word decides this local deletion
/// and nothing else. Best effort, after an enrollment: the caller logs a
/// failure, the copies stay, and a `pending` or unlisted device keeps its
/// credentials.
async fn forget_revoked_identities(
    client: &fleet_client::FleetClient,
    login: &fleet_client::AccountLogin<'_>,
    c: &team_config::TeamConfig,
) -> anyhow::Result<()> {
    let config = store::team_config_path()?;
    let Some(dir) = config.parent() else {
        return Ok(());
    };
    let mut asked = std::collections::HashSet::new();
    for entry in std::fs::read_dir(dir)? {
        let copy = entry?.path();
        let is_copy = copy
            .file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with("team.json.unreadable-"));
        if !is_copy {
            continue;
        }
        // Recovery import copies `team.json` unparsed: one copy that does not
        // read stops nothing. Only the path is logged, never the content.
        let old = match std::fs::read(&copy) {
            Ok(body) => match serde_json::from_slice::<team_config::TeamConfig>(&body) {
                Ok(old) => old,
                Err(_) => {
                    eprintln!("[team] copy {} skipped: not a team config", copy.display());
                    continue;
                }
            },
            Err(e) => {
                eprintln!("[team] copy {} skipped: {:?}", copy.display(), e.kind());
                continue;
            }
        };
        // Only an identity of this server and tenant is this login's to ask about.
        if old.device_id.is_empty()
            || old.device_id.eq_ignore_ascii_case(&c.device_id)
            || old.server_url != c.server_url
            || !old.tenant_id.eq_ignore_ascii_case(&c.tenant_id)
            || !asked.insert(old.device_id.to_ascii_lowercase())
        {
            continue;
        }
        let listed = client.account_device_status(login, &old.device_id).await?;
        if listed.device.is_none_or(|d| d.status != "revoked") {
            continue;
        }
        for (kind, reference) in [
            ("device-signing", &old.signing_credential_ref),
            ("device-hpke", &old.hpke_credential_ref),
        ] {
            // Only the name enrollment gave that device's key, never one in use.
            if *reference != format!("{kind}.{}", old.device_id)
                || *reference == c.signing_credential_ref
                || *reference == c.hpke_credential_ref
            {
                continue;
            }
            match credential::forget(reference) {
                Ok(()) => eprintln!(
                    "[team] forgot revoked device {}'s {kind} key",
                    old.device_id
                ),
                Err(e) => eprintln!(
                    "[team] revoked device {}'s {kind} key stays: {e}",
                    old.device_id
                ),
            }
        }
    }
    Ok(())
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

/// Export the recovery bundle again (v0.2.2b plan, section 4.X) to `path`,
/// sealed under `passphrase`: this root custodian device with every verified
/// fleet key it holds. Nothing is filed; success ends a rotation's re-export
/// prompt. The password is used for one login and never stored.
#[tauri::command]
async fn team_export_recovery_bundle(
    username: String,
    password: String,
    path: String,
    passphrase: String,
) -> Result<(), String> {
    let c = team_config::load().map_err(|e| e.to_string())?;
    if !c.can_sync() {
        return Err(crate::errcode::code("fleet.deviceNotEnrolled"));
    }
    bootstrap_anchor(&c).ok_or_else(|| crate::errcode::code("fleet.notCustodian"))?;
    handed_over()?;
    let signer = c.signing_key().map_err(|e| e.to_string())?;
    let seed = zeroize::Zeroizing::new(c.hpke_seed().map_err(|e| e.to_string())?);
    let fleet_hex = sync_cmd::fleet_id(&c);
    let fkeks = fleet_keys::verified_keys(&fleet_hex).map_err(|e| e.to_string())?;
    let newest = fkeks.iter().map(|(g, _)| *g).max();
    let (client, session) = open_session(&c, &username, &password).await?;
    let access = session.access_token.as_str();
    let recovery = root_bootstrap::RecoveryExport {
        path: std::path::Path::new(&path),
        passphrase: &passphrase,
    };
    // A renewal first, so the bundle carries the renewed root grant.
    let _ = renew_quietly(&client, &c, access).await;
    let result = root_bootstrap::export_again(
        &client, access, &fleet_hex, &signer, &seed, fkeks, &recovery,
    )
    .await
    .map_err(|e| e.to_string());
    client.end_session(access).await;
    match &result {
        Ok(grant) => {
            eprintln!("[recovery] export: ok");
            // The bundle opens every generation it carries and holds the
            // current root grant: a rotation's or renewal's prompt ends.
            if let Err(e) = newest.map_or(Ok(()), |n| fleet_custody::exported(n, grant)) {
                eprintln!("[recovery] export prompt: not cleared ({e:#})");
            }
            // v2.10 4.H steps 3 and 6 of an accepted hand-over.
            let recorded = std::fs::read(&path)
                .map_err(anyhow::Error::from)
                .and_then(|b| {
                    let sha = shardx_core::recovery_bundle::recovery_bundle_sha256(&b);
                    fleet_custody::handover_exported(newest.unwrap_or(0), &fleet_client::hex(&sha))
                });
            if let Err(e) = recorded {
                eprintln!("[handover] export: not recorded ({e:#})");
            }
        }
        Err(e) => eprintln!(
            "[recovery] export: refused {}",
            recovery_import::error_code(e)
        ),
    }
    result.map(drop)
}

/// v2.10 4.H step 1: a root custodian that appointed another device runs no
/// custody command of its own, before any session is opened.
fn handed_over() -> Result<(), String> {
    let state = fleet_custody::load().map_err(|e| e.to_string())?;
    fleet_custody::refuse_handed_over(&state).map_err(|e| e.to_string())
}

/// How far this device's Create fleet key got, and whether a revocation
/// asks for a fleet key rotation.
#[tauri::command]
fn team_fleet_custody_status() -> Result<fleet_custody::FleetCustodyStatus, String> {
    let mut status = fleet_custody::status().map_err(|e| e.to_string())?;
    let c = team_config::load().map_err(|e| e.to_string())?;
    // Advisory (ADR 0002 C-1): a ledger that does not read shows no banner.
    status.rotation_required = rotation_required(&c).unwrap_or_else(|e| {
        eprintln!("[rotation] banner: unreadable ({e:#})");
        None
    });
    Ok(status)
}

/// [`fleet_custody::rotation_required`] for this root custodian, against
/// the highest fleet generation its ledger verified; none elsewhere.
fn rotation_required(
    c: &team_config::TeamConfig,
) -> anyhow::Result<Option<fleet_custody::RotationRequired>> {
    let Some(pin) = bootstrap_anchor(c) else {
        return Ok(None);
    };
    let state = fleet_custody::load()?;
    if state.revocations.is_empty() {
        return Ok(None);
    }
    let fleet = fleet_client::decode_hex16(&sync_cmd::fleet_id(c), "fleet_id")?;
    let db = team::db::Db::open()?;
    let Some(active) = team::ledger::highest_generation(&db, &pin.0, &fleet)? else {
        return Ok(None);
    };
    let issuer = c.signing_key()?.verifying_key().to_bytes();
    // A holding that does not read counts as held.
    let held =
        |key: &[u8; 32]| team::ledger::holds(&db, &pin.0, key, &fleet, active).unwrap_or(true);
    Ok(fleet_custody::rotation_required(
        &state, &issuer, active, held,
    ))
}

/// Create the fleet key as the tenant's root custodian, or resume it (plan
/// v0.2.2a section 4.F): generation 0 of the tenant's fleet, its device and
/// recovery grants, acknowledged and activated, then the setup key is
/// released, then the verified collect. The password is used for one login
/// and never stored.
#[tauri::command]
async fn team_fleet_key_setup(
    username: String,
    password: String,
) -> Result<fleet_custody::FleetCustodyStatus, String> {
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
    let root = root_bootstrap::load().map_err(|e| e.to_string())?;
    let _running = fleet_custody::begin().map_err(|e| e.to_string())?;
    let client =
        fleet_client::FleetClient::new(&c.server_url, &c.token).map_err(|e| e.to_string())?;
    let device = fleet_custody::FleetDevice {
        tenant_id: &c.tenant_id,
        device_id: &c.device_id,
        account_id: &c.account_id,
        signer: &signer,
        hpke_seed: &hpke_seed,
        vault: &fleet_custody::CredentialFkekStore,
    };
    let login = fleet_client::AccountLogin {
        tenant_id: &c.tenant_id,
        username: username.trim(),
        password: &password,
    };
    let session = client
        .open_device_session(&login, &c.device_id, &signer, &hpke_seed)
        .await
        .map_err(|e| e.to_string())?;
    let access = session.access_token.as_str();
    let result = async {
        let mut state = fleet_custody::load().map_err(|e| e.to_string())?;
        fleet_custody::bootstrap_fleet(&client, access, &device, &root, &mut state, &mut |s| {
            fleet_custody::save(s)
        })
        .await
        .map_err(|e| e.to_string())?;
        // Generation 0 is ACTIVE with both grants acknowledged, and nothing
        // after `prepare` reads the setup key. Release it before the collect,
        // so a release that fails never leaves a usable key behind; a resumed
        // run replays the saved requests and collects without it.
        fleet_custody::release(device.vault).map_err(|e| e.to_string())?;
        // Step 9: only the verified collect keeps the key in `fleet_keys`.
        // Step 7's ACKED receipt already acknowledged the grant, so a server
        // that still reports it PENDING_ACK cannot fail setup after the keep.
        let (device_sk, _) = shardx_core::grants::derive_keypair(&hpke_seed);
        let fleet = collect_fleet_grant(&client, &c, access, &device_sk, false).await?;
        match setup_collect_error(fleet, 0) {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
    .await;
    client.end_session(access).await;
    result?;
    fleet_custody::status().map_err(|e| e.to_string())
}

/// Opens this device's session as `username` for one command; the password
/// serves that one login and is never stored.
async fn open_session(
    c: &team_config::TeamConfig,
    username: &str,
    password: &str,
) -> Result<(fleet_client::FleetClient, fleet_client::DeviceSession), String> {
    if username.trim().is_empty() || password.is_empty() {
        return Err(crate::errcode::code("fleet.setAccountFirst"));
    }
    let client =
        fleet_client::FleetClient::new(&c.server_url, &c.token).map_err(|e| e.to_string())?;
    let login = fleet_client::AccountLogin {
        tenant_id: &c.tenant_id,
        username: username.trim(),
        password,
    };
    let signer = c.signing_key().map_err(|e| e.to_string())?;
    let seed = zeroize::Zeroizing::new(c.hpke_seed().map_err(|e| e.to_string())?);
    let session = client
        .open_device_session(&login, &c.device_id, &signer, &seed)
        .await
        .map_err(|e| e.to_string())?;
    Ok((client, session))
}

/// The tenant's devices with the code each must show, for the root
/// custodian's Approve screen (v0.2.2a plan, section 4.A step 1). The first
/// sight of each pending device is noted here, and never reset.
#[tauri::command]
async fn team_devices(
    username: String,
    password: String,
) -> Result<Vec<fleet_custody::ListedDevice>, String> {
    let c = team_config::load().map_err(|e| e.to_string())?;
    if !c.can_sync() {
        return Err(crate::errcode::code("fleet.deviceNotEnrolled"));
    }
    let pin = bootstrap_anchor(&c).ok_or_else(|| crate::errcode::code("fleet.notCustodian"))?;
    let _running = fleet_custody::begin().map_err(|e| e.to_string())?;
    let (client, session) = open_session(&c, &username, &password).await?;
    if let Err(e) = renew_first(&client, &c, &session.access_token).await {
        client.end_session(&session.access_token).await;
        return Err(e);
    }
    let rows = client
        .list_tenant_devices(&session.access_token, &c.tenant_id)
        .await;
    client.end_session(&session.access_token).await;
    let rows = rows.map_err(|e| e.to_string())?;
    let mut state = fleet_custody::load().map_err(|e| e.to_string())?;
    let mut listed = fleet_custody::see_devices(
        &rows,
        &pin,
        root_bootstrap::now_ms(),
        &mut state,
        &mut |s| fleet_custody::save(s),
    )
    .map_err(|e| e.to_string())?;
    // Advisory (Q-57): Revoke checks fresh evidence itself. A ledger that
    // does not read offers no `compromised`.
    let ledger = team::db::Db::open().ok();
    for d in &mut listed {
        let key = fleet_client::decode_hex32(&d.signing_key_id, "signing_key_id")
            .map_err(|e| e.to_string())?;
        d.custodian = d.device_id.eq_ignore_ascii_case(&c.device_id)
            || ledger
                .as_ref()
                .is_none_or(|db| team::ledger::held_custody(db, &pin.0, &key).unwrap_or(true));
    }
    Ok(listed)
}

/// Approves the pending device `device_id` once the user confirmed that it
/// shows `sas` (section 4.A): its fleet-scoped approval, its three profile
/// capability grants and its grant of the fleet key. A device with saved
/// requests gets them resent as saved. With `as_custodian` (v2.10 4.H step
/// 1, Appoint) the device is approved tenant-wide and given an
/// `ExistingRootGrant` of the ACTIVE root, once every head is under the
/// ACTIVE generation (`fleet.handoverNeedsReseal`); this device then hands
/// its custody over.
#[tauri::command]
async fn team_approve_device(
    username: String,
    password: String,
    device_id: String,
    sas: String,
    as_custodian: Option<bool>,
) -> Result<(), String> {
    let c = team_config::load().map_err(|e| e.to_string())?;
    if !c.can_sync() {
        return Err(crate::errcode::code("fleet.deviceNotEnrolled"));
    }
    let pin = bootstrap_anchor(&c).ok_or_else(|| crate::errcode::code("fleet.notCustodian"))?;
    let as_custodian = as_custodian.unwrap_or(false);
    let appointed = fleet_custody::resumes_appointment(
        &fleet_custody::load().map_err(|e| e.to_string())?,
        &device_id,
    );
    if !(as_custodian && appointed) {
        handed_over()?;
    }
    let root = root_bootstrap::load().map_err(|e| e.to_string())?;
    let signer = c.signing_key().map_err(|e| e.to_string())?;
    let seed = zeroize::Zeroizing::new(c.hpke_seed().map_err(|e| e.to_string())?);
    let me = recipient(&c).map_err(|e| e.to_string())?;
    let _running = fleet_custody::begin().map_err(|e| e.to_string())?;
    let (client, session) = open_session(&c, &username, &password).await?;
    let access = session.access_token.as_str();
    let device = fleet_custody::FleetDevice {
        tenant_id: &c.tenant_id,
        device_id: &c.device_id,
        account_id: &c.account_id,
        signer: &signer,
        hpke_seed: &seed,
        vault: &fleet_custody::CredentialFkekStore,
    };
    let result = async {
        renew_first(&client, &c, access).await?;
        let rows = client
            .list_tenant_devices(access, &c.tenant_id)
            .await
            .map_err(|e| e.to_string())?;
        let row = rows
            .iter()
            .find(|r| r.device_id.eq_ignore_ascii_case(device_id.trim()))
            .ok_or_else(|| crate::errcode::code("fleet.deviceNotListed"))?;
        let now = root_bootstrap::now_ms();
        let fleet_hex = sync_cmd::fleet_id(&c);
        let fleet_key = |generation: u64| {
            verified_fleet_key(&fleet_hex, &pin, &me, generation, now)?
                .ok_or_else(|| anyhow::anyhow!(crate::errcode::code("fleet.createFleetKeyFirst")))
        };
        let withdrawn =
            |key: &[u8; 32]| team::ledger::withdrawn(&team::db::Db::open()?, &pin.0, key);
        let mut state = fleet_custody::load().map_err(|e| e.to_string())?;
        fleet_custody::approve_member(
            &client,
            access,
            &device,
            &pin,
            row,
            &sas,
            fleet_key,
            withdrawn,
            as_custodian.then_some(&root),
            now,
            &mut state,
            &mut |s| fleet_custody::save(s),
        )
        .await
        .map_err(|e| e.to_string())
    }
    .await;
    client.end_session(access).await;
    result
}

/// v2.10 4.H step 2: accept the root custody the root custodian appointed
/// this device to, or resume Accept ([`fleet_custody::accept_custody`]):
/// the root grant from the evidence, its ack, the root state, the own
/// capability grants, the verified collect of the accepted generation and
/// then this device's own grant of it. The password is used for one login
/// and never stored.
#[tauri::command]
async fn team_custody_accept(
    username: String,
    password: String,
) -> Result<fleet_custody::FleetCustodyStatus, String> {
    let c = team_config::load().map_err(|e| e.to_string())?;
    if !c.can_sync() {
        return Err(crate::errcode::code("fleet.deviceNotEnrolled"));
    }
    if !c.can_receive_custody() {
        return Err(crate::errcode::code("teamConfig.hpkeKeyUnusable"));
    }
    let pin = pinned_anchor(&c).ok_or_else(|| crate::errcode::code("fleet.handoverNoGrant"))?;
    let signer = c.signing_key().map_err(|e| e.to_string())?;
    let seed = zeroize::Zeroizing::new(c.hpke_seed().map_err(|e| e.to_string())?);
    let me = recipient(&c).map_err(|e| e.to_string())?;
    let _running = fleet_custody::begin().map_err(|e| e.to_string())?;
    let (client, session) = open_session(&c, &username, &password).await?;
    let access = session.access_token.as_str();
    let result = custody_accept(&client, &c, access, &signer, &seed, &me, &pin, &mut |s| {
        root_bootstrap::save(s)
    })
    .await;
    client.end_session(access).await;
    result?;
    team_fleet_custody_status()
}

/// [`team_custody_accept`] over the session `access`, the root state
/// written through `root_save`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn custody_accept(
    client: &fleet_client::FleetClient,
    c: &team_config::TeamConfig,
    access: &str,
    signer: &shardx_core::signing::Ed25519SigningKey,
    seed: &[u8; 32],
    me: &shardx_core::trust_chain::Recipient,
    pin: &(shardx_core::trust_chain::Binding, [u8; 32]),
    root_save: &mut impl FnMut(&root_bootstrap::BootstrapState) -> anyhow::Result<()>,
) -> Result<(), String> {
    let device = fleet_custody::FleetDevice {
        tenant_id: &c.tenant_id,
        device_id: &c.device_id,
        account_id: &c.account_id,
        signer,
        hpke_seed: seed,
        vault: &fleet_custody::CredentialFkekStore,
    };
    let now = root_bootstrap::now_ms();
    let fleet_hex = sync_cmd::fleet_id(c);
    let fleet_key = |generation: u64| {
        verified_fleet_key(&fleet_hex, pin, me, generation, now)?
            .ok_or_else(|| anyhow::anyhow!(crate::errcode::code("fleet.createFleetKeyFirst")))
    };
    let (device_sk, _) = shardx_core::grants::derive_keypair(seed);
    let device_sk = &device_sk;
    let collect = || async move {
        match collect_fleet_grant(client, c, access, device_sk, true)
            .await
            .map_err(|e| anyhow::anyhow!(e))?
        {
            FleetGrant::Opened(g) => Ok(g),
            other => Err(anyhow::anyhow!(setup_collect_error(other, u64::MAX)
                .unwrap_or_else(|| crate::errcode::code(
                    "fleet.custodyReplyMismatch"
                )))),
        }
    };
    let mut db = team::db::Db::open().map_err(|e| e.to_string())?;
    let mut ledger = fleet_custody::Ledger { db: &mut db, pin };
    let mut state = fleet_custody::load().map_err(|e| e.to_string())?;
    fleet_custody::accept_custody(
        client,
        access,
        &device,
        &mut ledger,
        fleet_key,
        collect,
        now,
        &mut state,
        &mut |s| fleet_custody::save(s),
        root_save,
    )
    .await
    .map_err(|e| format!("{e:#}"))
}

/// This device's key of `generation` of the fleet `fleet_hex`, only while its
/// grant still verifies to the pin, as sync reads it
/// (`team::sync::readable_key`).
fn verified_fleet_key(
    fleet_hex: &str,
    pin: &(shardx_core::trust_chain::Binding, [u8; 32]),
    me: &shardx_core::trust_chain::Recipient,
    generation: u64,
    now: u64,
) -> anyhow::Result<Option<zeroize::Zeroizing<[u8; 32]>>> {
    let fleet = fleet_client::decode_hex16(fleet_hex, "fleet_id")?;
    let ledger = team::db::Db::open()?;
    Ok(fleet_keys::load()?
        .keys_newest_first(fleet_hex, |_, _| true)
        .into_iter()
        .find(|(k, g)| {
            *g == generation
                && fleet_key_verifies(&ledger, pin, me, &fleet, *g, k, now).unwrap_or(false)
        })
        .map(|(k, _)| zeroize::Zeroizing::new(k)))
}

/// Rotate the fleet key as the tenant's root custodian, or resume the
/// rotation (sequence K, ADR 0002 D-9): N+1 is created with this device as
/// its required set and activated (N retires), the setup key is released,
/// N+1 is collected verified, then granted to every member a signed approval
/// names (Q-45). `skip_member`, the member whose grant keeps failing, is
/// left out first ([`fleet_custody::skip_member`]). The password is used for
/// one login and never stored.
#[tauri::command]
async fn team_fleet_key_rotate(
    username: String,
    password: String,
    skip_member: Option<String>,
) -> Result<fleet_custody::FleetCustodyStatus, String> {
    let c = team_config::load().map_err(|e| e.to_string())?;
    if !c.can_sync() {
        return Err(crate::errcode::code("fleet.deviceNotEnrolled"));
    }
    if !c.can_receive_custody() {
        return Err(crate::errcode::code("teamConfig.hpkeKeyUnusable"));
    }
    let pin = bootstrap_anchor(&c).ok_or_else(|| crate::errcode::code("fleet.notCustodian"))?;
    handed_over()?;
    let signer = c.signing_key().map_err(|e| e.to_string())?;
    let seed = zeroize::Zeroizing::new(c.hpke_seed().map_err(|e| e.to_string())?);
    let me = recipient(&c).map_err(|e| e.to_string())?;
    let root = root_bootstrap::load().map_err(|e| e.to_string())?;
    let _running = fleet_custody::begin().map_err(|e| e.to_string())?;
    let (client, session) = open_session(&c, &username, &password).await?;
    let access = session.access_token.as_str();
    let device = fleet_custody::FleetDevice {
        tenant_id: &c.tenant_id,
        device_id: &c.device_id,
        account_id: &c.account_id,
        signer: &signer,
        hpke_seed: &seed,
        vault: &fleet_custody::CredentialFkekStore,
    };
    let fleet_hex = sync_cmd::fleet_id(&c);
    let result = async {
        renew_first(&client, &c, access).await?;
        let error = |e: anyhow::Error| e.to_string();
        let now = root_bootstrap::now_ms();
        let started = std::time::Instant::now();
        let save = &mut |s: &fleet_custody::FleetCustodyState| fleet_custody::save(s);
        let mut state = fleet_custody::load().map_err(error)?;
        if let Some(id) = &skip_member {
            fleet_custody::skip_member(&mut state, id, save).map_err(error)?;
        }
        // Start needs N verified here, and N as the ledger's highest.
        let previous_key = |generation: u64| {
            let fleet = fleet_client::decode_hex16(&fleet_hex, "fleet_id")?;
            let db = team::db::Db::open()?;
            let highest = team::ledger::highest_generation(&db, &pin.0, &fleet)?;
            drop(db);
            verified_fleet_key(&fleet_hex, &pin, &me, generation, now)?
                .filter(|_| highest == Some(generation))
                .ok_or_else(|| anyhow::anyhow!(crate::errcode::code("fleet.rotationNeedsFleetKey")))
        };
        {
            let mut db = team::db::Db::open().map_err(error)?;
            let mut ledger = fleet_custody::Ledger {
                db: &mut db,
                pin: &pin,
            };
            fleet_custody::rotate_fleet(
                &client,
                access,
                &device,
                &root,
                &mut ledger,
                previous_key,
                || now + started.elapsed().as_millis() as u64,
                &mut state,
                save,
            )
            .await
            .map_err(error)?;
        }
        let generation = state.rotation.as_ref().map_or(0, |r| r.generation);
        let activated = Some(fleet_custody::RotationPhase::Activated);
        // 10. As Create fleet key: the setup key goes first, then only the
        // verified collect keeps N+1; `fleet_keys` keeps N too.
        if state.rotation.as_ref().map(|r| r.phase) != activated {
            fleet_custody::release_rotation_key(device.vault, &mut state, save).map_err(error)?;
            let (device_sk, _) = shardx_core::grants::derive_keypair(&seed);
            let fleet = collect_fleet_grant(&client, &c, access, &device_sk, false).await?;
            if let Some(error) = setup_collect_error(fleet, generation) {
                return Err(error);
            }
            fleet_custody::rotation_collected(now, &mut state, save).map_err(error)?;
        }
        // D8: a fleet key activated under the rotated root ends that prompt.
        if let Some(grant) = state
            .rotation
            .as_ref()
            .and_then(|r| fleet_client::decode_hex(&r.recovery_grant))
        {
            let issuer = signer.verifying_key().to_bytes();
            let mut root = root_bootstrap::load().map_err(error)?;
            root_rotation::fleet_rotated(&grant, &issuer, &mut root, &mut |s| {
                root_bootstrap::save(s)
            })
            .map_err(error)?;
        }
        // 11 and 12.
        let fkek = verified_fleet_key(&fleet_hex, &pin, &me, generation, now)
            .map_err(error)?
            .ok_or_else(|| crate::errcode::code("fleet.rotationNeedsFleetKey"))?;
        let mut db = team::db::Db::open().map_err(error)?;
        let mut ledger = fleet_custody::Ledger {
            db: &mut db,
            pin: &pin,
        };
        fleet_custody::grant_members(
            &client,
            access,
            &device,
            &mut ledger,
            &fkek,
            now,
            &mut state,
            save,
        )
        .await
        .map_err(error)
    }
    .await;
    client.end_session(access).await;
    result?;
    team_fleet_custody_status()
}

/// Re-seal all profiles as the tenant's root custodian, or resume the run
/// (v2.10 4.S, `team::sync::reseal_all`): every fleet head under an older
/// fleet key is committed again under the active one, from its ciphertext;
/// a profile in use, in error or quarantined is skipped and listed. Each
/// bound profile is claimed against a launch for its step. The password is
/// used for one login and never stored.
#[tauri::command]
async fn team_reseal_all(
    username: String,
    password: String,
) -> Result<fleet_custody::FleetCustodyStatus, String> {
    let c = team_config::load().map_err(|e| e.to_string())?;
    if !c.can_sync() {
        return Err(crate::errcode::code("fleet.deviceNotEnrolled"));
    }
    let pin =
        bootstrap_anchor(&c).ok_or_else(|| crate::errcode::code("sync.resealNotCustodian"))?;
    handed_over()?;
    let dev = team::sync::Device {
        signer: c.signing_key().map_err(|e| e.to_string())?,
        me: recipient(&c).map_err(|e| e.to_string())?,
        pin,
    };
    let fleet = fleet_client::decode_hex16(&sync_cmd::fleet_id(&c), "fleet_id")
        .map_err(|e| e.to_string())?;
    let _running = fleet_custody::begin().map_err(|e| e.to_string())?;
    let (client, session) = open_session(&c, &username, &password).await?;
    let access = session.access_token.as_str();
    let action = crate::errcode::code("profile.actionPushToTeam");
    let claim = |local: &str| -> Option<Box<dyn Send>> {
        let guard = profile::begin_user_mutation([local], &action).ok()?;
        Some(Box::new(guard))
    };
    if let Err(e) = renew_first(&client, &c, access).await {
        client.end_session(access).await;
        return Err(e);
    }
    // 4.H step 5: an accepted hand-over re-seals the outgoing key's heads.
    let outgoing = fleet_custody::load()
        .map_err(|e| e.to_string())?
        .handover
        .map(|h| fleet_client::decode_hex32(&h.outgoing, "outgoing"))
        .transpose()
        .map_err(|e| e.to_string())?;
    let resealed = team::sync::reseal_all(
        &client,
        access,
        &dev,
        fleet,
        outgoing,
        &claim,
        root_bootstrap::now_ms(),
        &mut |s: &fleet_custody::FleetCustodyState| fleet_custody::save(s),
    )
    .await;
    client.end_session(access).await;
    let run = resealed.map_err(|e| format!("{e:#}"))?;
    fleet_custody::handover_resealed(&run).map_err(|e| e.to_string())?;
    team_fleet_custody_status()
}

/// Revokes the tenant's device `device_id` as `reason`, `retired`, `lost` or,
/// for a member device, `compromised` (section 4.R, Q-57: checked against
/// fresh evidence evaluated to this device's pin). A saved revocation is
/// resent as saved. The device is cut off from the server, but keeps the
/// fleet key it already holds (section 7). After an appointment only the
/// appointee may be revoked (the cancel, D13). The outgoing custodian of an
/// accepted hand-over is revoked behind its checklist and live check (v2.10
/// 4.H step 7, [`fleet_custody::revoke_outgoing`]); with `lost`,
/// `accept_reverts` must list exactly the profiles it will revert.
#[tauri::command]
async fn team_revoke_device(
    username: String,
    password: String,
    device_id: String,
    reason: String,
    accept_reverts: Option<Vec<String>>,
) -> Result<(), String> {
    let reason = fleet_custody::revoke_reason(&reason).map_err(|e| e.to_string())?;
    let c = team_config::load().map_err(|e| e.to_string())?;
    if !c.can_sync() {
        return Err(crate::errcode::code("fleet.deviceNotEnrolled"));
    }
    let appointed = fleet_custody::load()
        .map_err(|e| e.to_string())?
        .handed_over_to;
    if !appointed.is_empty() && !appointed.eq_ignore_ascii_case(device_id.trim()) {
        return Err(crate::errcode::code("fleet.custodyHandedOver"));
    }
    let signer = c.signing_key().map_err(|e| e.to_string())?;
    let seed = zeroize::Zeroizing::new(c.hpke_seed().map_err(|e| e.to_string())?);
    let _running = fleet_custody::begin().map_err(|e| e.to_string())?;
    let (client, session) = open_session(&c, &username, &password).await?;
    let access = session.access_token.as_str();
    let device = fleet_custody::FleetDevice {
        tenant_id: &c.tenant_id,
        device_id: &c.device_id,
        account_id: &c.account_id,
        signer: &signer,
        hpke_seed: &seed,
        vault: &fleet_custody::CredentialFkekStore,
    };
    let result = async {
        let rows = client
            .list_tenant_devices(access, &c.tenant_id)
            .await
            .map_err(|e| e.to_string())?;
        let row = rows
            .iter()
            .find(|r| r.device_id.eq_ignore_ascii_case(device_id.trim()))
            .ok_or_else(|| crate::errcode::code("fleet.deviceNotListed"))?;
        let mut state = fleet_custody::load().map_err(|e| e.to_string())?;
        let pin = pinned_anchor(&c);
        let mut db = match pin {
            Some(_) if reason == shardx_core::authz_record::DeviceRevocationReason::Compromised => {
                Some(team::db::Db::open().map_err(|e| e.to_string())?)
            }
            _ => None,
        };
        if let (Some(pin), Some(h)) = (&pin, &state.handover) {
            if h.outgoing.eq_ignore_ascii_case(&row.signing_key_id) {
                let dev = team::sync::Device {
                    signer: c.signing_key().map_err(|e| e.to_string())?,
                    me: recipient(&c).map_err(|e| e.to_string())?,
                    pin: *pin,
                };
                let (client, dev) = (&client, &dev);
                let revert = |remote: String| async move {
                    let profile = fleet_client::decode_hex16(&remote, "remote_profile_id")?;
                    let local = team::sync::bound_local(&pin.0, &profile)?.ok_or_else(|| {
                        anyhow::anyhow!(crate::errcode::code("fleet.handoverRevertNotBound"))
                    })?;
                    let _claim = profile::begin_user_mutation(
                        [&local],
                        &crate::errcode::code("profile.actionRevertTeam"),
                    )?;
                    let udd = profile::user_data_dir(&local)?;
                    let started = std::time::Instant::now();
                    let pushed = team::sync::revert(
                        client,
                        access,
                        dev,
                        &local,
                        &udd,
                        root_bootstrap::now_ms(),
                        &|| started.elapsed(),
                    )
                    .await?;
                    anyhow::Ok(pushed.version)
                };
                let bound = |remote: &str| {
                    let profile = fleet_client::decode_hex16(remote, "remote_profile_id")?;
                    Ok(team::sync::bound_local(&pin.0, &profile)?.is_some())
                };
                return fleet_custody::revoke_outgoing(
                    client,
                    access,
                    &device,
                    pin,
                    row,
                    reason,
                    accept_reverts.as_deref().unwrap_or_default(),
                    bound,
                    revert,
                    root_bootstrap::now_ms(),
                    &mut state,
                    &mut |s| fleet_custody::save(s),
                )
                .await
                .map_err(|e| e.to_string());
            }
        }
        let mut ledger = pin
            .as_ref()
            .zip(db.as_mut())
            .map(|(pin, db)| fleet_custody::Ledger { db, pin });
        fleet_custody::revoke_member(
            &client,
            access,
            &device,
            row,
            reason,
            ledger.as_mut(),
            root_bootstrap::now_ms(),
            &mut state,
            &mut |s| fleet_custody::save(s),
        )
        .await
        .map_err(|e| e.to_string())
    }
    .await;
    client.end_session(access).await;
    result
}

/// What a joining device shows beside its code (section 4.J step 2): the
/// full anchor and key IDs are one click away.
#[derive(serde::Serialize, Debug)]
struct JoinCode {
    sas: String,
    anchor: String,
    signing_key_id: String,
    hpke_key_id: String,
    expires_at_ms: u64,
}

/// The end of this device's join window while it is open: ten minutes from
/// its own enrollment, by its own clock, never relaxed (ADR "Join window
/// rule"). An enrollment without a time has no window.
fn join_window(c: &team_config::TeamConfig, now: u64) -> Result<u64, String> {
    let end = c
        .enrolled_at_ms
        .saturating_add(fleet_custody::JOIN_WINDOW_MS);
    if c.enrolled_at_ms == 0 || now > end {
        return Err(crate::errcode::code("fleet.joinCodeExpired"));
    }
    Ok(end)
}

/// The binding and the anchor `A0` the tenant's trust evidence verifies to
/// on its own, read over the session `access`: a joining device has no pin
/// yet.
async fn evidence_anchor(
    client: &fleet_client::FleetClient,
    access: &str,
    c: &team_config::TeamConfig,
) -> Result<(shardx_core::trust_chain::Binding, [u8; 32]), String> {
    use shardx_core::trust_chain::{Binding, Evidence, TrustChain};
    let refused = || crate::errcode::code("fleet.trustEvidenceRefused");
    let id = client
        .server_identity(access)
        .await
        .map_err(|e| e.to_string())?;
    let binding = Binding {
        server_instance_id: fleet_client::decode_hex16(
            &id.server_instance_id,
            "server_instance_id",
        )
        .map_err(|e| e.to_string())?,
        tenant_id: fleet_client::decode_hex16(&c.tenant_id, "tenant_id")
            .map_err(|e| e.to_string())?,
    };
    let pages = client
        .trust_evidence(access, &c.tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let evidence = Evidence::collect(&binding, &pages).map_err(|_| refused())?;
    let chain = TrustChain::evaluate(evidence, None).map_err(|_| refused())?;
    Ok((binding, *chain.anchor()))
}

/// This device's join code (section 4.J step 2), while its window is open.
#[tauri::command]
async fn team_join_code(username: String, password: String) -> Result<JoinCode, String> {
    let c = team_config::load().map_err(|e| e.to_string())?;
    if !c.can_sync() {
        return Err(crate::errcode::code("fleet.deviceNotEnrolled"));
    }
    let expires_at_ms = match join_window(&c, root_bootstrap::now_ms()) {
        Ok(end) => end,
        // The UI offers Enroll again for an expired code, so say when
        // `team_enroll_again` would refuse it. Unasked, the code just reads
        // as expired; asked but unanswered (a refused login, a server down),
        // the error stands, so Enroll again is never offered on a guess. A
        // device with its own root state is refused unasked, as Reset is.
        Err(_) if own_root_state(&c).map_err(|e| e.to_string())? => {
            return Err(crate::errcode::code("fleet.enrollAgainRefused"));
        }
        Err(expired) if !username.trim().is_empty() && !password.is_empty() => {
            let client = fleet_client::FleetClient::new(&c.server_url, &c.token)
                .map_err(|e| e.to_string())?;
            let login = fleet_client::AccountLogin {
                tenant_id: &c.tenant_id,
                username: username.trim(),
                password: &password,
            };
            let status = client
                .account_device_status(&login, &c.device_id)
                .await
                .map_err(|e| e.to_string())?
                .device
                .map(|d| d.status);
            let pinned = status.as_deref() == Some("active")
                && read_pinned_anchor(&c).map_err(|e| e.to_string())?.is_some();
            return Err(if enroll_again_allowed(status.as_deref(), pinned) {
                expired
            } else if status.as_deref() == Some("active") {
                crate::errcode::code("fleet.joinedCollectKey")
            } else {
                crate::errcode::code("fleet.enrollAgainRefused")
            });
        }
        Err(expired) => return Err(expired),
    };
    let (client, session) = open_session(&c, &username, &password).await?;
    let pin = evidence_anchor(&client, &session.access_token, &c).await;
    client.end_session(&session.access_token).await;
    let (binding, anchor) = pin?;
    let me = recipient(&c).map_err(|e| e.to_string())?;
    let sas = shardx_core::trust_chain::join_sas(
        &binding.server_instance_id,
        &binding.tenant_id,
        &anchor,
        &me.signing_key_id,
        &me.hpke_key_id,
    );
    Ok(JoinCode {
        sas: shardx_core::trust_chain::join_sas_display(&sas),
        anchor: fleet_client::hex(&anchor),
        signing_key_id: fleet_client::hex(&me.signing_key_id),
        hpke_key_id: fleet_client::hex(&me.hpke_key_id),
        expires_at_ms,
    })
}

/// Section 4.J step 3: pins `evaluated` for `binding` as this device's
/// `JOIN` anchor when it is the `shown` one the user confirmed, the code
/// over the binding, the anchor and this device's keys is still the `sas`
/// shown beside it (ADR 0002 Q-12: the whole `(server_instance_id,
/// tenant_id, A0)` is what is pinned), and the window is still open.
#[allow(clippy::too_many_arguments)]
fn pin_join(
    c: &team_config::TeamConfig,
    ledger: &team::db::Db,
    binding: &shardx_core::trust_chain::Binding,
    evaluated: &[u8; 32],
    shown: &str,
    sas: &str,
    now: u64,
) -> Result<(), String> {
    join_window(c, now)?;
    let changed = || crate::errcode::code("fleet.joinAnchorChanged");
    if !shown
        .trim()
        .eq_ignore_ascii_case(&fleet_client::hex(evaluated))
    {
        return Err(changed());
    }
    let me = recipient(c).map_err(|e| e.to_string())?;
    let code = shardx_core::trust_chain::join_sas_display(&shardx_core::trust_chain::join_sas(
        &binding.server_instance_id,
        &binding.tenant_id,
        evaluated,
        &me.signing_key_id,
        &me.hpke_key_id,
    ));
    let typed: String = sas
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_ascii_lowercase();
    if typed != code.replace(' ', "") {
        return Err(crate::errcode::code("fleet.joinCodeChanged"));
    }
    let pinned = team::ledger::pin_anchor(ledger, binding, evaluated, team::ledger::JOIN, now)
        .map_err(|e| {
            eprintln!("[fleet] trust ledger: {e:#}");
            crate::errcode::code("team.trustLedgerUnreadable")
        })?;
    if !pinned {
        return Err(changed());
    }
    Ok(())
}

/// Pins the anchor `anchor` the user saw beside the matching code `sas`
/// (section 4.J step 3), only inside this device's join window: a late
/// confirm is never allowed, approved or not.
#[tauri::command]
async fn team_join_confirm(
    username: String,
    password: String,
    anchor: String,
    sas: String,
) -> Result<(), String> {
    let c = team_config::load().map_err(|e| e.to_string())?;
    if !c.can_sync() {
        return Err(crate::errcode::code("fleet.deviceNotEnrolled"));
    }
    join_window(&c, root_bootstrap::now_ms())?;
    let (client, session) = open_session(&c, &username, &password).await?;
    let pin = evidence_anchor(&client, &session.access_token, &c).await;
    client.end_session(&session.access_token).await;
    let (binding, evaluated) = pin?;
    let ledger = team::db::Db::open().map_err(|e| e.to_string())?;
    pin_join(
        &c,
        &ledger,
        &binding,
        &evaluated,
        &anchor,
        &sas,
        root_bootstrap::now_ms(),
    )
}

/// Clears this device's identity so it can enroll again (section 4.J step
/// 4): only while the server lists it pending or revoked, pinned here or not,
/// or active without a pin here, as when an approval landed after its join
/// window closed (v0.2.2b section 4.Z: revoked resets a device whose keys
/// are lost). A pin binds the server, tenant and anchor, not the device, so it
/// stays. An active pinned device and the root custodian keep theirs. The old
/// row stays on the server until a custodian revokes it.
#[tauri::command]
async fn team_enroll_again(
    username: String,
    password: String,
) -> Result<team_config::TeamStatus, String> {
    let mut c = team_config::load().map_err(|e| e.to_string())?;
    if !c.is_enrolled() {
        return Err(crate::errcode::code("fleet.deviceNotEnrolled"));
    }
    if username.trim().is_empty() || password.is_empty() {
        return Err(crate::errcode::code("fleet.setAccountFirst"));
    }
    let refused = || crate::errcode::code("fleet.enrollAgainRefused");
    // v2.11 RS: a root device resets only after a hand-over, on its signed
    // revocation; a live custodian is refused unasked.
    let root_device = own_root_state(&c).map_err(|e| e.to_string())?;
    if root_device
        && !fleet_custody::may_reset_root(&fleet_custody::load().map_err(|e| e.to_string())?)
    {
        return Err(refused());
    }
    let client =
        fleet_client::FleetClient::new(&c.server_url, &c.token).map_err(|e| e.to_string())?;
    let me = client
        .account_device_status(
            &fleet_client::AccountLogin {
                tenant_id: &c.tenant_id,
                username: username.trim(),
                password: &password,
            },
            &c.device_id,
        )
        .await
        .map_err(|e| e.to_string())?;
    // The ticket and the listing name one account, and it is the one that
    // enrolled this device when `team.json` records it (a config from before
    // `account_id` has none): anything else never resets it, as recovery
    // import checks the bundle's.
    let account = &me.ticket_account_id;
    if account.is_empty()
        || !me.account_id.eq_ignore_ascii_case(account)
        || (!c.account_id.is_empty() && !c.account_id.eq_ignore_ascii_case(account))
    {
        return Err(crate::errcode::code("fleet.enrollAgainOtherAccount"));
    }
    if root_device {
        return reset_root_device(c, &me);
    }
    let status = me.device.map(|d| d.status);
    // Only an active device's pin decides, so only its ledger is read.
    let pinned = status.as_deref() == Some("active")
        && read_pinned_anchor(&c).map_err(|e| e.to_string())?.is_some();
    if !enroll_again_allowed(status.as_deref(), pinned) {
        return Err(refused());
    }
    // `team.json` and the root state may have changed during the listing (an
    // import, Enroll, a new connection): only the identity checked above is
    // cleared, as import's write does.
    let now = team_config::load().map_err(|e| e.to_string())?;
    if !same_identity(&now, &c) || own_root_state(&now).map_err(|e| e.to_string())? {
        return Err(crate::errcode::code("fleet.identityChanged"));
    }
    c = now;
    // `revoked` and `pending` are the server's unauthenticated word, and a
    // seed that does not read may come back: the file is copied and the keys
    // are kept.
    let keep = matches!(status.as_deref(), Some("revoked" | "pending"))
        || c.signing_key().is_err()
        || c.hpke_seed().is_err();
    if keep {
        let copy = team_config::preserve_unreadable().map_err(|e| e.to_string())?;
        eprintln!(
            "[recovery] reset keeps the old credentials; team.json copied to {}",
            copy.display()
        );
    }
    // G8 and G12: the new identity collects the fleet key again and acks it
    // with its own request.
    let removed =
        fleet_keys::unindex_unopenable(&sync_cmd::fleet_id(&c)).map_err(|e| e.to_string())?;
    eprintln!("[recovery] reset: unindexed fleet key generations {removed:?}");
    fleet_custody::forget_device_acks().map_err(|e| e.to_string())?;
    let stale_refs = clear_identity(&mut c);
    team_config::save(&c).map_err(|e| e.to_string())?;
    for reference in stale_refs.iter().filter(|r| !r.is_empty() && !keep) {
        let _ = credential::forget(reference);
    }
    team_config::status().map_err(|e| e.to_string())
}

/// Whether `now` still names the identity of `c`.
fn same_identity(now: &team_config::TeamConfig, c: &team_config::TeamConfig) -> bool {
    now.server_url == c.server_url
        && now.tenant_id == c.tenant_id
        && now.device_id == c.device_id
        && now.signing_credential_ref == c.signing_credential_ref
        && now.hpke_credential_ref == c.hpke_credential_ref
}

/// v2.11 RS (ADR 0002 Q-63): Reset of this root device once the ticket
/// listing `me` serves its signed revocation from the issuer it trusts
/// ([`fleet_custody::reset_revocation_holds`]). Every TRK, every fleet key
/// generation, the root and custody state and the signing and HPKE
/// credentials go; nothing is kept, as the revocation is signed. The pin
/// stays, so the machine can Join again.
fn reset_root_device(
    c: team_config::TeamConfig,
    me: &fleet_client::AccountDeviceStatus,
) -> Result<team_config::TeamStatus, String> {
    let e = |e: anyhow::Error| e.to_string();
    let device = me
        .device
        .as_ref()
        .filter(|d| d.status == "revoked")
        .ok_or_else(|| crate::errcode::code("fleet.resetNeedsSignedRevocation"))?;
    let root = root_bootstrap::load().map_err(e)?;
    let custody = fleet_custody::load().map_err(e)?;
    let own = c.signing_key().map_err(e)?.verifying_key().to_bytes();
    let listed: Vec<(&str, &str)> = me
        .listed
        .iter()
        .filter(|d| !d.revocation.is_empty())
        .map(|d| {
            (
                d.revocation.as_str(),
                d.revocation_issuer_public_key.as_str(),
            )
        })
        .collect();
    let revocation = (
        device.revocation.as_str(),
        device.revocation_issuer_public_key.as_str(),
    );
    fleet_custody::reset_revocation_holds(&custody, &root, &own, revocation, &listed).map_err(e)?;
    let mut now = team_config::load().map_err(e)?;
    if !same_identity(&now, &c) || !own_root_state(&now).map_err(e)? {
        return Err(crate::errcode::code("fleet.identityChanged"));
    }
    eprintln!("[recovery] reset of a revoked root device: its keys and custody go");
    if root.trk_ref.starts_with("tenant-root.") {
        let _ = credential::forget(&root.trk_ref);
    }
    if let Some(r) = root
        .root_rotation
        .as_ref()
        .filter(|r| !r.trk_nonce.is_empty())
    {
        let _ = credential::forget(&root_bootstrap::trk_ref(&root.tenant_id, &r.trk_nonce));
    }
    fleet_custody::forget_setup_keys().map_err(e)?;
    fleet_keys::forget_fleet(&sync_cmd::fleet_id(&now)).map_err(e)?;
    // The root state goes before the custody state: a wipe that stops in
    // between leaves a device that is no longer root, which Reset clears as
    // the revoked device it is; the other way round it would be refused.
    for path in [store::custody_bootstrap_path(), store::fleet_custody_path()] {
        match std::fs::remove_file(path.map_err(e)?) {
            Err(err) if err.kind() != std::io::ErrorKind::NotFound => return Err(err.to_string()),
            _ => {}
        }
    }
    let refs = clear_identity(&mut now);
    team_config::save(&now).map_err(e)?;
    for reference in refs.iter().filter(|r| !r.is_empty()) {
        let _ = credential::forget(reference);
    }
    team_config::status().map_err(e)
}

/// Import a recovery bundle (v0.2.2b plan, section 4.I): this device becomes
/// the root custodian the bundle restores, then collects the fleet key and
/// returns that report. `old_device_lost` is the user's confirmation that the
/// old root device is lost or its keys were reset. The passphrase and
/// password serve this command only. A failed collect leaves the import
/// done, and Collect key custody runs it again.
#[tauri::command]
async fn team_import_recovery_bundle(
    path: String,
    passphrase: String,
    username: String,
    password: String,
    old_device_lost: bool,
) -> Result<serde_json::Value, String> {
    {
        let _running = fleet_custody::begin().map_err(|e| e.to_string())?;
        recovery_import::run(
            std::path::Path::new(&path),
            &passphrase,
            username.trim(),
            &password,
            old_device_lost,
            &mut recovery_import::save,
        )
        .await
        .map_err(|e| e.to_string())?;
    }
    imported_collect(team_collect_custody(username, password).await)
}

/// The collect after an import: its failure says the import itself is done,
/// so the UI offers Collect key custody rather than a new import.
fn imported_collect(
    report: Result<serde_json::Value, String>,
) -> Result<serde_json::Value, String> {
    eprintln!(
        "[recovery] import collect: {}",
        if report.is_ok() { "ok" } else { "failed" }
    );
    report
        .map_err(|e| crate::errcode::code_with("recovery.importedCollectFailed", &[("error", &e)]))
}

/// Whether the saved root state, finished or not, names this tenant and
/// device: such a device never enrolls again. One that does not load is the
/// error.
fn own_root_state(c: &team_config::TeamConfig) -> anyhow::Result<bool> {
    root_bootstrap::load().map(|root| {
        root.tenant_id.eq_ignore_ascii_case(&c.tenant_id)
            && root.device_id.eq_ignore_ascii_case(&c.device_id)
    })
}

/// Whether a device the server lists as `status` may enroll again: while
/// pending or revoked, or active without a pin here.
fn enroll_again_allowed(status: Option<&str>, pinned: bool) -> bool {
    match status {
        Some("pending" | "revoked") => true,
        Some("active") => !pinned,
        _ => false,
    }
}

/// Collect the root key grants issued to this device and report what opened.
///
/// The tenant root key itself is never returned to the caller: this reports
/// whether custody is in place, not the key. A grant that fails to open is
/// reported rather than skipped, because silently ignoring it would hide a
/// device that cannot actually decrypt anything.
///
/// Both reads go through this device's own session (ADR 0002 D-9), so they
/// need the account login; the password is used for one login and never
/// stored.
#[tauri::command]
async fn team_collect_custody(
    username: String,
    password: String,
) -> Result<serde_json::Value, String> {
    let c = team_config::load().map_err(|e| e.to_string())?;
    if !c.can_sync() {
        return Err(crate::errcode::code("fleet.deviceNotEnrolled"));
    }
    if username.trim().is_empty() || password.is_empty() {
        return Err(crate::errcode::code("fleet.setAccountFirst"));
    }
    // A collect may save an ack to the state a running setup also writes.
    let _running = fleet_custody::begin().map_err(|e| e.to_string())?;
    let signer = c.signing_key().map_err(|e| e.to_string())?;
    let seed = c.hpke_seed().map_err(|e| e.to_string())?;
    let (device_sk, _pk) = shardx_core::grants::derive_keypair(&seed);

    let client =
        fleet_client::FleetClient::new(&c.server_url, &c.token).map_err(|e| e.to_string())?;
    let login = fleet_client::AccountLogin {
        tenant_id: &c.tenant_id,
        username: username.trim(),
        password: &password,
    };
    let session = client
        .open_device_session(&login, &c.device_id, &signer, &seed)
        .await
        .map_err(|e| e.to_string())?;
    let access = session.access_token.as_str();
    // Recovery must keep working: even a lapse only logs here.
    log_renewal(&renew_custody(&client, &c, access).await);
    let result = async {
        let grants = client
            .root_key_grants(access, &c.tenant_id, &c.device_id)
            .await
            .map_err(|e| e.to_string())?;
        // A fleet grant is opened only once it verifies: see `custody_report`.
        let fleet = collect_fleet_grant(&client, &c, access, &device_sk, true).await?;
        custody_report(&device_sk, &grants, fleet)
    }
    .await;
    client.end_session(access).await;
    result
}

/// v2.10 4.R: this root custodian's renewal step over the session `access`,
/// under the custody lock the caller holds ([`root_bootstrap::renew`]). Any
/// other device has nothing to renew. A finished renewal asks for the
/// recovery bundle again: the saved one names the replaced root grant.
pub(crate) async fn renew_custody(
    client: &fleet_client::FleetClient,
    c: &team_config::TeamConfig,
    access: &str,
) -> anyhow::Result<root_bootstrap::RenewalOutcome> {
    let Some(pin) = bootstrap_anchor(c) else {
        return Ok(root_bootstrap::RenewalOutcome::NotCustodian);
    };
    fleet_custody::prompt_unexported_renewal()?;
    let mut state = root_bootstrap::load()?;
    let custody = fleet_custody::load()?;
    let signer = c.signing_key()?;
    let seed = zeroize::Zeroizing::new(c.hpke_seed()?);
    let me = recipient(c)?;
    let fleet_hex = sync_cmd::fleet_id(c);
    let now = root_bootstrap::now_ms();
    let device = root_bootstrap::RenewingDevice {
        account_id: &c.account_id,
        signer: &signer,
        hpke_seed: &seed,
    };
    let fleet_key = |generation: u64| {
        verified_fleet_key(&fleet_hex, &pin, &me, generation, now)?
            .ok_or_else(|| anyhow::anyhow!(crate::errcode::code("fleet.createFleetKeyFirst")))
    };
    let (device_sk, _) = shardx_core::grants::derive_keypair(&seed);
    let collect = async |generation: u64| {
        let kept = collect_fleet_grant(client, c, access, &device_sk, false)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        match setup_collect_error(kept, generation) {
            Some(e) => Err(anyhow::anyhow!(e)),
            None => Ok(()),
        }
    };
    let device_grant = root_bootstrap::own_device_grant(&state);
    let outcome = root_bootstrap::renew(
        client,
        access,
        &device,
        &custody,
        device_grant.as_deref(),
        now,
        fleet_key,
        collect,
        &mut state,
        &mut |s| root_bootstrap::save(s),
    )
    .await?;
    fleet_custody::prompt_unexported_renewal()?;
    renew_members_quietly(client, c, access, &pin).await;
    Ok(outcome)
}

/// v2.11 MR: the member renewal pass after this custodian's own renewal
/// step ([`fleet_custody::renew_members`]), best effort: a failure is
/// logged by its code and never fails the command or sync that ran it.
async fn renew_members_quietly(
    client: &fleet_client::FleetClient,
    c: &team_config::TeamConfig,
    access: &str,
    pin: &(shardx_core::trust_chain::Binding, [u8; 32]),
) {
    let renewed = async {
        let signer = c.signing_key()?;
        let seed = zeroize::Zeroizing::new(c.hpke_seed()?);
        let me = recipient(c)?;
        let fleet_hex = sync_cmd::fleet_id(c);
        let now = root_bootstrap::now_ms();
        let device = fleet_custody::FleetDevice {
            tenant_id: &c.tenant_id,
            device_id: &c.device_id,
            account_id: &c.account_id,
            signer: &signer,
            hpke_seed: &seed,
            vault: &fleet_custody::CredentialFkekStore,
        };
        let fleet_key = |generation: u64| {
            verified_fleet_key(&fleet_hex, pin, &me, generation, now)?
                .ok_or_else(|| anyhow::anyhow!(crate::errcode::code("fleet.createFleetKeyFirst")))
        };
        let mut db = team::db::Db::open()?;
        let mut ledger = fleet_custody::Ledger { db: &mut db, pin };
        let mut state = fleet_custody::load()?;
        fleet_custody::renew_members(
            client,
            access,
            &device,
            &mut ledger,
            fleet_key,
            now,
            &mut state,
            &mut |s| fleet_custody::save(s),
        )
        .await
    }
    .await;
    if let Err(e) = renewed {
        eprintln!(
            "[members] renewal failed {}",
            recovery_import::error_code(&e.to_string())
        );
    }
}

/// Logs a renewal step that did something, or failed, by its error code.
fn log_renewal(outcome: &anyhow::Result<root_bootstrap::RenewalOutcome>) {
    match outcome {
        Ok(
            o @ (root_bootstrap::RenewalOutcome::Renewed | root_bootstrap::RenewalOutcome::Busy),
        ) => {
            eprintln!("[renewal] {o:?}")
        }
        Ok(_) => {}
        Err(e) => eprintln!(
            "[renewal] failed {}",
            recovery_import::error_code(&e.to_string())
        ),
    }
}

/// D9: the renewal step a custodian command runs first, under its custody
/// lock. A lapse stops the command; any other renewal error is logged, and
/// the next command or sync tries again.
async fn renew_first(
    client: &fleet_client::FleetClient,
    c: &team_config::TeamConfig,
    access: &str,
) -> Result<(), String> {
    renewal_gate(renew_custody(client, c, access).await)
}

/// [`renew_first`]'s rule: only a lapse stops the command.
fn renewal_gate(outcome: anyhow::Result<root_bootstrap::RenewalOutcome>) -> Result<(), String> {
    if let Err(e) = &outcome {
        if crate::errcode::has_code(&e.to_string(), "fleet.custodyLapsed") {
            return Err(e.to_string());
        }
    }
    log_renewal(&outcome);
    Ok(())
}

/// D9 after a published sync or an export: the renewal step, best effort,
/// skipped while another custody command holds the lock. The outcome is
/// logged; callers never let it change their own result.
pub(crate) async fn renew_quietly(
    client: &fleet_client::FleetClient,
    c: &team_config::TeamConfig,
    access: &str,
) -> anyhow::Result<root_bootstrap::RenewalOutcome> {
    let outcome = match fleet_custody::begin() {
        Ok(_running) => renew_custody(client, c, access).await,
        Err(_) => Ok(root_bootstrap::RenewalOutcome::Busy),
    };
    log_renewal(&outcome);
    outcome
}

/// Renew custody (v2.10 4.R, the Team page's action): the root custodian's
/// renewal step now. A renewal in progress resumes; otherwise only a due
/// one runs. The password is used for one login and never stored.
#[tauri::command]
async fn team_renew_custody(
    username: String,
    password: String,
) -> Result<root_bootstrap::RenewalOutcome, String> {
    let c = team_config::load().map_err(|e| e.to_string())?;
    if !c.can_sync() {
        return Err(crate::errcode::code("fleet.deviceNotEnrolled"));
    }
    bootstrap_anchor(&c).ok_or_else(|| crate::errcode::code("fleet.notCustodian"))?;
    let _running = fleet_custody::begin().map_err(|e| e.to_string())?;
    // v2.11 MR: Renew custody also looks at every member now.
    let mut custody = fleet_custody::load().map_err(|e| e.to_string())?;
    custody.member_renewal.checked_ms = 0;
    fleet_custody::save(&custody).map_err(|e| e.to_string())?;
    let (client, session) = open_session(&c, &username, &password).await?;
    let access = session.access_token.as_str();
    let renewed = renew_custody(&client, &c, access).await;
    client.end_session(access).await;
    log_renewal(&renewed);
    renewed.map_err(|e| {
        let text = e.to_string();
        if crate::errcode::has_code(&text, "fleet.custodyLapsed") {
            text
        } else {
            crate::errcode::code_with(
                "fleet.custodyRenewalFailed",
                &[("code", recovery_import::error_code(&text))],
            )
        }
    })
}

/// Rotate root key (v2.11 sequence RR, ADR 0002 Q-59) as the tenant's root
/// custodian, or resume the run: a new TRK, every retained fleet key wrapped
/// under it, the recovery bundle written to `bundle_path` under `passphrase`
/// and pinned before the create (a resumed run keeps the path it saved),
/// then the activation. The fleet key rotation that follows is the next
/// step. The password is used for one login and never stored.
#[tauri::command]
async fn team_rotate_root(
    username: String,
    password: String,
    bundle_path: String,
    passphrase: String,
) -> Result<root_bootstrap::BootstrapStatus, String> {
    let c = team_config::load().map_err(|e| e.to_string())?;
    if !c.can_sync() {
        return Err(crate::errcode::code("fleet.deviceNotEnrolled"));
    }
    if !c.can_receive_custody() {
        return Err(crate::errcode::code("teamConfig.hpkeKeyUnusable"));
    }
    let pin = bootstrap_anchor(&c).ok_or_else(|| crate::errcode::code("fleet.notCustodian"))?;
    handed_over()?;
    let signer = c.signing_key().map_err(|e| e.to_string())?;
    let seed = zeroize::Zeroizing::new(c.hpke_seed().map_err(|e| e.to_string())?);
    let fleet_hex = sync_cmd::fleet_id(&c);
    let local = fleet_keys::verified_keys(&fleet_hex).map_err(|e| e.to_string())?;
    let newest = local.iter().map(|(g, _)| *g).max();
    let _running = fleet_custody::begin().map_err(|e| e.to_string())?;
    let (client, session) = open_session(&c, &username, &password).await?;
    let access = session.access_token.as_str();
    let result = async {
        // RR step 1: the RotationGrant links a live own tenant approval.
        renew_first(&client, &c, access).await?;
        let error = |e: anyhow::Error| e.to_string();
        let mut state = root_bootstrap::load().map_err(error)?;
        let custody = fleet_custody::load().map_err(error)?;
        let saved = state
            .root_rotation
            .as_ref()
            .filter(|r| !r.done && !r.recovery_path.is_empty())
            .map(|r| std::path::PathBuf::from(&r.recovery_path));
        let recovery = root_bootstrap::RecoveryExport {
            path: saved
                .as_deref()
                .unwrap_or(std::path::Path::new(&bundle_path)),
            passphrase: &passphrase,
        };
        let me = root_bootstrap::RenewingDevice {
            account_id: &c.account_id,
            signer: &signer,
            hpke_seed: &seed,
        };
        let mut db = team::db::Db::open().map_err(error)?;
        let mut ledger = fleet_custody::Ledger {
            db: &mut db,
            pin: &pin,
        };
        let rotated = root_rotation::rotate_root(
            &client,
            access,
            &me,
            &root_bootstrap::CredentialTrkStore,
            &mut ledger,
            &custody,
            &local,
            &recovery,
            root_bootstrap::now_ms(),
            &mut state,
            &mut |s| root_bootstrap::save(s),
        )
        .await;
        match &rotated {
            Ok(()) => eprintln!("[root-rotation] done"),
            Err(e) => eprintln!(
                "[root-rotation] stopped {}",
                recovery_import::error_code(&e.to_string())
            ),
        }
        rotated.map_err(error)?;
        // The new bundle holds every retained key and the current grant.
        let grant = root_bootstrap::root_grant_sha256(&state);
        if let Err(e) = newest.map_or(Ok(()), |n| fleet_custody::exported(n, &grant)) {
            eprintln!("[recovery] export prompt: not cleared ({e:#})");
        }
        Ok::<(), String>(())
    }
    .await;
    client.end_session(access).await;
    result?;
    root_bootstrap::status().map_err(|e| e.to_string())
}

/// Collect key custody's fleet step for a published sync the server refused
/// under a rotated key (`sync_cmd`), over that sync's session `access`, under
/// the custody lock a collect takes.
pub(crate) async fn collect_after_refusal(
    client: &fleet_client::FleetClient,
    c: &team_config::TeamConfig,
    access: &str,
) -> Result<FleetGrant, String> {
    let _running = fleet_custody::begin().map_err(|e| e.to_string())?;
    let seed = zeroize::Zeroizing::new(c.hpke_seed().map_err(|e| e.to_string())?);
    let (device_sk, _) = shardx_core::grants::derive_keypair(&seed);
    collect_fleet_grant(client, c, access, &device_sk, true).await
}

/// What became of this device's D-9 `DeviceHpkeGrant` of the fleet's ACTIVE
/// generation: the readback holds at most one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FleetGrant {
    /// No ACTIVE generation, no grant filed, or a revoked one.
    None,
    /// Filed, but this device pins no anchor to verify it against.
    Waiting,
    /// Verified, opened and in the fleet key store, for this generation.
    Opened(u64),
    /// Filed, but the grant did not verify or open.
    Failed,
    /// Filed, but the evidence could not be fetched: this error.
    Unfetched(String),
    /// Verified and opened, but the store holds another key, or one it
    /// cannot read, for its generation (rule 5, `KEY_SUBSTITUTION_DETECTED`).
    Substituted,
    /// Filed, but more than one generation above the highest this device
    /// verified: it missed a rotation and must enroll again (Q-27).
    MissedRotations,
}

/// Reads, over the device session `access`, this device's grant of the
/// fleet's ACTIVE generation and, when this device pinned an anchor, the
/// tenant trust evidence, and keeps the FKEK only if rule 5 accepts it. With
/// `ack`, a kept key's grant is then acknowledged once.
async fn collect_fleet_grant(
    client: &fleet_client::FleetClient,
    c: &team_config::TeamConfig,
    access: &str,
    device_sk: &[u8],
    ack: bool,
) -> Result<FleetGrant, String> {
    let fleet_id = sync_cmd::fleet_id(c);
    let Some(generation) = client
        .active_fleet_generation(access, &c.tenant_id, &fleet_id)
        .await
        .map_err(|e| e.to_string())?
    else {
        return Ok(FleetGrant::None);
    };
    // An unreadable or newer team database disables this before any key is
    // read (plan L2032).
    let mut ledger = team::db::Db::open().map_err(|e| e.to_string())?;
    let grant = match client
        .read_fleet_device_grant(access, &fleet_id, generation, &c.device_id)
        .await
    {
        Ok(Some(d)) => live_fleet_grant(&d, &fleet_id, generation, &c.device_id),
        Ok(None) => Ok(None),
        Err(e) => Err(e.to_string()),
    };
    let pin = pinned_anchor(c);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    let pages = match (&grant, &pin) {
        (Ok(Some(_)), Some(pin)) => Some(
            team::ledger::closure_evidence(
                client,
                access,
                &c.tenant_id,
                &mut ledger,
                pin,
                &[],
                now,
            )
            .await,
        ),
        _ => None,
    };
    let Some((container, acknowledged)) = grant? else {
        return Ok(FleetGrant::None);
    };
    let (Some(pin), Some(pages)) = (pin, pages) else {
        return Ok(FleetGrant::Waiting);
    };
    // Root custody is still reported when only the evidence fetch failed.
    let (pages, closure) = match pages {
        Ok(pages) => pages,
        Err(e) => return Ok(FleetGrant::Unfetched(e.to_string())),
    };
    let me = recipient(c).map_err(|e| e.to_string())?;
    let fleet = fleet_client::decode_hex16(&fleet_id, "fleet_id").map_err(|e| e.to_string())?;
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
        closure,
    )?;
    let kept = match fkek {
        None if missed_rotations(&ledger, &pin.0, &fleet, generation)? => {
            FleetGrant::MissedRotations
        }
        fkek => keep_fleet_key(&fleet_id, generation, fkek)?,
    };
    if ack && kept == FleetGrant::Opened(generation) {
        fleet_custody::ack_device_grant(client, access, &container, acknowledged)
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(kept)
}

/// Why Create fleet key, or Rotate fleet key for its new generation, stops
/// when its verified collect did not keep `generation`; `None` once it did.
/// Only a grant the evidence refused reads as refused evidence: an evidence
/// fetch that failed keeps its own error.
fn setup_collect_error(fleet: FleetGrant, generation: u64) -> Option<String> {
    let code = |key| Some(crate::errcode::code(key));
    match fleet {
        FleetGrant::Opened(g) if g == generation => None,
        FleetGrant::Unfetched(error) => Some(error),
        FleetGrant::Failed => code("fleet.trustEvidenceRefused"),
        FleetGrant::Substituted => code("fleet.keySubstitutionDetected"),
        FleetGrant::MissedRotations => code("fleet.enrollAgainMissedRotations"),
        // The root state was checked as activated, so its pin is readable.
        FleetGrant::Waiting => code("fleet.custodyStateCorrupt"),
        FleetGrant::None | FleetGrant::Opened(_) => code("fleet.custodyReplyMismatch"),
    }
}

/// Q-27: whether a fleet grant of `generation` lies more than one step above
/// the highest generation this device verified. `open_fleet_grant` refuses
/// such a grant, as it does one below; only this one asks to enroll again.
fn missed_rotations(
    ledger: &team::db::Db,
    binding: &shardx_core::trust_chain::Binding,
    fleet_id: &[u8; 16],
    generation: u64,
) -> Result<bool, String> {
    let highest = team::ledger::highest_generation(ledger, binding, fleet_id).map_err(|e| {
        eprintln!("[fleet] trust ledger: {e:#}");
        crate::errcode::code("team.trustLedgerUnreadable")
    })?;
    Ok(highest.is_some_and(|h| generation > h.saturating_add(1)))
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

/// The binding and anchor `A0` this device pinned: the device that
/// bootstrapped the tenant's custody keeps them in its root state, and
/// `open_fleet_grant` keeps the first one in the W6 ledger. Any other device
/// has the one pin of its tenant in the ledger, from the join ceremony (ADR
/// 0002 Q-12), or none. A ledger that does not read counts as none here,
/// which only ever refuses trust; see [`read_pinned_anchor`].
fn pinned_anchor(
    c: &team_config::TeamConfig,
) -> Option<(shardx_core::trust_chain::Binding, [u8; 32])> {
    read_pinned_anchor(c).ok().flatten()
}

/// [`pinned_anchor`], with a ledger that does not read as the error: a
/// decision that an unpinned device may lose its identity never takes an
/// unreadable pin for none.
fn read_pinned_anchor(
    c: &team_config::TeamConfig,
) -> anyhow::Result<Option<(shardx_core::trust_chain::Binding, [u8; 32])>> {
    if let Some(pin) = bootstrap_anchor(c) {
        return Ok(Some(pin));
    }
    let tenant = fleet_client::decode_hex16(&c.tenant_id, "tenant_id")?;
    Ok(tenant_pin(&tenant)?.map(|(binding, anchor, _)| (binding, anchor)))
}

/// The ledger's one pin of `tenant`, without creating a ledger that does not
/// exist yet.
fn tenant_pin(
    tenant: &[u8; 16],
) -> anyhow::Result<Option<(shardx_core::trust_chain::Binding, [u8; 32], String)>> {
    if !team::db::Db::path()?.try_exists()? {
        return Ok(None);
    }
    team::ledger::tenant_pin(&team::db::Db::open()?, tenant)
}

fn bootstrap_anchor(
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
/// reaches the anchor is recorded, with the grant it opened (G2-35);
/// `closure` says `pages` is a closure listing (`ledger::closure_evidence`).
#[allow(clippy::too_many_arguments)]
fn open_fleet_grant(
    container: &[u8],
    pages: &[Vec<shardx_core::trust_evidence::TenantTrustEvidencePageV2>],
    (binding, anchor): &(shardx_core::trust_chain::Binding, [u8; 32]),
    me: &shardx_core::trust_chain::Recipient,
    fleet_id: &[u8; 16],
    generation: u64,
    device_sk: &[u8],
    now: u64,
    ledger: &mut team::db::Db,
    server_url: &str,
    closure: bool,
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
    if !ledger::pin_anchor(ledger, binding, anchor, ledger::BOOTSTRAP, now).map_err(failed)?
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
    ledger::record(ledger, binding, &seen, &chain, opened, closure, now).map_err(|e| {
        // D12: kept as is, so it never reads as an unreadable ledger.
        if crate::errcode::has_code(&e.to_string(), "fleet.trustClosureNeeded") {
            e.to_string()
        } else {
            failed(e)
        }
    })?;
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
        let fleet = fleet_client::decode_hex16(&sync_cmd::fleet_id(c), "fleet_id")?;
        fleet_key_verifies(&ledger, &pin, &recipient(c)?, &fleet, generation, key, now)
    };
    verifies().unwrap_or_else(|e| {
        eprintln!("[fleet] trust ledger: {e:#}");
        false
    })
}

/// The exact grant container of the descriptor when it is an unrevoked
/// `DeviceHpkeGrant` of exactly this fleet, generation and device, with
/// whether it is acknowledged; `None` when it is revoked. A descriptor naming
/// anything else is a bad reply.
/// Nothing here is trusted: the container is verified against the trust
/// evidence (`open_fleet_grant`).
fn live_fleet_grant(
    descriptor: &[u8],
    fleet_id: &str,
    generation: u64,
    device_id: &str,
) -> Result<Option<(Vec<u8>, bool)>, String> {
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
    let (live, acknowledged) = match text("grant_state") {
        Some("PENDING_ACK") => (true, false),
        Some("ACKNOWLEDGED") => (true, true),
        Some("REVOKED") => (false, false),
        _ => return Err(bad()),
    };
    match field("exact_signed_container_bytes") {
        Some(Value::Bytes(container)) => Ok(live.then(|| (container.clone(), acknowledged))),
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
        FleetGrant::Failed
        | FleetGrant::Unfetched(_)
        | FleetGrant::Substituted
        | FleetGrant::MissedRotations => (0, 1, None),
        FleetGrant::None | FleetGrant::Waiting => (0, 0, None),
    };
    let fleet_grants_waiting = usize::from(matches!(
        fleet,
        FleetGrant::Waiting
            | FleetGrant::Failed
            | FleetGrant::Unfetched(_)
            | FleetGrant::Substituted
            | FleetGrant::MissedRotations
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
        "fleet_enroll_again": fleet == FleetGrant::MissedRotations,
        "can_sync_without_passphrase": false,
    }))
}

/// Decode a hex string from the server into bytes. The error never carries
/// the input, which a hostile server may fill with a secret it was sent.
fn hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    fleet_client::decode_hex(s).ok_or_else(|| crate::errcode::code("fleet.malformedHexFromServer"))
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

    /// D9: a custodian command stops on a lapse only; any other renewal
    /// error is logged and the command goes on.
    #[test]
    fn renew_first_stops_only_on_a_lapse() {
        use root_bootstrap::RenewalOutcome;
        let failed = anyhow::anyhow!(crate::errcode::code_with(
            "fleet.refusedCustody",
            &[("status", "500")]
        ));
        assert_eq!(renewal_gate(Err(failed)), Ok(()));
        assert_eq!(renewal_gate(Ok(RenewalOutcome::Renewed)), Ok(()));
        let lapsed = anyhow::anyhow!(crate::errcode::code("fleet.custodyLapsed"));
        let err = renewal_gate(Err(lapsed)).unwrap_err();
        assert!(
            crate::errcode::has_code(&err, "fleet.custodyLapsed"),
            "{err}"
        );
    }

    /// A collect that fails after an import says the import is done, and
    /// keeps the collect's own error; a report passes through.
    #[test]
    fn a_failed_collect_after_an_import_says_the_import_is_done() {
        let failed = errcode::code_with(
            "fleet.refusedCustody",
            &[("status", "503"), ("detail", "down")],
        );
        let err = imported_collect(Err(failed)).unwrap_err();
        assert!(
            errcode::has_code(&err, "recovery.importedCollectFailed"),
            "{err}"
        );
        assert!(errcode::has_code(
            &errcode::unescape_value(&err),
            "fleet.refusedCustody"
        ));
        let report = serde_json::json!({ "fleet_opened": 1 });
        assert_eq!(imported_collect(Ok(report.clone())), Ok(report));
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
        grant_of(FLEET, issuer, me, generation, common, fkek_key_id, fkek)
    }

    /// `grant_at` for the fleet `fleet_id`.
    fn grant_of(
        fleet_id: [u8; 16],
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
            fleet_id,
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
                &[pages.to_vec()],
                pin,
                to,
                &FLEET,
                generation,
                sk,
                now,
                &mut ledger,
                "https://fleet.test",
                true,
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
            &[pages.to_vec()],
            &pin,
            &me.to,
            &FLEET,
            generation,
            &me.hpke_sk,
            now,
            &mut ledger,
            "https://fleet.test",
            true,
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

    /// D12 (U1b): a fleet key opened in the evaluation that counts custodian
    /// D's revocation, a closure listing, keeps that listing as its pages and
    /// reverifies from them. Outside a closure the same evaluation opens and
    /// records nothing.
    #[test]
    fn a_fleet_key_opened_in_a_closure_evaluation_reverifies_from_its_stored_pages() {
        let me = me();
        let fkek = [0x5a; 32];
        let grant = fleet_grant(&me, shardx_core::fleet_grants::fkek_key_id(&fkek), &fkek);
        let revocation = revoke_d(&me, |_| {});
        let pages = with_d(
            &me,
            evidence(&me, grant.clone()),
            Some(T0 + 300 * DAY),
            vec![revocation.clone()],
        );
        let (_dir, path) = ledger_at();
        let pin = (BINDING, me.to.signing_key_id);
        let open = |closure| {
            let mut ledger = team::db::Db::open_at(&path).unwrap();
            open_fleet_grant(
                &grant,
                std::slice::from_ref(&pages),
                &pin,
                &me.to,
                &FLEET,
                1,
                &me.hpke_sk,
                T0 + DAY,
                &mut ledger,
                "https://fleet.test",
                closure,
            )
        };
        let refused = open(false).unwrap_err();
        assert!(refused.contains("fleet.trustClosureNeeded"), "{refused}");
        assert!(proven(&path).is_empty(), "nothing recorded");

        assert_eq!(open(true).unwrap().as_deref(), Some(&fkek));
        assert_eq!(proven(&path), [(hex(&d_id()), "DEVICE_REVOCATION".into())]);
        let db = team::db::Db::open_at(&path).unwrap();
        let (_, kept) = team::ledger::fleet_key_grant(&db, &BINDING, &pin.1, &FLEET, 1)
            .unwrap()
            .expect("the grant is kept");
        assert!(
            kept[0][0].containers.contains(&revocation),
            "the closure listing is the kept one"
        );
        assert!(fleet_key_verifies(&db, &pin, &me.to, &FLEET, 1, &fkek, T0 + 2 * DAY).unwrap());
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
        // F1: an approval signed by an outsider that no custodian authorised;
        // the server would never have filed it.
        let outsider = shardx_core::signing::Ed25519SigningKey::from_bytes(&[0x5a; 32]);
        let forged = |kind, scope_id| {
            let a = DeviceApprovalV2 {
                common: common(22),
                subject_account_id: [6; 16],
                subject_device_id: [0x6e; 16],
                subject_signing_key_id: m_key,
                subject_hpke_key_id: [0x6f; 32],
                approval_scope_kind: kind,
                approval_scope_id: scope_id,
            };
            build_record(&outsider, DOMAIN_DEVICE_APPROVAL, &a.encode())
        };
        let counts_with =
            |revoke_scope: (CapabilityScopeKind, [u8; 16]),
             tenant_approved: bool,
             outsider_approved: Option<(ApprovalScopeKind, [u8; 16])>| {
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
                if let Some((kind, scope_id)) = outsider_approved {
                    p.signing_public_keys
                        .push(outsider.verifying_key().to_bytes());
                    p.containers.push(forged(kind, scope_id));
                }
                let (_dir, path) = ledger_at();
                collect_at(&path, &pages, &[], 1, T0 + DAY);
                proven(&path) == [(hex(&m_key), "DEVICE_REVOCATION".into())]
            };
        let counts =
            |revoke_scope, tenant_approved| counts_with(revoke_scope, tenant_approved, None);
        assert!(counts((CapabilityScopeKind::Fleet, FLEET), false));
        for outsider in [
            (ApprovalScopeKind::Tenant, TENANT),
            (ApprovalScopeKind::Fleet, other_fleet),
        ] {
            assert!(
                counts_with((CapabilityScopeKind::Fleet, FLEET), false, Some(outsider)),
                "an outsider's approval must not widen the scope"
            );
        }
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

    /// Grants of `FLEET` generations 1, 2 and 3 to this device, each under
    /// the key `[generation; 32]`, and evidence holding all three.
    fn three_generations(me: &Me) -> (Vec<Vec<u8>>, Vec<Page>) {
        let grants: Vec<Vec<u8>> = (1..=3u8)
            .map(|g| {
                let k = [g; 32];
                let kid = shardx_core::fleet_grants::fkek_key_id(&k);
                grant_by(&me.sk, me, g.into(), 40 + g, kid, &k)
            })
            .collect();
        let mut pages = evidence(me, grants[0].clone());
        pages[0].containers.extend(grants[1..].iter().cloned());
        (grants, pages)
    }

    /// Q-27: a grant two generations above the highest verified is refused
    /// as before, and the collect report asks this device to enroll again.
    #[test]
    fn a_grant_two_generations_up_asks_to_enroll_again() {
        let me = me();
        let (grants, pages) = three_generations(&me);
        let (_dir, path) = ledger_at();
        assert_eq!(collect(&path, &pages, &grants[0], 1), Some([1; 32]));
        assert_eq!(collect(&path, &pages, &grants[2], 3), None);
        let ledger = team::db::Db::open_at(&path).unwrap();
        assert_eq!(missed_rotations(&ledger, &BINDING, &FLEET, 3), Ok(true));
        let report = custody_report(&[], &[], FleetGrant::MissedRotations).unwrap();
        assert_eq!(report["fleet_enroll_again"], true);
        assert_eq!(report["fleet_opened"], 0);
        assert_eq!(report["fleet_failed"], 1);
    }

    /// A grant below the highest verified generation stays the silent
    /// refusal it was: no enroll-again.
    #[test]
    fn a_grant_below_the_highest_generation_is_refused_silently() {
        let me = me();
        let (grants, pages) = three_generations(&me);
        let (_dir, path) = ledger_at();
        assert_eq!(collect(&path, &pages, &grants[1], 2), Some([2; 32]));
        assert_eq!(collect(&path, &pages, &grants[0], 1), None);
        let ledger = team::db::Db::open_at(&path).unwrap();
        assert_eq!(missed_rotations(&ledger, &BINDING, &FLEET, 1), Ok(false));
        let report = custody_report(&[], &[], FleetGrant::Failed).unwrap();
        assert_eq!(report["fleet_enroll_again"], false);
        assert_eq!(report["fleet_failed"], 1);
    }

    /// A member one rotation behind collects N+1 and keeps N beside it, so
    /// old heads stay readable and the next push seals under N+1.
    #[test]
    fn a_member_one_generation_behind_collects_the_new_key_and_keeps_the_old() {
        let _config = store::config_root_test_lock()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().unwrap();
        store::set_config_root(Some(dir.path().to_path_buf()));
        let me = me();
        let (grants, pages) = three_generations(&me);
        let (_ledger_dir, path) = ledger_at();
        let fleet = hex(&FLEET);
        let keep = |g: u64| {
            let key = collect(&path, &pages, &grants[g as usize - 1], g);
            keep_fleet_key(&fleet, g, key.map(zeroize::Zeroizing::new))
        };
        assert_eq!(keep(1), Ok(FleetGrant::Opened(1)));
        let ledger = team::db::Db::open_at(&path).unwrap();
        assert_eq!(missed_rotations(&ledger, &BINDING, &FLEET, 2), Ok(false));
        assert_eq!(keep(2), Ok(FleetGrant::Opened(2)));
        let held: Vec<(u64, [u8; 32])> = fleet_keys::verified_keys(&fleet)
            .unwrap()
            .into_iter()
            .map(|(g, k)| (g, *k))
            .collect();
        store::set_config_root(None);
        assert_eq!(held, [(1, [1; 32]), (2, [2; 32])]);
        let report = custody_report(&[], &[], FleetGrant::Opened(2)).unwrap();
        assert_eq!(report["newest_fleet_generation"], 2);
        assert_eq!(report["fleet_enroll_again"], false);
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
            assert!(team::ledger::pin_anchor(
                &db,
                &BINDING,
                &me.to.signing_key_id,
                team::ledger::BOOTSTRAP,
                T0
            )
            .unwrap());
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
            team::ledger::pin_anchor(&db, &BINDING, &anchor, team::ledger::BOOTSTRAP, T0).unwrap()
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

    /// S6 (plan v0.2.2b): a device 2.7.x enrolled has no fleet ID. The default
    /// fleet has the tenant's ID, so pull falls back to it and still tries the
    /// key of the grant this device verified.
    #[test]
    fn a_device_enrolled_without_a_fleet_id_pulls_with_its_verified_fleet_key() {
        let _config = store::config_root_test_lock()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let me = me();
        let fkek = [0x6e; 32];
        let kid = shardx_core::fleet_grants::fkek_key_id(&fkek);
        let grant = grant_of(TENANT, &me.sk, &me, 1, common(40), kid, &fkek);
        let pages = evidence(&me, grant.clone());
        let c = team_config::TeamConfig {
            tenant_id: hex(&TENANT),
            account_id: hex(&me.to.account_id),
            device_id: hex(&me.to.device_id),
            signing_key_seed: hex(&[1; 32]).into(),
            hpke_key_seed: hex(&[7; 32]).into(),
            ..Default::default()
        };
        assert!(c.fleet_id.is_empty());
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
        let mut ledger = team::db::Db::open_at(&path).unwrap();
        let pin = (BINDING, me.to.signing_key_id);
        let opened = open_fleet_grant(
            &grant,
            std::slice::from_ref(&pages),
            &pin,
            &me.to,
            &TENANT,
            1,
            &me.hpke_sk,
            T0 + DAY,
            &mut ledger,
            "https://fleet.test",
            true,
        )
        .unwrap()
        .map(|k| *k);
        drop(ledger);
        let kept = fleet_keys::collect(&hex(&TENANT), 1, &fkek).unwrap();
        let got = sync_cmd::pull_candidates(&c, T0 + 2 * DAY);
        store::set_config_root(None);
        assert_eq!((opened, kept), (Some(fkek), true));
        assert_eq!(got, [(fkek, 1)]);
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

    // ADR 0002 rule 6 and rule 1 "Sticky proven revocation" (critic r7 M23,
    // r8 minor 4) at the ledger, and D-6 (a)'s `renewed_after_revocation`.

    fn d_subject() -> shardx_core::authz_record::GrantSubject {
        shardx_core::authz_record::GrantSubject::Device {
            account_id: [6; 16],
            device_id: D_DEVICE,
            signing_key_id: d_id(),
            hpke_key_id: [13; 32],
        }
    }

    /// This device's tenant-scoped grant of `capability` to `subject`.
    fn granted(
        me: &Me,
        subject: shardx_core::authz_record::GrantSubject,
        capability: shardx_core::authz_record::Capability,
        replay: u8,
    ) -> Vec<u8> {
        use shardx_core::authz_record::*;
        let g = TenantCapabilityGrantV2 {
            common: common(replay),
            subject,
            scope_kind: CapabilityScopeKind::Tenant,
            scope_id: TENANT,
            capability,
        };
        build_record(&me.sk, DOMAIN_TENANT_CAPABILITY_GRANT, &g.encode())
    }

    /// Device `seed`, approved for the tenant by `issuer`: its subject, key
    /// and the approval; with `custodian`, also appointed by this device and
    /// holding `device.revoke`.
    fn member(
        me: &Me,
        issuer: &shardx_core::signing::Ed25519SigningKey,
        seed: u8,
        custodian: bool,
    ) -> (
        shardx_core::authz_record::GrantSubject,
        [u8; 32],
        Vec<Vec<u8>>,
    ) {
        use shardx_core::authz_record::*;
        let sk = shardx_core::signing::Ed25519SigningKey::from_bytes(&[seed; 32]);
        let key = shardx_core::keys::signing_key_id(sk.verifying_key().as_bytes());
        let subject = GrantSubject::Device {
            account_id: [seed; 16],
            device_id: [seed + 1; 16],
            signing_key_id: key,
            hpke_key_id: [seed; 32],
        };
        let approval = DeviceApprovalV2 {
            common: common(seed),
            subject_account_id: [seed; 16],
            subject_device_id: [seed + 1; 16],
            subject_signing_key_id: key,
            subject_hpke_key_id: [seed; 32],
            approval_scope_kind: ApprovalScopeKind::Tenant,
            approval_scope_id: TENANT,
        };
        let mut records = vec![build_record(
            issuer,
            DOMAIN_DEVICE_APPROVAL,
            &approval.encode(),
        )];
        if custodian {
            let root = TenantRootKeyGrantV2 {
                common: common(seed + 2),
                variant: RootGrantVariant::ExistingRootGrant,
                root_key_id: [8; 32],
                root_generation: 0,
                subject_account_id: [seed; 16],
                subject_device_id: [seed + 1; 16],
                subject_signing_key_id: key,
                recipient_hpke_key_id: [seed; 32],
                subject_device_approval_replay_id: [seed; 16],
                hpke_encapped_key_bytes: [3; 32],
                hpke_wrapped_trk_bytes: [4; 48],
            };
            records.push(build_record(
                &me.sk,
                DOMAIN_TENANT_ROOT_KEY_GRANT,
                &root.encode(),
            ));
            records.push(granted(
                me,
                subject.clone(),
                Capability::DeviceRevoke,
                seed + 3,
            ));
        }
        (subject, key, records)
    }

    /// `issuer`'s signed revocation of the device `subject`, issued at `T0`.
    fn revocation_of(
        issuer: &shardx_core::signing::Ed25519SigningKey,
        subject: &shardx_core::authz_record::GrantSubject,
        replay: u8,
    ) -> Vec<u8> {
        use shardx_core::authz_record::*;
        let GrantSubject::Device {
            account_id,
            device_id,
            signing_key_id,
            hpke_key_id,
        } = subject
        else {
            panic!("a device")
        };
        let r = DeviceRevocationV2 {
            common: common(replay),
            subject_account_id: *account_id,
            subject_device_id: *device_id,
            subject_signing_key_id: *signing_key_id,
            subject_hpke_key_id: *hpke_key_id,
            reason_code: DeviceRevocationReason::Compromised,
        };
        build_record(issuer, DOMAIN_DEVICE_REVOCATION, &r.encode())
    }

    /// D custodian with `device.revoke`, plus `extra`.
    fn with_d_revoking(me: &Me, extra: &[Vec<u8>]) -> Vec<Page> {
        let mut all = vec![granted(
            me,
            d_subject(),
            shardx_core::authz_record::Capability::DeviceRevoke,
            0x8f,
        )];
        all.extend_from_slice(extra);
        with_d(me, evidence(me, Vec::new()), Some(T0 + 300 * DAY), all)
    }

    fn proven_keys(path: &std::path::Path) -> Vec<String> {
        let mut keys: Vec<String> = proven(path).into_iter().map(|(k, _)| k).collect();
        keys.sort();
        keys
    }

    /// The chain the ledger at `path` evaluates `pages` to at `T0 + DAY`.
    fn chain_at(path: &std::path::Path, pages: &[Page]) -> shardx_core::trust_chain::TrustChain {
        let db = team::db::Db::open_at(path).unwrap();
        let me = me();
        team::ledger::evaluate(
            &db,
            &BINDING,
            &me.to.signing_key_id,
            &[pages.to_vec()],
            T0 + DAY,
        )
        .unwrap()
        .expect("the evidence verifies")
        .1
    }

    /// M23 refused: once this device counts D's revocation, a revocation of
    /// honest device H signed by D's key, dated inside D's window and first
    /// seen afterwards, is not counted: H is not withdrawn, so no revert
    /// skips H's heads.
    #[test]
    fn revert_refuses_a_backdated_revocation_by_a_sticky_revoked_key() {
        let me = me();
        let (h, h_key, h_approval) = member(&me, &me.sk, 0x48, false);
        let backdated = revocation_of(&d_key(), &h, 0x90);
        let (_dir, path) = ledger_at();
        collect(
            &path,
            &with_d_revoking(
                &me,
                &[h_approval.clone(), vec![revoke_d(&me, |_| {})]].concat(),
            ),
            &[],
            1,
        );
        assert_eq!(proven_keys(&path), [hex(&d_id())]);
        collect(
            &path,
            &with_d_revoking(&me, &[h_approval, vec![backdated]].concat()),
            &[],
            1,
        );
        assert_eq!(proven_keys(&path), [hex(&d_id())], "H is not counted");
        let db = team::db::Db::open_at(&path).unwrap();
        assert!(!team::ledger::withdrawn(&db, &BINDING, &h_key).unwrap());
    }

    /// D's approval and `profile.commit` of a fake committer F, signed by D's
    /// key and first seen after D's revocation was counted.
    fn appointed_by_d(me: &Me) -> ([u8; 32], Vec<Vec<u8>>) {
        use shardx_core::authz_record::*;
        let (f, f_key, mut records) = member(me, &d_key(), 0x68, false);
        let commit = TenantCapabilityGrantV2 {
            common: common(0x6a),
            subject: f,
            scope_kind: CapabilityScopeKind::Fleet,
            scope_id: FLEET,
            capability: Capability::ProfileCommit,
        };
        records.push(build_record(
            &d_key(),
            DOMAIN_TENANT_CAPABILITY_GRANT,
            &commit.encode(),
        ));
        records.push(granted(me, d_subject(), Capability::DeviceApprove, 0x8e));
        (f_key, records)
    }

    /// Whether `key` may commit to `FLEET` now: what a pull asks of a new
    /// head's signer (rule 6, first acceptance).
    fn commits(chain: &shardx_core::trust_chain::TrustChain, key: &[u8; 32]) -> bool {
        use shardx_core::trust_chain::Scope;
        let now = T0 + DAY;
        chain.approval_valid_at(key, Scope::Fleet(FLEET), now)
            && chain.capability_at(
                key,
                shardx_core::authz_record::Capability::ProfileCommit,
                Scope::Fleet(FLEET),
                now,
            )
    }

    /// M23 refused: an approval and `profile.commit` of fake committer F,
    /// signed by D's key and first seen after D's revocation was counted, do
    /// not count, so F's head is refused. Without that history they do.
    #[test]
    fn a_head_by_a_committer_a_sticky_revoked_key_appointed_is_refused() {
        let me = me();
        let (f, by_d) = appointed_by_d(&me);
        let (_fresh, fresh) = ledger_at();
        assert!(commits(&chain_at(&fresh, &with_d_revoking(&me, &by_d)), &f));
        let (_dir, path) = ledger_at();
        collect(
            &path,
            &with_d_revoking(&me, &[revoke_d(&me, |_| {})]),
            &[],
            1,
        );
        assert_eq!(proven_keys(&path), [hex(&d_id())]);
        let later = with_d_revoking(&me, &by_d);
        collect(&path, &later, &[], 1);
        assert!(!commits(&chain_at(&path, &later), &f));
    }

    /// M23 accepted ("Order"): what D issued and this device first saw before
    /// counting D's revocation keeps its standing: F may still commit.
    #[test]
    fn records_first_seen_before_a_count_keep_their_standing() {
        let me = me();
        let (f, by_d) = appointed_by_d(&me);
        let (_dir, path) = ledger_at();
        collect(&path, &with_d_revoking(&me, &by_d), &[], 1);
        let counting = [by_d.clone(), vec![revoke_d(&me, |_| {})]].concat();
        collect(&path, &with_d_revoking(&me, &counting), &[], 1);
        assert_eq!(proven_keys(&path), [hex(&d_id())]);
        let later = with_d_revoking(&me, &by_d);
        collect(&path, &later, &[], 1);
        assert!(commits(&chain_at(&path, &later), &f));
    }

    /// Documented limit, mutual revocation (critic r8 minor 4): a new device
    /// that sees, in one evaluation, custodian E's revocation of D and D's
    /// revocation of E counts both, so it holds E revoked too.
    #[test]
    fn limit_mutual_revocation_counts_both_on_a_new_device() {
        let me = me();
        let (e, e_key, mut extra) = member(&me, &me.sk, 0x58, true);
        let e_sk = shardx_core::signing::Ed25519SigningKey::from_bytes(&[0x58; 32]);
        extra.push(revocation_of(&e_sk, &d_subject(), 0x91));
        extra.push(revocation_of(&d_key(), &e, 0x92));
        let mut pages = with_d_revoking(&me, &extra);
        pages[0]
            .signing_public_keys
            .push(e_sk.verifying_key().to_bytes());
        let (_dir, path) = ledger_at();
        collect(&path, &pages, &[], 1);
        let mut both = vec![hex(&d_id()), hex(&e_key)];
        both.sort();
        assert_eq!(proven_keys(&path), both);
    }

    /// Documented limit: a new device that fetches D's revocation and D's
    /// backdated revocation of H in one evaluation counts the backdated one.
    #[test]
    fn limit_a_new_device_counts_a_backdated_revocation_with_its_revoker() {
        let me = me();
        let (h, h_key, mut extra) = member(&me, &me.sk, 0x48, false);
        extra.push(revoke_d(&me, |_| {}));
        extra.push(revocation_of(&d_key(), &h, 0x90));
        let (_dir, path) = ledger_at();
        collect(&path, &with_d_revoking(&me, &extra), &[], 1);
        let mut both = vec![hex(&d_id()), hex(&h_key)];
        both.sort();
        assert_eq!(proven_keys(&path), both);
    }

    /// Every custodian alert at `path`: kind, key, container and time.
    fn alerts(path: &std::path::Path) -> Vec<(String, String, String, i64)> {
        let db = team::db::Db::open_at(path).unwrap();
        let mut s = db
            .conn
            .prepare(
                "SELECT kind, signing_key_id, signed_container_hash, raised_at_ms
                 FROM trust_custodian_alerts ORDER BY signing_key_id",
            )
            .unwrap();
        let rows = s
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        rows
    }

    fn hash_of(container: &[u8]) -> String {
        hex(
            shardx_core::authz_record::AuthorizationRecord::parse(container)
                .unwrap()
                .signed_container_hash(),
        )
    }

    /// A ledger that counted this device's revocation of D, at `T0 + DAY`.
    fn counted_d(me: &Me) -> (tempfile::TempDir, std::path::PathBuf) {
        let (dir, path) = ledger_at();
        collect(
            &path,
            &with_d(
                me,
                evidence(me, Vec::new()),
                Some(T0 + 300 * DAY),
                vec![revoke_d(me, |_| {})],
            ),
            &[],
            1,
        );
        assert_eq!(proven_keys(&path), [hex(&d_id())]);
        (dir, path)
    }

    /// `extra` with D's custody but not its revocation (the server omits it).
    fn omitting(me: &Me, extra: Vec<Vec<u8>>) -> Vec<Page> {
        with_d(me, evidence(me, Vec::new()), Some(T0 + 300 * DAY), extra)
    }

    /// M23 refused (D-6 (a)): after D's revocation is counted, a backdated
    /// self-renewal of D does not count and raises exactly one
    /// `custodian.renewed_after_revocation`, naming D and the renewal.
    #[test]
    fn a_backdated_self_renewal_after_a_count_is_refused() {
        let me = me();
        let (_dir, path) = counted_d(&me);
        let before = custodian(&path, &d_id());
        let renewal = d_root(&d_key(), 0x93, T0 + 10 * DAY, LONG);
        collect(&path, &omitting(&me, vec![renewal.clone()]), &[], 1);
        assert_eq!(
            custodian(&path, &d_id()),
            before,
            "the renewal does not count"
        );
        assert_eq!(
            alerts(&path),
            [(
                "custodian.renewed_after_revocation".to_string(),
                hex(&d_id()),
                hash_of(&renewal),
                (T0 + DAY) as i64
            )]
        );
    }

    /// A renewal whose issuance actually predates the count,
    /// with a no-history control proving it otherwise extends custody.
    #[test]
    fn a_renewal_issued_before_the_count_is_sticky_and_alerts_once() {
        let me = me();
        let (_dir, path) = counted_d(&me);
        let before = custodian(&path, &d_id());
        let renewal = d_root(&d_key(), 0x93, T0 + DAY / 2, LONG);
        let later = omitting(&me, vec![renewal.clone()]);
        let (_fresh_dir, fresh) = ledger_at();
        collect_at(&fresh, &later, &[], 1, T0 + 20 * DAY);
        assert!(
            custodian(&fresh, &d_id()).1 > before.1,
            "without revocation history this renewal extends the window"
        );
        for day in [20, 21] {
            collect_at(&path, &later, &[], 1, T0 + day * DAY);
            assert_eq!(custodian(&path, &d_id()), before);
            assert_eq!(
                alerts(&path),
                [(
                    "custodian.renewed_after_revocation".to_string(),
                    hex(&d_id()),
                    hash_of(&renewal),
                    (T0 + 20 * DAY) as i64,
                )]
            );
        }
    }

    /// Critic B1: a container that names D as its issuer and renews D, but is
    /// signed by another key, or whose pages omit D's public key, is dropped
    /// as before and raises nothing.
    #[test]
    fn renewed_after_revocation_is_not_raised_for_a_forged_container() {
        let me = me();
        let (_dir, path) = counted_d(&me);
        let before = custodian(&path, &d_id());
        let other = shardx_core::signing::Ed25519SigningKey::from_bytes(&[0x33; 32]);
        let renewal = d_root(&d_key(), 0x93, T0 + 10 * DAY, LONG);
        let payload = shardx_core::authz_record::AuthorizationRecord::parse(&renewal)
            .unwrap()
            .canonical_payload_bytes()
            .to_vec();
        let forged = {
            use shardx_core::authz_record::*;
            use shardx_core::canonical as c;
            use shardx_core::signing::{SIGNATURE_SUITE_ID_ED25519, SIGNATURE_VERSION};
            let tbs = vec![
                ("container_domain", c::t(CONTAINER_DOMAIN)),
                ("container_version", c::u(CONTAINER_VERSION.into())),
                ("payload_domain", c::t(DOMAIN_TENANT_ROOT_KEY_GRANT)),
                ("payload_version", c::u(PAYLOAD_VERSION.into())),
                ("canonical_payload_bytes", c::b(&payload)),
                ("payload_sha256", c::b(&c::sha256(&payload))),
                (
                    "signature_suite_id",
                    c::u(SIGNATURE_SUITE_ID_ED25519.into()),
                ),
                ("signature_version", c::u(SIGNATURE_VERSION.into())),
                ("issuer_signing_key_id", c::b(&d_id())),
            ];
            shardx_core::signing::build_signed_container(&other, tbs).exact_bytes
        };
        let record = shardx_core::authz_record::AuthorizationRecord::parse(&forged).unwrap();
        assert_eq!(record.issuer_signing_key_id(), &d_id());
        let mut pages = omitting(&me, vec![forged]);
        pages[0]
            .signing_public_keys
            .push(other.verifying_key().to_bytes());
        collect(&path, &pages, &[], 1);
        let genuine = d_root(&d_key(), 0x94, T0 + 10 * DAY, LONG);
        let mut keyless = omitting(&me, vec![genuine]);
        let d_pk = d_key().verifying_key().to_bytes();
        keyless[0].signing_public_keys.retain(|pk| *pk != d_pk);
        collect(&path, &keyless, &[], 1);
        assert_eq!(custodian(&path, &d_id()), before);
        assert!(alerts(&path).is_empty());
    }

    /// Critic B1: one row per revoked key, whatever a server sends: two
    /// genuine renewals in one pull, a third in another, then the same
    /// evidence again leave one row naming the first and its time.
    #[test]
    fn renewed_after_revocation_is_bounded_per_key() {
        let me = me();
        let (_dir, path) = counted_d(&me);
        let r = |replay, from| d_root(&d_key(), replay, from, LONG);
        let (first, second, third) = (
            r(0x93, T0 + 10 * DAY),
            r(0x94, T0 + 11 * DAY),
            r(0x95, T0 + 12 * DAY),
        );
        collect_at(
            &path,
            &omitting(&me, vec![first.clone(), second]),
            &[],
            1,
            T0 + DAY,
        );
        collect_at(
            &path,
            &omitting(&me, vec![third.clone()]),
            &[],
            1,
            T0 + 2 * DAY,
        );
        collect_at(&path, &omitting(&me, vec![third]), &[], 1, T0 + 3 * DAY);
        assert_eq!(
            alerts(&path),
            [(
                "custodian.renewed_after_revocation".to_string(),
                hex(&d_id()),
                hash_of(&first),
                (T0 + DAY) as i64
            )]
        );
    }

    /// "Order": a renewal first seen no later than the counting evaluation
    /// keeps its standing and is never refused, so it raises nothing.
    #[test]
    fn renewed_after_revocation_is_not_raised_for_a_renewal_first_seen_before_the_count() {
        let me = me();
        let renewal = d_root(&d_key(), 0x93, T0 + 10 * DAY, LONG);
        let (_dir, path) = ledger_at();
        collect(
            &path,
            &omitting(&me, vec![renewal.clone(), revoke_d(&me, |_| {})]),
            &[],
            1,
        );
        assert_eq!(proven_keys(&path), [hex(&d_id())]);
        collect(&path, &omitting(&me, vec![renewal]), &[], 1);
        assert!(alerts(&path).is_empty());
    }

    /// Only D renewing itself raises: a renewal of D by another custodian is
    /// not refused, and a root grant D signs for another key is refused
    /// without an alert.
    #[test]
    fn renewed_after_revocation_is_not_raised_for_a_renewal_by_another_custodian() {
        use shardx_core::authz_record::*;
        let me = me();
        let (_dir, path) = counted_d(&me);
        let by_me = d_root(&me.sk, 0x93, T0 + 10 * DAY, LONG);
        let for_other = TenantRootKeyGrantV2 {
            common: common(0x94),
            variant: RootGrantVariant::ExistingRootGrant,
            root_key_id: [8; 32],
            root_generation: 0,
            subject_account_id: [0x58; 16],
            subject_device_id: [0x59; 16],
            subject_signing_key_id: [0x5a; 32],
            recipient_hpke_key_id: [0x58; 32],
            subject_device_approval_replay_id: [0x58; 16],
            hpke_encapped_key_bytes: [3; 32],
            hpke_wrapped_trk_bytes: [4; 48],
        };
        let for_other = build_record(&d_key(), DOMAIN_TENANT_ROOT_KEY_GRANT, &for_other.encode());
        collect(&path, &omitting(&me, vec![by_me, for_other]), &[], 1);
        assert!(alerts(&path).is_empty());
    }

    /// Local distrust alone raises nothing; a key both distrusted and
    /// revoked by a counted `DeviceRevocationV2` does, only for a renewal
    /// first seen after that revocation counted.
    #[test]
    fn renewed_after_revocation_is_not_raised_for_a_distrusted_key() {
        let me = me();
        let (_dir, path) = ledger_at();
        collect(&path, &omitting(&me, Vec::new()), &[], 1);
        {
            let db = team::db::Db::open_at(&path).unwrap();
            team::ledger::distrust_key(&db, &BINDING, &d_id(), T0 + DAY).unwrap();
        }
        let first = d_root(&d_key(), 0x93, T0 + 10 * DAY, LONG);
        collect(&path, &omitting(&me, vec![first.clone()]), &[], 1);
        assert!(alerts(&path).is_empty(), "distrusted only");
        collect(
            &path,
            &omitting(&me, vec![first, revoke_d(&me, |_| {})]),
            &[],
            1,
        );
        assert_eq!(proven(&path).len(), 2, "distrusted and revoked");
        assert!(alerts(&path).is_empty(), "served before the count");
        let second = d_root(&d_key(), 0x94, T0 + 11 * DAY, LONG);
        collect(&path, &omitting(&me, vec![second.clone()]), &[], 1);
        assert_eq!(
            alerts(&path),
            [(
                "custodian.renewed_after_revocation".to_string(),
                hex(&d_id()),
                hash_of(&second),
                (T0 + DAY) as i64
            )]
        );
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
            Ok(Some((container.clone(), true)))
        );
        assert_eq!(
            live_fleet_grant(&live, &fleet.to_uppercase(), 1, &device),
            Ok(Some((container.clone(), true)))
        );
        assert_eq!(
            live_fleet_grant(&descriptor(RootGrantState::PendingAck), &fleet, 1, &device),
            Ok(Some((container.clone(), false)))
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

    // ---- Join and Enroll again (v0.2.2a plan, section 4.J) ----

    const MINUTE: u64 = 60_000;
    const JOINER: [u8; 16] = [0x5a; 16];
    const BINDING_J: shardx_core::trust_chain::Binding = shardx_core::trust_chain::Binding {
        server_instance_id: INSTANCE,
        tenant_id: TENANT,
    };

    /// A joining device's config in a config root of its own.
    struct Joiner {
        _lock: std::sync::MutexGuard<'static, ()>,
        _dir: tempfile::TempDir,
    }

    impl Drop for Joiner {
        fn drop(&mut self) {
            store::set_config_root(None);
        }
    }

    fn joiner(server_url: &str, enrolled_at_ms: u64) -> Joiner {
        let lock = store::config_root_test_lock()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().unwrap();
        store::set_config_root(Some(dir.path().to_path_buf()));
        let mut c = team_config::TeamConfig {
            server_url: server_url.into(),
            tenant_id: hex(&TENANT),
            device_id: hex(&JOINER),
            account_id: hex(&[6; 16]),
            signing_key_seed: hex(&[7; 32]).into(),
            hpke_key_seed: hex(&[8; 32]).into(),
            enrolled_at_ms,
            ..Default::default()
        };
        team_config::save(&c).unwrap();
        assert!(team_config::protect_keys(&mut c).unwrap());
        Joiner {
            _lock: lock,
            _dir: dir,
        }
    }

    type Calls = std::sync::Arc<std::sync::Mutex<Vec<String>>>;

    /// A server that logs a ticket in and lists this device with `status` in
    /// `GET /v2/me`, recording every call.
    fn me_server(rt: &tokio::runtime::Runtime, status: &'static str) -> (String, Calls) {
        let calls: Calls = Default::default();
        let log = calls.clone();
        let app = axum::Router::new().fallback(
            move |method: axum::http::Method, uri: axum::http::Uri| {
                let log = log.clone();
                async move {
                    let call = format!("{method} {}", uri.path());
                    log.lock().unwrap().push(call.clone());
                    // `refused`: the server refuses the account login.
                    let code = if status == "refused" && call == "POST /v2/auth/login" {
                        axum::http::StatusCode::UNAUTHORIZED
                    } else {
                        axum::http::StatusCode::OK
                    };
                    let body = match call.as_str() {
                        "POST /v2/auth/login" => serde_json::json!({
                            "ticket": "v2t.fresh",
                            "ticket_id": hex(&[1; 16]),
                            "account_id": hex(&[6; 16]),
                            "server_instance_id": hex(&INSTANCE),
                            "restore_epoch": 0,
                        }),
                        // `missing`: the server no longer lists the joiner.
                        "GET /v2/me" => serde_json::json!({
                            "kind": "pre_device",
                            "account_id": hex(&[6; 16]),
                            "devices": [
                                {"device_id": hex(&[9; 16]), "status": "active"},
                                {"device_id": hex(if status == "missing" { &[9; 16] } else { &JOINER }), "status": status},
                            ],
                        }),
                        _ => serde_json::json!({}),
                    };
                    (code, axum::Json(body))
                }
            },
        );
        let url = rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            format!("http://{addr}")
        });
        (url, calls)
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn join_pin() -> Option<(shardx_core::trust_chain::Binding, [u8; 32], String)> {
        tenant_pin(&TENANT).unwrap()
    }

    #[test]
    fn the_join_code_expires_ten_minutes_after_this_device_enrolled() {
        let rt = runtime();
        let (url, calls) = me_server(&rt, "pending");
        let now = root_bootstrap::now_ms();
        let _j = joiner(&url, now - 10 * MINUTE - 1);
        let c = team_config::load().unwrap();
        let t0 = c.enrolled_at_ms;
        assert_eq!(join_window(&c, t0), Ok(t0 + 10 * MINUTE));
        assert_eq!(join_window(&c, t0 + 10 * MINUTE), Ok(t0 + 10 * MINUTE));
        for (c, at) in [
            (c.clone(), t0 + 10 * MINUTE + 1),
            (
                team_config::TeamConfig {
                    enrolled_at_ms: 0,
                    ..c.clone()
                },
                1,
            ),
        ] {
            let err = join_window(&c, at).unwrap_err();
            assert!(err.contains("fleet.joinCodeExpired"), "{err}");
        }
        let err = rt
            .block_on(team_join_code("u".into(), "p".into()))
            .unwrap_err();
        assert!(err.contains("fleet.joinCodeExpired"), "{err}");
        // Only the device's status is read, to say whether Enroll again is
        // allowed: no session opens and no evidence is fetched.
        assert_eq!(
            *calls.lock().unwrap(),
            ["POST /v2/auth/login", "GET /v2/me", "POST /v2/auth/logout"]
        );
    }

    #[test]
    fn a_late_join_confirm_is_refused_even_after_approval() {
        let rt = runtime();
        let (url, calls) = me_server(&rt, "active");
        let now = root_bootstrap::now_ms();
        let _j = joiner(&url, now - 11 * MINUTE);
        let anchor = [0x0a; 32];
        let err = rt
            .block_on(team_join_confirm(
                "u".into(),
                "p".into(),
                hex(&anchor),
                String::new(),
            ))
            .unwrap_err();
        assert!(err.contains("fleet.joinCodeExpired"), "{err}");
        assert!(calls.lock().unwrap().is_empty(), "no server is asked");
        assert!(!team::db::Db::path().unwrap().exists(), "nothing is pinned");

        // The pin itself checks the window again, with the anchor shown.
        let c = team_config::load().unwrap();
        let ledger = team::db::Db::open().unwrap();
        let sas = code_for(&c, &BINDING_J, &anchor);
        let err = pin_join(&c, &ledger, &BINDING_J, &anchor, &hex(&anchor), &sas, now).unwrap_err();
        assert!(err.contains("fleet.joinCodeExpired"), "{err}");
        assert_eq!(join_pin(), None);
    }

    /// The code this joiner shows for `binding` and `anchor`.
    fn code_for(
        c: &team_config::TeamConfig,
        binding: &shardx_core::trust_chain::Binding,
        anchor: &[u8; 32],
    ) -> String {
        let me = recipient(c).unwrap();
        shardx_core::trust_chain::join_sas_display(&shardx_core::trust_chain::join_sas(
            &binding.server_instance_id,
            &binding.tenant_id,
            anchor,
            &me.signing_key_id,
            &me.hpke_key_id,
        ))
    }

    /// ADR 0002 Q-12: the whole `(server_instance_id, tenant_id, A0)` is
    /// pinned only as the code showed it. A server that shows another
    /// instance at confirm time, with the same anchor, pins nothing.
    #[test]
    fn a_join_confirm_is_refused_when_the_server_instance_changed() {
        let now = root_bootstrap::now_ms();
        let _j = joiner("http://127.0.0.1:9", now);
        let c = team_config::load().unwrap();
        let ledger = team::db::Db::open().unwrap();
        let anchor = [0x0a; 32];
        let shown = code_for(&c, &BINDING_J, &anchor);
        let other = shardx_core::trust_chain::Binding {
            server_instance_id: [0x0d; 16],
            ..BINDING_J
        };
        for (binding, sas) in [(&other, shown.as_str()), (&BINDING_J, "")] {
            let err = pin_join(&c, &ledger, binding, &anchor, &hex(&anchor), sas, now).unwrap_err();
            assert!(err.contains("fleet.joinCodeChanged"), "{err}");
        }
        assert_eq!(join_pin(), None);
        pin_join(&c, &ledger, &BINDING_J, &anchor, &hex(&anchor), &shown, now).unwrap();
        assert_eq!(join_pin(), Some((BINDING_J, anchor, "JOIN".to_string())));
    }

    #[test]
    fn a_join_confirm_is_refused_for_another_tenant_than_the_one_shown() {
        let now = root_bootstrap::now_ms();
        let _j = joiner("http://127.0.0.1:9", now);
        let c = team_config::load().unwrap();
        let ledger = team::db::Db::open().unwrap();
        let anchor = [0x0a; 32];
        let shown = code_for(&c, &BINDING_J, &anchor);
        let substituted = shardx_core::trust_chain::Binding {
            tenant_id: [0x6f; 16],
            ..BINDING_J
        };
        let result = pin_join(
            &c,
            &ledger,
            &substituted,
            &anchor,
            &hex(&anchor),
            &shown,
            now,
        );
        assert!(
            result.is_err(),
            "a different tenant must not use the displayed code"
        );
        assert_eq!(
            ledger
                .conn
                .query_row("SELECT count(*) FROM trust_anchors", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    #[test]
    fn a_join_pin_is_refused_for_another_anchor_than_the_one_shown() {
        let now = root_bootstrap::now_ms();
        let _j = joiner("http://127.0.0.1:9", now);
        let c = team_config::load().unwrap();
        let ledger = team::db::Db::open().unwrap();
        let (evaluated, shown) = ([0x0a; 32], [0x0b; 32]);
        let sas = code_for(&c, &BINDING_J, &evaluated);
        for shown in [hex(&shown), String::new()] {
            let err = pin_join(&c, &ledger, &BINDING_J, &evaluated, &shown, &sas, now).unwrap_err();
            assert!(err.contains("fleet.joinAnchorChanged"), "{err}");
        }
        assert_eq!(join_pin(), None);
        pin_join(
            &c,
            &ledger,
            &BINDING_J,
            &evaluated,
            &hex(&evaluated).to_uppercase(),
            &sas,
            now,
        )
        .unwrap();
        assert_eq!(join_pin(), Some((BINDING_J, evaluated, "JOIN".to_string())));
        // A later ceremony against another anchor never replaces it.
        let other = code_for(&c, &BINDING_J, &shown);
        let err = pin_join(&c, &ledger, &BINDING_J, &shown, &hex(&shown), &other, now).unwrap_err();
        assert!(err.contains("fleet.joinAnchorChanged"), "{err}");
        assert_eq!(join_pin(), Some((BINDING_J, evaluated, "JOIN".to_string())));
    }

    #[test]
    fn a_joined_device_reads_its_anchor_from_the_join_pin() {
        let _j = joiner("http://127.0.0.1:9", root_bootstrap::now_ms());
        let c = team_config::load().unwrap();
        assert_eq!(pinned_anchor(&c), None);
        assert!(!team::db::Db::path().unwrap().exists(), "no ledger is made");
        let ledger = team::db::Db::open().unwrap();
        let other = shardx_core::trust_chain::Binding {
            tenant_id: [0x0c; 16],
            ..BINDING_J
        };
        assert!(team::ledger::pin_anchor(&ledger, &other, &[0x0c; 32], "JOIN", 1).unwrap());
        assert_eq!(pinned_anchor(&c), None, "another tenant's pin");
        assert!(team::ledger::pin_anchor(&ledger, &BINDING_J, &[0x0a; 32], "JOIN", 1).unwrap());
        assert_eq!(pinned_anchor(&c), Some((BINDING_J, [0x0a; 32])));
    }

    /// What enrolling again leaves: no id, no seeds, and the credentials
    /// only when `kept` (a device the server listed pending or revoked).
    fn assert_cleared(refs: [String; 2], kept: bool) {
        let c = team_config::load().unwrap();
        assert!(c.device_id.is_empty() && !c.is_enrolled() && !c.blocks_enrollment());
        assert!(c.signing_key_seed.is_empty() && c.hpke_key_seed.is_empty());
        assert!(c.signing_credential_ref.is_empty() && c.hpke_credential_ref.is_empty());
        assert_eq!(
            (c.server_url.is_empty(), c.tenant_id.as_str()),
            (false, hex(&TENANT).as_str())
        );
        for r in refs {
            match credential::load(&r) {
                Ok(_) => assert!(kept, "{r} was kept"),
                Err(gone) => {
                    assert!(!kept, "{r} was forgotten: {gone}");
                    assert!(gone.to_string().contains("credential.missing"), "{gone}");
                }
            }
        }
    }

    fn refs() -> [String; 2] {
        let c = team_config::load().unwrap();
        assert!(!c.signing_credential_ref.is_empty() && !c.hpke_credential_ref.is_empty());
        [c.signing_credential_ref, c.hpke_credential_ref]
    }

    #[test]
    fn reset_preserves_an_identity_replaced_while_listing_is_in_flight() {
        use std::sync::Arc;
        let rt = runtime();
        let changed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let changed_in_reply = changed.clone();
        let reply: Arc<fleet_custody::tests::Reply> = Arc::new(move |call, _| {
            let body = match call {
                "POST /v2/auth/login" => serde_json::json!({
                    "ticket": "v2t.fixture", "ticket_id": hex(&[1; 16]),
                    "account_id": hex(&[6; 16]), "server_instance_id": hex(&INSTANCE),
                    "restore_epoch": 0
                }),
                "GET /v2/me" => {
                    // A concurrent enrollment/import has committed another working identity.
                    let mut current = team_config::load().unwrap();
                    current.device_id = hex(&[0x6b; 16]);
                    current.signing_credential_ref = "race-signing".into();
                    current.hpke_credential_ref = "race-hpke".into();
                    credential::store(&current.signing_credential_ref, &[0x71; 32]).unwrap();
                    credential::store(&current.hpke_credential_ref, &[0x72; 32]).unwrap();
                    team_config::save(&current).unwrap();
                    root_bootstrap::save(&root_bootstrap::BootstrapState {
                        tenant_id: current.tenant_id,
                        device_id: current.device_id,
                        activated: true,
                        ..Default::default()
                    })
                    .unwrap();
                    changed_in_reply.store(true, std::sync::atomic::Ordering::SeqCst);
                    serde_json::json!({"account_id": hex(&[6; 16]), "devices": [{"device_id": hex(&JOINER), "status": "revoked"}]})
                }
                _ => serde_json::json!({}),
            };
            (200, serde_json::to_vec(&body).unwrap())
        });
        let (client, _) = rt.block_on(fleet_custody::tests::mock(reply));
        let _j = joiner(client.base_url(), root_bootstrap::now_ms());
        let result = rt.block_on(team_enroll_again("u".into(), "p".into()));
        assert!(changed.load(std::sync::atomic::Ordering::SeqCst));
        let after = team_config::load().unwrap();
        assert!(
            after.device_id == hex(&[0x6b; 16]),
            "Reset overwrote the newer root identity"
        );
        assert!(
            crate::errcode::has_code(&result.unwrap_err(), "fleet.identityChanged"),
            "Reset accepted a stale identity snapshot"
        );
    }

    /// Reset of the joiner, listed revoked, while `race` writes during the
    /// listing: the error, whether the joiner's credentials were kept, and
    /// the device ID `team.json` holds afterwards.
    fn reset_racing(race: fn()) -> (String, bool, String) {
        let rt = runtime();
        let reply: std::sync::Arc<fleet_custody::tests::Reply> = std::sync::Arc::new(
            move |call, _| {
                let body = match call {
                    "POST /v2/auth/login" => serde_json::json!({
                        "ticket": "v2t.fixture", "ticket_id": hex(&[1; 16]),
                        "account_id": hex(&[6; 16]), "server_instance_id": hex(&INSTANCE),
                        "restore_epoch": 0
                    }),
                    "GET /v2/me" => {
                        race();
                        serde_json::json!({"account_id": hex(&[6; 16]), "devices": [{"device_id": hex(&JOINER), "status": "revoked"}]})
                    }
                    _ => serde_json::json!({}),
                };
                (200, serde_json::to_vec(&body).unwrap())
            },
        );
        let (client, _) = rt.block_on(fleet_custody::tests::mock(reply));
        let _j = joiner(client.base_url(), root_bootstrap::now_ms());
        let refs = refs();
        let err = rt
            .block_on(team_enroll_again("u".into(), "p".into()))
            .unwrap_err();
        let kept = credential::load(&refs[0]).is_ok() && credential::load(&refs[1]).is_ok();
        (err, kept, team_config::load().unwrap().device_id)
    }

    /// D1: a root state that names this device by the time the listing
    /// returns refuses the Reset, though `team.json` did not change.
    #[test]
    fn reset_is_refused_when_only_the_root_state_changed_during_the_listing() {
        let (err, kept, device) = reset_racing(|| {
            root_bootstrap::save(&root_bootstrap::BootstrapState {
                tenant_id: hex(&TENANT),
                device_id: hex(&JOINER),
                activated: true,
                ..Default::default()
            })
            .unwrap();
        });
        assert!(
            crate::errcode::has_code(&err, "fleet.identityChanged"),
            "{err}"
        );
        assert!(
            kept,
            "Reset cleared a device that became the root custodian"
        );
        assert_eq!(device, hex(&JOINER));
    }

    /// D1: another identity in `team.json` by the time the listing returns
    /// refuses the Reset, though the root state did not change.
    #[test]
    fn reset_is_refused_when_only_team_json_changed_during_the_listing() {
        let (err, kept, device) = reset_racing(|| {
            let mut current = team_config::load().unwrap();
            current.device_id = hex(&[0x6b; 16]);
            team_config::save(&current).unwrap();
        });
        assert!(
            crate::errcode::has_code(&err, "fleet.identityChanged"),
            "{err}"
        );
        assert!(kept, "Reset overwrote a newer identity");
        assert_eq!(device, hex(&[0x6b; 16]));
    }

    #[test]
    fn reset_of_an_unlisted_device_keeps_identity_and_credentials() {
        let rt = runtime();
        let (url, _) = me_server(&rt, "missing");
        let _j = joiner(&url, root_bootstrap::now_ms());
        let before = team_json();
        let refs = refs();
        let result = rt.block_on(team_enroll_again("other-account".into(), "p".into()));
        assert!(result.is_err());
        assert!(team_json() == before);
        assert!(credential::load(&refs[0]).is_ok() && credential::load(&refs[1]).is_ok());
    }

    #[test]
    fn reset_checks_the_signed_in_account_against_the_saved_owner() {
        let rt = runtime();
        let reply: std::sync::Arc<fleet_custody::tests::Reply> = std::sync::Arc::new(|call, _| {
            let body = match call {
                "POST /v2/auth/login" => serde_json::json!({
                    "ticket": "v2t.fixture", "ticket_id": hex(&[1; 16]),
                    "account_id": hex(&[0x6c; 16]), "server_instance_id": hex(&INSTANCE),
                    "restore_epoch": 0
                }),
                "GET /v2/me" => serde_json::json!({
                    "account_id": hex(&[0x6c; 16]), "server_instance_id": hex(&INSTANCE),
                    "devices": [{"device_id": hex(&JOINER), "status": "pending"}]
                }),
                _ => serde_json::json!({}),
            };
            (200, serde_json::to_vec(&body).unwrap())
        });
        let (client, _) = rt.block_on(fleet_custody::tests::mock(reply));
        let _j = joiner(client.base_url(), root_bootstrap::now_ms());
        let before = team_json();
        assert!(team_config::load().unwrap().account_id != hex(&[0x6c; 16]));
        let result = rt.block_on(team_enroll_again("other-account".into(), "p".into()));
        assert!(
            team_json() == before,
            "a different signed-in account cleared the saved owner's device"
        );
        assert!(crate::errcode::has_code(
            &result.unwrap_err(),
            "fleet.enrollAgainOtherAccount"
        ));
    }

    /// A ticket of another account, with a `GET /v2/me` that leaves the
    /// account out, never resets the saved owner's device.
    #[test]
    fn reset_is_refused_when_the_listing_omits_the_ticket_account() {
        let rt = runtime();
        let reply: std::sync::Arc<fleet_custody::tests::Reply> = std::sync::Arc::new(|call, _| {
            let body = match call {
                "POST /v2/auth/login" => serde_json::json!({
                    "ticket": "v2t.fixture", "ticket_id": hex(&[1; 16]),
                    "account_id": hex(&[0x6c; 16]), "server_instance_id": hex(&INSTANCE),
                    "restore_epoch": 0
                }),
                "GET /v2/me" => serde_json::json!({
                    "server_instance_id": hex(&INSTANCE),
                    "devices": [{"device_id": hex(&JOINER), "status": "pending"}]
                }),
                _ => serde_json::json!({}),
            };
            (200, serde_json::to_vec(&body).unwrap())
        });
        let (client, _) = rt.block_on(fleet_custody::tests::mock(reply));
        let _j = joiner(client.base_url(), root_bootstrap::now_ms());
        assert!(team_config::load().unwrap().account_id != hex(&[0x6c; 16]));
        let before = team_json();
        let references = refs();
        let result = rt.block_on(team_enroll_again("other-account".into(), "p".into()));
        let unchanged = team_json() == before;
        let credentials_kept = references.iter().all(|r| credential::load(r).is_ok());
        assert!(
            result.is_err() && unchanged && credentials_kept,
            "Reset with omitted owner: refused={}, identity_kept={}, credentials_kept={}",
            result.is_err(),
            unchanged,
            credentials_kept
        );
        let err = result.unwrap_err();
        assert!(
            crate::errcode::has_code(&err, "fleet.enrollAgainOtherAccount"),
            "{err}"
        );
    }

    /// A config from before `account_id` still resets once the ticket and
    /// the listing name one account.
    #[test]
    fn a_config_without_an_account_resets_when_ticket_and_listing_agree() {
        let rt = runtime();
        let (url, _) = me_server(&rt, "pending");
        let _j = joiner(&url, root_bootstrap::now_ms());
        let mut c = team_config::load().unwrap();
        c.account_id.clear();
        team_config::save(&c).unwrap();
        let refs = refs();
        rt.block_on(team_enroll_again("u".into(), "p".into()))
            .unwrap();
        assert_cleared(refs, true);
    }

    /// A pin that no longer reads is no proof of no pin: Reset of a device
    /// listed active keeps its identity and credentials.
    #[test]
    fn reset_preserves_an_active_device_whose_pin_ledger_is_unreadable() {
        let rt = runtime();
        let (url, _) = me_server(&rt, "active");
        let _j = joiner(&url, root_bootstrap::now_ms());
        pin_here();
        assert!(pinned_anchor(&team_config::load().unwrap()).is_some());
        let before = team_json();
        let references = refs();
        std::fs::write(team::db::Db::path().unwrap(), b"unreadable test ledger").unwrap();
        assert!(team::db::Db::open().is_err());
        let result = rt.block_on(team_enroll_again("u".into(), "p".into()));
        let unchanged = team_json() == before;
        let credentials_kept = references.iter().all(|r| credential::load(r).is_ok());
        assert!(
            result.is_err() && unchanged && credentials_kept,
            "Reset with unreadable pin: refused={}, identity_kept={}, credentials_kept={}",
            result.is_err(),
            unchanged,
            credentials_kept
        );
        let err = result.unwrap_err();
        assert!(
            crate::errcode::has_code(&err, "team.trustLedgerUnreadable"),
            "{err}"
        );
    }

    #[test]
    fn connection_change_preserves_an_unfinished_root_identity() {
        for (url, tenant) in connection_changes() {
            let _j = joiner(URL_J, root_bootstrap::now_ms());
            root_here();
            let mut root = root_bootstrap::load().unwrap();
            root.self_grant = self_grant_here(&[9; 32]);
            root.create_request = "ab".into();
            // An interrupted bootstrap has saved its create request, which
            // the server may have acted on, but has not yet persisted
            // finish_activation's activated flag.
            root.activated = false;
            root_bootstrap::save(&root).unwrap();
            let before = team_json();
            let refs = refs();
            let result = team_set_connection(url, String::new(), tenant);
            assert!(
                team_json() == before,
                "connection change cleared the unfinished root identity"
            );
            assert!(credential::load(&refs[0]).is_ok() && credential::load(&refs[1]).is_ok());
            assert!(crate::errcode::has_code(
                &result.unwrap_err(),
                "fleet.rootCustodianKeepsConnection"
            ));
        }
    }

    /// A self-grant alone was never sent: the server holds no root
    /// generation of this device, so it may change its connection.
    #[test]
    fn a_bootstrap_with_only_a_self_grant_may_change_its_connection() {
        for (url, tenant) in connection_changes() {
            let _j = joiner(URL_J, root_bootstrap::now_ms());
            root_here();
            let mut root = root_bootstrap::load().unwrap();
            root.self_grant = self_grant_here(&[9; 32]);
            root.activated = false;
            root_bootstrap::save(&root).unwrap();
            team_set_connection(url.clone(), String::new(), tenant.clone()).unwrap();
            let c = team_config::load().unwrap();
            assert!(c.device_id.is_empty() && !c.is_enrolled());
            assert_eq!((c.server_url, c.tenant_id), (url, tenant));
        }
    }

    /// The joiner's first root self-grant of `trk`, in hex.
    fn self_grant_here(trk: &[u8; 32]) -> String {
        let c = team_config::load().unwrap();
        let signer = c.signing_key().unwrap();
        let (_, hpke_public) = shardx_core::grants::derive_keypair(&c.hpke_seed().unwrap());
        let cx = root_bootstrap::Context16 {
            tenant: TENANT,
            instance: INSTANCE,
            epoch: 0,
            account: [6; 16],
            device: JOINER,
            signing_key_id: shardx_core::keys::signing_key_id(signer.verifying_key().as_bytes()),
            hpke_key_id: shardx_core::keys::hpke_key_id(&hpke_public),
        };
        hex(&root_bootstrap::self_grant(
            &cx,
            &signer,
            &hpke_public,
            trk,
            [8; 16],
            root_bootstrap::now_ms(),
        )
        .unwrap())
    }

    /// D7: the export's fingerprint is the activated root's `root_key_id`,
    /// and nothing before activation.
    #[test]
    fn bootstrap_status_shows_the_root_key_id_once_activated() {
        let _j = joiner(URL_J, root_bootstrap::now_ms());
        root_here();
        let mut root = root_bootstrap::load().unwrap();
        root.self_grant = self_grant_here(&[9; 32]);
        root_bootstrap::save(&root).unwrap();
        assert_eq!(
            root_bootstrap::status().unwrap().root_key_id,
            hex(&shardx_core::keys::root_key_id(&[9; 32]))
        );
        root.activated = false;
        root_bootstrap::save(&root).unwrap();
        assert!(root_bootstrap::status().unwrap().root_key_id.is_empty());
    }

    #[test]
    fn enroll_again_clears_a_pending_identity() {
        let rt = runtime();
        let (url, calls) = me_server(&rt, "pending");
        let _j = joiner(&url, root_bootstrap::now_ms());
        let refs = refs();
        let status = rt
            .block_on(team_enroll_again("u".into(), "p".into()))
            .unwrap();
        assert!(status.device_id.is_empty());
        assert_cleared(refs, true);
        assert!(calls.lock().unwrap().contains(&"GET /v2/me".to_string()));
    }

    /// Architect 2: an approval that landed after this device's window
    /// closed leaves it active but unpinned; it enrolls again.
    #[test]
    fn an_approved_device_whose_join_code_expired_can_enroll_again() {
        let rt = runtime();
        let (url, _) = me_server(&rt, "active");
        let _j = joiner(&url, root_bootstrap::now_ms() - 60 * MINUTE);
        let refs = refs();
        let err = rt
            .block_on(team_join_code("u".into(), "p".into()))
            .unwrap_err();
        assert!(err.contains("fleet.joinCodeExpired"), "{err}");
        rt.block_on(team_enroll_again("u".into(), "p".into()))
            .unwrap();
        assert_cleared(refs, false);
    }

    /// An expired code reads as expired only where Enroll again is allowed:
    /// an active pinned device is pointed at its key, and a quarantined or
    /// unlisted one is told it cannot enroll again. Unasked, it is expired.
    #[test]
    fn an_expired_code_says_whether_enroll_again_is_allowed() {
        let expired = "fleet.joinCodeExpired";
        for (status, pinned, allowed, code) in [
            ("active", true, false, "fleet.joinedCollectKey"),
            ("active", false, true, expired),
            ("pending", true, true, expired),
            ("pending", false, true, expired),
            ("revoked", true, true, expired),
            ("revoked", false, true, expired),
            ("quarantined", false, false, "fleet.enrollAgainRefused"),
            ("missing", true, false, "fleet.enrollAgainRefused"),
            ("missing", false, false, "fleet.enrollAgainRefused"),
        ] {
            let listed = Some(status).filter(|s| *s != "missing");
            assert_eq!(
                enroll_again_allowed(listed, pinned),
                allowed,
                "{status} {pinned}"
            );
            let rt = runtime();
            let (url, _) = me_server(&rt, status);
            let _j = joiner(&url, root_bootstrap::now_ms() - 60 * MINUTE);
            if pinned {
                pin_here();
            }
            let err = rt
                .block_on(team_join_code("u".into(), "p".into()))
                .unwrap_err();
            assert!(err.contains(code), "{status} {pinned}: {err}");
            // No login to ask with: the code is just expired.
            let err = rt
                .block_on(team_join_code("u".into(), String::new()))
                .unwrap_err();
            assert!(err.contains(expired), "{status} {pinned}: {err}");
        }
    }

    /// An expired code whose status could not be asked (the login refused)
    /// reports that error, never the plain expired code the UI answers with
    /// Enroll again.
    #[test]
    fn an_expired_code_whose_status_is_unanswered_is_not_plain_expired() {
        let rt = runtime();
        let (url, _) = me_server(&rt, "refused");
        let _j = joiner(&url, root_bootstrap::now_ms() - 60 * MINUTE);
        pin_here();
        let err = rt
            .block_on(team_join_code("u".into(), "p".into()))
            .unwrap_err();
        assert!(err.contains("fleet.refusedLogin"), "{err}");
        assert!(!err.contains("fleet.joinCodeExpired"), "{err}");
    }

    /// Pins the joiner's tenant to an anchor, as a confirmed join does.
    fn pin_here() {
        let ledger = team::db::Db::open().unwrap();
        assert!(team::ledger::pin_anchor(&ledger, &BINDING_J, &[0x0a; 32], "JOIN", 1).unwrap());
    }

    #[test]
    fn enroll_again_is_refused_for_an_active_pinned_or_custodian_device() {
        let rt = runtime();
        // An approved device that pinned its anchor.
        let (url, calls) = me_server(&rt, "active");
        let j = joiner(&url, root_bootstrap::now_ms());
        let before = format!("{:?}", team_config::load().unwrap());
        pin_here();
        let err = rt
            .block_on(team_enroll_again("u".into(), "p".into()))
            .unwrap_err();
        assert!(err.contains("fleet.enrollAgainRefused"), "{err}");
        assert!(calls.lock().unwrap().contains(&"GET /v2/me".to_string()));
        assert_eq!(format!("{:?}", team_config::load().unwrap()), before);
        drop(j);

        for status in ["active", "pending"] {
            // The root custodian, whatever the server says.
            let (url, calls) = me_server(&rt, status);
            let _j = joiner(&url, root_bootstrap::now_ms());
            let before = format!("{:?}", team_config::load().unwrap());
            let root = root_bootstrap::BootstrapState {
                tenant_id: hex(&TENANT),
                device_id: hex(&JOINER).to_uppercase(),
                ..Default::default()
            };
            root_bootstrap::save(&root).unwrap();
            let err = rt
                .block_on(team_enroll_again("u".into(), "p".into()))
                .unwrap_err();
            assert!(err.contains("fleet.enrollAgainRefused"), "{err}");
            assert!(calls.lock().unwrap().is_empty(), "no server is asked");
            assert_eq!(format!("{:?}", team_config::load().unwrap()), before);
        }

        // A device the server no longer lists as waiting, approved or revoked.
        for status in ["quarantined", "retired"] {
            let (url, _) = me_server(&rt, status);
            let _j = joiner(&url, root_bootstrap::now_ms());
            let err = rt
                .block_on(team_enroll_again("u".into(), "p".into()))
                .unwrap_err();
            assert!(err.contains("fleet.enrollAgainRefused"), "{err}");
            assert!(team_config::load().unwrap().is_enrolled());
        }
    }

    /// Plan amendment (Architect, S3 review): a joiner that pinned inside its
    /// window but was never approved is not stuck pending. The pin binds the
    /// server, tenant and anchor, not the device, so it stays.
    #[test]
    fn a_pinned_pending_device_can_enroll_again() {
        let rt = runtime();
        let (url, _) = me_server(&rt, "pending");
        let _j = joiner(&url, root_bootstrap::now_ms());
        pin_here();
        let refs = refs();
        rt.block_on(team_enroll_again("u".into(), "p".into()))
            .unwrap();
        assert_cleared(refs, true);
        assert_eq!(
            join_pin(),
            Some((BINDING_J, [0x0a; 32], "JOIN".to_string()))
        );
    }

    /// How many `team.json.unreadable-*` copies the config root holds.
    fn team_json_copies() -> usize {
        let dir = store::team_config_path().unwrap();
        std::fs::read_dir(dir.parent().unwrap())
            .unwrap()
            .filter(|e| {
                let name = e.as_ref().unwrap().file_name();
                name.to_string_lossy().starts_with("team.json.unreadable-")
            })
            .count()
    }

    /// A saved fleet grant ack, as an earlier collect of this device left it.
    fn saved_ack() {
        fleet_custody::save(&fleet_custody::FleetCustodyState {
            device_acks: [("f.0".to_string(), "00".to_string())].into(),
            ..Default::default()
        })
        .unwrap();
    }

    /// S4, C12 (plan v0.2.2b): a revoked device whose seeds still read
    /// enrolls again with its file copied aside and both old credentials
    /// kept; its fleet ID and saved fleet grant acks go.
    #[test]
    fn a_revoked_device_enrolls_again_and_keeps_its_old_credentials() {
        let rt = runtime();
        let (url, _) = me_server(&rt, "revoked");
        let _j = joiner(&url, root_bootstrap::now_ms());
        pin_here();
        let mut c = team_config::load().unwrap();
        c.fleet_id = hex(&TENANT);
        team_config::save(&c).unwrap();
        saved_ack();
        let refs = refs();
        assert_eq!(team_json_copies(), 0);
        rt.block_on(team_enroll_again("u".into(), "p".into()))
            .unwrap();
        let c = team_config::load().unwrap();
        assert!(c.device_id.is_empty() && c.fleet_id.is_empty() && !c.is_enrolled());
        assert_eq!(team_json_copies(), 1);
        assert_eq!(*credential::load(&refs[0]).unwrap(), [7; 32]);
        assert_eq!(*credential::load(&refs[1]).unwrap(), [8; 32]);
        assert!(fleet_custody::load().unwrap().device_acks.is_empty());
    }

    /// R3-D2: `pending` is the server's unauthenticated word as `revoked`
    /// is, so a working device it lists pending keeps a copy of its file and
    /// both credentials.
    #[test]
    fn a_pending_reply_keeps_readable_credentials_and_a_copy() {
        let rt = runtime();
        let (url, _) = me_server(&rt, "pending");
        let _j = joiner(&url, root_bootstrap::now_ms());
        pin_here();
        let refs = refs();
        assert_eq!(team_json_copies(), 0);
        rt.block_on(team_enroll_again("u".into(), "p".into()))
            .unwrap();
        assert!(!team_config::load().unwrap().is_enrolled());
        assert_eq!(team_json_copies(), 1);
        assert_eq!(*credential::load(&refs[0]).unwrap(), [7; 32]);
        assert_eq!(*credential::load(&refs[1]).unwrap(), [8; 32]);
    }

    /// R3-D3: root grant hex from the server never panics on a multi-byte
    /// character or takes a sign, and its error never carries the input.
    #[test]
    fn root_grant_hex_from_the_server_never_panics_or_echoes() {
        let secret = "secret-sentinel-00";
        // A three-byte character, one more, then the literal secret: even length.
        let tainted = format!("\u{20ac}a{secret}");
        assert!(tainted.len().is_multiple_of(2));
        for s in [tainted.as_str(), "+f", "a\u{e9}0"] {
            let err = std::panic::catch_unwind(|| hex_bytes(s))
                .expect("hex_bytes panicked")
                .unwrap_err();
            assert!(
                crate::errcode::has_code(&err, "fleet.malformedHexFromServer"),
                "{err}"
            );
            assert!(!err.contains(secret), "{err}");
        }
        let grant = fleet_client::RootKeyGrant {
            grant_variant: String::new(),
            root_key_id: String::new(),
            root_generation: 0,
            recipient_hpke_key_id: String::new(),
            hpke_info_hex: "00".into(),
            hpke_encapped_key_hex: "00".into(),
            hpke_wrapped_trk_hex: "00".into(),
        };
        for field in 0..3 {
            let mut g = grant.clone();
            *[
                &mut g.hpke_info_hex,
                &mut g.hpke_encapped_key_hex,
                &mut g.hpke_wrapped_trk_hex,
            ][field] = tainted.clone();
            let err = std::panic::catch_unwind(|| custody_report(&[0; 32], &[g], FleetGrant::None))
                .expect("custody_report panicked")
                .unwrap_err();
            assert!(!err.contains(secret), "{field}: {err}");
        }
    }

    /// R3-D5: an expired code of a device with its own root state, finished
    /// or not, never reads as plain expired, the code the UI answers with
    /// Enroll again: the Reset would refuse it.
    #[test]
    fn an_expired_code_of_a_device_with_its_own_root_state_offers_no_enroll_again() {
        for status in ["pending", "active"] {
            let rt = runtime();
            let (url, _) = me_server(&rt, status);
            let _j = joiner(&url, root_bootstrap::now_ms() - 60 * MINUTE);
            root_bootstrap::save(&root_bootstrap::BootstrapState {
                tenant_id: hex(&TENANT),
                device_id: hex(&JOINER),
                ..Default::default()
            })
            .unwrap();
            for password in ["p", ""] {
                let err = rt
                    .block_on(team_join_code("u".into(), password.into()))
                    .unwrap_err();
                assert!(
                    err.contains("fleet.enrollAgainRefused"),
                    "{status} {password:?}: {err}"
                );
            }
        }
    }

    /// v2.8.1 nit 2: what the e2e mock fakes for an unfinished root setup,
    /// started and this device's but not activated, is what the backend
    /// reports for one, and its expired join code never offers Enroll again,
    /// before any call to the server.
    #[test]
    fn team_join_code_refuses_enroll_again_for_this_devices_unfinished_root_setup() {
        let rt = runtime();
        let (url, calls) = me_server(&rt, "pending");
        let _j = joiner(&url, root_bootstrap::now_ms() - 60 * MINUTE);
        root_bootstrap::save(&root_bootstrap::BootstrapState {
            tenant_id: hex(&TENANT),
            device_id: hex(&JOINER),
            server_instance_id: hex(&INSTANCE),
            ..Default::default()
        })
        .unwrap();
        let status = serde_json::to_value(root_bootstrap::status().unwrap()).unwrap();
        let flag = |name: &str| status[name].as_bool();
        assert_eq!(
            (flag("started"), flag("this_device"), flag("activated")),
            (Some(true), Some(true), Some(false))
        );
        let err = rt
            .block_on(team_join_code("u".into(), "p".into()))
            .unwrap_err();
        assert!(err.contains("fleet.enrollAgainRefused"), "{err}");
        assert!(calls.lock().unwrap().is_empty(), "{:?}", calls.lock());
    }

    /// The device ID the enrollment mock assigns.
    const ENROLLED: [u8; 16] = [0x6c; 16];

    /// Login, challenge and proof as `fleet_client::tests::enrollment`
    /// answers them (tenant `[4; 16]`, account `[5; 16]`), and a `/v2/me`
    /// listing `JOINER` as `old`, or an unreadable listing for an empty `old`.
    fn enroll_reply(call: &str, body: serde_json::Value, old: &str) -> serde_json::Value {
        if call == "GET /v2/me" {
            if old.is_empty() {
                return serde_json::json!({});
            }
            return serde_json::json!({
                "account_id": hex(&[5; 16]),
                "devices": [{"device_id": hex(&JOINER), "status": old}],
            });
        }
        let finish = serde_json::json!({
            "device_id": hex(&ENROLLED), "account_id": hex(&[5; 16]), "signing_key_id": "",
        });
        fleet_client::tests::enrollment(call, body, finish)
    }

    /// `JOINER` of tenant `[4; 16]` at `url`, its `team.json` copied aside
    /// and its identity cleared, as Reset leaves a device: its credentials.
    fn reset_joiner(url: &str) -> (Joiner, [String; 2]) {
        let j = joiner(url, root_bootstrap::now_ms());
        let mut c = team_config::load().unwrap();
        c.tenant_id = hex(&[4; 16]);
        team_config::save(&c).unwrap();
        team_config::preserve_unreadable().unwrap();
        let refs = clear_identity(&mut c);
        team_config::save(&c).unwrap();
        assert_eq!(refs[0], format!("device-signing.{}", hex(&JOINER)));
        (j, refs)
    }

    fn enroll(rt: &tokio::runtime::Runtime, copies: usize) {
        let status = rt
            .block_on(team_enroll_device("l".into(), "u".into(), "p".into()))
            .unwrap();
        assert!(status.is_enrolled);
        assert_eq!(team_config::load().unwrap().device_id, hex(&ENROLLED));
        assert_eq!(team_json_copies(), copies, "the copies stay");
    }

    /// v2.8.1 nit 3: after an enrollment, the old identity a copy names loses
    /// its credentials only when `/v2/me` lists it revoked; pending keeps them.
    #[test]
    fn enrollment_forgets_the_old_identitys_credentials_only_when_the_server_lists_it_revoked() {
        let rt = runtime();
        let url =
            fleet_client::tests::json_server(&rt, |call, body| enroll_reply(call, body, "revoked"));
        let (_j, refs) = reset_joiner(&url);
        // A copy that is not a team config, as recovery import may leave,
        // is skipped and stops nothing.
        let team_json = store::team_config_path().unwrap();
        std::fs::write(
            team_json.with_extension("json.unreadable-0"),
            b"{not a team config",
        )
        .unwrap();
        enroll(&rt, 2);
        for r in &refs {
            let gone = credential::load(r).unwrap_err().to_string();
            assert!(gone.contains("credential.missing"), "{r}: {gone}");
        }
        drop(_j);

        let url =
            fleet_client::tests::json_server(&rt, |call, body| enroll_reply(call, body, "pending"));
        let (_j, refs) = reset_joiner(&url);
        enroll(&rt, 1);
        assert_eq!(*credential::load(&refs[0]).unwrap(), [7; 32]);
        assert_eq!(*credential::load(&refs[1]).unwrap(), [8; 32]);
    }

    /// v2.8.1 nit 3: neither a forget the store refuses nor a listing that
    /// does not read fails the enrollment; what was not forgotten stays.
    #[test]
    fn a_failed_credential_forget_does_not_fail_the_enrollment() {
        let rt = runtime();
        let url =
            fleet_client::tests::json_server(&rt, |call, body| enroll_reply(call, body, "revoked"));
        let (_j, refs) = reset_joiner(&url);
        credential::fail_next_call(&refs[0]);
        enroll(&rt, 1);
        assert_eq!(*credential::load(&refs[0]).unwrap(), [7; 32]);
        assert!(credential::load(&refs[1]).is_err());
        drop(_j);

        let url = fleet_client::tests::json_server(&rt, |call, body| enroll_reply(call, body, ""));
        let (_j, refs) = reset_joiner(&url);
        enroll(&rt, 1);
        assert_eq!(*credential::load(&refs[0]).unwrap(), [7; 32]);
        assert_eq!(*credential::load(&refs[1]).unwrap(), [8; 32]);
    }

    // ---- v2.11 RS: Reset of a revoked root device (ADR 0002 Q-63) ----

    /// The appointee B of the joiner's hand-over, the old root O of the
    /// joiner's accepted hand-over, and a key the joiner never trusted.
    const B_SEED: [u8; 32] = [0x2b; 32];
    const OLD_SEED: [u8; 32] = [0x2a; 32];
    const STRANGER_SEED: [u8; 32] = [0x2c; 32];

    fn key_of(seed: &[u8; 32]) -> shardx_core::signing::Ed25519SigningKey {
        shardx_core::signing::Ed25519SigningKey::from_bytes(seed)
    }

    fn id_of(seed: &[u8; 32]) -> [u8; 32] {
        shardx_core::keys::signing_key_id(key_of(seed).verifying_key().as_bytes())
    }

    /// The joiner's own signing and HPKE key IDs (its seeds are `[7; 32]`
    /// and `[8; 32]`).
    fn joiner_keys() -> ([u8; 32], [u8; 32]) {
        let (_, pk) = shardx_core::grants::derive_keypair(&[8; 32]);
        (id_of(&[7; 32]), shardx_core::keys::hpke_key_id(&pk))
    }

    /// A revocation signed by `by` at `at` of `device` under `key`.
    fn signed_revocation(
        by: &[u8; 32],
        at: u64,
        subject: ([u8; 16], [u8; 16], [u8; 32]),
    ) -> Vec<u8> {
        revocation_on(INSTANCE, by, at, subject)
    }

    /// [`signed_revocation`] naming the server `instance`.
    fn revocation_on(
        instance: [u8; 16],
        by: &[u8; 32],
        at: u64,
        (tenant, device, key): ([u8; 16], [u8; 16], [u8; 32]),
    ) -> Vec<u8> {
        use shardx_core::authz_record::{
            build_record, CommonFields, DeviceRevocationReason, DeviceRevocationV2,
            DOMAIN_DEVICE_REVOCATION,
        };
        let r = DeviceRevocationV2 {
            common: CommonFields {
                replay_id: [at as u8; 16],
                tenant_id: tenant,
                issued_at_ms: at,
                not_before_ms: at,
                not_after_ms: at + DAY,
                server_instance_id: instance,
                restore_epoch: 0,
            },
            subject_account_id: [6; 16],
            subject_device_id: device,
            subject_signing_key_id: key,
            subject_hpke_key_id: joiner_keys().1,
            reason_code: DeviceRevocationReason::Retired,
        };
        build_record(&key_of(by), DOMAIN_DEVICE_REVOCATION, &r.encode())
    }

    /// The joiner's revocation signed by `by` at `at`.
    fn joiner_revoked_by(by: &[u8; 32], at: u64) -> Vec<u8> {
        signed_revocation(by, at, (TENANT, JOINER, joiner_keys().0))
    }

    /// A listed device: revoked by `revocation` from `issuer` when given.
    fn listed(
        device: [u8; 16],
        key: [u8; 32],
        by: Option<(&[u8; 32], Vec<u8>)>,
    ) -> serde_json::Value {
        let mut row = serde_json::json!({
            "device_id": hex(&device),
            "status": if by.is_some() { "revoked" } else { "active" },
            "signing_key_id": hex(&key),
            "hpke_key_id": hex(&[1; 32]),
        });
        if let Some((issuer, exact)) = by {
            row["revocation"] = hex(&exact).into();
            row["revocation_issuer_public_key"] =
                hex(key_of(issuer).verifying_key().as_bytes()).into();
        }
        row
    }

    /// A server whose ticket listing names `devices`; every call is seen.
    fn listing_server(
        rt: &tokio::runtime::Runtime,
        devices: Vec<serde_json::Value>,
    ) -> (fleet_client::FleetClient, fleet_custody::tests::Seen) {
        let reply: std::sync::Arc<fleet_custody::tests::Reply> =
            std::sync::Arc::new(move |call, _| {
                let body = match call {
                    "POST /v2/auth/login" => serde_json::json!({
                        "ticket": "v2t.fixture", "ticket_id": hex(&[1; 16]),
                        "account_id": hex(&[6; 16]), "server_instance_id": hex(&INSTANCE),
                        "restore_epoch": 0
                    }),
                    "GET /v2/me" => serde_json::json!({
                        "kind": "pre_device", "account_id": hex(&[6; 16]), "devices": devices,
                    }),
                    _ => serde_json::json!({}),
                };
                (200, serde_json::to_vec(&body).unwrap())
            });
        rt.block_on(fleet_custody::tests::mock(reply))
    }

    /// The joiner's activated root state, with `custody` as its custody.
    fn root_device_here(custody: fleet_custody::FleetCustodyState) {
        root_bootstrap::save(&root_bootstrap::BootstrapState {
            tenant_id: hex(&TENANT),
            device_id: hex(&JOINER),
            server_instance_id: hex(&INSTANCE),
            anchor: hex(&id_of(&OLD_SEED)),
            activated: true,
            ..Default::default()
        })
        .unwrap();
        fleet_custody::save(&fleet_custody::FleetCustodyState {
            tenant_id: hex(&TENANT),
            device_id: hex(&JOINER),
            server_instance_id: hex(&INSTANCE),
            ..custody
        })
        .unwrap();
    }

    /// The joiner as an old root that appointed B: its saved appointment
    /// approval of B's keys, signed by the joiner.
    fn handed_over_to_b() -> fleet_custody::FleetCustodyState {
        use shardx_core::authz_record::{
            build_record, ApprovalScopeKind, CommonFields, DeviceApprovalV2, DOMAIN_DEVICE_APPROVAL,
        };
        let b = hex(&[0x0b; 16]);
        let approval = DeviceApprovalV2 {
            common: CommonFields {
                replay_id: [0x0b; 16],
                tenant_id: TENANT,
                issued_at_ms: T0,
                not_before_ms: T0,
                not_after_ms: T0 + 730 * DAY,
                server_instance_id: INSTANCE,
                restore_epoch: 0,
            },
            subject_account_id: [6; 16],
            subject_device_id: [0x0b; 16],
            subject_signing_key_id: id_of(&B_SEED),
            subject_hpke_key_id: [1; 32],
            approval_scope_kind: ApprovalScopeKind::Tenant,
            approval_scope_id: TENANT,
        };
        let approval = build_record(
            &key_of(&[7; 32]),
            DOMAIN_DEVICE_APPROVAL,
            &approval.encode(),
        );
        fleet_custody::FleetCustodyState {
            handed_over_to: b.clone(),
            handed_over_generation: 1,
            members: [(
                b,
                fleet_custody::MemberApproval {
                    approval: hex(&approval),
                    root_grant: "00".into(),
                    ..Default::default()
                },
            )]
            .into(),
            ..Default::default()
        }
    }

    /// The joiner as the appointee of O's hand-over, accepted at generation
    /// 1; `rotated` once its own rotation activated generation 2.
    fn accepted_from_old(rotated: bool) -> fleet_custody::FleetCustodyState {
        fleet_custody::FleetCustodyState {
            handover: Some(fleet_custody::Handover {
                outgoing: hex(&id_of(&OLD_SEED)),
                accepted_generation: 1,
                phase: "granted".into(),
                root_grant_issuer: hex(key_of(&OLD_SEED).verifying_key().as_bytes()),
                rotated_generation: if rotated { 2 } else { 0 },
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// Reset of the joiner with its root `custody`, the server listing
    /// `devices`: the reply and the calls seen.
    fn root_reset(
        custody: fleet_custody::FleetCustodyState,
        devices: Vec<serde_json::Value>,
    ) -> (
        Result<team_config::TeamStatus, String>,
        Vec<String>,
        Joiner,
        [String; 2],
    ) {
        let rt = runtime();
        let (client, seen) = listing_server(&rt, devices);
        let j = joiner(client.base_url(), root_bootstrap::now_ms());
        root_device_here(custody);
        let refs = refs();
        let reply = rt.block_on(team_enroll_again("u".into(), "p".into()));
        let calls = seen
            .lock()
            .unwrap()
            .iter()
            .map(|(c, _)| c.clone())
            .collect();
        (reply, calls, j, refs)
    }

    fn joiner_listed(by: Option<(&[u8; 32], Vec<u8>)>) -> serde_json::Value {
        listed(JOINER, joiner_keys().0, by)
    }

    /// Nothing was wiped: the identity and the root state are still here.
    fn untouched(refs: &[String; 2]) {
        assert!(team_config::load().unwrap().is_enrolled());
        assert!(own_root_state(&team_config::load().unwrap()).unwrap());
        for r in refs {
            assert!(credential::load(r).is_ok(), "{r}");
        }
    }

    #[test]
    fn a_handed_over_root_resets_on_its_signed_revocation() {
        let revoked = joiner_revoked_by(&B_SEED, T0 + DAY);
        let (reply, _, _j, refs) = root_reset(
            handed_over_to_b(),
            vec![joiner_listed(Some((&B_SEED, revoked)))],
        );
        reply.unwrap();
        assert_cleared(refs, false);
        assert!(!own_root_state(&team_config::load().unwrap()).unwrap());
    }

    #[test]
    fn a_cancelled_appointee_resets_on_its_signed_revocation() {
        let revoked = joiner_revoked_by(&OLD_SEED, T0 + DAY);
        let (reply, _, _j, refs) = root_reset(
            accepted_from_old(false),
            vec![joiner_listed(Some((&OLD_SEED, revoked)))],
        );
        reply.unwrap();
        assert_cleared(refs, false);
    }

    fn refused_unsigned(reply: Result<team_config::TeamStatus, String>) {
        let err = reply.unwrap_err();
        assert!(
            crate::errcode::has_code(&err, "fleet.resetNeedsSignedRevocation"),
            "{err}"
        );
    }

    #[test]
    fn reset_refuses_a_root_device_without_a_revocation_field() {
        // Listed revoked by a 2.10 server, or still active.
        for row in [
            serde_json::json!({"device_id": hex(&JOINER), "status": "revoked"}),
            joiner_listed(None),
        ] {
            let (reply, calls, _j, refs) = root_reset(handed_over_to_b(), vec![row]);
            refused_unsigned(reply);
            assert!(calls.contains(&"GET /v2/me".to_string()));
            untouched(&refs);
        }
    }

    #[test]
    fn reset_refuses_a_revocation_signed_by_an_unknown_key() {
        let revoked = joiner_revoked_by(&STRANGER_SEED, T0 + DAY);
        let (reply, _, _j, refs) = root_reset(
            handed_over_to_b(),
            vec![joiner_listed(Some((&STRANGER_SEED, revoked.clone())))],
        );
        refused_unsigned(reply);
        untouched(&refs);
        drop(_j);
        // Served under a key it was not signed by.
        let (reply, _, _j, refs) = root_reset(
            handed_over_to_b(),
            vec![joiner_listed(Some((&B_SEED, revoked)))],
        );
        refused_unsigned(reply);
        untouched(&refs);
    }

    #[test]
    fn reset_refuses_a_revocation_naming_another_device_or_key() {
        let (_, key) = (JOINER, joiner_keys().0);
        for subject in [
            (TENANT, [0x0c; 16], key),
            (TENANT, JOINER, id_of(&STRANGER_SEED)),
            ([0x0d; 16], JOINER, key),
        ] {
            let revoked = signed_revocation(&B_SEED, T0 + DAY, subject);
            let (reply, _, _j, refs) = root_reset(
                handed_over_to_b(),
                vec![joiner_listed(Some((&B_SEED, revoked)))],
            );
            refused_unsigned(reply);
            untouched(&refs);
        }
        // Another server instance.
        let subject = (TENANT, JOINER, key);
        let revoked = revocation_on([0x0e; 16], &B_SEED, T0 + DAY, subject);
        let (reply, _, _j, refs) = root_reset(
            handed_over_to_b(),
            vec![joiner_listed(Some((&B_SEED, revoked)))],
        );
        refused_unsigned(reply);
        untouched(&refs);
    }

    #[test]
    fn reset_refuses_a_cancel_after_the_appointee_rotated() {
        let revoked = joiner_revoked_by(&OLD_SEED, T0 + DAY);
        let (reply, _, _j, refs) = root_reset(
            accepted_from_old(true),
            vec![joiner_listed(Some((&OLD_SEED, revoked)))],
        );
        refused_unsigned(reply);
        untouched(&refs);
    }

    /// The appointee whose own rotation to generation 2 stands at `phase`,
    /// with `activate_request` saved, before `rotated_generation` is.
    fn rotating_after_accept(
        phase: fleet_custody::RotationPhase,
        activate_request: &str,
    ) -> fleet_custody::FleetCustodyState {
        fleet_custody::FleetCustodyState {
            rotation: Some(fleet_custody::FleetRotationState {
                generation: 2,
                phase,
                activate_request: activate_request.into(),
                ..Default::default()
            }),
            ..accepted_from_old(false)
        }
    }

    #[test]
    fn reset_refuses_a_cancel_once_the_appointees_rotation_activated() {
        let revoked = joiner_revoked_by(&OLD_SEED, T0 + DAY);
        let (reply, _, _j, refs) = root_reset(
            rotating_after_accept(fleet_custody::RotationPhase::Activated, "00"),
            vec![joiner_listed(Some((&OLD_SEED, revoked)))],
        );
        refused_unsigned(reply);
        untouched(&refs);
    }

    #[test]
    fn reset_refuses_a_cancel_once_the_appointees_activation_was_sent() {
        // Its reply may have been lost: generation 2 may be ACTIVE.
        let revoked = joiner_revoked_by(&OLD_SEED, T0 + DAY);
        let (reply, _, _j, refs) = root_reset(
            rotating_after_accept(fleet_custody::RotationPhase::Preparing, "00"),
            vec![joiner_listed(Some((&OLD_SEED, revoked.clone())))],
        );
        refused_unsigned(reply);
        untouched(&refs);
        drop(_j);
        // A rotation that expired never activated: the cancel still resets.
        let (reply, _, _j, refs) = root_reset(
            rotating_after_accept(fleet_custody::RotationPhase::Expired, "00"),
            vec![joiner_listed(Some((&OLD_SEED, revoked)))],
        );
        reply.unwrap();
        assert_cleared(refs, false);
    }

    /// The appointee revoked O itself at T0: O's revocation of it from T0 on
    /// is refused.
    #[test]
    fn reset_refuses_a_revocation_signed_after_this_device_revoked_its_issuer() {
        use shardx_core::mutation::{
            DeviceRevokeRequestV2, IdempotentMutationRequestV2, OperationKind,
        };
        let container = signed_revocation(&[7; 32], T0, (TENANT, [0x0a; 16], id_of(&OLD_SEED)));
        let payload = DeviceRevokeRequestV2 {
            signed_container_hash: *shardx_core::authz_record::AuthorizationRecord::parse(
                &container,
            )
            .unwrap()
            .signed_container_hash(),
            exact_signed_revocation_container_bytes: container,
            activations: Vec::new(),
        };
        let request = IdempotentMutationRequestV2 {
            operation_kind: OperationKind::DeviceRevoke,
            idempotency_key: [0x41; 16],
            canonical_payload_bytes: payload.encode(),
            client_request_nonce: [0x42; 16],
            server_instance_id: INSTANCE,
            restore_epoch: 0,
        };
        let mut custody = accepted_from_old(false);
        custody
            .revocations
            .insert(hex(&[0x0a; 16]), hex(&request.encode()));
        let revoked = joiner_revoked_by(&OLD_SEED, T0 + DAY);
        let (reply, _, _j, refs) =
            root_reset(custody, vec![joiner_listed(Some((&OLD_SEED, revoked)))]);
        refused_unsigned(reply);
        untouched(&refs);
    }

    /// The root state goes before the custody state: a wipe that stops at the
    /// root state leaves a device Reset still takes as a revoked root.
    #[cfg(windows)]
    #[test]
    fn a_reset_stopped_before_the_root_state_went_resets_again() {
        use std::os::windows::fs::OpenOptionsExt;
        let rt = runtime();
        let revoked = joiner_revoked_by(&B_SEED, T0 + DAY);
        let (client, _) = listing_server(&rt, vec![joiner_listed(Some((&B_SEED, revoked)))]);
        let _j = joiner(client.base_url(), root_bootstrap::now_ms());
        root_device_here(handed_over_to_b());
        let refs = refs();
        // Read sharing only: the root state cannot be deleted while open.
        let held = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(store::custody_bootstrap_path().unwrap())
            .unwrap();
        rt.block_on(team_enroll_again("u".into(), "p".into()))
            .unwrap_err();
        drop(held);
        assert!(store::fleet_custody_path().unwrap().exists());
        untouched(&refs);
        rt.block_on(team_enroll_again("u".into(), "p".into()))
            .unwrap();
        assert_cleared(refs, false);
        assert!(!store::custody_bootstrap_path().unwrap().exists());
        assert!(!store::fleet_custody_path().unwrap().exists());
    }

    /// A stolen former custodian key (here the pinned anchor and the old root
    /// of another hand-over) plus a hostile server never wipe a root device.
    #[test]
    fn reset_refuses_a_revocation_from_a_former_custodian_key() {
        // The old root trusts only B; O is its pinned anchor.
        let revoked = joiner_revoked_by(&OLD_SEED, T0 + DAY);
        let (reply, _, _j, refs) = root_reset(
            handed_over_to_b(),
            vec![joiner_listed(Some((&OLD_SEED, revoked)))],
        );
        refused_unsigned(reply);
        untouched(&refs);
        drop(_j);
        // The appointee trusts only O, never the device it was appointed by
        // another custodian key.
        let revoked = joiner_revoked_by(&B_SEED, T0 + DAY);
        let (reply, _, _j, refs) = root_reset(
            accepted_from_old(false),
            vec![joiner_listed(Some((&B_SEED, revoked)))],
        );
        refused_unsigned(reply);
        untouched(&refs);
    }

    #[test]
    fn reset_refuses_a_revocation_signed_after_the_issuer_was_revoked() {
        // B itself was revoked at T0 + DAY; its revocation of the joiner
        // carries a later time.
        let b_revoked = signed_revocation(
            &STRANGER_SEED,
            T0 + DAY,
            (TENANT, [0x0b; 16], id_of(&B_SEED)),
        );
        let revoked = joiner_revoked_by(&B_SEED, T0 + 2 * DAY);
        let (reply, _, _j, refs) = root_reset(
            handed_over_to_b(),
            vec![
                listed(
                    [0x0b; 16],
                    id_of(&B_SEED),
                    Some((&STRANGER_SEED, b_revoked.clone())),
                ),
                joiner_listed(Some((&B_SEED, revoked))),
            ],
        );
        refused_unsigned(reply);
        untouched(&refs);
        drop(_j);
        // Signed before B's revocation, it still resets.
        let revoked = joiner_revoked_by(&B_SEED, T0);
        let (reply, _, _j, refs) = root_reset(
            handed_over_to_b(),
            vec![
                listed(
                    [0x0b; 16],
                    id_of(&B_SEED),
                    Some((&STRANGER_SEED, b_revoked)),
                ),
                joiner_listed(Some((&B_SEED, revoked))),
            ],
        );
        reply.unwrap();
        assert_cleared(refs, false);
    }

    #[test]
    fn reset_wipes_trk_fleet_keys_root_state_custody_and_seeds() {
        let rt = runtime();
        let revoked = joiner_revoked_by(&B_SEED, T0 + DAY);
        let (client, _) = listing_server(&rt, vec![joiner_listed(Some((&B_SEED, revoked)))]);
        let _j = joiner(client.base_url(), root_bootstrap::now_ms());
        pin_here();
        let mut c = team_config::load().unwrap();
        c.fleet_id = hex(&TENANT);
        team_config::save(&c).unwrap();
        // Create fleet key's and a rotation's setup keys.
        let setup: Vec<String> = [0x5f, 0x6f]
            .map(|n| format!("fleet-setup.{}.{}", hex(&TENANT), hex(&[n; 16])))
            .into();
        root_device_here(fleet_custody::FleetCustodyState {
            fkek_nonce: hex(&[0x5f; 16]),
            rotation: Some(fleet_custody::FleetRotationState {
                fkek_nonce: hex(&[0x6f; 16]),
                ..Default::default()
            }),
            ..handed_over_to_b()
        });
        for name in &setup {
            credential::store(name, &[0x5f; 32]).unwrap();
        }
        let trk = format!("tenant-root.{}.{}", hex(&TENANT), hex(&[0x5e; 16]));
        credential::store(&trk, &[0x5e; 32]).unwrap();
        let mut root = root_bootstrap::load().unwrap();
        (root.trk_nonce, root.trk_ref) = (hex(&[0x5e; 16]), trk.clone());
        // An unfinished root rotation holds its new TRK under its own nonce.
        let next_trk = root_bootstrap::trk_ref(&root.tenant_id, &hex(&[0x6f; 16]));
        credential::store(&next_trk, &[0x6f; 32]).unwrap();
        root.root_rotation = Some(crate::root_rotation::RootRotation {
            trk_nonce: hex(&[0x6f; 16]),
            ..Default::default()
        });
        root_bootstrap::save(&root).unwrap();
        assert!(fleet_keys::collect(&hex(&TENANT), 1, &[0x31; 32]).unwrap());
        assert!(fleet_keys::collect(&hex(&TENANT), 2, &[0x32; 32]).unwrap());
        let held = fleet_keys::load().unwrap().fleets[&hex(&TENANT)].clone();
        let refs = refs();

        rt.block_on(team_enroll_again("u".into(), "p".into()))
            .unwrap();
        assert_cleared(refs, false);
        assert!(credential::load(&trk).is_err(), "the TRK is forgotten");
        assert!(
            credential::load(&next_trk).is_err(),
            "the rotation TRK is forgotten"
        );
        for name in &setup {
            assert!(credential::load(name).is_err(), "{name}");
        }
        assert!(!fleet_keys::load()
            .unwrap()
            .fleets
            .contains_key(&hex(&TENANT)));
        for reference in held.credential_refs.values() {
            assert!(credential::load(reference).is_err(), "{reference}");
        }
        assert!(!store::custody_bootstrap_path().unwrap().exists());
        assert!(!store::fleet_custody_path().unwrap().exists());
        assert_eq!(
            join_pin(),
            Some((BINDING_J, [0x0a; 32], "JOIN".to_string())),
            "the pin stays"
        );
        assert_eq!(team_json_copies(), 0, "a signed revocation keeps nothing");
    }

    #[test]
    fn a_live_root_custodian_still_never_resets() {
        // Whatever the server lists, signed or not.
        let revoked = joiner_revoked_by(&B_SEED, T0 + DAY);
        let (reply, calls, _j, refs) = root_reset(
            fleet_custody::FleetCustodyState::default(),
            vec![joiner_listed(Some((&B_SEED, revoked)))],
        );
        let err = reply.unwrap_err();
        assert!(err.contains("fleet.enrollAgainRefused"), "{err}");
        assert!(calls.is_empty(), "no server is asked");
        untouched(&refs);
    }

    /// R3-D5: the UI treats a root state as this device's only when it names
    /// this tenant and device, or when `team.json` does not read.
    #[test]
    fn bootstrap_status_says_whether_the_root_state_is_this_devices() {
        let _j = joiner(URL_J, root_bootstrap::now_ms());
        let this_device = || {
            serde_json::to_value(root_bootstrap::status().unwrap()).unwrap()["this_device"].clone()
        };
        assert_eq!(this_device(), serde_json::json!(false), "no root state");
        root_here();
        assert_eq!(this_device(), serde_json::json!(true));
        let mine = root_bootstrap::load().unwrap();
        for other in [
            root_bootstrap::BootstrapState {
                device_id: hex(&[0x6b; 16]),
                ..mine.clone()
            },
            root_bootstrap::BootstrapState {
                tenant_id: hex(&[0x0e; 16]),
                ..mine.clone()
            },
        ] {
            root_bootstrap::save(&other).unwrap();
            assert_eq!(this_device(), serde_json::json!(false), "{other:?}");
        }
        // A directory in its place: `team.json` does not read at all.
        let team_json = store::team_config_path().unwrap();
        std::fs::remove_file(&team_json).unwrap();
        std::fs::create_dir(&team_json).unwrap();
        assert_eq!(
            this_device(),
            serde_json::json!(true),
            "an unreadable team.json"
        );
    }

    /// Nit 1: a ledger whose existence cannot be checked is not a device
    /// with no ledger.
    #[cfg(unix)]
    #[test]
    fn a_ledger_that_cannot_be_checked_is_an_error() {
        let _j = joiner(URL_J, root_bootstrap::now_ms());
        let dir = team::db::Db::path()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::write(&dir, b"not a directory").unwrap();
        assert!(tenant_pin(&TENANT).is_err());
    }

    /// Nit 2: the pin decides only for an active device, so a ledger that
    /// does not read never stops Enroll again of a pending or revoked one.
    #[test]
    fn an_unreadable_ledger_stops_only_an_active_device() {
        for status in ["pending", "revoked"] {
            let rt = runtime();
            let (url, _) = me_server(&rt, status);
            let _j = joiner(&url, root_bootstrap::now_ms() - 60 * MINUTE);
            let ledger = team::db::Db::path().unwrap();
            std::fs::create_dir_all(ledger.parent().unwrap()).unwrap();
            std::fs::write(&ledger, b"unreadable test ledger").unwrap();
            let err = rt
                .block_on(team_join_code("u".into(), "p".into()))
                .unwrap_err();
            assert!(err.contains("fleet.joinCodeExpired"), "{status}: {err}");
            rt.block_on(team_enroll_again("u".into(), "p".into()))
                .unwrap();
            assert!(!team_config::load().unwrap().is_enrolled(), "{status}");
        }
    }

    /// Nit 5: an expired code of an active device whose ledger does not read
    /// reports that, never the plain expired code that offers Enroll again.
    #[test]
    fn an_expired_code_with_an_unreadable_ledger_offers_no_enroll_again() {
        let rt = runtime();
        let (url, _) = me_server(&rt, "active");
        let _j = joiner(&url, root_bootstrap::now_ms() - 60 * MINUTE);
        pin_here();
        std::fs::write(team::db::Db::path().unwrap(), b"unreadable test ledger").unwrap();
        let err = rt
            .block_on(team_join_code("u".into(), "p".into()))
            .unwrap_err();
        assert!(err.contains("team.trustLedgerUnreadable"), "{err}");
        assert!(!err.contains("fleet.joinCodeExpired"), "{err}");
    }

    /// Nit 5: a ticket and a listing that both name an account, but not the
    /// same one, never reset the device.
    #[test]
    fn reset_is_refused_when_ticket_and_listing_name_different_accounts() {
        let rt = runtime();
        let reply: std::sync::Arc<fleet_custody::tests::Reply> = std::sync::Arc::new(|call, _| {
            let body = match call {
                "POST /v2/auth/login" => serde_json::json!({
                    "ticket": "v2t.fixture", "ticket_id": hex(&[1; 16]),
                    "account_id": hex(&[6; 16]), "server_instance_id": hex(&INSTANCE),
                    "restore_epoch": 0
                }),
                "GET /v2/me" => serde_json::json!({
                    "account_id": hex(&[0x6c; 16]), "server_instance_id": hex(&INSTANCE),
                    "devices": [{"device_id": hex(&JOINER), "status": "pending"}]
                }),
                _ => serde_json::json!({}),
            };
            (200, serde_json::to_vec(&body).unwrap())
        });
        let (client, _) = rt.block_on(fleet_custody::tests::mock(reply));
        let _j = joiner(client.base_url(), root_bootstrap::now_ms());
        let before = team_json();
        let references = refs();
        let err = rt
            .block_on(team_enroll_again("u".into(), "p".into()))
            .unwrap_err();
        assert!(
            crate::errcode::has_code(&err, "fleet.enrollAgainOtherAccount"),
            "{err}"
        );
        assert!(team_json() == before);
        assert!(references.iter().all(|r| credential::load(r).is_ok()));
    }

    /// Makes the joiner the activated root custodian of its tenant.
    fn root_here() {
        root_bootstrap::save(&root_bootstrap::BootstrapState {
            tenant_id: hex(&TENANT),
            device_id: hex(&JOINER),
            server_instance_id: hex(&INSTANCE),
            anchor: hex(&[0x0a; 32]),
            activated: true,
            ..Default::default()
        })
        .unwrap();
    }

    const URL_J: &str = "http://team.example";

    /// A server change and a tenant change of the joiner.
    fn connection_changes() -> [(String, String); 2] {
        [
            ("http://other.example".into(), hex(&TENANT)),
            (URL_J.into(), hex(&[0x0e; 16])),
        ]
    }

    fn team_json() -> Vec<u8> {
        std::fs::read(store::team_config_path().unwrap()).unwrap()
    }

    fn load_err(reference: &str) -> String {
        credential::load(reference).unwrap_err().to_string()
    }

    /// S4, G13: a root state that does not load fails the change closed, as
    /// Enroll again does: nothing is copied, saved or forgotten.
    #[test]
    fn a_server_change_with_a_corrupt_root_state_is_refused() {
        for (url, tenant) in connection_changes() {
            let _j = joiner(URL_J, root_bootstrap::now_ms());
            std::fs::write(store::custody_bootstrap_path().unwrap(), b"{corrupt").unwrap();
            let refs = refs();
            let before = team_json();
            assert!(team_set_connection(url, String::new(), tenant).is_err());
            assert_eq!(team_json(), before);
            assert_eq!(team_json_copies(), 0);
            assert_eq!(*credential::load(&refs[0]).unwrap(), [7; 32]);
            assert_eq!(*credential::load(&refs[1]).unwrap(), [8; 32]);
        }
    }

    /// A link to itself: a path whose existence cannot be checked. Windows
    /// uses a junction, which needs no privilege.
    fn link_to_itself(path: &std::path::Path) {
        #[cfg(windows)]
        {
            let made = std::process::Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(path)
                .arg(path)
                .output()
                .unwrap();
            assert!(made.status.success(), "{made:?}");
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(path, path).unwrap();
    }

    /// R4-D1: a root state whose existence cannot be checked is not a device
    /// without one. A connection change and Reset fail closed, with
    /// `team.json` and both credentials unchanged; the custody state and
    /// `team.json` do not read as absent either.
    #[test]
    fn a_root_state_that_cannot_be_checked_keeps_the_identity() {
        let kept = |refs: &[String; 2], before: &[u8]| {
            assert_eq!(team_json(), before);
            assert_eq!(team_json_copies(), 0);
            assert_eq!(*credential::load(&refs[0]).unwrap(), [7; 32]);
            assert_eq!(*credential::load(&refs[1]).unwrap(), [8; 32]);
        };
        for (url, tenant) in connection_changes() {
            let _j = joiner(URL_J, root_bootstrap::now_ms());
            link_to_itself(&store::custody_bootstrap_path().unwrap());
            let refs = refs();
            let before = team_json();
            assert!(team_set_connection(url, String::new(), tenant).is_err());
            kept(&refs, &before);
        }
        for status in ["pending", "revoked"] {
            let rt = runtime();
            let (url, calls) = me_server(&rt, status);
            let _j = joiner(&url, root_bootstrap::now_ms());
            link_to_itself(&store::custody_bootstrap_path().unwrap());
            let refs = refs();
            let before = team_json();
            assert!(rt
                .block_on(team_enroll_again("u".into(), "p".into()))
                .is_err());
            kept(&refs, &before);
            assert!(calls.lock().unwrap().is_empty(), "no server is asked");
        }
        let _j = joiner(URL_J, root_bootstrap::now_ms());
        link_to_itself(&store::fleet_custody_path().unwrap());
        assert!(fleet_custody::load().is_err());
        std::fs::remove_file(store::team_config_path().unwrap()).unwrap();
        link_to_itself(&store::team_config_path().unwrap());
        assert!(team_config::load().is_err());
    }

    /// S4, G13 (plan v0.2.2b): a server or tenant change is refused for the
    /// root custodian whose seeds read, do not answer or are locked, with
    /// `team.json` and its credentials unchanged.
    #[test]
    fn a_root_custodian_whose_keys_are_not_lost_keeps_its_connection() {
        for case in ["readable", "unavailable", "locked"] {
            for (url, tenant) in connection_changes() {
                let _j = joiner(URL_J, root_bootstrap::now_ms());
                root_here();
                let refs = refs();
                if case != "readable" {
                    for r in &refs {
                        credential::forget(r).unwrap();
                    }
                }
                if case == "unavailable" {
                    // One seed unavailable and one missing: only both lost
                    // lets the change through, so the guard refuses. Only
                    // its own read may take this failure: had anything read
                    // it first, both seeds would be lost.
                    credential::fail_next_call(&refs[0]);
                }
                if case == "locked" {
                    let key_file = key_file::path().unwrap();
                    std::fs::create_dir_all(key_file.parent().unwrap()).unwrap();
                    std::fs::write(&key_file, b"locked").unwrap();
                }
                let before = team_json();
                let err = team_set_connection(url, String::new(), tenant).unwrap_err();
                assert!(
                    err.contains("fleet.rootCustodianKeepsConnection"),
                    "{case}: {err}"
                );
                assert_eq!(team_json(), before, "{case}");
                assert_eq!(team_json_copies(), 0, "{case}");
                match case {
                    "readable" => {
                        assert_eq!(*credential::load(&refs[0]).unwrap(), [7; 32]);
                        assert_eq!(*credential::load(&refs[1]).unwrap(), [8; 32]);
                    }
                    "unavailable" => {
                        for r in &refs {
                            assert!(load_err(r).contains("credential.missing"), "{r}");
                        }
                    }
                    _ => {
                        for r in &refs {
                            assert!(load_err(r).contains("credential.locked"), "{r}");
                        }
                    }
                }
            }
        }
    }

    /// S4, G13: with both seeds lost, as missing credentials or as DPAPI
    /// blobs this account cannot open, the root custodian's change goes
    /// through with `team.json` copied and no credential forgotten. A member
    /// changes as before, its credentials forgotten. Either way the saved
    /// fleet grant acks go (G12).
    #[test]
    fn a_root_custodian_with_lost_keys_or_a_member_may_change_its_connection() {
        for case in ["missing", "foreign", "member"] {
            for (url, tenant) in connection_changes() {
                let _j = joiner(URL_J, root_bootstrap::now_ms());
                if case != "member" {
                    root_here();
                }
                saved_ack();
                let refs = refs();
                if case == "missing" {
                    for r in &refs {
                        credential::forget(r).unwrap();
                    }
                }
                if case == "foreign" {
                    // The file's blobs win over the stored seeds, which a
                    // forget would delete.
                    let mut c = team_config::load().unwrap();
                    c.signing_key_seed = "dpapi:AAAA".to_string().into();
                    c.hpke_key_seed = "dpapi:AAAA".to_string().into();
                    team_config::save(&c).unwrap();
                }
                team_set_connection(url.clone(), String::new(), tenant.clone()).unwrap();
                let c = team_config::load().unwrap();
                assert!(c.device_id.is_empty() && !c.is_enrolled(), "{case}");
                assert_eq!((c.server_url, c.tenant_id), (url, tenant));
                assert!(fleet_custody::load().unwrap().device_acks.is_empty());
                match case {
                    "missing" => assert_eq!(team_json_copies(), 1),
                    "foreign" => {
                        assert_eq!(team_json_copies(), 1);
                        assert_eq!(*credential::load(&refs[0]).unwrap(), [7; 32]);
                        assert_eq!(*credential::load(&refs[1]).unwrap(), [8; 32]);
                    }
                    _ => {
                        assert_eq!(team_json_copies(), 0);
                        for r in &refs {
                            assert!(load_err(r).contains("credential.missing"), "{r}");
                        }
                    }
                }
            }
        }
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
        assert_running_blocked(rt.block_on(sync_cmd::profile_sync_revert(
            profile_id.to_string(),
            None,
            None,
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
        // After single-instance: a link a second launch carries reaches this one.
        .plugin(tauri_plugin_deep_link::init())
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
            team_export_recovery_bundle,
            team_fleet_custody_status,
            team_fleet_key_setup,
            team_fleet_key_rotate,
            team_reseal_all,
            team_renew_custody,
            team_rotate_root,
            team_devices,
            team_approve_device,
            team_custody_accept,
            team_revoke_device,
            team_join_code,
            team_join_confirm,
            team_enroll_again,
            team_import_recovery_bundle,
            team_set_connection,
            team_test_connection,
            team_enroll_device,
            backup_cmd::profile_backup_create,
            sync_cmd::profile_sync_push,
            sync_cmd::profile_sync_publish,
            sync_cmd::profile_sync_cancel_publish,
            sync_cmd::profile_sync_revert,
            sync_cmd::profile_sync_pull,
            sync_cmd::profile_sync_status,
            sync_cmd::team_profiles_status,
            sync_cmd::team_profiles_under_older_key,
            sync_cmd::team_fleet_profiles,
            sync_cmd::team_join_profile,
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
            open_link::open_link_take,
        ])
        .setup(|app| {
            let _ = APP_HANDLE.set(app.handle().clone());

            {
                use tauri_plugin_deep_link::DeepLinkExt;
                // Installers register the scheme; an AppImage and a dev run have none.
                #[cfg(any(target_os = "linux", all(debug_assertions, windows)))]
                if let Err(e) = app.deep_link().register_all() {
                    eprintln!("[launcher] shardbrowser:// links not registered: {e}");
                }
                app.deep_link().on_open_url(|event| {
                    open_link::handle(event.urls().iter().map(|u| u.as_str()))
                });
                if let Ok(Some(urls)) = app.deep_link().get_current() {
                    open_link::handle(urls.iter().map(|u| u.as_str()));
                }
            }

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
