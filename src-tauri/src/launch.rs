use crate::{
    bookmarks, extensions,
    process::{self, Tracker},
    profile, proxy, settings, store,
};
use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Stdio;

/// Launch result: OS pid plus CDP endpoint when remote-debugging is on.
pub struct LaunchOutcome {
    pub pid: u32,
    pub launch_instance_token: String,
    pub cdp: Option<process::CdpInfo>,
}

struct LaunchOptions {
    args: Vec<String>,
    extension_dirs: Vec<PathBuf>,
    /// Restore the previous session on an interactive launch. Default true,
    /// matching what the browser does on its own. Automation profiles set this
    /// false: a profile driven by CDP accumulates tabs nobody closes, and
    /// reopening it then reloads all of them at once.
    restore_session: bool,
}

impl Default for LaunchOptions {
    fn default() -> Self {
        Self {
            args: Vec::new(),
            extension_dirs: Vec::new(),
            restore_session: true,
        }
    }
}

/// Resolve the ShardX executable from settings, runtime cache, or dev guess.
pub fn resolve_binary() -> Result<PathBuf> {
    if let Some(p) = settings::load()?.browser_path {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return Ok(pb);
        }
    }
    if let Ok(pb) = crate::runtime::binary_path() {
        if pb.exists() {
            return Ok(pb);
        }
    }
    #[cfg(target_os = "macos")]
    let guess = "/Users/kritos/Documents/GitHub/ShardXBrowser/build/src/out/Release_GN_arm64/ShardX.app/Contents/MacOS/ShardX";
    #[cfg(target_os = "windows")]
    let guess = "C:\\Program Files\\ShardX\\ShardX.exe";
    #[cfg(target_os = "linux")]
    let guess = "/opt/shardx/shardx";
    let pb = PathBuf::from(guess);
    if pb.exists() {
        return Ok(pb);
    }
    anyhow::bail!(crate::errcode::code("launch.browserMissing"))
}

/// Switches for a CDP-enabled launch. `--shardx-automation` gates the engine's
/// `Motion` domain, which human clicks and typing go through; without it every
/// `Motion.*` call answers "wasn't found". Unused, it costs nothing: the domain
/// stays out of `Schema.getDomains` either way.
pub(crate) const CDP_ARGS: [&str; 3] = [
    "--remote-debugging-port=0",
    "--remote-allow-origins=*",
    "--shardx-automation",
];

/// A window to go with the claimed screen (#67). Without one the engine passes
/// no --window-size and Chromium uses the REAL monitor's work area, so a
/// profile claiming 1920x1080 opened in a window sized for the host and sitting
/// outside its own claimed screen. A profile that names a usable window keeps
/// it. Derived per launch, never written back, so the stored profile (and team
/// sync) is untouched. Ported from upstream 081770c.
fn fill_window_from_screen(raw: &mut serde_json::Map<String, serde_json::Value>) {
    let Some(scr) = raw.get("screen").and_then(|v| v.as_object()) else {
        return;
    };
    let w = scr.get("width").and_then(|v| v.as_i64()).unwrap_or(0);
    let h = scr.get("height").and_then(|v| v.as_i64()).unwrap_or(0);
    if w <= 0 || h <= 0 {
        return;
    }
    let avail_w = scr
        .get("avail_width")
        .and_then(|v| v.as_i64())
        .unwrap_or(w)
        .max(1);
    let avail_h = scr
        .get("avail_height")
        .and_then(|v| v.as_i64())
        .unwrap_or(h)
        .max(1);
    let names_a_window = raw
        .get("window")
        .and_then(|v| v.as_object())
        .is_some_and(|win| {
            win.get("outer_width").and_then(|v| v.as_i64()).unwrap_or(0) > 0
                && win
                    .get("outer_height")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0)
                    > 0
        });
    if names_a_window {
        return;
    }
    let outer_h = (avail_h - 1).max(1);
    raw.insert(
        "window".into(),
        serde_json::json!({
            "outer_width": avail_w,
            "outer_height": outer_h,
            "inner_width": avail_w,
            "inner_height": (outer_h - 87).max(1),
        }),
    );
    eprintln!(
        "[launcher] display: profile named no window — derived {avail_w}x{outer_h} \
         from its claimed {w}x{h} screen"
    );
}

pub async fn launch_profile(
    profile_id: &str,
    enable_cdp: bool,
    headless: bool,
) -> Result<LaunchOutcome> {
    launch_profile_synced(profile_id, enable_cdp, headless, None, 0, "").await
}

/// As `launch_profile`, but joins the browser to a synchronisation group:
/// every profile launched under the same `sync_group` mirrors input.
pub async fn launch_profile_synced(
    profile_id: &str,
    enable_cdp: bool,
    headless: bool,
    sync_group: Option<&str>,
    bus_port: u16,
    bus_token: &str,
) -> Result<LaunchOutcome> {
    let launch_claim = profile::begin_profile_launch(profile_id)?;
    let bin = resolve_binary()?;
    let stored = profile::load_raw(profile_id)?;
    let udd = profile::user_data_dir(profile_id)?;
    // A browser this launcher did not start (an earlier launcher run, or one
    // started by hand) already holds the profile; a new launch would only be
    // handed over to it and exit.
    if crate::process::lock_is_live(&udd) {
        anyhow::bail!(crate::errcode::code("launch.openElsewhere"));
    }

    // Stored proxy by id, else ephemeral inline (quick profiles, not in store).
    let bound_proxy: Option<proxy::ProxyEntry> = stored
        .meta
        .proxy_id
        .as_deref()
        .and_then(|pid| proxy::get(pid).ok().flatten())
        .or_else(|| stored.meta.inline_proxy.clone());

    // Live UDP probe; QUIC/WebRTC gating uses current capability not stale cache.
    let proxy_udp_ok = if let Some(p) = bound_proxy.as_ref() {
        if matches!(p.kind, proxy::ProxyKind::Socks5) {
            match proxy::probe_udp(p).await {
                Ok(ms) => {
                    eprintln!("[launcher] UDP relay OK ({ms} ms) for proxy {}", p.host);
                    true
                }
                Err(e) => {
                    // Fail closed. A cached pass is no evidence: a proxy edited
                    // in place keeps its test history, and a VPN can make UDP
                    // look fine at test time. Enabling QUIC/WebRTC on a relay
                    // that drops UDP leaks or stalls the profile (CarterLeeAlt
                    // 5b418a9; upstream 6c3f65a "udp-test-vpn").
                    eprintln!(
                        "[launcher] UDP probe failed for proxy {} ({e}); QUIC and proxied WebRTC stay off",
                        p.host
                    );
                    false
                }
            }
        } else {
            false
        }
    } else {
        false
    };

    // Strip `_meta` wrapper and resolve "auto" sentinels before serialising.
    let mut raw = stored.config.clone();
    raw.remove("_meta");
    let launch_options = parse_launch_options(raw.remove("launch"))
        .context(crate::errcode::code("launch.optionsInvalid"))?;
    // Preserve legacy profile data in storage, but do not hand it to the
    // closed-source engine until the coherence gate in the design note passes.
    remove_unavailable_custom_fonts(&mut raw);
    resolve_auto_fields(&mut raw, bound_proxy.as_ref()).await;
    fill_window_from_screen(&mut raw);
    // The claimed screen still has to fit this monitor: the profile may have
    // moved to a smaller machine since it was created, and a window cannot be
    // larger than the screen it opens on. A display that holds the claim
    // leaves it untouched. "Real screen" mode hands the host's screen to the
    // engine instead, so there is nothing to fit.
    let real_screen = settings::load()
        .map(|s| s.screen_resolution_mode.as_deref() == Some("real"))
        .unwrap_or(false);
    if !real_screen {
        if let Some(w) = crate::main_window() {
            crate::clamp_screen_to_real_display(&w, &mut raw);
        }
    }
    let json =
        serde_json::to_string(&raw).context(crate::errcode::code("launch.serializeProfile"))?;

    // Pass fingerprint by file path — inline JSON overflows Windows' 32767-char CreateProcess limit.
    let fp_file = udd.join("fingerprint.json");
    std::fs::write(&fp_file, &json).context(crate::errcode::code("launch.writeFingerprint"))?;

    // Pre-warm Widevine CDM to avoid first-DRM-page component-updater stall.
    if let Err(e) = install_widevine(&udd) {
        eprintln!("[launcher] widevine pre-warm skipped: {e}");
    }

    let mut cmd = tokio::process::Command::new(&bin);
    cmd.arg(format!("--fingerprint-profile={}", fp_file.display()));
    cmd.arg(format!("--user-data-dir={}", udd.display()));

    // Per-profile window icon. A failure here is cosmetic, never fatal.
    let color = stored.meta.color.clone().filter(|c| !c.trim().is_empty());
    match crate::runtime::runtime_dir().and_then(|dir| {
        // Display name lives in the config, not in _meta; id as fallback.
        let name = stored
            .config
            .get("name")
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(profile_id);
        crate::profile_icon::ensure_icon(&dir, name, color.as_deref())
    }) {
        Ok(path) => {
            cmd.arg(format!("--shardx-profile-icon={}", path.display()));
        }
        Err(e) => {
            eprintln!("[launcher] profile icon unavailable: {e:#}");
        }
    }
    // Same accent behind the profile-name pill in the omnibox, so the icon and
    // the window never disagree about a profile's colour. Left off for "auto":
    // the pill then keeps the toolbar colour, which is the browser's own
    // default and follows the theme.
    if let Some(c) = color.as_deref() {
        cmd.arg(format!("--shardx-profile-pill-color={c}"));
    }
    cmd.arg("--no-first-run");

    // The browser's OWN strings -- form validation bubbles, context menus, the
    // built-in error and PDF pages -- come from Chromium's UI locale, which it
    // reads from the host OS unless told otherwise. A profile that claims
    // en-US but whose right-click menu is in Russian has announced the machine
    // behind it, so pass the locale the profile actually resolved to.
    if let Some(locale) = raw
        .get("icu_locale")
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
    {
        cmd.arg(format!("--lang={locale}"));
    }

    for arg in &launch_options.args {
        cmd.arg(arg);
    }
    // Extensions come from two places: explicit launch options (ours) and the
    // extension library (upstream). Chromium loads only what
    // --disable-extensions-except allows, so both lists go in together.
    let mut ext_paths: Vec<String> = launch_options
        .extension_dirs
        .iter()
        .map(|p| p.display().to_string())
        .collect();
    ext_paths.extend(
        stored
            .meta
            .extensions
            .iter()
            .filter_map(|id| extensions::load_path(id))
            .map(|p| p.display().to_string()),
    );
    if !ext_paths.is_empty() {
        let joined = ext_paths.join(",");
        cmd.arg(format!("--disable-extensions-except={joined}"));
        cmd.arg(format!("--load-extension={joined}"));
    }

    // Folder bookmarks, written before the browser reads the file.
    match bookmarks::apply_to_profile(&udd, &stored.meta.folder) {
        Ok(n) if n > 0 => eprintln!("[launcher] {n} folder bookmark(s) applied"),
        Ok(_) => {}
        Err(e) => eprintln!("[launcher] bookmarks skipped: {e}"),
    }
    // Disable WebGPU when profile omits `webgpu` (matches real Linux Chrome).
    let webgpu_present = raw.get("webgpu").map(|v| !v.is_null()).unwrap_or(false);
    if !webgpu_present {
        cmd.arg("--disable-features=WebGPU");
    }

    // Interactive launches: restore previous session, suppress crash bubble.
    // `launch.restore_session: false` opts a profile out — automation profiles
    // pile up tabs that nobody closes, and restoring them all at once is what
    // makes a long-idle profile crawl on reopen.
    if !headless && !enable_cdp {
        if launch_options.restore_session {
            cmd.arg("--restore-last-session");
        }
        cmd.arg("--hide-crash-restore-bubble");
    }

    // Credentials the engine cannot carry inline go through a loopback relay
    // (#100); it must outlive the spawn, so the tracker takes it below.
    let mut proxy_relay = None;
    if let Some(p) = bound_proxy.as_ref() {
        let proxy_arg = if crate::proxy_relay::needs_relay(p) {
            let relay = crate::proxy_relay::start(p.clone()).await?;
            let arg = relay.proxy_server_arg();
            eprintln!(
                "[launcher] proxy {} credentials need escaping; engine uses a loopback relay",
                p.host
            );
            proxy_relay = Some(relay);
            arg
        } else {
            p.to_proxy_server_arg()
        };
        cmd.arg(format!("--proxy-server={proxy_arg}"));

        // QUIC: enable only when proxy UDP relay verified; rely on Alt-Svc upgrade path.
        if proxy_udp_ok {
            cmd.arg("--enable-quic");
            eprintln!(
                "[launcher] QUIC enabled (Alt-Svc upgrade path): proxy {} UDP relay verified",
                p.host
            );
        } else {
            cmd.arg("--disable-quic");
            eprintln!(
                "[launcher] QUIC disabled: proxy {} has no working UDP relay",
                p.host
            );
        }
    } else if !names_a_proxy(&settings::load().map(|s| s.extra_args).unwrap_or_default()) {
        // No proxy bound means direct, not "whatever the OS is set to". Without
        // this, Chromium follows a system proxy (Clash, v2rayN, a corporate PAC)
        // while timezone and geo were resolved from the direct IP, so the
        // profile's exit IP and its claimed location disagree (CarterLeeAlt
        // a673138). An operator who routes through a proxy on purpose names it
        // in the global extra arguments, which this leaves alone.
        cmd.arg("--no-proxy-server");
    }

    // WebRTC IP policy: block / tcp_only / auto (auto = relay if UDP, else tcp_only).
    let webrtc_mode = raw.get("webrtc").and_then(|v| v.as_str()).unwrap_or("auto");
    let latest = bound_proxy.as_ref().and_then(|p| proxy::latest_test(&p.id));
    // Live geo for ICE-candidate spoofing, cached snapshot as fallback.
    let proxy_public_ip: Option<String> = if let Some(p) = bound_proxy.as_ref() {
        match proxy::geo_check(p, None).await {
            Ok(g) if !g.ip.is_empty() => Some(g.ip),
            _ => latest
                .as_ref()
                .map(|s| s.ip.clone())
                .filter(|ip| !ip.is_empty()),
        }
    } else {
        None
    };
    match webrtc_mode {
        "block" => {
            cmd.arg("--force-webrtc-ip-handling-policy=disable_non_proxied_udp");
            cmd.arg("--shardx-webrtc-policy=block");
            eprintln!("[launcher] WebRTC blocked (servers stripped, relay-only, UDP off)");
        }
        "tcp_only" => {
            cmd.arg("--force-webrtc-ip-handling-policy=disable_non_proxied_udp");
            cmd.arg("--shardx-webrtc-policy=tcp_only");
            if let Some(ip) = proxy_public_ip.as_deref() {
                cmd.arg(format!("--shardx-webrtc-public-ip={ip}"));
            }
            eprintln!("[launcher] WebRTC: TCP-only (servers stripped, mDNS host only, UDP off)");
        }
        _ => {
            if bound_proxy.is_none() {
                // No proxy bound — let WebRTC use the host network natively
                // (real IP shows in ICE candidates, which is what the user wants
                // when they explicitly didn't bind a proxy).
                eprintln!("[launcher] WebRTC auto -> native (no proxy bound)");
            } else if !proxy_udp_ok {
                cmd.arg("--force-webrtc-ip-handling-policy=disable_non_proxied_udp");
                cmd.arg("--shardx-webrtc-policy=tcp_only");
                if let Some(ip) = proxy_public_ip.as_deref() {
                    cmd.arg(format!("--shardx-webrtc-public-ip={ip}"));
                }
                eprintln!("[launcher] WebRTC auto -> TCP-only (no proxied UDP available)");
            } else {
                eprintln!("[launcher] WebRTC auto -> through proxy UDP relay");
            }
        }
    }

    // Screen resolution mode: presence-only switch to use host monitor.
    let s = settings::load()?;
    if s.screen_resolution_mode.as_deref() == Some("real") {
        cmd.arg("--shardx-real-screen");
    }

    // The bus is the process's link to the launcher, not the group's — the page
    // helper reports over it on launches that belong to no group at all.
    if bus_port != 0 {
        cmd.arg(format!("--shardx-bus=127.0.0.1:{bus_port}"));
        cmd.arg(format!("--shardx-bus-token={bus_token}"));
        cmd.arg(format!("--shardx-sync-profile={profile_id}"));
    }
    if let Some(group) = sync_group {
        cmd.arg(format!("--shardx-sync-group={group}"));
    }
    if s.helper_enabled {
        // In a group too: the fill travels as a command, not as input, so each
        // window fills with its own generated person.
        cmd.arg("--shardx-helper");
    }
    if s.camera_enabled {
        // No value — the picture is chosen in the running browser. Without the
        // switch the machine's own camera answers.
        cmd.arg("--shardx-camera");
    }

    // CDP: port=0 makes Chrome pick free port and write DevToolsActivePort.
    if enable_cdp {
        let _ = std::fs::remove_file(udd.join("DevToolsActivePort"));
        cmd.args(CDP_ARGS);
    }

    if headless {
        cmd.arg("--headless=new");
    }

    // Operator's own switches, last so they win a repeat.
    for a in settings::parse_extra_args(&s.extra_args) {
        cmd.arg(a);
    }

    cmd.stdout(Stdio::null()).stderr(Stdio::null());
    #[cfg(target_os = "windows")]
    {
        // 0x08000000 = CREATE_NO_WINDOW — suppress the brief console flash
        // when a Tauri GUI app spawns the engine binary.
        cmd.creation_flags(0x08000000);
    }
    let mut child = cmd
        .spawn()
        .context(crate::errcode::code("launch.spawnFailed"))?;
    if let Err(error) = profile::touch_launched(profile_id, None) {
        let _ = child.kill().await;
        let _ = child.wait().await;
        return Err(error).context(crate::errcode::code("launch.persistMetadata"));
    }
    let tracked = Tracker::shared().track_with_relay(
        profile_id.to_string(),
        child,
        stored.meta.temporary,
        proxy_relay,
        Some(udd.clone()),
    );
    drop(launch_claim);

    let cdp = if enable_cdp {
        match read_devtools_endpoint(&udd).await {
            Some(c) => {
                eprintln!(
                    "[launcher] CDP ready for {profile_id}: {}",
                    c.web_socket_debugger_url
                );
                if Tracker::shared().set_cdp_if_instance(
                    profile_id,
                    &tracked.launch_instance_token,
                    c.clone(),
                ) {
                    Some(c)
                } else {
                    None
                }
            }
            None => {
                eprintln!("[launcher] CDP: DevToolsActivePort not found within timeout");
                None
            }
        }
    } else {
        None
    };

    Ok(LaunchOutcome {
        pid: tracked.pid,
        launch_instance_token: tracked.launch_instance_token,
        cdp,
    })
}

fn parse_launch_options(value: Option<Value>) -> Result<LaunchOptions> {
    let Some(value) = value else {
        return Ok(LaunchOptions::default());
    };
    let obj = value
        .as_object()
        .context(crate::errcode::code("launch.optionsNotObject"))?;
    Ok(LaunchOptions {
        args: parse_launch_args(obj.get("args"))?,
        extension_dirs: parse_dirs(obj.get("extension_dirs"), "launch.extension_dirs")?,
        restore_session: match obj.get("restore_session") {
            None | Some(Value::Null) => true,
            Some(v) => v
                .as_bool()
                .context(crate::errcode::code("launch.restoreSessionNotBool"))?,
        },
    })
}

fn remove_unavailable_custom_fonts(raw: &mut serde_json::Map<String, Value>) -> bool {
    raw.remove("custom_fonts").is_some()
}

fn parse_launch_args(value: Option<&Value>) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for arg in parse_string_list(value, "launch.args", 256)? {
        let arg = sanitize_launch_arg(&arg)?;
        if seen.insert(arg.clone()) {
            out.push(arg);
        }
    }
    Ok(out)
}

fn parse_string_list(value: Option<&Value>, label: &str, max_len: usize) -> Result<Vec<String>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let arr = value
        .as_array()
        .with_context(|| crate::errcode::code_with("launch.listNotArray", &[("label", label)]))?;
    let mut out = Vec::new();
    for item in arr {
        let s = item
            .as_str()
            .with_context(|| {
                crate::errcode::code_with("launch.listNotStrings", &[("label", label)])
            })?
            .trim();
        if s.is_empty() {
            continue;
        }
        if s.len() > max_len || s.chars().any(|c| c.is_control()) {
            anyhow::bail!(crate::errcode::code_with(
                "launch.listBadString",
                &[("label", label)]
            ));
        }
        out.push(s.to_string());
    }
    Ok(out)
}

fn parse_dirs(value: Option<&Value>, label: &str) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for s in parse_string_list(value, label, 1024)? {
        if s.contains(',') {
            anyhow::bail!(crate::errcode::code_with(
                "launch.dirHasComma",
                &[("label", label)]
            ));
        }
        let path = PathBuf::from(&s);
        if !path.is_absolute() {
            anyhow::bail!(crate::errcode::code_with(
                "launch.dirNotAbsolute",
                &[("label", label)]
            ));
        }
        if !path.is_dir() {
            anyhow::bail!(crate::errcode::code_with(
                "launch.dirMissing",
                &[("label", label), ("path", &s)],
            ));
        }
        let canonical = path
            .canonicalize()
            .with_context(|| format!("canonicalize {s}"))?;
        let key = canonical.to_string_lossy().to_string();
        if seen.insert(key) {
            out.push(canonical);
        }
    }
    Ok(out)
}

fn sanitize_launch_arg(arg: &str) -> Result<String> {
    if !arg.starts_with("--") || arg == "--" {
        anyhow::bail!(crate::errcode::code_with(
            "launch.argPrefix",
            &[("arg", arg)]
        ));
    }
    if arg.len() > 512 || arg.chars().any(|c| c.is_control() || c.is_whitespace()) {
        anyhow::bail!(crate::errcode::code("launch.argBadChars"));
    }
    let name = arg[2..]
        .split(['=', ' '])
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if !SAFE_LAUNCH_SWITCHES.contains(&name.as_str()) {
        anyhow::bail!(crate::errcode::code_with(
            "launch.argNotAllowed",
            &[("name", &name)]
        ));
    }
    Ok(arg.trim().to_string())
}

const SAFE_LAUNCH_SWITCHES: &[&str] = &[
    "allow-file-access-from-files",
    "autoplay-policy",
    "disable-background-networking",
    "disable-background-timer-throttling",
    "disable-backgrounding-occluded-windows",
    "disable-breakpad",
    "disable-component-update",
    "disable-dev-shm-usage",
    "disable-gpu-watchdog",
    "disable-notifications",
    "disable-popup-blocking",
    "disable-renderer-backgrounding",
    "force-color-profile",
    "ignore-certificate-errors",
    "mute-audio",
    "start-maximized",
    "use-fake-device-for-media-stream",
    "use-fake-ui-for-media-stream",
    "window-position",
    "window-size",
];

/// Poll `<udd>/DevToolsActivePort` for ~6s; line 1 = port, line 2 = ws path.
/// Whether the operator's extra arguments choose a proxy themselves.
fn names_a_proxy(extra_args: &str) -> bool {
    settings::parse_extra_args(extra_args).iter().any(|a| {
        ["--proxy-server", "--proxy-pac-url", "--proxy-auto-detect"]
            .iter()
            .any(|p| a.starts_with(p))
    })
}

/// How long a launch waits for the browser to publish its debugging port. Six
/// seconds was not enough for a cold engine behind a slow proxy, and the start
/// then reported no CDP for a browser that came up moments later (upstream
/// 6c3f65a, "start-cdp-wait").
const CDP_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

async fn read_devtools_endpoint(udd: &Path) -> Option<process::CdpInfo> {
    let file = udd.join("DevToolsActivePort");
    let deadline = std::time::Instant::now() + CDP_WAIT;
    while std::time::Instant::now() < deadline {
        if let Ok(txt) = std::fs::read_to_string(&file) {
            let mut lines = txt.lines();
            if let (Some(port_s), Some(path)) = (lines.next(), lines.next()) {
                if let Ok(port) = port_s.trim().parse::<u16>() {
                    return Some(process::CdpInfo {
                        port,
                        http_url: format!("http://127.0.0.1:{port}"),
                        web_socket_debugger_url: format!("ws://127.0.0.1:{port}{}", path.trim()),
                    });
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    None
}

/// Resolve "auto" sentinels in profile JSON; with proxy: live → cached → country tag → host warn.
async fn resolve_auto_fields(
    cfg: &mut serde_json::Map<String, serde_json::Value>,
    proxy_opt: Option<&proxy::ProxyEntry>,
) {
    let want_tz_auto = cfg.get("timezone").and_then(|v| v.as_str()) == Some("auto");
    let want_lang_auto = cfg
        .get("navigator")
        .and_then(|n| n.get("language"))
        .and_then(|v| v.as_str())
        == Some("auto");
    let want_geo_auto = matches!(
        cfg.get("geolocation")
            .and_then(|g| g.get("mode"))
            .and_then(|v| v.as_str()),
        Some("auto")
    );

    if !(want_tz_auto || want_lang_auto || want_geo_auto) {
        return;
    }

    eprintln!(
        "[launcher] resolving auto fields (tz={} lang={} geo={} proxy={})",
        want_tz_auto,
        want_lang_auto,
        want_geo_auto,
        proxy_opt
            .map(|p| format!("{}:{}", p.host, p.port))
            .unwrap_or_else(|| "(direct)".into()),
    );

    // ---- geo source ----
    let mut source = "";
    let geo: Option<proxy::GeoInfo> = match proxy_opt {
        Some(p) => match proxy::geo_check_via(Some(p), None).await {
            Ok(g) => {
                source = "proxy-live";
                Some(g)
            }
            Err(e) => {
                eprintln!("[launcher] proxy geo failed: {e} — falling back to cached snapshot");
                if let Some(snap) = proxy::latest_test(&p.id) {
                    if !snap.country_code.is_empty() || !snap.timezone.is_empty() {
                        source = "cached-snapshot";
                        Some(proxy::GeoInfo {
                            ip: snap.ip,
                            country: snap.country,
                            country_code: snap.country_code,
                            region: snap.region,
                            city: snap.city,
                            isp: snap.isp,
                            timezone: snap.timezone,
                            latitude: snap.latitude,
                            longitude: snap.longitude,
                            provider: snap.provider,
                        })
                    } else {
                        None
                    }
                } else {
                    None
                }
                .or_else(|| {
                    if !p.country.is_empty() {
                        source = "country-tag";
                        Some(proxy::GeoInfo {
                            ip: String::new(),
                            country: String::new(),
                            country_code: p.country.clone(),
                            region: String::new(),
                            city: String::new(),
                            isp: String::new(),
                            timezone: String::new(),
                            latitude: 0.0,
                            longitude: 0.0,
                            provider: String::new(),
                        })
                    } else {
                        None
                    }
                })
            }
        },
        None => match proxy::geo_check_via(None, None).await {
            Ok(g) => {
                source = "direct-live";
                Some(g)
            }
            Err(e) => {
                eprintln!("[launcher] direct geo failed: {e} — falling back to host TZ/locale");
                None
            }
        },
    };

    let host_warn = || {
        if proxy_opt.is_some() {
            eprintln!(
                "[launcher] WARNING: proxy is bound but every geo source failed; \
                 using the LAUNCHER HOST's TZ/locale.  This will leak your real \
                 timezone — re-test the proxy or set the timezone manually."
            );
        }
    };

    // ---- concrete tz/locale/lat/lng ----
    let (resolved_tz, resolved_locale, resolved_lat, resolved_lng) = match geo {
        Some(ref g) => {
            let tz = if !g.timezone.is_empty() {
                g.timezone.clone()
            } else {
                proxy::country_to_timezone(&g.country_code).to_string()
            };
            let locale = proxy::country_to_locale(&g.country_code).to_string();
            let lat = if g.latitude != 0.0 {
                Some(g.latitude)
            } else {
                None
            };
            let lng = if g.longitude != 0.0 {
                Some(g.longitude)
            } else {
                None
            };
            (tz, locale, lat, lng)
        }
        None => {
            host_warn();
            (
                host_timezone().unwrap_or_else(|| "UTC".into()),
                host_locale().unwrap_or_else(|| "en-US".into()),
                None,
                None,
            )
        }
    };

    eprintln!("[launcher] resolved tz={resolved_tz} locale={resolved_locale} (source={source})");

    if want_tz_auto {
        cfg.insert(
            "timezone".into(),
            serde_json::Value::String(resolved_tz.clone()),
        );
    }

    if want_lang_auto {
        let base = resolved_locale
            .split('-')
            .next()
            .unwrap_or(&resolved_locale)
            .to_string();
        let accept = if resolved_locale == "en-US" {
            "en-US,en;q=0.9".to_string()
        } else {
            format!("{resolved_locale},{base};q=0.9,en-US;q=0.8,en;q=0.7")
        };
        let languages = if resolved_locale == "en-US" {
            vec![
                serde_json::Value::String("en-US".into()),
                serde_json::Value::String("en".into()),
            ]
        } else {
            vec![
                serde_json::Value::String(resolved_locale.clone()),
                serde_json::Value::String(base),
                serde_json::Value::String("en-US".into()),
                serde_json::Value::String("en".into()),
            ]
        };
        if let Some(nav) = cfg.get_mut("navigator").and_then(|v| v.as_object_mut()) {
            nav.insert(
                "language".into(),
                serde_json::Value::String(resolved_locale.clone()),
            );
            nav.insert("accept_language".into(), serde_json::Value::String(accept));
            nav.insert("languages".into(), serde_json::Value::Array(languages));
        }
        // Always overwrite icu_locale so it matches resolved navigator.language.
        cfg.insert(
            "icu_locale".into(),
            serde_json::Value::String(resolved_locale.clone()),
        );

        // The bundled presets all carry one Russian donor's SAPI voices, which
        // contradicts every other locale signal: a profile claiming en-US that
        // enumerates Irina and Pavel is a profile that stands out. Overwrite
        // them to match the locale actually resolved above.
        crate::speech::align_voices_with_locale(cfg, &resolved_locale);
    }

    if want_geo_auto {
        if let (Some(lat), Some(lng)) = (resolved_lat, resolved_lng) {
            cfg.insert(
                "geolocation".into(),
                serde_json::json!({
                    "mode": "manual",
                    "latitude": lat,
                    "longitude": lng,
                    "accuracy": 50.0,
                }),
            );
        } else {
            cfg.remove("geolocation");
        }
    }
}

/// Copy cached Widevine CDM into `<udd>/WidevineCdm/<version>/` (versioned layout
/// required by Chromium's DefaultComponentInstaller). No-op if cache absent.
fn install_widevine(udd: &Path) -> Result<()> {
    let src = store::widevine_cache_dir()?;
    if !src.exists() {
        anyhow::bail!(crate::errcode::code_with(
            "launch.cacheMissing",
            &[("path", &src.display().to_string())],
        ));
    }
    let manifest_path = src.join("manifest.json");
    if !manifest_path.exists() {
        anyhow::bail!(crate::errcode::code("launch.cacheNeedsReseed"));
    }
    let manifest_text = std::fs::read_to_string(&manifest_path)?;
    let manifest: serde_json::Value = serde_json::from_str(&manifest_text)
        .context(crate::errcode::code("launch.widevineParse"))?;
    let version = manifest
        .get("version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!(crate::errcode::code("launch.widevineNoVersion")))?;

    let widevine_root = udd.join("WidevineCdm");
    let versioned = widevine_root.join(version);
    if versioned.exists() {
        return Ok(());
    }
    // Clean up any stale flat layout from older launcher versions.
    let flat_manifest = widevine_root.join("manifest.json");
    if flat_manifest.exists() {
        for stray in ["manifest.json", "LICENSE", "_platform_specific"] {
            let p = widevine_root.join(stray);
            if p.is_dir() {
                let _ = std::fs::remove_dir_all(&p);
            } else if p.exists() {
                let _ = std::fs::remove_file(&p);
            }
        }
    }
    copy_dir_recursive(&src, &versioned)
        .with_context(|| format!("copy {} → {}", src.display(), versioned.display()))?;
    // Chromium reads this single-line marker on startup.
    std::fs::write(
        widevine_root.join("latest-component-updated-version"),
        version,
    )?;
    eprintln!("[launcher] widevine pre-warmed: {}", versioned.display());
    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else if ty.is_symlink() {
            // Resolve symlinks so dst tree stays portable across hosts.
            let target = std::fs::read_link(&from)?;
            let resolved = if target.is_absolute() {
                target
            } else {
                from.parent().unwrap().join(target)
            };
            if resolved.is_dir() {
                copy_dir_recursive(&resolved, &to)?;
            } else {
                std::fs::copy(&resolved, &to)?;
            }
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

/// Read host TZ from /etc/localtime symlink, fall back to $TZ.
fn host_timezone() -> Option<String> {
    if let Ok(target) = std::fs::read_link("/etc/localtime") {
        let path = target.to_string_lossy().into_owned();
        for prefix in ["/usr/share/zoneinfo/", "/var/db/timezone/zoneinfo/"] {
            if let Some(tz) = path.strip_prefix(prefix) {
                return Some(tz.to_string());
            }
        }
    }
    std::env::var("TZ").ok().filter(|s| !s.is_empty())
}

/// Extract BCP-47 locale from $LANG/$LC_ALL ("en_US.UTF-8" → "en-US").
fn host_locale() -> Option<String> {
    for var in ["LANG", "LC_ALL", "LC_MESSAGES"] {
        if let Ok(v) = std::env::var(var) {
            let stripped = v.split('.').next().unwrap_or("").replace('_', "-");
            if stripped.contains('-') {
                return Some(stripped);
            }
        }
    }
    None
}

#[cfg(test)]
mod direct_profile_tests {
    use super::names_a_proxy;

    #[test]
    fn only_an_operator_proxy_switch_keeps_the_system_route() {
        assert!(!names_a_proxy(""));
        assert!(!names_a_proxy("--mute-audio --lang=en"));
        assert!(names_a_proxy(
            "--mute-audio --proxy-server=http://10.0.0.1:3128"
        ));
        assert!(names_a_proxy("--proxy-pac-url=http://corp/proxy.pac"));
    }
}

#[cfg(test)]
mod window_from_screen_tests {
    use super::fill_window_from_screen;
    use serde_json::json;

    fn obj(v: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn derives_a_window_from_the_claimed_screen() {
        let mut raw = obj(json!({
            "screen": { "width": 1920, "height": 1080,
                        "avail_width": 1920, "avail_height": 1032 }
        }));
        fill_window_from_screen(&mut raw);
        let w = raw["window"].as_object().unwrap();
        assert_eq!(w["outer_width"], 1920);
        assert_eq!(w["outer_height"], 1031);
        assert_eq!(w["inner_width"], 1920);
        assert_eq!(w["inner_height"], 944);
    }

    #[test]
    fn leaves_a_profile_that_names_its_own_window() {
        let mut raw = obj(json!({
            "screen": { "width": 1920, "height": 1080,
                        "avail_width": 1920, "avail_height": 1032 },
            "window": { "outer_width": 1280, "outer_height": 800,
                        "inner_width": 1280, "inner_height": 713 }
        }));
        fill_window_from_screen(&mut raw);
        let w = raw["window"].as_object().unwrap();
        assert_eq!(w["outer_width"], 1280, "a captured window must survive");
        assert_eq!(w["inner_height"], 713);
    }

    #[test]
    fn falls_back_to_the_full_screen_when_avail_is_absent() {
        let mut raw = obj(json!({ "screen": { "width": 1366, "height": 768 } }));
        fill_window_from_screen(&mut raw);
        let w = raw["window"].as_object().unwrap();
        assert_eq!(w["outer_width"], 1366);
        assert_eq!(w["outer_height"], 767);
    }

    #[test]
    fn does_nothing_without_a_screen() {
        let mut raw = obj(json!({ "name": "no screen here" }));
        fill_window_from_screen(&mut raw);
        assert!(raw.get("window").is_none());
    }

    #[test]
    fn an_empty_window_block_is_still_filled() {
        let mut raw = obj(json!({
            "screen": { "width": 1600, "height": 900,
                        "avail_width": 1600, "avail_height": 860 },
            "window": {}
        }));
        fill_window_from_screen(&mut raw);
        assert_eq!(raw["window"]["outer_width"], 1600);
        assert_eq!(raw["window"]["outer_height"], 859);
    }
}

#[cfg(test)]
mod launch_option_tests {
    use super::{parse_launch_options, remove_unavailable_custom_fonts};
    use serde_json::json;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("shardx-launch-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn launch_options_allow_safe_args_and_extension_dirs() {
        let ext = temp_dir("extension");
        let value = json!({
            "args": ["--mute-audio", "--window-size=1200,900", "--mute-audio"],
            "extension_dirs": [ext.to_string_lossy()]
        });

        let opts = parse_launch_options(Some(value)).unwrap();

        assert_eq!(opts.args, vec!["--mute-audio", "--window-size=1200,900"]);
        assert_eq!(opts.extension_dirs.len(), 1);
    }

    #[test]
    fn launch_options_restore_session_defaults_on_and_opts_out() {
        // Absent key keeps the browser's own behaviour.
        assert!(parse_launch_options(None).unwrap().restore_session);
        assert!(
            parse_launch_options(Some(json!({})))
                .unwrap()
                .restore_session
        );
        assert!(
            parse_launch_options(Some(json!({"restore_session": null})))
                .unwrap()
                .restore_session
        );

        // Automation profiles opt out explicitly.
        assert!(
            !parse_launch_options(Some(json!({"restore_session": false})))
                .unwrap()
                .restore_session
        );

        // A non-boolean is a profile authoring mistake, not a silent default.
        assert!(parse_launch_options(Some(json!({"restore_session": "no"}))).is_err());
    }

    #[test]
    fn launch_options_reject_profile_isolation_switches() {
        let value = json!({ "args": ["--user-data-dir=C:\\tmp\\other"] });

        assert!(parse_launch_options(Some(value)).is_err());
    }

    #[test]
    fn launch_options_reject_embedded_whitespace() {
        let value = json!({ "args": ["--mute-audio --user-data-dir=C:\\tmp\\other"] });

        assert!(parse_launch_options(Some(value)).is_err());
    }

    #[test]
    fn legacy_custom_fonts_are_not_handed_to_the_engine() {
        let mut raw = json!({
            "custom_fonts": { "mode": "append", "dirs": ["C:\\fonts"] },
            "navigator": { "platform": "Win32" }
        })
        .as_object()
        .unwrap()
        .clone();

        assert!(remove_unavailable_custom_fonts(&mut raw));
        assert!(!raw.contains_key("custom_fonts"));
        assert_eq!(raw["navigator"]["platform"], "Win32");
    }
}
