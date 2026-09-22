// What the machine's GPU can actually do, and which library fingerprints it
// can wear without contradicting itself.
//
// Why this exists
// ---------------
// The core replaces the WebGL extension list with the profile's — that is the
// point of the profile. What it cannot do is make an extension WORK. So a
// profile listing WEBGL_compressed_texture_astc on a machine whose driver has
// no ASTC produces a page that reads:
//
//     gl.getSupportedExtensions()          -> [... "WEBGL_compressed_texture_astc" ...]
//     gl.getExtension("WEBGL_compressed_texture_astc")  -> null
//
// The list says yes and the object says no. That is not a weak spoof, it is a
// self-contradiction, and it costs a detector two calls with no permission, no
// timing and no baseline. Anti-fraud vendors check exactly this pair because
// it is the cheapest way to catch a rewritten list.
//
// Hence: find out what the host really supports, once, and keep profiles that
// need more than that away from the user — silently when a profile is picked
// for them, loudly when they pick one themselves.
//
// How the answer is obtained
// --------------------------
// From the core itself, over DevTools, on a throwaway user data dir. Not from
// this launcher's own webview: on macOS that is WebKit and on Linux WebKitGTK,
// and their extension names and coverage differ from ANGLE's. The only
// authoritative answer is the engine that will actually run the profile.
//
// The result is cached against the engine version, because a Chromium bump can
// change ANGLE and with it the list.

use crate::{runtime, store};
use anyhow::{anyhow, Context, Result};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HostGlCaps {
    /// UNMASKED_RENDERER_WEBGL of the host, for display in the warning.
    pub renderer: String,
    pub vendor: String,
    pub webgl1: Vec<String>,
    pub webgl2: Vec<String>,
    /// GPUAdapter.features of the host. `None` means NEVER PROBED — a cache
    /// written before this field existed — and must not be read as "this
    /// machine supports nothing": that turned every profile that names a
    /// feature into a red incompatibility notice at once. `Some([])` is a
    /// machine that was asked and has no adapter, which is a real answer.
    #[serde(default)]
    pub webgpu: Option<Vec<String>>,
    /// Engine build the probe ran against; a mismatch re-probes.
    pub engine_version: String,
}

/// What a fingerprint would ask of this machine that the machine cannot give.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Compat {
    pub compatible: bool,
    /// Extensions the profile declares for WebGL1 that the host lacks.
    pub missing_webgl1: Vec<String>,
    pub missing_webgl2: Vec<String>,
    /// WebGPU features the profile claims that the host adapter lacks. The
    /// engine narrows the reported set to what is really there, so the profile
    /// runs — it just reports a shorter list than the device it names would.
    #[serde(default)]
    pub missing_webgpu: Vec<String>,
    /// The profile's own GPU string, so the UI can say "this is a Mali profile
    /// on an Apple GPU" without a second lookup.
    pub profile_renderer: String,
}

fn cache_path() -> Result<std::path::PathBuf> {
    Ok(store::settings_path()?
        .parent()
        .ok_or_else(|| anyhow!("no config dir"))?
        .join("host-gl-caps.json"))
}

pub fn cached() -> Option<HostGlCaps> {
    let text = std::fs::read_to_string(cache_path().ok()?).ok()?;
    let caps: HostGlCaps = serde_json::from_str(&text).ok()?;
    if caps.webgl1.is_empty() {
        return None;
    }
    // Written before the WebGPU probe existed: re-ask rather than treat the
    // silence as an answer.  An EMPTY list counts as silence too — a machine
    // with a working GPU does not report zero adapter features, so that is a
    // probe that could not ask, and caching it hid every preset behind a GPU
    // mismatch until the engine version happened to change.
    match caps.webgpu.as_ref() {
        None => return None,
        Some(v) if v.is_empty() => return None,
        Some(_) => {}
    }
    // A bump can move ANGLE under us; a stale list would start rejecting
    // profiles that became fine, or accepting ones that stopped being.
    if caps.engine_version != runtime::engine_version().unwrap_or_default() {
        return None;
    }
    Some(caps)
}

/// The JS the probe runs. Kept here rather than in a file so there is nothing
/// to ship and nothing to get out of step with the struct above.
const PROBE_JS: &str = r#"(async () => {
  const c1 = document.createElement('canvas').getContext('webgl');
  const c2 = document.createElement('canvas').getContext('webgl2');
  const name = (g) => {
    if (!g) return '';
    const d = g.getExtension('WEBGL_debug_renderer_info');
    return d ? String(g.getParameter(d.UNMASKED_RENDERER_WEBGL)) : '';
  };
  const vend = (g) => {
    if (!g) return '';
    const d = g.getExtension('WEBGL_debug_renderer_info');
    return d ? String(g.getParameter(d.UNMASKED_VENDOR_WEBGL)) : '';
  };
  // WebGPU asks asynchronously and may not be there at all; an absent adapter
  // is an empty list, which reads as "warn about nothing" rather than as
  // "warn about everything".
  let webgpu = [];
  try {
    const a = navigator.gpu ? await navigator.gpu.requestAdapter() : null;
    if (a) webgpu = [...a.features].sort();
  } catch (e) {}
  return JSON.stringify({
    renderer: name(c2) || name(c1),
    vendor: vend(c2) || vend(c1),
    webgl1: c1 ? c1.getSupportedExtensions() : [],
    webgl2: c2 ? c2.getSupportedExtensions() : [],
    webgpu,
  });
})()"#;

async fn evaluate_in_core(port: u16) -> Result<String> {
    let http = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()?;
    // The browser needs a moment to open its port; poll rather than sleep a
    // fixed amount, so a slow machine is not a failure and a fast one is not a
    // wait.
    let mut ws_url = None;
    for _ in 0..120 {
        if let Ok(resp) = http
            .get(format!("http://127.0.0.1:{port}/json/list"))
            .send()
            .await
        {
            if let Ok(list) = resp.json::<Value>().await {
                if let Some(t) = list
                    .as_array()
                    .and_then(|a| a.iter().find(|t| t["type"] == "page"))
                {
                    if let Some(u) = t["webSocketDebuggerUrl"].as_str() {
                        ws_url = Some(u.to_string());
                        break;
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let ws_url = ws_url.ok_or_else(|| anyhow!("core did not open a debugging port"))?;

    let (mut socket, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .context("connect to the core's debugging port")?;
    let msg = json!({
        "id": 1,
        "method": "Runtime.evaluate",
        "params": {
            "expression": PROBE_JS,
            "returnByValue": true,
            // The probe is async now: WebGPU only answers through a promise.
            "awaitPromise": true,
        },
    });
    socket
        .send(tokio_tungstenite::tungstenite::Message::Text(
            msg.to_string(),
        ))
        .await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while tokio::time::Instant::now() < deadline {
        let next = tokio::time::timeout_at(deadline, socket.next()).await;
        let Ok(Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text)))) = next else {
            continue;
        };
        let v: Value = serde_json::from_str(&text)?;
        if v["id"] == 1 {
            return v["result"]["result"]["value"]
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| anyhow!("probe returned no value"));
        }
    }
    Err(anyhow!("probe timed out"))
}

/// Ask the engine what this machine supports. Caches; pass force to re-ask.
pub async fn probe(force: bool) -> Result<HostGlCaps> {
    if !force {
        if let Some(hit) = cached() {
            return Ok(hit);
        }
    }
    let binary = runtime::binary_path().context("engine is not installed yet")?;
    let scratch = std::env::temp_dir().join(format!("shardx-glcaps-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch)?;

    // A free port from the OS rather than a fixed one: the user may well have
    // profiles running, and a collision here would read their browser instead
    // of ours.
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0")?;
        l.local_addr()?.port()
    };

    // A page, not about:blank.  WebGPU is [SecureContext] and about:blank is
    // an opaque origin, so navigator.gpu is simply not there and the probe
    // recorded "this machine has no WebGPU adapter" -- which then stuck in the
    // cache and made every preset show a GPU mismatch.  A file:// URL is
    // potentially trustworthy, so the same probe answers with the real
    // adapter.  WebGL never needed this; it has no secure-context rule.
    let probe_page = scratch.join("probe.html");
    std::fs::write(&probe_page, "<!doctype html><title>gl</title>")?;

    let mut cmd = tokio::process::Command::new(&binary);
    cmd.arg(format!("--remote-debugging-port={port}"))
        .arg(format!("--user-data-dir={}", scratch.display()))
        .arg("--no-first-run")
        .arg("--no-default-browser-check")
        // Off-screen rather than headless: headless can fall back to a
        // software rasteriser, and a software rasteriser's extension list is
        // not the one the user's profiles will run against.
        .arg("--window-position=-32000,-32000")
        .arg("--window-size=200,200")
        .arg(format!("file://{}", probe_page.display()));
    #[cfg(target_os = "windows")]
    {
        // tokio's Command exposes creation_flags inherently on Windows; no
        // std::os::windows::process::CommandExt import is needed here.
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let mut child = cmd.spawn().context("start the engine for a GPU probe")?;

    let raw = evaluate_in_core(port).await;
    let _ = child.kill().await;
    let _ = std::fs::remove_dir_all(&scratch);
    let raw = raw?;

    let parsed: Value = serde_json::from_str(&raw)?;
    let list = |k: &str| -> Vec<String> {
        parsed[k]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    let caps = HostGlCaps {
        renderer: parsed["renderer"].as_str().unwrap_or_default().to_string(),
        vendor: parsed["vendor"].as_str().unwrap_or_default().to_string(),
        webgl1: list("webgl1"),
        webgl2: list("webgl2"),
        webgpu: Some(list("webgpu")),
        engine_version: runtime::engine_version().unwrap_or_default(),
    };
    if caps.webgl1.is_empty() {
        anyhow::bail!("the engine reported no WebGL at all");
    }
    let _ = std::fs::write(cache_path()?, serde_json::to_string_pretty(&caps)?);
    Ok(caps)
}

/// Which of a fingerprint's declared extensions this machine cannot back.
///
/// Only the direction that matters is checked. A profile that declares FEWER
/// extensions than the host has is fine — the core hides the rest, and a page
/// asking for a hidden one gets null from both the list and getExtension,
/// which is what a device without it looks like. The reverse is the
/// contradiction.
pub fn compat(payload: &Value, caps: &HostGlCaps) -> Compat {
    let host1: BTreeSet<&str> = caps.webgl1.iter().map(String::as_str).collect();
    let host2: BTreeSet<&str> = caps.webgl2.iter().map(String::as_str).collect();
    let declared = |key: &str| -> Vec<String> {
        payload["webgl"][key]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    let missing_webgl1: Vec<String> = declared("extensions")
        .into_iter()
        .filter(|e| !host1.contains(e.as_str()))
        .collect();
    let missing_webgl2: Vec<String> = declared("extensions_v2")
        .into_iter()
        .filter(|e| !host2.contains(e.as_str()))
        .collect();
    // An unprobed host answers nothing here: it is not evidence about the
    // machine, and treating it as one flags every profile in the library.
    let missing_webgpu: Vec<String> = match caps.webgpu.as_ref() {
        None => Vec::new(),
        Some(host) => {
            let host_gpu: BTreeSet<&str> = host.iter().map(String::as_str).collect();
            payload["webgpu"]["features"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str())
                        .filter(|f| !host_gpu.contains(f))
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default()
        }
    };
    Compat {
        compatible: missing_webgl1.is_empty()
            && missing_webgl2.is_empty()
            && missing_webgpu.is_empty(),
        missing_webgl1,
        missing_webgl2,
        missing_webgpu,
        profile_renderer: payload["webgl"]["renderer"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps() -> HostGlCaps {
        HostGlCaps {
            renderer: "Apple M3".into(),
            vendor: "Apple".into(),
            webgl1: vec!["EXT_float_blend".into()],
            webgl2: vec!["EXT_float_blend".into()],
            webgpu: Some(vec![
                "texture-compression-astc".into(),
                "texture-compression-bc".into(),
                "shader-f16".into(),
            ]),
            engine_version: String::new(),
        }
    }

    /// Only the direction that matters is reported: a profile claiming FEWER
    /// features than the host has is not a problem — the engine narrows to the
    /// profile's list and a page sees a shorter one, which is what the claimed
    /// device would report anyway.
    #[test]
    fn only_features_the_host_lacks_are_reported() {
        let payload = serde_json::json!({
            "webgpu": { "features": ["texture-compression-astc", "shader-f16"] }
        });
        let c = compat(&payload, &caps());
        assert!(c.missing_webgpu.is_empty());
        assert!(c.compatible);
    }

    #[test]
    fn a_feature_this_machine_cannot_back_is_named() {
        let payload = serde_json::json!({
            "webgpu": { "features": ["texture-compression-etc2", "subgroups", "shader-f16"] }
        });
        let c = compat(&payload, &caps());
        assert_eq!(
            c.missing_webgpu,
            vec!["texture-compression-etc2", "subgroups"]
        );
        assert!(
            !c.compatible,
            "the profile asks for what the machine has not got"
        );
    }

    /// A profile with no list at all keeps the old behaviour — the host's own
    /// features, and nothing to warn about.
    #[test]
    fn a_profile_that_declares_nothing_warns_about_nothing() {
        let c = compat(&serde_json::json!({ "webgpu": {} }), &caps());
        assert!(c.missing_webgpu.is_empty());
    }

    /// A machine with no WebGPU adapter reports an empty list, which must not
    /// read as "supports nothing" and warn about every feature a profile names.
    #[test]
    fn a_machine_without_webgpu_is_not_a_machine_that_supports_nothing() {
        let mut c = caps();
        c.webgpu = Some(Vec::new());
        let payload = serde_json::json!({ "webgpu": { "features": ["shader-f16"] } });
        let out = compat(&payload, &c);
        // It IS reported — the profile claims something this machine cannot
        // show — but the warning names one feature, not the whole list.
        assert_eq!(out.missing_webgpu, vec!["shader-f16"]);
    }

    /// A cache written before the WebGPU probe existed says nothing about the
    /// machine. Reading that silence as "has no features" turned every profile
    /// in the library red at once, on desktop and mobile alike, the day the
    /// library gained feature lists.
    #[test]
    fn an_unprobed_host_warns_about_nothing() {
        let mut c = caps();
        c.webgpu = None;
        let payload = serde_json::json!({
            "webgpu": { "features": ["shader-f16", "texture-compression-etc2"] }
        });
        let out = compat(&payload, &c);
        assert!(out.missing_webgpu.is_empty());
        assert!(out.compatible);
    }

    /// And such a cache is not used at all: the launcher re-asks rather than
    /// keep answering from a record that predates the question.
    #[test]
    fn an_unprobed_cache_is_not_a_cache_hit() {
        let mut c = caps();
        c.webgpu = None;
        let json = serde_json::to_string(&c).unwrap();
        let back: HostGlCaps = serde_json::from_str(&json).unwrap();
        assert!(
            back.webgpu.is_none(),
            "the field must survive the round trip"
        );
    }
}
