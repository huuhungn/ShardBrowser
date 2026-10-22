// Does the installed engine carry the Motion domain, and does the launcher
// unlock it?
//
// `Motion` is a browser-level CDP domain -- human pointer curves, keystroke
// timing, finger gestures -- that the MCP server's human_click/human_type tools
// and the upstream SDKs drive. It is deliberately absent from Schema.getDomains
// and /json/protocol, so the only honest test is to call it and read the error.
//
// An earlier version of this probe launched the engine without
// `--shardx-automation` and concluded the domain did not exist. The engine gates
// the domain behind that switch: without it every method answers "wasn't found".
// The probe now launches with exactly the switches the launcher passes for a
// CDP launch, so dropping the switch from the launcher fails it.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tungstenite::{connect, Message};

struct Engine {
    child: Child,
    udd: std::path::PathBuf,
}

impl Drop for Engine {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.udd);
    }
}

/// Start the installed engine with a throwaway profile and return the
/// browser-level websocket URL. `None` when no engine is installed.
fn launch(cdp_args: &[&str]) -> Option<(Engine, String)> {
    let bin = shardx_launcher_lib::runtime_binary_path_for_tests().ok()?;
    if !bin.exists() {
        return None;
    }

    let udd = std::env::temp_dir().join(format!(
        "shardx-motion-probe-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&udd).ok()?;

    let mut child = Command::new(&bin)
        .arg(format!("--user-data-dir={}", udd.display()))
        .args(cdp_args)
        .arg("--no-first-run")
        .arg("--no-default-browser-check")
        .arg("--window-position=-32000,-32000")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;

    let stderr = child.stderr.take()?;
    let mut ws = None;
    let deadline = Instant::now() + Duration::from_secs(60);
    let reader = BufReader::new(stderr);
    for line in reader.lines().map_while(Result::ok) {
        if let Some(rest) = line.strip_prefix("DevTools listening on ") {
            ws = Some(rest.trim().to_string());
            break;
        }
        if Instant::now() > deadline {
            break;
        }
    }

    Some((Engine { child, udd }, ws?))
}

/// Call one CDP method on the browser target and hand back the raw reply,
/// error and all -- the error text is the evidence here.
fn call(ws_url: &str, method: &str, params: Value) -> Value {
    let (mut sock, _) = connect(ws_url).expect("connect to the engine");
    sock.send(Message::Text(
        json!({ "id": 1, "method": method, "params": params }).to_string(),
    ))
    .expect("send");

    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if let Ok(Message::Text(txt)) = sock.read() {
            let v: Value = serde_json::from_str(&txt).unwrap_or(Value::Null);
            if v.get("id") == Some(&json!(1)) {
                return v;
            }
        }
    }
    Value::Null
}

/// True when the engine answered "no such method" for this exact method. Other
/// errors ("Invalid parameters", "createPointer first") prove the method exists.
fn method_missing(reply: &Value, method: &str) -> bool {
    let msg = reply["error"]["message"].as_str().unwrap_or("");
    msg.contains(&format!("'{method}' wasn't found"))
}

/// The methods the MCP server and the upstream SDKs call, taken from
/// upstream's `sdks/node/src/motion.ts` rather than guessed.
const MOTION_METHODS: &[&str] = &[
    "Motion.createPointer",
    "Motion.destroyPointer",
    "Motion.glideTo",
    "Motion.tap",
    "Motion.dragTo",
    "Motion.wheel",
    "Motion.enterText",
    "Motion.pressKey",
    "Motion.touchTap",
    "Motion.touchSwipe",
    "Motion.touchDrag",
    "Motion.touchLongPress",
    "Motion.pinch",
    "Motion.setOrientation",
];

fn missing_methods(ws: &str) -> Vec<&'static str> {
    MOTION_METHODS
        .iter()
        .copied()
        .filter(|m| method_missing(&call(ws, m, json!({})), m))
        .collect()
}

#[test]
fn a_cdp_launch_unlocks_the_motion_domain() {
    let Some((_engine, ws)) = launch(shardx_launcher_lib::cdp_launch_args_for_tests()) else {
        eprintln!("no engine installed; skipping");
        return;
    };

    let missing = missing_methods(&ws);
    assert!(
        missing.is_empty(),
        "a profile started with CDP cannot reach {missing:?}; human_click and          human_type fail on it"
    );
}

#[test]
fn the_automation_switch_is_what_unlocks_it() {
    // Same launch minus the switch: if the domain were always on, the switch
    // and the test above would prove nothing.
    let Some((_engine, ws)) = launch(&["--remote-debugging-port=0"]) else {
        eprintln!("no engine installed; skipping");
        return;
    };

    assert_eq!(missing_methods(&ws).len(), MOTION_METHODS.len());
}

#[test]
fn the_motion_domain_stays_out_of_the_advertised_protocol() {
    let Some((_engine, ws)) = launch(shardx_launcher_lib::cdp_launch_args_for_tests()) else {
        eprintln!("no engine installed; skipping");
        return;
    };

    // Whether or not the domain is implemented, it must never be enumerable:
    // a page that can list it can fingerprint the browser by its presence.
    let reply = call(&ws, "Schema.getDomains", json!({}));
    let advertised = reply["result"]["domains"]
        .as_array()
        .map(|d| {
            d.iter()
                .any(|entry| entry["name"].as_str() == Some("Motion"))
        })
        .unwrap_or(false);

    assert!(
        !advertised,
        "Motion is discoverable through Schema.getDomains, which makes the          engine identifiable by protocol enumeration"
    );
}
