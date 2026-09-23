// Does the installed engine carry the Motion domain?
//
// Upstream ships Node, Python and Rust SDKs around a browser-level CDP domain
// called `Motion` -- human pointer curves, keystroke timing, finger gestures.
// The domain is deliberately absent from Schema.getDomains and /json/protocol
// so a page cannot enumerate it, which means the only honest way to know
// whether an engine implements it is to call it and read the error.
//
// This probe exists so the answer is a test result rather than an assumption.
// Porting those SDKs against an engine without the domain would ship three
// libraries of dead code whose every call fails at runtime.
//
// Today the answer is no: the engine this fork installs does not implement it.
// The test therefore records the current state and, more usefully, tells us the
// day an engine update changes it -- at which point the SDK port moves from
// speculative to justified.

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
fn launch() -> Option<(Engine, String)> {
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
        .arg("--remote-debugging-port=0")
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

/// True when the engine answered "no such method", in whatever wording.
fn method_missing(reply: &Value) -> bool {
    let msg = reply["error"]["message"].as_str().unwrap_or("");
    msg.contains("wasn't found")
        || msg.contains("was not found")
        || msg.contains("not found")
        || msg.contains("Unknown method")
}

/// The eleven methods the upstream SDKs drive. Kept in one place so the port
/// decision is about a measured surface, not a remembered one.
const MOTION_METHODS: &[&str] = &[
    "Motion.createPointer",
    "Motion.movePointer",
    "Motion.pressPointer",
    "Motion.releasePointer",
    "Motion.scroll",
    "Motion.typeText",
    "Motion.pressKey",
    "Motion.createFinger",
    "Motion.tap",
    "Motion.swipe",
    "Motion.setOrientation",
];

#[test]
fn the_motion_domain_is_absent_from_this_engine() {
    let Some((_engine, ws)) = launch() else {
        eprintln!("no engine installed; skipping");
        return;
    };

    let mut present = Vec::new();
    for method in MOTION_METHODS {
        let reply = call(&ws, method, json!({}));
        if !method_missing(&reply) {
            present.push(*method);
        }
    }

    // Read this failure as good news, not a broken test: the engine grew the
    // domain, so the Motion SDK port is now worth doing. Port it, then invert
    // this assertion to guard the surface the SDK depends on.
    assert!(
        present.is_empty(),
        "the engine now implements Motion ({present:?}) -- the SDK port is unblocked, \
         see the handoff note on Motion"
    );
}

#[test]
fn the_motion_domain_stays_out_of_the_advertised_protocol() {
    let Some((_engine, ws)) = launch() else {
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
        "Motion is discoverable through Schema.getDomains, which makes the \
         engine identifiable by protocol enumeration"
    );
}
