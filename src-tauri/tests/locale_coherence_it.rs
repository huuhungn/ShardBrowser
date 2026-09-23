// The engine must honour what the launcher now writes.
//
// Two fixes in this branch only work if the engine reads them the way the
// launcher assumes:
//
//   #81  --lang=<locale>     -> the browser's OWN strings follow the profile
//   #80  speech.voices[]     -> getVoices() reports the corrected local voices
//
// A unit test can prove the launcher builds the right command line; only the
// engine can prove the command line means what we think. This test launches
// the engine that is actually installed, with a fingerprint file written the
// way `launch.rs` writes one, and reads the result back over CDP.
//
// Skipped, not failed, when no engine is installed -- CI runners have no
// runtime and a missing engine is not a broken fix.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tungstenite::{connect, Message};

/// A launched engine that cleans up after itself even when a test panics.
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

/// Write a fingerprint the way launch.rs does, start the engine on a free
/// debugging port, and return the websocket URL CDP listens on.
fn launch(fingerprint: Value, lang: Option<&str>) -> Option<(Engine, String)> {
    let bin = shardx_launcher_lib::runtime_binary_path_for_tests().ok()?;
    if !bin.exists() {
        return None;
    }

    let udd = std::env::temp_dir().join(format!(
        "shardx-locale-it-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&udd).ok()?;

    let fp_file = udd.join("fingerprint.json");
    std::fs::write(&fp_file, serde_json::to_string(&fingerprint).unwrap()).ok()?;

    // Port 0 makes the engine pick a free port and report it on stderr, which
    // avoids a race against anything else using a fixed port.
    let mut cmd = Command::new(&bin);
    cmd.arg(format!("--fingerprint-profile={}", fp_file.display()))
        .arg(format!("--user-data-dir={}", udd.display()))
        .arg("--remote-debugging-port=0")
        .arg("--window-position=-32000,-32000")
        .arg("--no-first-run")
        .arg("--no-default-browser-check")
        .stderr(Stdio::piped());
    if let Some(l) = lang {
        cmd.arg(format!("--lang={l}"));
    }

    let mut child = cmd.spawn().ok()?;
    let stderr = child.stderr.take()?;

    // "DevTools listening on ws://127.0.0.1:<port>/devtools/browser/<id>"
    let mut ws = None;
    let mut reader = BufReader::new(stderr);
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let line = line.trim_end().to_string();
        if let Some(rest) = line.strip_prefix("DevTools listening on ") {
            ws = Some(rest.trim().to_string());
            break;
        }
        if Instant::now() > deadline {
            break;
        }
    }

    let ws = ws?;

    // Keep draining stderr for the rest of the run. Dropping the pipe here
    // leaves the engine writing into a closed handle, which stalls the helper
    // processes -- including the one that enumerates the speech voices.
    std::thread::spawn(move || for _ in reader.lines().map_while(Result::ok) {});

    Some((Engine { child, udd }, ws))
}

/// Evaluate an expression in a fresh tab and return the JSON result.
fn eval(ws_url: &str, expression: &str) -> Value {
    let (mut sock, _) = connect(ws_url).expect("connect to the engine");

    // Target.createTarget + attach gives a page to run in; the browser-level
    // endpoint cannot evaluate page script on its own.
    let send = |sock: &mut tungstenite::WebSocket<_>, id: u64, method: &str, params: Value| {
        sock.send(Message::Text(
            json!({ "id": id, "method": method, "params": params }).to_string(),
        ))
        .unwrap();
    };
    let recv_id = |sock: &mut tungstenite::WebSocket<_>, want: u64| -> Value {
        loop {
            if let Ok(Message::Text(t)) = sock.read() {
                let v: Value = serde_json::from_str(&t).unwrap();
                if v["id"] == json!(want) {
                    return v;
                }
            }
        }
    };

    send(
        &mut sock,
        1,
        "Target.createTarget",
        // Speech synthesis is not guaranteed on about:blank; a real origin is
        // where a page would read the voice list anyway.
        json!({ "url": "https://example.com" }),
    );
    let target_id = recv_id(&mut sock, 1)["result"]["targetId"]
        .as_str()
        .unwrap()
        .to_string();

    send(
        &mut sock,
        2,
        "Target.attachToTarget",
        json!({ "targetId": target_id, "flatten": true }),
    );
    let session = recv_id(&mut sock, 2)["result"]["sessionId"]
        .as_str()
        .unwrap()
        .to_string();

    // The voice list is populated as the renderer comes up, so give the page
    // the moment it needs before asking -- an empty list from a renderer that
    // is not ready yet is not evidence about the fingerprint.
    std::thread::sleep(Duration::from_secs(3));

    sock.send(Message::Text(
        json!({
            "id": 3,
            "sessionId": session,
            "method": "Runtime.evaluate",
            "params": { "expression": expression, "returnByValue": true, "awaitPromise": true }
        })
        .to_string(),
    ))
    .unwrap();

    recv_id(&mut sock, 3)["result"]["result"]["value"].clone()
}

/// A profile the way the launcher hands one to the engine, after the fixes.
fn english_profile() -> Value {
    json!({
        "navigator": {
            "language": "en-US",
            "languages": ["en-US", "en"],
            "accept_language": "en-US,en;q=0.9"
        },
        "icu_locale": "en-US",
        "speech": {
            "voices": [
                { "name": "Microsoft David - English (United States)", "lang": "en-US",
                  "local_service": true, "is_default": true },
                { "name": "Microsoft Zira - English (United States)", "lang": "en-US",
                  "local_service": true, "is_default": false },
                { "name": "Google US English", "lang": "en-US",
                  "local_service": false, "is_default": false }
            ]
        }
    })
}

#[test]
fn the_engine_reports_the_voices_the_launcher_wrote() {
    let Some((_engine, ws)) = launch(english_profile(), Some("en-US")) else {
        eprintln!("no engine installed; skipping");
        return;
    };

    // The platform voice service starts with the browser, so the very first
    // page of a cold profile can see an empty list through no fault of the
    // fingerprint. Ask again rather than read that as evidence.
    let mut list: Vec<String> = Vec::new();
    for _ in 0..5 {
        let voices = eval(
            &ws,
            r#"new Promise(resolve => {
                 const read = () => speechSynthesis.getVoices()
                   .filter(v => v.localService)
                   .map(v => v.name + '|' + v.lang);
                 const first = read();
                 if (first.length) return resolve(first);
                 speechSynthesis.onvoiceschanged = () => resolve(read());
                 setTimeout(() => resolve(read()), 5000);
               })"#,
        );
        list = voices
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        if !list.is_empty() {
            break;
        }
    }

    assert!(
        !list.is_empty(),
        "the engine reported no local voices at all"
    );
    assert!(
        list.iter().all(|v| v.ends_with("|en-US")),
        "an en-US profile must not report voices from another locale: {list:?}"
    );
    assert!(
        !list
            .iter()
            .any(|v| v.contains("Irina") || v.contains("Pavel")),
        "the Russian donor's voices leaked into an English profile: {list:?}"
    );
}

#[test]
fn the_browsers_own_strings_follow_the_profile_not_the_host() {
    let Some((_engine, ws)) = launch(english_profile(), Some("en-US")) else {
        eprintln!("no engine installed; skipping");
        return;
    };

    // validationMessage is rendered by the browser itself, in the UI locale.
    // On this Russian-locale host it reads "Заполните это поле." without
    // --lang, and English with it.
    let message = eval(
        &ws,
        r#"(() => {
             const i = document.createElement('input');
             i.required = true;
             document.body.appendChild(i);
             i.checkValidity();
             return i.validationMessage;
           })()"#,
    );

    let msg = message.as_str().unwrap_or_default().to_string();
    assert!(!msg.is_empty(), "no validation message was produced");
    assert!(
        msg.is_ascii(),
        "the browser's own strings did not follow the profile locale: {msg:?}"
    );
}
