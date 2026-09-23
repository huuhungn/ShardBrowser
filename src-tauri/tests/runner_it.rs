//! The runner, against the engine actually installed on this machine.
//!
//! The unit tests cover variable expansion, branch arithmetic and selector
//! escaping with hand-written projects. They would all pass unchanged if the
//! CDP transport never connected, if `Runtime.evaluate` returned a shape the
//! code misreads, or if a "click" never reached the page. Only a real launch
//! against a real page proves the runner does what a report claims.
//!
//! Skipped, not failed, when no engine is installed — a fresh checkout has no
//! runtime yet, and a suite that cannot pass before first install is a suite
//! people learn to ignore.

use serde_json::{json, Value};
use shardx_launcher_lib::automation::{Block, Branch, Project, RunSettings};
use shardx_launcher_lib::{cdp, runner};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A page with everything the minimal block set needs to touch: a heading to
/// read, an input to type into, and a button whose click changes the text.
const PAGE: &str = r#"<!doctype html><meta charset="utf-8"><title>Runner fixture</title>
<h1 id="title">ready</h1>
<!-- Text a hostile page would serve: it closes the operator's string literal
     and appends a statement of its own. -->
<div id="hostile">'; window.__pwned = 'yes'; '</div>
<input id="name">
<button id="go" onclick="document.getElementById('title').textContent = 'hello ' + document.getElementById('name').value">go</button>
<div id="late"></div>
<script>setTimeout(() => { document.getElementById('late').textContent = 'arrived'; }, 400);</script>
"#;

struct Engine {
    child: Child,
    ws_url: String,
    _dir: tempfile::TempDir,
}

impl Drop for Engine {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn engine_binary() -> Option<PathBuf> {
    let binary = shardx_launcher_lib::runtime_binary_path_for_tests().ok()?;
    binary.exists().then_some(binary)
}

/// Start the engine on a throwaway profile with CDP open, and read the
/// websocket URL from its own DevToolsActivePort — the same way the launcher
/// does, so the test exercises the path production uses.
fn start_engine(page_url: &str) -> Option<Engine> {
    let binary = engine_binary()?;
    let dir = tempfile::tempdir().expect("a scratch profile dir");
    let udd = dir.path().join("udd");
    std::fs::create_dir_all(&udd).expect("create the profile dir");

    let child = Command::new(&binary)
        .arg(format!("--user-data-dir={}", udd.display()))
        .arg("--remote-debugging-port=0")
        .arg("--no-first-run")
        .arg("--no-default-browser-check")
        // Off-screen rather than headless: headless changes which web APIs
        // behave, and the point is to test the engine operators actually run.
        .arg("--window-position=-32000,-32000")
        .arg(page_url)
        // Keep the pipes open: a child whose stderr fills an unread buffer
        // blocks, and the test then times out for the wrong reason.
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("launch the engine");

    let port_file = udd.join("DevToolsActivePort");
    let deadline = Instant::now() + Duration::from_secs(30);
    let ws_url = loop {
        if Instant::now() >= deadline {
            panic!("the engine never wrote DevToolsActivePort");
        }
        if let Ok(text) = std::fs::read_to_string(&port_file) {
            let mut lines = text.lines();
            if let (Some(port), Some(path)) = (lines.next(), lines.next()) {
                if !port.trim().is_empty() {
                    break format!("ws://127.0.0.1:{}{}", port.trim(), path.trim());
                }
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    };

    Some(Engine {
        child,
        ws_url,
        _dir: dir,
    })
}

fn fixture_url() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().expect("a scratch dir for the fixture page");
    let file = dir.path().join("fixture.html");
    std::fs::write(&file, PAGE).expect("write the fixture page");
    let url = format!("file:///{}", file.display().to_string().replace('\\', "/"));
    (dir, url)
}

fn block(id: &str, kind: &str, params: Value) -> Block {
    Block {
        id: id.into(),
        kind: kind.into(),
        label: String::new(),
        params,
        enabled: true,
        x: 0.0,
        y: 0.0,
        on_done: Branch::Next,
        secrets: Vec::new(),
        on_fail: Branch::Stop,
    }
}

/// A block that carries on when it fails.
///
/// The refusal tests need the run to continue past the refused step so a
/// later block can confirm nothing happened; the default `Branch::Stop` would
/// end the run and leave that unproven.
fn block_continuing(id: &str, kind: &str, params: Value) -> Block {
    Block {
        on_fail: Branch::Next,
        ..block(id, kind, params)
    }
}

fn project(blocks: Vec<Block>) -> Project {
    Project {
        id: "it".into(),
        name: "Integration".into(),
        notes: String::new(),
        blocks,
        run: RunSettings::default(),
        created_at: 0,
        updated_at: 0,
    }
}

/// The whole minimal block set, against a real page: navigate, wait for an
/// element that only appears later, type, click, read the result back into a
/// variable, and assert on what the page really says.
#[tokio::test]
async fn the_minimal_blocks_really_drive_a_real_page() {
    let (_fixture_dir, url) = fixture_url();
    let Some(engine) = start_engine(&url) else {
        eprintln!("skipped: engine runtime is not installed");
        return;
    };

    let profile_id = "it-runner";
    cdp::attach(profile_id.to_string(), engine.ws_url.clone())
        .await
        .expect("attach to the running engine");

    let p = project(vec![
        block("nav", "navigate", json!({ "url": url })),
        // Only appears 400ms after load: a wait that does not really wait
        // fails here.
        block("late", "waitForSelector", json!({ "selector": "#late" })),
        block(
            "name",
            "setVariable",
            json!({ "name": "who", "value": "ann" }),
        ),
        block(
            "type",
            "type",
            json!({ "selector": "#name", "text": "{{who}}" }),
        ),
        block("click", "click", json!({ "selector": "#go" })),
        block(
            "read",
            "readText",
            json!({ "selector": "#title", "into": "greeting" }),
        ),
        block(
            "check",
            "assert",
            json!({ "selector": "#title", "expected": "hello ann" }),
        ),
    ]);

    let report = runner::run(&p, profile_id, HashMap::new())
        .await
        .expect("the run should start");

    cdp::detach(profile_id);

    for step in &report.steps {
        assert_eq!(
            step.outcome,
            runner::StepOutcome::Ok,
            "step {} ({}) failed: {:?}",
            step.block_id,
            step.kind,
            step.error
        );
    }
    assert!(report.ok, "the run should succeed: {report:?}");
    assert_eq!(report.passes, 1);

    // The variable proves the click really reached the page and the read
    // really came back from it, rather than the run simply not erroring.
    assert_eq!(
        report.variables.get("greeting").map(String::as_str),
        Some("hello ann"),
        "the page should show what the run typed and clicked: {:?}",
        report.variables
    );
}

/// A step that cannot succeed is reported as failed, and a failing step that
/// says Stop really ends the run rather than carrying on.
#[tokio::test]
async fn a_step_that_cannot_succeed_fails_and_stops_the_run() {
    let (_fixture_dir, url) = fixture_url();
    let Some(engine) = start_engine(&url) else {
        eprintln!("skipped: engine runtime is not installed");
        return;
    };

    let profile_id = "it-runner-fail";
    cdp::attach(profile_id.to_string(), engine.ws_url.clone())
        .await
        .expect("attach to the running engine");

    let mut p = project(vec![
        block("nav", "navigate", json!({ "url": url })),
        block("missing", "click", json!({ "selector": "#nothing-here" })),
        block(
            "after",
            "setVariable",
            json!({ "name": "ran", "value": "yes" }),
        ),
    ]);
    // Keep the wait short: the point is the verdict, not the timeout.
    p.blocks[1].on_fail = Branch::Stop;

    let report = runner::run(&p, profile_id, HashMap::new())
        .await
        .expect("the run should start");

    cdp::detach(profile_id);

    assert!(
        !report.ok,
        "a run with a failed step must not report success"
    );
    let failed = report
        .steps
        .iter()
        .find(|s| s.block_id == "missing")
        .expect("the failing step should appear in the report");
    assert_eq!(failed.outcome, runner::StepOutcome::Failed);
    assert!(
        failed
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("#nothing-here"),
        "the error should name the selector: {:?}",
        failed.error
    );
    assert!(
        !report.variables.contains_key("ran"),
        "a stopped run must not keep executing later steps"
    );
}

/// An assertion that does not hold fails, and says what it saw instead — the
/// whole reason an operator opens the report.
#[tokio::test]
async fn a_false_assertion_quotes_what_the_page_actually_said() {
    let (_fixture_dir, url) = fixture_url();
    let Some(engine) = start_engine(&url) else {
        eprintln!("skipped: engine runtime is not installed");
        return;
    };

    let profile_id = "it-runner-assert";
    cdp::attach(profile_id.to_string(), engine.ws_url.clone())
        .await
        .expect("attach to the running engine");

    let p = project(vec![
        block("nav", "navigate", json!({ "url": url })),
        block(
            "check",
            "assert",
            json!({ "selector": "#title", "expected": "goodbye" }),
        ),
    ]);

    let report = runner::run(&p, profile_id, HashMap::new())
        .await
        .expect("the run should start");

    cdp::detach(profile_id);

    let failed = report
        .steps
        .iter()
        .find(|s| s.block_id == "check")
        .expect("the assertion should appear in the report");
    assert_eq!(failed.outcome, runner::StepOutcome::Failed);
    let error = failed.error.clone().unwrap_or_default();
    assert!(
        error.contains("goodbye") && error.contains("ready"),
        "the error should quote both sides, got: {error}"
    );
}

/// A throwaway HTTP server, so traffic tests exercise the real network stack
/// rather than `file://` reads that never touch it.
///
/// It answers exactly three paths: one that works, one that 500s, and the page
/// that fetches both.
struct Server {
    port: u16,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        // Unblock the accept loop so the thread can notice and exit.
        let _ = std::net::TcpStream::connect(("127.0.0.1", self.port));
    }
}

fn start_server() -> Server {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a test server");
    let port = listener.local_addr().unwrap().port();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = stop.clone();

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            if flag.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 2048];
            let read = stream.read(&mut buf).unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..read]).to_string();
            let path = request
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("/")
                .to_string();

            let (status, body) = match path.as_str() {
                "/api/ok" => ("200 OK", "{\"ok\":true}".to_string()),
                "/api/broken" => ("500 Internal Server Error", "{\"ok\":false}".to_string()),
                _ => (
                    "200 OK",
                    format!(
                        "<!doctype html><meta charset=\"utf-8\"><title>traffic</title>\
                         <h1 id=\"title\">ready</h1>\
                         <script>\
                           fetch('/api/ok').then(() => {{ document.title = 'fetched'; }});\
                         </script>"
                    ),
                ),
            };

            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });

    Server { port, stop }
}

/// Recording proves the requests a page really made, including the ones that
/// no rendered text would reveal.
///
/// This is the test the unit tests cannot stand in for: they fold hand-written
/// events into the log, and would pass unchanged if `Network.enable` were
/// never sent, if the events arrived on a session the recorder does not read,
/// or if CDP named its fields differently than assumed.
#[tokio::test]
async fn a_recorded_run_reports_the_requests_the_page_actually_made() {
    let server = start_server();
    let page = format!("http://127.0.0.1:{}/", server.port);

    let Some(engine) = start_engine("about:blank") else {
        eprintln!("skipped: engine runtime is not installed");
        return;
    };

    let profile_id = "it-traffic-ok";
    cdp::attach(profile_id.to_string(), engine.ws_url.clone())
        .await
        .expect("attach to the running engine");

    let p = project(vec![
        block("rec", "recordTraffic", json!({})),
        block("nav", "navigate", json!({ "url": page })),
        // The fetch is fired from a promise callback, so the document being
        // loaded does not mean it has happened yet.
        block("settle", "wait", json!({ "ms": 1500 })),
        block(
            "seen",
            "assertRequest",
            json!({ "urlContains": "/api/ok", "into": "hits" }),
        ),
        block("stop", "stopTraffic", json!({ "into": "requests" })),
    ]);

    let report = runner::run(&p, profile_id, HashMap::new())
        .await
        .expect("the run should start");

    cdp::detach(profile_id);

    assert!(
        report.ok,
        "the run should pass; steps: {:?}",
        report
            .steps
            .iter()
            .map(|s| (&s.kind, &s.outcome, &s.error))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        report.variables.get("hits").map(String::as_str),
        Some("1"),
        "the XHR the page fired should have been recorded exactly once"
    );
    let recorded: usize = report
        .variables
        .get("requests")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    assert!(
        recorded >= 2,
        "the document and its fetch should both be recorded, got {recorded}"
    );
}

/// A request the operator asked about that never happened is a failed step,
/// not a quietly passing one.
#[tokio::test]
async fn asserting_on_a_request_the_page_never_made_fails_the_step() {
    let server = start_server();
    let page = format!("http://127.0.0.1:{}/", server.port);

    let Some(engine) = start_engine("about:blank") else {
        eprintln!("skipped: engine runtime is not installed");
        return;
    };

    let profile_id = "it-traffic-missing";
    cdp::attach(profile_id.to_string(), engine.ws_url.clone())
        .await
        .expect("attach to the running engine");

    let p = project(vec![
        block("rec", "recordTraffic", json!({})),
        block("nav", "navigate", json!({ "url": page })),
        block("settle", "wait", json!({ "ms": 800 })),
        block(
            "nope",
            "assertRequest",
            json!({ "urlContains": "/api/never" }),
        ),
    ]);

    let report = runner::run(&p, profile_id, HashMap::new())
        .await
        .expect("the run should start");

    cdp::detach(profile_id);

    assert!(!report.ok, "asserting on a request nobody made must fail");
    let step = report
        .steps
        .iter()
        .find(|s| s.block_id == "nope")
        .expect("the assertion should be in the report");
    assert!(
        step.error
            .as_deref()
            .unwrap_or_default()
            .contains("/api/never"),
        "the error should name the URL the operator asked about: {:?}",
        step.error
    );
}

/// A request that came back 500 is not a request that worked.
///
/// The page loads fine and shows nothing wrong; only the recording knows.
#[tokio::test]
async fn a_request_that_failed_on_the_server_fails_the_assertion() {
    let server = start_server();
    let page = format!("http://127.0.0.1:{}/api/broken", server.port);

    let Some(engine) = start_engine("about:blank") else {
        eprintln!("skipped: engine runtime is not installed");
        return;
    };

    let profile_id = "it-traffic-500";
    cdp::attach(profile_id.to_string(), engine.ws_url.clone())
        .await
        .expect("attach to the running engine");

    let p = project(vec![
        block("rec", "recordTraffic", json!({})),
        block("nav", "navigate", json!({ "url": page })),
        block("settle", "wait", json!({ "ms": 600 })),
        block(
            "seen",
            "assertRequest",
            json!({ "urlContains": "/api/broken" }),
        ),
    ]);

    let report = runner::run(&p, profile_id, HashMap::new())
        .await
        .expect("the run should start");

    cdp::detach(profile_id);

    assert!(
        !report.ok,
        "a 500 must not pass an assertion about the request"
    );
    let step = report
        .steps
        .iter()
        .find(|s| s.block_id == "seen")
        .expect("the assertion should be in the report");
    assert!(
        step.error.as_deref().unwrap_or_default().contains("500"),
        "the error should say what the server answered: {:?}",
        step.error
    );
}

/// The attack the provenance guard exists to stop, end to end.
///
/// The fixture serves a heading whose *text* closes a JS string literal and
/// appends a statement. A `readText` block lifts it into a variable, and an
/// `evaluate` block interpolates that variable believing it is a string.
///
/// Before the guard this ran the page's statement (`window.__pwned = 'yes'`).
/// Now the step is refused, and the error names the variable and points at the
/// alternative rather than leaving the operator to guess.
#[tokio::test]
async fn a_page_supplied_value_is_refused_at_the_script_sink() {
    let (_fixture_dir, url) = fixture_url();
    let Some(engine) = start_engine(&url) else {
        eprintln!("skipped: engine runtime is not installed");
        return;
    };

    let profile_id = "it-evaluate-provenance";
    cdp::attach(profile_id.to_string(), engine.ws_url.clone())
        .await
        .expect("attach to the running engine");

    let p = project(vec![
        block("nav", "navigate", json!({ "url": url })),
        block(
            "steal",
            "readText",
            json!({ "selector": "#hostile", "into": "payload" }),
        ),
        block_continuing(
            "run",
            "evaluate",
            json!({ "script": "window.__pwned = '{{payload}}'; 1" }),
        ),
        block(
            "confirm",
            "evaluate",
            json!({ "script": "window.__pwned ?? 'no'", "into": "pwned" }),
        ),
    ]);

    let report = runner::run(&p, profile_id, HashMap::new())
        .await
        .expect("the run should start");

    cdp::detach(profile_id);

    let run = report
        .steps
        .iter()
        .find(|s| s.block_id == "run")
        .expect("the script step should be in the report");
    let error = run.error.as_deref().unwrap_or_default();
    assert!(
        error.contains("payload") && error.contains("outside the project"),
        "the refusal should name the variable and why: {error:?}"
    );
    assert!(
        error.contains("with"),
        "the refusal should point at the safe alternative: {error:?}"
    );
    assert_eq!(
        report.variables.get("pwned").map(String::as_str),
        Some("no"),
        "the page's statement must not have run: {:?}",
        report.variables
    );
}

/// Refusing interpolation is only reasonable because there is somewhere else
/// for the value to go. `with` hands it to the page as a real argument, so the
/// same hostile text arrives as data — quotes and all — and can be used.
#[tokio::test]
async fn outside_text_still_reaches_a_script_as_a_bound_argument() {
    let (_fixture_dir, url) = fixture_url();
    let Some(engine) = start_engine(&url) else {
        eprintln!("skipped: engine runtime is not installed");
        return;
    };

    let profile_id = "it-evaluate-bound";
    cdp::attach(profile_id.to_string(), engine.ws_url.clone())
        .await
        .expect("attach to the running engine");

    let p = project(vec![
        block("nav", "navigate", json!({ "url": url })),
        block(
            "steal",
            "readText",
            json!({ "selector": "#hostile", "into": "payload" }),
        ),
        // Same value, same script, delivered as an argument instead.
        block(
            "use",
            "evaluate",
            json!({
                "script": "window.__pwned ??= 'no'; return payload",
                "with": ["payload"],
                "into": "seen",
            }),
        ),
        block(
            "confirm",
            "evaluate",
            json!({ "script": "window.__pwned ?? 'no'", "into": "pwned" }),
        ),
    ]);

    let report = runner::run(&p, profile_id, HashMap::new())
        .await
        .expect("the run should start");

    cdp::detach(profile_id);

    assert!(report.ok, "the run should succeed: {:?}", report.steps);
    assert_eq!(
        report.variables.get("seen").map(String::as_str),
        Some("'; window.__pwned = 'yes'; '"),
        "the script should have received the hostile text intact, as data: {:?}",
        report.variables
    );
    assert_eq!(
        report.variables.get("pwned").map(String::as_str),
        Some("no"),
        "and none of it should have executed: {:?}",
        report.variables
    );
}

/// A copy must carry the origin with it. Otherwise one `setVariable` launders
/// the page's text into a name the guard trusts, and the refusal above becomes
/// a formality anyone can step around.
#[tokio::test]
async fn copying_an_outside_value_does_not_launder_it() {
    let (_fixture_dir, url) = fixture_url();
    let Some(engine) = start_engine(&url) else {
        eprintln!("skipped: engine runtime is not installed");
        return;
    };

    let profile_id = "it-evaluate-launder";
    cdp::attach(profile_id.to_string(), engine.ws_url.clone())
        .await
        .expect("attach to the running engine");

    let p = project(vec![
        block("nav", "navigate", json!({ "url": url })),
        block(
            "steal",
            "readText",
            json!({ "selector": "#hostile", "into": "payload" }),
        ),
        block(
            "launder",
            "setVariable",
            json!({ "name": "clean", "value": "{{payload}}" }),
        ),
        block_continuing(
            "run",
            "evaluate",
            json!({ "script": "window.__pwned = '{{clean}}'; 1" }),
        ),
        block(
            "confirm",
            "evaluate",
            json!({ "script": "window.__pwned ?? 'no'", "into": "pwned" }),
        ),
    ]);

    let report = runner::run(&p, profile_id, HashMap::new())
        .await
        .expect("the run should start");

    cdp::detach(profile_id);

    let run = report
        .steps
        .iter()
        .find(|s| s.block_id == "run")
        .expect("the script step should be in the report");
    assert!(
        run.error.as_deref().unwrap_or_default().contains("clean"),
        "the copy should still be refused, naming the copy: {:?}",
        run.error
    );
    assert_eq!(
        report.variables.get("pwned").map(String::as_str),
        Some("no"),
        "the page's statement must not have run: {:?}",
        report.variables
    );
}

/// An operator's own text is not restricted. The guard is about provenance,
/// so a script interpolating a variable the project itself set keeps working.
#[tokio::test]
async fn an_operators_own_value_still_interpolates() {
    let (_fixture_dir, url) = fixture_url();
    let Some(engine) = start_engine(&url) else {
        eprintln!("skipped: engine runtime is not installed");
        return;
    };

    let profile_id = "it-evaluate-operator";
    cdp::attach(profile_id.to_string(), engine.ws_url.clone())
        .await
        .expect("attach to the running engine");

    let p = project(vec![
        block("nav", "navigate", json!({ "url": url })),
        block(
            "mine",
            "setVariable",
            json!({ "name": "greeting", "value": "hello" }),
        ),
        block(
            "run",
            "evaluate",
            json!({ "script": "'{{greeting}} there'", "into": "said" }),
        ),
    ]);

    let report = runner::run(&p, profile_id, HashMap::new())
        .await
        .expect("the run should start");

    cdp::detach(profile_id);

    assert!(report.ok, "the run should succeed: {:?}", report.steps);
    assert_eq!(
        report.variables.get("said").map(String::as_str),
        Some("hello there"),
        "the operator's own text should interpolate as before: {:?}",
        report.variables
    );
}
