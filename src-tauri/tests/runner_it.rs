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
        block("name", "setVariable", json!({ "name": "who", "value": "ann" })),
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
        block("after", "setVariable", json!({ "name": "ran", "value": "yes" })),
    ]);
    // Keep the wait short: the point is the verdict, not the timeout.
    p.blocks[1].on_fail = Branch::Stop;

    let report = runner::run(&p, profile_id, HashMap::new())
        .await
        .expect("the run should start");

    cdp::detach(profile_id);

    assert!(!report.ok, "a run with a failed step must not report success");
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
