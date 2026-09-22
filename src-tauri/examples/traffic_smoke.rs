//! Smoke check: run the traffic blocks against a real profile's engine.
//!
//! Point it at the CDP websocket of a profile the launcher already started:
//!
//!     cargo run --example traffic_smoke -- ws://127.0.0.1:PORT/devtools/browser/ID https://example.com
//!
//! It does not start or stop anything: whoever started the browser keeps
//! ownership of it, which is the launcher's rule for automation.

use std::collections::HashMap;

use shardx_launcher_lib::automation::{Block, Project, RunSettings};
use shardx_launcher_lib::{cdp, runner};

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let ws = args.next().expect("usage: traffic_smoke <ws-url> <page-url>");
    let url = args.next().expect("usage: traffic_smoke <ws-url> <page-url>");

    let profile_id = "smoke";
    cdp::attach(profile_id.to_string(), ws)
        .await
        .expect("attach to the running engine");

    let project = Project {
        id: "smoke".into(),
        name: "Traffic smoke".into(),
        notes: String::new(),
        blocks: vec![
            block("rec", "recordTraffic", serde_json::json!({})),
            block("nav", "navigate", serde_json::json!({ "url": url })),
            block("settle", "wait", serde_json::json!({ "ms": 2500 })),
            block(
                "stop",
                "stopTraffic",
                serde_json::json!({ "into": "requests" }),
            ),
        ],
        run: RunSettings::default(),
        created_at: 0,
        updated_at: 0,
    };

    let report = runner::run(&project, profile_id, HashMap::new())
        .await
        .expect("the run should finish");

    println!("ok: {}", report.ok);
    println!("recorded: {}", report.requests.len());
    for step in &report.steps {
        println!("  step {:<7} {:?} {}ms", step.kind, step.outcome, step.ms);
    }
    let failed = report
        .requests
        .iter()
        .filter(|r| r.error.is_some() || r.status.map(|s| s >= 400).unwrap_or(false))
        .count();
    println!("failed requests: {failed}");
    for entry in report.requests.iter().take(12) {
        println!(
            "  {:<6} {:<4} {}",
            entry.method,
            entry
                .status
                .map(|s| s.to_string())
                .unwrap_or_else(|| entry.error.clone().unwrap_or_else(|| "-".into())),
            entry.url,
        );
    }

    cdp::detach(profile_id);
}

fn block(id: &str, kind: &str, params: serde_json::Value) -> Block {
    // Built through serde so the example stays honest about the shape a saved
    // project has, rather than tracking every field the struct grows.
    serde_json::from_value(serde_json::json!({
        "id": id,
        "kind": kind,
        "params": params,
    }))
    .expect("a block")
}
