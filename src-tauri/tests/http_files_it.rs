//! HTTP sessions and file blocks, against real sockets and a real filesystem.
//!
//! The unit tests around these cover the rules in isolation. What they cannot
//! show is the property that matters most in production: that a call made by
//! a project actually leaves through the profile's proxy. A client built with
//! the wrong proxy, or with one that silently failed to apply, behaves
//! identically in every unit test and puts the host's own IP in the site's
//! logs next to that profile's session.
//!
//! So the proxy test here runs a real CONNECT proxy in-process and asserts the
//! request arrived through it.

use serde_json::{json, Value};
use shardx_launcher_lib::automation::{Block, Branch, Project, RunSettings};
use shardx_launcher_lib::{files, http_session, runner, store};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

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
        id: "p-http".into(),
        name: "HTTP".into(),
        notes: String::new(),
        blocks,
        run: RunSettings::default(),
        created_at: 0,
        updated_at: 0,
    }
}

/// A scratch config root, so tests never touch the real profile store.
fn scratch() -> (std::sync::MutexGuard<'static, ()>, tempfile::TempDir) {
    let guard = store::config_root_test_lock()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().expect("a scratch config root");
    store::set_config_root(Some(dir.path().to_path_buf()));
    (guard, dir)
}

/// A minimal origin server: answers every request with a fixed body.
struct Origin {
    port: u16,
    hits: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
    }
}

fn start_origin() -> Origin {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind an origin");
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let (h, s) = (hits.clone(), stop.clone());

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            if s.load(Ordering::Relaxed) {
                break;
            }
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            if req.is_empty() {
                continue;
            }
            h.fetch_add(1, Ordering::Relaxed);

            let path = req
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("/")
                .to_string();

            // Echo back a cookie on /set so cookie persistence can be tested,
            // and report what the client sent on /echo.
            let (status, extra, body) = if path.starts_with("/set") {
                (
                    "200 OK",
                    "Set-Cookie: session=abc123; Path=/\r\n".to_string(),
                    "{\"set\":true}".to_string(),
                )
            } else if path.starts_with("/echo") {
                let cookie = req
                    .lines()
                    .find(|l| l.to_lowercase().starts_with("cookie:"))
                    .unwrap_or("")
                    .to_string();
                (
                    "200 OK",
                    String::new(),
                    format!("{{\"cookie\":\"{}\"}}", cookie.replace('"', "")),
                )
            } else if path.starts_with("/boom") {
                (
                    "500 Internal Server Error",
                    String::new(),
                    "nope".to_string(),
                )
            } else {
                ("200 OK", String::new(), "{\"ok\":true}".to_string())
            };

            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n{extra}\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });

    Origin { port, hits, stop }
}

/// A real HTTP proxy that counts what passes through it.
///
/// Handles plain forwarding (absolute-form request line), which is what an
/// `http://` request through an HTTP proxy uses.
struct ProxyServer {
    port: u16,
    seen: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
}

impl Drop for ProxyServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
    }
}

fn start_proxy() -> ProxyServer {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a proxy");
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let (c, s) = (seen.clone(), stop.clone());

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            if s.load(Ordering::Relaxed) {
                break;
            }
            let Ok(mut client) = stream else { continue };
            let mut buf = [0u8; 8192];
            let n = client.read(&mut buf).unwrap_or(0);
            if n == 0 {
                continue;
            }
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let Some(line) = req.lines().next() else {
                continue;
            };
            let mut parts = line.split_whitespace();
            let _method = parts.next().unwrap_or("");
            let target = parts.next().unwrap_or("");

            // Absolute-form target proves the client addressed us as a proxy
            // rather than connecting to the origin directly.
            if !target.starts_with("http://") {
                continue;
            }
            c.fetch_add(1, Ordering::Relaxed);

            let without_scheme = &target["http://".len()..];
            let (authority, path) = match without_scheme.find('/') {
                Some(i) => (&without_scheme[..i], &without_scheme[i..]),
                None => (without_scheme, "/"),
            };

            let Ok(mut upstream) = TcpStream::connect(authority) else {
                continue;
            };
            // Rewrite to origin-form and forward the rest untouched.
            let rest = req.splitn(2, "\r\n").nth(1).unwrap_or("");
            let forwarded = format!("GET {path} HTTP/1.1\r\n{rest}");
            let _ = upstream.write_all(forwarded.as_bytes());

            let mut response = Vec::new();
            let _ = upstream.read_to_end(&mut response);
            let _ = client.write_all(&response);
        }
    });

    ProxyServer { port, seen, stop }
}

/// Write a profile into the scratch store, optionally bound to a proxy.
fn make_profile(id: &str, proxy_port: Option<u16>) {
    let proxy_id = proxy_port.map(|port| {
        let entry = json!({
            "id": "px-test",
            "name": "Test proxy",
            "kind": "http",
            "host": "127.0.0.1",
            "port": port,
            "username": "",
            "password": "",
            "country": "",
            "notes": ""
        });
        let store_json = json!({ "proxies": [entry] });
        std::fs::write(
            store::proxies_path().expect("proxies path"),
            serde_json::to_vec_pretty(&store_json).unwrap(),
        )
        .expect("write the proxy store");
        "px-test".to_string()
    });

    let dir = store::profiles_dir().expect("profiles dir");
    std::fs::create_dir_all(&dir).expect("create profiles dir");
    // `StoredProfile` reads its metadata from `_meta`; writing `meta` here
    // would deserialise into a default profile with no proxy, and the proxy
    // test would then pass for the wrong reason.
    let profile = json!({
        "_meta": {
            "id": id,
            "name": id,
            "proxy_id": proxy_id,
        }
    });
    std::fs::write(
        dir.join(format!("{id}.json")),
        serde_json::to_vec_pretty(&profile).unwrap(),
    )
    .expect("write the profile");
}

/// The property the whole module exists for: a project's HTTP call leaves
/// through the profile's proxy, not the host's own network.
///
/// A client built without the proxy still reaches the origin and still returns
/// 200, so only counting what the proxy saw can tell the two apart.
#[tokio::test]
async fn a_projects_http_call_goes_out_through_the_profiles_proxy() {
    let (_g, _d) = scratch();
    let origin = start_origin();
    let proxy = start_proxy();
    make_profile("px-profile", Some(proxy.port));

    let url = format!("http://127.0.0.1:{}/plain", origin.port);
    let p = project(vec![
        block("open", "httpOpen", json!({})),
        block(
            "get",
            "httpRequest",
            json!({ "url": url, "into": "body", "statusInto": "code", "mustSucceed": true }),
        ),
        block("close", "httpClose", json!({})),
    ]);

    let report = runner::run(&p, "px-profile", HashMap::new())
        .await
        .expect("the run should start");

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
        report.variables.get("code").map(String::as_str),
        Some("200")
    );
    assert_eq!(
        proxy.seen.load(Ordering::Relaxed),
        1,
        "the request must have gone through the profile's proxy, not direct"
    );
    assert_eq!(
        origin.hits.load(Ordering::Relaxed),
        1,
        "the origin should have been reached exactly once"
    );
}

/// A profile bound to a proxy that cannot be reached fails the step rather
/// than quietly falling back to a direct connection.
#[tokio::test]
async fn a_dead_proxy_fails_the_call_instead_of_going_direct() {
    let (_g, _d) = scratch();
    let origin = start_origin();

    // A port nobody is listening on.
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    };
    make_profile("dead-proxy", Some(dead));

    let url = format!("http://127.0.0.1:{}/plain", origin.port);
    let p = project(vec![
        block("open", "httpOpen", json!({})),
        block("get", "httpRequest", json!({ "url": url })),
    ]);

    let report = runner::run(&p, "dead-proxy", HashMap::new())
        .await
        .expect("the run should start");

    assert!(!report.ok, "a call through a dead proxy must fail");
    assert_eq!(
        origin.hits.load(Ordering::Relaxed),
        0,
        "nothing may reach the origin when the proxy is down: that would be \
         the host's own IP"
    );
}

/// Cookies persist across blocks, which is what makes a login usable by the
/// steps that follow it.
#[tokio::test]
async fn a_session_carries_its_cookies_between_blocks() {
    let (_g, _d) = scratch();
    let origin = start_origin();
    make_profile("cookie-profile", None);

    let base = format!("http://127.0.0.1:{}", origin.port);
    let p = project(vec![
        block("open", "httpOpen", json!({})),
        block(
            "login",
            "httpRequest",
            json!({ "url": format!("{base}/set") }),
        ),
        block(
            "check",
            "httpRequest",
            json!({ "url": format!("{base}/echo"), "into": "echoed" }),
        ),
        block("close", "httpClose", json!({})),
    ]);

    let report = runner::run(&p, "cookie-profile", HashMap::new())
        .await
        .expect("the run should start");

    assert!(report.ok, "steps: {:?}", report.steps);
    let echoed = report.variables.get("echoed").cloned().unwrap_or_default();
    assert!(
        echoed.contains("session=abc123"),
        "the cookie set by the first call should be sent by the second: {echoed}"
    );
}

/// A run that ends without its close block must not leave the session open,
/// or the next run inherits a login it never performed.
#[tokio::test]
async fn a_failed_run_does_not_leave_its_session_open() {
    let (_g, _d) = scratch();
    let origin = start_origin();
    make_profile("leaky", None);

    let base = format!("http://127.0.0.1:{}", origin.port);
    let p = project(vec![
        block("open", "httpOpen", json!({})),
        block(
            "login",
            "httpRequest",
            json!({ "url": format!("{base}/set") }),
        ),
        // Fails, so the run stops before any close block.
        block(
            "boom",
            "httpRequest",
            json!({ "url": format!("{base}/boom"), "mustSucceed": true }),
        ),
        block("close", "httpClose", json!({})),
    ]);

    let report = runner::run(&p, "leaky", HashMap::new())
        .await
        .expect("the run should start");
    assert!(!report.ok, "the 500 should fail the run");

    // The session must be gone: a call now should complain that none is open.
    let e = http_session::request(
        "leaky",
        "GET",
        &format!("{base}/echo"),
        &HashMap::new(),
        None,
    )
    .await
    .unwrap_err();
    assert!(
        format!("{e:#}").contains("httpOpen"),
        "the session should have been closed when the run ended: {e:#}"
    );
}

/// A non-2xx is reported, not raised, unless the project asked for success.
#[tokio::test]
async fn a_status_is_reported_when_the_project_did_not_demand_success() {
    let (_g, _d) = scratch();
    let origin = start_origin();
    make_profile("status-profile", None);

    let url = format!("http://127.0.0.1:{}/boom", origin.port);
    let p = project(vec![
        block("open", "httpOpen", json!({})),
        block(
            "get",
            "httpRequest",
            json!({ "url": url, "statusInto": "code" }),
        ),
        block("close", "httpClose", json!({})),
    ]);

    let report = runner::run(&p, "status-profile", HashMap::new())
        .await
        .expect("the run should start");

    assert!(
        report.ok,
        "polling an endpoint that 500s is not itself a failure"
    );
    assert_eq!(
        report.variables.get("code").map(String::as_str),
        Some("500")
    );
}

/// Files a project writes land on disk and read back through the run.
#[tokio::test]
async fn a_project_can_write_then_read_its_own_file() {
    let (_g, dir) = scratch();

    let p = project(vec![
        block(
            "w",
            "writeFile",
            json!({ "path": "out/run.txt", "contents": "alpha" }),
        ),
        block(
            "a",
            "appendFile",
            json!({ "path": "out/run.txt", "contents": "-beta" }),
        ),
        block(
            "e",
            "fileExists",
            json!({ "path": "out/run.txt", "mustExist": true }),
        ),
        block(
            "r",
            "readFile",
            json!({ "path": "out/run.txt", "into": "text" }),
        ),
    ]);

    let report = runner::run(&p, "file-profile", HashMap::new())
        .await
        .expect("the run should start");

    assert!(report.ok, "steps: {:?}", report.steps);
    assert_eq!(
        report.variables.get("text").map(String::as_str),
        Some("alpha-beta")
    );
    assert!(
        dir.path().join("automation-files/out/run.txt").is_file(),
        "the file should be inside the workspace"
    );
}

/// A file variable substitutes like any other, which is how a project writes
/// what it read from a page or an API.
#[tokio::test]
async fn file_contents_flow_through_variables() {
    let (_g, _d) = scratch();

    let p = project(vec![
        block(
            "set",
            "setVariable",
            json!({ "name": "who", "value": "alice" }),
        ),
        block(
            "w",
            "writeFile",
            json!({ "path": "greet.txt", "contents": "hello {{who}}" }),
        ),
        block(
            "r",
            "readFile",
            json!({ "path": "greet.txt", "into": "greeting" }),
        ),
    ]);

    let report = runner::run(&p, "file-profile", HashMap::new())
        .await
        .expect("the run should start");

    assert!(report.ok, "steps: {:?}", report.steps);
    assert_eq!(
        report.variables.get("greeting").map(String::as_str),
        Some("hello alice")
    );
}

/// A project that names a path outside the workspace fails, and writes
/// nothing there.
#[tokio::test]
async fn a_project_cannot_write_outside_its_workspace() {
    let (_g, dir) = scratch();

    let p = project(vec![block(
        "w",
        "writeFile",
        json!({ "path": "../proxies.json", "contents": "stolen" }),
    )]);

    let report = runner::run(&p, "file-profile", HashMap::new())
        .await
        .expect("the run should start");

    assert!(!report.ok, "the traversal must fail the run");
    // The real proof: the launcher's own store is untouched.
    let leaked = dir.path().join("proxies.json");
    assert!(
        !leaked.exists() || std::fs::read_to_string(&leaked).unwrap_or_default() != "stolen",
        "the project must not have written into the config root"
    );
    // And the workspace itself is where the rule is enforced from.
    assert!(files::workspace().unwrap().starts_with(dir.path()));
}
