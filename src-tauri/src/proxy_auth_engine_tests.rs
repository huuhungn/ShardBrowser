//! Opt-in, real-engine regression for upstream #100. Never uses operator profiles.
//! Run with SHARDX_TEST_ENGINE and SHARDX_TEST_SCRATCH set to absolute paths:
//! cargo test --lib proxy_auth_engine_tests -- --ignored --test-threads=1
//! Credentials are generated per run and assertions report only counters.

use crate::{cdp, launch, process::Tracker, settings, store};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::json;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};

const BODY: &str = "issue100-via-authenticated-proxy";

#[derive(Default)]
struct Counts {
    accepted: AtomicUsize,
    target_hits: AtomicUsize,
    rejected: AtomicUsize,
    direct: AtomicUsize,
}

struct ListenerTask(JoinHandle<()>);
impl Drop for ListenerTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Roots;
impl Drop for Roots {
    fn drop(&mut self) {
        store::set_data_root(None);
        store::set_config_root(None);
    }
}

async fn read_header(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut bytes = Vec::new();
    while bytes.len() < 16 * 1024 {
        bytes.push(stream.read_u8().await?);
        if bytes.ends_with(b"\r\n\r\n") {
            return String::from_utf8(bytes)
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData));
        }
    }
    Err(std::io::ErrorKind::InvalidData.into())
}

async fn serve(expected: Option<String>, counts: Arc<Counts>) -> (u16, ListenerTask) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let mut peers = JoinSet::new();
        loop {
            tokio::select! {
                incoming = listener.accept() => {
                    let Ok((mut stream, _)) = incoming else { break };
                    let expected = expected.clone();
                    let counts = counts.clone();
                    peers.spawn(async move {
                        let Ok(Ok(header)) = tokio::time::timeout(
                            Duration::from_secs(5), read_header(&mut stream),
                        ).await else { return };
                        let response = if let Some(expected) = expected {
                            let authorized = header.lines().filter_map(|line| line.split_once(':'))
                                .any(|(key, value)| key.eq_ignore_ascii_case("proxy-authorization")
                                    && value.trim() == expected);
                            if !authorized {
                                counts.rejected.fetch_add(1, Ordering::SeqCst);
                                "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"issue100\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
                            } else {
                                counts.accepted.fetch_add(1, Ordering::SeqCst);
                                // Launcher geo checks also use this proxy; only the page target proves the engine path.
                                if header.lines().next().is_some_and(|line| line.contains("/issue100-target")) {
                                    counts.target_hits.fetch_add(1, Ordering::SeqCst);
                                }
                                // No public request is forwarded, including launcher geo checks.
                                format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{BODY}", BODY.len())
                            }
                        } else {
                            counts.direct.fetch_add(1, Ordering::SeqCst);
                            "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndirect".to_string()
                        };
                        let _ = stream.write_all(response.as_bytes()).await;
                    });
                }
                _ = peers.join_next(), if !peers.is_empty() => {}
            }
        }
    });
    (port, ListenerTask(task))
}

const NAV_ATTEMPTS: usize = 3;

async fn navigate_and_read(id: &str, target: u16) -> anyhow::Result<bool> {
    let navigation = cdp::page_call(
        id,
        "Page.navigate",
        json!({ "url": format!("http://127.0.0.1:{target}/issue100-target") }),
    )
    .await?;
    if navigation.get("errorText").is_some() {
        tokio::time::sleep(Duration::from_millis(500)).await;
        return Ok(false);
    }
    for _ in 0..50 {
        let value = cdp::page_call(
            id,
            "Runtime.evaluate",
            json!({
                "expression": "document.body ? document.body.innerText : ''",
                "returnByValue": true
            }),
        )
        .await?;
        if value["result"]["value"].as_str() == Some(BODY) {
            return Ok(true);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(false)
}

async fn run_case(label: &str, comma: bool) -> anyhow::Result<()> {
    let counts = Arc::new(Counts::default());
    let mut username = uuid::Uuid::new_v4().simple().to_string();
    if comma {
        username.insert(8, ',');
    }
    let password = uuid::Uuid::new_v4().simple().to_string();
    let expected = format!(
        "Basic {}",
        STANDARD.encode(format!("{username}:{password}"))
    );
    let (port, _proxy) = serve(Some(expected), counts.clone()).await;
    let (target, _direct) = serve(None, counts.clone()).await;
    let id = format!("issue100-{}", uuid::Uuid::new_v4().simple());
    let profile_path = store::profiles_dir()?.join(format!("{id}.json"));
    let profile = json!({
        "name": "Issue 100 isolated regression", "webrtc": "block",
        "_meta": {
            "id": id, "temporary": true,
            "inline_proxy": {
                "id": "", "name": "isolated-loopback", "kind": "http",
                "host": "127.0.0.1", "port": port,
                "username": username, "password": password
            }
        }
    });
    std::fs::write(&profile_path, serde_json::to_vec(&profile)?)?;
    let outcome = launch::launch_profile(&id, true, true).await?;
    let result: anyhow::Result<bool> = async {
        let ws = outcome
            .cdp
            .as_ref()
            .map(|c| c.web_socket_debugger_url.clone())
            .ok_or_else(|| anyhow::anyhow!("CDP did not start"))?;
        cdp::attach(id.clone(), ws).await?;
        // The engine can fail its first proxy challenge while its own startup
        // requests race the navigation (seen with plain credentials too), so
        // retry a few times. A credential the proxy rejects fails every try.
        for attempt in 1..=NAV_ATTEMPTS {
            if navigate_and_read(&id, target).await? {
                eprintln!("issue100 {label}: loaded on attempt {attempt}");
                return Ok(true);
            }
        }
        Ok(false)
    }
    .await;
    cdp::detach(&id);
    Tracker::shared()
        .kill_if_instance(&id, outcome.pid, &outcome.launch_instance_token)
        .await?;
    for _ in 0..100 {
        if !Tracker::shared().is_running(&id) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    anyhow::ensure!(
        !Tracker::shared().is_running(&id),
        "test engine cleanup incomplete"
    );
    let accepted = counts.accepted.load(Ordering::SeqCst);
    let target_hits = counts.target_hits.load(Ordering::SeqCst);
    let rejected = counts.rejected.load(Ordering::SeqCst);
    let direct = counts.direct.load(Ordering::SeqCst);
    let loaded = result?;
    eprintln!("issue100 {label}: accepted={accepted} target_hits={target_hits} rejected={rejected} direct={direct} loaded={loaded}");
    anyhow::ensure!(direct == 0, "{label}: direct fallback detected");
    anyhow::ensure!(
        loaded && target_hits > 0,
        "{label}: engine failed proxy authentication/page load"
    );
    anyhow::ensure!(!profile_path.exists(), "temporary profile was not removed");
    Ok(())
}

#[test]
#[ignore = "requires explicit SHARDX_TEST_ENGINE and SHARDX_TEST_SCRATCH; launches isolated headless engines"]
fn launcher_http_comma_credentials_reach_authenticated_proxy() {
    let engine = std::env::var("SHARDX_TEST_ENGINE").expect("set explicit test engine path");
    assert!(
        std::path::Path::new(&engine).is_file(),
        "test engine missing"
    );
    let scratch = std::env::var("SHARDX_TEST_SCRATCH").expect("set explicit scratch directory");
    let _lock = store::config_root_test_lock().lock().unwrap();
    let temp = tempfile::Builder::new()
        .prefix("issue100-")
        .tempdir_in(scratch)
        .unwrap();
    store::set_config_root(Some(temp.path().join("config")));
    store::set_data_root(Some(temp.path().join("data")));
    let _roots = Roots;
    settings::save(&settings::Settings {
        browser_path: Some(engine),
        extra_args: "--proxy-bypass-list=<-loopback> --disable-background-networking --disable-component-update --disable-gpu".into(),
        ..Default::default()
    }).unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        run_case("control", false).await.unwrap();
        run_case("comma-username", true).await.unwrap();
    });
}
