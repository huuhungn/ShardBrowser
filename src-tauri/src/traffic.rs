//! Recording the requests a profile makes while a project runs.
//!
//! This is the read-only half of traffic interception: the runner turns
//! `Network` on, every request and response is folded into one entry per
//! request id, and a project can then assert against what the page actually
//! fetched rather than against what it rendered. Rewriting or blocking
//! requests needs `Fetch`, which pauses the page until each one is answered,
//! and is deliberately not done here -- a recorder that stalls the run when
//! the operator closes the window is worse than no recorder.
//!
//! Bodies are not collected. `Network.getResponseBody` has to be called while
//! the response is still in the renderer's cache, so collecting every body
//! would mean a call per response, on the reader task, during the run.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::task::JoinHandle;

use crate::cdp;

/// One request, as far as the page got with it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Entry {
    /// CDP's request id; unique within a session, and how the halves are
    /// paired up.
    pub id: String,
    pub method: String,
    pub url: String,
    /// The resource type CDP reported (Document, XHR, Script, ...). Empty
    /// until the request is reported, which is always before its response.
    pub kind: String,
    /// None until a response arrives. A request that was blocked, cancelled,
    /// or is still in flight when the recording stops keeps None, which is
    /// what `failed` reports on.
    pub status: Option<u16>,
    /// Set when the request failed outright, e.g. a DNS failure or a block.
    pub error: Option<String>,
    /// Bytes the response carried, once known.
    pub bytes: Option<u64>,
    /// When the request left, in ms since the recording started.
    pub started_ms: u64,
}

impl Entry {
    /// Whether this request did not end in a response the page could use.
    ///
    /// A recorder that only reported transport errors would call a 500 a
    /// success, which is not what an operator asserting "the login call
    /// worked" means.
    pub fn failed(&self) -> bool {
        match (self.error.as_deref(), self.status) {
            (Some(_), _) => true,
            (None, Some(code)) => !(200..400).contains(&code),
            (None, None) => true,
        }
    }
}

#[derive(Default)]
struct Log {
    /// Insertion-ordered so a report reads in the order the page fetched.
    order: Vec<String>,
    by_id: HashMap<String, Entry>,
    /// Dropped because the cap was reached; reported rather than hidden.
    dropped: u64,
}

/// A live recording. Dropping it stops the reader task.
pub struct Recorder {
    log: Arc<Mutex<Log>>,
    task: JoinHandle<()>,
    profile_id: String,
}

/// How many requests one recording keeps.
///
/// A page left open on a video site will produce requests for as long as it is
/// open; without a cap the log is a slow memory leak that only shows up on the
/// runs that matter, which are the long ones.
const MAX_ENTRIES: usize = 5_000;

impl Recorder {
    /// Turn `Network` on and start folding its events into a log.
    ///
    /// The profile must already be attached: the recorder does not start
    /// browsers, for the same reason the runner does not.
    pub async fn start(profile_id: &str) -> Result<Self> {
        let rx = cdp::subscribe(profile_id)
            .context("the profile is not attached — start it before recording traffic")?;

        // Enable before anything else: events that fire between attaching and
        // enabling are simply never sent, so a recorder that enabled last
        // would silently miss the first requests of a navigation.
        cdp::page_call(profile_id, "Network.enable", json!({}))
            .await
            .context("the profile would not report its network activity")?;

        let log: Arc<Mutex<Log>> = Arc::new(Mutex::new(Log::default()));
        let sink = log.clone();
        let started = std::time::Instant::now();

        let mut rx = rx;
        let task = tokio::spawn(async move {
            loop {
                let event = match rx.recv().await {
                    Ok(e) => e,
                    // Lagged means the page outran the channel. The entries
                    // are gone either way; count them so a report can say so
                    // instead of quietly being short.
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        if let Ok(mut l) = sink.lock() {
                            l.dropped += n;
                        }
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                };
                let Ok(mut l) = sink.lock() else { break };
                absorb(
                    &mut l,
                    &event.method,
                    &event.params,
                    started.elapsed().as_millis() as u64,
                );
            }
        });

        Ok(Self {
            log,
            task,
            profile_id: profile_id.to_string(),
        })
    }

    /// Everything recorded so far, in the order the page requested it.
    pub fn entries(&self) -> Vec<Entry> {
        let Ok(l) = self.log.lock() else {
            return Vec::new();
        };
        l.order
            .iter()
            .filter_map(|id| l.by_id.get(id).cloned())
            .collect()
    }

    /// Requests dropped because the recorder could not keep up or hit its cap.
    pub fn dropped(&self) -> u64 {
        self.log.lock().map(|l| l.dropped).unwrap_or(0)
    }

    /// Stop recording and turn `Network` back off.
    ///
    /// Leaving it on would keep the browser serialising every request to a
    /// socket nobody reads for as long as the profile stays open.
    pub async fn stop(self) -> Vec<Entry> {
        let entries = self.entries();
        self.task.abort();
        // Best effort: the profile may already be gone, which is not a
        // failure worth reporting over the run's own outcome.
        let _ = cdp::page_call(&self.profile_id, "Network.disable", json!({})).await;
        entries
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Fold one event into the log.
///
/// Split out so the pairing logic can be tested without a browser: the
/// interesting part is that the halves of a request arrive separately and out
/// of order with respect to other requests.
fn absorb(log: &mut Log, method: &str, params: &Value, at_ms: u64) {
    let Some(id) = params.get("requestId").and_then(|v| v.as_str()) else {
        return;
    };

    match method {
        "Network.requestWillBeSent" => {
            if log.by_id.contains_key(id) {
                // A redirect reuses the request id. Keep the first entry: the
                // operator asked for a URL, and that is the one they will
                // assert on.
                return;
            }
            if log.order.len() >= MAX_ENTRIES {
                log.dropped += 1;
                return;
            }
            let request = params.get("request");
            let entry = Entry {
                id: id.to_string(),
                method: request
                    .and_then(|r| r.get("method"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("GET")
                    .to_string(),
                url: request
                    .and_then(|r| r.get("url"))
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                kind: params
                    .get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                status: None,
                error: None,
                bytes: None,
                started_ms: at_ms,
            };
            log.order.push(id.to_string());
            log.by_id.insert(id.to_string(), entry);
        }

        "Network.responseReceived" => {
            let status = params
                .get("response")
                .and_then(|r| r.get("status"))
                .and_then(|v| v.as_u64());
            if let Some(entry) = log.by_id.get_mut(id) {
                entry.status = status.map(|s| s as u16);
                if entry.kind.is_empty() {
                    if let Some(kind) = params.get("type").and_then(|v| v.as_str()) {
                        entry.kind = kind.to_string();
                    }
                }
            }
        }

        "Network.loadingFinished" => {
            if let Some(entry) = log.by_id.get_mut(id) {
                entry.bytes = params
                    .get("encodedDataLength")
                    .and_then(|v| v.as_f64())
                    .map(|n| n.max(0.0) as u64);
            }
        }

        "Network.loadingFailed" => {
            if let Some(entry) = log.by_id.get_mut(id) {
                entry.error = Some(
                    params
                        .get("errorText")
                        .and_then(|v| v.as_str())
                        .unwrap_or("the request failed")
                        .to_string(),
                );
            }
        }

        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sent(id: &str, url: &str, method: &str) -> Value {
        json!({
            "requestId": id,
            "type": "XHR",
            "request": { "url": url, "method": method },
        })
    }

    fn received(id: &str, status: u64) -> Value {
        json!({ "requestId": id, "response": { "status": status } })
    }

    #[test]
    fn a_request_and_its_response_become_one_entry() {
        let mut log = Log::default();
        absorb(
            &mut log,
            "Network.requestWillBeSent",
            &sent("1", "https://a/x", "POST"),
            5,
        );
        absorb(&mut log, "Network.responseReceived", &received("1", 201), 9);
        absorb(
            &mut log,
            "Network.loadingFinished",
            &json!({ "requestId": "1", "encodedDataLength": 412.0 }),
            10,
        );

        assert_eq!(log.order.len(), 1);
        let e = &log.by_id["1"];
        assert_eq!(e.url, "https://a/x");
        assert_eq!(e.method, "POST");
        assert_eq!(e.status, Some(201));
        assert_eq!(e.bytes, Some(412));
        assert_eq!(e.started_ms, 5);
        assert!(!e.failed());
    }

    #[test]
    fn responses_that_arrive_out_of_order_still_pair_with_their_requests() {
        // Two requests in flight at once is the normal case on any real page,
        // and the second one's response routinely lands first.
        let mut log = Log::default();
        absorb(
            &mut log,
            "Network.requestWillBeSent",
            &sent("1", "https://a/slow", "GET"),
            0,
        );
        absorb(
            &mut log,
            "Network.requestWillBeSent",
            &sent("2", "https://a/fast", "GET"),
            1,
        );
        absorb(&mut log, "Network.responseReceived", &received("2", 200), 2);
        absorb(
            &mut log,
            "Network.responseReceived",
            &received("1", 500),
            30,
        );

        assert_eq!(log.by_id["1"].status, Some(500));
        assert_eq!(log.by_id["2"].status, Some(200));
        // Order is the order they were requested, not the order they finished.
        assert_eq!(log.order, vec!["1".to_string(), "2".to_string()]);
    }

    #[test]
    fn a_server_error_counts_as_a_failure() {
        let mut log = Log::default();
        absorb(
            &mut log,
            "Network.requestWillBeSent",
            &sent("1", "https://a/x", "GET"),
            0,
        );
        absorb(&mut log, "Network.responseReceived", &received("1", 500), 1);
        assert!(
            log.by_id["1"].failed(),
            "a 500 is not a request that worked"
        );
    }

    #[test]
    fn a_redirect_is_reported_as_the_url_the_operator_asked_for() {
        // CDP reuses the request id across a redirect chain.
        let mut log = Log::default();
        absorb(
            &mut log,
            "Network.requestWillBeSent",
            &sent("1", "https://a/login", "GET"),
            0,
        );
        absorb(
            &mut log,
            "Network.requestWillBeSent",
            &sent("1", "https://a/home", "GET"),
            1,
        );

        assert_eq!(log.order.len(), 1, "a redirect is one request, not two");
        assert_eq!(log.by_id["1"].url, "https://a/login");
    }

    #[test]
    fn a_request_that_never_came_back_is_a_failure_not_a_success() {
        let mut log = Log::default();
        absorb(
            &mut log,
            "Network.requestWillBeSent",
            &sent("1", "https://a/x", "GET"),
            0,
        );
        assert!(
            log.by_id["1"].failed(),
            "a request still in flight has not succeeded, and a report must not imply it has",
        );
    }

    #[test]
    fn a_transport_failure_is_recorded_with_its_reason() {
        let mut log = Log::default();
        absorb(
            &mut log,
            "Network.requestWillBeSent",
            &sent("1", "https://nope/x", "GET"),
            0,
        );
        absorb(
            &mut log,
            "Network.loadingFailed",
            &json!({ "requestId": "1", "errorText": "net::ERR_NAME_NOT_RESOLVED" }),
            1,
        );
        let e = &log.by_id["1"];
        assert!(e.failed());
        assert_eq!(e.error.as_deref(), Some("net::ERR_NAME_NOT_RESOLVED"));
    }

    #[test]
    fn events_without_a_request_id_are_ignored_rather_than_panicking() {
        // Network emits plenty of these (Network.dataReceived on some builds,
        // policy updates, ...). A recorder that unwrapped here would kill the
        // reader task and silently stop recording mid-run.
        let mut log = Log::default();
        absorb(&mut log, "Network.requestServedFromCache", &json!({}), 0);
        absorb(
            &mut log,
            "Network.responseReceived",
            &json!({ "nothing": true }),
            0,
        );
        assert!(log.order.is_empty());
    }

    #[test]
    fn a_response_for_a_request_we_never_saw_is_dropped_quietly() {
        // Enabling Network mid-flight means responses to requests that left
        // before we were listening.
        let mut log = Log::default();
        absorb(
            &mut log,
            "Network.responseReceived",
            &received("99", 200),
            0,
        );
        assert!(log.by_id.is_empty());
        assert!(log.order.is_empty());
    }

    #[test]
    fn the_log_stops_growing_at_the_cap_and_says_how_much_it_dropped() {
        let mut log = Log::default();
        for i in 0..(MAX_ENTRIES + 10) {
            absorb(
                &mut log,
                "Network.requestWillBeSent",
                &sent(&i.to_string(), "https://a/x", "GET"),
                0,
            );
        }
        assert_eq!(log.order.len(), MAX_ENTRIES);
        assert_eq!(log.dropped, 10);
    }
}
