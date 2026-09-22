//! A minimal CDP client: one live session per running profile.
//!
//! Not a general library. It speaks exactly what the runner needs — send a
//! command, await its reply, and let a caller wait for a named event.
//!
//! The launcher already learns a profile's websocket URL from its
//! `DevToolsActivePort` when it starts one (see `launch.rs`), so this file
//! never guesses a port or scans for one.
//!
//! One session per profile, held in a process-wide map, because two sessions
//! against one browser would each see half the replies.

use anyhow::{anyhow, Context, Result};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message;

type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Value, String>>>>>;

/// One event off the wire.
#[derive(Clone, Debug)]
pub struct CdpEvent {
    pub method: String,
    pub params: Value,
}

struct Session {
    out: mpsc::UnboundedSender<Message>,
    pending: Pending,
    next_id: AtomicU64,
    /// Target session id for the page, once attached. Commands that act on a
    /// page (navigate, evaluate, click) must carry it; browser-level ones
    /// must not.
    page_session: Mutex<Option<String>>,
    /// Every event, for callers waiting on one or recording them. Carries the
    /// params as well as the name: a recorder told only that
    /// `Network.responseReceived` fired would still have to go back and ask
    /// which request it was about, by which time the page may have moved on.
    events: broadcast::Sender<CdpEvent>,
}

impl Session {
    async fn call(&self, method: &str, params: Value, session: Option<String>) -> Result<Value> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .map_err(|_| anyhow!("cdp lock poisoned"))?
            .insert(id, tx);

        let mut msg = json!({ "id": id, "method": method, "params": params });
        if let Some(s) = session {
            msg["sessionId"] = json!(s);
        }
        self.out
            .send(Message::Text(msg.to_string()))
            .map_err(|_| anyhow!("cdp connection closed"))?;

        // A step that hangs forever is worse than one that fails: the run
        // cannot report, retry or stop. Every call is bounded.
        match tokio::time::timeout(std::time::Duration::from_secs(120), rx).await {
            Ok(Ok(Ok(v))) => Ok(v),
            Ok(Ok(Err(e))) => Err(anyhow!(e)),
            Ok(Err(_)) => Err(anyhow!("cdp connection closed")),
            Err(_) => Err(anyhow!("{method} timed out")),
        }
    }

    fn page(&self) -> Option<String> {
        self.page_session.lock().ok()?.clone()
    }
}

fn sessions() -> &'static Mutex<HashMap<String, Arc<Session>>> {
    static S: OnceLock<Mutex<HashMap<String, Arc<Session>>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

fn get(profile_id: &str) -> Option<Arc<Session>> {
    sessions().lock().ok()?.get(profile_id).cloned()
}

pub fn is_attached(profile_id: &str) -> bool {
    sessions()
        .lock()
        .map(|s| s.contains_key(profile_id))
        .unwrap_or(false)
}

/// Open a session against an already-running profile and attach to its first
/// page. `ws_url` is the browser-level URL the launcher read from
/// `DevToolsActivePort`.
pub async fn attach(profile_id: String, ws_url: String) -> Result<()> {
    attach_with(profile_id, ws_url, |_, _| {}).await
}

/// As `attach`, plus a callback for every event that arrives. The callback
/// runs on the reader task, so it must not block.
pub async fn attach_with<E>(profile_id: String, ws_url: String, on_event: E) -> Result<()>
where
    E: Fn(String, Value) + Send + Sync + 'static,
{
    if is_attached(&profile_id) {
        return Ok(());
    }

    let (stream, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .with_context(|| format!("connect {ws_url}"))?;
    let (mut sink, mut source) = stream.split();

    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Message>();
    let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
    let (events, _) = broadcast::channel::<CdpEvent>(512);

    let session = Arc::new(Session {
        out: out_tx.clone(),
        pending: pending.clone(),
        next_id: AtomicU64::new(1),
        page_session: Mutex::new(None),
        events,
    });

    // Writer.
    tokio::spawn(async move {
        while let Some(m) = out_rx.recv().await {
            if sink.send(m).await.is_err() {
                break;
            }
        }
    });

    // Reader: replies go to whoever is waiting, events are broadcast.
    {
        let pending = pending.clone();
        let session_for_reader = session.clone();
        let id_for_reader = profile_id.clone();
        tokio::spawn(async move {
            while let Some(Ok(msg)) = source.next().await {
                let text = match msg {
                    Message::Text(t) => t,
                    Message::Close(_) => break,
                    _ => continue,
                };
                let Ok(v) = serde_json::from_str::<Value>(&text) else {
                    continue;
                };

                if let Some(id) = v.get("id").and_then(|x| x.as_u64()) {
                    let slot = pending.lock().ok().and_then(|mut p| p.remove(&id));
                    if let Some(tx) = slot {
                        let reply = match v.get("error") {
                            Some(e) => Err(e
                                .get("message")
                                .and_then(|m| m.as_str())
                                .unwrap_or("cdp error")
                                .to_string()),
                            None => Ok(v.get("result").cloned().unwrap_or(Value::Null)),
                        };
                        let _ = tx.send(reply);
                    }
                    continue;
                }

                let Some(method) = v.get("method").and_then(|m| m.as_str()) else {
                    continue;
                };
                let params = v.get("params").cloned().unwrap_or(Value::Null);

                // A page that navigates itself, or a target that replaces the
                // one we attached to, must not leave the session pointing at a
                // page that no longer exists.
                if method == "Target.detachedFromTarget" {
                    if let Ok(mut slot) = session_for_reader.page_session.lock() {
                        let gone = params.get("sessionId").and_then(|s| s.as_str());
                        if slot.as_deref() == gone {
                            *slot = None;
                        }
                    }
                }

                let _ = session_for_reader.events.send(CdpEvent {
                    method: method.to_string(),
                    params: params.clone(),
                });
                on_event(method.to_string(), params);
            }

            // The browser went away: drop the session so a later call fails
            // fast with "not attached" rather than timing out after two
            // minutes against a socket nobody is reading.
            if let Ok(mut map) = sessions().lock() {
                map.remove(&id_for_reader);
            }
        });
    }

    // Find the page target and attach to it. A browser that has just started
    // answers Target.getTargets before its first tab exists, so a single ask
    // races the launch and reports "no page" on a browser that is about to
    // have one. Wait for the tab rather than blaming the caller.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let page_target = loop {
        let targets = session
            .call("Target.getTargets", json!({}), None)
            .await
            .context("list targets")?;
        let found = targets
            .get("targetInfos")
            .and_then(|t| t.as_array())
            .and_then(|list| {
                list.iter().find(|t| {
                    t.get("type").and_then(|x| x.as_str()) == Some("page")
                        // about:blank placeholders and devtools pages are not
                        // something a run can drive.
                        && t.get("url")
                            .and_then(|u| u.as_str())
                            .map(|u| !u.starts_with("devtools://"))
                            .unwrap_or(true)
                })
            })
            .and_then(|t| t.get("targetId").and_then(|x| x.as_str()))
            .map(str::to_string);

        if let Some(id) = found {
            break id;
        }
        if std::time::Instant::now() >= deadline {
            detach(&profile_id);
            return Err(anyhow!("the profile has no page to drive"));
        }
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    };

    let attached = session
        .call(
            "Target.attachToTarget",
            json!({ "targetId": page_target, "flatten": true }),
            None,
        )
        .await
        .context("attach to page")?;
    let page_session = attached
        .get("sessionId")
        .and_then(|s| s.as_str())
        .map(str::to_string)
        .context("no session id for the page")?;

    if let Ok(mut slot) = session.page_session.lock() {
        *slot = Some(page_session.clone());
    }

    // Page and Runtime carry the events the runner waits on.
    let _ = session
        .call("Page.enable", json!({}), Some(page_session.clone()))
        .await;
    let _ = session
        .call("Runtime.enable", json!({}), Some(page_session))
        .await;

    sessions()
        .lock()
        .map_err(|_| anyhow!("cdp lock poisoned"))?
        .insert(profile_id, session);
    Ok(())
}

/// Drop the session. Safe to call for a profile that was never attached.
pub fn detach(profile_id: &str) {
    if let Ok(mut map) = sessions().lock() {
        map.remove(profile_id);
    }
}

/// Send a command to the profile's page.
pub async fn page_call(profile_id: &str, method: &str, params: Value) -> Result<Value> {
    let session = get(profile_id).context("this profile is not attached")?;
    let page = session.page();
    session.call(method, params, page).await
}

/// Send a browser-level command (no page session).
pub async fn browser_call(profile_id: &str, method: &str, params: Value) -> Result<Value> {
    let session = get(profile_id).context("this profile is not attached")?;
    session.call(method, params, None).await
}

/// A subscription to the event stream, taken BEFORE the command that should
/// produce the event. Taking it afterwards is a race the run loses roughly
/// whenever the machine is busy.
pub struct EventWait {
    rx: broadcast::Receiver<CdpEvent>,
}

/// Subscribe to every event on a profile's session.
///
/// Callers that want one named event should use `watch`; this is for the ones
/// that record a stream of them and cannot know the names in advance.
pub fn subscribe(profile_id: &str) -> Option<broadcast::Receiver<CdpEvent>> {
    Some(get(profile_id)?.events.subscribe())
}

pub fn watch(profile_id: &str) -> Option<EventWait> {
    let session = get(profile_id)?;
    Some(EventWait {
        rx: session.events.subscribe(),
    })
}

impl EventWait {
    /// Wait for one named event. False on timeout, or if the connection closed
    /// first — either way the caller should treat the step as failed rather
    /// than assume the page is ready.
    pub async fn until(mut self, method: &str, timeout: std::time::Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                return false;
            }
            match tokio::time::timeout(left, self.rx.recv()).await {
                Ok(Ok(seen)) if seen.method == method => return true,
                Ok(Ok(_)) => continue,
                // Lagged: events were dropped while we were not reading. The
                // one we want may have been among them, so keep waiting
                // rather than report a failure we cannot prove.
                Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
                Ok(Err(broadcast::error::RecvError::Closed)) => return false,
                Err(_) => return false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_profile_that_was_never_attached_is_not_attached() {
        assert!(!is_attached("no-such-profile"));
    }

    #[tokio::test]
    async fn a_call_against_an_unattached_profile_fails_rather_than_hangs() {
        // The runner turns this into a failed step. If it hung instead, a run
        // against a profile that died would never finish or report.
        let err = page_call("no-such-profile", "Page.reload", json!({}))
            .await
            .expect_err("a call with no session must fail");
        assert!(
            err.to_string().contains("not attached"),
            "the error should say why: {err}"
        );
    }

    #[test]
    fn detaching_something_never_attached_is_harmless() {
        detach("no-such-profile");
        assert!(!is_attached("no-such-profile"));
    }

    #[test]
    fn there_is_no_event_stream_for_an_unattached_profile() {
        assert!(watch("no-such-profile").is_none());
    }
}
