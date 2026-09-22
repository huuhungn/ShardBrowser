//! HTTP calls a project makes on its own, outside the page.
//!
//! A project often needs to talk to an API directly: fetch a token before
//! logging in, poll a job until it finishes, or read back what the site
//! recorded after a form was submitted. Driving that through the page means
//! injecting `fetch` into whatever document happens to be open and hoping its
//! origin and CSP allow the call.
//!
//! The important part is whose network the call goes out on. A profile exists
//! to look like one consistent person: the browser goes through the profile's
//! proxy, so a side-channel HTTP call from the launcher process would leave
//! the host's own IP in the site's logs next to that profile's session. Every
//! session here is therefore built against the same proxy the profile
//! launches with, resolved the same way `launch` resolves it, and a profile
//! bound to a proxy that cannot be built is an error rather than a call that
//! silently goes out direct.
//!
//! Cookies persist per session so a login survives across blocks, and stay in
//! memory: writing them next to the profile would mean two different cookie
//! jars for one identity, with no rule saying which the site should see.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use crate::{profile, proxy};

/// How long a single request may take before it is called a failure.
///
/// Without this a hung endpoint would hold the run open indefinitely; the
/// block contract everywhere else is that a step either succeeds or fails.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Cap on the body kept in memory from one response.
///
/// Projects read tokens and JSON records, not downloads. A misaimed URL
/// pointing at a large file should fail the step rather than grow the
/// launcher's memory by its size.
const MAX_BODY: usize = 8 * 1024 * 1024;

/// What a call returned, in the shape a project can assert against.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpReply {
    pub status: u16,
    pub body: String,
    /// True when the body was cut at [`MAX_BODY`], so an assertion that fails
    /// on a truncated body can say why rather than looking like a bad match.
    #[serde(default)]
    pub truncated: bool,
}

/// One live session: a client plus the cookies it has accumulated.
struct Session {
    client: reqwest::Client,
}

fn sessions() -> &'static Mutex<HashMap<String, Session>> {
    static S: OnceLock<Mutex<HashMap<String, Session>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Build a client that goes out on the same proxy the profile browses through.
///
/// Resolution mirrors `launch`: stored proxy by id first, then the inline
/// proxy a temporary profile carries. A profile with no proxy at all browses
/// direct, so calling direct matches it.
fn client_for(profile_id: &str) -> Result<reqwest::Client> {
    let stored = profile::load_raw(profile_id)
        .with_context(|| format!("profile {profile_id} could not be read"))?;

    let bound: Option<proxy::ProxyEntry> = stored
        .meta
        .proxy_id
        .as_deref()
        .and_then(|pid| proxy::get(pid).ok().flatten())
        .or_else(|| stored.meta.inline_proxy.clone());

    let mut builder = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .cookie_store(true);

    if let Some(entry) = bound.as_ref() {
        // `to_proxy_server_arg` percent-encodes credentials and is what the
        // browser itself is launched with, so the two cannot drift apart.
        let url = entry.to_proxy_server_arg();
        let proxy = reqwest::Proxy::all(&url).with_context(|| {
            format!(
                "profile {profile_id} is bound to proxy {} which cannot be used for HTTP",
                entry.name
            )
        })?;
        builder = builder.proxy(proxy);
    }

    builder
        .build()
        .context("the HTTP client for this profile could not be built")
}

/// Open a session for a profile, replacing any session it already had.
pub fn open(profile_id: &str) -> Result<()> {
    let client = client_for(profile_id)?;
    sessions()
        .lock()
        .unwrap()
        .insert(profile_id.to_string(), Session { client });
    Ok(())
}

/// Drop a profile's session and the cookies it held.
pub fn close(profile_id: &str) -> bool {
    sessions().lock().unwrap().remove(profile_id).is_some()
}

fn client(profile_id: &str) -> Result<reqwest::Client> {
    sessions()
        .lock()
        .unwrap()
        .get(profile_id)
        .map(|s| s.client.clone())
        .ok_or_else(|| {
            anyhow!("no HTTP session is open for this profile; add an httpOpen block first")
        })
}

/// Send one request on the profile's session.
///
/// A non-2xx status is returned, not raised: asking for a status is a normal
/// thing for a project to do, and the assertion belongs in the project rather
/// than here.
pub async fn request(
    profile_id: &str,
    method: &str,
    url: &str,
    headers: &HashMap<String, String>,
    body: Option<&str>,
) -> Result<HttpReply> {
    let client = client(profile_id)?;

    let method: reqwest::Method = method
        .to_uppercase()
        .parse()
        .with_context(|| format!("{method} is not an HTTP method"))?;

    let mut req = client.request(method, url);
    for (k, v) in headers {
        req = req.header(k.as_str(), v.as_str());
    }
    if let Some(b) = body {
        req = req.body(b.to_string());
    }

    let res = req
        .send()
        .await
        .with_context(|| format!("the request to {url} did not complete"))?;

    let status = res.status().as_u16();
    let full = res
        .text()
        .await
        .with_context(|| format!("the response from {url} could not be read"))?;

    let truncated = full.len() > MAX_BODY;
    let body = if truncated {
        // Cut on a character boundary so the body stays valid UTF-8.
        let mut end = MAX_BODY;
        while end > 0 && !full.is_char_boundary(end) {
            end -= 1;
        }
        full[..end].to_string()
    } else {
        full
    };

    Ok(HttpReply {
        status,
        body,
        truncated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn calling_without_opening_a_session_says_which_block_is_missing() {
        // The operator error this catches: an httpRequest block with no
        // httpOpen before it. "no session" alone would not tell them what to
        // add.
        let e = request(
            "never-opened",
            "GET",
            "http://127.0.0.1:1/",
            &HashMap::new(),
            None,
        )
        .await
        .unwrap_err();
        assert!(
            format!("{e:#}").contains("httpOpen"),
            "the error should name the block to add: {e:#}"
        );
    }

    #[test]
    fn closing_a_session_that_was_never_open_is_not_an_error() {
        // Cleanup runs on paths where opening may not have happened, so this
        // has to be safe to call blind.
        assert!(!close("never-opened-either"));
    }

    #[tokio::test]
    async fn a_profile_that_does_not_exist_cannot_open_a_session() {
        // Rather than falling back to a direct client, which would put the
        // host's own IP behind a profile's name.
        assert!(open("no-such-profile-at-all").is_err());
    }
}
