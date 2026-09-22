//! Running an automation project against a live profile.
//!
//! The minimum an operator actually needs: open a page, wait for something,
//! click and type, carry values between steps, and know honestly whether the
//! run succeeded.
//!
//! Deliberately smaller than upstream's runner. Every block here is one this
//! engine can really perform — nothing depends on the CDP Motion domain, which
//! build 152.0.7977.65 does not implement (see `tests/motion_protocol_it.rs`).
//! A block that cannot be honestly executed is not offered at all, rather than
//! offered and quietly doing nothing.
//!
//! The walk follows each block's own `on_done` / `on_fail` branch rather than
//! falling through the list, because that is what the stored project means.

use crate::automation::{Block, Branch, Project};
use crate::cdp;
use crate::traffic;
use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// How long one step may take before it is called failed. Projects do not
/// carry a per-step timeout yet; when they do, this becomes its default.
const STEP_TIMEOUT: Duration = Duration::from_secs(30);

/// Pause between attempts when a block's branch says to retry.
const RETRY_DELAY: Duration = Duration::from_millis(500);

/// A run that branches can, in principle, loop forever. The budget bounds a
/// pass so a bad `Goto` ends as a reported failure instead of a hung launcher.
const MAX_STEPS_PER_PASS: usize = 10_000;

/// What happened to one attempt at one block.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum StepOutcome {
    Ok,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
pub struct StepReport {
    pub block_id: String,
    pub kind: String,
    /// The operator's own label, so a report reads like their script.
    pub label: String,
    pub outcome: StepOutcome,
    /// 1 on the first try, 2 after one retry, and so on.
    pub attempt: u32,
    pub ms: u64,
    /// Present when the step failed, in the operator's words, not CDP's.
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RunReport {
    pub project_id: String,
    pub profile_id: String,
    /// True only if no step failed and no step stopped the run.
    pub ok: bool,
    /// How many passes actually ran.
    pub passes: u32,
    pub steps: Vec<StepReport>,
    pub ms: u64,
    /// Variables as they stood at the end — what an operator reading the
    /// report needs to understand what the run actually saw.
    pub variables: HashMap<String, String>,
    /// Set when the run ended for a reason other than finishing its passes.
    pub stopped_because: Option<String>,
    /// Requests recorded by `stopTraffic`, in the order they were made.
    ///
    /// Counting them into a variable tells an operator how many there were;
    /// only the entries themselves say which ones failed, which is the whole
    /// reason to record traffic.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requests: Vec<crate::traffic::Entry>,
}

/// Values carried between steps. Text params interpolate `{{name}}`.
#[derive(Debug, Default, Clone)]
pub struct Variables(HashMap<String, String>);

impl Variables {
    pub fn new(seed: HashMap<String, String>) -> Self {
        Self(seed)
    }

    pub fn set(&mut self, name: &str, value: impl Into<String>) {
        self.0.insert(name.to_string(), value.into());
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }

    pub fn into_inner(self) -> HashMap<String, String> {
        self.0
    }

    /// Replace every `{{name}}` with its value. An unknown name is left
    /// exactly as written: a step that types a literal `{{token}}` into a
    /// field is a visible bug, whereas typing an empty string silently
    /// submits a form with a missing value.
    pub fn expand(&self, text: &str) -> String {
        let chars: Vec<char> = text.chars().collect();
        let mut out = String::with_capacity(text.len());
        let mut i = 0;
        while i < chars.len() {
            if chars[i] == '{' && i + 1 < chars.len() && chars[i + 1] == '{' {
                if let Some(close) = find_close(&chars, i + 2) {
                    let name: String = chars[i + 2..close].iter().collect();
                    match self.0.get(name.trim()) {
                        Some(v) => out.push_str(v),
                        None => {
                            out.push_str("{{");
                            out.push_str(&name);
                            out.push_str("}}");
                        }
                    }
                    i = close + 2;
                    continue;
                }
            }
            out.push(chars[i]);
            i += 1;
        }
        out
    }
}

fn find_close(chars: &[char], from: usize) -> Option<usize> {
    let mut i = from;
    while i + 1 < chars.len() {
        if chars[i] == '}' && chars[i + 1] == '}' {
            return Some(i);
        }
        // A newline inside a placeholder means it was never a placeholder.
        if chars[i] == '\n' {
            return None;
        }
        i += 1;
    }
    None
}

/// The block kinds this build can really perform.
pub fn supported_kinds() -> &'static [&'static str] {
    &[
        "navigate",
        "wait",
        "waitForSelector",
        "click",
        "type",
        "setVariable",
        "readText",
        "assert",
        "evaluate",
        "recordTraffic",
        "stopTraffic",
        "assertRequest",
        "httpOpen",
        "httpRequest",
        "httpClose",
        "readFile",
        "writeFile",
        "appendFile",
        "fileExists",
        "deleteFile",
        "dbExecute",
        "dbQuery",
    ]
}

/// Check a project before running it, so an operator learns about an unknown
/// block while editing rather than half way through a run.
pub fn unsupported_blocks(project: &Project) -> Vec<(String, String)> {
    project
        .blocks
        .iter()
        .filter(|b| b.enabled && !supported_kinds().contains(&b.kind.as_str()))
        .map(|b| (b.id.clone(), b.kind.clone()))
        .collect()
}

/// Blocks that drive the page, and so need a browser attached.
///
/// Everything else -- HTTP calls, files, variables -- runs without one, so a
/// project that never touches a page should not have to start a browser to
/// do its work.
fn needs_browser(kind: &str) -> bool {
    matches!(
        kind,
        "navigate"
            | "waitForSelector"
            | "click"
            | "type"
            | "readText"
            | "assert"
            | "evaluate"
            | "recordTraffic"
            | "stopTraffic"
            | "assertRequest"
    )
}

/// Run a whole project against a profile.
///
/// A project with page blocks needs the profile running and attached
/// (`cdp::attach`) first: starting browsers is the launcher's job, and a
/// runner that started them too would race the launcher's own bookkeeping.
/// A project made only of HTTP, file and variable blocks needs no browser and
/// is allowed to run without one.
pub async fn run(
    project: &Project,
    profile_id: &str,
    seed: HashMap<String, String>,
) -> Result<RunReport> {
    let wants_browser = project
        .blocks
        .iter()
        .any(|b| b.enabled && needs_browser(&b.kind));

    if wants_browser && !cdp::is_attached(profile_id) {
        return Err(anyhow!(
            "the profile is not attached — start it before running a project"
        ));
    }
    let unknown = unsupported_blocks(project);
    if let Some((id, kind)) = unknown.first() {
        // Refuse rather than skip: a run that quietly omits a step reports a
        // success the operator did not get.
        return Err(anyhow!(
            "this build cannot run the {kind:?} block ({id}); remove or disable it first"
        ));
    }

    let started = Instant::now();
    let mut vars = Variables::new(seed);
    let mut state = RunState::default();
    let mut steps: Vec<StepReport> = Vec::new();
    let mut stopped_because: Option<String> = None;
    let mut failed_any = false;
    let mut passes = 0u32;

    // loops == 0 means "until the hours are up"; anything else is a count.
    let deadline = if project.run.loops == 0 && project.run.hours > 0.0 {
        Some(Instant::now() + Duration::from_secs_f64(project.run.hours * 3600.0))
    } else {
        None
    };
    let max_passes = if project.run.loops == 0 {
        u32::MAX
    } else {
        project.run.loops
    };
    if project.run.loops == 0 && deadline.is_none() {
        return Err(anyhow!(
            "this project loops forever: set a pass count or a time limit"
        ));
    }

    'passes: while passes < max_passes {
        if let Some(end) = deadline {
            if Instant::now() >= end {
                break;
            }
        }
        passes += 1;

        let mut cursor = start_index(project);
        let mut budget = MAX_STEPS_PER_PASS;

        while let Some(index) = cursor {
            let Some(block) = project.blocks.get(index) else {
                break;
            };
            if budget == 0 {
                stopped_because = Some(format!(
                    "the run took more than {MAX_STEPS_PER_PASS} steps in one pass — check the branches for a loop"
                ));
                failed_any = true;
                break 'passes;
            }
            budget -= 1;

            if !block.enabled {
                cursor = Some(index + 1);
                continue;
            }
            if let Some(end) = deadline {
                if Instant::now() >= end {
                    stopped_because = Some("the time limit ran out".into());
                    break 'passes;
                }
            }

            // Retry lives on the branch, so the attempt loop is here.
            let mut attempt = 0u32;
            let branch = loop {
                attempt += 1;
                let step_started = Instant::now();
                let result = perform(block, profile_id, &mut vars, &mut state).await;
                let ms = step_started.elapsed().as_millis() as u64;

                match result {
                    Ok(()) => {
                        steps.push(StepReport {
                            block_id: block.id.clone(),
                            kind: block.kind.clone(),
                            label: block.label.clone(),
                            outcome: StepOutcome::Ok,
                            attempt,
                            ms,
                            error: None,
                        });
                        break block.on_done.clone();
                    }
                    Err(e) => {
                        steps.push(StepReport {
                            block_id: block.id.clone(),
                            kind: block.kind.clone(),
                            label: block.label.clone(),
                            outcome: StepOutcome::Failed,
                            attempt,
                            ms,
                            error: Some(format!("{e:#}")),
                        });
                        match &block.on_fail {
                            // Retry(n) means n more tries after the first.
                            Branch::Retry(n) if attempt <= *n => {
                                tokio::time::sleep(RETRY_DELAY).await;
                                continue;
                            }
                            // Out of retries: carry on rather than strand the
                            // run on a branch that no longer applies.
                            Branch::Retry(_) => {
                                failed_any = true;
                                break Branch::Next;
                            }
                            other => {
                                failed_any = true;
                                break other.clone();
                            }
                        }
                    }
                }
            };

            match branch {
                Branch::Next => cursor = Some(index + 1),
                Branch::Stop => {
                    stopped_because = Some(format!("step {} stopped the run", block.id));
                    break 'passes;
                }
                Branch::EndPass => break,
                Branch::Goto(ref id) => {
                    // A goto to a deleted step behaves as Next, so removing a
                    // block cannot strand a run.
                    cursor = match project.blocks.iter().position(|b| &b.id == id) {
                        Some(target) => Some(target),
                        None => Some(index + 1),
                    };
                }
                // Retry on success has no meaning; treat it as falling through
                // rather than repeating a step that already worked.
                Branch::Retry(_) => cursor = Some(index + 1),
            }
        }
    }

    // Cookies are an identity, and a session left open would hand the next
    // run whatever this one logged into. Closing is safe to call blind.
    if state.http_open {
        crate::http_session::close(profile_id);
    }

    Ok(RunReport {
        project_id: project.id.clone(),
        profile_id: profile_id.to_string(),
        ok: !failed_any && stopped_because.is_none(),
        passes,
        steps,
        ms: started.elapsed().as_millis() as u64,
        variables: vars.into_inner(),
        stopped_because,
        requests: state.recorded,
    })
}

/// Where a pass begins: the project's chosen start block, or the first one.
fn start_index(project: &Project) -> Option<usize> {
    if project.blocks.is_empty() {
        return None;
    }
    if project.run.start.is_empty() {
        return Some(0);
    }
    // A start id pointing at a deleted block falls back to the top rather
    // than running nothing at all and calling that a success.
    project
        .blocks
        .iter()
        .position(|b| b.id == project.run.start)
        .or(Some(0))
}

/// A string parameter, expanded, or an error naming what is missing.
/// Read a block's SQL parameters.
///
/// Placeholders are expanded inside string parameters, so a project can bind
/// a value an earlier block found, but the result is still *bound* rather
/// than pasted into the statement.
fn db_params(block: &Block, vars: &Variables) -> Result<Vec<serde_json::Value>> {
    let Some(raw) = block.params.get("params") else {
        return Ok(Vec::new());
    };

    // Written by hand in the editor, so it arrives as a JSON string there and
    // as an array over the API.
    let list = match raw {
        serde_json::Value::Array(items) => items.clone(),
        serde_json::Value::String(text) => {
            if text.trim().is_empty() {
                return Ok(Vec::new());
            }

            // Parse the array before substituting anything. A scraped value
            // holding a quote would otherwise close its own string and could
            // add or drop an element, binding values to the wrong columns.
            // Only if the text is not an array on its own is it expanded
            // first, which is how a whole array held in one variable works.
            match serde_json::from_str::<Vec<serde_json::Value>>(text) {
                Ok(list) => list,
                Err(_) => {
                    let expanded = vars.expand(text);
                    if expanded.trim().is_empty() {
                        return Ok(Vec::new());
                    }
                    serde_json::from_str::<Vec<serde_json::Value>>(&expanded)
                        .context("\"params\" must be a JSON array, e.g. [\"alice\", 1]")?
                }
            }
        }
        other => return Err(anyhow!("\"params\" must be a JSON array, not {other}")),
    };

    Ok(list
        .into_iter()
        .map(|value| match value {
            serde_json::Value::String(s) => serde_json::Value::String(vars.expand(&s)),
            other => other,
        })
        .collect())
}

fn param_text(block: &Block, name: &str, vars: &Variables) -> Result<String> {
    let raw = block
        .params
        .get(name)
        .and_then(|v| v.as_str())
        .with_context(|| format!("the {:?} block needs a {name}", block.kind))?;
    Ok(vars.expand(raw))
}

/// What a run carries between blocks besides its variables.
///
/// The recorder has to outlive the block that started it -- that is the whole
/// point of a separate stop block -- so it lives here rather than in
/// `perform`.
#[derive(Default)]
struct RunState {
    traffic: Option<traffic::Recorder>,
    /// Requests handed over by `stopTraffic`, kept for the run report.
    recorded: Vec<traffic::Entry>,
    /// Whether an `httpOpen` block opened a session this run.
    ///
    /// Tracked so a run that ends without reaching its `httpClose` -- because
    /// a step failed, or the project simply forgot one -- does not leave a
    /// logged-in session behind for the next run to inherit.
    http_open: bool,
}

async fn perform(
    block: &Block,
    profile_id: &str,
    vars: &mut Variables,
    state: &mut RunState,
) -> Result<()> {
    match block.kind.as_str() {
        "navigate" => {
            let url = param_text(block, "url", vars)?;
            // Subscribe before navigating, or a fast page can load before we
            // are listening and the step waits out its whole timeout.
            let watch = cdp::watch(profile_id).context("the profile went away")?;
            cdp::page_call(profile_id, "Page.navigate", json!({ "url": url }))
                .await
                .with_context(|| format!("navigate to {url}"))?;
            if !watch.until("Page.loadEventFired", STEP_TIMEOUT).await {
                return Err(anyhow!("{url} did not finish loading in time"));
            }
            Ok(())
        }

        "wait" => {
            let ms = block
                .params
                .get("ms")
                .and_then(|v| v.as_u64())
                .context("the \"wait\" block needs an ms")?;
            tokio::time::sleep(Duration::from_millis(ms)).await;
            Ok(())
        }

        "waitForSelector" => {
            let selector = param_text(block, "selector", vars)?;
            wait_for_selector(profile_id, &selector).await
        }

        "click" => {
            let selector = param_text(block, "selector", vars)?;
            wait_for_selector(profile_id, &selector).await?;
            // Click through the page's own event path rather than synthesising
            // coordinates: an element under a sticky header is still the
            // element the operator picked.
            let v = evaluate(
                profile_id,
                &format!(
                    "(() => {{ const el = document.querySelector({}); \
                     if (!el) return 'missing'; \
                     el.scrollIntoView({{block:'center'}}); el.click(); return 'ok'; }})()",
                    js_string(&selector)
                ),
            )
            .await?;
            if v.as_str() == Some("ok") {
                Ok(())
            } else {
                Err(anyhow!("nothing matched {selector} when the click ran"))
            }
        }

        "type" => {
            let selector = param_text(block, "selector", vars)?;
            let text = param_text(block, "text", vars)?;
            wait_for_selector(profile_id, &selector).await?;
            // Set the value through the prototype setter, then fire the events
            // a framework listens for: assigning `.value` alone leaves React
            // and Vue believing the field is still empty.
            let v = evaluate(
                profile_id,
                &format!(
                    "(() => {{ const el = document.querySelector({}); \
                     if (!el) return 'missing'; el.focus(); \
                     const d = Object.getOwnPropertyDescriptor(el.constructor.prototype,'value'); \
                     if (d && d.set) d.set.call(el, {}); else el.value = {}; \
                     el.dispatchEvent(new Event('input', {{bubbles:true}})); \
                     el.dispatchEvent(new Event('change', {{bubbles:true}})); \
                     return 'ok'; }})()",
                    js_string(&selector),
                    js_string(&text),
                    js_string(&text)
                ),
            )
            .await?;
            if v.as_str() == Some("ok") {
                Ok(())
            } else {
                Err(anyhow!(
                    "nothing matched {selector} when the text was typed"
                ))
            }
        }

        "setVariable" => {
            let name = block
                .params
                .get("name")
                .and_then(|v| v.as_str())
                .context("the \"setVariable\" block needs a name")?
                .to_string();
            let value = param_text(block, "value", vars).unwrap_or_default();
            vars.set(&name, value);
            Ok(())
        }

        "readText" => {
            let selector = param_text(block, "selector", vars)?;
            let into = block
                .params
                .get("into")
                .and_then(|v| v.as_str())
                .context("the \"readText\" block needs an into")?
                .to_string();
            wait_for_selector(profile_id, &selector).await?;
            let v = evaluate(profile_id, &read_text_expr(&selector)).await?;
            match v.as_str() {
                Some(text) => {
                    vars.set(&into, text.trim());
                    Ok(())
                }
                None => Err(anyhow!("nothing matched {selector} to read")),
            }
        }

        "assert" => {
            let selector = param_text(block, "selector", vars)?;
            let expected = param_text(block, "expected", vars)?;
            wait_for_selector(profile_id, &selector).await?;
            let v = evaluate(profile_id, &read_text_expr(&selector)).await?;
            let seen = v.as_str().unwrap_or_default();
            if seen.contains(&expected) {
                Ok(())
            } else {
                // Quote both sides: "expected X, saw Y" is the whole reason
                // the operator opens the report.
                Err(anyhow!(
                    "expected {selector} to contain {expected:?}, saw {:?}",
                    seen.trim()
                ))
            }
        }

        // Traffic recording. Split into start and stop blocks on purpose: what
        // an operator wants to assert on is usually the requests one action
        // provoked, not every request the profile made all run.
        "recordTraffic" => {
            if state.traffic.is_some() {
                // Silently restarting would throw away what was recorded so
                // far, and the operator would be asserting against a window
                // they did not mean.
                return Err(anyhow!(
                    "traffic is already being recorded; stop it before starting again"
                ));
            }
            state.traffic = Some(traffic::Recorder::start(profile_id).await?);
            Ok(())
        }

        "stopTraffic" => {
            let recorder = state
                .traffic
                .take()
                .context("nothing is being recorded — add a \"recordTraffic\" block first")?;
            let dropped = recorder.dropped();
            let entries = recorder.stop().await;
            if let Some(name) = block.params.get("into").and_then(|v| v.as_str()) {
                vars.set(name, entries.len().to_string());
            }
            state.recorded.extend(entries.iter().cloned());
            if dropped > 0 {
                // Report rather than fail: the requests that were recorded are
                // still true, and a run that failed here would be failing for
                // something the page did, not something the project got wrong.
                vars.set("traffic_dropped", dropped.to_string());
            }
            Ok(())
        }

        "assertRequest" => {
            let recorder = state
                .traffic
                .as_ref()
                .context("nothing is being recorded — add a \"recordTraffic\" block first")?;
            let url_part = param_text(block, "urlContains", vars)?;
            let entries = recorder.entries();
            let matched: Vec<_> = entries
                .iter()
                .filter(|e| e.url.contains(&url_part))
                .collect();

            if matched.is_empty() {
                return Err(anyhow!(
                    "no request matching {url_part:?} was made ({} recorded so far)",
                    entries.len()
                ));
            }

            // Default to demanding a request that worked: "the page called the
            // login endpoint" is nearly always meant as "and it did not 500".
            let require_ok = block
                .params
                .get("mustSucceed")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            if require_ok && matched.iter().all(|e| e.failed()) {
                let worst = matched
                    .iter()
                    .find_map(|e| e.error.clone())
                    .or_else(|| {
                        matched
                            .iter()
                            .find_map(|e| e.status.map(|s| format!("HTTP {s}")))
                    })
                    .unwrap_or_else(|| "it never came back".to_string());
                return Err(anyhow!(
                    "every request matching {url_part:?} failed — {worst}"
                ));
            }
            if let Some(name) = block.params.get("into").and_then(|v| v.as_str()) {
                vars.set(name, matched.len().to_string());
            }
            Ok(())
        }

        "httpOpen" => {
            crate::http_session::open(profile_id)?;
            state.http_open = true;
            Ok(())
        }

        "httpRequest" => {
            let url = param_text(block, "url", vars)?;
            let method = block
                .params
                .get("method")
                .and_then(|v| v.as_str())
                .unwrap_or("GET");

            // Headers and body are the places credentials appear, so both go
            // through variable expansion and neither is logged here.
            let mut headers = std::collections::HashMap::new();
            if let Some(map) = block.params.get("headers").and_then(|v| v.as_object()) {
                for (k, v) in map {
                    if let Some(s) = v.as_str() {
                        headers.insert(k.clone(), vars.expand(s));
                    }
                }
            }
            let body = block
                .params
                .get("body")
                .and_then(|v| v.as_str())
                .map(|s| vars.expand(s));

            let reply =
                crate::http_session::request(profile_id, method, &url, &headers, body.as_deref())
                    .await?;

            if let Some(name) = block.params.get("into").and_then(|v| v.as_str()) {
                vars.set(name, reply.body.clone());
            }
            if let Some(name) = block.params.get("statusInto").and_then(|v| v.as_str()) {
                vars.set(name, reply.status.to_string());
            }

            // A status check is opt-in: polling an endpoint until it stops
            // returning 404 is a normal thing for a project to do.
            let expect_ok = block
                .params
                .get("mustSucceed")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if expect_ok && !(200..300).contains(&reply.status) {
                return Err(anyhow!(
                    "{method} {url} answered HTTP {}, not a success",
                    reply.status
                ));
            }
            Ok(())
        }

        "httpClose" => {
            if !crate::http_session::close(profile_id) {
                return Err(anyhow!(
                    "no HTTP session is open for this profile; add an \"httpOpen\" block first"
                ));
            }
            state.http_open = false;
            Ok(())
        }

        "readFile" => {
            let path = param_text(block, "path", vars)?;
            let contents = crate::files::read(&path)?;
            let name = block
                .params
                .get("into")
                .and_then(|v| v.as_str())
                .context("the \"readFile\" block needs an into")?;
            vars.set(name, contents);
            Ok(())
        }

        "writeFile" => {
            let path = param_text(block, "path", vars)?;
            let contents = param_text(block, "contents", vars)?;
            crate::files::write(&path, &contents)
        }

        "appendFile" => {
            let path = param_text(block, "path", vars)?;
            let contents = param_text(block, "contents", vars)?;
            crate::files::append(&path, &contents)
        }

        "fileExists" => {
            let path = param_text(block, "path", vars)?;
            let found = crate::files::exists(&path)?;
            if let Some(name) = block.params.get("into").and_then(|v| v.as_str()) {
                vars.set(name, found.to_string());
            }
            // Opt-in so this can be used both to branch and to assert.
            let required = block
                .params
                .get("mustExist")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if required && !found {
                return Err(anyhow!("{path} is not in the automation workspace"));
            }
            Ok(())
        }

        "deleteFile" => {
            let path = param_text(block, "path", vars)?;
            crate::files::remove(&path)
        }

        "dbExecute" => {
            let database = param_text(block, "database", vars)?;
            let sql = param_text(block, "sql", vars)?;
            let params = db_params(block, vars)?;
            let changed = crate::db::execute(&database, &sql, &params)?;
            if let Some(name) = block.params.get("into").and_then(|v| v.as_str()) {
                vars.set(name, changed.to_string());
            }
            Ok(())
        }

        "dbQuery" => {
            let database = param_text(block, "database", vars)?;
            let sql = param_text(block, "sql", vars)?;
            let params = db_params(block, vars)?;
            let rows = crate::db::query(&database, &sql, &params)?;

            // Two shapes, because projects want two different things: the
            // whole result to write out or pass on, and a single field to
            // branch on without parsing JSON in an evaluate block.
            if let Some(name) = block.params.get("into").and_then(|v| v.as_str()) {
                vars.set(name, serde_json::to_string(&rows)?);
            }
            if let Some(name) = block.params.get("countInto").and_then(|v| v.as_str()) {
                vars.set(name, rows.len().to_string());
            }
            if let Some(name) = block.params.get("firstInto").and_then(|v| v.as_str()) {
                let column = block
                    .params
                    .get("firstColumn")
                    .and_then(|v| v.as_str())
                    .context("\"firstInto\" also needs a \"firstColumn\"")?;
                let value = rows
                    .first()
                    .and_then(|row| row.get(column))
                    .map(|v| match v {
                        serde_json::Value::String(s) => s.clone(),
                        other => other.to_string(),
                    })
                    .unwrap_or_default();
                vars.set(name, value);
            }

            let least = block
                .params
                .get("minRows")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as usize;
            if rows.len() < least {
                return Err(anyhow!(
                    "the query returned {} rows, fewer than the {least} required",
                    rows.len()
                ));
            }
            Ok(())
        }

        "evaluate" => {
            let script = param_text(block, "script", vars)?;
            let v = evaluate(profile_id, &script).await?;
            if let Some(name) = block.params.get("into").and_then(|x| x.as_str()) {
                vars.set(name, value_to_text(&v));
            }
            Ok(())
        }

        other => Err(anyhow!("this build cannot run a {other:?} block")),
    }
}

fn read_text_expr(selector: &str) -> String {
    format!(
        "(() => {{ const el = document.querySelector({}); \
         return el ? (el.innerText ?? el.textContent ?? '') : null; }})()",
        js_string(selector)
    )
}

/// Poll for a selector until it matches or the step's time runs out.
async fn wait_for_selector(profile_id: &str, selector: &str) -> Result<()> {
    let deadline = Instant::now() + STEP_TIMEOUT;
    let expr = format!("document.querySelector({}) !== null", js_string(selector));
    loop {
        if let Ok(v) = evaluate(profile_id, &expr).await {
            if v.as_bool() == Some(true) {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            return Err(anyhow!(
                "waited {}s but nothing matched {selector}",
                STEP_TIMEOUT.as_secs()
            ));
        }
        tokio::time::sleep(Duration::from_millis(120)).await;
    }
}

/// Evaluate an expression in the page and return its value.
async fn evaluate(profile_id: &str, expression: &str) -> Result<Value> {
    let reply = cdp::page_call(
        profile_id,
        "Runtime.evaluate",
        json!({
            "expression": expression,
            "returnByValue": true,
            "awaitPromise": true,
        }),
    )
    .await?;

    // A thrown exception comes back as a successful CDP reply carrying
    // exceptionDetails. Treating that as success is how a broken step passes.
    if let Some(details) = reply.get("exceptionDetails") {
        let text = details
            .get("exception")
            .and_then(|e| e.get("description"))
            .and_then(|d| d.as_str())
            .or_else(|| details.get("text").and_then(|t| t.as_str()))
            .unwrap_or("the page threw while running this step");
        return Err(anyhow!(text.to_string()));
    }

    Ok(reply
        .get("result")
        .and_then(|r| r.get("value"))
        .cloned()
        .unwrap_or(Value::Null))
}

/// A JS string literal that cannot break out of its quotes, whatever the
/// operator typed into the selector box.
fn js_string(s: &str) -> String {
    Value::String(s.to_string()).to_string()
}

fn value_to_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Run a saved project by id against a running profile, attaching if needed.
///
/// Shared by the HTTP API and the desktop UI so both enforce the same rules:
/// the profile must already be running (a run never launches a browser as a
/// side effect), and it must expose a debugging port the launcher itself
/// recorded, so a run cannot reach a browser the launcher does not own.
pub async fn run_saved(
    project_id: &str,
    profile_id: &str,
    seed: HashMap<String, String>,
) -> Result<RunReport> {
    let project = crate::automation::get(project_id)?;
    run_guarded(&project, profile_id, seed).await
}

/// Run a project that was handed to us rather than saved.
///
/// Callers that build a project on the fly -- the MCP traffic tool asking
/// "what did this page request?" -- go through here so they are held to the
/// same rules as a saved run instead of reaching the runner unguarded.
pub async fn run_unsaved(
    project: &Project,
    profile_id: &str,
    seed: HashMap<String, String>,
) -> Result<RunReport> {
    run_guarded(project, profile_id, seed).await
}

/// The guards every run passes, whoever asked for it.
async fn run_guarded(
    project: &Project,
    profile_id: &str,
    seed: HashMap<String, String>,
) -> Result<RunReport> {
    // A project with no page blocks needs no browser, so requiring one would
    // refuse runs that are pure HTTP and file work.
    let wants_browser = project
        .blocks
        .iter()
        .any(|b| b.enabled && needs_browser(&b.kind));

    if wants_browser {
        if !crate::is_profile_running(profile_id) {
            return Err(anyhow!("profile {profile_id} is not running"));
        }

        if !cdp::is_attached(profile_id) {
            let endpoint = crate::process::Tracker::shared()
                .cdp(profile_id)
                .ok_or_else(|| {
                    anyhow!(
                        "profile {profile_id} is running without a debugging port; \
                         restart it to automate it"
                    )
                })?;
            cdp::attach(profile_id.to_string(), endpoint.web_socket_debugger_url).await?;
        }
    }

    run(project, profile_id, seed).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::automation::{Block, Branch, Project, RunSettings};

    fn vars(pairs: &[(&str, &str)]) -> Variables {
        Variables::new(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
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

    /// Run one block with no recorder started, the way a project that forgot
    /// its `recordTraffic` block would.
    async fn perform_alone(b: &Block) -> Result<()> {
        let mut v = vars(&[]);
        let mut state = RunState::default();
        perform(b, "no-such-profile", &mut v, &mut state).await
    }

    #[tokio::test]
    async fn asserting_on_traffic_nobody_recorded_says_so() {
        // The failure an operator actually hits: they added assertRequest and
        // not the record block that has to come before it. Reporting "no
        // request matched" there would send them looking at the page.
        let b = block("b1", "assertRequest", json!({ "urlContains": "/login" }));
        let e = perform_alone(&b).await.unwrap_err();
        let msg = format!("{e:#}");
        assert!(
            msg.contains("recordTraffic"),
            "the error should name the block that is missing, got: {msg}"
        );
    }

    #[tokio::test]
    async fn stopping_a_recording_that_never_started_says_so() {
        let b = block("b1", "stopTraffic", json!({}));
        let e = perform_alone(&b).await.unwrap_err();
        assert!(format!("{e:#}").contains("recordTraffic"));
    }

    #[tokio::test]
    async fn recording_traffic_on_a_dead_profile_fails_rather_than_hangs() {
        // Same contract as every other block: a profile that went away is a
        // failed step, not a run that never finishes.
        let b = block("b1", "recordTraffic", json!({}));
        assert!(perform_alone(&b).await.is_err());
    }

    #[test]
    fn the_traffic_blocks_are_ones_this_build_will_run() {
        // A block the editor offers but `run` refuses is a project that saves
        // and then cannot start at all.
        let p = project(vec![
            block("b1", "recordTraffic", json!({})),
            block("b2", "assertRequest", json!({ "urlContains": "/x" })),
            block("b3", "stopTraffic", json!({})),
        ]);
        assert!(unsupported_blocks(&p).is_empty());
    }

    fn project(blocks: Vec<Block>) -> Project {
        Project {
            id: "p1".into(),
            name: "Test".into(),
            notes: String::new(),
            blocks,
            run: RunSettings::default(),
            created_at: 0,
            updated_at: 0,
        }
    }

    #[test]
    fn a_placeholder_becomes_its_value() {
        let v = vars(&[("user", "ann")]);
        assert_eq!(v.expand("hello {{user}}"), "hello ann");
        assert_eq!(v.expand("{{user}}{{user}}"), "annann");
        assert_eq!(v.expand("{{ user }}"), "ann");
    }

    #[test]
    fn an_unknown_placeholder_is_left_visible_rather_than_blanked() {
        // A literal {{token}} in a field is an obvious bug; an empty string
        // silently submits a form with a missing value.
        let v = vars(&[("user", "ann")]);
        assert_eq!(v.expand("{{missing}}"), "{{missing}}");
        assert_eq!(v.expand("{{user}}/{{missing}}"), "ann/{{missing}}");
    }

    #[test]
    fn text_with_no_placeholders_survives_untouched() {
        let v = vars(&[]);
        assert_eq!(v.expand("plain"), "plain");
        assert_eq!(v.expand("a { b } c"), "a { b } c");
        assert_eq!(v.expand("{{unclosed"), "{{unclosed");
        assert_eq!(v.expand("{{user\n}}"), "{{user\n}}");
    }

    #[test]
    fn a_selector_cannot_break_out_of_its_javascript_string() {
        // An operator pasting a selector containing a quote must not end up
        // executing whatever follows it.
        let hostile = r#"a"]); alert(1); //"#;
        let literal = js_string(hostile);
        assert!(literal.starts_with('"') && literal.ends_with('"'));

        // Every quote inside the literal must be escaped, or the rest of the
        // selector becomes code.
        let inner: Vec<char> = literal[1..literal.len() - 1].chars().collect();
        for (i, c) in inner.iter().enumerate() {
            if *c == '"' {
                let escaped = i > 0 && inner[i - 1] == '\\';
                assert!(escaped, "an unescaped quote survived: {literal}");
            }
        }

        let parsed: String = serde_json::from_str(&literal).expect("a valid JS/JSON string");
        assert_eq!(parsed, hostile, "escaping must not change the selector");
    }

    #[test]
    fn an_unknown_block_is_named_before_the_run_starts() {
        let p = project(vec![
            block("a", "navigate", json!({ "url": "https://example.com" })),
            block("b", "wasm", json!({})),
        ]);
        let unknown = unsupported_blocks(&p);
        assert_eq!(unknown, vec![("b".to_string(), "wasm".to_string())]);
    }

    #[test]
    fn a_disabled_unknown_block_does_not_block_the_run() {
        let mut p = project(vec![block("b", "wasm", json!({}))]);
        p.blocks[0].enabled = false;
        assert!(unsupported_blocks(&p).is_empty());
    }

    #[test]
    fn a_pass_starts_where_the_project_says() {
        let mut p = project(vec![
            block("a", "wait", json!({ "ms": 1 })),
            block("b", "wait", json!({ "ms": 1 })),
        ]);
        assert_eq!(start_index(&p), Some(0));
        p.run.start = "b".into();
        assert_eq!(start_index(&p), Some(1));
    }

    #[test]
    fn a_start_block_that_was_deleted_falls_back_to_the_top() {
        // Running nothing at all and calling it a success is worse than
        // running the script from its first step.
        let mut p = project(vec![block("a", "wait", json!({ "ms": 1 }))]);
        p.run.start = "gone".into();
        assert_eq!(start_index(&p), Some(0));
    }

    #[test]
    fn an_empty_project_has_nowhere_to_start() {
        assert_eq!(start_index(&project(vec![])), None);
    }

    /// The flip side of the rule above: work that never touches a page should
    /// not have to start a browser to get done.
    #[tokio::test]
    async fn a_project_of_only_offline_blocks_needs_no_browser() {
        let p = project(vec![block("a", "wait", json!({ "ms": 1 }))]);
        let report = run(&p, "no-such-profile", HashMap::new())
            .await
            .expect("a project with no page blocks should run without one");
        assert!(report.ok, "the run should have succeeded: {report:?}");
    }

    #[tokio::test]
    async fn a_run_against_an_unattached_profile_is_refused_not_reported_as_success() {
        // A page block, because those are the ones that need a browser: a
        // project of pure waits has nothing to attach to and is allowed to run.
        let p = project(vec![block(
            "a",
            "navigate",
            json!({ "url": "https://example.com" }),
        )]);
        let err = run(&p, "no-such-profile", HashMap::new())
            .await
            .expect_err("a run with no browser must fail");
        assert!(
            err.to_string().contains("not attached"),
            "the error should say why: {err}"
        );
    }

    #[test]
    fn a_missing_parameter_is_reported_by_name() {
        let b = block("a", "navigate", json!({}));
        let err = param_text(&b, "url", &vars(&[])).expect_err("a navigate with no url must fail");
        assert!(err.to_string().contains("url"), "got: {err}");
    }

    #[test]
    fn a_parameter_carries_variables_into_the_step() {
        let b = block("a", "navigate", json!({ "url": "https://{{host}}/in" }));
        let got = param_text(&b, "url", &vars(&[("host", "example.com")])).unwrap();
        assert_eq!(got, "https://example.com/in");
    }

    #[test]
    fn a_value_read_from_the_page_keeps_its_text_shape() {
        assert_eq!(value_to_text(&json!("plain")), "plain");
        assert_eq!(value_to_text(&json!(null)), "");
        assert_eq!(value_to_text(&json!(42)), "42");
        assert_eq!(value_to_text(&json!(true)), "true");
    }
}
