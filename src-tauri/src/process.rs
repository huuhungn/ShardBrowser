// Tracker for launched ShardX child processes; keyed by profile_id.

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;
use tokio::process::Child;

#[cfg(windows)]
fn taskkill_profile_process(pid: u32, force_tree: bool) {
    use std::os::windows::process::CommandExt;

    let pid_arg = pid.to_string();
    let mut args = vec!["/PID", pid_arg.as_str()];
    if force_tree {
        args.extend(["/T", "/F"]);
    }
    // 0x08000000 = CREATE_NO_WINDOW — suppress the console flash.
    let _ = std::process::Command::new("taskkill")
        .args(args)
        .creation_flags(0x08000000)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

pub struct Tracker {
    inner: Mutex<HashMap<String, ChildEntry>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillOutcome {
    Stopped { pid: u32 },
    NotRunning,
    PidMismatch { expected_pid: u32, actual_pid: u32 },
    LaunchInstanceMismatch { pid: u32 },
}

pub struct TrackedProcess {
    pub pid: u32,
    pub launch_instance_token: String,
}

struct ChildEntry {
    pid: u32,
    launch_instance_token: String,
    killer: tokio::sync::mpsc::Sender<()>,
    /// Set once DevToolsActivePort is read; None for UI launches.
    cdp: Option<CdpInfo>,
    /// Safe, ephemeral human-verification handoff reported by MCP.
    verification: Option<VerificationStatus>,
    /// Process start; serialised as elapsed ms in RunningProfile.
    started_at: Instant,
}

/// CDP endpoint for an API-launched profile.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CdpInfo {
    pub port: u16,
    pub http_url: String,
    /// ws://127.0.0.1:<port>/devtools/browser/<id> for Puppeteer/Playwright.
    pub web_socket_debugger_url: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct VerificationStatus {
    pub required: bool,
    pub provider: String,
    pub kind: String,
    pub updated_at: u64,
}

impl Tracker {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Take a spawned child + monitor it; entry removed on exit/kill.
    pub fn track(
        &'static self,
        profile_id: String,
        mut child: Child,
        temporary: bool,
    ) -> TrackedProcess {
        let pid = child.id().unwrap_or(0);
        let launch_instance_token = uuid::Uuid::new_v4().to_string();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);

        {
            let mut g = self.inner.lock().unwrap();
            g.insert(
                profile_id.clone(),
                ChildEntry {
                    pid,
                    launch_instance_token: launch_instance_token.clone(),
                    killer: tx,
                    cdp: None,
                    verification: None,
                    started_at: Instant::now(),
                },
            );
        }

        // Graceful shutdown (SIGTERM / taskkill WM_CLOSE) → 5s → hard kill.
        // Graceful path flushes session state so next launch skips the restore prompt.
        let started_at = Instant::now();
        let tracked_launch_instance_token = launch_instance_token.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = child.wait() => {}
                _ = rx.recv() => {
                    #[cfg(unix)]
                    {
                        if let Some(p) = child.id() {
                            // SAFETY: libc::kill on a child pid we own.
                            unsafe { libc::kill(p as libc::pid_t, libc::SIGTERM); }
                        }
                    }
                    #[cfg(windows)]
                    {
                        if let Some(p) = child.id() {
                            // taskkill /PID without /F posts WM_CLOSE for clean shutdown.
                            taskkill_profile_process(p, false);
                        }
                    }
                    let graceful = tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        child.wait(),
                    ).await;
                    if graceful.is_err() {
                        #[cfg(windows)]
                        {
                            if let Some(p) = child.id() {
                                taskkill_profile_process(p, true);
                            }
                        }
                        let _ = child.kill().await;
                        let _ = child.wait().await;
                    }
                }
            }
            // Bump the persisted total runtime; non-temporary only (temp
            // profiles get deleted next line so their counter is moot).
            // Every step below is best-effort: a panic here used to abort the
            // task before the tracker entry was dropped, leaving a phantom
            // "running" row whose Stop button could never clear it.
            if !temporary {
                let elapsed_ms = started_at.elapsed().as_millis() as u64;
                let bump = std::panic::catch_unwind(|| {
                    crate::profile::add_runtime(&profile_id, elapsed_ms)
                });
                match bump {
                    Ok(Err(e)) => eprintln!("[launcher] add_runtime({profile_id}) failed: {e}"),
                    Err(_) => eprintln!("[launcher] add_runtime({profile_id}) panicked"),
                    Ok(Ok(())) => {}
                }
            }
            // Tear down temporary profile (config + udd) on close.
            if temporary {
                let cleanup = std::panic::catch_unwind(|| crate::profile::delete(&profile_id));
                match cleanup {
                    Ok(Ok(())) => {
                        eprintln!("[launcher] temporary profile {profile_id} deleted on close")
                    }
                    Ok(Err(e)) => {
                        eprintln!("[launcher] temporary profile {profile_id} cleanup failed: {e}")
                    }
                    Err(_) => {
                        eprintln!("[launcher] temporary profile {profile_id} cleanup panicked")
                    }
                }
            }
            // Keep the entry visible until every final profile write/delete is
            // complete so a user mutation cannot race shutdown cleanup.
            Self::shared().remove_if_instance(&profile_id, &tracked_launch_instance_token);
        });

        TrackedProcess {
            pid,
            launch_instance_token,
        }
    }

    /// Attach CDP only to the exact launch instance that requested it.
    pub fn set_cdp_if_instance(
        &self,
        profile_id: &str,
        launch_instance_token: &str,
        cdp: CdpInfo,
    ) -> bool {
        if let Ok(mut g) = self.inner.lock() {
            if let Some(e) = g.get_mut(profile_id) {
                if e.launch_instance_token == launch_instance_token {
                    e.cdp = Some(cdp);
                    return true;
                }
            }
        }
        false
    }

    /// CDP endpoint when the profile was launched with remote debugging.
    pub fn cdp(&self, profile_id: &str) -> Option<CdpInfo> {
        self.inner.lock().ok()?.get(profile_id)?.cdp.clone()
    }

    pub fn is_running(&self, profile_id: &str) -> bool {
        self.inner
            .lock()
            .map(|entries| entries.contains_key(profile_id))
            .unwrap_or(true)
    }

    #[cfg(test)]
    pub fn set_running_for_test(&self, profile_id: &str, running: bool) {
        let mut entries = self.inner.lock().expect("tracker lock");
        if running {
            let (killer, _receiver) = tokio::sync::mpsc::channel(1);
            entries.insert(
                profile_id.to_string(),
                ChildEntry {
                    pid: 0,
                    launch_instance_token: "test-instance".into(),
                    killer,
                    cdp: None,
                    verification: None,
                    started_at: Instant::now(),
                },
            );
        } else {
            entries.remove(profile_id);
        }
    }

    #[cfg(test)]
    fn set_running_instance_for_test(
        &self,
        profile_id: &str,
        pid: u32,
        launch_instance_token: &str,
    ) -> tokio::sync::mpsc::Receiver<()> {
        let mut entries = self.inner.lock().expect("tracker lock");
        let (killer, receiver) = tokio::sync::mpsc::channel(1);
        entries.insert(
            profile_id.to_string(),
            ChildEntry {
                pid,
                launch_instance_token: launch_instance_token.into(),
                killer,
                cdp: None,
                verification: None,
                started_at: Instant::now(),
            },
        );
        receiver
    }

    /// Update the in-memory verification handoff for a running profile.
    pub fn set_verification(
        &self,
        profile_id: &str,
        verification: Option<VerificationStatus>,
    ) -> bool {
        let Ok(mut g) = self.inner.lock() else {
            return false;
        };
        let Some(entry) = g.get_mut(profile_id) else {
            return false;
        };
        entry.verification = verification;
        true
    }

    pub fn running(&self) -> Vec<RunningProfile> {
        let g = self.inner.lock().unwrap();
        g.iter()
            .map(|(id, e)| RunningProfile {
                profile_id: id.clone(),
                pid: e.pid,
                cdp: e.cdp.clone(),
                verification: e.verification.clone(),
                uptime_ms: e.started_at.elapsed().as_millis() as u64,
            })
            .collect()
    }

    pub async fn kill_if_instance(
        &self,
        profile_id: &str,
        expected_pid: u32,
        expected_launch_instance_token: &str,
    ) -> Result<KillOutcome> {
        let target = {
            let g = self.inner.lock().unwrap();
            let Some(entry) = g.get(profile_id) else {
                return Ok(KillOutcome::NotRunning);
            };
            if entry.pid != expected_pid {
                return Ok(KillOutcome::PidMismatch {
                    expected_pid,
                    actual_pid: entry.pid,
                });
            }
            if entry.launch_instance_token != expected_launch_instance_token {
                return Ok(KillOutcome::LaunchInstanceMismatch { pid: entry.pid });
            }
            (entry.killer.clone(), entry.pid)
        };
        let (killer, pid) = target;
        let _ = killer.send(()).await;
        Ok(KillOutcome::Stopped { pid })
    }

    fn remove_if_instance(&self, profile_id: &str, launch_instance_token: &str) -> bool {
        let Ok(mut entries) = self.inner.lock() else {
            return false;
        };
        let matches = entries
            .get(profile_id)
            .map(|entry| entry.launch_instance_token == launch_instance_token)
            .unwrap_or(false);
        if matches {
            entries.remove(profile_id);
        }
        matches
    }

    pub async fn kill(&self, profile_id: &str) -> Result<bool> {
        let killer = {
            let entries = self.inner.lock().unwrap();
            let Some(entry) = entries.get(profile_id) else {
                return Ok(false);
            };
            entry.killer.clone()
        };
        // The tracking task owns the Child handle and performs graceful stop
        // plus its hard-kill fallback without reacquiring the process by PID.
        let _ = killer.send(()).await;
        Ok(true)
    }

    pub fn shared() -> &'static Tracker {
        static INSTANCE: std::sync::OnceLock<Tracker> = std::sync::OnceLock::new();
        INSTANCE.get_or_init(Tracker::new)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RunningProfile {
    pub profile_id: String,
    pub pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cdp: Option<CdpInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<VerificationStatus>,
    /// Milliseconds since the engine was spawned; frontend formats as
    /// "1h 23m" / "12m 30s" / "45s".
    pub uptime_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::{KillOutcome, Tracker};
    use std::time::Duration;
    use tokio::process::Command;

    async fn assert_immediate_exit_is_finalized(temporary: bool) {
        let profile_id = format!(
            "process-immediate-exit-{}-{}",
            if temporary { "temporary" } else { "persistent" },
            uuid::Uuid::new_v4()
        );
        let mut command = if cfg!(windows) {
            let mut command = Command::new("cmd.exe");
            command.args(["/C", "exit", "0"]);
            command
        } else {
            let mut command = Command::new("sh");
            command.args(["-c", "exit 0"]);
            command
        };
        let child = command.spawn().expect("spawn immediate exit child");
        Tracker::shared().track(profile_id.clone(), child, temporary);

        for _ in 0..100 {
            if !Tracker::shared().is_running(&profile_id) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("immediate exit child remained tracked: {profile_id}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn persistent_immediate_exit_is_finalized() {
        assert_immediate_exit_is_finalized(false).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn temporary_immediate_exit_is_finalized() {
        assert_immediate_exit_is_finalized(true).await;
    }

    /// The tracker entry outlives the child only until finalization runs. That
    /// bookkeeping writes to the profile on disk, and a profile that cannot be
    /// written (missing, unreadable, corrupt JSON) must not strand the entry:
    /// a stranded entry shows the user a Running row with a Stop button that
    /// can never clear, because the child it refers to is already gone.
    #[tokio::test(flavor = "current_thread")]
    async fn exit_is_finalized_even_when_profile_bookkeeping_fails() {
        // No profile of this id exists on disk, so add_runtime's load fails.
        let profile_id = format!("process-missing-profile-{}", uuid::Uuid::new_v4());
        let mut command = if cfg!(windows) {
            let mut command = Command::new("cmd.exe");
            command.args(["/C", "exit", "0"]);
            command
        } else {
            let mut command = Command::new("sh");
            command.args(["-c", "exit 0"]);
            command
        };
        let child = command.spawn().expect("spawn immediate exit child");
        Tracker::shared().track(profile_id.clone(), child, false);

        for _ in 0..100 {
            if !Tracker::shared().is_running(&profile_id) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("failed bookkeeping stranded a phantom running entry: {profile_id}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn launch_instance_guard_never_stops_a_same_pid_replacement() {
        let tracker = Tracker::new();
        let mut replacement_killer = tracker.set_running_instance_for_test(
            "profile-instance-guard",
            111,
            "replacement-instance",
        );

        let outcome = tracker
            .kill_if_instance("profile-instance-guard", 111, "owned-instance")
            .await
            .expect("instance mismatch should be a normal guarded outcome");

        assert_eq!(outcome, KillOutcome::LaunchInstanceMismatch { pid: 111 });
        assert!(matches!(
            replacement_killer.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn launch_instance_guard_stops_only_the_exact_owned_instance() {
        let tracker = Tracker::new();
        let mut owned_killer =
            tracker.set_running_instance_for_test("profile-instance-owned", 111, "owned-instance");

        let outcome = tracker
            .kill_if_instance("profile-instance-owned", 111, "owned-instance")
            .await
            .expect("owned launch instance should be stoppable");

        assert_eq!(outcome, KillOutcome::Stopped { pid: 111 });
        assert_eq!(owned_killer.recv().await, Some(()));
    }

    #[test]
    fn stale_finalizer_never_removes_a_replacement_instance() {
        let tracker = Tracker::new();
        let _receiver =
            tracker.set_running_instance_for_test("profile-instance-finalizer", 111, "instance-2");

        assert!(!tracker.remove_if_instance("profile-instance-finalizer", "instance-1"));
        assert!(tracker.is_running("profile-instance-finalizer"));
        assert!(tracker.remove_if_instance("profile-instance-finalizer", "instance-2"));
        assert!(!tracker.is_running("profile-instance-finalizer"));
    }

    #[test]
    fn stale_cdp_completion_never_updates_a_replacement_instance() {
        let tracker = Tracker::new();
        let _receiver =
            tracker.set_running_instance_for_test("profile-instance-cdp", 111, "instance-2");
        let stale_cdp = super::CdpInfo {
            port: 9222,
            http_url: "http://127.0.0.1:9222".into(),
            web_socket_debugger_url: "ws://127.0.0.1:9222/devtools/browser/stale".into(),
        };

        assert!(!tracker.set_cdp_if_instance("profile-instance-cdp", "instance-1", stale_cdp));
        assert!(tracker.cdp("profile-instance-cdp").is_none());
    }
}
