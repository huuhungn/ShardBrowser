//! Loopback broker for window sync: one TCP connection per browser, one JSON
//! line per input event, copied to the group's other members. The payload is
//! never parsed here — the launcher brokers only because a listener is cheap
//! on this side.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

/// One connected browser.
struct Member {
    id: u64,
    /// The profile this window runs; the panel names and addresses members by it.
    profile: String,
    /// Held out without leaving: neither sends nor receives while excluded.
    excluded: bool,
    tx: mpsc::UnboundedSender<String>,
}

/// Screen area a layout was applied to: x, y, width, height.
type Area = (i32, i32, i32, i32);

#[derive(Default)]
struct State {
    /// group name -> members
    groups: HashMap<String, Vec<Member>>,
    /// group name -> suspended
    paused: HashMap<String, bool>,
    /// group name -> id of the member that published most recently
    driving: HashMap<String, u64>,
    /// group name -> layout last asked for and the area it used. Remembered so a
    /// window that comes up after the layout was chosen is placed too.
    arranged: HashMap<String, (Layout, Area)>,
    /// profile -> what the page helper last found there.
    helper: HashMap<String, serde_json::Value>,
    /// profile -> the field set the panel was dismissed for. Closing the panel
    /// answers about THIS page; a different field set is a different question.
    helper_dismissed: HashMap<String, String>,
    next_id: u64,
}

pub struct Bus {
    pub port: u16,
    pub token: String,
    state: Arc<Mutex<State>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberStatus {
    pub profile: String,
    pub excluded: bool,
    /// True for the window that published most recently — the one driving.
    pub driving: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupStatus {
    pub group: String,
    pub members: Vec<MemberStatus>,
    pub paused: bool,
}

#[derive(Deserialize)]
struct Hello {
    hello: String,
    #[serde(default)]
    token: String,
    #[serde(default)]
    profile: String,
}

/// How to lay the group's windows out on screen.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Layout {
    /// Side by side in one row. Best for two or three.
    Row,
    /// As square a grid as the count allows.
    Grid,
    /// Overlapping, offset down-right; every title bar stays clickable.
    Cascade,
}

impl Bus {
    /// Binds an ephemeral loopback port and accepts. Loopback only — this
    /// carries the operator's keystrokes.
    pub async fn start(token: String) -> Result<Arc<Bus>> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .context("bind sync bus")?;
        let port = listener.local_addr()?.port();
        let bus = Arc::new(Bus {
            port,
            token,
            state: Arc::new(Mutex::new(State::default())),
        });
        let accept_bus = bus.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let b = accept_bus.clone();
                        tokio::spawn(async move { b.serve(stream).await });
                    }
                    Err(e) => {
                        eprintln!("[bus] accept failed: {e}");
                        return;
                    }
                }
            }
        });
        Ok(bus)
    }

    async fn serve(self: Arc<Self>, stream: TcpStream) {
        // Nagle would hold a keystroke back waiting for company.
        let _ = stream.set_nodelay(true);
        let (read_half, mut write_half) = stream.into_split();
        let mut lines = BufReader::new(read_half).lines();

        // Greeting first: loopback is not authorisation, any local process can
        // connect, so the token is what proves this launcher started it.
        let Ok(Some(first)) = lines.next_line().await else {
            return;
        };
        let Ok(hello) = serde_json::from_str::<Hello>(&first) else {
            return;
        };
        if hello.token != self.token {
            eprintln!("[bus] rejected a connection with a bad token");
            return;
        }
        let group = hello.hello;

        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        let id = {
            let mut st = self.state.lock().unwrap();
            st.next_id += 1;
            let id = st.next_id;
            st.groups.entry(group.clone()).or_default().push(Member {
                id,
                profile: hello.profile.clone(),
                excluded: false,
                tx,
            });
            // A member joining a suspended group must not start acting.
            if *st.paused.get(&group).unwrap_or(&false) {
                let members = st.groups.get(&group).unwrap();
                if let Some(m) = members.iter().find(|m| m.id == id) {
                    let _ = m.tx.send("{\"suspended\":true}\n".to_string());
                }
            }
            id
        };

        // Re-place every member, not just the newcomer: slots depend on the count.
        let replay = self.state.lock().unwrap().arranged.get(&group).copied();
        if let Some((layout, area)) = replay {
            self.arrange(&group, layout, area);
        }

        let writer = tokio::spawn(async move {
            while let Some(line) = rx.recv().await {
                if write_half.write_all(line.as_bytes()).await.is_err() {
                    return;
                }
            }
        });

        while let Ok(Some(line)) = lines.next_line().await {
            if line.is_empty() {
                continue;
            }
            // A helper report is for the launcher, not for the group: it
            // describes one page in one window.
            if line.contains("\"helper\"") {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
                    if let Some(h) = v.get("helper") {
                        let mut st = self.state.lock().unwrap();
                        st.helper.insert(hello.profile.clone(), h.clone());
                    }
                    continue;
                }
            }
            self.fan_out(&group, id, &line);
        }

        // EOF: the browser closed or died. No heartbeats, no stale entries.
        self.drop_member(&group, id, &hello.profile);
        writer.abort();
    }

    /// Remove one member and, once a group empties, every trace of that group.
    ///
    /// `paused` and `arranged` are keyed by group name and outlive `groups`
    /// unless they are cleared here. A group that was suspended, then fully
    /// closed, would otherwise leave `paused` set: the next browser to join
    /// under the same name is suspended on arrival for a reason nobody can
    /// see, because the group it belonged to no longer exists.
    fn drop_member(&self, group: &str, id: u64, profile: &str) {
        let mut st = self.state.lock().unwrap();
        let emptied = match st.groups.get_mut(group) {
            Some(members) => {
                members.retain(|m| m.id != id);
                members.is_empty()
            }
            None => false,
        };
        if emptied {
            st.groups.remove(group);
            st.paused.remove(group);
            st.arranged.remove(group);
            st.driving.remove(group);
        }
        // The window is gone, so its offer goes with it.
        st.helper.remove(profile);
    }

    fn fan_out(&self, group: &str, from: u64, line: &str) {
        let mut st = self.state.lock().unwrap();
        if *st.paused.get(group).unwrap_or(&false) {
            return;
        }
        st.driving.insert(group.to_string(), from);
        let Some(members) = st.groups.get(group) else {
            return;
        };
        // An excluded window neither sends nor receives.
        if members.iter().any(|m| m.id == from && m.excluded) {
            return;
        }
        let framed = format!("{line}\n");
        for m in members {
            // Never back to the sender — that is the echo to avoid.
            if m.id != from && !m.excluded {
                let _ = m.tx.send(framed.clone());
            }
        }
    }

    /// Lays the group's windows out inside `area` (the usable screen). The
    /// launcher assigns slots; each window then moves itself — moving them from
    /// here would need an Accessibility grant on macOS.
    pub fn arrange(&self, group: &str, layout: Layout, area: (i32, i32, i32, i32)) {
        let mut st = self.state.lock().unwrap();
        st.arranged.insert(group.to_string(), (layout, area));
        let Some(members) = st.groups.get(group) else {
            return;
        };
        let n = members.len() as i32;
        if n == 0 {
            return;
        }
        let (ax, ay, aw, ah) = area;
        for (i, m) in members.iter().enumerate() {
            let i = i as i32;
            let (x, y, w, h) = match layout {
                Layout::Row => (ax + aw * i / n, ay, aw / n, ah),
                Layout::Grid => {
                    let cols = (n as f64).sqrt().ceil() as i32;
                    let rows = (n + cols - 1) / cols;
                    let (cx, cy) = (i % cols, i / cols);
                    (
                        ax + aw * cx / cols,
                        ay + ah * cy / rows,
                        aw / cols,
                        ah / rows,
                    )
                }
                Layout::Cascade => {
                    // A title bar of offset each; the last must still fit.
                    let step = 32.min(ah / (n + 1).max(1));
                    (ax + step * i, ay + step * i, aw * 3 / 4, ah * 3 / 4)
                }
            };
            let line = format!(
                "{{\"bounds\":{{\"x\":{x},\"y\":{y},\"w\":{w},\"h\":{h}}},\"activate\":true}}\n"
            );
            let _ = m.tx.send(line);
        }
    }

    /// Asks every window to close — a browser asked to close writes out its
    /// session and cookies; a killed process does not.
    pub fn stop(&self, group: &str) {
        let st = self.state.lock().unwrap();
        if let Some(members) = st.groups.get(group) {
            for m in members {
                let _ = m.tx.send("{\"close\":true}\n".to_string());
            }
        }
    }

    /// What the page helper last found in `profile`, if anything.
    pub fn helper_fields(&self, profile: &str) -> Option<serde_json::Value> {
        self.state.lock().unwrap().helper.get(profile).cloned()
    }

    /// The kinds on offer, comparable between reports. Kinds, not positions —
    /// a page that reflows on scroll is still the same offer.
    fn helper_key(fields: &serde_json::Value) -> String {
        let Some(list) = fields.get("fields").and_then(|f| f.as_array()) else {
            return String::new();
        };
        let mut kinds: Vec<&str> = list
            .iter()
            .filter_map(|f| f.get("kind").and_then(|k| k.as_str()))
            .collect();
        kinds.sort_unstable();
        kinds.join(",")
    }

    /// The operator closed the panel. Remember what it was offering.
    pub fn helper_dismiss(&self, profile: &str) {
        let mut st = self.state.lock().unwrap();
        let key = st
            .helper
            .get(profile)
            .map(Self::helper_key)
            .unwrap_or_default();
        st.helper_dismissed.insert(profile.to_string(), key);
    }

    /// Every profile with something fillable on screen. `triggers` narrows it to
    /// the kinds wanted (empty = all); filtered here so the setting is live.
    pub fn helper_profiles(&self, triggers: &[String]) -> Vec<String> {
        let st = self.state.lock().unwrap();
        st.helper
            .iter()
            .filter(|(profile, v)| {
                // Dismissed and still the same offer. A different step asks for
                // different kinds and so comes back on its own.
                if st.helper_dismissed.get(*profile) == Some(&Self::helper_key(v)) {
                    return false;
                }
                let Some(fields) = v.get("fields").and_then(|f| f.as_array()) else {
                    return false;
                };
                fields.iter().any(|f| {
                    let kind = f.get("kind").and_then(|k| k.as_str()).unwrap_or("");
                    triggers.is_empty() || triggers.iter().any(|t| t == kind)
                })
            })
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Tells every window in a group to fill: a command each, so each fills with
    /// its own person. Returns how many were told.
    pub fn fill_group(&self, group: &str) -> usize {
        let st = self.state.lock().unwrap();
        let Some(members) = st.groups.get(group) else {
            return 0;
        };
        let mut told = 0;
        for m in members {
            if !m.excluded && m.tx.send("{\"fill\":true}\n".to_string()).is_ok() {
                told += 1;
            }
        }
        told
    }

    /// Which group a profile belongs to, if any.
    pub fn group_of(&self, profile: &str) -> Option<String> {
        let st = self.state.lock().unwrap();
        for (group, members) in &st.groups {
            if members.iter().any(|m| m.profile == profile) {
                return Some(group.clone());
            }
        }
        None
    }

    /// Tells one profile's window to fill what its helper found.
    pub fn fill(&self, profile: &str) {
        let st = self.state.lock().unwrap();
        for members in st.groups.values() {
            for m in members {
                if m.profile == profile {
                    let _ = m.tx.send("{\"fill\":true}\n".to_string());
                }
            }
        }
    }

    pub fn set_excluded(&self, group: &str, profile: &str, excluded: bool) {
        let mut st = self.state.lock().unwrap();
        if let Some(members) = st.groups.get_mut(group) {
            for m in members.iter_mut() {
                if m.profile == profile {
                    m.excluded = excluded;
                    // Tell the window too, so it stops performing.
                    let _ = m.tx.send(format!("{{\"suspended\":{excluded}}}\n"));
                }
            }
        }
    }

    pub fn status(&self, group: &str) -> GroupStatus {
        let st = self.state.lock().unwrap();
        let driving = st.driving.get(group).copied().unwrap_or(0);
        GroupStatus {
            group: group.to_string(),
            members: st
                .groups
                .get(group)
                .map(|ms| {
                    ms.iter()
                        .map(|m| MemberStatus {
                            profile: m.profile.clone(),
                            excluded: m.excluded,
                            driving: m.id == driving,
                        })
                        .collect()
                })
                .unwrap_or_default(),
            paused: *st.paused.get(group).unwrap_or(&false),
        }
    }

    /// Suspends or resumes a whole group at once.
    pub fn set_paused(&self, group: &str, paused: bool) {
        let st = self.state.lock().unwrap();
        let mut st = st;
        st.paused.insert(group.to_string(), paused);
        if let Some(members) = st.groups.get(group) {
            let line = format!("{{\"suspended\":{paused}}}\n");
            for m in members {
                let _ = m.tx.send(line.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Bus, Layout, Member, State};
    use std::sync::{Arc, Mutex};
    use tokio::sync::mpsc;

    /// A bus with no listener: these tests exercise bookkeeping, not I/O.
    fn test_bus() -> Bus {
        Bus {
            port: 0,
            token: "test-token".to_string(),
            state: Arc::new(Mutex::new(State::default())),
        }
    }

    /// Adds a member the way `serve` does, returning its id.
    fn join(bus: &Bus, group: &str, profile: &str) -> u64 {
        let (tx, rx) = mpsc::unbounded_channel::<String>();
        // Keep the receiver alive for the test's duration; a dropped receiver
        // would make sends fail and mask what we are asserting.
        std::mem::forget(rx);
        let mut st = bus.state.lock().unwrap();
        st.next_id += 1;
        let id = st.next_id;
        st.groups
            .entry(group.to_string())
            .or_default()
            .push(Member {
                id,
                profile: profile.to_string(),
                excluded: false,
                tx,
            });
        id
    }

    /// Everything keyed by group name must go when the group empties. A
    /// surviving `paused` entry silently suspends the next browser to use the
    /// same group name, with no group on screen to explain why.
    #[test]
    fn emptying_a_group_clears_its_group_keyed_state() {
        let bus = test_bus();
        let id = join(&bus, "alpha", "profile-1");
        bus.set_paused("alpha", true);
        bus.arrange("alpha", Layout::Grid, (0, 0, 800, 600));

        {
            let st = bus.state.lock().unwrap();
            assert!(st.paused.contains_key("alpha"), "precondition: paused set");
            assert!(
                st.arranged.contains_key("alpha"),
                "precondition: arrangement recorded"
            );
        }

        bus.drop_member("alpha", id, "profile-1");

        let st = bus.state.lock().unwrap();
        assert!(!st.groups.contains_key("alpha"), "group should be gone");
        assert!(
            !st.paused.contains_key("alpha"),
            "paused outlived its group: the next joiner is suspended for no visible reason"
        );
        assert!(
            !st.arranged.contains_key("alpha"),
            "arrangement outlived its group"
        );
        assert!(
            !st.driving.contains_key("alpha"),
            "driving member outlived its group"
        );
        assert!(
            !st.helper.contains_key("profile-1"),
            "helper offer outlived its window"
        );
    }

    /// The cleanup must not fire while other members remain: a group loses one
    /// window at a time, and the survivors keep their suspension and layout.
    #[test]
    fn dropping_one_of_several_members_keeps_the_group() {
        let bus = test_bus();
        let first = join(&bus, "beta", "profile-1");
        join(&bus, "beta", "profile-2");
        bus.set_paused("beta", true);

        bus.drop_member("beta", first, "profile-1");

        let st = bus.state.lock().unwrap();
        assert_eq!(
            st.groups.get("beta").map(|m| m.len()),
            Some(1),
            "the surviving member should still be in the group"
        );
        assert_eq!(
            st.paused.get("beta"),
            Some(&true),
            "a group that still has members keeps its suspension"
        );
        assert!(
            !st.helper.contains_key("profile-1"),
            "the departing window's helper offer should still be dropped"
        );
    }

    /// `HashMap` lookups by group name are exact; a member id from one group
    /// must never remove a member from another.
    #[test]
    fn dropping_an_unknown_group_is_a_no_op() {
        let bus = test_bus();
        let id = join(&bus, "gamma", "profile-1");

        bus.drop_member("no-such-group", id, "profile-2");

        let st = bus.state.lock().unwrap();
        assert_eq!(
            st.groups.get("gamma").map(|m| m.len()),
            Some(1),
            "an unrelated group should be untouched"
        );
    }
}
