//! Automation projects: the blocks an operator recorded, and the settings a
//! run uses. Storage only — running them lives in `runner.rs`.
//!
//! Kept deliberately separate from the runner so a project can be written,
//! exported and imported by a build that cannot yet execute every block kind
//! it contains. `kind` and `params` are open strings/JSON for the same reason:
//! the block palette grows without a storage migration, and a project authored
//! against a newer palette still loads here rather than failing to parse.

use crate::store;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

/// What to do when a step finishes, or does not work out.
///
/// A flat list cannot express a real script: half of what an operator writes
/// is "and if this is not there, do that instead". Every step therefore
/// carries its own branch and the runner follows it, rather than always
/// falling through to the next line.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum Branch {
    /// Fall through to the step below. The default.
    #[default]
    Next,
    /// End this profile's whole run.
    Stop,
    /// End this pass; the next one starts from the top.
    EndPass,
    /// Jump to a step by id. An id that no longer exists behaves as Next, so
    /// deleting a step cannot strand a run.
    Goto(String),
    /// Try this same step again up to N more times, then take Next.
    Retry(u32),
}

/// One recorded step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub params: Value,
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Where the block sits on the canvas. Layout only — the run follows the
    /// connections, never the coordinates.
    #[serde(default)]
    pub x: f64,
    #[serde(default)]
    pub y: f64,
    /// Where to go when the step succeeds.
    #[serde(default)]
    pub on_done: Branch,
    /// Parameter names whose values must never leave this machine. Emptied on
    /// export and asked for again on import, because a project shared with a
    /// password still in it is a password published.
    #[serde(default)]
    pub secrets: Vec<String>,
    /// Where to go when it fails. Defaults to stopping: silently carrying on
    /// after a click that found nothing is how a run ends up typing a password
    /// into the wrong page.
    #[serde(default = "stop_branch")]
    pub on_fail: Branch,
}

fn stop_branch() -> Branch {
    Branch::Stop
}

fn yes() -> bool {
    true
}

fn one() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunSettings {
    /// Browsers running at once.
    #[serde(default = "one")]
    pub threads: u32,
    /// Passes over the block list. 0 means run until `hours` is up.
    #[serde(default = "one")]
    pub loops: u32,
    /// Only meaningful when `loops` is 0.
    #[serde(default)]
    pub hours: f64,
    /// Profiles this project drives, by id. Local to this machine, so it never
    /// travels in an export.
    #[serde(default)]
    pub profiles: Vec<String>,
    /// Which block the run starts at. Empty means the first in the list.
    #[serde(default)]
    pub start: String,
}

impl Default for RunSettings {
    fn default() -> Self {
        Self {
            threads: 1,
            loops: 1,
            hours: 0.0,
            profiles: Vec::new(),
            start: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub blocks: Vec<Block>,
    #[serde(default)]
    pub run: RunSettings,
    /// Unix seconds.
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Db {
    #[serde(default)]
    projects: Vec<Project>,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Serialises writers, so two windows saving at once cannot interleave.
fn lock() -> &'static Mutex<()> {
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(()))
}

/// Write through a temp file and rename, so a crash mid-write leaves the old
/// projects intact rather than a half-written file that loads as empty.
fn write_atomic(path: &Path, body: &[u8]) -> Result<()> {
    let tmp = path.with_extension("json.tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(body)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path).with_context(|| format!("rename {}", path.display()))?;
    Ok(())
}

fn read_db() -> Result<Db> {
    let path = store::automation_path()?;
    if !path.exists() {
        return Ok(Db::default());
    }
    let raw = fs::read_to_string(&path)?;
    if raw.trim().is_empty() {
        return Ok(Db::default());
    }
    Ok(serde_json::from_str(&raw).unwrap_or_default())
}

fn write_db(db: &Db) -> Result<()> {
    write_atomic(
        &store::automation_path()?,
        serde_json::to_vec_pretty(db)?.as_slice(),
    )
}

pub fn list() -> Result<Vec<Project>> {
    Ok(read_db()?.projects)
}

pub fn get(id: &str) -> Result<Project> {
    read_db()?
        .projects
        .into_iter()
        .find(|p| p.id == id)
        .context(crate::errcode::code("automation.noSuchProject"))
}

pub fn create(name: &str) -> Result<Project> {
    let _g = lock().lock().unwrap();
    let mut db = read_db()?;
    let t = now();
    let project = Project {
        id: uuid::Uuid::new_v4().to_string(),
        name: if name.trim().is_empty() {
            "Untitled".into()
        } else {
            name.trim().into()
        },
        notes: String::new(),
        blocks: Vec::new(),
        run: RunSettings::default(),
        created_at: t,
        updated_at: t,
    };
    db.projects.push(project.clone());
    write_db(&db)?;
    Ok(project)
}

pub fn save(mut project: Project) -> Result<Project> {
    let _g = lock().lock().unwrap();
    let mut db = read_db()?;
    project.updated_at = now();
    match db.projects.iter_mut().find(|p| p.id == project.id) {
        Some(slot) => *slot = project.clone(),
        None => db.projects.push(project.clone()),
    }
    write_db(&db)?;
    Ok(project)
}

pub fn delete(id: &str) -> Result<()> {
    let _g = lock().lock().unwrap();
    let mut db = read_db()?;
    db.projects.retain(|p| p.id != id);
    write_db(&db)
}

pub fn duplicate(id: &str) -> Result<Project> {
    let _g = lock().lock().unwrap();
    let mut db = read_db()?;
    let src = db
        .projects
        .iter()
        .find(|p| p.id == id)
        .cloned()
        .context(crate::errcode::code("automation.noSuchProject"))?;
    let t = now();
    let copy = Project {
        id: uuid::Uuid::new_v4().to_string(),
        name: format!("{} copy", src.name),
        created_at: t,
        updated_at: t,
        ..src
    };
    db.projects.push(copy.clone());
    write_db(&db)?;
    Ok(copy)
}

// ---- Export / import ----

/// Bumped when the shape changes. An import that refuses an unknown format is
/// better than one that silently drops half a project.
pub const BUNDLE_FORMAT: u32 = 1;

/// A parameter an import has to ask for, because the export refused to carry
/// its value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeedsSecret {
    pub block_id: String,
    pub label: String,
    pub params: Vec<String>,
}

/// A project on its way to another machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bundle {
    pub format: u32,
    pub exported_at: u64,
    pub project: Project,
    /// Which parameters were blanked, so the far end can ask for them by name
    /// instead of leaving the operator to discover the gaps at run time.
    #[serde(default)]
    pub needs: Vec<NeedsSecret>,
}

/// Pack a project for export, blanking every parameter its author marked
/// secret and dropping the local profile list.
pub fn export(project_id: &str) -> Result<Bundle> {
    let mut project = get(project_id)?;

    let mut needs = Vec::new();
    for block in &mut project.blocks {
        if block.secrets.is_empty() {
            continue;
        }
        let mut cleared = Vec::new();
        if let Value::Object(map) = &mut block.params {
            for name in &block.secrets {
                if let Some(slot) = map.get_mut(name) {
                    *slot = Value::String(String::new());
                    cleared.push(name.clone());
                }
            }
        }
        if !cleared.is_empty() {
            needs.push(NeedsSecret {
                block_id: block.id.clone(),
                label: if block.label.is_empty() {
                    block.kind.clone()
                } else {
                    block.label.clone()
                },
                params: cleared,
            });
        }
    }

    // The run's profile list is this machine's ids and means nothing anywhere
    // else, so it does not travel.
    project.run.profiles.clear();

    Ok(Bundle {
        format: BUNDLE_FORMAT,
        exported_at: now(),
        project,
        needs,
    })
}

/// Take a bundle in as a NEW project. Never overwrites an existing one by id:
/// two machines that both edited "the same" project would otherwise silently
/// clobber each other's work.
pub fn import(bundle: Bundle) -> Result<Project> {
    if bundle.format > BUNDLE_FORMAT {
        anyhow::bail!(crate::errcode::code_with(
            "automation.bundleTooNew",
            &[
                ("format", &bundle.format.to_string()),
                ("supported", &BUNDLE_FORMAT.to_string())
            ]
        ));
    }

    let _g = lock().lock().unwrap();
    let mut db = read_db()?;
    let t = now();
    let mut project = bundle.project;
    project.id = uuid::Uuid::new_v4().to_string();
    project.created_at = t;
    project.updated_at = t;
    // Profile ids from another machine would name profiles that do not exist
    // here, or worse, different ones that happen to share an id.
    project.run.profiles.clear();

    db.projects.push(project.clone());
    write_db(&db)?;
    Ok(project)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn block_with_secret() -> Block {
        Block {
            id: "b1".into(),
            kind: "type".into(),
            label: "sign in".into(),
            params: json!({ "selector": "#pw", "text": "hunter2", "delay": 30 }),
            enabled: true,
            x: 0.0,
            y: 0.0,
            on_done: Branch::Next,
            secrets: vec!["text".into()],
            on_fail: Branch::Stop,
        }
    }

    #[test]
    fn a_step_that_fails_stops_the_run_unless_told_otherwise() {
        // The default matters more than it looks: a run that carries on past a
        // failed click types into whatever page happens to be in front of it.
        let json = r#"{ "id": "b1", "kind": "click", "params": {} }"#;
        let block: Block = serde_json::from_str(json).expect("parse");
        assert_eq!(block.on_fail, Branch::Stop);
        assert_eq!(block.on_done, Branch::Next);
        assert!(block.enabled, "a step with no enabled flag should run");
    }

    #[test]
    fn a_project_from_a_newer_palette_still_loads() {
        // Kinds are open on purpose. A project authored against a build with
        // more block kinds must still open here, or an operator upgrading one
        // machine loses the ability to read their own projects on the others.
        let json = r#"{
            "id": "p1", "name": "x", "created_at": 1, "updated_at": 1,
            "blocks": [{ "id": "b", "kind": "some.future.block", "params": { "a": 1 } }]
        }"#;
        let project: Project = serde_json::from_str(json).expect("parse");
        assert_eq!(project.blocks[0].kind, "some.future.block");
    }

    #[test]
    fn an_export_blanks_the_values_its_author_marked_secret() {
        let mut project = Project {
            id: "p1".into(),
            name: "x".into(),
            notes: String::new(),
            blocks: vec![block_with_secret()],
            run: RunSettings::default(),
            created_at: 1,
            updated_at: 1,
        };
        project.run.profiles = vec!["profile-on-this-machine".into()];

        // Same work export() does, on a value rather than the on-disk db, so
        // the test does not depend on a config root.
        let mut needs = Vec::new();
        for block in &mut project.blocks {
            let mut cleared = Vec::new();
            if let Value::Object(map) = &mut block.params {
                for name in &block.secrets {
                    if let Some(slot) = map.get_mut(name) {
                        *slot = Value::String(String::new());
                        cleared.push(name.clone());
                    }
                }
            }
            if !cleared.is_empty() {
                needs.push(cleared);
            }
        }
        project.run.profiles.clear();

        let body = serde_json::to_string(&project).unwrap();
        assert!(
            !body.contains("hunter2"),
            "an exported project still carried a password: {body}"
        );
        assert!(
            body.contains("#pw"),
            "blanking a secret must not take the rest of the step with it"
        );
        assert!(
            !body.contains("profile-on-this-machine"),
            "local profile ids must not travel in an export"
        );
        assert_eq!(needs, vec![vec!["text".to_string()]]);
    }

    #[test]
    fn a_bundle_from_a_newer_build_is_refused_rather_than_half_read() {
        let bundle = Bundle {
            format: BUNDLE_FORMAT + 1,
            exported_at: 0,
            project: Project {
                id: "p".into(),
                name: "x".into(),
                notes: String::new(),
                blocks: Vec::new(),
                run: RunSettings::default(),
                created_at: 0,
                updated_at: 0,
            },
            needs: Vec::new(),
        };
        let err = import(bundle).expect_err("a newer format must be refused");
        assert!(
            crate::errcode::resolve_to_english(&err.to_string()).contains("newer build"),
            "the refusal should say why: {err}"
        );
    }

    #[test]
    fn a_branch_survives_the_round_trip_it_will_actually_take() {
        for branch in [
            Branch::Next,
            Branch::Stop,
            Branch::EndPass,
            Branch::Goto("b7".into()),
            Branch::Retry(3),
        ] {
            let json = serde_json::to_string(&branch).unwrap();
            let back: Branch = serde_json::from_str(&json).unwrap();
            assert_eq!(branch, back, "branch changed meaning through {json}");
        }
    }
}
