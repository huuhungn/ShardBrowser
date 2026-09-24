//! Moving the data root. Copy, verify, then delete — a rename cannot cross
//! disks. `launch` checks the lock, so the UI is not the only guard.

use crate::{settings, store};
use anyhow::{Context, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use tauri::Emitter;

static MIGRATING: AtomicBool = AtomicBool::new(false);

pub fn in_progress() -> bool {
    MIGRATING.load(Ordering::SeqCst)
}

/// What the progress bar reads.
#[derive(Debug, Clone, Serialize)]
pub struct Progress {
    /// "scan" | "copy" | "verify" | "cleanup" | "done"
    pub phase: &'static str,
    pub done: u64,
    pub total: u64,
    pub percent: u8,
    /// File currently being moved, relative to the root.
    pub current: String,
}

/// Directories that move; everything else in the config dir stays where the
/// launcher can always find it.
const MOVED: &[&str] = &["profiles", "user-data", "extensions", "trash"];

fn emit(app: &tauri::AppHandle, p: Progress) {
    let _ = app.emit("data-migration", p);
}

/// Move the data root to `dst`. Returns the number of files moved.
pub fn run(app: &tauri::AppHandle, dst: &Path) -> Result<u64> {
    if MIGRATING.swap(true, Ordering::SeqCst) {
        anyhow::bail!(crate::errcode::code("migrate.alreadyRunning"));
    }
    let out = do_run(app, dst);
    MIGRATING.store(false, Ordering::SeqCst);
    if out.is_err() {
        emit(
            app,
            Progress {
                phase: "done",
                done: 0,
                total: 0,
                percent: 100,
                current: String::new(),
            },
        );
    }
    out
}

fn do_run(app: &tauri::AppHandle, dst: &Path) -> Result<u64> {
    let src = store::data_root()?;
    let dst = dst.to_path_buf();
    if dst == src {
        anyhow::bail!(crate::errcode::code("migrate.sameFolder"));
    }
    if dst.starts_with(&src) {
        anyhow::bail!(crate::errcode::code("migrate.nestedFolder"));
    }
    std::fs::create_dir_all(&dst).with_context(|| format!("create {}", dst.display()))?;
    writable(&dst)?;

    emit(
        app,
        Progress {
            phase: "scan",
            done: 0,
            total: 0,
            percent: 0,
            current: String::new(),
        },
    );
    let mut files: Vec<(PathBuf, PathBuf)> = Vec::new();
    for name in MOVED {
        let from = src.join(name);
        if from.exists() {
            collect(&from, &dst.join(name), &mut files)?;
        }
    }
    let total = files.len() as u64;
    if total == 0 {
        finish(&dst)?;
        emit(
            app,
            Progress {
                phase: "done",
                done: 0,
                total: 0,
                percent: 100,
                current: String::new(),
            },
        );
        return Ok(0);
    }

    let mut done = 0u64;
    for (from, to) in &files {
        if let Some(parent) = to.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(from, to)
            .with_context(|| format!("copy {} → {}", from.display(), to.display()))?;
        done += 1;
        // One event per file is noise on a profile with ten thousand cache
        // entries; the bar only needs to move.
        if done.is_multiple_of(25) || done == total {
            emit(
                app,
                Progress {
                    phase: "copy",
                    done,
                    total,
                    percent: ((done * 100) / total) as u8,
                    current: from
                        .strip_prefix(&src)
                        .unwrap_or(from)
                        .display()
                        .to_string(),
                },
            );
        }
    }

    emit(
        app,
        Progress {
            phase: "verify",
            done,
            total,
            percent: 100,
            current: String::new(),
        },
    );
    for (from, to) in &files {
        let a = std::fs::metadata(from).map(|m| m.len()).unwrap_or(0);
        let b = std::fs::metadata(to).map(|m| m.len()).unwrap_or(u64::MAX);
        if a != b {
            anyhow::bail!(crate::errcode::code_with(
                "migrate.copyIncomplete",
                &[("path", &from.display().to_string())]
            ));
        }
    }

    // Only now is the old copy expendable.
    emit(
        app,
        Progress {
            phase: "cleanup",
            done,
            total,
            percent: 100,
            current: String::new(),
        },
    );
    finish(&dst)?;
    for name in MOVED {
        let old = src.join(name);
        if old.exists() {
            let _ = std::fs::remove_dir_all(&old);
        }
    }

    emit(
        app,
        Progress {
            phase: "done",
            done,
            total,
            percent: 100,
            current: String::new(),
        },
    );
    Ok(done)
}

/// Persist the new root and point the process at it.
fn finish(dst: &Path) -> Result<()> {
    let mut s = settings::load()?;
    s.data_root = Some(dst.display().to_string());
    settings::save(&s)?;
    store::set_data_root(Some(dst.to_path_buf()));
    Ok(())
}

/// Fail before copying rather than half-way through: an external disk mounted
/// read-only looks like an ordinary directory until something is written.
fn writable(dir: &Path) -> Result<()> {
    let probe = dir.join(".shardx-write-test");
    std::fs::write(&probe, b"ok").with_context(|| {
        crate::errcode::code_with(
            "migrate.notWritable",
            &[("path", &dir.display().to_string())],
        )
    })?;
    let _ = std::fs::remove_file(&probe);
    Ok(())
}

fn collect(src: &Path, dst: &Path, out: &mut Vec<(PathBuf, PathBuf)>) -> Result<()> {
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        match entry.file_type() {
            Ok(t) if t.is_dir() => collect(&from, &to, out)?,
            // Symlinks are followed by copy(); a profile dir has none anyway.
            Ok(_) => out.push((from, to)),
            Err(_) => {}
        }
    }
    Ok(())
}
