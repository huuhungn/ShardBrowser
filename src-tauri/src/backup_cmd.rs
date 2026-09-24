//! Tauri commands for encrypted local profile backup and restore.
//!
//! This is the application surface over `shardx_core::backup_file`. Until this
//! module existed the encrypted-backup library had no caller: v0.2.0 shipped
//! sealing, a wire format and a fleet server that nothing in the Launcher
//! could reach (see issue #17).
//!
//! Two rules shape everything here:
//!
//! 1. **A running profile is never backed up or restored.** Chromium holds
//!    SQLite handles open; copying underneath it yields a torn snapshot, and
//!    restoring underneath it corrupts a live profile. Both commands take the
//!    same `begin_user_mutation` claim the other destructive profile
//!    operations take.
//! 2. **The passphrase is never persisted.** It arrives, derives a key, and is
//!    dropped. There is no recovery path if the user forgets it — that is the
//!    cost of a backup that opens on a machine which has never seen this one.

use serde::Serialize;
use std::path::PathBuf;

use crate::profile;

/// Result of a completed backup, for display and for the user to record.
#[derive(Debug, Serialize)]
pub struct BackupResult {
    /// Absolute path of the file written.
    pub path: String,
    /// Size on disk in bytes.
    pub file_bytes: u64,
    /// SHA-256 of the file, hex — the digest an operator records as evidence.
    pub sha256: String,
}

/// What `backup_inspect` can tell the UI without a passphrase.
#[derive(Debug, Serialize)]
pub struct BackupFileSummary {
    pub path: String,
    pub file_bytes: u64,
    pub sha256: String,
}

/// Back up `profile_id` to `dest_path`, encrypted under `passphrase`.
///
/// Fails if the profile is running. The passphrase minimum length is enforced
/// by the KDF layer, so a short passphrase is refused before any file is
/// written.
#[tauri::command]
pub async fn profile_backup_create(
    profile_id: String,
    dest_path: String,
    passphrase: String,
) -> Result<BackupResult, String> {
    // Same claim as delete/clone: a torn backup of a live profile is worse
    // than no backup, because it looks like a valid one.
    let _claim = profile::begin_user_mutation(
        [&profile_id],
        &crate::errcode::code("profile.actionBackUpProfile"),
    )
    .map_err(|error| error.to_string())?;

    let udd = profile::user_data_dir(&profile_id).map_err(|e| e.to_string())?;
    if !udd.exists() {
        return Err(crate::errcode::code("profile.backupNoDataYet"));
    }
    let dest = PathBuf::from(&dest_path);

    // Argon2id is deliberately slow, and packing a profile is IO-bound, so this
    // must not run on the UI thread.
    let info = tokio::task::spawn_blocking(move || {
        shardx_core::backup_file::create(&profile_id, &udd, &dest, &passphrase)
    })
    .await
    .map_err(|e| {
        crate::errcode::code_with("profile.backupTaskFailed", &[("error", &e.to_string())])
    })?
    .map_err(|e| format!("{e:#}"))?;

    Ok(BackupResult {
        path: dest_path,
        file_bytes: info.file_bytes,
        sha256: info.sha256,
    })
}

/// Restore `src_path` over `profile_id`.
///
/// The profile must exist and must not be running. The backup is fully
/// recovered and authenticated in memory before anything touches the profile
/// directory, so a wrong passphrase or a damaged file cannot leave a partial
/// profile behind.
#[tauri::command]
pub async fn profile_backup_restore(
    profile_id: String,
    src_path: String,
    passphrase: String,
) -> Result<u64, String> {
    let _claim = profile::begin_user_mutation(
        [&profile_id],
        &crate::errcode::code("profile.actionRestoreFromBackup"),
    )
    .map_err(|error| error.to_string())?;

    // Restoring into a profile the app does not know about would leave data on
    // disk with no entry in the list, so require the profile to exist first.
    profile::load_raw(&profile_id).map_err(|_| crate::errcode::code("profile.noSuchProfile"))?;

    let udd = profile::user_data_dir(&profile_id).map_err(|e| e.to_string())?;
    let src = PathBuf::from(&src_path);
    if !src.exists() {
        return Err(crate::errcode::code("profile.backupFileNotFound"));
    }

    tokio::task::spawn_blocking(move || shardx_core::backup_file::restore(&src, &udd, &passphrase))
        .await
        .map_err(|e| {
            crate::errcode::code_with(
                "profile.backupRestoreTaskFailed",
                &[("error", &e.to_string())],
            )
        })?
        .map_err(|e| format!("{e:#}"))
}

/// Check that a file looks like a ShardX backup, without a passphrase.
///
/// Lets the UI reject a wrong file before prompting for a passphrase, rather
/// than making the user type one to find out.
#[tauri::command]
pub async fn profile_backup_inspect(src_path: String) -> Result<BackupFileSummary, String> {
    let src = PathBuf::from(&src_path);
    let info = tokio::task::spawn_blocking(move || shardx_core::backup_file::inspect(&src))
        .await
        .map_err(|e| {
            crate::errcode::code_with(
                "profile.backupInspectTaskFailed",
                &[("error", &e.to_string())],
            )
        })?
        .map_err(|e| format!("{e:#}"))?;
    Ok(BackupFileSummary {
        path: src_path,
        file_bytes: info.file_bytes,
        sha256: info.sha256,
    })
}

#[cfg(test)]
mod tests {
    /// Every backup entry point must take a lifecycle claim before touching a
    /// profile. This mirrors the existing profile-mutation guard test: the
    /// failure it protects against is silent data loss on a live profile.
    #[test]
    fn both_mutating_backup_commands_claim_the_profile_first() {
        let src = include_str!("backup_cmd.rs");

        for cmd in ["profile_backup_create", "profile_backup_restore"] {
            let body = src
                .split(&format!("pub async fn {cmd}("))
                .nth(1)
                .unwrap_or_else(|| panic!("{cmd} not found"));
            let claim = body
                .find("begin_user_mutation")
                .unwrap_or_else(|| panic!("{cmd} does not claim the profile"));
            // The claim must come before any filesystem work.
            for io_call in ["user_data_dir", "backup_file::"] {
                if let Some(io_at) = body.find(io_call) {
                    assert!(
                        claim < io_at,
                        "{cmd} touches {io_call} before claiming the profile"
                    );
                }
            }
        }
    }

    /// `inspect` is read-only and takes no passphrase, so it must NOT claim a
    /// profile — it is used to validate a file before the user commits to a
    /// restore.
    #[test]
    fn inspect_does_not_claim_a_profile() {
        let src = include_str!("backup_cmd.rs");
        let body = src
            .split("pub async fn profile_backup_inspect(")
            .nth(1)
            .expect("inspect not found");
        let end = body.find("\n}").unwrap_or(body.len());
        assert!(
            !body[..end].contains("begin_user_mutation"),
            "inspect is read-only and must not take a mutation claim"
        );
    }
}
