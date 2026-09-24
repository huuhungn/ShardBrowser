//! Tauri commands for pushing and pulling profiles through a team server.
//!
//! This is the application surface over `fleet_client`. Until this module
//! existed the fleet transfer code had no caller: v0.2.1 shipped lease, upload
//! and download methods that the linker dropped, so the shipped binary did not
//! contain the routes at all (see issue #23).
//!
//! The rules from `backup_cmd` apply unchanged, for the same reasons:
//!
//! 1. **A running profile is never pushed or pulled.** Chromium holds SQLite
//!    handles open; reading underneath it yields a torn snapshot and writing
//!    underneath it corrupts a live profile.
//! 2. **The passphrase is never persisted.** It derives the file key and is
//!    dropped.
//!
//! One rule is specific to sync. The container uploaded here is byte-identical
//! to a local `.shxbak`: the same `backup_file` seal produces it, so the server
//! stores a blob it cannot open. That is deliberate — the team server holds
//! ciphertext and version metadata, never profile contents.
//!
//! The passphrase is therefore a *shared secret between devices*, not a
//! per-device key. Everyone who pulls a profile must know the passphrase used
//! to push it. Replacing that with per-device key wrapping is the tenant root
//! key work described in `docs/key-custody.md`; it is not implemented, and
//! pretending otherwise would be worse than saying so plainly.

use serde::Serialize;

use crate::{fleet_client, fleet_keys, profile, team_config};

/// Result of a completed push.
#[derive(Debug, Serialize)]
pub struct PushResult {
    /// Version the server assigned to this snapshot.
    pub version: i64,
    /// Size of the sealed container in bytes.
    pub container_bytes: u64,
    /// SHA-256 of the container, hex — matches the digest a local backup of
    /// the same profile state would report.
    pub sha256: String,
}

/// What the team server knows about a profile, without downloading it.
#[derive(Debug, Serialize)]
pub struct RemoteSnapshot {
    pub version: i64,
    pub container_bytes: i64,
    pub sha256: String,
}

/// Load team config and fail with an actionable message if sync is not set up.
fn ready_config() -> Result<team_config::TeamConfig, String> {
    let c = team_config::load().map_err(|e| e.to_string())?;
    if c.server_url.is_empty() {
        return Err(crate::errcode::code("sync.noTeamServer"));
    }
    if !c.is_enrolled() {
        return Err(crate::errcode::code("sync.deviceNotEnrolled"));
    }
    if !c.can_sync() {
        // An older enrollment predates storing the account id. It cannot be
        // reconstructed locally, and guessing one would fail server-side
        // authorization anyway.
        return Err(crate::errcode::code("sync.enrolledBeforeSyncExisted"));
    }
    Ok(c)
}

/// Derive the fleet id used for a profile.
///
/// The server scopes snapshots by fleet. The Launcher has no fleet picker yet,
/// so a device uses the fleet recorded at enrollment, falling back to its
/// tenant id. This keeps a single-fleet tenant working without inventing an id
/// the server has never seen.
fn fleet_id(c: &team_config::TeamConfig) -> String {
    if c.fleet_id.is_empty() {
        c.tenant_id.clone()
    } else {
        c.fleet_id.clone()
    }
}

/// Push `profile_id` to the team server, sealed under `passphrase`.
///
/// The profile must exist and must not be running. `base_version` is the
/// version this push derives from: pass the version last seen from
/// `profile_sync_status`, or 0 for a first push. The server rejects a commit
/// whose base does not match the current head, which is what stops two devices
/// silently overwriting each other.
#[tauri::command]
pub async fn profile_sync_push(
    profile_id: String,
    passphrase: String,
    base_version: i64,
) -> Result<PushResult, String> {
    // Running-state first: a user whose profile is running must be told to
    // stop it, not sent to fix server settings that were never the problem.
    let _claim = profile::begin_user_mutation(
        [&profile_id],
        &crate::errcode::code("profile.actionPushToTeam"),
    )
    .map_err(|error| error.to_string())?;
    let c = ready_config()?;
    profile::load_raw(&profile_id).map_err(|_| crate::errcode::code("profile.noSuchProfile"))?;

    let udd = profile::user_data_dir(&profile_id).map_err(|e| e.to_string())?;
    if !udd.exists() {
        return Err(crate::errcode::code("sync.noDataToPush"));
    }

    // Prefer the fleet key this device collected from its grant: it is the
    // key the fleet actually shares, so no passphrase has to be agreed out of
    // band. The passphrase path stays for devices that have not collected a
    // grant yet, and is refused outright if neither is available.
    let fleet_key = fleet_keys::load()
        .ok()
        .and_then(|s| s.active_key(&c.fleet_id));
    if fleet_key.is_none() && passphrase.is_empty() {
        return Err(
            "this device has no fleet key yet — collect key custody in Team settings, \
             or supply a passphrase"
                .into(),
        );
    }

    // Argon2id is deliberately slow and packing is IO-bound: not on the UI
    // thread.
    let seal_profile_id = profile_id.clone();
    let sealed = tokio::task::spawn_blocking(move || match fleet_key {
        Some((fkek, _generation)) => {
            shardx_core::backup_file::seal_profile_with_fkek(&seal_profile_id, &udd, &fkek)
        }
        None => shardx_core::backup_file::seal_profile(&seal_profile_id, &udd, &passphrase),
    })
    .await
    .map_err(|e| crate::errcode::code_with("sync.sealTaskFailed", &[("error", &e.to_string())]))?
    .map_err(|e| format!("{e:#}"))?;

    let signer = c.signing_key().map_err(|e| e.to_string())?;
    let client =
        fleet_client::FleetClient::new(&c.server_url, &c.token).map_err(|e| e.to_string())?;

    let fleet = fleet_id(&c);
    // The snapshot id identifies this upload attempt, not the profile.
    let snapshot_id = fleet_client::random_id_hex();
    let profile_ref = profile_ref(&profile_id);

    let version = client
        .upload(
            &fleet_client::UploadRequest {
                tenant_id: &c.tenant_id,
                profile_id: &profile_ref,
                fleet_id: &fleet,
                snapshot_id: &snapshot_id,
                account_id: &c.account_id,
                device_id: &c.device_id,
                // Must match what `backup_file` sealed the container under, or
                // the manifest would describe a key generation the container
                // does not use.
                key_generation: 1,
                base_version,
                container: &sealed.bytes,
            },
            &signer,
            LEASE_TTL_SECONDS,
        )
        .await
        .map_err(|e| format!("{e:#}"))?;

    Ok(PushResult {
        version,
        container_bytes: sealed.info.file_bytes,
        sha256: sealed.info.sha256,
    })
}

/// Pull the current snapshot of `profile_id` and restore it over the local
/// profile.
///
/// The container is downloaded and fully authenticated in memory before
/// anything touches the profile directory, so a wrong passphrase or a damaged
/// transfer cannot leave a half-written profile behind.
#[tauri::command]
pub async fn profile_sync_pull(profile_id: String, passphrase: String) -> Result<u64, String> {
    let _claim = profile::begin_user_mutation(
        [&profile_id],
        &crate::errcode::code("profile.actionPullFromTeam"),
    )
    .map_err(|error| error.to_string())?;
    let c = ready_config()?;
    profile::load_raw(&profile_id).map_err(|_| crate::errcode::code("profile.noSuchProfile"))?;

    let udd = profile::user_data_dir(&profile_id).map_err(|e| e.to_string())?;

    let client =
        fleet_client::FleetClient::new(&c.server_url, &c.token).map_err(|e| e.to_string())?;
    let profile_ref = profile_ref(&profile_id);

    let head = client
        .head(&c.tenant_id, &profile_ref)
        .await
        .map_err(|e| format!("{e:#}"))?;
    if head.version == 0 {
        return Err(crate::errcode::code(
            "profile.theTeamServerHasNoSnapshotForThisProfi",
        ));
    }

    let container = client
        .download(&c.tenant_id, &profile_ref, head.version)
        .await
        .map_err(|e| format!("{e:#}"))?;

    // Try every fleet key this device holds, newest first: a snapshot pushed
    // before a rotation is sealed under an older generation and must still
    // restore. Falls back to the passphrase for pre-custody snapshots.
    let candidates = fleet_keys::load()
        .map(|s| s.keys_newest_first(&c.fleet_id))
        .unwrap_or_default();

    tokio::task::spawn_blocking(move || {
        let mut last_err = None;
        for (fkek, _generation) in &candidates {
            match shardx_core::backup_file::open_profile_with_fkek(&container, &udd, fkek) {
                Ok(bytes) => return Ok(bytes),
                Err(e) => last_err = Some(e),
            }
        }
        if !passphrase.is_empty() {
            return shardx_core::backup_file::open_profile(&container, &udd, &passphrase);
        }
        Err(last_err.unwrap_or_else(|| {
            anyhow::anyhow!(
                "this device has no fleet key for this snapshot — collect key custody in \
                 Team settings, or supply the passphrase it was pushed with"
            )
        }))
    })
    .await
    .map_err(|e| crate::errcode::code_with("sync.restoreTaskFailed", &[("error", &e.to_string())]))?
    .map_err(|e| format!("{e:#}"))
}

/// What the server currently holds for `profile_id`, or `None` if nothing.
///
/// This needs no passphrase: it reads version metadata, never contents.
#[tauri::command]
pub async fn profile_sync_status(profile_id: String) -> Result<Option<RemoteSnapshot>, String> {
    let c = ready_config()?;
    let client =
        fleet_client::FleetClient::new(&c.server_url, &c.token).map_err(|e| e.to_string())?;

    let head = client
        .head(&c.tenant_id, &profile_ref(&profile_id))
        .await
        .map_err(|e| format!("{e:#}"))?;

    if head.version == 0 {
        return Ok(None);
    }
    Ok(Some(RemoteSnapshot {
        version: head.version,
        container_bytes: head.container_size,
        sha256: head.container_sha256,
    }))
}

/// How long to hold the write lease. Long enough to upload a large profile on
/// a slow link, short enough that a crashed push frees the profile quickly.
const LEASE_TTL_SECONDS: i64 = 600;

/// Map a local profile id to the 16-byte id the server expects.
///
/// Local profile ids are free-form strings; `/v2/` ids are exactly 16 bytes of
/// hex. Hashing gives a stable, collision-resistant mapping, and using the same
/// derivation as a local backup's ids keeps the two consistent.
fn profile_ref(profile_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"shardx-fleet/profile/");
    h.update(profile_id.as_bytes());
    let full: [u8; 32] = h.finalize().into();
    full[..16].iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_ref_is_sixteen_bytes_of_hex() {
        let r = profile_ref("some-profile");
        assert_eq!(r.len(), 32, "server ids are 16 bytes, hex-encoded");
        assert!(r.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn profile_ref_is_stable_and_distinct() {
        assert_eq!(profile_ref("a"), profile_ref("a"));
        assert_ne!(profile_ref("a"), profile_ref("b"));
    }
}
