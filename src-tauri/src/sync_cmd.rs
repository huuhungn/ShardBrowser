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

    // Argon2id is deliberately slow and packing is IO-bound: not on the UI
    // thread.
    let seal_profile_id = profile_id.clone();
    let sealed =
        tokio::task::spawn_blocking(move || seal_for_push(&seal_profile_id, &udd, &passphrase))
            .await
            .map_err(|e| {
                crate::errcode::code_with("sync.sealTaskFailed", &[("error", &e.to_string())])
            })??;

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

/// Seal a profile for push: always under the passphrase, never a cached fleet
/// key. Those came from the team server, which cannot yet prove who issued
/// them, and sealing under a key the server chose would let it read every push
/// from here on.
fn seal_for_push(
    profile_id: &str,
    udd: &std::path::Path,
    passphrase: &str,
) -> Result<shardx_core::backup_file::SealedProfile, String> {
    if passphrase.is_empty() {
        return Err(crate::errcode::code("sync.passphraseRequired"));
    }
    shardx_core::backup_file::seal_profile(profile_id, udd, passphrase)
        .map_err(|e| format!("{e:#}"))
}

/// Open a pulled container: every cached fleet key first, newest first (a
/// snapshot an earlier version pushed under one must still restore), then the
/// passphrase. The server picks the bytes, so a container sealed for any
/// profile other than `profile_id` is refused before the profile is touched.
fn open_pulled(
    container: &[u8],
    udd: &std::path::Path,
    profile_id: &str,
    candidates: &[([u8; 32], u64)],
    passphrase: &str,
) -> Result<u64, String> {
    use shardx_core::backup_file::{open_profile_for, open_profile_with_fkek};
    for (fkek, _generation) in candidates {
        if let Ok(bytes) = open_profile_with_fkek(container, udd, fkek, profile_id) {
            return Ok(bytes);
        }
    }
    if passphrase.is_empty() {
        return Err(crate::errcode::code("sync.pullPassphraseRequired"));
    }
    open_profile_for(container, udd, passphrase, profile_id).map_err(|e| format!("{e:#}"))
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

    let candidates = fleet_keys::load()
        .map(|s| s.keys_newest_first(&c.fleet_id))
        .unwrap_or_default();

    tokio::task::spawn_blocking(move || {
        open_pulled(&container, &udd, &profile_id, &candidates, &passphrase)
    })
    .await
    .map_err(|e| {
        crate::errcode::code_with("sync.restoreTaskFailed", &[("error", &e.to_string())])
    })?
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

    /// With a fleet key cached and a passphrase given, push still seals a
    /// passphrase container: it opens with the passphrase and not the key.
    #[test]
    fn push_seals_under_the_passphrase_even_with_a_cached_fleet_key() {
        let _config = crate::store::config_root_test_lock()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().unwrap();
        crate::store::set_config_root(Some(dir.path().to_path_buf()));
        let fkek = [0x5Cu8; 32];
        let fleet = "dd".repeat(16);
        team_config::save(&team_config::TeamConfig {
            fleet_id: fleet.clone(),
            ..Default::default()
        })
        .unwrap();
        let mut keys = fleet_keys::FleetKeyStore::default();
        keys.insert(&fleet, 1, &fkek);
        fleet_keys::save(&keys).unwrap();
        let udd = dir.path().join("udd");
        std::fs::create_dir_all(&udd).unwrap();
        std::fs::write(udd.join("Preferences"), b"{}").unwrap();

        let sealed = seal_for_push("p", &udd, "team-passphrase");
        crate::store::set_config_root(None);
        let bytes = sealed.expect("seal").bytes;

        assert_eq!(
            &bytes[..8],
            b"SHXBAK01",
            "a passphrase container, not SHXFLT01"
        );
        let out = dir.path().join("out");
        assert!(
            shardx_core::backup_file::open_profile_with_fkek(&bytes, &out, &fkek, "p").is_err(),
            "the cached fleet key must not open it"
        );
        shardx_core::backup_file::open_profile(&bytes, &out, "team-passphrase")
            .expect("opens with the passphrase");
    }

    /// Pull with no key that opens the snapshot and no passphrase asks for the
    /// passphrase in the operator's language.
    #[test]
    fn pull_without_a_working_key_or_passphrase_asks_for_the_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let udd = dir.path().join("udd");
        std::fs::create_dir_all(&udd).unwrap();
        std::fs::write(udd.join("Preferences"), b"{}").unwrap();
        let bytes = shardx_core::backup_file::seal_profile("p", &udd, "team-passphrase")
            .unwrap()
            .bytes;
        let out = dir.path().join("out");

        for candidates in [vec![], vec![([0x11u8; 32], 1)]] {
            let err = open_pulled(&bytes, &out, "p", &candidates, "").unwrap_err();
            assert!(
                crate::errcode::has_code(&err, "sync.pullPassphraseRequired"),
                "{err}"
            );
        }
        assert!(open_pulled(&bytes, &out, "p", &[([0x11u8; 32], 1)], "team-passphrase").is_ok());
    }

    /// A server that answers a pull for one profile with another profile's
    /// genuine snapshot is refused, under a cached fleet key or the passphrase.
    #[test]
    fn pull_refuses_another_profiles_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let udd = dir.path().join("udd");
        std::fs::create_dir_all(&udd).unwrap();
        std::fs::write(udd.join("Preferences"), b"{}").unwrap();
        let fkek = [0x5Cu8; 32];
        let by_key = shardx_core::backup_file::seal_profile_with_fkek("other", &udd, &fkek)
            .unwrap()
            .bytes;
        let by_passphrase =
            shardx_core::backup_file::seal_profile("other", &udd, "team-passphrase")
                .unwrap()
                .bytes;
        let out = dir.path().join("out");

        let err = open_pulled(&by_key, &out, "p", &[(fkek, 1)], "").unwrap_err();
        assert!(
            crate::errcode::has_code(&err, "sync.pullPassphraseRequired"),
            "{err}"
        );
        let err = open_pulled(&by_passphrase, &out, "p", &[], "team-passphrase").unwrap_err();
        assert!(err.contains("another profile"), "{err}");
        assert!(
            !out.exists(),
            "nothing restored from another profile's snapshot"
        );
    }

    /// A fleet key cached from the team server must not stand in for the
    /// passphrase: the server may have chosen that key.
    #[test]
    fn push_refuses_an_empty_passphrase_even_with_a_cached_fleet_key() {
        let _config = crate::store::config_root_test_lock()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let _lifecycle = profile::lifecycle_test_guard();
        let dir = tempfile::tempdir().unwrap();
        crate::store::set_config_root(Some(dir.path().to_path_buf()));

        let mut stored = profile::StoredProfile::default();
        profile::save_raw(&mut stored).unwrap();
        let id = stored.meta.id.clone();
        let udd = profile::user_data_dir(&id).unwrap();
        std::fs::create_dir_all(&udd).unwrap();
        std::fs::write(udd.join("Preferences"), b"{}").unwrap();

        let seed = "11".repeat(32);
        team_config::save(&team_config::TeamConfig {
            // Nothing listens here, so a push that got past the key check
            // fails on the network instead of with the refusal.
            server_url: "http://127.0.0.1:9".into(),
            token: "t".into(),
            tenant_id: "aa".repeat(16),
            device_id: "bb".repeat(16),
            account_id: "cc".repeat(16),
            fleet_id: "dd".repeat(16),
            signing_key_seed: seed.clone(),
            hpke_key_seed: seed,
            ..Default::default()
        })
        .unwrap();
        let mut keys = fleet_keys::FleetKeyStore::default();
        keys.insert(&"dd".repeat(16), 1, &[0x5Cu8; 32]);
        fleet_keys::save(&keys).unwrap();

        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(profile_sync_push(id, String::new(), 0));
        crate::store::set_config_root(None);

        let err = result.expect_err("push must refuse without a passphrase");
        assert!(
            crate::errcode::has_code(&err, "sync.passphraseRequired"),
            "expected the passphrase refusal, got: {err}"
        );
    }
}
