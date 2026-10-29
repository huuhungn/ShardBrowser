//! Crash-safe replacement of the launcher's own state files (G2-49).
//!
//! Each write goes to a synced sibling, owner-only on Unix, that then
//! replaces the target in one step. After a crash or power cut the path holds
//! the old bytes or the new ones, never a mix, and once the call returns the
//! new bytes and the rename are on disk:
//! - Windows: `MoveFileExW` with `MOVEFILE_WRITE_THROUGH` returns only after
//!   the move is flushed.
//! - Unix: the parent directory is fsynced after the rename.

use std::fs;
use std::io::Write;
use std::path::Path;

/// Writes `bytes` over `path` as described above. A failed write removes its
/// temporary file and leaves `path` as it was.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = std::path::PathBuf::from(tmp);
    let result = (|| {
        let mut f = fs::File::create(&tmp)?;
        crash_point("created");
        f.write_all(bytes)?;
        crash_point("written");
        f.sync_all()?;
        crash_point("synced");
        drop(f);
        restrict(&tmp);
        replace_file(&tmp, path)?;
        crash_point("replaced");
        sync_parent(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Where the crash harness can kill a test build (G2-49); nothing in a
/// release build.
#[cfg(test)]
fn crash_point(point: &str) {
    crate::crash_harness::pause_if(point);
}

#[cfg(not(test))]
fn crash_point(_point: &str) {}

/// Restricts the file to its owner where the platform expresses that in mode
/// bits. Best effort: failing to tighten permissions must not lose the write.
#[cfg(unix)]
fn restrict(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict(_path: &Path) {}

#[cfg(unix)]
fn sync_parent(path: &Path) -> std::io::Result<()> {
    match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => fs::File::open(dir)?.sync_all(),
        _ => Ok(()),
    }
}

/// `MOVEFILE_WRITE_THROUGH` already flushed the move.
#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(windows))]
pub(crate) fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(windows)]
pub(crate) fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let source_wide: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination_wide: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let moved = unsafe {
        MoveFileExW(
            source_wide.as_ptr(),
            destination_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_durable_write_replaces_the_file_and_leaves_no_temporary() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        write_private(&path, b"one").unwrap();
        write_private(&path, b"two").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two");
        assert!(!dir.path().join("state.json.tmp").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn a_failed_replace_keeps_the_old_file_and_removes_the_temporary() {
        let dir = tempfile::tempdir().unwrap();
        // A directory at the target path: the replace fails after the
        // temporary was written and synced.
        let path = dir.path().join("state.json");
        fs::create_dir(&path).unwrap();
        fs::write(path.join("inner"), b"old").unwrap();
        assert!(write_private(&path, b"new").is_err());
        assert_eq!(fs::read(path.join("inner")).unwrap(), b"old");
        assert!(!dir.path().join("state.json.tmp").exists());
    }

    /// The state file the harness replaces: 256 KiB of one byte after an
    /// 8-byte version, so a torn file cannot pass for a whole one.
    fn version(n: u64) -> Vec<u8> {
        let mut bytes = n.to_le_bytes().to_vec();
        bytes.resize(256 * 1024, (n % 251) as u8);
        bytes
    }

    /// The version a file holds, if it is exactly one whole version.
    fn whole(bytes: &[u8]) -> Option<u64> {
        let n = u64::from_le_bytes(bytes.get(..8)?.try_into().ok()?);
        (bytes == version(n).as_slice()).then_some(n)
    }

    const CHILD: &str = "durable::tests::child_replaces_once";
    const LOOP_CHILD: &str = "durable::tests::child_replaces_in_a_loop";

    #[test]
    #[ignore = "child process of the crash harness"]
    fn child_replaces_once() {
        let Some(path) = std::env::var_os("SHARDX_CRASH_FILE") else {
            return;
        };
        write_private(Path::new(&path), &version(2)).unwrap();
        crate::crash_harness::pause_if("returned");
    }

    /// G2-49: a process killed at each step of a replace leaves the old bytes
    /// until the rename and the new ones from it on, never a mix; the next
    /// write goes through over whatever temporary the kill left.
    #[test]
    fn a_write_killed_at_any_step_leaves_the_old_or_the_new_file() {
        for (point, expected) in [
            ("created", 1),
            ("written", 1),
            ("synced", 1),
            ("replaced", 2),
            ("returned", 2),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("state.json");
            write_private(&path, &version(1)).unwrap();
            let reached =
                crate::crash_harness::kill_at(CHILD, point, &[("SHARDX_CRASH_FILE", &path)]);
            assert!(reached, "{point}");
            assert_eq!(whole(&fs::read(&path).unwrap()), Some(expected), "{point}");
            write_private(&path, &version(3)).unwrap();
            assert_eq!(whole(&fs::read(&path).unwrap()), Some(3), "{point}");
            assert!(!dir.path().join("state.json.tmp").exists(), "{point}");
        }
    }

    #[test]
    #[ignore = "child process of the crash harness"]
    fn child_replaces_in_a_loop() {
        let Some(path) = std::env::var_os("SHARDX_CRASH_FILE") else {
            return;
        };
        for n in 2_u64..u64::MAX {
            write_private(Path::new(&path), &version(n)).unwrap();
            println!("WROTE {n}");
        }
    }

    /// Killed at an arbitrary moment of back-to-back replaces, the file is one
    /// whole version, no older than the last write that returned.
    #[test]
    fn a_kill_during_back_to_back_writes_never_tears_or_loses_a_returned_write() {
        for target in [2_u64, 9, 31] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("state.json");
            write_private(&path, &version(1)).unwrap();
            let child =
                crate::crash_harness::spawn(LOOP_CHILD, "-", &[("SHARDX_CRASH_FILE", &path)]);
            assert!(crate::crash_harness::kill_after(
                child,
                &format!("WROTE {target}")
            ));
            let got = whole(&fs::read(&path).unwrap());
            assert!(got.is_some_and(|n| n >= target), "{target}: {got:?}");
        }
    }

    /// G2-49 on the volume the tests run on (local NTFS on Windows): an
    /// exclusive create never overwrites a file that exists, and neither does
    /// a hard link, the no-clobber install of immutable records
    /// (`server/src/identity.rs` `write_record`).
    #[test]
    fn creating_a_file_that_exists_never_overwrites_it() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(windows)]
        shardx_core::volume::require_local_ntfs(dir.path()).unwrap();
        let path = dir.path().join("object");
        fs::write(&path, b"immutable").unwrap();
        let err = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        let other = dir.path().join("other");
        fs::write(&other, b"intruder").unwrap();
        let err = fs::hard_link(&other, &path).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&path).unwrap(), b"immutable");
    }
}
