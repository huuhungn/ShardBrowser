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
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        restrict(&tmp);
        replace_file(&tmp, path)?;
        sync_parent(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

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
}
