//! The supported-filesystem gate (ADR 0002 Q-30, plan L1110, L2335): state
//! lives only on a local NTFS volume. A UNC path, a mapped or substituted
//! network drive, and a FAT32, exFAT, ReFS or any other volume are refused,
//! because the durability and SQLite locking evidence (G2-49, G2-50) holds
//! for local NTFS only.
//!
//! Only Windows is classified. Elsewhere [`require_local_ntfs`] accepts every
//! path and callers keep their own policy (the server's Linux mount
//! allowlist).

use std::path::Path;

/// `GetDriveTypeW` results this gate tells apart.
pub const DRIVE_REMOVABLE: u32 = 2;
pub const DRIVE_FIXED: u32 = 3;
pub const DRIVE_REMOTE: u32 = 4;

/// Why a path's volume is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VolumeRefusal {
    /// A UNC path, or a drive Windows reports as remote (SMB, WebDAV, NFS).
    Network,
    /// A local volume that is not NTFS, or not a disk: the filesystem name,
    /// with the drive type when that is the reason.
    Unsupported(String),
    /// The volume could not be queried; unknown is refused.
    Unreadable(String),
}

impl std::fmt::Display for VolumeRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network => write!(f, "is on a network share"),
            Self::Unsupported(fs) => write!(f, "is on a {fs} volume, not local NTFS"),
            Self::Unreadable(e) => write!(f, "is on a volume that cannot be checked: {e}"),
        }
    }
}

/// The policy, apart from the system calls: `unc` is whether the resolved
/// path is a UNC path, `drive_type` is `GetDriveTypeW` of its volume root and
/// `filesystem` the name `GetVolumeInformation*` reports.
pub fn classify(unc: bool, drive_type: u32, filesystem: &str) -> Result<(), VolumeRefusal> {
    if unc || drive_type == DRIVE_REMOTE {
        return Err(VolumeRefusal::Network);
    }
    if !matches!(drive_type, DRIVE_FIXED | DRIVE_REMOVABLE) {
        return Err(VolumeRefusal::Unsupported(format!(
            "{filesystem} (drive type {drive_type})"
        )));
    }
    if filesystem != "NTFS" {
        return Err(VolumeRefusal::Unsupported(filesystem.to_string()));
    }
    Ok(())
}

/// Refuses `path` unless it resolves, through junctions, symbolic links and
/// `subst` drives, to a directory or file on a local NTFS volume.
#[cfg(windows)]
pub fn require_local_ntfs(path: &Path) -> Result<(), VolumeRefusal> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetDriveTypeW, GetVolumeInformationByHandleW, GetVolumePathNameW,
        FILE_FLAG_BACKUP_SEMANTICS,
    };

    let unreadable = |e: std::io::Error| VolumeRefusal::Unreadable(e.to_string());
    // A mapped or substituted network drive resolves to `\\?\UNC\...` too.
    let resolved = std::fs::canonicalize(path).map_err(unreadable)?;
    if resolved
        .as_os_str()
        .to_string_lossy()
        .starts_with(r"\\?\UNC\")
    {
        return Err(VolumeRefusal::Network);
    }
    let wide: Vec<u16> = resolved.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut root = vec![0u16; wide.len() + 1];
    // SAFETY: both buffers are NUL-terminated or sized as passed.
    if unsafe { GetVolumePathNameW(wide.as_ptr(), root.as_mut_ptr(), root.len() as u32) } == 0 {
        return Err(unreadable(std::io::Error::last_os_error()));
    }
    // SAFETY: `root` is the NUL-terminated volume root just written.
    let drive_type = unsafe { GetDriveTypeW(root.as_ptr()) };
    // The handle names the volume the bytes live on, mount points included.
    let handle = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(&resolved)
        .map_err(unreadable)?;
    let mut name = [0u16; 261];
    // SAFETY: the handle is open; unused out-parameters are null.
    let read = unsafe {
        GetVolumeInformationByHandleW(
            handle.as_raw_handle() as _,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            name.as_mut_ptr(),
            name.len() as u32,
        )
    };
    if read == 0 {
        return Err(unreadable(std::io::Error::last_os_error()));
    }
    let len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
    classify(false, drive_type, &String::from_utf16_lossy(&name[..len]))
}

/// No classification off Windows; see the module documentation.
#[cfg(not(windows))]
pub fn require_local_ntfs(_path: &Path) -> Result<(), VolumeRefusal> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_local_ntfs_disk_is_accepted() {
        classify(false, DRIVE_FIXED, "NTFS").unwrap();
        classify(false, DRIVE_REMOVABLE, "NTFS").unwrap();
        for fs in ["FAT32", "exFAT", "FAT", "ReFS", "UDF", "ntfs", ""] {
            assert_eq!(
                classify(false, DRIVE_FIXED, fs),
                Err(VolumeRefusal::Unsupported(fs.to_string())),
                "{fs}"
            );
        }
        // A share reports the server's filesystem, NTFS included.
        assert_eq!(
            classify(true, DRIVE_FIXED, "NTFS"),
            Err(VolumeRefusal::Network)
        );
        assert_eq!(
            classify(false, DRIVE_REMOTE, "NTFS"),
            Err(VolumeRefusal::Network)
        );
        // Unknown, no root, CD-ROM and RAM disk are not local disks.
        for drive_type in [0, 1, 5, 6] {
            assert!(
                matches!(
                    classify(false, drive_type, "NTFS"),
                    Err(VolumeRefusal::Unsupported(_))
                ),
                "{drive_type}"
            );
        }
    }

    /// The test's temporary directory is on the runner's NTFS system disk.
    #[cfg(windows)]
    #[test]
    fn a_local_ntfs_directory_is_accepted_and_a_missing_one_is_not() {
        let dir = std::env::temp_dir().join(format!("shardx-volume-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        require_local_ntfs(&dir).unwrap();
        std::fs::write(dir.join("f"), b"x").unwrap();
        require_local_ntfs(&dir.join("f")).unwrap();
        assert!(matches!(
            require_local_ntfs(&dir.join("missing")),
            Err(VolumeRefusal::Unreadable(_))
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// An SMB share is refused even though the server's disk is NTFS. CI
    /// creates a share and names it in `SHARDX_TEST_SMB_DIR`; elsewhere the
    /// loopback administrative share is tried, and the test says why it
    /// skipped when neither is reachable.
    #[cfg(windows)]
    #[test]
    fn an_smb_share_is_refused() {
        let Some(share) = smb_probe() else {
            eprintln!(
                "SKIPPED an_smb_share_is_refused: set SHARDX_TEST_SMB_DIR to a reachable \
                 \\\\host\\share directory (needs an SMB share; CI creates one)"
            );
            return;
        };
        assert_eq!(
            require_local_ntfs(&share),
            Err(VolumeRefusal::Network),
            "{share:?}"
        );
    }

    /// The share to probe: `SHARDX_TEST_SMB_DIR`, which must then be
    /// reachable, or else `\\localhost\C$\...` of the temporary directory.
    #[cfg(windows)]
    fn smb_probe() -> Option<std::path::PathBuf> {
        if let Some(dir) = std::env::var_os("SHARDX_TEST_SMB_DIR") {
            let dir = std::path::PathBuf::from(dir);
            assert!(dir.exists(), "SHARDX_TEST_SMB_DIR {dir:?} is not reachable");
            return Some(dir);
        }
        let temp = std::fs::canonicalize(std::env::temp_dir()).ok()?;
        let local = temp.to_string_lossy();
        let rest = local.strip_prefix(r"\\?\")?;
        let (drive, tail) = rest.split_once(":\\")?;
        let share = std::path::PathBuf::from(format!(r"\\localhost\{drive}$\{tail}"));
        share.exists().then_some(share)
    }
}
