//! Files a project may read and write.
//!
//! Projects need files at the edges: a list of accounts to work through, a
//! token another tool left behind, a line appended per processed item so a
//! re-run can skip what is done.
//!
//! A project is data, not code. It arrives over the authenticated API, from
//! an MCP client, or from a teammate's export, and any of those may carry a
//! path. Handing that path straight to `fs::write` makes every project a
//! request to write anywhere the launcher can reach: the profile store, the
//! proxy list with its credentials, or the user's startup folder.
//!
//! So reads and writes are confined to one workspace directory under the
//! launcher's own config root. Paths are resolved and then checked against
//! that root *after* normalisation, because `a/../../b` only shows what it
//! reaches once resolved. Symlinks are rejected rather than followed, since
//! an existing link inside the workspace would otherwise be a legal path that
//! lands outside it.

use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};

use crate::store;

/// Cap on a single file read, matching the HTTP body cap: projects read
/// records and tokens, and a misaimed path should fail rather than pull an
/// arbitrarily large file into memory.
const MAX_READ: u64 = 8 * 1024 * 1024;

/// The one directory projects may touch.
pub fn workspace() -> Result<PathBuf> {
    let dir = store::config_root()?.join("automation-files");
    std::fs::create_dir_all(&dir).with_context(|| {
        format!(
            "the automation workspace {} could not be created",
            dir.display()
        )
    })?;
    Ok(dir)
}

/// Resolve a project-supplied path to a real path inside the workspace.
///
/// Rejects absolute paths, parent traversal, Windows drive and UNC prefixes,
/// and symlinks. The containment check runs on the normalised result, so a
/// path that only escapes once resolved is caught.
fn resolve(rel: &str) -> Result<PathBuf> {
    if rel.trim().is_empty() {
        bail!("a file path is required");
    }

    // A Windows path is only made of components on Windows: parsed on Linux,
    // `C:\Windows\System32` is one ordinary file name, backslashes and all,
    // so the component walk below would wave it through. Reject the two
    // Windows spellings by hand, on every platform, before parsing.
    if rel.contains('\\') {
        bail!("a file path must use '/' and stay inside the automation workspace: {rel}");
    }
    let names_a_drive = {
        let b = rel.as_bytes();
        b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
    };
    if names_a_drive {
        bail!("a file path must be relative to the automation workspace: {rel}");
    }

    let candidate = Path::new(rel);
    for part in candidate.components() {
        match part {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir => {
                bail!("a file path may not contain '..': {rel}")
            }
            // `C:\`, `\\server\share`, and a leading `/` all leave the
            // workspace by construction.
            Component::RootDir | Component::Prefix(_) => {
                bail!("a file path must be relative to the automation workspace: {rel}")
            }
        }
    }

    // Build the path from the *canonical* root so the comparison below is
    // between two paths of the same form. On Windows `canonicalize` returns a
    // `\\?\C:\...` extended-length path, so mixing a canonical root with a
    // plain one makes every containment check fail.
    let root = workspace()?;
    let canonical_root = root.canonicalize().unwrap_or_else(|_| root.clone());

    let mut normalised = canonical_root.clone();
    for part in candidate.components() {
        if let Component::Normal(p) = part {
            normalised.push(p);
        }
    }

    // Only an existing path can be canonicalised, and that is exactly the case
    // that needs re-checking: a link or junction already on disk is the one
    // way an in-workspace name resolves somewhere else. A path that does not
    // exist yet is contained by construction, having been built from the root
    // out of `Normal` components only.
    if let Ok(real) = normalised.canonicalize() {
        if !real.starts_with(&canonical_root) {
            bail!("a file path must stay inside the automation workspace: {rel}");
        }
    }

    // A symlink is a legal in-workspace path that can point anywhere, so
    // refuse rather than follow it.
    if let Ok(meta) = std::fs::symlink_metadata(&normalised) {
        if meta.file_type().is_symlink() {
            bail!("{rel} is a link; links are not followed inside the workspace");
        }
    }

    Ok(normalised)
}

/// Resolve a database name to a path inside the workspace.
///
/// Databases are subject to the same containment rules as files -- they are
/// files -- but SQLite opens them by path itself, so the check has to be
/// available separately from the read and write helpers.
pub fn resolve_for_db(rel: &str) -> Result<PathBuf> {
    resolve(rel)
}

/// Read a file from the workspace.
pub fn read(rel: &str) -> Result<String> {
    let path = resolve(rel)?;

    let meta = std::fs::metadata(&path)
        .with_context(|| format!("{rel} could not be read from the automation workspace"))?;
    if meta.len() > MAX_READ {
        bail!(
            "{rel} is {} bytes, larger than the {MAX_READ} byte limit for a project file",
            meta.len()
        );
    }

    std::fs::read_to_string(&path).with_context(|| format!("{rel} is not valid UTF-8 text"))
}

/// Write a file in the workspace, replacing what was there.
pub fn write(rel: &str, contents: &str) -> Result<()> {
    let path = resolve(rel)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("the folder for {rel} could not be created"))?;
    }
    std::fs::write(&path, contents).with_context(|| format!("{rel} could not be written"))
}

/// Append a line to a file in the workspace, creating it when absent.
///
/// This is the shape a run log wants: each processed item recorded as it
/// happens, so a run that dies half way still says what it did.
pub fn append(rel: &str, contents: &str) -> Result<()> {
    use std::io::Write as _;

    let path = resolve(rel)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("the folder for {rel} could not be created"))?;
    }

    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("{rel} could not be opened for appending"))?;
    f.write_all(contents.as_bytes())
        .with_context(|| format!("{rel} could not be appended to"))?;
    Ok(())
}

/// Does a file exist in the workspace?
pub fn exists(rel: &str) -> Result<bool> {
    Ok(resolve(rel)?.is_file())
}

/// Remove a file from the workspace. Missing is not an error.
pub fn remove(rel: &str) -> Result<()> {
    let path = resolve(rel)?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow!(e)).with_context(|| format!("{rel} could not be removed")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> (std::sync::MutexGuard<'static, ()>, tempfile::TempDir) {
        // The store-wide lock, not a private one: other test modules swap the
        // same global root.
        let guard = store::config_root_test_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().expect("a scratch config root");
        store::set_config_root(Some(dir.path().to_path_buf()));
        (guard, dir)
    }

    #[test]
    fn a_file_written_by_a_project_reads_back() {
        let (_g, _d) = scratch();
        write("run/accounts.txt", "alice\nbob\n").unwrap();
        assert_eq!(read("run/accounts.txt").unwrap(), "alice\nbob\n");
    }

    #[test]
    fn appending_keeps_what_was_already_there() {
        // A run log that overwrote itself each step would report only the
        // last item rather than everything done before a crash.
        let (_g, _d) = scratch();
        append("log.txt", "one\n").unwrap();
        append("log.txt", "two\n").unwrap();
        assert_eq!(read("log.txt").unwrap(), "one\ntwo\n");
    }

    #[test]
    fn a_project_cannot_climb_out_of_the_workspace() {
        // The attack this blocks: a shared project whose path walks up into
        // the launcher's own config and rewrites it.
        let (_g, _d) = scratch();
        for path in [
            "../profiles/stolen.json",
            "a/../../escape.txt",
            "./../../escape.txt",
        ] {
            let e = write(path, "x").unwrap_err();
            assert!(
                format!("{e:#}").contains(".."),
                "{path} should be refused for traversal, got: {e:#}"
            );
        }
    }

    #[test]
    fn a_project_cannot_name_an_absolute_path() {
        let (_g, _d) = scratch();
        // Windows spellings must be refused on Linux too: a path is only
        // parsed into components by the host's rules, so `C:\...` reaches a
        // Linux build as one ordinary file name unless it is refused by hand.
        for path in [
            "/etc/passwd",
            r"C:\Windows\System32\drivers\etc\hosts",
            r"c:/Windows/System32/drivers/etc/hosts",
            r"\\server\share\file.txt",
            r"notes\..\..\escape.txt",
        ] {
            assert!(
                write(path, "x").is_err(),
                "{path} should be refused as absolute"
            );
        }
    }

    #[test]
    fn writes_land_inside_the_workspace_and_nowhere_else() {
        // Proves containment by looking at the filesystem, not just at the
        // error type: a rule that accepted the path but wrote elsewhere would
        // pass the rejection tests above.
        let (_g, dir) = scratch();
        write("nested/deep/file.txt", "here").unwrap();

        let expected = dir.path().join("automation-files/nested/deep/file.txt");
        assert!(
            expected.is_file(),
            "the file should be under the workspace: {}",
            expected.display()
        );
    }

    #[test]
    fn reading_a_file_that_is_not_there_fails_naming_it() {
        let (_g, _d) = scratch();
        let e = read("missing.txt").unwrap_err();
        assert!(format!("{e:#}").contains("missing.txt"));
    }

    #[test]
    fn removing_a_file_that_is_not_there_is_fine() {
        // Cleanup blocks run on paths where the file may never have been
        // created.
        let (_g, _d) = scratch();
        assert!(remove("never-existed.txt").is_ok());
    }

    #[test]
    fn a_link_inside_the_workspace_is_not_followed() {
        // A link is a legal in-workspace path that resolves anywhere, so it
        // would otherwise defeat every check above.
        let (_g, dir) = scratch();
        let root = workspace().unwrap();
        let outside = dir.path().join("outside.txt");
        std::fs::write(&outside, "secret").unwrap();

        #[cfg(windows)]
        let made = std::os::windows::fs::symlink_file(&outside, root.join("link.txt")).is_ok();
        #[cfg(not(windows))]
        let made = std::os::unix::fs::symlink(&outside, root.join("link.txt")).is_ok();

        if !made {
            // Unprivileged Windows cannot create links; nothing to prove.
            return;
        }
        assert!(
            read("link.txt").is_err(),
            "a link should not be read through"
        );
    }
}
