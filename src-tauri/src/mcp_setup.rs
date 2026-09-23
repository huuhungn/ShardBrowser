// Download the MCP server source from the matching custom fork release into a user-chosen
// folder.  The app does NOT run or manage it — the user installs deps
// + registers it with their MCP client themselves (see
// rust/shardx-launcher/mcp/README.md).
//
// The bundle ships pre-packed at ~12 KB (just index.js + package.json
// + README.md), so the download is instant and contains no
// node_modules / .gitignore noise.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Public release asset for this exact Launcher version. The browser runtime
/// remains on its upstream CDN; only the MCP helper bundle follows the fork.
/// Pinning the tag prevents an older Launcher from downloading a future MCP
/// bundle that may require a newer Automation API.
const MCP_ARCHIVE_URL: &str = concat!(
    "https://github.com/huuhungn/ShardBrowser/releases/download/v",
    env!("CARGO_PKG_VERSION"),
    "/ShardX-MCP.tar.gz"
);

/// Top-level directory inside the tarball that wraps the actual files.
const MCP_TOP_DIR: &str = "ShardX-MCP";

fn download_destination(dir: &Path) -> PathBuf {
    // The picker text says "choose a folder" while the status box shows the
    // actual `mcp` folder. If the user repairs by selecting that shown folder,
    // update it in place instead of creating `mcp/mcp`.
    if is_mcp_dir(dir) || dir.file_name().is_some_and(|name| name == "mcp") {
        dir.to_path_buf()
    } else {
        dir.join("mcp")
    }
}

/// Download the MCP server into `<dir>/mcp` and return that path.
///
/// If `<dir>` already is the MCP folder, repair/update it in place.
pub async fn download_mcp(dir: &Path) -> Result<PathBuf> {
    let dest = download_destination(dir);
    let bytes = reqwest::get(MCP_ARCHIVE_URL)
        .await
        .context("download MCP archive")?
        .error_for_status()
        .context("MCP archive request failed")?
        .bytes()
        .await
        .context("read MCP archive")?;

    let gz = flate2::read::GzDecoder::new(&bytes[..]);
    let mut archive = tar::Archive::new(gz);
    std::fs::create_dir_all(&dest)?;
    let mut extracted = 0usize;

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        // Strip the single top-level wrapper dir ("ShardX-MCP/") so files
        // land directly under dest/.
        let rel: PathBuf = path
            .strip_prefix(MCP_TOP_DIR)
            .unwrap_or(&path)
            .to_path_buf();
        if rel.as_os_str().is_empty() {
            continue;
        }
        let out = dest.join(&rel);
        if entry.header().entry_type().is_dir() {
            std::fs::create_dir_all(&out)?;
        } else {
            if let Some(parent) = out.parent() {
                std::fs::create_dir_all(parent)?;
            }
            entry.unpack(&out)?;
            extracted += 1;
        }
    }
    if extracted == 0 {
        anyhow::bail!("MCP archive contained no files (CDN delivered an empty bundle?)");
    }
    Ok(dest)
}

pub fn is_mcp_dir(dir: &Path) -> bool {
    if !dir.join("index.js").is_file() || !dir.join("package.json").is_file() {
        return false;
    }
    std::fs::read_to_string(dir.join("package.json"))
        .map(|s| s.contains("\"shardx-mcp\""))
        .unwrap_or(false)
}

pub fn package_version(dir: &Path) -> Option<String> {
    let body = std::fs::read_to_string(dir.join("package.json")).ok()?;
    let package = serde_json::from_str::<serde_json::Value>(&body).ok()?;
    package.get("version")?.as_str().map(str::to_owned)
}

/// True when every runtime dependency declared by the downloaded MCP package
/// has a package manifest under node_modules. This intentionally checks the
/// package's own dependency list so future archive updates do not require a
/// matching Launcher code change.
pub fn dependencies_installed(dir: &Path) -> bool {
    if !is_mcp_dir(dir) {
        return false;
    }
    let Ok(body) = std::fs::read_to_string(dir.join("package.json")) else {
        return false;
    };
    let Ok(package) = serde_json::from_str::<serde_json::Value>(&body) else {
        return false;
    };
    let Some(dependencies) = package.get("dependencies").and_then(|v| v.as_object()) else {
        return false;
    };
    !dependencies.is_empty()
        && dependencies.keys().all(|name| {
            dir.join("node_modules")
                .join(Path::new(name))
                .join("package.json")
                .is_file()
        })
}

pub fn resolve_mcp_dir(dir: &Path) -> Option<PathBuf> {
    if is_mcp_dir(dir) {
        return Some(dir.to_path_buf());
    }
    let nested = dir.join("mcp");
    is_mcp_dir(&nested).then_some(nested)
}

pub fn find_existing_mcp() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(dir) = dirs::document_dir() {
        candidates.extend([
            dir.join("MCP").join("ShardBrowser").join("mcp"),
            dir.join("MCP").join("mcp"),
            dir.join("ShardBrowser").join("mcp"),
            dir.join("GitHub").join("ShardBrowser").join("mcp"),
            dir.join("mcp"),
        ]);
    }
    if let Some(dir) = dirs::download_dir() {
        candidates.push(dir.join("mcp"));
    }
    if let Some(dir) = dirs::desktop_dir() {
        candidates.push(dir.join("mcp"));
    }
    candidates.into_iter().find_map(|p| resolve_mcp_dir(&p))
}

#[cfg(test)]
mod tests {
    use super::{dependencies_installed, download_destination, is_mcp_dir, package_version};
    use std::path::Path;

    #[test]
    fn detects_downloaded_mcp_folder() {
        let dir = std::env::temp_dir().join(format!("shardx-mcp-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("index.js"), "").unwrap();
        std::fs::write(dir.join("package.json"), r#"{ "name": "shardx-mcp" }"#).unwrap();

        assert!(is_mcp_dir(&dir));
        assert_eq!(package_version(&dir), None);
        assert_eq!(super::resolve_mcp_dir(&dir).as_deref(), Some(dir.as_path()));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn download_destination_avoids_nested_mcp_when_repairing() {
        let base = std::env::temp_dir().join(format!(
            "shardx-mcp-destination-test-{}",
            std::process::id()
        ));
        let normal_parent = base.join("ShardBrowser");
        let existing_mcp = normal_parent.join("mcp");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&existing_mcp).unwrap();
        std::fs::write(existing_mcp.join("index.js"), "").unwrap();
        std::fs::write(
            existing_mcp.join("package.json"),
            r#"{ "name": "shardx-mcp" }"#,
        )
        .unwrap();

        assert_eq!(download_destination(&normal_parent), existing_mcp);
        assert_eq!(download_destination(&existing_mcp), existing_mcp);

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn detects_installed_runtime_dependencies() {
        let dir = std::env::temp_dir().join(format!(
            "shardx-mcp-dependencies-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("index.js"), "").unwrap();
        std::fs::write(
            dir.join("package.json"),
            r#"{
                "name": "shardx-mcp",
                "dependencies": {
                    "@modelcontextprotocol/sdk": "^1",
                    "patchright": "^1",
                    "zod": "^3"
                }
            }"#,
        )
        .unwrap();

        assert!(!dependencies_installed(&dir));
        for dependency in ["@modelcontextprotocol/sdk", "patchright", "zod"] {
            let package_dir = dir.join("node_modules").join(Path::new(dependency));
            std::fs::create_dir_all(&package_dir).unwrap();
            std::fs::write(package_dir.join("package.json"), "{}").unwrap();
        }
        assert!(dependencies_installed(&dir));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reads_downloaded_mcp_version() {
        let dir =
            std::env::temp_dir().join(format!("shardx-mcp-version-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("index.js"), "").unwrap();
        std::fs::write(
            dir.join("package.json"),
            r#"{ "name": "shardx-mcp", "version": "0.1.11" }"#,
        )
        .unwrap();

        assert_eq!(package_version(&dir).as_deref(), Some("0.1.11"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
