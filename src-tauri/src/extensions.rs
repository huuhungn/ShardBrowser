//! Extension library. Name, description and icon are read out of the extension
//! itself, so the grid matches what the browser will load.

use crate::errcode;
use crate::store;
use anyhow::{Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionEntry {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    /// Largest icon the manifest declares, as a `data:` URL. Empty when the
    /// extension ships none.
    pub icon: String,
    /// Unpacked directory handed to `--load-extension`.
    pub path: String,
    pub size_bytes: u64,
    /// "@<unix_secs>", same marker profiles use.
    pub added_at: String,
}

fn dir_for(id: &str) -> Result<PathBuf> {
    if id.is_empty() || id.contains(['/', '\\', '.']) {
        anyhow::bail!("{}", errcode::code("extensions.invalidId"));
    }
    Ok(store::extensions_dir()?.join(id))
}

/// `--load-extension` wants the directory holding manifest.json. A .crx often
/// unpacks with everything under one top-level folder; follow that down.
fn manifest_root(dir: &Path) -> PathBuf {
    if dir.join("manifest.json").exists() {
        return dir.to_path_buf();
    }
    if let Ok(rd) = fs::read_dir(dir) {
        let subs: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect();
        if subs.len() == 1 && subs[0].join("manifest.json").exists() {
            return subs[0].clone();
        }
    }
    dir.to_path_buf()
}

pub fn list() -> Result<Vec<ExtensionEntry>> {
    let root = store::extensions_dir()?;
    let mut out = Vec::new();
    for entry in fs::read_dir(&root)? {
        let entry = entry?;
        if !entry.path().is_dir() {
            continue;
        }
        let id = entry.file_name().to_string_lossy().to_string();
        if let Ok(e) = read_entry(&id) {
            out.push(e);
        }
    }
    out.sort_by_key(|a| a.name.to_lowercase());
    Ok(out)
}

/// Directory to hand `--load-extension`, or None when the id is unknown.
pub fn load_path(id: &str) -> Option<PathBuf> {
    let dir = dir_for(id).ok()?;
    let root = manifest_root(&dir);
    root.join("manifest.json").exists().then_some(root)
}

fn read_entry(id: &str) -> Result<ExtensionEntry> {
    let dir = dir_for(id)?;
    let root = manifest_root(&dir);
    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(root.join("manifest.json"))?)?;
    let msgs = locale_messages(&root, &manifest);
    let sv = |key: &str| -> String {
        resolve_msg(
            manifest.get(key).and_then(|v| v.as_str()).unwrap_or(""),
            &msgs,
        )
    };
    let added_at = fs::read_to_string(dir.join(".added"))
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    Ok(ExtensionEntry {
        id: id.to_string(),
        name: {
            let n = sv("name");
            if n.is_empty() {
                id.to_string()
            } else {
                n
            }
        },
        version: sv("version"),
        description: sv("description"),
        icon: best_icon(&root, &manifest).unwrap_or_default(),
        path: root.display().to_string(),
        size_bytes: dir_size(&dir),
        added_at,
    })
}

/// `__MSG_key__` placeholders, resolved against the default locale's
/// messages.json — Chrome Web Store extensions name themselves that way, and
/// without this the grid would read "__MSG_appName__".
fn locale_messages(root: &Path, manifest: &serde_json::Value) -> serde_json::Value {
    let Some(loc) = manifest.get("default_locale").and_then(|v| v.as_str()) else {
        return serde_json::Value::Null;
    };
    let p = root.join("_locales").join(loc).join("messages.json");
    fs::read_to_string(p)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(serde_json::Value::Null)
}

fn resolve_msg(raw: &str, msgs: &serde_json::Value) -> String {
    let Some(key) = raw
        .strip_prefix("__MSG_")
        .and_then(|r| r.strip_suffix("__"))
    else {
        return raw.to_string();
    };
    msgs.get(key)
        .and_then(|v| v.get("message"))
        .and_then(|v| v.as_str())
        .unwrap_or(raw)
        .to_string()
}

/// Largest declared icon as a data: URL. MV2 puts them under `icons`, MV3 the
/// same, and some extensions only carry an action icon — try all three.
fn best_icon(root: &Path, manifest: &serde_json::Value) -> Option<String> {
    fn largest(map: &serde_json::Value, best: &mut Option<(u64, String)>) {
        let Some(obj) = map.as_object() else { return };
        for (k, v) in obj {
            let Some(rel) = v.as_str() else { continue };
            let size: u64 = k.parse().unwrap_or(0);
            if best.as_ref().map(|(s, _)| size > *s).unwrap_or(true) {
                *best = Some((size, rel.to_string()));
            }
        }
    }

    let mut best: Option<(u64, String)> = None;
    if let Some(v) = manifest.get("icons") {
        largest(v, &mut best);
    }
    if best.is_none() {
        for key in ["action", "browser_action", "page_action"] {
            let Some(v) = manifest.get(key).and_then(|a| a.get("default_icon")) else {
                continue;
            };
            match v.as_str() {
                Some(s) => best = Some((0, s.to_string())),
                None => largest(v, &mut best),
            }
        }
    }
    let (_, rel) = best?;
    let path = root.join(rel.trim_start_matches('/'));
    let bytes = fs::read(&path).ok()?;
    let mime = match path.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "svg" => "image/svg+xml",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        _ => "image/png",
    };
    Some(format!(
        "data:{mime};base64,{}",
        base64::engine::general_purpose::STANDARD.encode(bytes)
    ))
}

fn dir_size(dir: &Path) -> u64 {
    let mut total = 0;
    let Ok(rd) = fs::read_dir(dir) else { return 0 };
    for e in rd.flatten() {
        match e.file_type() {
            Ok(t) if t.is_dir() => total += dir_size(&e.path()),
            Ok(_) => total += e.metadata().map(|m| m.len()).unwrap_or(0),
            Err(_) => {}
        }
    }
    total
}

/// Import a .crx, a .zip or an already-unpacked folder. Returns the new entry.
pub fn import(src: &Path) -> Result<ExtensionEntry> {
    let id = uuid::Uuid::new_v4().simple().to_string();
    let dst = dir_for(&id)?;
    fs::create_dir_all(&dst)?;

    let res = if src.is_dir() {
        copy_dir(src, &dst)
    } else {
        unpack_archive(src, &dst)
    };
    if let Err(e) = res {
        let _ = fs::remove_dir_all(&dst);
        return Err(e);
    }
    if !manifest_root(&dst).join("manifest.json").exists() {
        let _ = fs::remove_dir_all(&dst);
        anyhow::bail!("{}", errcode::code("extensions.noManifest"));
    }
    let _ = fs::write(
        dst.join(".added"),
        format!(
            "@{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        ),
    );
    read_entry(&id)
}

/// Import from a Web Store page, a bare extension id, or a direct .crx / .zip
/// URL. A store page is not the file, so the id is pulled out and the download
/// built from it.
pub async fn import_url(raw: &str) -> Result<ExtensionEntry> {
    let url = resolve_download_url(raw)?;
    let client = reqwest::Client::builder()
        .user_agent(format!(
            "Mozilla/5.0 Chrome/{}",
            crate::runtime::CHROMIUM_VERSION
        ))
        .build()?;
    let resp = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("fetch {url}"))?;
    let status = resp.status();
    // The store answers 204 for an id it does not know rather than 404.
    if status == reqwest::StatusCode::NO_CONTENT {
        anyhow::bail!("{}", errcode::code("extensions.notInWebStore"));
    }
    let resp = resp
        .error_for_status()
        .with_context(|| format!("fetch {url}"))?;
    let bytes = resp.bytes().await?;
    if bytes.len() < 4 {
        anyhow::bail!("{}", errcode::code("extensions.emptyDownload"));
    }
    // Say so before unzip does: a page that 200s with HTML is the usual mistake.
    if bytes.starts_with(b"<") {
        anyhow::bail!("{}", errcode::code("extensions.linkIsWebPage"));
    }

    let tmp =
        std::env::temp_dir().join(format!("shardx-ext-{}.crx", uuid::Uuid::new_v4().simple()));
    fs::write(&tmp, &bytes)?;
    let out = import(&tmp);
    let _ = fs::remove_file(&tmp);
    out
}

/// Web Store address or bare id → the update endpoint that serves the .crx.
/// Anything else is taken as a direct link to the file.
fn resolve_download_url(raw: &str) -> Result<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        anyhow::bail!("{}", errcode::code("extensions.noLink"));
    }
    if let Some(id) = webstore_id(raw) {
        return Ok(format!(
            "https://clients2.google.com/service/update2/crx?response=redirect&acceptformat=crx2,crx3&prodversion={}&x=id%3D{}%26uc",
            crate::runtime::CHROMIUM_VERSION,
            id,
        ));
    }
    if !raw.starts_with("http://") && !raw.starts_with("https://") {
        anyhow::bail!("{}", errcode::code("extensions.neitherLinkNorId"));
    }
    Ok(raw.to_string())
}

/// Extension ids are 32 characters of a-p. Accepts a bare id, or picks it out
/// of either shape of Web Store address.
fn webstore_id(raw: &str) -> Option<String> {
    let is_id = |s: &str| s.len() == 32 && s.bytes().all(|b| (b'a'..=b'p').contains(&b));
    if is_id(raw) {
        return Some(raw.to_string());
    }
    if !raw.contains("chromewebstore.google.com") && !raw.contains("chrome.google.com/webstore") {
        return None;
    }
    raw.split(&['/', '?', '#'][..])
        .find(|seg| is_id(seg))
        .map(|s| s.to_string())
}

pub fn delete(id: &str) -> Result<()> {
    let dir = dir_for(id)?;
    if dir.exists() {
        fs::remove_dir_all(dir)?;
    }
    Ok(())
}

/// A .crx is a header followed by a plain zip; strip the header and unzip.
fn unpack_archive(src: &Path, dst: &Path) -> Result<()> {
    let bytes = fs::read(src).with_context(|| format!("read {}", src.display()))?;
    let zip_start = crx_payload_offset(&bytes)?;
    let cursor = std::io::Cursor::new(&bytes[zip_start..]);
    let mut zip = zip::ZipArchive::new(cursor).context(errcode::code("extensions.notAnArchive"))?;
    for i in 0..zip.len() {
        let mut f = zip.by_index(i)?;
        let Some(rel) = f.enclosed_name() else {
            continue;
        };
        let out = dst.join(rel);
        if f.is_dir() {
            fs::create_dir_all(&out)?;
            continue;
        }
        if let Some(parent) = out.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut buf = Vec::with_capacity(f.size() as usize);
        f.read_to_end(&mut buf)?;
        fs::write(&out, buf)?;
    }
    Ok(())
}

/// Byte offset of the zip inside a .crx (0 for a plain .zip).
fn crx_payload_offset(bytes: &[u8]) -> Result<usize> {
    if bytes.len() < 16 || &bytes[0..4] != b"Cr24" {
        return Ok(0);
    }
    let u32_at = |i: usize| -> u32 {
        u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]])
    };
    let offset = match u32_at(4) {
        2 => 16 + u32_at(8) as usize + u32_at(12) as usize,
        3 => 12 + u32_at(8) as usize,
        v => anyhow::bail!(
            "{}",
            errcode::code_with("extensions.crxVersionUnsupported", &[("v", &v.to_string())])
        ),
    };
    if offset >= bytes.len() {
        anyhow::bail!("{}", errcode::code("extensions.crxHeaderTruncated"));
    }
    Ok(offset)
}

fn copy_dir(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let to = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &to)?;
        } else {
            fs::copy(entry.path(), &to)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    /// The download URL must come out as one unbroken string. It was once
    /// written with a line continuation and shipped with the indentation still
    /// in it, which the store answered with a 404.
    #[test]
    fn webstore_url_has_no_whitespace() {
        let id = "acmacodkjbdgmoleebolmdjonilkdbch";
        for raw in [
            id,
            "https://chromewebstore.google.com/detail/rabby-wallet/acmacodkjbdgmoleebolmdjonilkdbch",
            "https://chromewebstore.google.com/detail/rabby-wallet/acmacodkjbdgmoleebolmdjonilkdbch?hl=en",
            "https://chrome.google.com/webstore/detail/rabby-wallet/acmacodkjbdgmoleebolmdjonilkdbch",
        ] {
            let u = super::resolve_download_url(raw).unwrap();
            assert!(!u.contains(char::is_whitespace), "whitespace in {u}");
            assert!(u.starts_with("https://clients2.google.com/service/update2/crx?"), "{u}");
            assert!(u.ends_with(&format!("x=id%3D{id}%26uc")), "{u}");
        }
    }

    #[test]
    fn direct_links_pass_through() {
        assert_eq!(
            super::resolve_download_url("https://example.com/a.crx").unwrap(),
            "https://example.com/a.crx"
        );
        assert!(super::resolve_download_url("not a link").is_err());
        assert!(super::resolve_download_url("").is_err());
    }
}
