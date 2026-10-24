use crate::store;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Settings {
    /// Absolute path to the ShardX executable.
    pub browser_path: Option<String>,
    /// Theme: "dark" (default) or "light".
    #[serde(default = "default_theme")]
    pub theme: String,
    /// Geo-IP checker provider used by the proxy "Test" button.
    /// One of "ip-api.com" | "ipapi.co" | "ipwho.is".
    #[serde(default)]
    pub geo_checker: Option<String>,
    /// "fingerprint" (use the screen from the bound fingerprint) or
    /// "real" (let ShardX use the host's real screen).
    #[serde(default)]
    pub screen_resolution_mode: Option<String>,
    /// Offer to fill fields a generated identity fits. Never applies to a
    /// synchronised launch — input is already mirrored there.
    #[serde(default = "default_true")]
    pub helper_enabled: bool,
    /// Profile's camera is ShardX's rather than the machine's. On by default:
    /// the host's real camera contradicts the fingerprint and links profiles.
    #[serde(default = "default_true")]
    pub camera_enabled: bool,
    /// Field kinds the helper reacts to, as the engine names them. Empty = all.
    #[serde(default)]
    pub helper_triggers: Vec<String>,
    /// Hide the launcher to the system tray on close instead of quitting.
    #[serde(default = "default_minimize_to_tray")]
    pub minimize_to_tray: bool,
    /// Register the Launcher for the current user's desktop login.
    #[serde(default)]
    pub launch_at_login: bool,
    /// Keep the main window hidden when it was launched by the startup entry.
    #[serde(default = "default_start_minimized")]
    pub start_minimized: bool,
    /// True when the payload actually carried the two startup fields above.
    /// Serde cannot tell "absent" from "false" for a plain bool, and a save
    /// that omits them must leave the login registration alone rather than
    /// read the defaults as a request to turn it off. Never stored.
    #[serde(default, skip_serializing)]
    pub startup_fields_present: bool,
    /// Appended to every launch, one per line. Applied last, so a repeat wins.
    #[serde(default)]
    pub extra_args: String,
    /// Where profiles, user-data, extensions and the trash live. None = the
    /// config dir. Changed through `data_root_migrate`, never by hand.
    #[serde(default)]
    pub data_root: Option<String>,

    // ---- Local automation HTTP API (axum + JWT bearer) ----
    /// Whether the local API server listens on 127.0.0.1:`api_port`.
    #[serde(default = "default_api_enabled")]
    pub api_enabled: bool,
    /// Port the API binds on 127.0.0.1.
    #[serde(default = "default_api_port")]
    pub api_port: u16,
    /// HS256 signing key for API JWTs.  Auto-generated on first run
    /// (see `ensure_secret`); rotating it invalidates issued tokens.
    #[serde(default)]
    pub api_secret: String,
    /// Last downloaded MCP server folder, if any.
    #[serde(default)]
    pub mcp_path: Option<String>,
}

fn default_true() -> bool {
    true
}

fn default_theme() -> String {
    "dark".into()
}

fn default_minimize_to_tray() -> bool {
    true
}

fn default_start_minimized() -> bool {
    true
}

fn default_api_enabled() -> bool {
    true
}

fn default_api_port() -> u16 {
    40325
}

/// Why the settings file could not be read this run, or None while it reads.
static LOAD_ERROR: Mutex<Option<String>> = Mutex::new(None);

/// The secret minted for a run whose settings file could not be read. Held
/// because `ensure_secret` runs more than once -- at startup for the server and
/// again whenever the UI asks for a token -- and a fresh one each time would
/// hand out tokens the running server rejects.
static RUN_SECRET: Mutex<Option<String>> = Mutex::new(None);

/// What a fresh install starts with.
pub fn defaults() -> Settings {
    Settings {
        browser_path: None,
        theme: default_theme(),
        geo_checker: Some("ip-api.com".into()),
        screen_resolution_mode: Some("fingerprint".into()),
        helper_enabled: default_true(),
        camera_enabled: default_true(),
        helper_triggers: Vec::new(),
        minimize_to_tray: default_minimize_to_tray(),
        launch_at_login: false,
        start_minimized: default_start_minimized(),
        startup_fields_present: false,
        extra_args: String::new(),
        data_root: None,
        api_enabled: default_api_enabled(),
        api_port: default_api_port(),
        api_secret: String::new(),
        mcp_path: None,
    }
}

/// Read the file as text whatever wrote it. `Set-Content -Encoding UTF8` puts a
/// byte-order mark in front of UTF-8 and a plain PowerShell `>` writes UTF-16;
/// both used to be a parse failure. Ported from upstream 6c3f65a.
fn decode_text(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xFF, 0xFE]) || bytes.starts_with(&[0xFE, 0xFF]) {
        let big_endian = bytes[0] == 0xFE;
        let units: Vec<u16> = bytes[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| {
                if big_endian {
                    u16::from_be_bytes([c[0], c[1]])
                } else {
                    u16::from_le_bytes([c[0], c[1]])
                }
            })
            .collect();
        return String::from_utf16_lossy(&units);
    }
    let body = String::from_utf8_lossy(bytes).into_owned();
    body.strip_prefix('\u{feff}')
        .map(str::to_owned)
        .unwrap_or(body)
}

/// Why the settings file could not be read, or None while it reads fine.
pub fn load_error() -> Option<String> {
    LOAD_ERROR.lock().ok().and_then(|g| g.clone())
}

fn set_load_error(msg: Option<String>) {
    if let Ok(mut g) = LOAD_ERROR.lock() {
        *g = msg;
    }
}

pub fn load() -> Result<Settings> {
    let path = store::settings_path()?;
    if !path.exists() {
        set_load_error(None);
        return Ok(defaults());
    }
    let body = decode_text(&fs::read(&path)?);
    match serde_json::from_str::<Settings>(&body) {
        Ok(s) => {
            set_load_error(None);
            Ok(s)
        }
        Err(e) => {
            // Defaults for this run only. They used to be `Default`, with port 0
            // and the API off, and the first save wrote them over the file: one
            // stray byte lost the data root (where every profile lives), the
            // MCP path and the API secret. `save` now refuses instead.
            let msg = format!("{}: {e}", path.display());
            eprintln!("[launcher] settings could not be read, running on defaults: {msg}");
            set_load_error(Some(msg));
            Ok(defaults())
        }
    }
}

/// Load settings, generating + persisting the API JWT secret if it's
/// still empty.  Call once at startup before the server reads it.
pub fn ensure_secret() -> Result<Settings> {
    let mut s = load()?;
    if !s.api_secret.is_empty() {
        return Ok(s);
    }
    let secret = || {
        format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        )
    };
    // An unreadable file may well hold a working secret; writing a new one over
    // it would sign out every API client. Use one for this run only.
    if load_error().is_some() {
        let mut g = RUN_SECRET.lock().unwrap_or_else(|p| p.into_inner());
        s.api_secret = g.get_or_insert_with(secret).clone();
        return Ok(s);
    }
    s.api_secret = secret();
    save(&s)?;
    Ok(s)
}

/// Split into switches on whitespace; quoted runs survive.
pub fn parse_extra_args(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    for ch in raw.chars() {
        match (quote, ch) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => cur.push(c),
            (None, c @ ('"' | '\'')) => quote = Some(c),
            (None, c) if c.is_whitespace() => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            (None, c) => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

pub fn save(s: &Settings) -> Result<()> {
    // Every caller saves a struct that started from `load`; while the file is
    // unreadable that struct is defaults, and writing it would destroy the only
    // copy of what the operator configured.
    if let Some(err) = load_error() {
        anyhow::bail!(crate::errcode::code_with(
            "settings.unreadable",
            &[("detail", &err)]
        ));
    }
    let body = serde_json::to_string_pretty(s)?;
    fs::write(store::settings_path()?, body)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_settings_gain_safe_startup_defaults() {
        let parsed: Settings = serde_json::from_str(
            r#"{
                "browser_path": null,
                "theme": "dark",
                "minimize_to_tray": true,
                "api_enabled": true,
                "api_port": 40325
            }"#,
        )
        .expect("parse legacy settings");

        assert!(!parsed.launch_at_login);
        assert!(parsed.start_minimized);
        assert!(parsed.api_enabled);
    }

    fn scratch() -> (std::sync::MutexGuard<'static, ()>, tempfile::TempDir) {
        let guard = store::config_root_test_lock()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().expect("a scratch config root");
        store::set_config_root(Some(dir.path().to_path_buf()));
        (guard, dir)
    }

    #[test]
    fn an_unreadable_file_is_never_written_over() {
        let (_g, _dir) = scratch();
        let path = store::settings_path().unwrap();
        let broken = r#"{"data_root": "D:\\profiles", "api_secret": "kept","#;
        fs::write(&path, broken).unwrap();

        let s = load().unwrap();
        assert!(load_error().is_some());
        // Real defaults for the run, not `Default`'s port 0 with the API off.
        assert_eq!(s.api_port, 40325);
        assert!(s.api_enabled);

        let first = ensure_secret().unwrap().api_secret;
        assert!(!first.is_empty());
        assert_eq!(
            ensure_secret().unwrap().api_secret,
            first,
            "one secret per run"
        );
        assert!(save(&s).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), broken);

        // Fixed by hand: it reads again and saves again.
        fs::write(&path, "{}").unwrap();
        load().unwrap();
        assert!(load_error().is_none());
        assert!(save(&defaults()).is_ok());
        store::set_config_root(None);
    }

    #[test]
    fn a_byte_order_mark_or_utf16_still_reads() {
        assert_eq!(decode_text(b"\xEF\xBB\xBF{}"), "{}");
        let utf16: Vec<u8> = [0xFF, 0xFE]
            .into_iter()
            .chain("{}".encode_utf16().flat_map(u16::to_le_bytes))
            .collect();
        assert_eq!(decode_text(&utf16), "{}");
    }
}
