use serde_json::Value;
use std::process::Stdio;

use crate::{api, mcp_setup, settings};

fn normalize_cli_path(path: &str) -> String {
    let trimmed = path.trim().trim_matches('"').trim_matches('\'');
    let normalized = trimmed
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_string();
    #[cfg(windows)]
    {
        normalized.to_ascii_lowercase()
    }
    #[cfg(not(windows))]
    {
        normalized
    }
}

fn normalize_api_url(url: &str) -> String {
    url.trim().trim_end_matches('/').to_string()
}

fn expected_mcp_index_path(settings: &settings::Settings) -> Option<String> {
    let resolved = settings
        .mcp_path
        .as_deref()
        .and_then(|path| mcp_setup::resolve_mcp_dir(std::path::Path::new(path)))
        .or_else(mcp_setup::find_existing_mcp)?;
    Some(resolved.join("index.js").display().to_string())
}

fn expected_api_url(settings: &settings::Settings) -> String {
    let runtime = api::runtime_status();
    let port = runtime.port.unwrap_or(settings.api_port);
    format!("http://127.0.0.1:{port}")
}

/// Hermes `config get` prints the resolved value as a small YAML fragment.
/// Only the handful of shapes this entry can take are parsed here, which avoids
/// pulling a YAML crate into the build for one command.
///
/// Recognised shape:
///
/// ```yaml
/// command: C:/Program Files/nodejs/node.exe
/// args:
/// - C:/path/to/mcp/index.js
/// env:
///   SHARDX_API: http://127.0.0.1:40325
/// enabled: true
/// ```
fn parse_config_get_output(text: &str) -> Option<Value> {
    if text.trim().is_empty() || text.trim().starts_with("Config key not set") {
        return None;
    }

    let mut command: Option<String> = None;
    let mut args: Vec<Value> = Vec::new();
    let mut env = serde_json::Map::new();
    let mut enabled = true;
    let mut section = "";

    for raw in text.lines() {
        let line = raw.trim_end();
        if line.trim().is_empty() {
            continue;
        }

        let indented = line.starts_with(' ') || line.starts_with('-');
        if !indented {
            section = "";
        }

        if let Some(rest) = line.strip_prefix("command:") {
            command = Some(rest.trim().trim_matches('"').to_string());
        } else if line.starts_with("args:") {
            section = "args";
        } else if line.starts_with("env:") {
            section = "env";
        } else if let Some(rest) = line.strip_prefix("enabled:") {
            enabled = rest.trim() != "false";
        } else if section == "args" {
            if let Some(item) = line.trim().strip_prefix("- ") {
                args.push(Value::String(item.trim().trim_matches('"').to_string()));
            }
        } else if section == "env" {
            if let Some((key, value)) = line.trim().split_once(": ") {
                env.insert(
                    key.trim().to_string(),
                    Value::String(value.trim().trim_matches('"').to_string()),
                );
            }
        }
    }

    command.as_ref()?;

    Some(serde_json::json!({
        "enabled": enabled,
        "command": command,
        "args": Value::Array(args),
        "env": Value::Object(env),
    }))
}

fn hermes_mcp_status_from_entry(
    entry: &Value,
    expected_index_path: Option<String>,
    expected_api: String,
) -> Value {
    let enabled = entry
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let command = entry
        .get("command")
        .and_then(Value::as_str)
        .map(str::to_string);
    let index_path = entry
        .get("args")
        .and_then(Value::as_array)
        .and_then(|args| {
            args.iter().find_map(|arg| {
                let value = arg.as_str()?;
                let normalized = normalize_cli_path(value);
                if normalized.ends_with("\\index.js") || normalized.ends_with("/index.js") {
                    Some(value.to_string())
                } else {
                    None
                }
            })
        });
    let env = entry.get("env").and_then(Value::as_object);
    let configured_api = env
        .and_then(|env| env.get("SHARDX_API"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let token_in_config = env
        .and_then(|env| env.get("SHARDX_TOKEN"))
        .and_then(Value::as_str)
        .map(|value| !value.is_empty())
        .unwrap_or(false);

    let path_matches = expected_index_path.as_ref().and_then(|expected| {
        index_path
            .as_ref()
            .map(|actual| normalize_cli_path(actual) == normalize_cli_path(expected))
    });
    let api_matches = configured_api
        .as_ref()
        .map(|actual| normalize_api_url(actual) == normalize_api_url(&expected_api));

    let mut issues = Vec::new();
    if !enabled {
        issues.push("entry is disabled");
    }
    if path_matches == Some(false) {
        issues.push("index.js path does not match the selected MCP folder");
    }
    if path_matches.is_none() {
        issues.push("index.js path could not be verified");
    }
    if api_matches == Some(false) {
        issues.push("SHARDX_API does not match the current Automation API URL");
    }
    if api_matches.is_none() {
        issues.push("SHARDX_API is not configured");
    }
    if token_in_config {
        issues.push("SHARDX_TOKEN is stored in Hermes config");
    }

    let ready = issues.is_empty();
    let (state, message) = if ready {
        (
            "registered",
            "Hermes has a matching shardbrowser MCP entry. Restart Hermes, then run health_check.",
        )
    } else if !enabled {
        (
            "disabled",
            "Hermes has shardbrowser, but it is disabled. Repair or re-add the entry.",
        )
    } else {
        (
            "needs_repair",
            "Hermes shardbrowser exists but should be repaired: path/API/token placement needs attention.",
        )
    };

    serde_json::json!({
        "available": true,
        "registered": true,
        "enabled": enabled,
        "transport_type": "stdio",
        "command": command,
        "index_path": index_path,
        "expected_index_path": expected_index_path,
        "path_matches": path_matches,
        "api": configured_api,
        "expected_api": expected_api,
        "api_matches": api_matches,
        "token_in_config": token_in_config,
        "ready": ready,
        "state": state,
        "message": message,
        "issues": issues,
    })
}

fn hermes_not_registered_status(
    expected_index_path: Option<String>,
    expected_api: String,
) -> Value {
    serde_json::json!({
        "available": true,
        "registered": false,
        "enabled": false,
        "transport_type": null,
        "command": null,
        "index_path": null,
        "expected_index_path": expected_index_path,
        "path_matches": null,
        "api": null,
        "expected_api": expected_api,
        "api_matches": null,
        "token_in_config": false,
        "ready": false,
        "state": "not_registered",
        "message": "Hermes has no shardbrowser MCP entry yet. Use the add command, then restart Hermes.",
        "issues": ["shardbrowser is not registered with Hermes"],
    })
}

pub async fn status() -> Result<Value, String> {
    let s = settings::load().map_err(|e| e.to_string())?;
    let expected_index_path = expected_mcp_index_path(&s);
    let expected_api = expected_api_url(&s);

    let mut child = tokio::process::Command::new("hermes");
    child
        .args(["config", "get", "mcp_servers.shardbrowser"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let output = match tokio::time::timeout(std::time::Duration::from_secs(4), child.output()).await
    {
        Ok(Ok(output)) => output,
        Ok(Err(err)) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(serde_json::json!({
                "available": false,
                "registered": false,
                "enabled": false,
                "transport_type": null,
                "command": null,
                "index_path": null,
                "expected_index_path": expected_index_path,
                "path_matches": null,
                "api": null,
                "expected_api": expected_api,
                "api_matches": null,
                "token_in_config": false,
                "ready": false,
                "state": "hermes_not_found",
                "message": "Hermes was not found on PATH. Install/open Hermes, then run the add command.",
                "issues": ["hermes command not found"],
            }));
        }
        Ok(Err(_)) => {
            return Ok(serde_json::json!({
                "available": false,
                "registered": false,
                "enabled": false,
                "transport_type": null,
                "command": null,
                "index_path": null,
                "expected_index_path": expected_index_path,
                "path_matches": null,
                "api": null,
                "expected_api": expected_api,
                "api_matches": null,
                "token_in_config": false,
                "ready": false,
                "state": "unavailable",
                "message": "Hermes could not be started to read its MCP configuration.",
                "issues": ["hermes config get failed"],
            }));
        }
        Err(_) => {
            return Ok(serde_json::json!({
                "available": false,
                "registered": false,
                "enabled": false,
                "transport_type": null,
                "command": null,
                "index_path": null,
                "expected_index_path": expected_index_path,
                "path_matches": null,
                "api": null,
                "expected_api": expected_api,
                "api_matches": null,
                "token_in_config": false,
                "ready": false,
                "state": "timeout",
                "message": "Hermes did not answer within 4 seconds.",
                "issues": ["hermes config get timed out"],
            }));
        }
    };

    if !output.status.success() {
        return Ok(hermes_not_registered_status(
            expected_index_path,
            expected_api,
        ));
    }

    let text = String::from_utf8_lossy(&output.stdout);
    match parse_config_get_output(&text) {
        Some(entry) => Ok(hermes_mcp_status_from_entry(
            &entry,
            expected_index_path,
            expected_api,
        )),
        None => Ok(hermes_not_registered_status(
            expected_index_path,
            expected_api,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{hermes_mcp_status_from_entry, parse_config_get_output};

    const SAMPLE: &str = "command: C:/Program Files/nodejs/node.exe\nargs:\n- C:/Users/Administrator/Documents/MCP/ShardBrowser/mcp/index.js\nenv:\n  SHARDX_API: http://127.0.0.1:40325\nconnect_timeout: 60\ntimeout: 300\nenabled: true\n";

    #[test]
    fn parses_the_real_config_get_shape() {
        let entry = parse_config_get_output(SAMPLE).expect("entry parses");
        assert_eq!(
            entry["command"].as_str(),
            Some("C:/Program Files/nodejs/node.exe")
        );
        assert_eq!(entry["args"].as_array().map(Vec::len), Some(1));
        assert_eq!(
            entry["env"]["SHARDX_API"].as_str(),
            Some("http://127.0.0.1:40325")
        );
        assert_eq!(entry["enabled"].as_bool(), Some(true));
    }

    #[test]
    fn unset_key_is_not_an_entry() {
        assert!(parse_config_get_output("Config key not set: mcp_servers.shardbrowser").is_none());
        assert!(parse_config_get_output("   ").is_none());
    }

    #[test]
    fn matching_hermes_entry_is_registered_without_token_leak() {
        let entry = parse_config_get_output(SAMPLE).expect("entry parses");
        let status = hermes_mcp_status_from_entry(
            &entry,
            Some("C:/Users/Administrator/Documents/MCP/ShardBrowser/mcp/index.js".into()),
            "http://127.0.0.1:40325".into(),
        );

        assert_eq!(status["state"].as_str(), Some("registered"));
        assert_eq!(status["ready"].as_bool(), Some(true));
        assert_eq!(status["token_in_config"].as_bool(), Some(false));
    }

    #[test]
    fn token_in_config_needs_repair() {
        let entry = parse_config_get_output(
            "command: node\nargs:\n- C:/mcp/index.js\nenv:\n  SHARDX_API: http://127.0.0.1:40325\n  SHARDX_TOKEN: abc123\nenabled: true\n",
        )
        .expect("entry parses");
        let status = hermes_mcp_status_from_entry(
            &entry,
            Some("C:/mcp/index.js".into()),
            "http://127.0.0.1:40325".into(),
        );

        assert_eq!(status["state"].as_str(), Some("needs_repair"));
        assert_eq!(status["token_in_config"].as_bool(), Some(true));
        assert!(status["message"]
            .as_str()
            .unwrap_or_default()
            .contains("repair"));
    }

    #[test]
    fn disabled_entry_is_reported_as_disabled() {
        let entry = parse_config_get_output(
            "command: node\nargs:\n- C:/mcp/index.js\nenv:\n  SHARDX_API: http://127.0.0.1:40325\nenabled: false\n",
        )
        .expect("entry parses");
        let status = hermes_mcp_status_from_entry(
            &entry,
            Some("C:/mcp/index.js".into()),
            "http://127.0.0.1:40325".into(),
        );

        assert_eq!(status["state"].as_str(), Some("disabled"));
        assert_eq!(status["ready"].as_bool(), Some(false));
    }
}
