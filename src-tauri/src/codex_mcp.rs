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

fn codex_mcp_status_from_config(
    config: &Value,
    expected_index_path: Option<String>,
    expected_api: String,
) -> Value {
    let transport = config.get("transport").unwrap_or(&Value::Null);
    let enabled = config
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let transport_type = transport
        .get("type")
        .and_then(Value::as_str)
        .map(str::to_string);
    let command = transport
        .get("command")
        .and_then(Value::as_str)
        .map(str::to_string);
    let index_path = transport
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
    let env = transport.get("env").and_then(Value::as_object);
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
    if transport_type.as_deref() != Some("stdio") {
        issues.push("transport is not stdio");
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
        issues.push("SHARDX_TOKEN is stored in Codex config");
    }

    let ready = issues.is_empty();
    let (state, message) = if ready {
        (
            "registered",
            "Codex has a matching shardbrowser MCP entry. Restart Codex, then run health_check.",
        )
    } else if !enabled {
        (
            "disabled",
            "Codex has shardbrowser, but it is disabled. Repair or re-add the entry.",
        )
    } else if transport_type.as_deref() != Some("stdio") {
        (
            "unsupported_transport",
            "Codex shardbrowser exists, but it is not a stdio MCP entry.",
        )
    } else {
        (
            "needs_repair",
            "Codex shardbrowser exists but should be repaired: path/API/token placement needs attention.",
        )
    };

    serde_json::json!({
        "available": true,
        "registered": true,
        "enabled": enabled,
        "transport_type": transport_type,
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

fn codex_not_registered_status(expected_index_path: Option<String>, expected_api: String) -> Value {
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
        "message": "Codex CLI is installed, but no shardbrowser MCP entry was found.",
        "issues": ["run the Codex add command"],
    })
}

pub async fn status() -> Result<Value, String> {
    let s = settings::load().map_err(|e| e.to_string())?;
    let expected_index_path = expected_mcp_index_path(&s);
    let expected_api = expected_api_url(&s);

    let mut child = tokio::process::Command::new("codex");
    child
        .args(["mcp", "get", "shardbrowser", "--json"])
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
                "state": "codex_not_found",
                "message": "Codex CLI was not found on PATH. Install/open Codex CLI, then run the add command.",
                "issues": ["codex command not found"],
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
                "state": "error",
                "message": "Could not run Codex CLI to inspect MCP registration.",
                "issues": ["codex command failed to launch"],
            }));
        }
        Err(_) => {
            return Ok(serde_json::json!({
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
                "state": "timeout",
                "message": "Codex CLI did not answer within 4 seconds.",
                "issues": ["codex mcp get timed out"],
            }));
        }
    };

    if !output.status.success() {
        return Ok(codex_not_registered_status(
            expected_index_path,
            expected_api,
        ));
    }

    let config: Value = serde_json::from_slice(&output.stdout).map_err(|_| {
        "Codex CLI returned a response that ShardX could not parse as JSON.".to_string()
    })?;
    Ok(codex_mcp_status_from_config(
        &config,
        expected_index_path,
        expected_api,
    ))
}

#[cfg(test)]
mod tests {
    use super::codex_mcp_status_from_config;

    #[test]
    fn matching_codex_entry_is_registered_without_token_leak() {
        let status = codex_mcp_status_from_config(
            &serde_json::json!({
                "enabled": true,
                "transport": {
                    "type": "stdio",
                    "command": "C:\\Program Files\\nodejs\\node.exe",
                    "args": ["C:\\Users\\Administrator\\Documents\\MCP\\ShardBrowser\\mcp\\index.js"],
                    "env": { "SHARDX_API": "http://127.0.0.1:40325" }
                }
            }),
            Some("C:/Users/Administrator/Documents/MCP/ShardBrowser/mcp/index.js".into()),
            "http://127.0.0.1:40325".into(),
        );

        assert_eq!(status["state"].as_str(), Some("registered"));
        assert_eq!(status["ready"].as_bool(), Some(true));
        assert_eq!(status["token_in_config"].as_bool(), Some(false));
    }

    #[test]
    fn token_or_path_mismatch_needs_repair() {
        let status = codex_mcp_status_from_config(
            &serde_json::json!({
                "enabled": true,
                "transport": {
                    "type": "stdio",
                    "command": "node",
                    "args": ["C:\\old\\mcp\\index.js"],
                    "env": {
                        "SHARDX_API": "http://127.0.0.1:12345",
                        "SHARDX_TOKEN": "redacted"
                    }
                }
            }),
            Some("C:\\new\\mcp\\index.js".into()),
            "http://127.0.0.1:40325".into(),
        );

        assert_eq!(status["state"].as_str(), Some("needs_repair"));
        assert_eq!(status["ready"].as_bool(), Some(false));
        assert_eq!(status["path_matches"].as_bool(), Some(false));
        assert_eq!(status["api_matches"].as_bool(), Some(false));
        assert_eq!(status["token_in_config"].as_bool(), Some(true));
    }
}
