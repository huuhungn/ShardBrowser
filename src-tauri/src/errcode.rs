//! Error codes the interface translates.
//!
//! A Tauri command answers with a plain `String`, and the interface prints it
//! in a toast. So a sentence written here is what a Vietnamese operator reads,
//! in English, with no locale file anywhere in the path.
//!
//! Translating in Rust is the wrong side of the boundary: the chosen language
//! lives in browser storage, so the backend does not know it, and shipping a
//! second copy of the dictionary into the binary would leave two catalogues to
//! drift apart. Instead a command emits a marker,
//!
//! ```text
//! [[shardx:launch.browserMissing]]
//! [[shardx:launch.argPrefix|arg=--headless]]
//! ```
//!
//! and `localiseBackendError` in the interface swaps it for the operator's
//! language right before the toast renders.
//!
//! Only messages an operator can act on belong here. Schema complaints from
//! the automation API are read by script authors in an HTTP response, and
//! those stay English — a translated JSON error helps nobody debug a script.

/// Marker for a message with no arguments.
pub fn code(key: &str) -> String {
    format!("[[shardx:{key}]]")
}

/// Marker carrying `name=value` arguments for the locale string's
/// placeholders. Values may not contain `|` or `]`, which delimit the marker;
/// callers pass short identifiers (a switch name, a path), never prose.
pub fn code_with(key: &str, args: &[(&str, &str)]) -> String {
    let mut out = format!("[[shardx:{key}");
    for (k, v) in args {
        let safe = v.replace(['|', ']'], "");
        out.push_str(&format!("|{k}={safe}"));
    }
    out.push_str("]]");
    out
}

/// The interface's English dictionary, compiled in.
///
/// Markers are meant for the interface, which knows the operator's language.
/// The automation HTTP API has no such reader: a script author sees the raw
/// JSON, so a marker there is worse than the sentence it replaced. This turns
/// a marker back into the English the API has always returned.
///
/// `en.json` is the same file the interface ships, so the two cannot drift:
/// a key renamed on one side fails to compile, or fails the parity test, on
/// the other.
static EN_LOCALE: &str = include_str!("../../src/shared/i18n/locales/en.json");

fn dictionary() -> &'static std::collections::HashMap<String, String> {
    static DICT: std::sync::OnceLock<std::collections::HashMap<String, String>> =
        std::sync::OnceLock::new();
    DICT.get_or_init(|| {
        let mut flat = std::collections::HashMap::new();
        let parsed: serde_json::Value = serde_json::from_str(EN_LOCALE)
            .expect("en.json ships with the interface and must parse");
        fn walk(
            node: &serde_json::Value,
            prefix: &str,
            out: &mut std::collections::HashMap<String, String>,
        ) {
            match node {
                serde_json::Value::Object(map) => {
                    for (k, v) in map {
                        let key = if prefix.is_empty() {
                            k.clone()
                        } else {
                            format!("{prefix}.{k}")
                        };
                        walk(v, &key, out);
                    }
                }
                serde_json::Value::String(s) => {
                    out.insert(prefix.to_string(), s.clone());
                }
                _ => {}
            }
        }
        walk(&parsed, "", &mut flat);
        flat
    })
}

/// Replace every `[[shardx:key|a=b]]` marker with its English sentence.
///
/// Mirrors `localiseBackendError` in the interface, minus the language
/// choice. An unknown key keeps the marker's own text rather than vanishing,
/// so a stale code is visible in the API response instead of silently
/// becoming an empty string.
pub fn resolve_to_english(text: &str) -> String {
    let dict = dictionary();
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("[[shardx:") {
        out.push_str(&rest[..start]);
        let after = &rest[start + "[[shardx:".len()..];
        let Some(end) = after.find("]]") else {
            // Unterminated marker: emit the remainder untouched.
            break;
        };
        let body = &after[..end];
        let mut parts = body.split('|');
        let key = parts.next().unwrap_or_default();
        let args: Vec<(&str, &str)> = parts.filter_map(|p| p.split_once('=')).collect();
        match dict.get(key) {
            Some(template) => {
                let mut sentence = template.clone();
                for (name, value) in &args {
                    sentence = sentence.replace(&format!("{{{name}}}"), value);
                }
                out.push_str(&sentence);
            }
            None => {
                // No such key: prefer the English the caller carried, else
                // leave the key itself so the cause is still diagnosable.
                let fallback = args
                    .iter()
                    .find(|(n, _)| *n == "en")
                    .map(|(_, v)| *v)
                    .unwrap_or(key);
                out.push_str(fallback);
            }
        }
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_code_round_trips() {
        assert_eq!(
            code("launch.browserMissing"),
            "[[shardx:launch.browserMissing]]"
        );
    }

    #[test]
    fn arguments_are_appended_in_order() {
        assert_eq!(
            code_with("launch.argPrefix", &[("arg", "--headless")]),
            "[[shardx:launch.argPrefix|arg=--headless]]"
        );
    }

    /// A value containing the delimiters would truncate the marker and leave
    /// half of it rendered as literal text in the toast.
    #[test]
    fn delimiters_in_a_value_cannot_break_the_marker() {
        let m = code_with("k", &[("p", "a|b]c")]);
        assert_eq!(m, "[[shardx:k|p=abc]]");
        assert_eq!(m.matches("]]").count(), 1);
    }

    #[test]
    fn a_marker_resolves_to_the_english_sentence() {
        let english = resolve_to_english(&code("launch.browserMissing"));
        assert!(!english.contains("[[shardx:"), "marker survived: {english}");
        assert!(english.contains("ShardX browser"), "unexpected: {english}");
    }

    #[test]
    fn arguments_fill_the_placeholders() {
        let out = resolve_to_english(&code_with(
            "fleet.refusedClaim",
            &[("status", "409"), ("detail", "held by another device")],
        ));
        assert!(out.contains("409"), "status missing: {out}");
        assert!(
            out.contains("held by another device"),
            "detail missing: {out}"
        );
        assert!(!out.contains('{'), "placeholder left unfilled: {out}");
    }

    /// A chain is `label: cause`. Only the label is a marker; the cause is
    /// whatever the operating system or network said, and must survive.
    #[test]
    fn surrounding_text_is_preserved() {
        let chained = format!("{}: connection refused", code("fleet.uploadChunk"));
        let out = resolve_to_english(&chained);
        assert!(out.ends_with(": connection refused"), "cause lost: {out}");
        assert!(!out.contains("[[shardx:"));
    }

    #[test]
    fn an_unknown_key_degrades_to_something_readable() {
        assert_eq!(resolve_to_english("[[shardx:no.such.key]]"), "no.such.key");
        assert_eq!(
            resolve_to_english("[[shardx:no.such.key|en=disk is full]]"),
            "disk is full"
        );
    }

    #[test]
    fn text_without_a_marker_is_returned_unchanged() {
        assert_eq!(resolve_to_english("profile is locked"), "profile is locked");
        assert_eq!(resolve_to_english(""), "");
    }

    /// An unterminated marker must not swallow the rest of the message.
    #[test]
    fn a_truncated_marker_does_not_eat_the_message() {
        let out = resolve_to_english("before [[shardx:oops after");
        assert!(out.contains("before"), "lost the prefix: {out}");
        assert!(out.contains("after"), "lost the suffix: {out}");
    }

    /// The guarantee that makes this safe: every key the Rust side emits is
    /// present in the dictionary it compiles in. Without this, a renamed key
    /// would turn an API error into a bare key string at runtime, and nothing
    /// would catch it until a script author complained.
    #[test]
    fn every_code_emitted_by_rust_exists_in_the_dictionary() {
        let dict = dictionary();
        let mut missing = Vec::new();
        for entry in std::fs::read_dir(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"))
            .expect("source directory is readable")
        {
            let path = entry.expect("readable entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            // This file's own doc comments and tests carry illustrative keys
            // (`a.b`, `launch.argPrefix`) that deliberately do not exist.
            if path.file_name().and_then(|n| n.to_str()) == Some("errcode.rs") {
                continue;
            }
            let src = std::fs::read_to_string(&path).expect("source file is readable");
            // `code("a.b")` / `code_with("a.b", ...)` with a literal key.
            for (idx, _) in src
                .match_indices("code(\"")
                .chain(src.match_indices("code_with(\""))
            {
                let after = &src[idx..];
                let Some(open) = after.find('"') else {
                    continue;
                };
                let Some(close) = after[open + 1..].find('"') else {
                    continue;
                };
                let key = &after[open + 1..open + 1 + close];
                if key.contains('.') && !dict.contains_key(key) {
                    missing.push(format!(
                        "{}: {key}",
                        path.file_name().unwrap_or_default().to_string_lossy()
                    ));
                }
            }
        }
        missing.sort();
        missing.dedup();
        assert!(
            missing.is_empty(),
            "codes with no en.json entry: {missing:#?}"
        );
    }
}
