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
}
