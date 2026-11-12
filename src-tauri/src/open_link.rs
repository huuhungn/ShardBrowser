//! `shardbrowser://open/<profile>` links. Any web page can fire a custom
//! scheme, so a link only names a profile (its id, or its exact name): nothing
//! starts here. The launcher comes forward and the interface asks the operator
//! before it starts the profile, the way the Start button does. Extra paths,
//! queries and every other action are refused, and no launch option, URL or
//! proxy can travel in a link.

use std::sync::Mutex;

/// The longest id or name a link may carry, in characters.
const MAX_REF_CHARS: usize = 128;
/// Links waiting for the interface; a page firing more than this is spamming.
const MAX_PENDING: usize = 8;

/// A link that arrived before the interface asked for it (a cold start, or a
/// launcher still showing the first-run gate). `None` is a malformed link.
static PENDING: Mutex<Vec<Option<String>>> = Mutex::new(Vec::new());

fn pending() -> std::sync::MutexGuard<'static, Vec<Option<String>>> {
    PENDING.lock().unwrap_or_else(|e| e.into_inner())
}

/// The profile id or name an open link names, or None for anything else.
fn parse(link: &str) -> Option<String> {
    let url = url::Url::parse(link).ok()?;
    if url.scheme() != "shardbrowser"
        || url.host_str() != Some("open")
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    let path = url.path().strip_prefix('/')?;
    let raw = path.strip_suffix('/').unwrap_or(path);
    if raw.is_empty() || raw.contains('/') {
        return None;
    }
    let name = percent_encoding::percent_decode_str(raw)
        .decode_utf8()
        .ok()?;
    let valid = name.chars().count() <= MAX_REF_CHARS && !name.chars().any(char::is_control);
    valid.then(|| name.into_owned())
}

/// Queues what the links name and wakes the interface. Called by the
/// deep-link plugin, on a cold start and for a link a running launcher gets.
pub fn handle<S: AsRef<str>>(links: impl IntoIterator<Item = S>) {
    {
        let mut queue = pending();
        for link in links {
            let parsed = parse(link.as_ref());
            if queue.len() < MAX_PENDING && !queue.contains(&parsed) {
                queue.push(parsed);
            }
        }
    }
    if let Some(app) = crate::app_handle() {
        use tauri::Emitter;
        crate::show_main_window(app);
        let _ = app.emit("open-link", ());
    }
}

/// Takes the queued links: a profile id or name each, or None for a link the
/// interface should call malformed.
#[tauri::command]
pub fn open_link_take() -> Vec<Option<String>> {
    std::mem::take(&mut *pending())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_an_id_or_a_name() {
        assert_eq!(
            parse("shardbrowser://open/k1i65jwh"),
            Some("k1i65jwh".into())
        );
        assert_eq!(
            parse("shardbrowser://open/3f2b-41_a/"),
            Some("3f2b-41_a".into())
        );
    }

    #[test]
    fn decodes_percent_escapes() {
        assert_eq!(
            parse("shardbrowser://open/VN%20Automation%20001"),
            Some("VN Automation 001".into())
        );
        assert_eq!(
            parse("shardbrowser://open/Qu%E1%BA%A3n%20l%C3%BD"),
            Some("Quản lý".into())
        );
        // An encoded slash stays inside the name, it never adds a path segment.
        assert_eq!(parse("shardbrowser://open/a%2Fb"), Some("a/b".into()));
    }

    #[test]
    fn refuses_extra_parts() {
        for link in [
            "shardbrowser://open",
            "shardbrowser://open/",
            "shardbrowser://open//",
            "shardbrowser://open/a/b",
            "shardbrowser://open/a/b/",
            "shardbrowser://open/a?url=https://evil.example",
            "shardbrowser://open/a?",
            "shardbrowser://open/a#frag",
            "shardbrowser://open:80/a",
            "shardbrowser://user@open/a",
            "shardbrowser://user:pw@open/a",
        ] {
            assert_eq!(parse(link), None, "{link}");
        }
    }

    #[test]
    fn refuses_other_actions_and_schemes() {
        for link in [
            "shardbrowser://delete/abc",
            "shardbrowser://create/abc",
            "shardbrowser://open.evil/abc",
            "shardbrowser:///open/abc",
            "shardbrowser:open/abc",
            "https://example.com/open/abc",
            "other://open/abc",
            "open/abc",
            "",
        ] {
            assert_eq!(parse(link), None, "{link}");
        }
    }

    #[test]
    fn refuses_bad_names() {
        for link in [
            "shardbrowser://open/a%00b",
            "shardbrowser://open/a%0Ab",
            "shardbrowser://open/%FF%FE",
            &format!("shardbrowser://open/{}", "a".repeat(MAX_REF_CHARS + 1)),
        ] {
            assert_eq!(parse(link), None, "{link}");
        }
        assert!(parse(&format!(
            "shardbrowser://open/{}",
            "a".repeat(MAX_REF_CHARS)
        ))
        .is_some());
    }

    #[test]
    fn queues_every_link_once_and_hands_them_over() {
        let _ = open_link_take();
        handle([
            "shardbrowser://open/abc",
            "shardbrowser://open/abc",
            "shardbrowser://open/a?x=1",
        ]);
        assert_eq!(open_link_take(), vec![Some("abc".to_string()), None]);
        assert!(open_link_take().is_empty());
        handle((0..MAX_PENDING + 3).map(|n| format!("shardbrowser://open/p{n}")));
        assert_eq!(open_link_take().len(), MAX_PENDING);
    }
}
