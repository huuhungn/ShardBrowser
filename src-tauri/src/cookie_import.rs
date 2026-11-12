// Cookie import parser: turns the common export formats into `cookies::Cookie`.
//
//   - Netscape `cookies.txt` (curl, yt-dlp, "Get cookies.txt" extensions)
//   - Cookie-Editor / EditThisCookie JSON (`expirationDate`, `hostOnly`, `session`)
//   - Playwright / Puppeteer cookie arrays and `storageState` (`expires` -1 = session)
//   - the launcher's own schema (what `cookies::export` writes)
//
// The format mapping follows the MIT-licensed camoufox-profile-manager
// (polyackiy/camoufox-profile-manager, core/cookie_transfer.py).
//
// A malformed entry never aborts the import and is never dropped silently: it is
// listed by position with a reason code. The report carries no cookie values.

use crate::cookies::Cookie;
use anyhow::{anyhow, Result};
use serde::Serialize;
use serde_json::Value;

/// One entry that was not imported. `position` is the 1-based line of a
/// `cookies.txt` file, or the 1-based array index of a JSON export.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Skipped {
    pub position: usize,
    pub reason: &'static str,
}

#[derive(Debug)]
pub struct Parsed {
    pub format: &'static str,
    pub cookies: Vec<Cookie>,
    pub skipped: Vec<Skipped>,
}

#[derive(Debug, Serialize)]
pub struct ImportReport {
    pub imported: usize,
    pub format: &'static str,
    pub skipped: Vec<Skipped>,
}

impl Parsed {
    pub fn into_report(self, imported: usize) -> ImportReport {
        ImportReport {
            imported,
            format: self.format,
            skipped: self.skipped,
        }
    }
}

/// Unix seconds below 1e11 (year 5138); milliseconds below 1e14; microseconds
/// below 1e17. The ranges do not overlap for any date from 1973 to 5138, so
/// the magnitude alone identifies the unit. shortcut: Chromium's 1601-epoch
/// microseconds (about 1.3e16 today) would read as Unix microseconds, so they
/// are not supported.
const SECS_LIMIT: f64 = 1e11;
const MILLIS_LIMIT: f64 = 1e14;
const MICROS_LIMIT: f64 = 1e17;

/// Expiry in whatever unit the exporter used -> Unix seconds, `None` = session.
/// Zero and negatives are session markers (Netscape 0, Playwright -1).
fn normalise_expiry(raw: f64) -> Result<Option<f64>, &'static str> {
    if !raw.is_finite() {
        return Err("badExpiry");
    }
    Ok(if raw <= 0.0 {
        None
    } else if raw < SECS_LIMIT {
        Some(raw)
    } else if raw < MILLIS_LIMIT {
        Some(raw / 1e3)
    } else if raw < MICROS_LIMIT {
        Some(raw / 1e6)
    } else {
        return Err("expiryOutOfRange");
    })
}

fn normalise_same_site(raw: &str) -> &'static str {
    match raw.to_ascii_lowercase().as_str() {
        "none" | "no_restriction" => "None",
        "lax" => "Lax",
        "strict" => "Strict",
        _ => "unspecified",
    }
}

/// Chromium keys domain cookies by a leading dot and host-only cookies without.
fn host_key(domain: &str, include_subdomains: bool) -> String {
    let bare = domain.trim_start_matches('.');
    if include_subdomains {
        format!(".{bare}")
    } else {
        bare.to_string()
    }
}

/// Detect the format of `text` and convert it.
pub fn parse(text: &str) -> Result<Parsed> {
    let text = text.trim_start_matches('\u{feff}');
    if text.trim_start().starts_with(['[', '{']) {
        let value: Value = serde_json::from_str(text).map_err(|e| {
            anyhow!(crate::errcode::code_with(
                "cookies.importInvalidJson",
                &[
                    ("line", &e.line().to_string()),
                    ("column", &e.column().to_string()),
                ],
            ))
        })?;
        return parse_value(&value);
    }
    parse_netscape(text)
}

/// Convert an already-parsed JSON cookie array or `{ "cookies": [...] }` object.
pub fn parse_value(value: &Value) -> Result<Parsed> {
    let (entries, has_origins) = match value {
        Value::Array(entries) => (entries, false),
        Value::Object(o) => match o.get("cookies") {
            Some(Value::Array(entries)) => (entries, o.contains_key("origins")),
            _ => return Err(unrecognised()),
        },
        _ => return Err(unrecognised()),
    };
    let mut parsed = Parsed {
        format: json_format(entries, has_origins),
        cookies: Vec::new(),
        skipped: Vec::new(),
    };
    for (i, entry) in entries.iter().enumerate() {
        match cookie_from_json(entry) {
            Ok(c) => parsed.cookies.push(c),
            Err(reason) => parsed.skipped.push(Skipped {
                position: i + 1,
                reason,
            }),
        }
    }
    Ok(parsed)
}

fn unrecognised() -> anyhow::Error {
    anyhow!(crate::errcode::code("cookies.importUnrecognizedFormat"))
}

/// Informational label only; every JSON flavour goes through one mapping.
fn json_format(entries: &[Value], has_origins: bool) -> &'static str {
    let has = |keys: &[&str]| {
        entries
            .iter()
            .filter_map(Value::as_object)
            .any(|o| keys.iter().any(|k| o.contains_key(*k)))
    };
    if has_origins {
        "playwright"
    } else if has(&["expirationDate", "hostOnly", "session", "storeId"]) {
        "cookie-editor"
    } else if has(&["http_only", "same_site"]) {
        "shardx"
    } else if has(&["httpOnly", "sameSite"]) {
        "playwright"
    } else {
        "shardx"
    }
}

fn cookie_from_json(entry: &Value) -> Result<Cookie, &'static str> {
    let o = entry.as_object().ok_or("notObject")?;
    let string = |key: &str| o.get(key).and_then(Value::as_str);
    let flag = |keys: &[&str]| {
        keys.iter()
            .find_map(|k| o.get(*k))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    };

    let name = string("name")
        .filter(|s| !s.is_empty())
        .ok_or("missingName")?;
    let value = string("value").ok_or("missingValue")?;
    let domain = string("domain")
        .filter(|s| !s.is_empty())
        .ok_or("missingDomain")?;

    // `expires` (fork, Playwright) or `expirationDate` (Cookie-Editor).
    let expires = match ["expires", "expirationDate"]
        .iter()
        .find_map(|k| o.get(*k).filter(|v| !v.is_null()))
    {
        Some(v) if !flag(&["session"]) => normalise_expiry(v.as_f64().ok_or("badExpiry")?)?,
        _ => None,
    };

    // Cookie-Editor's `hostOnly` is authoritative for the leading dot; without
    // it the domain is used as written, as the fork always did.
    let domain = match o.get("hostOnly").and_then(Value::as_bool) {
        Some(host_only) => host_key(domain, !host_only),
        None => domain.to_string(),
    };

    Ok(Cookie {
        domain,
        name: name.to_string(),
        value: value.to_string(),
        path: string("path")
            .filter(|s| !s.is_empty())
            .unwrap_or("/")
            .to_string(),
        expires,
        secure: flag(&["secure"]),
        http_only: flag(&["httpOnly", "http_only"]),
        same_site: ["sameSite", "same_site"]
            .iter()
            .find_map(|k| string(k))
            .map(|s| normalise_same_site(s).to_string()),
    })
}

fn parse_netscape(text: &str) -> Result<Parsed> {
    let mut parsed = Parsed {
        format: "netscape",
        cookies: Vec::new(),
        skipped: Vec::new(),
    };
    let mut seen_cookie_line = false;
    for (i, raw) in text.lines().enumerate() {
        let (line, http_only) = match raw.strip_prefix("#HttpOnly_") {
            Some(rest) => (rest, true),
            None => (raw, false),
        };
        if line.trim().is_empty() || (!http_only && line.trim_start().starts_with('#')) {
            continue;
        }
        seen_cookie_line = true;
        match netscape_line(line, http_only) {
            Ok(c) => parsed.cookies.push(c),
            Err(reason) => parsed.skipped.push(Skipped {
                position: i + 1,
                reason,
            }),
        }
    }
    // Prose or an unknown format would otherwise come back as a pile of
    // "too few fields" lines; say plainly that nothing was recognised.
    let only_prose =
        parsed.cookies.is_empty() && parsed.skipped.iter().all(|s| s.reason == "tooFewFields");
    if !seen_cookie_line || only_prose {
        return Err(unrecognised());
    }
    Ok(parsed)
}

/// domain, include-subdomains, path, secure, expiry, name, value (tab separated).
fn netscape_line(line: &str, http_only: bool) -> Result<Cookie, &'static str> {
    let f: Vec<&str> = line.splitn(7, '\t').collect();
    if f.len() < 7 {
        return Err("tooFewFields");
    }
    let bool_field = |s: &str| match s.trim().to_ascii_uppercase().as_str() {
        "TRUE" => Ok(true),
        "FALSE" => Ok(false),
        _ => Err("badFlag"),
    };
    let include_subdomains = bool_field(f[1])?;
    let secure = bool_field(f[3])?;
    let expires = normalise_expiry(f[4].trim().parse::<f64>().map_err(|_| "badExpiry")?)?;
    let domain = f[0].trim();
    if domain.trim_start_matches('.').is_empty() {
        return Err("missingDomain");
    }
    if f[5].is_empty() {
        return Err("missingName");
    }
    Ok(Cookie {
        domain: host_key(domain, include_subdomains),
        name: f[5].to_string(),
        value: f[6].to_string(),
        path: if f[2].is_empty() { "/" } else { f[2] }.to_string(),
        expires,
        secure,
        http_only,
        same_site: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every value below is synthetic.
    const FAKE: &str = "fake-value-123";

    fn skipped(p: &Parsed) -> Vec<(usize, &'static str)> {
        p.skipped.iter().map(|s| (s.position, s.reason)).collect()
    }

    #[test]
    fn netscape_parses_flags_httponly_comments_and_session() {
        let text = [
            "# Netscape HTTP Cookie File".to_string(),
            String::new(),
            format!(".example.com\tTRUE\t/\tTRUE\t1900000000\tsid\t{FAKE}"),
            format!("#HttpOnly_.example.com\tTRUE\t/app\tFALSE\t0\ttoken\t{FAKE}"),
            format!("www.example.com\tFALSE\t/\tFALSE\t1900000000\thost\t{FAKE}"),
            "# a plain comment".to_string(),
        ]
        .join("\n");
        let p = parse(&text).unwrap();
        assert_eq!(p.format, "netscape");
        assert!(p.skipped.is_empty());
        assert_eq!(p.cookies.len(), 3);

        let sid = &p.cookies[0];
        assert_eq!(sid.domain, ".example.com");
        assert!(sid.secure && !sid.http_only);
        assert_eq!(sid.expires, Some(1_900_000_000.0));

        let token = &p.cookies[1];
        assert!(token.http_only && !token.secure);
        assert_eq!(token.path, "/app");
        assert_eq!(token.expires, None, "expiry 0 is a session cookie");

        assert_eq!(p.cookies[2].domain, "www.example.com", "FALSE = host only");
    }

    #[test]
    fn netscape_value_may_contain_tabs_and_crlf_is_tolerated() {
        let p = parse(".example.com\tTRUE\t/\tFALSE\t0\tn\ta\tb\r\n").unwrap();
        assert_eq!(p.cookies[0].value, "a\tb");
    }

    #[test]
    fn netscape_reports_malformed_lines_by_number_without_values() {
        let text = [
            "# Netscape HTTP Cookie File".to_string(),
            format!(".a.com\tTRUE\t/\tFALSE\t0\tgood\t{FAKE}"),
            ".a.com\tTRUE\t/\tFALSE\t0\tshort".to_string(),
            format!(".a.com\tMAYBE\t/\tFALSE\t0\tflag\t{FAKE}"),
            format!(".a.com\tTRUE\t/\tFALSE\tsoon\texp\t{FAKE}"),
            format!("\tTRUE\t/\tFALSE\t0\tnodomain\t{FAKE}"),
            format!(".a.com\tTRUE\t/\tFALSE\t0\t\t{FAKE}"),
            format!(".a.com\tTRUE\t/\tFALSE\t1e30\thuge\t{FAKE}"),
        ]
        .join("\n");
        let p = parse(&text).unwrap();
        assert_eq!(p.cookies.len(), 1);
        assert_eq!(
            skipped(&p),
            vec![
                (3, "tooFewFields"),
                (4, "badFlag"),
                (5, "badExpiry"),
                (6, "missingDomain"),
                (7, "missingName"),
                (8, "expiryOutOfRange"),
            ]
        );
        let report = serde_json::to_string(&p.into_report(1)).unwrap();
        assert!(!report.contains(FAKE), "report must not echo cookie values");
        assert!(
            !report.contains("good"),
            "report must not echo cookie names"
        );
    }

    #[test]
    fn unknown_text_is_unrecognised_not_a_pile_of_skips() {
        for text in [
            "",
            "   \n\n",
            "hello world\nthis is not cookies",
            "# only comments",
        ] {
            let e = parse(text).unwrap_err().to_string();
            assert!(
                crate::errcode::has_code(&e, "cookies.importUnrecognizedFormat"),
                "{text:?} -> {e}"
            );
        }
    }

    #[test]
    fn cookie_editor_export_is_converted() {
        let text = format!(
            r#"[
              {{"domain":".example.com","expirationDate":1900000000.5,"hostOnly":false,
                "httpOnly":true,"name":"a","path":"/","sameSite":"no_restriction",
                "secure":true,"session":false,"storeId":"0","value":"{FAKE}"}},
              {{"domain":"example.com","hostOnly":true,"httpOnly":false,"name":"b",
                "path":"/x","sameSite":"unspecified","secure":false,"session":true,
                "expirationDate":1900000000,"value":"{FAKE}"}},
              {{"domain":"example.com","hostOnly":false,"name":"c","sameSite":"lax",
                "session":false,"expirationDate":1900000000,"value":"{FAKE}"}},
              {{"domain":".example.com","hostOnly":true,"name":"d","sameSite":"strict",
                "session":true,"value":"{FAKE}"}}
            ]"#
        );
        let p = parse(&text).unwrap();
        assert_eq!(p.format, "cookie-editor");
        assert!(p.skipped.is_empty());
        let [a, b, c, d] = &p.cookies[..] else {
            panic!("4 cookies")
        };
        assert_eq!(a.expires, Some(1_900_000_000.5));
        assert_eq!(a.same_site.as_deref(), Some("None"));
        assert!(a.http_only && a.secure);
        assert_eq!(b.expires, None, "session:true wins over expirationDate");
        assert_eq!(b.same_site.as_deref(), Some("unspecified"));
        assert_eq!(c.domain, ".example.com", "hostOnly:false adds the dot");
        assert_eq!(c.same_site.as_deref(), Some("Lax"));
        assert_eq!(d.domain, "example.com", "hostOnly:true strips the dot");
        assert_eq!(d.same_site.as_deref(), Some("Strict"));
    }

    #[test]
    fn playwright_state_and_array_are_converted() {
        let cookie = format!(
            r#"{{"name":"s","value":"{FAKE}","domain":".example.com","path":"/",
                "expires":-1,"httpOnly":true,"secure":true,"sameSite":"Lax"}}"#
        );
        let state = format!(
            r#"{{"cookies":[{cookie}],"origins":[{{"origin":"https://example.com","localStorage":[]}}]}}"#
        );
        let p = parse(&state).unwrap();
        assert_eq!(p.format, "playwright");
        assert_eq!(p.cookies[0].expires, None, "expires -1 is a session cookie");
        assert_eq!(p.cookies[0].same_site.as_deref(), Some("Lax"));
        assert!(p.cookies[0].http_only);

        let p = parse(&format!("[{cookie}]")).unwrap();
        assert_eq!(p.format, "playwright");
        assert_eq!(p.cookies.len(), 1);
    }

    #[test]
    fn launcher_schema_is_unchanged() {
        let text = format!(
            r#"[{{"domain":".example.com","name":"a","value":"{FAKE}","expires":1900000000.25,
                 "secure":true,"http_only":true,"same_site":"Strict"}},
                {{"domain":"example.com","name":"b","value":"{FAKE}","httpOnly":true,"sameSite":"None"}}]"#
        );
        let p = parse(&text).unwrap();
        assert_eq!(p.format, "shardx");
        let [a, b] = &p.cookies[..] else {
            panic!("2 cookies")
        };
        assert_eq!(a.expires, Some(1_900_000_000.25));
        assert_eq!(a.path, "/");
        assert!(a.http_only && a.secure);
        assert_eq!(a.same_site.as_deref(), Some("Strict"));
        assert_eq!(b.expires, None);
        assert!(b.http_only);
        assert_eq!(b.same_site.as_deref(), Some("None"));
        // `{ "cookies": [...] }` (the API's export shape) is accepted too.
        let wrapped = format!(r#"{{"cookies":{text}}}"#);
        assert_eq!(parse(&wrapped).unwrap().cookies.len(), 2);
        assert!(parse("[]").unwrap().cookies.is_empty());
    }

    #[test]
    fn json_entries_that_cannot_import_are_reported_by_index() {
        let text = format!(
            r#"[{{"domain":"a.com","name":"ok","value":"{FAKE}"}},
                "nope",
                {{"domain":"a.com","value":"{FAKE}"}},
                {{"name":"n","value":"{FAKE}"}},
                {{"domain":"a.com","name":"n"}},
                {{"domain":"a.com","name":"n","value":"{FAKE}","expires":"soon"}}]"#
        );
        let p = parse(&text).unwrap();
        assert_eq!(p.cookies.len(), 1);
        assert_eq!(
            skipped(&p),
            vec![
                (2, "notObject"),
                (3, "missingName"),
                (4, "missingDomain"),
                (5, "missingValue"),
                (6, "badExpiry"),
            ]
        );
    }

    #[test]
    fn broken_json_and_wrong_shapes_fail_with_codes() {
        let e = parse("[{\"domain\": ").unwrap_err().to_string();
        assert!(
            crate::errcode::has_code(&e, "cookies.importInvalidJson"),
            "{e}"
        );
        assert!(!e.contains("domain"), "error must not echo input");
        for text in ["{\"cookies\": 3}", "{\"a\": 1}"] {
            let e = parse(text).unwrap_err().to_string();
            assert!(
                crate::errcode::has_code(&e, "cookies.importUnrecognizedFormat"),
                "{e}"
            );
        }
    }

    #[test]
    fn expiry_unit_boundaries() {
        // seconds: below 1e11
        assert_eq!(normalise_expiry(1_900_000_000.0), Ok(Some(1_900_000_000.0)));
        assert_eq!(
            normalise_expiry(99_999_999_999.0),
            Ok(Some(99_999_999_999.0))
        );
        // milliseconds: [1e11, 1e14)
        assert_eq!(normalise_expiry(1e11), Ok(Some(1e8)));
        assert_eq!(
            normalise_expiry(1_900_000_000_000.0),
            Ok(Some(1_900_000_000.0))
        );
        assert_eq!(
            normalise_expiry(99_999_999_999_999.0),
            Ok(Some(99_999_999_999.999))
        );
        // microseconds: [1e14, 1e17)
        assert_eq!(normalise_expiry(1e14), Ok(Some(1e8)));
        assert_eq!(
            normalise_expiry(1_900_000_000_000_000.0),
            Ok(Some(1_900_000_000.0))
        );
        // out of range and non-finite
        assert_eq!(normalise_expiry(1e17), Err("expiryOutOfRange"));
        assert_eq!(normalise_expiry(f64::NAN), Err("badExpiry"));
        assert_eq!(normalise_expiry(f64::INFINITY), Err("badExpiry"));
        // session markers
        assert_eq!(normalise_expiry(0.0), Ok(None));
        assert_eq!(normalise_expiry(-1.0), Ok(None));
    }

    #[test]
    fn millisecond_and_microsecond_expiry_reach_the_cookie() {
        let text = format!(
            r#"[{{"domain":"a.com","name":"ms","value":"{FAKE}","expires":1900000000000}},
                {{"domain":"a.com","name":"us","value":"{FAKE}","expires":1900000000000000}}]"#
        );
        let p = parse(&text).unwrap();
        assert_eq!(p.cookies[0].expires, Some(1_900_000_000.0));
        assert_eq!(p.cookies[1].expires, Some(1_900_000_000.0));
    }

    #[test]
    fn bom_is_ignored() {
        let text = format!("\u{feff}.a.com\tTRUE\t/\tFALSE\t0\tn\t{FAKE}");
        assert_eq!(parse(&text).unwrap().cookies.len(), 1);
        assert_eq!(parse("\u{feff}[]").unwrap().cookies.len(), 0);
    }
}
