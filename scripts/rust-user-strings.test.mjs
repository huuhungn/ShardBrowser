/**
 * The Rust side answers commands with plain `String` errors, and the UI prints
 * many of them verbatim in a toast. So an English sentence written in
 * `src-tauri` reaches a Vietnamese user unchanged — and no locale file is
 * involved, which is exactly why the React guard cannot see it.
 *
 * This is a ratchet, not a clean gate: the backend is still entirely English.
 * The baseline below records what exists today. New English sentences fail;
 * removing one and forgetting to shrink the baseline fails too, so the number
 * can only go down.
 */
import { strict as assert } from "node:assert";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const here = dirname(fileURLToPath(import.meta.url));
const rustRoot = join(here, "..", "src-tauri", "src");
const baselineFile = join(here, "rust-user-strings.baseline.json");

function rustFilesUnder(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...rustFilesUnder(full));
    else if (entry.endsWith(".rs")) out.push(full);
  }
  return out.sort();
}

/**
 * Logging macros are internal: they go to a file, never to a toast. Anything
 * on such a line is out of scope no matter how much it reads like a sentence.
 */
const LOG_MACRO = /\b(?:tracing::\w+|log::\w+|println!|eprintln!|debug!|info!|warn!|error!|trace!)\s*\(/;

/**
 * The shapes that actually become a user-visible `Err(String)`: an explicit
 * error value, a conversion into one, or an anyhow context label — the labels
 * matter because several commands render the whole cause chain with `{e:#}`,
 * which concatenates every `.context(...)` into the toast text.
 */
const ERROR_SHAPE = /(?:Err\(|map_err|anyhow!|bail!|ok_or_else|\.context\(|\.with_context\()/;

/** `#[cfg(test)]` blocks describe fixtures, not user-facing failures. */
function withoutTestModules(src) {
  const lines = src.split("\n");
  const kept = [];
  let depth = 0;
  let inTest = false;
  for (const line of lines) {
    if (!inTest && /#\[cfg\(test\)\]/.test(line)) {
      inTest = true;
      depth = 0;
      kept.push("");
      continue;
    }
    if (inTest) {
      depth += (line.match(/\{/g) ?? []).length;
      depth -= (line.match(/\}/g) ?? []).length;
      kept.push("");
      if (depth <= 0 && /\}/.test(line)) inTest = false;
      continue;
    }
    kept.push(line);
  }
  return kept.join("\n");
}

/**
 * A sentence a person reads, as opposed to an identifier, a path, a SQL
 * fragment or a format-only shell. Two words minimum, at least one of them a
 * real word rather than a `{placeholder}`.
 */
function isUserProse(text) {
  const withoutPlaceholders = text.replace(/\{[^}]*\}/g, " ").trim();
  if (withoutPlaceholders.length < 12) return false;
  if (/^(?:SELECT|INSERT|UPDATE|DELETE|CREATE|PRAGMA|ALTER|DROP)\b/i.test(withoutPlaceholders)) return false;
  if (/^[a-z]+:\/\//.test(withoutPlaceholders)) return false;            // a URL
  if (/^[-\w.]+\.(?:json|rs|exe|dll|zip|toml|db)$/i.test(withoutPlaceholders)) return false;
  if (/^[A-Z_]{3,}$/.test(withoutPlaceholders)) return false;            // SCREAMING_CONST
  if (/^--?[\w-]+$/.test(withoutPlaceholders)) return false;             // a CLI switch
  const words = withoutPlaceholders.match(/[A-Za-z]{2,}/g) ?? [];
  if (words.length < 2) return false;
  // Identifier-ish runs (`snake_case_thing`, `camelCaseThing`) are not prose.
  if (!/\s/.test(withoutPlaceholders)) return false;
  return true;
}

const STRING_LITERAL = /"((?:[^"\\]|\\.)*)"/g;

function userStringsIn(src) {
  const found = [];
  for (const [i, line] of withoutTestModules(src).split("\n").entries()) {
    const s = line.trim();
    if (s.startsWith("//") || s.startsWith("///")) continue;
    if (LOG_MACRO.test(s)) continue;
    if (!ERROR_SHAPE.test(s)) continue;
    for (const m of s.matchAll(STRING_LITERAL)) {
      const text = m[1];
      if (isUserProse(text)) found.push({ line: i + 1, text });
    }
  }
  return found;
}

function currentFindings() {
  const out = [];
  for (const file of rustFilesUnder(rustRoot)) {
    const rel = relative(rustRoot, file).replace(/\\/g, "/");
    for (const hit of userStringsIn(readFileSync(file, "utf8"))) {
      out.push(`${rel}: ${hit.text}`);
    }
  }
  return out.sort();
}

test("no new English sentence is added to the Rust command surface", () => {
  const baseline = JSON.parse(readFileSync(baselineFile, "utf8"));
  const known = new Set(baseline.strings);
  const found = currentFindings();

  const added = found.filter((f) => !known.has(f));
  assert.deepEqual(
    added,
    [],
    `New English text returned from src-tauri. The UI prints these verbatim, so a ` +
      `Vietnamese user reads English. Give the command a stable error code the UI ` +
      `can translate, or add it to ${relative(here, baselineFile)} with a reason.\n` +
      added.map((a) => `  ${a}`).join("\n"),
  );
});

test("the baseline shrinks and never silently grows", () => {
  const baseline = JSON.parse(readFileSync(baselineFile, "utf8"));
  const found = new Set(currentFindings());
  const stale = baseline.strings.filter((s) => !found.has(s));

  assert.deepEqual(
    stale,
    [],
    `The baseline lists text that is no longer in the source. Remove these entries ` +
      `so the count keeps falling instead of leaving room for a new string to take ` +
      `their place:\n` + stale.map((s) => `  ${s}`).join("\n"),
  );
});
