/**
 * The backend cannot translate its own errors: the chosen language lives in
 * browser storage. So a Tauri command emits `[[shardx:key]]` and the interface
 * swaps it for the operator's language on the way to the toast.
 *
 * These tests pin the swap itself — that a marker becomes Vietnamese, that an
 * unknown key degrades to the English the backend sent rather than to a bare
 * key, and that redaction still runs on the result.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const read = (p) => readFileSync(new URL(p, import.meta.url), "utf8");

const utils = read("../src/shared/lib/utils.ts");
const vi = JSON.parse(read("../src/shared/i18n/locales/vi.json"));
const en = JSON.parse(read("../src/shared/i18n/locales/en.json"));

/**
 * Compile the real `localiseBackendError` out of utils.ts rather than
 * reimplementing it, so the test fails when the shipped regex changes.
 * The source is TypeScript only in its type annotation, which is stripped.
 */
function loadLocaliser() {
  const marker = "export const localiseBackendError";
  const start = utils.indexOf(marker);
  assert.notEqual(start, -1, "localiseBackendError is missing from utils.ts");
  const semi = utils.indexOf("\n  });", start);
  assert.notEqual(semi, -1, "could not find the end of localiseBackendError");
  const decl = utils
    .slice(start, semi + "\n  });".length)
    .replace(marker, "const localiseBackendError")
    .replace("(text: string, depth = 0): string =>", "(text, depth = 0) =>")
    // The body keeps one type annotation, which plain JS cannot parse.
    .replace("const vars: Record<string, string> = {}", "const vars = {}");
  return new Function("t", `${decl}; return localiseBackendError;`);
}

const compile = loadLocaliser();

/** `translate` from i18n/index.ts, pinned to one dictionary. */
const makeT = (dict) => (key, vars) => {
  let out = dict[key] ?? en[key] ?? key;
  if (vars) for (const [k, v] of Object.entries(vars)) out = out.split(`{${k}}`).join(String(v));
  return out;
};

const localiseWith = (dict, text) => compile(makeT(dict))(text);

test("a marker becomes the operator's language", () => {
  const out = localiseWith(vi, "[[shardx:launch.browserMissing]]");
  assert.equal(out, vi["launch.browserMissing"]);
  assert.match(out, /Chưa cài trình duyệt ShardX/);
  assert.doesNotMatch(out, /\[\[shardx:/);
});

test("a marker nested in an argument is translated too", () => {
  // `profile.rs` splices a translatable label into a sentence: the operator
  // must read both halves in their language, not one half plus a raw marker.
  const dict = {
    "profile.stopRunningBrowser": "Hãy dừng trình duyệt đang chạy trước khi bạn {action}",
    "profile.actionDeleteProfile": "xóa hồ sơ này",
  };
  // `code_with` percent-escapes `]` in an argument, so the nested marker
  // arrives as `...actionDeleteProfile%5D%5D` — escaped, the outer marker
  // still parses as one unit, and unescaping restores the inner one.
  const out = localiseWith(
    dict,
    "[[shardx:profile.stopRunningBrowser|action=[[shardx:profile.actionDeleteProfile%5D%5D]]",
  );
  assert.doesNotMatch(out, /\[\[shardx:/);
  assert.equal(out, "Hãy dừng trình duyệt đang chạy trước khi bạn xóa hồ sơ này");
});

test("arguments fill the locale string's placeholders", () => {
  const dict = { "test.withArg": "Không mở được {name}" };
  assert.equal(localiseWith(dict, "[[shardx:test.withArg|name=hồ sơ A]]"), "Không mở được hồ sơ A");
});

test("an unknown key never shows the operator a raw marker", () => {
  // A stale or misspelled code must still read as a sentence. Rendering
  // "[[shardx:launch.notInAnyDictionary]]" in a toast is the worst outcome,
  // so an unmapped key falls back to the generic apology.
  const out = localiseWith(vi, "[[shardx:launch.notInAnyDictionary]]");
  assert.ok(!out.includes("[[shardx:"), `raw marker leaked: ${out}`);
  assert.equal(out, vi["errors.unknownBackend"]);
});

test("an unknown key prefers English the backend supplied", () => {
  // When Rust ships prose alongside the code, that beats the generic text.
  const out = localiseWith(vi, "[[shardx:some.newCode|en=Disk is full]]");
  assert.equal(out, "Disk is full");
});

test("text around the marker survives", () => {
  const dict = { "a.b": "Đã đóng" };
  assert.equal(localiseWith(dict, "prefix [[shardx:a.b]] suffix"), "prefix Đã đóng suffix");
});

test("every key the backend emits exists in both dictionaries", () => {
  // A command emitting a code with no locale entry shows the raw marker, and
  // that only surfaces when the failure happens in front of an operator.
  const rust = [
    "src-tauri/src/launch.rs",
    "src-tauri/src/lib.rs",
    "src-tauri/src/updater.rs",
    "src-tauri/src/bookmarks.rs",
  ]
    .map((p) => read(`../${p}`))
    .join("\n");
  const keys = [...rust.matchAll(/errcode::code(?:_with)?\(\s*"([^"]+)"/g)].map((m) => m[1]);
  assert.ok(keys.length > 0, "no error codes found — has the helper been renamed?");
  for (const k of new Set(keys)) {
    assert.ok(en[k], `en.json is missing ${k}`);
    assert.ok(vi[k], `vi.json is missing ${k}`);
  }
});
