// The block editor must offer the params the runner actually reads.
//
// The runner looks its params up by string key inside `exec_block`, and an
// unknown key is not an error there -- it simply is not found. So an editor
// that writes `contains` where the runner reads `expected` produces a project
// that saves, loads, and runs, and then fails at the step with "the assert
// block needs an expected" in front of an operator who filled the box in.
//
// Nothing in the type system connects the two sides: the params are
// `serde_json::Value` in Rust and `Record<string, unknown>` in TypeScript, on
// purpose, because each kind carries a different shape. This test is that
// missing link, so it reads the keys back out of runner.rs rather than
// restating them -- a list transcribed by hand would drift exactly the way the
// editor already did.

import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";

import { build } from "esbuild";

const ROOT = path.resolve(import.meta.dirname, "..");
const RUNNER_RS = path.join(ROOT, "src-tauri/src/runner.rs");
const EDITOR_TSX = path.join(ROOT, "src/pages/automation/index.tsx");

/// The kinds the runner will accept, read from `supported_kinds`.
function kindsFromRunner(source) {
  const block = source.match(/fn supported_kinds\(\)[^{]*\{\s*&\[([^\]]*)\]/s);
  assert.ok(block, "runner.rs no longer has a supported_kinds list to read");
  return [...block[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]);
}

/// The body of `exec_block`, which is where params are looked up by name.
function execBlockBody(source) {
  const start = source.indexOf("match block.kind.as_str() {");
  assert.ok(start > 0, "runner.rs no longer dispatches on block.kind");
  return source.slice(start);
}

/// Params read by a helper rather than named in the arm itself.
///
/// `db_params(block, vars)` reads "params" internally; without this the guard
/// would report a key the editor writes and the runner "never reads", which
/// is exactly the false alarm that teaches people to ignore the guard.
const HELPER_PARAMS = { db_params: "params" };

/// Params one arm reads, however it reads them.
///
/// Both spellings count: `param_text(block, "url", vars)` for the substituted
/// ones and `params.get("ms")` for the raw ones. Missing either would let a
/// whole class of key drift through unnoticed.
function paramsForKind(execBody, kind) {
  const arm = execBody.indexOf(`"${kind}" => {`);
  if (arm < 0) return null;
  const nextArm = execBody.slice(arm + kind.length + 8).search(/\n\s{8}"[a-zA-Z]+" => \{/);
  const body =
    nextArm < 0 ? execBody.slice(arm) : execBody.slice(arm, arm + kind.length + 8 + nextArm);

  const keys = new Set();
  for (const m of body.matchAll(/param_text\(\s*block\s*,\s*"([^"]+)"/g)) keys.add(m[1]);
  for (const m of body.matchAll(/params\s*\.\s*get\(\s*"([^"]+)"\s*\)/g)) keys.add(m[1]);
  // Helpers that read a well-known key off the block themselves, so the name
  // never appears as a literal in the arm.
  for (const [helper, key] of Object.entries(HELPER_PARAMS)) {
    if (body.includes(`${helper}(block`)) keys.add(key);
  }
  return keys;
}

/// Params the arm cannot run without, i.e. the ones whose absence is an error.
///
/// `.context("the \"wait\" block needs an ms")?` and `.unwrap_or_default()`
/// are the two shapes in the runner today; only the first is required.
function requiredParamsForKind(execBody, kind) {
  const arm = execBody.indexOf(`"${kind}" => {`);
  if (arm < 0) return null;
  const nextArm = execBody.slice(arm + kind.length + 8).search(/\n\s{8}"[a-zA-Z]+" => \{/);
  const body =
    nextArm < 0 ? execBody.slice(arm) : execBody.slice(arm, arm + kind.length + 8 + nextArm);

  const required = new Set();
  // A lookup followed by `?` before the next lookup is a required param.
  const lookups = [
    ...body.matchAll(/param_text\(\s*block\s*,\s*"([^"]+)"[^;]*?;/gs),
    ...body.matchAll(/params\s*\.\s*get\(\s*"([^"]+)"\s*\)[^;]*?;/gs),
  ];
  for (const m of lookups) {
    if (m[0].includes("unwrap_or_default")) continue;
    if (m[0].includes("?")) required.add(m[1]);
  }
  return required;
}

/// The editor's PARAMS table, compiled so the real object can be inspected.
async function loadEditorParams() {
  const dir = await mkdtemp(path.join(os.tmpdir(), "shardx-automation-"));
  const outfile = path.join(dir, "params.mjs");
  const source = await readFile(EDITOR_TSX, "utf8");

  // The table is module-private and the page imports Tauri and React around
  // it, neither of which loads under node. Bundling just the table keeps the
  // test reading the shipped literal without dragging the app in with it.
  const table = source.match(/const PARAMS: Record<string, ParamSpec\[\]> = \{.*?\n\};/s);
  assert.ok(table, "the automation editor no longer declares a PARAMS table");
  const specType = source.match(/type ParamSpec = \{.*?\n\};/s);
  assert.ok(specType, "the automation editor no longer declares ParamSpec");

  const entry = path.join(dir, "params.ts");
  const { writeFile } = await import("node:fs/promises");
  await writeFile(entry, `${specType[0]}\n${table[0]}\nexport { PARAMS };\n`, "utf8");
  await build({
    entryPoints: [entry],
    outfile,
    bundle: true,
    format: "esm",
    platform: "node",
    logLevel: "silent",
  });
  const mod = await import(pathToFileURL(outfile).href);
  await rm(dir, { recursive: true, force: true });
  return mod.PARAMS;
}

test("the editor offers every kind the runner supports", async () => {
  const runner = await readFile(RUNNER_RS, "utf8");
  const PARAMS = await loadEditorParams();
  for (const kind of kindsFromRunner(runner)) {
    assert.ok(
      Object.hasOwn(PARAMS, kind),
      `the runner supports "${kind}" but the editor cannot build one`,
    );
  }
});

test("the editor never offers a kind the runner would reject", async () => {
  const runner = await readFile(RUNNER_RS, "utf8");
  const supported = new Set(kindsFromRunner(runner));
  const PARAMS = await loadEditorParams();
  for (const kind of Object.keys(PARAMS)) {
    assert.ok(supported.has(kind), `the editor offers "${kind}", which the runner refuses`);
  }
});

test("every param the editor writes is one the runner reads", async () => {
  const runner = await readFile(RUNNER_RS, "utf8");
  const execBody = execBlockBody(runner);
  const PARAMS = await loadEditorParams();

  for (const [kind, specs] of Object.entries(PARAMS)) {
    const read = paramsForKind(execBody, kind);
    assert.ok(read, `the runner has no arm for "${kind}"`);
    for (const spec of specs) {
      assert.ok(
        read.has(spec.key),
        `the editor writes ${kind}.${spec.key}, which the runner never reads`,
      );
    }
  }
});

test("every param the runner requires is one the editor can fill in", async () => {
  const runner = await readFile(RUNNER_RS, "utf8");
  const execBody = execBlockBody(runner);
  const PARAMS = await loadEditorParams();

  for (const kind of kindsFromRunner(runner)) {
    const required = requiredParamsForKind(execBody, kind);
    const offered = new Set((PARAMS[kind] ?? []).map((s) => s.key));
    for (const key of required ?? []) {
      assert.ok(
        offered.has(key),
        `a "${kind}" block cannot run without ${key}, but the editor has no box for it`,
      );
    }
  }
});

/// A param the runner reads but the editor has no box for is unreachable: the
/// operator cannot type it, so the feature it controls does not exist for
/// anyone working in the UI. Optional params are exactly where this hides,
/// because the "required" check above passes them by.
///
/// Some params are genuinely not for the editor -- they are written by another
/// program through the API. Those are listed here, so that exempting one is a
/// visible decision rather than a silent gap.
const NOT_FOR_THE_EDITOR = new Set([
  // Written by the MCP traffic tool, which builds its own project.
  "recordTraffic.urlContains",
]);

test("every optional param the runner reads has a box in the editor", async () => {
  const runner = await readFile(RUNNER_RS, "utf8");
  const execBody = execBlockBody(runner);
  const PARAMS = await loadEditorParams();

  const missing = [];
  for (const kind of kindsFromRunner(runner)) {
    const read = paramsForKind(execBody, kind);
    if (!read) continue;
    const offered = new Set((PARAMS[kind] ?? []).map((s) => s.key));
    for (const key of read) {
      if (!offered.has(key) && !NOT_FOR_THE_EDITOR.has(`${kind}.${key}`)) {
        missing.push(`${kind}.${key}`);
      }
    }
  }

  assert.deepEqual(
    missing,
    [],
    `the runner reads these, but nobody using the editor can set them: ${missing.join(", ")}`,
  );
});

test("params the runner reads as numbers are not offered as text", async () => {
  const runner = await readFile(RUNNER_RS, "utf8");
  const execBody = execBlockBody(runner);
  const PARAMS = await loadEditorParams();

  // `as_u64()` on a JSON string returns None, so a box that stores "1000"
  // fails the step with the same message as an empty one.
  for (const [kind, specs] of Object.entries(PARAMS)) {
    const arm = execBody.indexOf(`"${kind}" => {`);
    if (arm < 0) continue;
    for (const spec of specs) {
      const readsNumber = new RegExp(
        `get\\(\\s*"${spec.key}"\\s*\\)[\\s\\S]{0,120}?as_(u64|i64|f64)\\(\\)`,
      ).test(execBody.slice(arm));
      if (readsNumber) {
        assert.equal(
          spec.numeric,
          true,
          `the runner reads ${kind}.${spec.key} as a number, so the editor must store one`,
        );
      }
    }
  }
});
