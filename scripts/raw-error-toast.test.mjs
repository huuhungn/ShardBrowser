// A backend error must reach the operator through `safeUiError`.
//
// `toast.err(String(e))` renders whatever the backend said. Commands now answer
// in error codes, so that call shows a raw `[[shardx:...]]` marker instead of a
// sentence — and it skips the token scrubbing `safeUiError` performs, which is
// why a failing proxy call could print credentials into a screenshot.
//
// The rule is cheap to state and easy to break during a refactor, so it is
// pinned here rather than left to review.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import assert from "node:assert/strict";

const SRC = new URL("../src/", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");

const walk = (dir) =>
  readdirSync(dir).flatMap((name) => {
    const full = join(dir, name);
    return statSync(full).isDirectory() ? walk(full) : [full];
  });

const sources = walk(SRC).filter((f) => f.endsWith(".ts") || f.endsWith(".tsx"));

test("a backend error is never toasted raw", () => {
  const offenders = [];
  for (const file of sources) {
    const lines = readFileSync(file, "utf8").split(/\r?\n/);
    lines.forEach((line, i) => {
      // The first shape this guard caught was `toast.err(String(e))`. The
      // marker leaks just as badly when the raw error is one argument among
      // several — `toast.err(t("x") + String(e))`, `t("x", { error: String(e) })`
      // — or when it is stored for later rendering with `setErr(String(e))`.
      // Match the raw error anywhere in the call, and let `safeUiError` on the
      // line clear it.
      // A fourth shape skips the toast helpers entirely: the error is stashed
      // in state (`err: String(e)`, `setPwErr(String(e))`) and rendered later,
      // which leaks the same marker one component away from the catch block.
      const viaHelper = /(?:toast\.err|set(?:[A-Z]\w*)?(?:Err|Error)\w*)\([^;]*(?:String\(|`\$\{|\?\.message)/.test(line);
      const viaState = /\b(?:err|error)\s*:\s*(?:String\(|`\$\{)/.test(line);
      const raw = viaHelper || viaState;
      if (raw && !line.includes("safeUiError")) {
        offenders.push(`${file.slice(SRC.length)}:${i + 1}`);
      }
    });
  }
  assert.deepEqual(
    offenders,
    [],
    `these toasts show the backend's raw answer; wrap the error in safeUiError():\n  ${offenders.join(
      "\n  ",
    )}`,
  );
});

test("safeUiError resolves a marker and scrubs a token", () => {
  // Guards the two jobs that make the wrapper worth requiring above.
  const utils = readFileSync(join(SRC, "shared/lib/utils.ts"), "utf8");
  assert.match(utils, /export const safeUiError/);
  const body = utils.slice(utils.indexOf("export const safeUiError"));
  assert.match(body, /localiseBackendError\(/);
  assert.match(body, /Bearer/);
});
