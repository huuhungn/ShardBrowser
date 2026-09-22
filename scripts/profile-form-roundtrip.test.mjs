// The editor must not change a profile the operator did not change.
//
// Regression guard for the platform_version round trip. The form is the only
// path between what is on disk and what gets written back, so a field the form
// forgets to read is a field save silently rebuilds from the preset. That is
// how editing an unrelated noise toggle moved a profile from one macOS release
// to another: fromStored() never read navigator.platform_version, the form
// kept its "" default, and toStored() then took the preset's value instead.
//
// A test that only checked toStored() would have passed throughout: the bug
// lives in the gap between the two halves, so only a full load-then-save round
// trip can catch it.

import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";

import { build } from "esbuild";

const ROOT = path.resolve(import.meta.dirname, "..");

/// The form module compiled to something node can import.
///
/// It is TypeScript and it imports sibling TypeScript, so it cannot be loaded
/// directly. Bundling it here keeps the test honest -- it exercises the real
/// module rather than a copy of its logic transcribed into the test.
async function loadFormModule() {
  const dir = await mkdtemp(path.join(os.tmpdir(), "shardx-form-"));
  const outfile = path.join(dir, "form.mjs");
  await build({
    entryPoints: [path.join(ROOT, "src/entities/profile/model/form.ts")],
    outfile,
    bundle: true,
    format: "esm",
    platform: "node",
    logLevel: "silent",
  });
  const mod = await import(pathToFileURL(outfile).href);
  return { mod, cleanup: () => rm(dir, { recursive: true, force: true }) };
}

/// A profile as the launcher writes it: the preset's payload, with the values
/// randomised per-profile at creation already substituted in.
function storedProfile({ platformVersion }) {
  return {
    _meta: { id: "p1", proxy_id: null, gpu_preset_id: "mac-m2-mbp13", extensions: [] },
    name: "shop-pl-1",
    notes: "",
    timezone: "auto",
    webrtc: "auto",
    navigator: {
      user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
      hardware_concurrency: 8,
      device_memory: 8,
      language: "auto",
      platform_version: platformVersion,
      do_not_track: null,
    },
    client_hints: { platform_version: platformVersion },
    noise: { canvas: { enabled: true }, webgl: { enabled: true } },
  };
}

/// The library preset the profile was built from. Its platform_version is the
/// donor machine's, NOT this profile's -- that is the whole point: creation
/// randomises away from it, and an edit must not undo that.
const PRESET = {
  id: "mac-m2-mbp13",
  label: "MacBook Pro 13 (M2)",
  platform: "macos",
  payload: {
    navigator: {
      user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
      hardware_concurrency: 8,
      device_memory: 8,
      platform_version: "15.6.1",
    },
    client_hints: { platform_version: "15.6.1" },
    webgl: { renderer: "Apple M2", extensions: [] },
  },
};

test("an edit that touches nothing keeps the OS version the profile was created with", async () => {
  const { mod, cleanup } = await loadFormModule();
  try {
    // 14.7 is what creation randomised to; 15.6.1 is what the preset says.
    const stored = storedProfile({ platformVersion: "14.7" });

    const form = mod.fromStored(stored);
    assert.equal(
      form.platform_version,
      "14.7",
      "the editor must load the version the profile actually has",
    );

    const saved = mod.toStored(form, PRESET);
    assert.equal(
      saved.navigator.platform_version,
      "14.7",
      "saving an untouched form must not adopt the preset's OS version",
    );
    assert.equal(
      saved.client_hints.platform_version,
      "14.7",
      "client hints must agree with navigator, or the two contradict each other",
    );
  } finally {
    await cleanup();
  }
});

test("a profile written before navigator carried the version reads it from client hints", async () => {
  const { mod, cleanup } = await loadFormModule();
  try {
    const stored = storedProfile({ platformVersion: "13.4" });
    delete stored.navigator.platform_version;

    const form = mod.fromStored(stored);
    assert.equal(form.platform_version, "13.4");

    const saved = mod.toStored(form, PRESET);
    assert.equal(saved.navigator.platform_version, "13.4");
    assert.equal(saved.client_hints.platform_version, "13.4");
  } finally {
    await cleanup();
  }
});

test("a deliberate change to the OS version is still honoured", async () => {
  const { mod, cleanup } = await loadFormModule();
  try {
    const stored = storedProfile({ platformVersion: "14.7" });
    const form = mod.fromStored(stored);

    const saved = mod.toStored({ ...form, platform_version: "15.1" }, PRESET);
    assert.equal(saved.navigator.platform_version, "15.1");
    assert.equal(saved.client_hints.platform_version, "15.1");
  } finally {
    await cleanup();
  }
});

test("a profile that never had an OS version still inherits the preset's", async () => {
  const { mod, cleanup } = await loadFormModule();
  try {
    // Nothing on disk to preserve, so the preset's value is the right answer
    // rather than a regression -- the empty form field means "inherit donor".
    const stored = storedProfile({ platformVersion: "14.7" });
    delete stored.navigator.platform_version;
    delete stored.client_hints;

    const form = mod.fromStored(stored);
    assert.equal(form.platform_version, "");

    const saved = mod.toStored(form, PRESET);
    assert.equal(
      saved.navigator.platform_version,
      "15.6.1",
      "with nothing to preserve the preset's value is what should land",
    );
  } finally {
    await cleanup();
  }
});
