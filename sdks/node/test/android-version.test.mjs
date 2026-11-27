// Phone profiles report the Chrome for Android build of the engine's major, under the Chrome brand.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { applyChromeBrand, applyEngineVersion } from "../dist/profile.js";
import { Runtime } from "../dist/runtime.js";

const phone = () => ({ navigator: { user_agent: "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Mobile Safari/537.36" },
  client_hints: { mobile: true, brand_full_version: "156.0.8078.48" } });

test("a phone gets the Android build, with the build and patch from it", () => {
  const cfg = phone();
  applyEngineVersion(cfg, "157.0.8103.39", undefined, undefined, undefined, "157.0.8103.38");
  assert.equal(cfg.client_hints.brand_version, "157");
  assert.equal(cfg.client_hints.brand_full_version, "157.0.8103.38");
  assert.equal(cfg.client_hints.chrome_patch, 38);
  assert.match(cfg.navigator.user_agent, /Chrome\/157\.0\.0\.0 Mobile/);
});

test("no Android build, or one of another major, keeps the engine's", () => {
  for (const android of [undefined, "156.0.8078.81", "157.0.8103", ""]) {
    const cfg = phone();
    applyEngineVersion(cfg, "157.0.8103.39", undefined, undefined, undefined, android);
    assert.equal(cfg.client_hints.brand_full_version, "157.0.8103.39", String(android));
  }
});

test("a phone with no brand gets Google Chrome, a named one stays", () => {
  const bare = phone();
  applyChromeBrand(bare);
  assert.equal(bare.client_hints.brand, "Google Chrome");
  const named = { client_hints: { brand: "Chromium" } };
  applyChromeBrand(named);
  assert.equal(named.client_hints.brand, "Chromium");
  const noHints = {};
  applyChromeBrand(noHints);
  assert.deepEqual(noHints, {});
});

test("a desktop profile gets the build its OS is shipped, with the build and patch from it", () => {
  for (const [platform, want, patch] of [["Windows", "158.0.8127.37", 37], ["Linux", "158.0.8127.36", 36]]) {
    const cfg = { navigator: { platform, user_agent: "Mozilla/5.0 Chrome/157.0.0.0 Safari/537.36" },
      client_hints: { mobile: false, brand_full_version: "157.0.8103.50" } };
    applyEngineVersion(cfg, "158.0.8127.36", undefined, undefined, undefined, want);
    assert.equal(cfg.client_hints.brand_full_version, want, platform);
    assert.equal(cfg.client_hints.chrome_patch, patch, platform);
    assert.match(cfg.navigator.user_agent, /Chrome\/158\.0\.0\.0 /);
  }
});

test("a runtime names no other build for a platform the manifest does not list", () => {
  const rt = new Runtime({ cacheDir: mkdtempSync(join(tmpdir(), "shardx-claimed-")) });
  assert.equal(rt.claimedChromiumVersion("Windows", false), undefined);
  assert.equal(rt.claimedChromiumVersion("Android", true), undefined);
});
