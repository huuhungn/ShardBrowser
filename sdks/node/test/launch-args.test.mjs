// Launch decisions that need no engine: the CDP switches and the profile
// claims that pick whether WebGPU is switched off.
import test from "node:test";
import assert from "node:assert/strict";

import { CDP_ARGS } from "../dist/browser.js";
import { Profile } from "../dist/profile.js";

test("CDP launches unlock the Motion domain", () => {
  assert.ok(CDP_ARGS.includes("--shardx-automation"));
  assert.ok(CDP_ARGS.includes("--remote-debugging-port=0"));
});

test("desktop Linux is claimed by its platform, Android is not", () => {
  const linux = new Profile({ navigator: { platform: "Linux x86_64" } });
  assert.equal(linux.claimsLinuxDesktop, true);
  assert.equal(linux.claimsMobile, false);

  const android = new Profile({
    navigator: { platform: "Linux armv81", user_agent: "Mozilla/5.0 (Linux; Android 14)" },
  });
  assert.equal(android.claimsMobile, true);
  assert.equal(android.claimsLinuxDesktop, false);

  assert.equal(new Profile({ client_hints: { mobile: true } }).claimsMobile, true);
  assert.equal(new Profile({ navigator: { platform: "Win32" } }).claimsLinuxDesktop, false);
});
