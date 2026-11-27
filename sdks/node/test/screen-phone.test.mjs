// A phone keeps the handset's screen whatever the screen mode says.
import { test } from "node:test";
import assert from "node:assert/strict";
import { configClaimsMobile } from "../dist/profile.js";
import { applyScreenStrategy } from "../dist/screen.js";

const phone = () => ({
  client_hints: { mobile: true },
  screen: { width: 412, height: 915, avail_width: 412, avail_height: 915 },
  window: { outer_width: 412, outer_height: 915, inner_width: 412, inner_height: 800 },
});

test("a phone is recognised by the engine's three signals", () => {
  assert.equal(configClaimsMobile({ client_hints: { mobile: true } }), true);
  assert.equal(configClaimsMobile({ client_hints: { platform: "Android" } }), true);
  assert.equal(configClaimsMobile({ navigator: { user_agent: "Mozilla/5.0 (Linux; Android 10; K)" } }), true);
  assert.equal(configClaimsMobile({ navigator: { platform: "Linux armv8l" } }), false);
  assert.equal(configClaimsMobile({ navigator: { user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" } }), false);
});

test("every screen mode leaves a phone's screen and window alone", () => {
  for (const mode of ["profile", "cap_to_host", "use_host"]) {
    const cfg = phone();
    applyScreenStrategy(cfg, mode);
    assert.deepEqual(cfg, phone(), mode);
  }
});
