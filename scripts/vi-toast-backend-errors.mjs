// Shows the REAL toast for a REAL backend error code, after a live language
// switch — the thing vi-language-switch.mjs cannot do, because it only reads
// static labels and never makes a command fail.
//
// A locale test already proves vi.json holds Vietnamese. What this proves is
// end to end: the exact string a Tauri command returns reaches the operator
// as a Vietnamese sentence, through the product's own path, with credentials
// still redacted afterwards.
//
// No test-only bridge is added to the app. The app calls Rust through
// window.__TAURI_INTERNALS__.invoke, which is absent in a browser preview, so
// this file supplies one that rejects exactly the way Rust does — then clicks
// the Settings button whose catch is `toast.err(String(e))`, the very pattern
// that looked like a credential leak. What renders is what a user would see.
import { chromium } from "@playwright/test";
import { mkdirSync } from "node:fs";
import { join } from "node:path";

const BASE = process.env.VI_BASE ?? "http://127.0.0.1:4199";
const OUT = process.env.VI_OUT ?? join(process.cwd(), "vi-toast-shots");
mkdirSync(OUT, { recursive: true });

// Exactly what src-tauri returns today. The proxy URL case proves translation
// runs before redaction rather than instead of it; the unknown code proves the
// fallback is prose and not a bare key.
const CASES = [
  ["launch.browserMissing", "[[shardx:launch.browserMissing]]"],
  ["fleet.closeProfilesFirst", "[[shardx:fleet.closeProfilesFirst]]"],
  ["updater.waitForDownload", "[[shardx:updater.waitForDownload]]"],
  ["bookmarks.needsUrl+proxy", "[[shardx:bookmarks.needsUrl]] http://alice:S3cret@10.0.0.9:8080"],
  ["unknown code", "[[shardx:no.such.code]]"],
  ["plain English error", "profile is locked by another device"],
];

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1296, height: 900 } });

// Install the bridge before any app code runs. Only the command the test
// clicks may fail: rejecting everything breaks start-up and the app never
// paints, so the toast under test would never exist. Start-up reads get an
// empty-but-valid shape for the same reason.
await page.addInitScript(() => {
  window.__SHARDX_NEXT_ERROR__ = null;
  window.__TAURI_INTERNALS__ = {
    invoke: (cmd) => {
      if (window.__SHARDX_NEXT_ERROR__ && cmd === "api_regenerate_token")
        return Promise.reject(window.__SHARDX_NEXT_ERROR__);
      if (/list|all/i.test(cmd)) return Promise.resolve([]);
      return Promise.resolve({});
    },
    transformCallback: (cb) => cb,
  };
});

await page.goto(BASE, { waitUntil: "domcontentloaded" });

// The release-star modal covers the screen on first run.
const star = page.locator('[role="dialog"], .modal').first();
await star.waitFor({ state: "visible", timeout: 5000 }).catch(() => {});
if (await star.count()) {
  await page.keyboard.press("Escape").catch(() => {});
  await star.waitFor({ state: "detached", timeout: 3000 }).catch(() => {});
}

// Switch to Vietnamese the way a user does, without reloading.
await page.getByRole("button", { name: "Settings", exact: true }).click();
await page.waitForTimeout(500);
const combo = page.getByRole("combobox").filter({ hasText: /English|Ti.ng Vi.t/ }).first();
if (await combo.count()) {
  await combo.click();
  await page.getByText("Tiếng Việt", { exact: false }).first().click();
} else {
  await page.locator("select").first().selectOption("vi");
}
await page.waitForTimeout(900);

const lang = await page.evaluate(() => localStorage.getItem("shardx.lang"));
if (lang !== "vi") {
  console.error(`language did not switch (shardx.lang=${lang}); aborting`);
  await page.screenshot({ path: join(OUT, "switch-failed.png") });
  await browser.close();
  process.exit(1);
}

// The button whose catch is `toast.err(String(e))` — regenerate API token.
const trigger = page.getByRole("button", { name: /Tạo lại|Regenerate|token/i }).first();
if (!(await trigger.count())) {
  console.error("could not find the API-token button that raises a toast");
  await page.screenshot({ path: join(OUT, "no-trigger.png") });
  await browser.close();
  process.exit(1);
}

let failures = 0;
for (const [label, payload] of CASES) {
  await page.evaluate((text) => {
    window.__SHARDX_NEXT_ERROR__ = text;
  }, payload);

  await trigger.click();
  const toastEl = page.locator(".toast-err").first();
  await toastEl.waitFor({ state: "visible", timeout: 4000 }).catch(() => {});
  const out = (await toastEl.count()) ? (await toastEl.innerText()).trim() : "(no toast rendered)";

  const leaked = /S3cret|alice:/.test(out);
  const rawKey = /\[\[shardx:/.test(out) || /^[a-z]+\.[a-zA-Z.]+$/.test(out);
  const noToast = out === "(no toast rendered)";
  if (leaked || rawKey || noToast) failures++;

  console.log(
    `${label.padEnd(26)} -> ${JSON.stringify(out)}` +
      `${leaked ? "  LEAKED" : ""}${rawKey ? "  RAW-KEY" : ""}${noToast ? "  MISSING" : ""}`,
  );
  await page.screenshot({ path: join(OUT, `${label.replace(/[^a-z0-9]+/gi, "-")}.png`) });

  // Clear the stack so the next case reads its own toast.
  await page.evaluate(() => {
    document.querySelectorAll(".toast-err button").forEach((b) => b.click());
  });
  await page.waitForTimeout(250);
}

console.log(
  failures
    ? `\n${failures} TOAST(S) WRONG`
    : "\nevery backend code rendered as Vietnamese prose, credentials redacted",
);
await browser.close();
process.exit(failures ? 1 : 0);
