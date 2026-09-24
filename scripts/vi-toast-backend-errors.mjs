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
import { mkdirSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { spawn } from "node:child_process";

const OUT = process.env.VI_OUT ?? join(process.cwd(), "vi-toast-shots");
mkdirSync(OUT, { recursive: true });

// Serving whatever is in dist/ is unsafe: `npm run test:e2e` leaves it built
// with --mode e2e, whose mock bridge answers every invoke with "Unhandled E2E
// command" — the toast then shows that instead of the translated error, and an
// earlier version of this script called that a pass. Build production here and
// refuse to run if the mock is present.
const run = (cmd, args, opts = {}) =>
  new Promise((resolve, reject) => {
    const p = spawn(cmd, args, { stdio: "inherit", shell: process.platform === "win32", ...opts });
    p.on("exit", (code) => (code === 0 ? resolve() : reject(new Error(`${cmd} exited ${code}`))));
  });

let server;
const BASE = process.env.VI_BASE;
if (!BASE) {
  console.log("building production bundle…");
  await run("npm", ["run", "build"]);
  const mocked = readdirSync("dist/assets").filter(
    (f) => f.endsWith(".js") && readFileSync(join("dist/assets", f), "utf8").includes("Unhandled E2E command"),
  );
  if (mocked.length) {
    console.error(`dist/ still carries the E2E mock (${mocked[0]}); refusing to test against it.`);
    process.exit(1);
  }
  // Run vite.js with this Node directly: `npx` behind a shell makes server.pid
  // the shell's, so killing it leaves the real preview holding the port and CI
  // waits forever on an open handle.
  server = spawn(process.execPath, [join("node_modules", "vite", "bin", "vite.js"), "preview", "--port", "4199", "--strictPort"], {
    stdio: "ignore",
  });
  for (let i = 0; i < 40; i++) {
    try {
      await fetch("http://127.0.0.1:4199/");
      break;
    } catch {
      await new Promise((r) => setTimeout(r, 500));
    }
  }
}
const stopServer = () => {
  server?.kill();
};

const TARGET = BASE ?? "http://127.0.0.1:4199";

// Exactly what src-tauri returns today. The proxy URL case proves translation
// runs before redaction rather than instead of it; the unknown code proves the
// fallback is prose and not a bare key.
const CASES = [
  ["launch.browserMissing", "[[shardx:launch.browserMissing]]", "vi"],
  ["fleet.closeProfilesFirst", "[[shardx:fleet.closeProfilesFirst]]", "vi"],
  ["updater.waitForDownload", "[[shardx:updater.waitForDownload]]", "vi"],
  ["bookmarks.needsUrl+proxy", "[[shardx:bookmarks.needsUrl]] http://alice:S3cret@10.0.0.9:8080", "vi"],
  ["unknown code", "[[shardx:no.such.code]]", "vi"],
  // A real fleet_client chain: anyhow joins the outer context to the inner
  // cause, so the marker arrives mid-sentence and must still translate.
  [
    "fleet chain mid-sentence",
    "[[shardx:fleet.unreachableUploadChunk]]: connection refused",
    "vi",
  ],
  // A coded refusal carrying the server's own status and words.
  [
    "fleet refusal with args",
    "[[shardx:fleet.refusedClaim|status=409|detail=held by another device]]",
    "vi",
  ],
  // Rust text with no code cannot be translated; it must still reach the user.
  ["plain English error", "profile is locked by another device", "as-is"],
  // A launch failure carrying the operating system's own words. This is the
  // most common real toast: the operator pressed Start and it did not.
  [
    "launch.spawnFailed chain",
    "[[shardx:launch.spawnFailed]]: Access is denied. (os error 5)",
    "vi",
  ],
  // A profile path error: the argument is a Windows path, which contains
  // backslashes and a colon, and must survive the marker intact.
  [
    "profile.parseRecord with path",
    "[[shardx:profile.parseRecord|path=C:\\\\Users\\\\a\\\\profiles\\\\x.json]]",
    "vi",
  ],
  // An automation run refused before it started. This is the reply the HTTP
  // API turns into a 409, so the same code has to read correctly in the panel.
  [
    "runner.profileNotRunning",
    "[[shardx:runner.profileNotRunning|profile_id=VN Automation 001]]",
    "vi",
  ],
  // Two arguments at once, one of them naming a block kind the operator wrote.
  [
    "runner.blockNeedsField",
    "[[shardx:runner.blockNeedsField|kind=dbQuery|field=sql]]",
    "vi",
  ],
  // A CSS selector containing the pipe that separates arguments. If the
  // parser splits naively the selector arrives truncated, so the operator is
  // sent looking at the wrong element.
  [
    "runner.clickNoMatch with a pipe in the selector",
    "[[shardx:runner.clickNoMatch|selector=a[href='/x?a=1%7C2'%5D]]",
    "vi",
  ],
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

await page.goto(TARGET, { waitUntil: "domcontentloaded" });

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
  stopServer();
  process.exit(1);
}

// The button whose catch is `toast.err(String(e))` — regenerate API token.
const trigger = page.getByRole("button", { name: /Tạo lại|Regenerate|token/i }).first();
if (!(await trigger.count())) {
  console.error("could not find the API-token button that raises a toast");
  await page.screenshot({ path: join(OUT, "no-trigger.png") });
  await browser.close();
  stopServer();
  process.exit(1);
}

let failures = 0;
for (const [label, payload, expect] of CASES) {
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
  // A code case must render Vietnamese. Diacritics are the cheap proof: every
  // vi string for these keys carries them, and English never does. Without
  // this the script passed while the app served untranslated English.
  const notVi = expect === "vi" && !/[ăâđêôơưàáảãạèéẻẽẹìíỉĩịòóỏõọùúủũụỳýỷỹỵ]/i.test(out);
  const bridgeFail = /Unhandled E2E command|__TAURI|is not a function/i.test(out);
  // anyhow joins a context to its cause with ": ", so a locale string that ends
  // in a period renders as ".: connection refused". Catch the seam, not the eye.
  const doublePunct = /[.!?:]\s*[:;]/.test(out);
  if (leaked || rawKey || noToast || notVi || bridgeFail || doublePunct) failures++;

  console.log(
    `${label.padEnd(26)} -> ${JSON.stringify(out)}` +
      `${leaked ? "  LEAKED" : ""}${rawKey ? "  RAW-KEY" : ""}${noToast ? "  MISSING" : ""}` +
      `${notVi ? "  NOT-VIETNAMESE" : ""}${bridgeFail ? "  BRIDGE-BROKEN" : ""}` +
      `${doublePunct ? "  DOUBLE-PUNCTUATION" : ""}`,
  );
  const shot = join(OUT, `${label.replace(/[^a-z0-9]+/gi, "-")}.png`);
  // Photograph the error toast itself. A full-page shot also catches the
  // unrelated "saved" toast, which makes the evidence contradict the
  // assertion above.
  if (await toastEl.count()) await toastEl.screenshot({ path: shot });
  else await page.screenshot({ path: shot });

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
stopServer();
process.exit(failures ? 1 : 0);
