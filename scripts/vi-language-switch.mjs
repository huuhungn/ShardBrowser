// Loads the app in English, switches to Vietnamese the way a user does — from
// the settings screen, without reloading — then reads every screen.
//
// vi-screens.mjs sets the language before the first paint, so every module is
// imported with Vietnamese already loaded. That hides the one bug this file
// exists to catch: a label built at import time keeps whichever language was
// loaded then, and a walk that never switches mid-session always looks clean.
import { chromium } from "@playwright/test";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const BASE = process.env.VI_BASE ?? "http://127.0.0.1:4199";
const OUT = process.env.VI_OUT ?? join(process.cwd(), "vi-switch-shots");
mkdirSync(OUT, { recursive: true });

const SCREENS = [
  ["browsers", "Trình duyệt"],
  ["proxies", "Proxy"],
  ["fingerprints", "Vân tay"],
  ["extensions", "Tiện ích"],
  ["bookmarks", "Dấu trang"],
  ["trash", "Thùng rác"],
  ["automation", "Tự động hoá"],
  ["proxyshard", "ProxyShard"],
  ["settings", "Cài đặt"],
];

// Words that are English on purpose: product names, protocol tokens, and the
// patch log's upstream commit subjects.
const ALLOWED = [
  "ShardX", "ProxyShard", "Chrome", "Chromium", "Windows", "Linux", "macOS",
  "HTTP", "HTTPS", "SOCKS5", "Header", "User-Agent", "WebGL", "WebRTC", "Canvas",
  "GPU", "API", "URL", "IP", "DNS", "TLS", "JSON", "CSV", "ID", "UUID", "MCP",
  "Playwright", "Puppeteer", "Selenium", "GitHub", "OK", "Accept-Language",
];

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1296, height: 900 } });

// Start in English, explicitly — this is the state the bug needs.
await page.goto(BASE, { waitUntil: "domcontentloaded" });
await page.evaluate(() => localStorage.setItem("shardx.lang", "en"));
await page.reload({ waitUntil: "domcontentloaded" });
await page.waitForTimeout(600);

const starModal = page.locator(".fixed.inset-0.z-50");
await starModal.waitFor({ state: "visible", timeout: 5000 }).catch(() => {});
if (await starModal.count()) {
  await page.getByRole("button", { name: /later|maybe|not now|close/i }).first().click().catch(async () => {
    await page.keyboard.press("Escape");
  });
  await page.waitForTimeout(300);
}

// The app navigates through its sidebar, not the URL, so drive it the way a
// person does — by the English name, because English is still loaded.
const EN_NAMES = {
  browsers: "Browsers", proxies: "Proxies", fingerprints: "Fingerprints",
  extensions: "Extensions", bookmarks: "Bookmarks", trash: "Trash",
  automation: "Automation", proxyshard: "ProxyShard", settings: "Settings",
};

// Visit every screen in English first, so each module is imported while English
// is the loaded language. A frozen label is only wrong after this point.
for (const [route] of SCREENS) {
  await page.getByRole("button", { name: EN_NAMES[route], exact: true }).click();
  await page.waitForTimeout(250);
}

// Now switch to Vietnamese from the settings screen, the way a user would,
// and do NOT reload: a reload would re-import every module and hide the bug.
await page.getByRole("button", { name: "Settings", exact: true }).click();
await page.waitForTimeout(400);
const combo = page.getByRole("combobox").filter({ hasText: /English|Ti.ng Vi.t/ }).first();
if (await combo.count()) {
  await combo.click();
  await page.getByText("Tiếng Việt", { exact: false }).first().click();
} else {
  const select = page.locator("select").first();
  await select.selectOption("vi");
}
await page.waitForTimeout(900);

// Prove the switch actually happened before judging anything as an escape.
const langNow = await page.evaluate(() => localStorage.getItem("shardx.lang"));
if (langNow !== "vi") {
  console.error(`language did not switch (shardx.lang=${langNow}); aborting`);
  await page.screenshot({ path: join(OUT, "switch-failed.png") });
  await browser.close();
  process.exit(1);
}

const englishLeft = /\b(Add|Delete|Remove|Save|Cancel|Close|Enable|Disable|Import|Export|Settings|Profile|Profiles|Proxy list|Search|Refresh|Failed|Success|Loading|Ready|Never|Unknown|Other|Privacy|Headers|Block|Blocks|Step|Steps|Run|Stop|Start|Edit|New|Copy|Paste|Select|Clear|Apply|Reset|Back|Next|Done|Yes|No|not tested|try again|up to date|ready to install)\b/g;

const report = [];
for (const [route, label] of SCREENS) {
  await page.getByRole("button", { name: label, exact: true }).click();
  await page.waitForTimeout(450);
  const shot = join(OUT, `${route}.png`);
  await page.screenshot({ path: shot, fullPage: true });
  const text = await page.locator("body").innerText();

  // Profile names, notes and proxy hosts are the user's own data: "VN
  // Automation 001 - No Proxy" is a name someone typed, not an untranslated
  // label, and reading the table body as UI text reports it forever.
  const chrome = await page
    .locator("body")
    .evaluate((el) => {
      const clone = el.cloneNode(true);
      for (const cell of clone.querySelectorAll(
        "tbody td, tbody th, .t-cols, [data-row], [role='row']",
      )) {
        cell.remove();
      }
      return clone.innerText;
    });

  const raw = [...text.matchAll(/\b[a-z]+\.[a-z][A-Za-z.]+\b/g)]
    .map((m) => m[0])
    // A host name is not a translation key: shardx.lang is, api.proxyshard.com
    // is not, and the difference is the top-level domain on the end.
    .filter((s) => !/\.(com|net|org|io|dev|json|exe|md|ts|tsx|local)$/.test(s));
  // Remove the allowed words as whole words: a plain substring removal splices
  // what is left together — "AUTOMATION API" became "AUTOMATION", whose tail
  // then read as the English word "No".
  const scrubbed = chrome.replace(
    new RegExp(`\\b(?:${ALLOWED.map((w) => w.replace(/[.*+?^${}()|[\]\\-]/g, "\\$&")).join("|")})\\b`, "g"),
    " ",
  );
  const english = [...new Set([...scrubbed.matchAll(englishLeft)].map((m) => m[0]))];

  report.push({ route, label, shot, rawKeys: [...new Set(raw)], english });
  console.log(
    `${route.padEnd(14)} english=${english.length ? english.join(",") : "none"}` +
      ` rawKeys=${raw.length ? [...new Set(raw)].join(",") : "none"}`,
  );
}
writeFileSync(join(OUT, "report.json"), JSON.stringify(report, null, 1), "utf8");
const bad = report.filter((r) => r.english.length || r.rawKeys.length);
console.log(bad.length ? `\nSCREENS WITH ESCAPES: ${bad.map((b) => b.route).join(", ")}` : "\nall screens clean after a live language switch");
await browser.close();
