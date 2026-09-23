// Walks the app in Vietnamese and writes one screenshot per screen, plus the
// visible text, so the translation can be read rather than assumed.
import { chromium } from "@playwright/test";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const BASE = process.env.VI_BASE ?? "http://127.0.0.1:4188";
const OUT = process.env.VI_OUT ?? join(process.cwd(), "vi-shots");
mkdirSync(OUT, { recursive: true });

const SCREENS = [
  ["browsers", "Trình duyệt"],
  ["proxies", "Proxy"],
  ["fingerprints", "Vân tay"],
  ["extensions", "Tiện ích"],
  ["bookmarks", "Dấu trang"],
  ["trash", "Thùng rác"],
  ["automation", "Tự động hoá"],
  ["patchlog", "Nhật ký vá"],
  ["proxyshard", "ProxyShard"],
  ["settings", "Cài đặt"],
];

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1296, height: 900 } });

// Set the language the way the app itself does, then reload so every screen
// mounts already translated.
await page.goto(BASE, { waitUntil: "domcontentloaded" });
await page.evaluate(() => localStorage.setItem("shardx.lang", "vi"));
await page.reload({ waitUntil: "domcontentloaded" });
await page.waitForTimeout(600);

// The one-time star prompt covers the sidebar on a fresh profile. Read it
// first (it is a screen too), then dismiss it so the walk can proceed.
const starModal = page.locator(".fixed.inset-0.z-50");
await starModal.waitFor({ state: "visible", timeout: 5000 }).catch(() => {});
if (await starModal.count()) {
  const starText = await starModal.innerText();
  mkdirSync(OUT, { recursive: true });
  await page.screenshot({ path: join(OUT, "star-prompt.png") });
  writeFileSync(join(OUT, "star-prompt.txt"), starText, "utf8");
  console.log("== star prompt ==\n  " + starText.split("\n").filter(Boolean).join(" | "));
  await page.getByRole("button", { name: "Để sau", exact: true }).click();
  await starModal.waitFor({ state: "detached", timeout: 5000 }).catch(() => {});
  await page.waitForTimeout(300);
}

const report = [];
for (const [route, label] of SCREENS) {
  // The app navigates through its sidebar rather than the URL, so drive it the
  // way a person does: click the entry, by its Vietnamese name.
  await page.getByRole("button", { name: label, exact: true }).click();
  await page.waitForTimeout(700);
  const shot = join(OUT, `${route}.png`);
  await page.screenshot({ path: shot, fullPage: false });
  const text = await page.evaluate(() => document.body.innerText);
  // Anything that still looks like a raw key is the failure worth seeing.
  const rawKeys = [...text.matchAll(/\b[a-z]+\.[a-zA-Z][a-zA-Z0-9]+\b/g)]
    .map((m) => m[0])
    .filter((s) => !/\.(com|net|org|io|json|exe|dev|md|ts|tsx)$/.test(s));
  report.push({ route, label, shot, rawKeys: [...new Set(rawKeys)], text });
}

await browser.close();
writeFileSync(join(OUT, "report.json"), JSON.stringify(report, null, 1), "utf8");
for (const r of report) {
  console.log(`== ${r.route} ==`);
  if (r.rawKeys.length) console.log(`  RAW KEYS: ${r.rawKeys.join(", ")}`);
  console.log(
    "  " +
      r.text
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean)
        .slice(0, 14)
        .join(" | "),
  );
}
