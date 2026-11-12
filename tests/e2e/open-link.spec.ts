import { expect, test, type Page } from "@playwright/test";

// A shardbrowser://open link only names a profile: the launcher asks first,
// showing the name, and starts nothing until the operator confirms.
async function open(page: Page) {
  await page.goto("/?e2e=default", { waitUntil: "domcontentloaded" });
  await expect(page.getByText("VN Automation 001 - No Proxy").first()).toBeVisible();
}

// The backend queues the links and emits `open-link`; the mock queue stands in for it.
async function link(page: Page, ref: string | null) {
  await page.evaluate((r) => {
    const w = window as unknown as {
      __e2eOpenLinks?: (string | null)[];
      __TAURI_INTERNALS__: { invoke: (cmd: string, args: object) => Promise<unknown> };
    };
    (w.__e2eOpenLinks ??= []).push(r);
    return w.__TAURI_INTERNALS__.invoke("plugin:event|emit", { event: "open-link", payload: null });
  }, ref);
}

const launches = (page: Page) => page.locator("html").getAttribute("data-e2e-launches");

test("a link asks with the profile name, Cancel starts nothing, Start launches it", async ({ page }) => {
  await open(page);
  await link(page, "VN Automation 001 - No Proxy");
  const dialog = page.getByRole("dialog");
  await expect(dialog).toContainText("Start profile");
  await expect(dialog).toContainText("“VN Automation 001 - No Proxy”");
  await dialog.getByRole("button", { name: "Cancel" }).click();
  await expect(dialog).toHaveCount(0);
  expect(await launches(page)).toBeNull();

  // By id this time; the fixture launch fails, which proves Start reached it.
  await link(page, "profile-alpha");
  await page.getByRole("dialog").getByRole("button", { name: "Start", exact: true }).click();
  await expect(page.getByText("fixture browser launch failed").first()).toBeVisible();
  expect(await launches(page)).toBe("1");
});

test("a running profile is not asked about, an unknown or malformed link gets a toast", async ({ page }) => {
  await open(page);
  await link(page, "Beta Research");
  await expect(page.getByText("“Beta Research” is already running.")).toBeVisible();
  await link(page, "no-such-profile");
  await expect(page.getByText("No profile matches that link.")).toBeVisible();
  await link(page, null);
  await expect(page.getByText("That link is not a valid profile link and was ignored.")).toBeVisible();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  expect(await launches(page)).toBeNull();
});

test("a profile started while the dialog is open is not stopped by Start", async ({ page }) => {
  await open(page);
  await link(page, "profile-alpha");
  const dialog = page.getByRole("dialog");
  await expect(dialog).toContainText("Start profile");
  await page.evaluate(() => {
    (window as unknown as { __e2eStartedElsewhere?: string[] }).__e2eStartedElsewhere = ["profile-alpha"];
  });
  await dialog.getByRole("button", { name: "Start", exact: true }).click();
  await expect(page.getByText("is already running.").first()).toBeVisible();
  expect(await launches(page)).toBeNull();
});
