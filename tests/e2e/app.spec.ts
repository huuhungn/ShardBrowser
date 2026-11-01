import { expect, test, type Page } from "@playwright/test";

async function gotoMocked(page: Page, path = "/") {
  await page.goto(path, { waitUntil: "domcontentloaded" });
}

test("startup loading, profile error, and retry are deterministic", async ({ page }) => {
  await gotoMocked(page, "/?e2e=profile-error-once&profilesDelay=400");

  await expect(page.getByRole("status").filter({ hasText: "Loading profiles" })).toBeVisible();
  await expect(page.getByRole("alert").filter({ hasText: "Profiles could not be loaded" })).toBeVisible();
  await page.getByRole("button", { name: "Retry" }).evaluate((button) => {
    (button as HTMLButtonElement).click();
    (button as HTMLButtonElement).click();
  });
  await expect(page.getByText("VN Automation 001 - No Proxy")).toBeVisible();
  await expect(page.locator("html")).toHaveAttribute("data-e2e-max-profile-lists-in-flight", "1");
});

test("runtime startup error can retry into the app", async ({ page }) => {
  await gotoMocked(page, "/?e2e=runtime-error-once");

  await expect(page.getByRole("alert").filter({ hasText: "Setup failed" })).toBeVisible();
  await page.getByRole("button", { name: "Retry setup" }).evaluate((button) => {
    (button as HTMLButtonElement).click();
    (button as HTMLButtonElement).click();
  });
  await expect(page.getByRole("heading", { name: "Browsers" })).toBeVisible();
  await expect.poll(() => page.locator("html").getAttribute("data-e2e-runtime-checks")).toBe("2");
});

test("runtime install errors remain recoverable", async ({ page }) => {
  await gotoMocked(page, "/?e2e=runtime-install-error-once");

  await expect(page.getByRole("alert").filter({ hasText: "fixture runtime install failed" })).toBeVisible();
  await page.getByRole("button", { name: "Retry setup" }).click();
  await expect(page.getByRole("heading", { name: "Browsers" })).toBeVisible();
});

test("browsers search and responsive actions are keyboard reachable", async ({ page }) => {
  await gotoMocked(page);

  await expect(page.getByRole("heading", { name: "Browsers" })).toBeVisible();
  await page.keyboard.press("ControlOrMeta+K");
  await expect(page.getByRole("searchbox", { name: "Search Browsers" })).toBeFocused();
  await page.getByRole("searchbox", { name: "Search Browsers" }).fill("Beta");
  await expect(page.getByText("Beta Research")).toBeVisible();
  await expect(page.getByText("VN Automation 001 - No Proxy")).toBeHidden();
  await page.getByRole("searchbox", { name: "Search Browsers" }).fill("missing");
  await expect(page.getByRole("heading", { name: "No matching profiles" })).toBeVisible();
  await page.getByRole("button", { name: "Clear search" }).click();
  const profileName = "VN Automation 001 - No Proxy";
  await expect(page.getByRole("button", { name: `Start profile ${profileName}` })).toBeVisible();
  await expect(page.getByRole("button", { name: `Edit profile ${profileName}` })).toBeVisible();
  await expect(page.getByRole("button", { name: `More actions for profile ${profileName}` })).toBeVisible();
  await expect(page.getByRole("button", { name: `Unpin profile ${profileName}` })).toBeHidden();
  await expect(page.getByRole("checkbox", { name: "Select all profiles on this page" })).toBeVisible();
  await expect(page.getByRole("checkbox", { name: `Select profile ${profileName}` })).toBeVisible();
  await expect(page.locator(`.cell-name[title="${profileName}"]`)).toBeVisible();

  await page.getByRole("button", { name: "More actions for profile Beta Research" }).click();
  await expect(page.getByRole("button", { name: "Clone" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Copy CDP HTTP URL" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Copy DevTools inspect URL" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Delete" })).toBeVisible();
  await page.keyboard.press("Escape");
});

test("desktop-wide actions, theme, and launch errors remain visible", async ({ page }) => {
  await page.setViewportSize({ width: 1720, height: 1000 });
  await gotoMocked(page);

  const profileName = "VN Automation 001 - No Proxy";
  await expect(page.getByRole("button", { name: `Unpin profile ${profileName}` })).toBeVisible();
  await expect(page.getByRole("button", { name: "Copy CDP HTTP URL for Beta Research" })).toBeVisible();
  const profileNameText = page.locator(".cell-name .name-main", { hasText: profileName }).first();
  await expect(profileNameText).toBeVisible();
  await expect.poll(() => profileNameText.evaluate((element) => element.scrollWidth <= element.clientWidth)).toBe(true);
  await page.getByRole("tab", { name: "Light" }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await page.getByRole("button", { name: `Start profile ${profileName}` }).click();
  await expect(page.locator(".launch-error-inline")).toContainText("fixture browser launch failed");
  await expect(page.locator(".toast-err")).toHaveAttribute("role", "alert");
});

test("a start that is still on its way can be cancelled", async ({ page }) => {
  await page.setViewportSize({ width: 1720, height: 1000 });
  await gotoMocked(page, "/?e2e=slow-launch");

  const profileName = "VN Automation 001 - No Proxy";
  const start = page.getByRole("button", { name: `Start profile ${profileName}` });
  await start.click();
  // Still starting: the same button now cancels instead of sitting disabled.
  await expect(start).toBeEnabled();
  await expect(start).toHaveText("Cancel");
  await start.click();

  await expect(page.locator(".toast-ok").last()).toContainText("Start cancelled");
  await expect(start).toHaveText("Start");
  // A cancel is a choice, not a failure: nothing is left on the row.
  await expect(page.locator(".launch-error-inline")).toHaveCount(0);
});

test("quitting while browsers run says why it was refused", async ({ page }) => {
  await gotoMocked(page);
  await expect(page.getByRole("button", { name: /^Start profile / }).first()).toBeVisible();
  await page.evaluate(() =>
    (window as unknown as { __TAURI_INTERNALS__: { invoke: (c: string, a: unknown) => Promise<unknown> } })
      .__TAURI_INTERNALS__.invoke("plugin:event|emit", {
        event: "launcher:exit-blocked",
        payload: { running_count: 2 },
      }),
  );
  await expect(page.locator(".toast-err").last()).toContainText("2 browsers");
});

test("legacy custom-font metadata survives an ordinary profile edit but stays hidden", async ({ page }) => {
  await gotoMocked(page);

  const profileName = "VN Automation 001 - No Proxy";
  await page.getByRole("button", { name: `Edit profile ${profileName}` }).click();
  await expect(page.getByText("Custom fonts", { exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Save changes" }).click();

  await expect.poll(async () => {
    const encoded = await page.locator("html").getAttribute("data-e2e-saved-custom-fonts");
    return encoded ? JSON.parse(encoded) : null;
  }).toEqual({
    mode: "append",
    dirs: ["C:\\Fixture\\Fonts"],
    names: ["Fixture Sans"],
    random_count: 1,
  });
});

test("invalid profile names are rejected before profile persistence", async ({ page }) => {
  await gotoMocked(page);

  await page.getByRole("button", { name: "New profile" }).click();
  await page.getByLabel("Profile name").fill("bad/name");
  await page.getByRole("button", { name: "Create profile" }).click();

  await expect(page.getByRole("alert").filter({ hasText: "Invalid profile name" })).toBeVisible();
  await expect(page.locator("html")).toHaveAttribute("data-e2e-profile-name-validations", "1");
  await expect(page.locator("html")).not.toHaveAttribute("data-e2e-profile-saves", /.+/);
});

test("empty profiles are distinct from search results", async ({ page }) => {
  await gotoMocked(page, "/?e2e=profiles-empty");

  await expect(page.getByRole("heading", { name: "No profiles yet" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "No matching profiles" })).toHaveCount(0);
});

test("empty folders have a distinct state", async ({ page }) => {
  await gotoMocked(page, "/?e2e=folder-empty");

  await page.getByRole("button", { name: /Empty QA 0/ }).click();
  await expect(page.getByRole("heading", { name: "Folder is empty" })).toBeVisible();
});

test("proxies empty state is backend-free and sanitized", async ({ page }) => {
  await gotoMocked(page, "/?e2e=proxies-empty");

  await page.getByRole("button", { name: "Proxies" }).click();
  await expect(page.getByRole("heading", { name: "Proxies", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "No proxies yet" })).toBeVisible();
});

test("proxy errors retry single-flight and search can be cleared", async ({ page }) => {
  await gotoMocked(page, "/?e2e=proxy-error-once&proxiesDelay=300");
  await expect(page.getByText("VN Automation 001 - No Proxy")).toBeVisible();

  await page.getByRole("button", { name: "Proxies" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Loading proxies" })).toBeVisible();
  await expect(page.getByRole("alert").filter({ hasText: "Proxies could not be loaded" })).toBeVisible();
  await page.getByRole("button", { name: "Retry" }).evaluate((button) => {
    (button as HTMLButtonElement).click();
    (button as HTMLButtonElement).click();
  });
  await expect(page.getByText("US Sanitize 1")).toBeVisible();
  await expect(page.locator("html")).toHaveAttribute("data-e2e-max-proxy-lists-in-flight", "1");

  await page.keyboard.press("ControlOrMeta+K");
  const search = page.getByRole("searchbox", { name: "Search Proxies" });
  await search.fill("missing");
  await expect(page.getByRole("heading", { name: "No matching proxies" })).toBeVisible();
  await page.getByRole("button", { name: "Clear search" }).click();
  await expect(page.getByText("US Sanitize 1")).toBeVisible();
});

test("settings dirty state and MCP readiness render from fixture", async ({ page }) => {
  await gotoMocked(page);

  await page.getByRole("button", { name: "Settings" }).click();
  await expect(page.getByText("Startup entry not registered")).toBeVisible();
  await page.getByLabel("Start ShardX Launcher when I sign in").check();
  await expect(page.getByLabel("Start in the system tray")).toBeEnabled();
  await expect(page.getByText("MCP ready", { exact: true })).toBeVisible();
  await expect(page.getByLabel("MCP setup readiness")).toContainText("API reachable");
  await expect(page.getByRole("button", { name: "Check Hermes registration" })).toBeVisible();
  await page.getByRole("button", { name: "Check Hermes registration" }).click();
  await expect(page.getByRole("button", { name: "Refresh status" })).toBeVisible();
  const advanced = page.getByText("Advanced actions", { exact: true });
  await advanced.click();
  await expect(page.getByRole("button", { name: "Copy Codex repair command" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Refresh status" })).toHaveCount(1);
  await page.getByLabel("Port").fill("40326");
  await expect(page.getByText("Unsaved changes")).toBeVisible();
  await expect(page.getByText("Restart required")).toBeVisible();
  await expect(page.getByRole("region", { name: "Settings save status" })).toHaveCSS("position", "sticky");
  await expect(page.getByRole("button", { name: /Save settings/ })).toBeEnabled();
});

test("the first device sets up root custody once its passphrases agree", async ({ page }) => {
  await gotoMocked(page, "/?e2e=team-first-device");
  await page.getByRole("button", { name: "Settings" }).click();

  const card = page.getByTestId("custody-bootstrap");
  await expect(card).toContainText("First device of a new tenant");
  await card.getByLabel("Account username").fill("owner");
  await card.getByLabel("Account password").fill("pw");
  await card.getByLabel("Recovery passphrase", { exact: true }).fill("correct horse");
  await card.getByLabel("Recovery passphrase again").fill("correct horsf");
  await card.getByRole("button", { name: "Set up root custody" }).click();
  await expect(page.getByText("The two passphrases differ")).toBeVisible();
  await expect(page.locator("html")).not.toHaveAttribute("data-e2e-custody-bootstraps", /.+/);

  await card.getByLabel("Recovery passphrase again").fill("correct horse");
  await card.getByRole("button", { name: "Set up root custody" }).click();
  await expect(page.getByText("Root custody is set up")).toBeVisible();
  await expect(page.locator("html")).toHaveAttribute("data-e2e-custody-path", "C:\\Users\\Example\\shardx-recovery.shxrecovery");
  await expect(page.getByTestId("custody-bootstrap")).toHaveCount(0);
  await expect(page.getByText("Bootstrap anchor")).toBeVisible();
  await expect(page.locator(`input[value="${"a0".repeat(32)}"]`)).toBeVisible();
  await expect(page.getByTestId("keys-unprotected")).toHaveCount(0);
});

test("an interrupted custody setup resumes at its saved bundle without asking for a path", async ({ page }) => {
  await gotoMocked(page, "/?e2e=team-first-device-resume");
  await page.getByRole("button", { name: "Settings" }).click();
  await expect(page.getByTestId("keys-unprotected")).toContainText("not protected by the OS credential store");

  const card = page.getByTestId("custody-bootstrap");
  await expect(card).toContainText("C:\\Users\\Example\\kept.shxrecovery");
  await card.getByLabel("Account username").fill("owner");
  await card.getByLabel("Account password").fill("pw");
  await card.getByLabel("Recovery passphrase", { exact: true }).fill("correct horse");
  await card.getByLabel("Recovery passphrase again").fill("correct horse");
  await card.getByRole("button", { name: "Resume custody setup" }).click();
  await expect(page.getByText("Root custody is set up")).toBeVisible();
  await expect(page.locator("html")).toHaveAttribute("data-e2e-custody-path", "C:\\Users\\Example\\kept.shxrecovery");
  await expect(page.locator("html")).not.toHaveAttribute("data-e2e-save-dialogs", /.+/);
});

test("keys the credential store refused move into a key file once both passphrases agree", async ({ page }) => {
  await gotoMocked(page, "/?e2e=team-first-device-resume");
  await page.getByRole("button", { name: "Settings" }).click();

  const card = page.getByTestId("keys-unprotected");
  await card.getByLabel("Key file passphrase", { exact: true }).fill("correct horse");
  await card.getByLabel("Key file passphrase again").fill("correct horsf");
  await card.getByRole("button", { name: "Protect with a passphrase" }).click();
  await expect(page.getByText("The two passphrases differ")).toBeVisible();
  await expect(page.locator("html")).not.toHaveAttribute("data-e2e-key-files", /.+/);

  await card.getByLabel("Key file passphrase again").fill("correct horse");
  await card.getByRole("button", { name: "Protect with a passphrase" }).click();
  await expect(page.getByText("The keys are now in the encrypted key file.")).toBeVisible();
  await expect(page.locator("html")).toHaveAttribute("data-e2e-key-files", "1");
  await expect(page.getByTestId("keys-unprotected")).toHaveCount(0);
});

test("locked keys open with the key file passphrase and stay locked with a wrong one", async ({ page }) => {
  await gotoMocked(page, "/?e2e=team-keys-locked");
  await page.getByRole("button", { name: "Settings" }).click();

  const card = page.getByTestId("keys-locked");
  await expect(card).toContainText("locked in its key file");
  await card.getByLabel("Key file passphrase").fill("wrong horse");
  await card.getByRole("button", { name: "Unlock keys" }).click();
  await expect(page.getByText("That is not the key file passphrase.")).toBeVisible();
  await expect(page.getByTestId("keys-locked")).toBeVisible();
  await expect(card.getByLabel("Key file passphrase")).toHaveValue("");

  await card.getByLabel("Key file passphrase").fill("correct horse");
  await card.getByRole("button", { name: "Unlock keys" }).click();
  await expect(page.getByText("Keys unlocked for this session.")).toBeVisible();
  await expect(page.getByTestId("keys-locked")).toHaveCount(0);
  await expect(page.getByTestId("keys-unprotected")).toHaveCount(0);
});

test("choosing a language translates what has been moved into locales", async ({ page }) => {
  await gotoMocked(page);
  await page.getByRole("button", { name: "Settings" }).click();

  // The picker carries the language's own name, so someone who cannot read the
  // current interface language can still find their own.
  const picker = page.getByRole("combobox", { name: "Language" });
  await expect(picker).toBeVisible();
  await expect(picker).toContainText("English");

  await picker.click();
  await page.getByRole("option", { name: "Tiếng Việt" }).click();

  // The card's own title comes from locales/, so it flips immediately.
  await expect(
    page.getByRole("heading", { name: "Ngôn ngữ", level: 3 }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Language", level: 3 }),
  ).toHaveCount(0);

  // The choice has to survive a reload, or it is a toggle rather than a setting.
  await page.reload();
  // And the sidebar came with it: the button that said "Settings" on the way in
  // is "Cài đặt" on the way back, which is the whole point of the setting.
  await page.getByRole("button", { name: "Cài đặt" }).click();
  await expect(
    page.getByRole("heading", { name: "Ngôn ngữ", level: 3 }),
  ).toBeVisible();

  // The whole Settings screen moved into locales/, so its other cards follow.
  await expect(
    page.getByRole("heading", { name: "Dịch vụ tra vị trí proxy", level: 3 }),
  ).toBeVisible();

  // Emphasis is carried inside the translated string rather than by the JSX
  // around it, so the bold word has to survive the trip through locales/.
  const apiHelp = page.getByText(/API HTTP cục bộ \(axum\)/);
  await expect(apiHelp.locator("strong")).toHaveText("127.0.0.1");
  await expect(apiHelp).not.toContainText("*");

  // This row used to be the example of a screen still holding its English; it
  // has since moved into locales/ with the rest, so Vietnamese is what a
  // Vietnamese reader gets.
  await expect(page.getByLabel("Mở ShardX Launcher khi tôi đăng nhập")).toBeVisible();

  // A key with no translation must never surface as its own name to someone
  // using the app — no raw "settings.foo.bar" anywhere on the screen.
  await expect(page.getByText(/settings\.[a-z]+\./)).toHaveCount(0);
});

test("the profile row menu opens in Vietnamese", async ({ page }) => {
  // These three entries were hardcoded English long after the rest of the row
  // moved into locales/, because the scan that guards labels could not see a
  // string ending in "…". The menu is built on click, so only opening it proves
  // the keys are wired — reading the locale file proves nothing.
  await gotoMocked(page);
  await page.getByRole("button", { name: "Settings" }).click();
  const picker = page.getByRole("combobox", { name: "Language" });
  await picker.click();
  await page.getByRole("option", { name: "Tiếng Việt" }).click();

  await page.getByRole("button", { name: "Trình duyệt" }).click();
  const row = page.getByText("VN Automation 001 - No Proxy");
  await expect(row).toBeVisible();

  await page.getByRole("button", { name: /Thêm thao tác cho hồ sơ/ }).first().click();

  const menu = page.getByRole("button", { name: "Chuyển vào thư mục…", exact: true });
  await expect(menu).toBeVisible();
  await expect(page.getByRole("button", { name: "Sao lưu (đã mã hoá)…", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Khôi phục từ bản sao lưu…", exact: true })).toBeVisible();

  // And nothing beside them is still English.
  await expect(page.getByText("Move to folder…")).toHaveCount(0);
  await expect(page.getByText("Back up (encrypted)…")).toHaveCount(0);
  await expect(page.getByText("Restore from backup…")).toHaveCount(0);
});

test("startup setting registers the Launcher while MCP stays client-spawned", async ({ page }) => {
  await gotoMocked(page);
  await page.getByRole("button", { name: "Settings" }).click();

  await page.getByLabel("Start ShardX Launcher when I sign in").check();
  await page.getByRole("button", { name: /Save settings/ }).click();

  await expect(page.getByText("Startup entry registered")).toBeVisible();
  await expect(page.getByText(/MCP server remains a lightweight stdio process/)).toBeVisible();
  await expect(page.getByText("All changes saved")).toBeVisible();
});

test("Settings exposes one honest Codex repair action", async ({ page }) => {
  await gotoMocked(page, "/?e2e=codex-needs-repair");

  await page.getByRole("button", { name: "Settings" }).click();
  await page.getByText("Advanced actions", { exact: true }).click();
  await page.getByRole("button", { name: "Check Codex registration" }).click();
  await expect(page.getByRole("button", { name: "Copy Codex repair command" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Copy Codex repair command" })).toHaveCount(1);
  await expect(page.getByText("no config is changed automatically")).toBeVisible();
});

test("Advanced actions stay collapsed until opened", async ({ page }) => {
  await gotoMocked(page, "/?e2e=hermes-registered");

  await page.getByRole("button", { name: "Settings" }).click();
  await expect(page.getByRole("button", { name: "Check Hermes registration" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Check Codex registration" })).toBeHidden();

  await page.getByText("Advanced actions", { exact: true }).click();
  await expect(page.getByRole("button", { name: "Check Codex registration" })).toBeVisible();
});

test("Settings reports Hermes registration alongside Codex", async ({ page }) => {
  await gotoMocked(page, "/?e2e=hermes-not-registered");

  await page.getByRole("button", { name: "Settings" }).click();
  await page.getByRole("button", { name: "Check Hermes registration" }).click();

  await expect(page.getByText("Hermes MCP fixture is not registered.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Copy Hermes add command" })).toHaveCount(1);
});

test("pages without search do not expose a fake shortcut", async ({ page }) => {
  await gotoMocked(page);

  for (const [navName, heading] of [["Settings", "Settings"], ["Fingerprints", "Fingerprint Library"], ["ProxyShard", "ProxyShard"]]) {
    await page.getByRole("button", { name: navName }).click();
    await expect(page.getByRole("heading", { name: heading, exact: true })).toBeVisible();
    await expect(page.getByRole("searchbox")).toHaveCount(0);
  }
});

test("macOS uses Cmd+K and Escape clears then blurs search", async ({ page }) => {
  await page.addInitScript(() => {
    Object.defineProperty(navigator, "userAgent", {
      configurable: true,
      get: () => "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 Chrome/125 Safari/537.36",
    });
  });
  await gotoMocked(page);

  await expect(page.getByText("⌘K", { exact: true })).toBeVisible();
  await page.keyboard.press("Meta+K");
  const search = page.getByRole("searchbox", { name: "Search Browsers" });
  await expect(search).toBeFocused();
  await search.fill("Beta");
  await search.press("Escape");
  await expect(search).toHaveValue("");
  await search.press("Escape");
  await expect(search).not.toBeFocused();
});

test("CSSelect supports Arrow, Enter, Space, and Escape without saving", async ({ page }) => {
  await gotoMocked(page);

  await page.getByRole("button", { name: "New profile" }).click();
  const proxySelect = page.locator("label").filter({ has: page.getByText("Proxy", { exact: true }) }).getByRole("combobox").first();
  await proxySelect.focus();
  await proxySelect.press("ArrowDown");
  await expect(proxySelect).toHaveAttribute("aria-expanded", "true");
  await proxySelect.press("ArrowDown");
  await proxySelect.press("Enter");
  await expect(proxySelect).toContainText("US Sanitize 1");
  await proxySelect.press("Space");
  await expect(proxySelect).toHaveAttribute("aria-expanded", "true");
  await proxySelect.press("Escape");
  await expect(proxySelect).toHaveAttribute("aria-expanded", "false");
  await expect(page.getByText("Custom fonts", { exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Cancel" }).click();
});

test("updater requires consent, reports progress, and requests restart", async ({ page }) => {
  await gotoMocked(page, "/?updateDownloadStepDelay=500");

  await expect(page.getByText("Update available → v0.1.29")).toBeVisible();
  const trigger = page.getByRole("button", { name: /ShardX Launcher v0.1.29/ });
  await trigger.focus();
  await trigger.click();
  await expect(page.getByRole("dialog", { name: "ShardX Launcher update" })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog", { name: "ShardX Launcher update" })).toBeHidden();
  await expect(trigger).toBeFocused();

  await trigger.click();
  await page.getByRole("button", { name: "Download update" }).click();
  await expect(page.getByRole("progressbar", { name: "Download Launcher update" })).toBeVisible();
  await expect(page.getByText("Signature verified — ready to install")).toBeVisible();
  await expect(page.locator("html")).toHaveAttribute("data-e2e-update-downloads", "1");
  await page.getByRole("button", { name: "Install and restart" }).click();
  await expect(page.locator("html")).toHaveAttribute("data-e2e-update-installs", "1");
  await expect(page.locator("html")).toHaveAttribute("data-e2e-restart-requests", "1");
});

test("updater surfaces invalid signatures inline", async ({ page }) => {
  await gotoMocked(page, "/?update=invalid-signature");

  await page.getByRole("button", { name: /ShardX Launcher v0.1.29/ }).click();
  await page.getByRole("button", { name: "Download update" }).click();
  await expect(page.getByRole("alert").filter({ hasText: "Update could not be completed" })).toBeVisible();
  await expect(page.getByRole("alert")).toContainText("signature verification failed");
});

test("updater surfaces offline checks inline", async ({ page }) => {
  await gotoMocked(page, "/?update=check-error");

  await expect(page.getByText("update check needs attention")).toBeVisible();
  await page.getByRole("button", { name: /ShardX Launcher v/ }).click();
  await expect(page.getByRole("button", { name: "Retry" })).toBeVisible();
});

test("updater distinguishes checking and up-to-date states", async ({ page }) => {
  await gotoMocked(page, "/?update=none&updateHold=1");

  await expect(page.locator("html")).toHaveAttribute("data-e2e-update-check-pending", "true");
  await expect(page.getByText("checking for updates…")).toBeVisible();
  await page.evaluate(() => (window as Window & { __resolveUpdateCheck?: () => void }).__resolveUpdateCheck?.());
  await expect(page.getByText("up to date", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: /ShardX Launcher v0.1.29/ }).click();
  await expect(page.getByText("Launcher is up to date")).toBeVisible();
  await expect(page.getByRole("button", { name: "Check again" })).toBeVisible();
});

test("a running profile can raise its verification tab, and says so when it cannot", async ({ page }) => {
  await gotoMocked(page);

  // profile-beta is the fixture's running profile; the action is meaningless
  // for a stopped one, so the menu must gate it rather than fail at click time.
  await page.getByRole("button", { name: "More actions for profile Beta Research" }).click();
  const raise = page.getByRole("button", { name: "Bring verification tab to front" });
  await expect(raise).toBeEnabled();
  await raise.click();
  await expect(page.getByText("Verification tab brought to front")).toBeVisible();
});

test("a failed verification raise reports the reason instead of going quiet", async ({ page }) => {
  await gotoMocked(page, "/?e2e=verification-activate-fails");

  await page.getByRole("button", { name: "More actions for profile Beta Research" }).click();
  await page.getByRole("button", { name: "Bring verification tab to front" }).click();

  // Silence here would leave the operator staring at an unchanged window.
  await expect(page.getByText(/Could not bring verification tab to front/)).toBeVisible();
  await expect(page.getByText(/No active page to raise/)).toBeVisible();
});

test("an existing MCP folder can be adopted without downloading a second copy", async ({ page }) => {
  await gotoMocked(page);
  await page.getByRole("button", { name: "Settings" }).click();

  const currentFolder = page.locator("code", { hasText: "ShardX-MCP" });
  await expect(currentFolder).toHaveText("C:\\Users\\Example\\ShardX-MCP");
  await page.getByRole("button", { name: "Use existing MCP folder" }).click();

  // Adoption is only real if the reported path actually moves.
  await expect(page.locator("code", { hasText: "Existing-MCP" }))
    .toHaveText("C:\\Users\\Example\\Existing-MCP");
  await expect(page.getByText(/Using MCP server at/)).toBeVisible();
});

test("the search shortcut hint stays on one line", async ({ page }) => {
  await page.setViewportSize({ width: 1600, height: 900 });
  await gotoMocked(page);

  // The hint sits in a narrow slot beside the input. With an ordinary space it
  // wrapped to two lines and rendered as a squashed column, so measure every
  // hint on the page against its own line height rather than trusting the first.
  const wrapped = await page.evaluate(() =>
    [...document.querySelectorAll("span")]
      .filter((s) => /Ctrl|⌘/.test(s.textContent || ""))
      .map((s) => {
        const r = s.getBoundingClientRect();
        const lh = parseFloat(getComputedStyle(s).lineHeight) || 21;
        return { text: s.textContent, height: Math.round(r.height), lineHeight: lh };
      })
      .filter((h) => h.height > h.lineHeight * 1.4));
  expect(wrapped).toEqual([]);
});

test("tags reach the rows, the search and the filter, and survive rename, delete with undo and a reload", async ({ page }) => {
  await gotoMocked(page);
  const alpha = "VN Automation 001 - No Proxy";
  const alphaRow = page.locator(".cell-name", { has: page.getByText(alpha) });
  const betaRow = page.locator(".cell-name", { has: page.getByText("Beta Research") });

  // Beta runs in the fixture, so the bulk tag skips it and says so.
  await page.getByRole("checkbox", { name: `Select profile ${alpha}` }).check();
  await page.getByRole("checkbox", { name: "Select profile Beta Research" }).check();
  await page.getByRole("button", { name: "Tag", exact: true }).click();
  await page.getByRole("textbox", { name: "New tag" }).fill("  Client   A ");
  await page.getByRole("textbox", { name: "New tag" }).press("Enter");
  await expect(page.getByText("Skipped 1 running profiles; stop them to change their tags.")).toBeVisible();
  await expect(alphaRow.getByTestId("row-tags")).toHaveText("Client A");
  await expect(betaRow.getByTestId("row-tags")).toHaveCount(0);

  await page.getByRole("searchbox", { name: "Search Browsers" }).fill("client");
  await expect(page.getByText(alpha)).toBeVisible();
  await expect(page.getByText("Beta Research")).toHaveCount(0);
  await page.getByRole("searchbox", { name: "Search Browsers" }).fill("");

  await page.getByRole("button", { name: "Filters" }).click();
  await page.getByRole("combobox", { name: "Tag", exact: true }).click();
  await page.getByRole("option", { name: "Client A" }).click();
  await expect(page.getByText(alpha)).toBeVisible();
  await expect(page.getByText("Beta Research")).toHaveCount(0);
  await page.getByRole("button", { name: "Clear filters" }).click();
  await expect(page.getByText("Beta Research")).toBeVisible();

  await page.reload();
  // A reload can land on the patch log; the tags are what matters here.
  await page.getByRole("button", { name: "Browsers" }).click();
  await expect(alphaRow.getByTestId("row-tags")).toHaveText("Client A");

  await page.getByRole("button", { name: "Settings" }).click();
  const rows = page.getByTestId("tag-row");
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText("Profiles: 1");
  await rows.first().getByRole("button", { name: "Rename Client A" }).click();
  await page.getByRole("textbox", { name: "Rename" }).fill("Client B");
  await page.getByRole("textbox", { name: "Rename" }).press("Enter");
  await expect(rows.first()).toContainText("Client B");
  await expect(page.getByText("Client A")).toHaveCount(0);

  await rows.first().getByRole("button", { name: "Delete Client B" }).click();
  await expect(rows).toHaveCount(0);
  await page.getByRole("status").filter({ hasText: "“Client B” was deleted." }).getByRole("button", { name: "Undo" }).click();
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText("Profiles: 1");

  await page.getByRole("button", { name: "Browsers" }).click();
  await expect(alphaRow.getByTestId("row-tags")).toHaveText("Client B");

  // A name typed but not yet entered is saved with the rest.
  await page.getByRole("button", { name: `More actions for profile ${alpha}` }).click();
  await page.getByRole("button", { name: "Edit tags" }).click();
  await page.getByRole("textbox", { name: "Add a tag" }).fill("Typed");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(alphaRow.getByTestId("row-tags")).toHaveText("Client BTyped");
});

// tauri.conf.json sets minWidth 1280. Each case once pushed buttons off screen
// or squeezed the folder tabs under them.
for (const [width, pick] of [[1280, "one"], [1280, "all"], [1296, "one"], [1440, "all"]] as const) {
  test(`the selection bar keeps the header usable at ${width}px with ${pick} selected`, async ({ page }) => {
    await page.setViewportSize({ width, height: 800 });
    await gotoMocked(page);
    if (pick === "all") await page.getByRole("checkbox", { name: "Select all profiles on this page" }).check();
    else await page.getByRole("checkbox", { name: "Select profile Beta Research" }).check();
    await expect(page.getByText(pick === "all" ? "2 selected" : "1 selected")).toBeVisible();

    const hidden = await page.evaluate(() => {
      const header = document.querySelector("[data-testid=browsers-header]")!;
      const bounds = header.getBoundingClientRect();
      return [...header.querySelectorAll("button")]
        .filter((b) => {
          const r = b.getBoundingClientRect();
          const hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
          return r.right > bounds.right + 0.5 || r.left < bounds.left - 0.5 || !(hit && b.contains(hit));
        })
        .map((b) => b.textContent?.trim() || b.getAttribute("aria-label"));
    });
    expect(hidden).toEqual([]);
    await expect(page.getByRole("button", { name: "New profile" })).toBeInViewport({ ratio: 1 });
  });
}

// A second quick click landed on the wrong row because the table moved down
// when the selection bar appeared, and again when "Launch synced" joined it.
test("selecting profiles does not move the table at 1280px", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await gotoMocked(page);
  const selectAll = page.getByRole("checkbox", { name: "Select all profiles on this page" });
  const top = async () => (await selectAll.boundingBox())!.y;
  const before = await top();

  await page.getByRole("checkbox", { name: "Select profile Beta Research" }).check();
  await expect(page.getByText("1 selected")).toBeVisible();
  expect(await top()).toBe(before);

  await selectAll.check();
  await expect(page.getByText("2 selected")).toBeVisible();
  await expect(page.getByRole("button", { name: /Launch synced/ })).toBeVisible();
  expect(await top()).toBe(before);
});

// Every row is its own CSS grid, so an `auto` actions track sized by its own
// buttons lets the header (whose actions cell is empty) lay out differently.
async function columnLefts(page: Page, grid: string) {
  return page.evaluate((selector) =>
    [...document.querySelectorAll(selector)].map((row) =>
      [...row.children]
        .filter((cell) => getComputedStyle(cell).display !== "none")
        .map((cell) => Math.round(cell.getBoundingClientRect().left)),
    ), grid);
}

for (const width of [2560, 2200, 1720, 1500, 1296, 1024, 900]) {
  test(`table headers stay over their columns at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 860 });
    await gotoMocked(page);
    await expect(page.getByText("Beta Research")).toBeVisible();
    const [head, ...rows] = await columnLefts(page, ".t-cols");
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) expect(row).toEqual(head);

    await page.getByRole("button", { name: "Proxies" }).click();
    await expect(page.getByText("US Sanitize 1")).toBeVisible();
    const [proxyHead, ...proxyRows] = await columnLefts(page, ".p-cols");
    expect(proxyRows.length).toBeGreaterThan(0);
    for (const row of proxyRows) expect(row).toEqual(proxyHead);
  });
}

test("a start in progress keeps the columns aligned on a 2560px screen", async ({ page }) => {
  // The root font is 16px here, so "Cancel" is the widest label the Start button shows.
  await page.setViewportSize({ width: 2560, height: 1200 });
  await gotoMocked(page, "/?e2e=slow-launch");
  const start = page.getByRole("button", { name: "Start profile VN Automation 001 - No Proxy" });
  await start.click();
  await expect(start).toHaveText("Cancel");
  const [head, ...rows] = await columnLefts(page, ".t-cols");
  for (const row of rows) expect(row).toEqual(head);
  await start.click();
  await expect(start).toHaveText("Start");
});

test("the page header keeps its place on pages without a search box", async ({ page }) => {
  await gotoMocked(page);
  const heading = page.getByRole("heading", { level: 1 });
  await expect(heading).toHaveText("Browsers");
  await expect(page.getByRole("button", { name: "Browsers" })).toHaveAttribute("aria-current", "page");

  const tops: number[] = [];
  // Extensions and Automation have a search box; Trash, Fingerprints and Settings do not.
  for (const [name, title] of [["Extensions", "Extensions"], ["Trash", "Trash"], ["Fingerprints", "Fingerprint Library"], ["Automation", "Automation"], ["Settings", "Settings"]]) {
    await page.getByRole("button", { name, exact: true }).click();
    await expect(heading).toHaveText(title);
    await expect(page.getByRole("button", { name, exact: true })).toHaveAttribute("aria-current", "page");
    await expect(page.getByRole("button", { name: "Browsers" })).not.toHaveAttribute("aria-current", "page");
    tops.push(Math.round((await heading.boundingBox())!.y));
  }
  expect(new Set(tops).size).toBe(1);
});

test("empty states read in the chosen language", async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem("shardx.lang", "vi"));
  await gotoMocked(page, "/?e2e=proxies-empty");
  // The folder tab that lists every profile used to say "All" in every language.
  await expect(page.getByRole("button", { name: /^Tất cả/ })).toBeVisible();
  await page.getByRole("button", { name: "Proxy", exact: true }).click();
  await expect(page.getByText("Thêm một máy chủ SOCKS5/HTTP(S) để hồ sơ đi qua nó.")).toBeVisible();
  await page.getByRole("button", { name: "Vân tay" }).click();
  await expect(page.getByRole("heading", { name: "Chưa có vân tay nào" })).toBeVisible();
});

test("the fingerprint library states a GPU mismatch once and keeps the cards quiet", async ({ page }) => {
  await gotoMocked(page, "/?e2e=fingerprints");
  await page.getByRole("button", { name: "Fingerprints", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: "2 of 3 fingerprints claim GPU features" })).toBeVisible();
  // One icon per mismatched card, named for screen readers, with no word repeated on every card.
  await expect(page.getByRole("button", { name: "GPU mismatch" })).toHaveCount(2);
  await expect(page.getByText("GPU mismatch", { exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "GPU mismatch" }).first().click();
  await expect(page.getByRole("dialog")).toContainText("This fingerprint does not fit this machine");
  await page.getByRole("dialog").getByRole("button", { name: "Close", exact: true }).last().click();
  // Remove is a named icon on user cards only, and is not drawn as a red error button.
  const remove = page.getByRole("button", { name: "Remove Win RTX 3060" });
  await expect(remove).toBeVisible();
  await expect(remove).not.toHaveText("✕");
  await expect(page.getByRole("button", { name: /^Remove / })).toHaveCount(2);
});
