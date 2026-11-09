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

test("Team section shows the team card and Settings no longer does", async ({ page }) => {
  await gotoMocked(page);
  const intro = page.getByText("Enroll this device with a team server to sync encrypted profiles.");

  await page.getByRole("button", { name: "Team", exact: true }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Team");
  await expect(page.getByRole("button", { name: "Team", exact: true })).toHaveAttribute("aria-current", "page");
  await expect(intro).toBeVisible();
  await expect(page.getByLabel("Server URL")).toBeVisible();

  await page.getByRole("button", { name: "Settings" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Settings");
  await expect(intro).toHaveCount(0);
  await expect(page.getByLabel("Server URL")).toHaveCount(0);
});

test("Team page shows one badge per binding state", async ({ page }) => {
  await gotoMocked(page, "/?e2e=team-profiles");
  await page.getByRole("button", { name: "Team", exact: true }).click();

  const row = (text: string) => page.getByTestId("team-profile").filter({ hasText: text });
  for (const [text, badge] of [
    ["Beta Research", "Local only"],
    ["VN Automation 001", "Available"],
    ["team-checked-out", "Checked out here"],
    ["team-lease-at-risk", "Lease at risk"],
    ["team-expired-lease", "Lease at risk"],
    ["team-uploading", "Uploading"],
    ["team-quarantined", "Quarantined"],
  ]) {
    await expect(row(text)).toContainText(badge);
  }
  await expect(row("team-quarantined")).toContainText("the server offered an older state");
  await expect(row("team-reported-only")).toContainText("Quarantined");
  await expect(row("team-reported-only")).toContainText("signer revoked");
  await expect(row("team-expired-lease")).not.toContainText("Checked out here");
  await expect(row("VN Automation 001")).not.toContainText("Quarantined");
});

test("Team page warns about a custodian renewed after revocation", async ({ page }) => {
  await gotoMocked(page, "/?e2e=team-profiles");
  await page.getByRole("button", { name: "Team", exact: true }).click();

  const alert = page.getByTestId("team-alert");
  await expect(alert).toHaveCount(1);
  await expect(alert).toHaveAttribute("role", "alert");
  await expect(alert).toContainText("renewed after it was revoked");
  await expect(alert).toContainText("key a1b2c3d4)");
  await expect(alert).not.toContainText("a1b2c3d4e");
  await expect(alert).not.toContainText("3210f");
  await expect(alert.getByRole("button")).toHaveCount(0);
});

test("Team page shows no alert banner when there are no alerts", async ({ page }) => {
  await gotoMocked(page, "/?e2e=team-profiles-quiet");
  await page.getByRole("button", { name: "Team", exact: true }).click();
  // A bound row's badge only appears once the statuses are loaded.
  await expect(page.getByTestId("team-profile").filter({ hasText: "team-uploading" })).toContainText("Uploading");
  await expect(page.getByTestId("team-alert")).toHaveCount(0);
});

async function teamPage(page: Page, query = "") {
  await gotoMocked(page, `/?e2e=team-profiles${query}`);
  await page.getByRole("button", { name: "Team", exact: true }).click();
  return (text: string) => page.getByTestId("team-profile").filter({ hasText: text });
}

// Each call that reaches the server clears the password first, as TeamCard does.
async function teamSignIn(page: Page) {
  const account = page.getByTestId("team-account");
  await account.getByLabel("Account username").fill("owner");
  await account.getByLabel("Account password").fill("pw");
}

test("no team action is offered before the statuses load", async ({ page }) => {
  const row = await teamPage(page, "&teamStatusDelay=1500");
  await expect(row("Beta Research")).toBeVisible();
  await expect(page.getByTestId("team-profile").getByRole("button")).toHaveCount(0);
  await expect(row("Beta Research").getByRole("button", { name: "Publish" })).toBeVisible();
  await expect(row("team-checked-out").getByRole("button", { name: "Check in" })).toBeVisible();
});

test("revert is offered only for a proven run and asks for confirmation", async ({ page }) => {
  const row = await teamPage(page);
  for (const text of [
    "VN Automation 001", "Beta Research", "team-checked-out", "team-lease-at-risk",
    "team-expired-lease", "team-uploading", "team-quarantined", "team-reported-only",
  ]) {
    await expect(row(text)).toBeVisible();
    await expect(row(text).getByRole("button", { name: /revert/i })).toHaveCount(0);
  }
  const proven = row("team-proven-run");
  await expect(proven.getByRole("button", { name: "Check in" })).toHaveCount(0);
  await teamSignIn(page);

  await proven.getByRole("button", { name: "Revert", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toContainText(
    "Local unsynced changes will be replaced by the last valid snapshot, after the server accepts the revert.",
  );
  await dialog.getByRole("button", { name: "Cancel" }).click();
  await expect(dialog).toHaveCount(0);
  await expect(page.locator("html")).not.toHaveAttribute("data-e2e-reverts", /.+/);
  await expect(proven).toContainText("Quarantined");

  await proven.getByRole("button", { name: "Revert", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Revert" }).click();
  await expect(page.locator("html")).toHaveAttribute("data-e2e-reverts", "1");
  await expect(proven).toContainText("Available");
  await expect(proven.getByRole("button", { name: /revert/i })).toHaveCount(0);
  await expect(page.getByText("Profile reverted to its last valid snapshot.")).toBeVisible();
});

test("a reported-only quarantine offers no revert", async ({ page }) => {
  const row = await teamPage(page);
  const reported = row("team-reported-only");
  await expect(reported).toContainText("signer revoked");
  await expect(reported.getByRole("button", { name: /revert/i })).toHaveCount(0);
  await expect(reported.getByRole("button", { name: "Check in" })).toHaveCount(0);
  // A signer-revoked quarantine still pulls: pull accepts a later valid head.
  await expect(reported.getByRole("button")).toHaveText(["Pull", "Unbind"]);
  await expect(row("team-quarantined").getByRole("button")).toHaveText(["Unbind"]);
});

test("a revert in progress hides check-in and offers resume", async ({ page }) => {
  const row = await teamPage(page);
  const reverting = row("team-reverting");
  await expect(reverting.getByRole("button", { name: "Resume revert" })).toBeVisible();
  await expect(reverting.getByRole("button", { name: "Check in" })).toHaveCount(0);
  await expect(row("team-checked-out").getByRole("button", { name: "Check in" })).toBeVisible();

  await teamSignIn(page);
  await reverting.getByRole("button", { name: "Resume revert" }).click();
  await expect(page.getByRole("dialog")).toContainText("replaced by the last valid snapshot");
  await page.getByRole("dialog").getByRole("button", { name: "Revert" }).click();
  await expect(reverting).toContainText("Available");
  await expect(reverting.getByRole("button", { name: /revert/i })).toHaveCount(0);
  await expect(reverting.getByRole("button", { name: "Check in" })).toBeVisible();
});

test("publish then unbind refresh badges", async ({ page }) => {
  const row = await teamPage(page);
  const beta = row("Beta Research");
  await expect(beta).toContainText("Local only");
  await expect(beta.getByRole("button")).toHaveText(["Publish"]);
  await expect(beta.getByRole("button", { name: "Publish" })).toBeDisabled();

  await teamSignIn(page);
  await beta.getByRole("button", { name: "Publish" }).click();
  await expect(beta).toContainText("Checked out here");
  await expect(page.getByText("Profile published to the team.")).toBeVisible();
  await expect(beta.getByRole("button")).toHaveText(["Check in", "Pull", "Unbind"]);
  await expect(page.getByTestId("team-account").getByLabel("Account password")).toHaveValue("");

  await teamSignIn(page);
  await beta.getByRole("button", { name: "Check in" }).click();
  await expect(beta).toContainText("Available");
  await expect(page.getByText("Profile checked in.")).toBeVisible();
  await teamSignIn(page);
  await beta.getByRole("button", { name: "Pull" }).click();
  await expect(page.getByText("Profile pulled from the team.")).toBeVisible();

  await beta.getByRole("button", { name: "Unbind" }).click();
  await expect(page.getByRole("dialog")).toContainText("stays on this device as a local profile");
  await page.getByRole("dialog").getByRole("button", { name: "Unbind" }).click();
  await expect(beta).toContainText("Local only");
  await expect(beta.getByRole("button")).toHaveText(["Publish"]);
  await expect(page.locator("html")).toHaveAttribute("data-e2e-unbinds", "1");
});

test("join creates a local profile and shows it available", async ({ page }) => {
  const row = await teamPage(page);
  const rows = page.getByTestId("team-profile");
  await expect(row("team-reverting")).toBeVisible();
  const before = await rows.count();

  await teamSignIn(page);
  await page.getByTestId("team-fleet").getByRole("button", { name: "Show fleet profiles" }).click();
  const fleet = page.getByTestId("team-fleet-profile");
  await expect(fleet).toHaveCount(3);
  await expect(fleet.filter({ hasText: "Alpha" })).toContainText("Joined");
  await expect(fleet.filter({ hasText: "Team profile c3c3c3c3" })).toBeVisible();

  await teamSignIn(page);
  await fleet.filter({ hasText: "Shop" }).getByRole("button", { name: "Join" }).click();
  await expect(rows).toHaveCount(before + 1);
  await expect(row("Shop")).toContainText("Available");
  await expect(fleet.filter({ hasText: "Shop" })).toContainText("Joined");
  await expect(page.getByText("Joined Shop.")).toBeVisible();
});

test("a failed join removes the local profile it created", async ({ page }) => {
  const row = await teamPage(page, "&teamRefuse=team_join_profile");
  const rows = page.getByTestId("team-profile");
  await expect(row("team-reverting")).toBeVisible();
  const before = await rows.count();

  await teamSignIn(page);
  await page.getByTestId("team-fleet").getByRole("button", { name: "Show fleet profiles" }).click();
  await teamSignIn(page);
  await page.getByTestId("team-fleet-profile").filter({ hasText: "Shop" }).getByRole("button", { name: "Join" }).click();
  await expect(page.getByText("This device's fleet key was collected by an earlier version")).toBeVisible();
  await expect(page.locator("html")).toHaveAttribute("data-e2e-profile-saves", "1");
  await expect(page.locator("html")).toHaveAttribute("data-e2e-profile-deletes", "1");
  await expect(rows).toHaveCount(before);
  await expect(row("Shop")).toHaveCount(0);
  await expect(page.getByText("[[shardx:")).toHaveCount(0);
});

test("a join whose first pull fails keeps the bound profile", async ({ page }) => {
  const row = await teamPage(page, "&teamJoinFailAfterBind=1");
  const rows = page.getByTestId("team-profile");
  await expect(row("team-reverting")).toBeVisible();
  const before = await rows.count();

  await teamSignIn(page);
  await page.getByTestId("team-fleet").getByRole("button", { name: "Show fleet profiles" }).click();
  await teamSignIn(page);
  await page.getByTestId("team-fleet-profile").filter({ hasText: "Shop" }).getByRole("button", { name: "Join" }).click();
  await expect(page.getByText("The team server has a newer version of this profile.")).toBeVisible();
  await expect(rows).toHaveCount(before + 1);
  await expect(row("Shop")).toContainText("Available");
  await expect(page.locator("html")).toHaveAttribute("data-e2e-profile-saves", "1");
  await expect(page.locator("html")).not.toHaveAttribute("data-e2e-profile-deletes", /.+/);
});

test("joining under a label a local profile already uses falls back to a unique name", async ({ page }) => {
  const row = await teamPage(page);
  const rows = page.getByTestId("team-profile");
  await expect(row("team-reverting")).toBeVisible();
  const before = await rows.count();
  const shop = page.getByTestId("team-fleet-profile").filter({ hasText: "Shop" });

  await teamSignIn(page);
  await page.getByTestId("team-fleet").getByRole("button", { name: "Show fleet profiles" }).click();
  await teamSignIn(page);
  await shop.getByRole("button", { name: "Join" }).click();
  await expect(row("Shop")).toContainText("Available");
  // Unbinding keeps the local "Shop", so joining again meets its name.
  await row("Shop").getByRole("button", { name: "Unbind" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Unbind" }).click();
  await expect(row("Shop")).toContainText("Local only");

  await teamSignIn(page);
  await shop.getByRole("button", { name: "Join" }).click();
  await expect(row("Team profile c2c2c2c2c2c2c2c2")).toContainText("Available");
  await expect(rows).toHaveCount(before + 2);
  await expect(row("Shop")).toHaveCount(1);
  await expect(page.locator("html")).toHaveAttribute("data-e2e-profile-saves", "3");
});

test("a refused action shows the localized error and keeps the row", async ({ page }) => {
  const row = await teamPage(page, "&teamRefuse=profile_sync_publish,profile_sync_push");
  const checkedOut = row("team-checked-out");
  await teamSignIn(page);
  await checkedOut.getByRole("button", { name: "Check in" }).click();
  await expect(page.getByText("The team server has a newer version of this profile. Pull it before pushing.")).toBeVisible();
  await expect(checkedOut).toContainText("Checked out here");
  await expect(checkedOut.getByRole("button", { name: "Check in" })).toBeVisible();

  // A refused publish may leave its stored request behind: Cancel ends it.
  const beta = row("Beta Research");
  await teamSignIn(page);
  await beta.getByRole("button", { name: "Publish" }).click();
  await expect(page.getByText("Pushing is blocked: a device that may hold this fleet's key was revoked")).toBeVisible();
  await expect(beta).toContainText("Local only");
  await expect(page.getByText("[[shardx:")).toHaveCount(0);
  await beta.getByRole("button", { name: "Cancel publish" }).click();
  await expect(page.getByText("The unfinished publish was cancelled.")).toBeVisible();
  await expect(page.locator("html")).toHaveAttribute("data-e2e-cancel-publishes", "1");
  await expect(beta.getByRole("button")).toHaveText(["Publish"]);
});

type TeamHead = {
  version: number; label: string | null; holder: string | null; revoked: boolean;
  /** The old root custodian pushed it after the hand-over's re-seal. */
  oldRootPush?: boolean;
};
type TeamDeviceRow = {
  device_id: string; label: string; status: "pending" | "active" | "revoked"; granted: boolean;
  /** The fleet generation its grant is for. */
  generation?: number;
  /** The server refuses it a grant for a rotated key. */
  refuses?: boolean;
  /** The server fails its grant for a rotated key with an error a resend may cure. */
  fails?: boolean;
  /** It holds root custody; A always does. */
  custodian?: boolean;
};

/**
 * The one team server both devices of the journey talk to, through the
 * `e2eTeamServer` binding the `team-device-*` mocks call. Each op answers with
 * the head a device would accept; a head signed by a key later proven revoked
 * quarantines whoever pulls it until a revert seals a valid one over it.
 *
 * It also lists the tenant's devices: A, the active root custodian, plus any
 * in `more`. Enrolling files a pending row; approving one grants it the fleet
 * key once A created it, and revoking one refuses its sessions from then on.
 * A rotation grants the next generation to every active device but A's
 * refused ones; a push sealed under an older generation is refused.
 *
 * The v2.10 hand-over: A appoints a pending device only while every head is
 * under the newest generation, and only the device `appointed` names accepts.
 */
function fakeTeamServer(more: TeamDeviceRow[] = [], appointed: string | null = null) {
  const heads = new Map<string, TeamHead>();
  const devices: TeamDeviceRow[] = [
    { device_id: "aa".repeat(16), label: "Machine A", status: "active", granted: false, custodian: true }, ...more,
  ];
  let fleetKey = false;
  let generation = 0;
  // A rotation left activated by a member whose grant failed resumes at its generation.
  let failing: string | null = null;
  // The generation each head was sealed under.
  const sealed = new Map<string, number>();
  let enrolled = 0;
  const row = (id: unknown) => devices.find((d) => d.device_id === id);
  // A device session: a revoked device is refused, as v2_auth refuses it.
  const live = (id: unknown) => {
    const d = row(id);
    if (!d) throw new Error("[[shardx:fleet.refusedSession|status=401|detail=unknown device]]");
    if (d.status === "revoked") {
      throw new Error("[[shardx:fleet.refusedSession|status=403|detail=the device is revoked and holds no live approval]]");
    }
    return d;
  };
  const head = (id: string) => {
    const h = heads.get(id);
    if (!h) throw new Error(`no team profile ${id}`);
    return h;
  };
  const reply = (id: string) => {
    const h = head(id);
    return {
      remote_profile_id: id, version: h.version, label: h.label,
      quarantine: h.revoked ? "SIGNER_REVOKED" : null, revert_available: h.revoked, key_generation: sealed.get(id) ?? 0,
    };
  };
  type Args = {
    label?: string | null; remote_profile_id?: string; pin?: number | null; device_id?: string; target?: string;
    generation?: number; skip?: string | null; custodian?: boolean;
  };
  const ops: Record<string, (device: string, args: Args) => unknown> = {
    enroll: (_device, { label }) => {
      const device_id = `b${++enrolled}`.repeat(16);
      devices.push({ device_id, label: String(label), status: "pending", granted: false });
      return { device_id };
    },
    live: (_device, { device_id }) => { live(device_id); return null; },
    status: (_device, { device_id }) => row(device_id)?.status ?? null,
    devices: (_device, { device_id }) => {
      live(device_id);
      return devices.map(({ device_id: id, label, status, custodian }) => ({
        device_id: id, label, status, custodian: !!custodian,
      }));
    },
    fleetKey: (_device, { device_id }) => {
      Object.assign(live(device_id), { granted: true, generation });
      fleetKey = true;
      return null;
    },
    approve: (_device, { device_id, target, custodian }) => {
      live(device_id);
      const d = row(target);
      if (d?.status !== "pending") throw new Error("[[shardx:fleet.deviceNotPending]]");
      if (custodian && [...heads.entries()].some(([id, h]) => h.version > 0 && (sealed.get(id) ?? 0) < generation)) {
        throw new Error("[[shardx:fleet.handoverNeedsReseal]]");
      }
      Object.assign(d, { status: "active", granted: fleetKey, generation, custodian: !!custodian || d.custodian });
      if (custodian) appointed = String(target);
      return null;
    },
    // The root grant A filed for the device it appointed, from A's key.
    accept: (_device, { device_id }) => {
      live(device_id);
      if (appointed !== device_id) throw new Error("[[shardx:fleet.handoverNoGrant]]");
      return { outgoing: "aa".repeat(32), generation };
    },
    generation: () => generation,
    // The heads that block revoking the old root: one under an older generation, or one it pushed after the re-seal.
    blockers: () => [...heads.entries()]
      .filter(([id, h]) => h.version > 0 && ((sealed.get(id) ?? 0) < generation || h.oldRootPush))
      .map(([id, h]) => ({ profile: id, after_reseal: (sealed.get(id) ?? 0) >= generation && !!h.oldRootPush })),
    // The new custodian's revert of a head the old root pushed after the re-seal.
    undo: (_device, { remote_profile_id }) => {
      const h = head(String(remote_profile_id));
      Object.assign(h, { version: h.version + 1, oldRootPush: false });
      return h.version;
    },
    revoke: (_device, { device_id, target }) => {
      live(device_id);
      const held = !!row(target)?.granted;
      Object.assign(row(target) ?? {}, { status: "revoked", granted: false });
      return { held };
    },
    rotate: (_device, { device_id, skip }) => {
      live(device_id);
      if (!failing) generation += 1;
      failing = null;
      let [filed, refused, skipped] = [0, 0, 0];
      for (const d of devices) {
        // The new root custodian's rotation skips the outgoing one, A.
        const outgoing = device_id === appointed && d.device_id === "aa".repeat(16);
        if (d.status === "revoked" || (d.status === "active" && (d.device_id === skip || outgoing))) {
          skipped += 1;
          continue;
        }
        if (d.status !== "active") continue;
        if (d.device_id !== device_id && d.refuses) refused += 1;
        else if (d.device_id !== device_id && d.fails) failing = d.device_id;
        else {
          Object.assign(d, { granted: true, generation });
          if (d.device_id !== device_id) filed += 1;
        }
      }
      return { generation, filed, refused, skipped, failing };
    },
    collect: (_device, { device_id }) => {
      const d = live(device_id);
      return { granted: d.granted, generation: d.generation ?? 0 };
    },
    list: () => [...heads.keys()].map(reply),
    publish: (device, { label, generation: g }) => {
      const id = `d${heads.size + 1}`.repeat(16);
      heads.set(id, { version: 0, label: label ?? null, holder: device, revoked: false });
      sealed.set(id, g ?? 0);
      return reply(id);
    },
    pull: (_device, { remote_profile_id }) => reply(String(remote_profile_id)),
    // Check-in is the checkout inside push: it takes the lease when free and releases it.
    push: (device, args) => {
      const { remote_profile_id, pin } = args;
      const h = head(String(remote_profile_id));
      if (h.holder && h.holder !== device) throw new Error(`lease held by device ${h.holder}`);
      if (h.revoked || pin !== h.version) throw new Error("[[shardx:sync.remoteAhead]]");
      if ((args.generation ?? 0) < generation) throw new Error("[[shardx:sync.fleetKeyRotated]]");
      Object.assign(h, { version: h.version + 1, holder: null });
      sealed.set(String(remote_profile_id), args.generation ?? 0);
      return reply(String(remote_profile_id));
    },
    // Re-seal all profiles: a free head under an older generation gets a new version under the newest one.
    reseal: (device, { device_id }) => {
      live(device_id);
      const profiles: Record<string, string> = {};
      for (const [id, h] of heads) {
        if (h.version === 0 || (sealed.get(id) ?? 0) >= generation) profiles[id] = "current";
        else if (h.holder && h.holder !== device) profiles[id] = "skipped:in-use";
        else if (h.revoked) profiles[id] = "skipped:quarantined";
        else if (h.label === "Untrusted") profiles[id] = "skipped:error:sync.signerUntrusted";
        else {
          h.version += 1;
          sealed.set(id, generation);
          profiles[id] = `resealed:${h.version}`;
        }
      }
      return { generation, profiles };
    },
    // Not modelled: the caller's pin, the lease, and proven vs reported-only revocation.
    revert: (_device, { remote_profile_id }) => {
      const h = head(String(remote_profile_id));
      if (!h.revoked) throw new Error("nothing to revert");
      Object.assign(h, { version: h.version + 1, revoked: false });
      return reply(String(remote_profile_id));
    },
  };
  return {
    heads,
    devices,
    /** A appoints `id`, as its Approve as root custodian files. */
    appoint: (id: string) => { appointed = id; },
    call: (op: string, device: string, args: Args) => ops[op](device, args),
    /** A device whose key is later proven revoked checks in a new head. */
    revokedCheckIn: (id: string) => Object.assign(head(id), { version: head(id).version + 1, revoked: true }),
  };
}

/** What a device's own team database reports for each binding, as `state@pin`. */
const teamPins = (page: Page) => page.evaluate(async () => {
  const ipc = (window as unknown as {
    __TAURI_INTERNALS__: { invoke: (cmd: string) => Promise<{ profiles: { sync_state: string; remote_version: number }[] }> };
  }).__TAURI_INTERNALS__;
  return (await ipc.invoke("team_profiles_status")).profiles.map((p) => `${p.sync_state}@${p.remote_version}`);
});

/**
 * Open team device `device`'s Team page against `server`, its clock faked when
 * `clock` is set. The longer names are B, or A, with seeds that do not read.
 * `query` adds mock parameters to the page URL.
 */
async function teamDevicePage(
  page: Page,
  device: "a" | "b" | "keys-lost" | "key-store-unavailable" | "root-keys-lost" | "root-key-store-unavailable",
  server: ReturnType<typeof fakeTeamServer>,
  clock = false,
  query = "",
) {
  if (clock) await page.clock.install();
  await page.exposeFunction("e2eTeamServer", server.call);
  await gotoMocked(page, (device.length === 1 ? `/?e2e=team-device-${device}` : `/?e2e=team-${device}`) + query);
  await page.getByRole("button", { name: "Team", exact: true }).click();
  return page.getByTestId("team-card");
}

// TeamCard's own account login; each call that reaches the server clears the password.
async function cardSignIn(page: Page) {
  const card = page.getByTestId("team-card");
  await card.getByLabel("Account username").fill("owner");
  await card.getByLabel("Account password").fill("pw");
}

async function cardClick(page: Page, name: string) {
  await cardSignIn(page);
  await page.getByTestId("team-card").getByRole("button", { name, exact: true }).click();
}

async function teamEnroll(page: Page, label: string) {
  const card = page.getByTestId("team-card");
  await card.getByLabel("Device label").fill(label);
  await cardClick(page, "Enroll this device");
  await expect(card.getByTestId("team-join")).toBeVisible();
}

/** The custodian's device rows labelled `label`, freshly listed. */
async function listDevices(a: Page, label: string) {
  await cardClick(a, "Show devices");
  return a.getByTestId("team-device").filter({ hasText: label });
}

/**
 * B enrolls as "Machine B" and is refused the fleet until it collects; A
 * creates the fleet key, the codes on both pages match, A approves B, and B
 * pins the anchor and collects generation 0.
 */
async function admitB(a: Page, b: Page) {
  await test.step("B enrolls, and its fleet list is refused before it collects", async () => {
    await teamEnroll(b, "Machine B");
    await teamSignIn(b);
    await b.getByTestId("team-fleet").getByRole("button", { name: "Show fleet profiles" }).click();
    await expect(b.getByText("No fleet key this device verified opens this team profile.")).toBeVisible();
    await expect(b.getByTestId("team-fleet-profile")).toHaveCount(0);
  });

  await test.step("A creates the fleet key", async () => {
    await cardClick(a, "Create fleet key");
    await expect(a.getByTestId("team-devices").getByText("Fleet key ready", { exact: true })).toBeVisible();
    await expect(a.getByTestId("team-export")).toContainText("A recovery bundle exported before 2.8.0 cannot restore the team");
  });

  const row = await test.step("B's join code is the code A's Devices shows, full key IDs too", async () => {
    await cardClick(b, "Show join code");
    const sas = b.getByTestId("team-join-sas");
    await expect(sas).toHaveText(/^([0-9a-f]{4} ){7}[0-9a-f]{4}$/);
    const rowB = await listDevices(a, "Machine B");
    await expect(rowB).toContainText("Pending");
    await expect(rowB.getByTestId("team-device-sas")).toHaveText(await sas.innerText());
    await b.getByTestId("team-join").getByRole("button", { name: "Show full key IDs" }).click();
    await rowB.getByRole("button", { name: "Show full key IDs" }).click();
    const ids = await b.getByTestId("team-join-key-ids").locator("dd").allInnerTexts();
    expect(ids).toHaveLength(3);
    for (const id of ids) expect(id).toMatch(/^[0-9a-f]{64}$/);
    await expect(rowB.getByTestId("team-device-key-ids").locator("dd")).toHaveText(ids);
    // B's own Team page shows the same two key IDs the custodian compares.
    const own = b.getByTestId("team-own-key-ids").locator("input");
    await expect(own.nth(0)).toHaveValue(ids[0]);
    await expect(own.nth(1)).toHaveValue(ids[1]);
    return rowB;
  });

  await test.step("Approve stays disabled until the codes are confirmed to match", async () => {
    const approve = row.getByRole("button", { name: "Approve", exact: true });
    await cardSignIn(a);
    await expect(approve).toBeDisabled();
    await row.getByLabel("The code on the other device matches").check();
    await expect(approve).toBeEnabled();
    await approve.click();
    await expect(row).toContainText("Active");
  });

  await test.step("B clicks Codes match, then collects the fleet key", async () => {
    await cardClick(b, "Codes match");
    await expect(b.getByTestId("team-join")).toContainText("Codes confirmed.");
    await cardClick(b, "Collect key custody");
    await expect(b.getByText("Fleet key collected (generation 0).")).toBeVisible();
    // Joined: status reports the kept key, so no join code or Enroll again is offered.
    await expect(b.getByTestId("team-join")).toHaveCount(0);
    await expect(b.getByTestId("team-joined")).toContainText("holds a verified fleet key");
  });
}

/** Revokes the custodian's device row labelled `label` as `reason`, through its confirm dialog. */
async function revokeAs(a: Page, label: string, reason: "Retired" | "Lost") {
  const row = await listDevices(a, label);
  await cardSignIn(a);
  if (reason === "Lost") {
    await row.getByRole("combobox", { name: "Reason" }).click();
    await a.getByRole("option", { name: "Lost" }).click();
  }
  await row.getByRole("button", { name: "Revoke" }).click();
  const dialog = a.getByRole("dialog");
  await expect(dialog).not.toContainText("until key rotation ships");
  await expect(dialog).toContainText("until you rotate the fleet key: rotate it after revoking.");
  await dialog.getByRole("button", { name: "Revoke" }).click();
  await expect(row).toContainText("Revoked");
}

/** Rotates the fleet key on A through the confirm dialog, which warns that rotation does not reach back. */
async function rotateOn(a: Page, button = "Rotate fleet key") {
  await cardClick(a, button);
  const dialog = a.getByRole("dialog");
  await expect(dialog).toContainText("must be activated within 30 days");
  await expect(dialog).toContainText("keys and data a revoked device already copied cannot be revoked retroactively");
  await dialog.getByRole("button", { name: button }).click();
}

test("a revoke raises the rotation banner by reason, and a rotation clears it and asks for a new recovery bundle", async ({ page: a }) => {
  const server = fakeTeamServer([
    { device_id: "c1".repeat(16), label: "Machine C", status: "active", granted: true, generation: 0 },
    { device_id: "c2".repeat(16), label: "Machine D", status: "active", granted: true, generation: 0 },
    { device_id: "c3".repeat(16), label: "Machine E", status: "active", granted: false },
    { device_id: "c4".repeat(16), label: "Machine F", status: "active", granted: true, generation: 0, refuses: true },
  ]);
  const card = await teamDevicePage(a, "a", server);
  await cardClick(a, "Create fleet key");
  const banner = card.getByTestId("team-rotation-banner");

  await test.step("a revoked device that held no fleet key raises no banner", async () => {
    await revokeAs(a, "Machine E", "Retired");
    await expect(banner).toHaveCount(0);
  });

  await test.step("routine after a retired holder, urgent after a lost one", async () => {
    await revokeAs(a, "Machine C", "Retired");
    await expect(banner).toContainText("A retired device still holds the team's current fleet key.");
    await revokeAs(a, "Machine D", "Lost");
    await expect(banner).toContainText("A revoked device that was lost");
  });

  await test.step("the rotation clears the banner, reports refused members and asks for a new bundle", async () => {
    await expect(card.getByTestId("team-export-due")).toHaveCount(0);
    await rotateOn(a);
    await expect(a.getByText("Fleet key rotated to generation 1.").first()).toBeVisible();
    await expect(a.getByText("The team server refused the new fleet key for 1 device(s).")).toBeVisible();
    await expect(banner).toHaveCount(0);
    await expect(card.getByTestId("team-rotation-status"))
      .toContainText("New key granted to 0 device(s); refused by the server for 1; skipped for 3.");
    await expect(card.getByTestId("team-export-due")).toContainText("Export the recovery bundle again.");
  });

  await test.step("exporting the recovery bundle ends the prompt", async () => {
    const out = card.getByTestId("team-export");
    await cardSignIn(a);
    await out.getByLabel("Recovery passphrase", { exact: true }).fill("correct horse");
    await out.getByLabel("Recovery passphrase again").fill("correct horse");
    await out.getByLabel("I recorded this root key fingerprint").check();
    await out.getByRole("button", { name: "Export recovery bundle" }).click();
    await expect(a.getByText("Recovery bundle exported to C:\\Users\\Example\\shardx-recovery.shxrecovery.")).toBeVisible();
    await expect(card.getByTestId("team-export-due")).toHaveCount(0);
  });
});

test("compromised is offered for a member row only, and its revoke asks for an urgent rotation", async ({ page: a }) => {
  const server = fakeTeamServer([
    { device_id: "c1".repeat(16), label: "Machine C", status: "active", granted: true, generation: 0 },
    { device_id: "c5".repeat(16), label: "Machine X", status: "active", granted: true, generation: 0, custodian: true },
  ]);
  const card = await teamDevicePage(a, "a", server);
  await cardClick(a, "Create fleet key");
  // A web-first assertion: the option list renders after the click.
  const offers = async (label: string, reasons: string[]) => {
    const row = await listDevices(a, label);
    await row.getByRole("combobox", { name: "Reason" }).click();
    await expect(a.getByRole("option")).toHaveText(reasons);
    await a.keyboard.press("Escape");
    await expect(a.getByRole("option")).toHaveCount(0);
  };

  await test.step("a custodian row is not offered compromised; a member row is", async () => {
    await offers("Machine X", ["Retired", "Lost"]);
    await offers("Machine C", ["Retired", "Lost", "Compromised"]);
  });

  await test.step("the compromised revoke warns that pushes stop until the rotation, then raises the urgent banner", async () => {
    const row = await listDevices(a, "Machine C");
    await cardSignIn(a);
    await row.getByRole("combobox", { name: "Reason" }).click();
    await a.getByRole("option", { name: "Compromised" }).click();
    await row.getByRole("button", { name: "Revoke" }).click();
    const dialog = a.getByRole("dialog");
    await expect(dialog).toContainText("no device can push or publish under the current key");
    await dialog.getByRole("button", { name: "Revoke" }).click();
    await expect(row).toContainText("Revoked");
    await expect(card.getByTestId("team-rotation-banner")).toContainText("lost or compromised");
  });
});

test("a rotation held up by a member's failing grant finishes once the custodian uses skip member", async ({ page: a }) => {
  const server = fakeTeamServer([
    { device_id: "c1".repeat(16), label: "Machine C", status: "active", granted: true, generation: 0 },
    { device_id: "c6".repeat(16), label: "Machine G", status: "active", granted: true, generation: 0, fails: true },
  ]);
  const card = await teamDevicePage(a, "a", server);
  await cardClick(a, "Create fleet key");
  await rotateOn(a);
  const failing = card.getByTestId("team-rotation-failing");
  await expect(card.getByTestId("team-rotation-status")).toContainText("is unfinished");
  // One failure may be a timeout: Skip is offered only once a resume fails too.
  await expect(failing).toHaveCount(0);
  await rotateOn(a, "Resume fleet key rotation");
  await expect(failing).toContainText(`keeps failing the new fleet key grant of device ${"c6".repeat(4)}`);

  await cardSignIn(a);
  await failing.getByRole("button", { name: "Skip member" }).click();
  const dialog = a.getByRole("dialog");
  await expect(dialog).toContainText("revoke it and have it enroll again");
  await dialog.getByRole("button", { name: "Skip member" }).click();
  await expect(card.getByTestId("team-rotation-status"))
    .toContainText("New key granted to 1 device(s); refused by the server for 0; skipped for 1.");
  await expect(failing).toHaveCount(0);
  expect(server.devices.find((d) => d.label === "Machine G")?.generation).toBe(0);
});

test("an unfinished rotation shows Resume and its deadline, and refuses Approve until it is done", async ({ page: a }) => {
  const server = fakeTeamServer([{ device_id: "c1".repeat(16), label: "Machine C", status: "pending", granted: false }]);
  const card = await teamDevicePage(a, "a", server, false, "&teamRotation=unfinished");
  await expect(card.getByTestId("team-rotation-status")).toContainText("The fleet key rotation to generation 1 is unfinished.");
  await expect(card.getByTestId("team-rotation-status")).toContainText("Finish it before");
  const row = await listDevices(a, "Machine C");
  await cardSignIn(a);
  await row.getByLabel("The code on the other device matches").check();
  await row.getByRole("button", { name: "Approve", exact: true }).click();
  await expect(a.getByText("A fleet key rotation is unfinished. Finish it before approving a device.")).toBeVisible();
  expect(server.devices.find((d) => d.label === "Machine C")?.status).toBe("pending");

  await rotateOn(a, "Resume fleet key rotation");
  await expect(card.getByTestId("team-rotation-status")).toContainText("Fleet key rotated to generation 1.");
  await expect(card.getByRole("button", { name: "Rotate fleet key" })).toBeVisible();
  await cardSignIn(a);
  await row.getByRole("button", { name: "Approve", exact: true }).click();
  await expect(row).toContainText("Active");
});

test("an expired rotation shows the stuck notice, keeps Rotate on to try again, and Approve works", async ({ page: a }) => {
  const server = fakeTeamServer([{ device_id: "c1".repeat(16), label: "Machine C", status: "pending", granted: false }]);
  const card = await teamDevicePage(a, "a", server, false, "&teamRotation=expired");
  await expect(card.getByTestId("team-rotation-status")).toContainText("expired before it was activated");
  await expect(card.getByTestId("team-rotation-status")).not.toContainText("Finish it before");
  await cardSignIn(a);
  await expect(card.getByRole("button", { name: "Rotate fleet key" })).toBeEnabled();
  const row = await listDevices(a, "Machine C");
  await cardSignIn(a);
  await row.getByLabel("The code on the other device matches").check();
  await row.getByRole("button", { name: "Approve", exact: true }).click();
  await expect(row).toContainText("Active");
});

test("a pull refused as under a retired key shows why", async ({ page }) => {
  const row = await teamPage(page, "&teamRefuse=profile_sync_pull&teamRefuseCode=sync.headUnderRetiredKey");
  await teamSignIn(page);
  await row("VN Automation 001").getByRole("button", { name: "Pull" }).click();
  await expect(page.getByText("This snapshot is under an older team key this device does not hold.")).toBeVisible();
  await expect(page.getByText("[[shardx:")).toHaveCount(0);
});

test("after a rotation the custodian pushes profiles under an older key, and a member's check-in collects the new key", async ({
  page: a, browser, baseURL, viewport,
}) => {
  test.slow();
  const server = fakeTeamServer();
  const b = await (await browser.newContext({ baseURL, viewport })).newPage();
  await teamDevicePage(a, "a", server);
  await teamDevicePage(b, "b", server);
  await admitB(a, b);
  const rowA = a.getByTestId("team-profile").filter({ hasText: "Beta Research" });
  const rowB = b.getByTestId("team-profile").filter({ hasText: "Beta Research" });
  const click = async (page: Page, row: ReturnType<Page["getByTestId"]>, name: string) => {
    await teamSignIn(page);
    await row.getByRole("button", { name, exact: true }).click();
  };
  const older = a.getByTestId("team-older-key-profile").filter({ hasText: "Beta Research" });

  await test.step("A publishes under generation 0, B joins and checks in, A stays behind", async () => {
    await click(a, rowA, "Publish");
    await click(a, rowA, "Check in");
    await expect.poll(() => teamPins(a)).toEqual(["AVAILABLE@1"]);
    await teamSignIn(b);
    await b.getByTestId("team-fleet").getByRole("button", { name: "Show fleet profiles" }).click();
    await teamSignIn(b);
    await b.getByTestId("team-fleet-profile").filter({ hasText: "Beta Research" }).getByRole("button", { name: "Join" }).click();
    await click(b, rowB, "Check in");
    await expect.poll(() => teamPins(b)).toEqual(["AVAILABLE@2"]);
  });

  await test.step("A rotates; its profile still under generation 0 is listed", async () => {
    await expect(a.getByTestId("team-older-key")).toHaveCount(0);
    await rotateOn(a);
    await expect(older).toContainText("Generation 0");
    await expect(a.getByTestId("team-older-key")).toContainText("cannot read these profiles");
  });

  const id = [...server.heads.keys()][0];
  await test.step("behind B's version, Push says to pull first and neither pulls nor pushes", async () => {
    await cardSignIn(a);
    await older.getByRole("button", { name: "Push", exact: true }).click();
    await expect(older).toContainText("This device's copy is behind the team server, so nothing was pushed.");
    expect(server.heads.get(id)?.version).toBe(2);
    await expect.poll(() => teamPins(a)).toEqual(["AVAILABLE@1"]);
  });

  await test.step("pulled from the profile list, the copy is pushed under generation 1", async () => {
    await click(a, rowA, "Pull");
    await expect.poll(() => teamPins(a)).toEqual(["AVAILABLE@2"]);
    await expect(older).toContainText("Generation 0");
    await cardSignIn(a);
    await older.getByRole("button", { name: "Push", exact: true }).click();
    await expect(a.getByText("Beta Research is now under the newest fleet key.")).toBeVisible();
    await expect(a.getByTestId("team-older-key")).toHaveCount(0);
    await expect.poll(() => teamPins(a)).toEqual(["AVAILABLE@3"]);
  });

  await test.step("B's check-in refused under the old key collects generation 1 and runs once more", async () => {
    await click(b, rowB, "Pull");
    await click(b, rowB, "Check in");
    await expect(b.getByText("Fleet key collected (generation 1).")).toBeVisible();
    await expect(b.getByText("The team's fleet key was rotated", { exact: false })).toHaveCount(0);
    await expect.poll(() => teamPins(b)).toEqual(["AVAILABLE@4"]);
  });

  await test.step("two more rotations later, B is told to enroll again", async () => {
    await rotateOn(a);
    await expect(a.getByText("Fleet key rotated to generation 2.").first()).toBeVisible();
    await rotateOn(a);
    await expect(a.getByText("Fleet key rotated to generation 3.").first()).toBeVisible();
    await cardClick(b, "Collect key custody");
    await expect(b.getByText("This device missed more than one fleet key rotation", { exact: false })).toBeVisible();
    await expect(b.getByText("The fleet key grant for this device failed its check", { exact: false })).toHaveCount(0);
  });

  await test.step("a Check in from the profile list takes the row off the older-key list", async () => {
    // Behind B's version 4: pulled, then pushed as version 5 under generation 3.
    await click(a, rowA, "Pull");
    await cardSignIn(a);
    await older.getByRole("button", { name: "Push", exact: true }).click();
    await expect(a.getByTestId("team-older-key")).toHaveCount(0);
    await expect.poll(() => teamPins(a)).toEqual(["AVAILABLE@5"]);
    await rotateOn(a);
    await expect(older).toContainText("Generation 3");
    await click(a, rowA, "Check in");
    await expect.poll(() => teamPins(a)).toEqual(["AVAILABLE@6"]);
    await expect(a.getByTestId("team-older-key")).toHaveCount(0);
  });
  await b.context().close();
});

test("re-seal all profiles moves each free head under the newest key and lists the profiles it skips", async ({ page: a }) => {
  const server = fakeTeamServer();
  const card = await teamDevicePage(a, "a", server);
  const rowA = a.getByTestId("team-profile").filter({ hasText: "Beta Research" });
  const results = card.getByTestId("team-reseal-profile");
  await cardClick(a, "Create fleet key");

  await test.step("A publishes and checks in under generation 0; another device holds a second profile", async () => {
    for (const name of ["Publish", "Check in"]) {
      await teamSignIn(a);
      await rowA.getByRole("button", { name, exact: true }).click();
    }
    await expect.poll(() => teamPins(a)).toEqual(["AVAILABLE@1"]);
    server.heads.set("e1".repeat(16), { version: 1, label: "Leased", holder: "b", revoked: false });
    server.heads.set("e2".repeat(16), { version: 1, label: "Untrusted", holder: null, revoked: false });
  });

  await test.step("after a rotation the confirm warns members to pull first, and the run lists each outcome", async () => {
    await rotateOn(a);
    await cardClick(a, "Re-seal all profiles");
    const dialog = a.getByRole("dialog");
    await expect(dialog).toContainText("Members with unpushed changes must Pull first, which replaces their local changes.");
    await expect(dialog).toContainText("Profiles in use, in error or quarantined are skipped and listed.");
    await dialog.getByRole("button", { name: "Re-seal all profiles" }).click();
    await expect(a.getByText("Re-seal finished: 1 re-sealed, 0 already current, 2 skipped.")).toBeVisible();
    await expect(results).toHaveCount(3);
    await expect(results.filter({ hasText: "Re-sealed (version 2)" })).toHaveCount(1);
    await expect(results.filter({ hasText: "Skipped: in use, checked out or with unpushed changes" })).toHaveCount(1);
    // An error shows its message, never the raw code.
    await expect(results.filter({ hasText: "Skipped: The snapshot's signer is not trusted to commit this profile" }))
      .toHaveCount(1);
    await expect(results.filter({ hasText: "sync.signerUntrusted" })).toHaveCount(0);
    await expect.poll(() => teamPins(a)).toEqual(["AVAILABLE@2"]);
    await expect(a.getByTestId("team-older-key")).toHaveCount(0);
  });

  await test.step("a second run commits nothing new", async () => {
    await cardClick(a, "Re-seal all profiles");
    await a.getByRole("dialog").getByRole("button", { name: "Re-seal all profiles" }).click();
    await expect(a.getByText("Re-seal finished: 0 re-sealed, 1 already current, 2 skipped.")).toBeVisible();
    expect([...server.heads.values()].map((h) => h.version)).toEqual([2, 1, 1]);
  });
  await expect(a.getByText("[[shardx:")).toHaveCount(0);
});

test("a root custodian past 75% of its custody records is warned, renews, and is asked to export again", async ({ page: a }) => {
  const server = fakeTeamServer();
  const card = await teamDevicePage(a, "a", server, false, "&teamRenewal=due");
  const renewal = card.getByTestId("team-renewal");
  await expect(renewal.getByTestId("team-renewal-warning")).toContainText("Root custody records end");
  await expect(card.getByTestId("team-export-due")).toHaveCount(0);
  await cardClick(a, "Renew custody");
  await expect(a.getByText("Root custody renewed. Export the recovery bundle again.")).toBeVisible();
  await expect(renewal.getByTestId("team-renewal-warning")).toHaveCount(0);
  await expect(renewal).toContainText("Renewed automatically on the next custody action or team sync");
  await expect(renewal.getByRole("button", { name: "Renew custody" })).toHaveCount(0);
  await expect(card.getByTestId("team-export-due")).toContainText(
    "Root custody was renewed, so a recovery bundle exported before holds the replaced root grant.",
  );
  await expect(a.getByText("[[shardx:")).toHaveCount(0);
});

test("a root custodian not yet due to renew sees its custody dates and no renew action", async ({ page: a }) => {
  const server = fakeTeamServer();
  const card = await teamDevicePage(a, "a", server);
  const renewal = card.getByTestId("team-renewal");
  await expect(renewal).toContainText("Root custody records");
  await expect(renewal.getByTestId("team-renewal-warning")).toHaveCount(0);
  await expect(renewal.getByTestId("team-renewal-key-age")).toContainText("counts as the root custodian's until");
  await expect(renewal.getByRole("button", { name: "Renew custody" })).toHaveCount(0);
});

// The v2.10 root custody hand-over (plan 4.H): A, the root custodian, appoints B;
// B accepts and works through the checklist, then revokes A, which stays inert.
const B_ID = "b1".repeat(16);
const pendingB: TeamDeviceRow = { device_id: B_ID, label: "Machine B", status: "pending", granted: false };
const activeB: TeamDeviceRow = { device_id: B_ID, label: "Machine B", status: "active", granted: true, generation: 0 };

/** The hand-over checklist's step states on `page`, in order. */
const handoverSteps = (page: Page) =>
  page.getByTestId("team-handover-step").evaluateAll((els) => els.map((e) => e.getAttribute("data-state")));

/** Appoints the pending "Machine B" on A through the code tick and the confirm dialog. */
async function appointB(a: Page) {
  const row = await listDevices(a, "Machine B");
  await cardSignIn(a);
  await row.getByLabel("The code on the other device matches").check();
  await row.getByRole("button", { name: "Approve as root custodian" }).click();
  await a.getByRole("dialog").getByRole("button", { name: "Approve as root custodian" }).click();
  return row;
}

/** Opens B, the device A appointed, and accepts root custody on it. */
async function acceptOnB(b: Page, server: ReturnType<typeof fakeTeamServer>) {
  const card = await teamDevicePage(b, "b", server, false, "&teamHandover=appointed");
  await cardClick(b, "Accept root custody");
  await expect(b.getByText("Root custody accepted. Work through the hand-over checklist.")).toBeVisible();
  await expect.poll(() => handoverSteps(b)).toEqual(["next", "waiting", "waiting", "waiting", "waiting"]);
  return card;
}

/** Exports the recovery bundle on the page's own root custodian. */
async function exportBundle(page: Page) {
  const out = page.getByTestId("team-export");
  await cardSignIn(page);
  await out.getByLabel("Recovery passphrase", { exact: true }).fill("correct horse");
  await out.getByLabel("Recovery passphrase again").fill("correct horse");
  await out.getByLabel("I recorded this root key fingerprint").check();
  await out.getByRole("button", { name: "Export recovery bundle" }).click();
}

/** B's checklist steps 0-3: export, rotate, re-seal, export again, each enabled once the one before is done. */
async function finishChecklist(b: Page) {
  const card = b.getByTestId("team-card");
  await cardSignIn(b);
  await expect(card.getByRole("button", { name: "Rotate fleet key" })).toBeDisabled();
  await expect(card.getByRole("button", { name: "Re-seal all profiles" })).toBeDisabled();
  await exportBundle(b);
  await expect.poll(() => handoverSteps(b)).toEqual(["done", "next", "waiting", "waiting", "waiting"]);
  await rotateOn(b);
  await expect.poll(() => handoverSteps(b)).toEqual(["done", "done", "next", "waiting", "waiting"]);
  await cardClick(b, "Re-seal all profiles");
  await b.getByRole("dialog").getByRole("button", { name: "Re-seal all profiles" }).click();
  await expect.poll(() => handoverSteps(b)).toEqual(["done", "done", "done", "next", "waiting"]);
  await exportBundle(b);
  await expect.poll(() => handoverSteps(b)).toEqual(["done", "done", "done", "done", "next"]);
}

/** Starts revoking the old root "Machine A" on B as `reason`, through the confirm that states the member rule. */
async function revokeOldRoot(b: Page, reason: "Retired" | "Lost") {
  const row = await listDevices(b, "Machine A");
  await expect(row).toContainText("Old root");
  await cardSignIn(b);
  await row.getByRole("combobox", { name: "Reason" }).click();
  await expect(b.getByRole("option", { name: "Compromised" })).toHaveCount(0);
  await b.getByRole("option", { name: reason }).click();
  await row.getByRole("button", { name: "Revoke" }).click();
  const dialog = b.getByRole("dialog");
  await expect(dialog).toContainText(
    "Every member must run 2.10 and have synced once since the hand-over began: a member still on 2.9.x distrusts peers it has not seen and must enroll again.",
  );
  await dialog.getByRole("button", { name: "Revoke" }).click();
  return row;
}

test("team-handover-appoint: the root custodian approves a pending device as root custodian and hands over", async ({ page: a }) => {
  const server = fakeTeamServer([pendingB]);
  const card = await teamDevicePage(a, "a", server);
  await cardClick(a, "Create fleet key");
  const row = await listDevices(a, "Machine B");
  await cardSignIn(a);
  await expect(row.getByRole("button", { name: "Approve as root custodian" })).toBeDisabled();
  await row.getByLabel("The code on the other device matches").check();
  await row.getByRole("button", { name: "Approve as root custodian" }).click();
  const dialog = a.getByRole("dialog");
  await expect(dialog).toContainText("Machine B becomes the root custodian and this computer hands its root custody over.");
  await expect(dialog).toContainText("can be cancelled only by revoking Machine B before it rotates the fleet key");
  await dialog.getByRole("button", { name: "Approve as root custodian" }).click();
  await expect(a.getByText("Machine B was approved as root custodian.")).toBeVisible();
  await expect(row).toContainText("Active");
  await expect(card.getByTestId("team-handed-over")).toContainText("Root custody was handed to device b1b1b1b1.");
  await expect(card.getByRole("button", { name: "Rotate fleet key" })).toHaveCount(0);
  await expect(card.getByTestId("team-export")).toHaveCount(0);
  await expect(card.getByTestId("team-renewal")).toHaveCount(0);
  expect(server.devices.find((d) => d.device_id === B_ID)?.custodian).toBe(true);
  await expect(a.getByText("[[shardx:")).toHaveCount(0);
});

test("team-handover-needs-reseal: appointing is refused until every head is under the current fleet key", async ({ page: a }) => {
  const server = fakeTeamServer([pendingB]);
  const card = await teamDevicePage(a, "a", server);
  await cardClick(a, "Create fleet key");
  server.heads.set("e1".repeat(16), { version: 1, label: "Shop", holder: null, revoked: false });
  await rotateOn(a);
  const row = await appointB(a);
  await expect(a.getByText(
    "Re-seal all profiles first: every profile head must be under the current fleet key before another device can take over root custody.",
  )).toBeVisible();
  await expect(row).toContainText("Pending");
  await expect(card.getByTestId("team-handed-over")).toHaveCount(0);

  await cardClick(a, "Re-seal all profiles");
  await a.getByRole("dialog").getByRole("button", { name: "Re-seal all profiles" }).click();
  await expect(a.getByText("Re-seal finished: 1 re-sealed, 0 already current, 0 skipped.")).toBeVisible();
  await cardSignIn(a);
  await row.getByRole("button", { name: "Approve as root custodian" }).click();
  await a.getByRole("dialog").getByRole("button", { name: "Approve as root custodian" }).click();
  await expect(card.getByTestId("team-handed-over")).toBeVisible();
  await expect(a.getByText("[[shardx:")).toHaveCount(0);
});

test("team-handover-accept: the appointed device accepts root custody and is shown the checklist", async ({ page: b }) => {
  const server = fakeTeamServer([activeB]);
  const card = await teamDevicePage(b, "b", server, false, "&teamHandover=appointed");
  const accept = card.getByTestId("team-handover-accept");
  await expect(accept).toContainText("Only when the root custodian approved this device as the new root custodian");
  await expect(card.getByTestId("team-handover-checklist")).toHaveCount(0);
  await cardClick(b, "Accept root custody");
  await expect(b.getByText("No root custodian has appointed this device yet.")).toBeVisible();
  await expect(card.getByTestId("team-handover-checklist")).toHaveCount(0);

  server.appoint(B_ID);
  await cardClick(b, "Accept root custody");
  await expect(b.getByText("Root custody accepted. Work through the hand-over checklist.")).toBeVisible();
  await expect(accept).toHaveCount(0);
  await expect(card.getByTestId("team-handover-checklist")).toContainText("Root custody hand-over");
  await expect.poll(() => handoverSteps(b)).toEqual(["next", "waiting", "waiting", "waiting", "waiting"]);
  await expect(card.getByTestId("team-devices").getByText("Fleet key ready", { exact: true })).toBeVisible();
  await expect(b.getByText("[[shardx:")).toHaveCount(0);
});

test("team-handover-checklist: the new custodian's steps enable in order and its rotation skips the old root", async ({ page: b }) => {
  const server = fakeTeamServer([activeB], B_ID);
  await acceptOnB(b, server);
  const old = await listDevices(b, "Machine A");
  await cardSignIn(b);
  await expect(old.getByRole("button", { name: "Revoke" })).toBeDisabled();
  await finishChecklist(b);
  expect(server.devices.find((d) => d.label === "Machine A")?.generation).not.toBe(1);
  await cardSignIn(b);
  await expect(old.getByRole("button", { name: "Revoke" })).toBeEnabled();
  await expect(b.getByText("[[shardx:")).toHaveCount(0);
});

test("team-handover-blocked: a head the old root pushed after the re-seal blocks a retired revoke", async ({ page: b }) => {
  const server = fakeTeamServer([activeB], B_ID);
  server.heads.set("e1".repeat(16), { version: 1, label: "Shop", holder: null, revoked: false });
  const card = await acceptOnB(b, server);
  await finishChecklist(b);
  Object.assign(server.heads.get("e1".repeat(16)) ?? {}, { version: 3, oldRootPush: true });
  const row = await revokeOldRoot(b, "Retired");
  await expect(b.getByText(/The old root custodian cannot be revoked yet: finish the hand-over step "heads" first/)).toBeVisible();
  await expect(card.getByTestId("team-handover-blockers")).toContainText("e1e1e1e1");
  await expect(row).toContainText("Active");
  expect(server.devices.find((d) => d.label === "Machine A")?.status).toBe("active");
  await expect(b.getByText("[[shardx:")).toHaveCount(0);
});

test("team-handover-lost-reverts: a lost old root is revoked once the will-be-reverted list is confirmed", async ({ page: b }) => {
  const server = fakeTeamServer([activeB], B_ID);
  server.heads.set("e1".repeat(16), { version: 1, label: "Shop", holder: null, revoked: false });
  const card = await acceptOnB(b, server);
  await finishChecklist(b);
  Object.assign(server.heads.get("e1".repeat(16)) ?? {}, { version: 3, oldRootPush: true });
  const row = await revokeOldRoot(b, "Lost");
  const reverts = b.getByRole("dialog").filter({ hasText: "Revoke the old root and revert these profiles?" });
  await expect(reverts).toContainText("They will be reverted right after the revoke: e1e1e1e1");
  await reverts.getByRole("button", { name: "Revoke and revert" }).click();
  await expect(row).toContainText("Revoked");
  await expect(card.getByTestId("team-handover-revert")).toContainText("e1e1e1e1 Reverted (version 4)");
  await expect(card.getByTestId("team-handover-done")).toBeVisible();
  expect(server.heads.get("e1".repeat(16))?.version).toBe(4);
  expect(server.devices.find((d) => d.label === "Machine A")?.status).toBe("revoked");
  await expect(b.getByText("[[shardx:")).toHaveCount(0);
});

test("team-handover-cancel-too-late: the old root cannot cancel once the new custodian rotated", async ({
  page: a, browser, baseURL, viewport,
}) => {
  const server = fakeTeamServer([{ ...activeB, custodian: true }], B_ID);
  const b = await (await browser.newContext({ baseURL, viewport })).newPage();
  await teamDevicePage(a, "a", server, false, "&teamHandover=appointed");
  await acceptOnB(b, server);
  await exportBundle(b);
  await expect.poll(() => handoverSteps(b)).toEqual(["done", "next", "waiting", "waiting", "waiting"]);
  await rotateOn(b);
  await expect.poll(() => handoverSteps(b)).toEqual(["done", "done", "next", "waiting", "waiting"]);

  const row = await listDevices(a, "Machine B");
  await cardSignIn(a);
  await row.getByRole("button", { name: "Revoke" }).click();
  const dialog = a.getByRole("dialog");
  await expect(dialog).toContainText("Revoking the appointed device cancels the hand-over");
  await dialog.getByRole("button", { name: "Revoke" }).click();
  await expect(a.getByText("The new root custodian already rotated the fleet key, so the hand-over can no longer be cancelled.")).toBeVisible();
  await expect(row).toContainText("Active");
  await expect(a.getByTestId("team-handed-over")).toBeVisible();
  expect(server.devices.find((d) => d.device_id === B_ID)?.status).toBe("active");
  await b.context().close();
});

test("team-handover-done: the new custodian revokes the old root as retired and the hand-over ends", async ({ page: b }) => {
  const server = fakeTeamServer([activeB], B_ID);
  server.heads.set("e1".repeat(16), { version: 1, label: "Shop", holder: null, revoked: false });
  const card = await acceptOnB(b, server);
  await finishChecklist(b);
  const row = await revokeOldRoot(b, "Retired");
  await expect(row).toContainText("Revoked");
  await expect(card.getByTestId("team-handover-done")).toContainText(
    "Root custody hand-over finished: the old root device is revoked.",
  );
  await expect.poll(() => handoverSteps(b)).toEqual(["done", "done", "done", "done", "done"]);
  await expect(card.getByTestId("team-handover-revert")).toHaveCount(0);
  expect(server.devices.find((d) => d.label === "Machine A")?.status).toBe("revoked");
  await expect(b.getByText("[[shardx:")).toHaveCount(0);
});

test("team-old-root-inert: a root custodian that handed over runs no custody action and can only cancel", async ({ page: a }) => {
  const server = fakeTeamServer([
    { ...activeB, custodian: true },
    { device_id: "c1".repeat(16), label: "Machine C", status: "active", granted: true, generation: 0 },
    { device_id: "d1".repeat(16), label: "Machine D", status: "pending", granted: false },
  ], B_ID);
  const card = await teamDevicePage(a, "a", server, false, "&teamHandover=appointed");
  const notice = card.getByTestId("team-handed-over");
  await expect(notice).toContainText("Root custody was handed to device b1b1b1b1. This computer runs no custody actions any more.");
  await expect(notice).toContainText("revoked this computer, reset it below");
  await expect(notice.getByRole("button", { name: "Reset this device" })).toBeVisible();
  for (const name of ["Rotate fleet key", "Re-seal all profiles", "Create fleet key", "Export recovery bundle", "Renew custody"]) {
    await expect(card.getByRole("button", { name })).toHaveCount(0);
  }
  await expect(card.getByTestId("team-handover-accept")).toHaveCount(0);

  const pending = await listDevices(a, "Machine D");
  await cardSignIn(a);
  await pending.getByLabel("The code on the other device matches").check();
  await expect(pending.getByRole("button", { name: "Approve", exact: true })).toBeDisabled();
  await expect(pending.getByRole("button", { name: "Approve as root custodian" })).toHaveCount(0);
  await expect(a.getByTestId("team-device").filter({ hasText: "Machine C" }).getByRole("button", { name: "Revoke" }))
    .toHaveCount(0);

  // Before the new custodian rotates, revoking it cancels the hand-over and custody comes back.
  const appointee = a.getByTestId("team-device").filter({ hasText: "Machine B" });
  await appointee.getByRole("button", { name: "Revoke" }).click();
  await a.getByRole("dialog").getByRole("button", { name: "Revoke" }).click();
  await expect(appointee).toContainText("Revoked");
  await expect(notice).toHaveCount(0);
  await expect(card.getByRole("button", { name: "Rotate fleet key" })).toBeVisible();
  await expect(a.getByText("[[shardx:")).toHaveCount(0);
});

test("reset the old root: a handed-over root resets only once the server lists it revoked", async ({ page: a }) => {
  const server = fakeTeamServer([{ ...activeB, custodian: true }], B_ID);
  const card = await teamDevicePage(a, "a", server, false, "&teamHandover=appointed");
  const reset = card.getByTestId("team-handed-over").getByRole("button", { name: "Reset this device" });
  await expect(reset).toBeDisabled();
  await cardSignIn(a);
  await reset.click();
  await expect(a.getByText("This root device can be reset only once the team server lists it revoked")).toBeVisible();
  await expect(card.getByTestId("team-handed-over")).toBeVisible();

  // The new custodian revoked it: the signed revocation lets it reset.
  server.devices.find((d) => d.label === "Machine A")!.status = "revoked";
  await cardSignIn(a);
  await reset.click();
  await expect(a.getByText("This device's identity was cleared. Enroll it again for a new join code.")).toBeVisible();
  await expect(card.getByTestId("team-handed-over")).toHaveCount(0);
  await expect(a.getByText("[[shardx:")).toHaveCount(0);
});

test("member renewal: each member shows its approval end, warns from 75%, and a 2.10 server is named", async ({ page: a }) => {
  const machineC: TeamDeviceRow = { device_id: "c1".repeat(16), label: "Machine C", status: "active", granted: true, generation: 0 };
  const server = fakeTeamServer([machineC]);
  const card = await teamDevicePage(a, "a", server, false, "&teamMemberApproval=late&teamMembers=server-too-old");
  const row = await listDevices(a, "Machine C");
  await expect(row.getByTestId("team-device-approval")).toContainText("Approval ends");
  await expect(row.getByTestId("team-device-approval")).toContainText("renew custody now");
  await expect(card.getByTestId("team-members-server-update")).toContainText(
    "The team server is too old to renew member devices' approvals.",
  );
  // This computer's own row shows no member approval.
  await expect(a.getByTestId("team-device").filter({ hasText: "Machine A" }).getByTestId("team-device-approval"))
    .toHaveCount(0);
  await expect(a.getByText("[[shardx:")).toHaveCount(0);
});

test("member renewal: a member early in its approval shows its end without a warning", async ({ page: a }) => {
  const machineC: TeamDeviceRow = { device_id: "c1".repeat(16), label: "Machine C", status: "active", granted: true, generation: 0 };
  const server = fakeTeamServer([machineC]);
  const card = await teamDevicePage(a, "a", server);
  const row = await listDevices(a, "Machine C");
  await expect(row.getByTestId("team-device-approval")).toContainText("Approval ends");
  await expect(row.getByTestId("team-device-approval")).not.toContainText("renew custody now");
  await expect(card.getByTestId("team-members-server-update")).toHaveCount(0);
});

// The two-machine gate (Plan:2388), each step a test.step below:
//   publish               = S5 publish on A
//   checkout/restore on B = S3b join + pull on B
//   use                   = an ordinary launch; the mock launch is not team-aware, so only the real run covers it
//   check-in on B         = S5 check-in on B (the checkout inside push)
//   checkout on A         = A pull + check-in
// The real two-machine run is recorded in docs/team-ui-evidence/two-machine-run.md.
test("two devices pass one team profile back and forth, then revert a revoked head to available", async ({
  page: a, browser, baseURL, viewport,
}) => {
  // Two pages and about twenty actions: under the full parallel run it can pass 30s.
  test.slow();
  const server = fakeTeamServer();
  const b = await (await browser.newContext({ baseURL, viewport })).newPage();
  await teamDevicePage(a, "a", server);
  await teamDevicePage(b, "b", server);
  await admitB(a, b);
  const rowA = a.getByTestId("team-profile").filter({ hasText: "Beta Research" });
  const rowB = b.getByTestId("team-profile").filter({ hasText: "Beta Research" });
  const click = async (page: Page, row: ReturnType<Page["getByTestId"]>, name: string) => {
    await teamSignIn(page);
    await row.getByRole("button", { name, exact: true }).click();
  };

  await test.step("publish: S5 publish on A", async () => {
    await expect(rowA).toContainText("Local only");
    await click(a, rowA, "Publish");
    await expect(rowA).toContainText("Checked out here");
    await expect.poll(() => teamPins(a)).toEqual(["CHECKED_OUT@0"]);
  });

  await test.step("A checks in its first version", async () => {
    await click(a, rowA, "Check in");
    await expect(rowA).toContainText("Available");
    await expect.poll(() => teamPins(a)).toEqual(["AVAILABLE@1"]);
  });

  await test.step("checkout/restore on B: S3b join + pull", async () => {
    await expect(rowB).toHaveCount(0);
    await teamSignIn(b);
    await b.getByTestId("team-fleet").getByRole("button", { name: "Show fleet profiles" }).click();
    const fleet = b.getByTestId("team-fleet-profile").filter({ hasText: "Beta Research" });
    await expect(fleet).toContainText("Version 1");
    await teamSignIn(b);
    await fleet.getByRole("button", { name: "Join" }).click();
    await expect(rowB).toContainText("Available");
    await expect(fleet).toContainText("Joined");
    await expect.poll(() => teamPins(b)).toEqual(["AVAILABLE@1"]);
    await click(b, rowB, "Pull");
    await expect(b.getByText("Profile pulled from the team.")).toBeVisible();
    await expect.poll(() => teamPins(b)).toEqual(["AVAILABLE@1"]);
  });

  await test.step("check-in on B: S5 check-in", async () => {
    await click(b, rowB, "Check in");
    await expect(b.getByText("Profile checked in.")).toBeVisible();
    await expect(rowB).toContainText("Available");
    await expect.poll(() => teamPins(b)).toEqual(["AVAILABLE@2"]);
    await expect.poll(() => teamPins(a)).toEqual(["AVAILABLE@1"]);
  });

  await test.step("A, still on version 1, is refused a check-in over B's version 2", async () => {
    await click(a, rowA, "Check in");
    await expect(a.getByText("The team server has a newer version of this profile. Pull it before pushing.")).toBeVisible();
    await expect(rowA).toContainText("Available");
    await expect.poll(() => teamPins(a)).toEqual(["AVAILABLE@1"]);
    expect([...server.heads.values()]).toEqual([{ version: 2, label: "Beta Research", holder: null, revoked: false }]);
  });

  await test.step("checkout on A: A pull + check-in", async () => {
    await click(a, rowA, "Pull");
    await expect.poll(() => teamPins(a)).toEqual(["AVAILABLE@2"]);
    await click(a, rowA, "Check in");
    await expect.poll(() => teamPins(a)).toEqual(["AVAILABLE@3"]);
    await expect(rowA).toContainText("Available");
  });

  const id = [...server.heads.keys()][0];
  await test.step("a head signed by a key later proven revoked quarantines both devices", async () => {
    server.revokedCheckIn(id);
    for (const [page, row, pin] of [[a, rowA, 3], [b, rowB, 2]] as const) {
      await click(page, row, "Pull");
      await expect(row).toContainText("Quarantined");
      await expect(row).toContainText("signer revoked");
      await expect(row.getByRole("button")).toHaveText(["Revert", "Pull", "Unbind"]);
      await expect.poll(() => teamPins(page)).toEqual([`QUARANTINED@${pin}`]);
    }
  });

  await test.step("B reverts, A pulls the revert, and both are available", async () => {
    await click(b, rowB, "Revert");
    await b.getByRole("dialog").getByRole("button", { name: "Revert" }).click();
    await expect(b.getByText("Profile reverted to its last valid snapshot.")).toBeVisible();
    await expect(rowB).toContainText("Available");
    await click(a, rowA, "Pull");
    await expect(rowA).toContainText("Available");
    for (const row of [rowA, rowB]) {
      await expect(row.getByRole("button")).toHaveText(["Check in", "Pull", "Unbind"]);
    }
    // Final pins: both devices on the revert head the server holds.
    await expect.poll(() => teamPins(a)).toEqual(["AVAILABLE@5"]);
    await expect.poll(() => teamPins(b)).toEqual(["AVAILABLE@5"]);
    expect(server.heads.get(id)).toEqual({ version: 5, label: "Beta Research", holder: null, revoked: false });
  });
  await b.context().close();
});

test("a custodian revokes a device and the device can no longer pull", async ({ page: a, browser, baseURL, viewport }) => {
  test.slow();
  const server = fakeTeamServer();
  const b = await (await browser.newContext({ baseURL, viewport })).newPage();
  await teamDevicePage(a, "a", server);
  await teamDevicePage(b, "b", server);
  await admitB(a, b);
  const rowA = a.getByTestId("team-profile").filter({ hasText: "Beta Research" });
  const rowB = b.getByTestId("team-profile").filter({ hasText: "Beta Research" });
  const click = async (page: Page, row: ReturnType<Page["getByTestId"]>, name: string) => {
    await teamSignIn(page);
    await row.getByRole("button", { name, exact: true }).click();
  };
  await click(a, rowA, "Publish");
  await click(a, rowA, "Check in");
  await expect(rowA).toContainText("Available");
  await teamSignIn(b);
  await b.getByTestId("team-fleet").getByRole("button", { name: "Show fleet profiles" }).click();
  await teamSignIn(b);
  await b.getByTestId("team-fleet-profile").filter({ hasText: "Beta Research" }).getByRole("button", { name: "Join" }).click();
  await expect(rowB).toContainText("Available");
  await click(b, rowB, "Pull");
  await expect(b.getByText("Profile pulled from the team.")).toBeVisible();

  const row = await listDevices(a, "Machine B");
  await expect(row).toContainText("Active");
  await cardSignIn(a);
  await row.getByRole("button", { name: "Revoke" }).click();
  const dialog = a.getByRole("dialog");
  await expect(dialog).toContainText("It keeps the fleet key it already holds");
  await expect(dialog).toContainText(
    "A head it signed before the revoke that this computer already pinned is quarantined too (signer revoked): run Revert on that profile to continue.",
  );
  await dialog.getByRole("button", { name: "Revoke" }).click();
  await expect(row).toContainText("Revoked");
  await expect(row.getByRole("button", { name: "Revoke" })).toHaveCount(0);
  expect(server.devices.find((d) => d.label === "Machine B")?.status).toBe("revoked");

  await click(b, rowB, "Pull");
  await expect(b.getByText("The team server refused to open a session for this device (403)")).toBeVisible();
  await expect(b.getByText("revoked and holds no live approval")).toBeVisible();
  await b.context().close();
});

test("an expired join code offers Enroll again and a new code", async ({ page: b }) => {
  const server = fakeTeamServer();
  const card = await teamDevicePage(b, "b", server, true);
  await teamEnroll(b, "Machine B");
  await cardClick(b, "Show join code");
  const sas = b.getByTestId("team-join-sas");
  const first = await sas.innerText();
  await expect(card.getByTestId("team-join")).toContainText("left on this computer's clock");

  await b.clock.fastForward("10:01");
  await expect(card.getByTestId("team-join")).toContainText("This join code has expired.");
  await expect(sas).toHaveCount(0);
  await expect(card.getByRole("button", { name: "Codes match" })).toHaveCount(0);
  // The local clock alone offers nothing: Show join code asks the backend.
  await expect(card.getByRole("button", { name: "Enroll again" })).toHaveCount(0);

  await cardClick(b, "Show join code");
  await cardClick(b, "Enroll again");
  await expect(card.getByRole("button", { name: "Enroll this device" })).toBeVisible();
  await teamEnroll(b, "Machine B");
  await cardClick(b, "Show join code");
  await expect(sas).toHaveText(/^([0-9a-f]{4} ){7}[0-9a-f]{4}$/);
  expect(await sas.innerText()).not.toBe(first);
  await expect(card.getByRole("button", { name: "Codes match" })).toBeVisible();
});

test("an approved device whose join code expired can enroll again", async ({ page: a, browser, baseURL, viewport }) => {
  test.slow();
  const server = fakeTeamServer();
  const b = await (await browser.newContext({ baseURL, viewport })).newPage();
  await teamDevicePage(a, "a", server);
  const cardB = await teamDevicePage(b, "b", server, true);
  await cardClick(a, "Create fleet key");
  await teamEnroll(b, "Machine B");
  await cardClick(b, "Show join code");
  const old = await listDevices(a, "Machine B");
  await old.getByLabel("The code on the other device matches").check();
  await cardSignIn(a);
  await old.getByRole("button", { name: "Approve", exact: true }).click();
  await expect(old).toContainText("Active");

  await b.clock.fastForward("10:01");
  await expect(cardB.getByTestId("team-join")).toContainText("This join code has expired.");
  await cardClick(b, "Show join code");
  await cardClick(b, "Enroll again");
  await teamEnroll(b, "Machine B");

  const rows = await listDevices(a, "Machine B");
  await expect(rows).toHaveCount(2);
  await expect(rows.nth(0)).toContainText("Active");
  await expect(rows.nth(0)).not.toContainText("Newest");
  await expect(rows.nth(1)).toContainText("Pending");
  await expect(rows.nth(1)).toContainText("Newest");
  await expect(rows.nth(1)).toContainText("approve this one if its code matches");
  await b.context().close();
});

test("an active pinned device is not offered reenrollment after reopening Team", async ({ page: a, browser, baseURL, viewport }) => {
  const server = fakeTeamServer();
  const b = await (await browser.newContext({ baseURL, viewport })).newPage();
  try {
    await teamDevicePage(a, "a", server);
    await teamDevicePage(b, "b", server, true);
    await cardClick(a, "Create fleet key");
    await teamEnroll(b, "Pinned B");
    await cardClick(b, "Show join code");
    const row = await listDevices(a, "Pinned B");
    await row.getByLabel("The code on the other device matches").check();
    await cardSignIn(a);
    await row.getByRole("button", { name: "Approve", exact: true }).click();
    await expect(row).toContainText("Active");
    await cardClick(b, "Codes match");
    await expect(b.getByTestId("team-join")).toContainText("Codes confirmed.");
    // No collect yet. Remounting loses component state but preserves the pin.
    await b.getByRole("button", { name: "Settings", exact: true }).click();
    await b.clock.fastForward("10:01");
    await b.getByRole("button", { name: "Team", exact: true }).click();
    await cardClick(b, "Show join code");
    await expect(b.getByTestId("team-join")).toContainText("This join code has expired.");
    // Prove the actual mock command models the backend's refusal for this state.
    const rejected = await b.evaluate(async () => {
      const ipc = (window as unknown as { __TAURI_INTERNALS__: { invoke: (cmd: string, args: object) => Promise<unknown> } }).__TAURI_INTERNALS__;
      try {
        await ipc.invoke("team_enroll_again", { username: "owner", password: "pw" });
        return false;
      } catch (e) { return String(e).includes("fleet.enrollAgainRefused"); }
    });
    expect(rejected).toBe(true);
    await expect(b.getByTestId("team-card").getByRole("button", { name: "Enroll again", exact: true })).toHaveCount(0);
  } finally { await b.context().close(); }
});

test("an active pinned device is not offered reenrollment when a remounted code expires", async ({ page: a, browser, baseURL, viewport }) => {
  const server = fakeTeamServer();
  const b = await (await browser.newContext({ baseURL, viewport })).newPage();
  try {
    await teamDevicePage(a, "a", server);
    await teamDevicePage(b, "b", server, true);
    await cardClick(a, "Create fleet key");
    await teamEnroll(b, "Pinned B");
    await cardClick(b, "Show join code");
    const row = await listDevices(a, "Pinned B");
    await row.getByLabel("The code on the other device matches").check();
    await cardSignIn(a);
    await row.getByRole("button", { name: "Approve", exact: true }).click();
    await expect(row).toContainText("Active");
    await cardClick(b, "Codes match");
    await expect(b.getByTestId("team-join")).toContainText("Codes confirmed.");
    await b.getByRole("button", { name: "Settings", exact: true }).click();
    await b.getByRole("button", { name: "Team", exact: true }).click();
    await cardClick(b, "Show join code");
    await expect(b.getByTestId("team-join-sas")).toBeVisible();
    await b.clock.fastForward("10:01");
    await expect(b.getByTestId("team-join")).toContainText("This join code has expired.");
    const rejected = await b.evaluate(async () => {
      const ipc = (window as unknown as { __TAURI_INTERNALS__: { invoke: (cmd: string, args: object) => Promise<unknown> } }).__TAURI_INTERNALS__;
      try {
        await ipc.invoke("team_enroll_again", { username: "owner", password: "pw" });
        return false;
      } catch (e) { return String(e).includes("fleet.enrollAgainRefused"); }
    });
    expect(rejected).toBe(true);
    await expect(b.getByTestId("team-card").getByRole("button", { name: "Enroll again", exact: true })).toHaveCount(0);
  } finally { await b.context().close(); }
});

test("a custodian with no usable key is not shown Fleet key ready", async ({ page: a }) => {
  const server = fakeTeamServer(KEY_GATE_ROWS);
  await teamDevicePage(a, "a", server);
  await cardClick(a, "Create fleet key");
  await expect(a.getByTestId("team-devices").getByText("Fleet key ready", { exact: true })).toBeVisible();
  // Model the real backend's tested lost-key state: the setup journal stays
  // created/released, while team_status reports no key usable for sealing.
  await a.evaluate(() => {
    const ipc = (window as unknown as { __TAURI_INTERNALS__: { invoke: (...args: unknown[]) => Promise<unknown> } }).__TAURI_INTERNALS__;
    const original = ipc.invoke.bind(ipc);
    ipc.invoke = async (...args) => {
      const result = await original(...args);
      return args[0] === "team_status"
        ? { ...(result as object), has_fleet_key: false, fleet_key_blocked: false }
        : result;
    };
  });
  await a.getByRole("button", { name: "Settings", exact: true }).click();
  await a.getByRole("button", { name: "Team", exact: true }).click();
  await expect(a.getByTestId("team-devices")).toBeVisible();
  await expect(a.getByTestId("team-devices").getByText("Fleet key ready", { exact: true })).toHaveCount(0);
  await expect(a.getByTestId("team-devices").getByText(/holds no usable fleet key/)).toBeVisible();
  await expectKeyGates(a);
});

test("a custodian whose fleet key is blocked is shown the Q-18 notice", async ({ page: a }) => {
  const server = fakeTeamServer(KEY_GATE_ROWS);
  await teamDevicePage(a, "a", server);
  await cardClick(a, "Create fleet key");
  // As a custodian whose key verifies, but a compromised revoke blocks sealing.
  await a.evaluate(() => {
    const ipc = (window as unknown as { __TAURI_INTERNALS__: { invoke: (...args: unknown[]) => Promise<unknown> } }).__TAURI_INTERNALS__;
    const original = ipc.invoke.bind(ipc);
    ipc.invoke = async (...args) => {
      const result = await original(...args);
      return args[0] === "team_status"
        ? { ...(result as object), has_fleet_key: false, fleet_key_blocked: true }
        : result;
    };
  });
  await a.getByRole("button", { name: "Settings", exact: true }).click();
  await a.getByRole("button", { name: "Team", exact: true }).click();
  const devices = a.getByTestId("team-devices");
  await expect(devices.getByText(/pushing under it is blocked/)).toBeVisible();
  await expect(devices.getByText("Fleet key ready", { exact: true })).toHaveCount(0);
  await expect(devices.getByText(/holds no usable fleet key/)).toHaveCount(0);
  await expectKeyGates(a);
});

/** An active row to revoke and a pending row to approve, beside A. */
const KEY_GATE_ROWS: TeamDeviceRow[] = [
  { device_id: "c3".repeat(16), label: "Gate Active", status: "active", granted: false },
  { device_id: "d4".repeat(16), label: "Gate Pending", status: "pending", granted: false },
];

/** Without a usable key Approve stays off, while Revoke, which needs none, stays on. */
async function expectKeyGates(a: Page) {
  const pending = await listDevices(a, "Gate Pending");
  await pending.getByLabel("The code on the other device matches").check();
  await cardSignIn(a);
  await expect(pending.getByRole("button", { name: "Approve", exact: true })).toBeDisabled();
  const active = a.getByTestId("team-device").filter({ hasText: "Gate Active" });
  await expect(active.getByRole("button", { name: "Revoke", exact: true })).toBeEnabled();
}

test("the custodian cannot approve a row it first saw more than ten minutes ago", async ({ page: a, browser, baseURL, viewport }) => {
  const server = fakeTeamServer();
  const b = await (await browser.newContext({ baseURL, viewport })).newPage();
  await teamDevicePage(a, "a", server, true);
  await teamDevicePage(b, "b", server);
  await cardClick(a, "Create fleet key");
  await teamEnroll(b, "Machine B");

  const row = await listDevices(a, "Machine B");
  const approve = row.getByRole("button", { name: "Approve", exact: true });
  await row.getByLabel("The code on the other device matches").check();
  await cardSignIn(a);
  await expect(approve).toBeEnabled();
  await expect(row).toContainText("left on this computer's clock");

  await a.clock.fastForward("10:01");
  await expect(row).toContainText("Expired");
  await expect(approve).toBeDisabled();
  // Listing again keeps the first sight: the window is not reset.
  await listDevices(a, "Machine B");
  await cardSignIn(a);
  await expect(row).toContainText("Expired");
  await expect(approve).toBeDisabled();
  expect(server.devices.find((d) => d.label === "Machine B")?.status).toBe("pending");
  await b.context().close();
});

test("the reason list offers Retired and Lost, and Compromised for a member row only", async ({ page: a }) => {
  const server = fakeTeamServer([
    { device_id: "c1".repeat(16), label: "Machine C", status: "active", granted: false },
    { device_id: "c5".repeat(16), label: "Machine X", status: "active", granted: false, custodian: true },
  ]);
  await teamDevicePage(a, "a", server);
  const custodian = await listDevices(a, "Machine X");
  const row = a.getByTestId("team-device").filter({ hasText: "Machine C" });
  await expect(a.getByTestId("team-device").filter({ hasText: "Machine A" }).getByRole("combobox")).toHaveCount(0);
  await custodian.getByRole("combobox", { name: "Reason" }).click();
  await expect(a.getByRole("option")).toHaveText(["Retired", "Lost"]);
  await a.keyboard.press("Escape");
  await expect(a.getByRole("option")).toHaveCount(0);
  const reason = row.getByRole("combobox", { name: "Reason" });
  await expect(reason).toContainText("Retired");
  await reason.click();
  await expect(a.getByRole("option")).toHaveText(["Retired", "Lost", "Compromised"]);
  await a.getByRole("option", { name: "Lost" }).click();
  await expect(reason).toContainText("Lost");
});

test("approval stays disabled until the custodian creates its fleet key", async ({ page: a }) => {
  const server = fakeTeamServer([{ device_id: "c1".repeat(16), label: "Verifier Pending", status: "pending", granted: false }]);
  await teamDevicePage(a, "a", server);
  const row = await listDevices(a, "Verifier Pending");
  await row.getByLabel("The code on the other device matches").check();
  const devices = a.getByTestId("team-devices");
  // Listing cleared the password: the hint says why Approve is off.
  await expect(devices).toContainText("Enter your password above to approve.");
  await cardSignIn(a);
  await expect(a.getByRole("button", { name: "Create fleet key", exact: true })).toBeVisible();
  await expect(row.getByRole("button", { name: "Approve", exact: true })).toBeDisabled();
  await expect(devices).toContainText("Create the fleet key above before approving a device.");
  await expect(devices).not.toContainText("Enter your password above to approve.");
});

test("revoke stays disabled until the custodian creates its fleet key", async ({ page: a }) => {
  const server = fakeTeamServer([{ device_id: "c1".repeat(16), label: "Verifier Active", status: "active", granted: false }]);
  await teamDevicePage(a, "a", server);
  const row = await listDevices(a, "Verifier Active");
  await cardSignIn(a);
  await expect(a.getByRole("button", { name: "Create fleet key", exact: true })).toBeVisible();
  await expect(row.getByRole("button", { name: "Revoke", exact: true })).toBeDisabled();
});

test("refreshed keys require a fresh join-code comparison", async ({ page: a }) => {
  const server = fakeTeamServer([{ device_id: "c1".repeat(16), label: "Verifier Pending", status: "pending", granted: false }]);
  await teamDevicePage(a, "a", server);
  await cardClick(a, "Create fleet key");
  const row = await listDevices(a, "Verifier Pending");
  await row.getByLabel("The code on the other device matches").check();
  await a.evaluate(() => {
    const ipc = (window as unknown as { __TAURI_INTERNALS__: { invoke: (...args: unknown[]) => Promise<unknown> } }).__TAURI_INTERNALS__;
    const original = ipc.invoke.bind(ipc);
    ipc.invoke = async (...args) => {
      const result = await original(...args);
      if (args[0] === "team_devices") {
        return (result as Record<string, unknown>[]).map((r) => r.label === "Verifier Pending"
          ? { ...r, signing_key_id: "d2".repeat(32), hpke_key_id: "e3".repeat(32), sas: "1234 5678 90ab cdef 1234 5678 90ab cdef" }
          : r);
      }
      return result;
    };
  });
  await listDevices(a, "Verifier Pending");
  await cardSignIn(a);
  await expect(row.getByTestId("team-device-sas")).toHaveText("1234 5678 90ab cdef 1234 5678 90ab cdef");
  await expect(row.getByLabel("The code on the other device matches")).not.toBeChecked();
  await expect(row.getByRole("button", { name: "Approve", exact: true })).toBeDisabled();
});

// Recovery (plan v0.2.2b, S5): import, export, Reset, and the expired join code of G11.
const OLD_DEVICE_LOST = "The old root custodian device is lost or its keys were reset";
/** B as the `team-keys-lost` and `team-key-store-unavailable` mocks enroll it: active and joined. */
const LOST_B: TeamDeviceRow = { device_id: "b0".repeat(16), label: "Lost B", status: "active", granted: true };

test("a fresh device imports a recovery bundle and becomes root custodian", async ({ page: c }) => {
  const server = fakeTeamServer([{ device_id: "d4".repeat(16), label: "Machine D", status: "pending", granted: false }]);
  const card = await teamDevicePage(c, "b", server);
  const form = card.getByTestId("team-import");
  await form.getByLabel("Recovery passphrase", { exact: true }).fill("correct horse");
  await form.getByLabel(OLD_DEVICE_LOST).check();
  await cardClick(c, "Import recovery bundle");
  await expect(c.getByText("The recovery bundle was imported.")).toBeVisible();
  await expect(c.locator("html")).toHaveAttribute("data-e2e-import-path", "C:\\Users\\Example\\a.shxrecovery");
  await expect(card.getByTestId("team-import")).toHaveCount(0);
  await expect(card.getByText("Bootstrap anchor")).toBeVisible();
  const row = await listDevices(c, "Machine D");
  await row.getByLabel("The code on the other device matches").check();
  await cardSignIn(c);
  await expect(row.getByRole("button", { name: "Approve", exact: true })).toBeEnabled();
});

test("the import needs the old device lost tick", async ({ page }) => {
  const card = await teamDevicePage(page, "b", fakeTeamServer());
  const form = card.getByTestId("team-import");
  const button = form.getByRole("button", { name: "Import recovery bundle" });
  await cardSignIn(page);
  await form.getByLabel("Recovery passphrase", { exact: true }).fill("correct horse");
  await expect(button).toBeDisabled();
  await form.getByLabel(OLD_DEVICE_LOST).check();
  await expect(button).toBeEnabled();
  // This checks the mock only; the launcher's own refusal is unit-tested in recovery_import.rs.
  const refused = await page.evaluate(async () => {
    const ipc = (window as unknown as { __TAURI_INTERNALS__: { invoke: (cmd: string, args: object) => Promise<unknown> } }).__TAURI_INTERNALS__;
    try {
      await ipc.invoke("team_import_recovery_bundle", {
        path: "C:\\Users\\Example\\a.shxrecovery", passphrase: "correct horse", username: "owner", password: "pw", oldDeviceLost: false,
      });
      return false;
    } catch (e) { return String(e).includes("recovery.confirmOldDeviceLost"); }
  });
  expect(refused).toBe(true);
  await expect(card.getByTestId("team-import")).toBeVisible();
});

test("an import whose collect is refused another fleet key says so", async ({ page: c }) => {
  const card = await teamDevicePage(c, "b", fakeTeamServer());
  // As the follow-up collect finding another key than this device holds for that generation.
  await c.evaluate(() => {
    const ipc = (window as unknown as { __TAURI_INTERNALS__: { invoke: (...args: unknown[]) => Promise<unknown> } }).__TAURI_INTERNALS__;
    const original = ipc.invoke.bind(ipc);
    ipc.invoke = async (...args) => {
      const result = await original(...args);
      return args[0] === "team_import_recovery_bundle"
        ? { ...(result as object), fleet_opened: 0, newest_fleet_generation: null, fleet_refusal: "KEY_SUBSTITUTION_DETECTED" }
        : result;
    };
  });
  const form = card.getByTestId("team-import");
  await form.getByLabel("Recovery passphrase", { exact: true }).fill("correct horse");
  await form.getByLabel(OLD_DEVICE_LOST).check();
  await cardClick(c, "Import recovery bundle");
  await expect(c.getByText("The recovery bundle was imported.")).toBeVisible();
  await expect(c.getByText("Refused: the team server offered another fleet key")).toBeVisible();
  await expect(c.getByText("Fleet key collected")).toHaveCount(0);
});

test("an import with rejected fleet evidence reports failure rather than waiting", async ({ page }) => {
  const card = await teamDevicePage(page, "b", fakeTeamServer());
  await page.evaluate(() => {
    const ipc = (window as unknown as { __TAURI_INTERNALS__: { invoke: (...args: unknown[]) => Promise<unknown> } }).__TAURI_INTERNALS__;
    const original = ipc.invoke.bind(ipc);
    ipc.invoke = async (...args) => {
      const result = await original(...args);
      // Exact report shape of custody_report(..., FleetGrant::Failed).
      return args[0] === "team_import_recovery_bundle"
        ? { ...(result as object), fleet_opened: 0, fleet_failed: 1, newest_fleet_generation: null,
            fleet_grants_waiting: 1, fleet_refusal: null }
        : result;
    };
  });
  const form = card.getByTestId("team-import");
  await form.getByLabel("Recovery passphrase", { exact: true }).fill("correct horse");
  await form.getByLabel(OLD_DEVICE_LOST).check();
  await cardClick(page, "Import recovery bundle");
  await expect(page.getByText("The recovery bundle was imported.")).toBeVisible();
  await expect(page.getByText("A fleet key grant is waiting but was not kept.", { exact: false })).toHaveCount(0);
  await expect(page.getByText("The fleet key grant for this device failed its check: it did not verify or open, or its evidence could not be fetched, so nothing was kept. Collect key custody again; if it fails again, ask a custodian to grant the fleet key again.")).toBeVisible();
});

test("the root custodian exports a recovery bundle, and Export is off before the fleet key exists", async ({ page: a }) => {
  await teamDevicePage(a, "a", fakeTeamServer());
  const out = a.getByTestId("team-export");
  await expect(out).toContainText("A recovery bundle exported before 2.8.0 cannot restore the team");
  const button = out.getByRole("button", { name: "Export recovery bundle" });
  await cardSignIn(a);
  await out.getByLabel("Recovery passphrase", { exact: true }).fill("correct horse");
  await out.getByLabel("Recovery passphrase again").fill("correct horse");
  await expect(button).toBeDisabled();
  await expect(out).toContainText("Create the fleet key above before exporting the recovery bundle.");
  await cardClick(a, "Create fleet key");
  await expect(out).not.toContainText("Create the fleet key above");
  await cardSignIn(a);
  await out.getByLabel("I recorded this root key fingerprint").check();
  await button.click();
  await expect(a.getByText("Recovery bundle exported to C:\\Users\\Example\\shardx-recovery.shxrecovery.")).toBeVisible();
  await expect(a.locator("html")).toHaveAttribute("data-e2e-export-path", "C:\\Users\\Example\\shardx-recovery.shxrecovery");
});

test("export waits for the owner's recovery fingerprint confirmation", async ({ page }) => {
  await teamDevicePage(page, "a", fakeTeamServer());
  await cardClick(page, "Create fleet key");
  const form = page.getByTestId("team-export");
  await cardSignIn(page);
  await form.getByLabel("Recovery passphrase", { exact: true }).fill("correct horse");
  await form.getByLabel("Recovery passphrase again").fill("correct horse");
  // Journey E requires owner fingerprint confirmation in addition to the
  // passphrase confirmation: the root key ID is shown, and Export stays off
  // until the owner ticks that it was recorded.
  await expect(form.getByText("Root key fingerprint (root key ID)")).toBeVisible();
  await expect(form.locator("input[readonly]")).toHaveValue("5e".repeat(32));
  const button = form.getByRole("button", { name: "Export recovery bundle" });
  await expect(button).toBeDisabled();
  await button.click({ force: true });
  await expect(page.getByText("Recovery bundle exported to C:\\Users\\Example\\shardx-recovery.shxrecovery.")).toHaveCount(0);
  await expect(page.locator("html")).not.toHaveAttribute("data-e2e-export-path", /./);
  await form.getByLabel("I recorded this root key fingerprint").check();
  await button.click();
  await expect(page.getByText("Recovery bundle exported to C:\\Users\\Example\\shardx-recovery.shxrecovery.")).toBeVisible();
});

test("export says why it is off when the root key fingerprint does not read", async ({ page }) => {
  await teamDevicePage(page, "a", fakeTeamServer());
  await page.evaluate(() => {
    const ipc = (window as unknown as { __TAURI_INTERNALS__: { invoke: (...args: unknown[]) => Promise<unknown> } }).__TAURI_INTERNALS__;
    const original = ipc.invoke.bind(ipc);
    ipc.invoke = async (...args) => {
      const result = await original(...args);
      return args[0] === "team_custody_bootstrap_status" ? { ...(result as object), root_key_id: "" } : result;
    };
  });
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await page.getByRole("button", { name: "Team", exact: true }).click();
  await cardClick(page, "Create fleet key");
  const form = page.getByTestId("team-export");
  await cardSignIn(page);
  await form.getByLabel("Recovery passphrase", { exact: true }).fill("correct horse");
  await form.getByLabel("Recovery passphrase again").fill("correct horse");
  await expect(form.getByTestId("team-export-no-root-key-id")).toHaveText(
    "Export is off: the root key fingerprint could not be read from this device's saved root custody setup.",
  );
  await expect(form.getByLabel("I recorded this root key fingerprint")).toHaveCount(0);
  await expect(form.getByRole("button", { name: "Export recovery bundle" })).toBeDisabled();
});

test("a member whose keys are lost is reset after a custodian revokes it, then enrolls again", async ({
  page: a, browser, baseURL, viewport,
}) => {
  const server = fakeTeamServer([LOST_B]);
  const b = await (await browser.newContext({ baseURL, viewport })).newPage();
  try {
    await teamDevicePage(a, "a", server);
    const cardB = await teamDevicePage(b, "keys-lost", server);
    await expect(cardB.getByTestId("team-keys-lost")).toContainText("Ask a custodian to revoke this device, then reset it.");
    await cardClick(a, "Create fleet key");
    const row = await listDevices(a, "Lost B");
    await cardSignIn(a);
    await row.getByRole("combobox", { name: "Reason" }).click();
    await a.getByRole("option", { name: "Lost" }).click();
    await row.getByRole("button", { name: "Revoke" }).click();
    await a.getByRole("dialog").getByRole("button", { name: "Revoke" }).click();
    await expect(row).toContainText("Revoked");

    await cardClick(b, "Reset this device");
    await expect(b.getByText("This device's identity was cleared.")).toBeVisible();
    await expect(cardB.getByTestId("team-keys-lost")).toHaveCount(0);
    await teamEnroll(b, "Machine B");
    expect(server.devices.map((d) => `${d.label}:${d.status}`)).toEqual(["Machine A:active", "Lost B:revoked", "Machine B:pending"]);
  } finally { await b.context().close(); }
});

test("a member whose keys are lost and is still active is told to ask for revocation, and Reset is refused", async ({ page }) => {
  const server = fakeTeamServer([LOST_B]);
  const card = await teamDevicePage(page, "keys-lost", server);
  const lost = card.getByTestId("team-keys-lost");
  await expect(lost).toContainText("This device's keys are lost. Ask a custodian to revoke this device, then reset it.");
  await expect(card.getByTestId("team-join")).toHaveCount(0);
  await expect(card.getByTestId("team-import")).toHaveCount(0);
  await cardClick(page, "Reset this device");
  await expect(page.getByText(
    "This device cannot enroll again: it is the root custodian, has joined the team, or the team server does not list it as waiting, approved or revoked",
  )).toBeVisible();
  await expect(lost).toBeVisible();
  expect(server.devices.find((d) => d.label === "Lost B")?.status).toBe("active");
});

test("a member whose key store is unavailable sees the try again notice, not keys lost", async ({ page }) => {
  const card = await teamDevicePage(page, "key-store-unavailable", fakeTeamServer([LOST_B]));
  const notice = card.getByTestId("team-keys-lost");
  await expect(notice).toContainText("The key store did not answer; try again before resetting this device.");
  await expect(notice).not.toContainText("keys are lost");
  await expect(notice.getByRole("button", { name: "Reset this device" })).toBeVisible();
});

test("a root custodian whose keys are lost is offered import, not Reset", async ({ page: a }) => {
  const card = await teamDevicePage(a, "root-keys-lost", fakeTeamServer());
  const lost = card.getByTestId("team-keys-lost");
  await expect(lost).toContainText("import your recovery bundle to restore it");
  await expect(card.getByRole("button", { name: "Reset this device" })).toHaveCount(0);
  await expect(card.getByTestId("team-devices")).toHaveCount(0);
  await lost.getByLabel("Recovery passphrase", { exact: true }).fill("correct horse");
  await lost.getByLabel(OLD_DEVICE_LOST).check();
  await cardClick(a, "Import recovery bundle");
  await expect(card.getByTestId("team-keys-lost")).toHaveCount(0);
  await expect(card.getByTestId("team-devices")).toBeVisible();
});

test("an unreadable root state never offers Reset", async ({ page }) => {
  const card = await teamDevicePage(page, "root-keys-lost", fakeTeamServer());
  await expect(card.getByRole("button", { name: "Reset this device" })).toHaveCount(0);
  await page.evaluate(() => {
    const ipc = (window as unknown as { __TAURI_INTERNALS__: { invoke: (...args: unknown[]) => Promise<unknown> } }).__TAURI_INTERNALS__;
    const original = ipc.invoke.bind(ipc);
    ipc.invoke = async (...args) => {
      if (args[0] === "team_custody_bootstrap_status") {
        throw new Error("[[shardx:fleet.custodyStateCorrupt]]");
      }
      return original(...args);
    };
  });
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await page.getByRole("button", { name: "Team", exact: true }).click();
  await expect(card.getByTestId("team-keys-lost")).toBeVisible();
  await expect(card.getByTestId("team-root-state-unreadable")).toBeVisible();
  await expect(card.getByRole("button", { name: "Reset this device" })).toHaveCount(0);
});

test("an interrupted root setup with lost keys never offers Reset", async ({ page }) => {
  const card = await teamDevicePage(page, "root-keys-lost", fakeTeamServer());
  await page.evaluate(() => {
    const ipc = (window as unknown as { __TAURI_INTERNALS__: { invoke: (...args: unknown[]) => Promise<unknown> } }).__TAURI_INTERNALS__;
    const original = ipc.invoke.bind(ipc);
    ipc.invoke = async (...args) => {
      const result = await original(...args);
      if (args[0] === "team_custody_bootstrap_status") {
        return { ...(result as Record<string, unknown>), started: true, activated: false };
      }
      return result;
    };
  });
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await page.getByRole("button", { name: "Team", exact: true }).click();
  await expect(card.getByTestId("team-keys-lost")).toBeVisible();
  await expect(card.getByRole("button", { name: "Reset this device" })).toHaveCount(0);
  // Import refuses a root state that saved no anchor, so none is offered either.
  await expect(card.getByTestId("team-keys-lost")).toContainText("started setting up the team's root key");
  await expect(card.getByTestId("team-import")).toHaveCount(0);
});

test("a root custodian whose key store is unavailable is told to try again, with no Reset or sign-in", async ({ page: a }) => {
  const card = await teamDevicePage(a, "root-key-store-unavailable", fakeTeamServer());
  const notice = card.getByTestId("team-keys-lost");
  await expect(notice).toContainText("The key store did not answer; try again. This device is the root custodian and cannot be reset.");
  await expect(notice.getByLabel("Account username")).toHaveCount(0);
  await expect(notice.getByRole("button")).toHaveCount(0);
  await expect(card.getByTestId("team-import")).toHaveCount(0);
});

test("a lost-key device offers no Reset or sign-in while its root state is still loading", async ({ page }) => {
  const card = await teamDevicePage(page, "root-keys-lost", fakeTeamServer());
  await page.evaluate(() => {
    const w = window as unknown as {
      __TAURI_INTERNALS__: { invoke: (...args: unknown[]) => Promise<unknown> }; e2eReleaseBoot: () => void;
    };
    const ipc = w.__TAURI_INTERNALS__;
    const original = ipc.invoke.bind(ipc);
    const held = new Promise<void>((resolve) => { w.e2eReleaseBoot = resolve; });
    ipc.invoke = async (...args) => {
      if (args[0] === "team_custody_bootstrap_status") await held;
      return original(...args);
    };
  });
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await page.getByRole("button", { name: "Team", exact: true }).click();
  const lost = card.getByTestId("team-keys-lost");
  await expect(lost).toBeAttached();
  await expect(card.getByRole("button", { name: "Reset this device" })).toHaveCount(0);
  await expect(lost.getByLabel("Account username")).toHaveCount(0);
  await page.evaluate(() => (window as unknown as { e2eReleaseBoot: () => void }).e2eReleaseBoot());
  await expect(lost).toContainText("import your recovery bundle to restore it");
  await expect(card.getByRole("button", { name: "Reset this device" })).toHaveCount(0);
});

test("an unfinished root setup whose key store is unavailable does not claim to be the root custodian", async ({ page }) => {
  const card = await teamDevicePage(page, "root-key-store-unavailable", fakeTeamServer());
  await page.evaluate(() => {
    const ipc = (window as unknown as { __TAURI_INTERNALS__: { invoke: (...args: unknown[]) => Promise<unknown> } }).__TAURI_INTERNALS__;
    const original = ipc.invoke.bind(ipc);
    ipc.invoke = async (...args) => {
      const result = await original(...args);
      if (args[0] === "team_custody_bootstrap_status") {
        return { ...(result as Record<string, unknown>), started: true, activated: false };
      }
      return result;
    };
  });
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await page.getByRole("button", { name: "Team", exact: true }).click();
  const notice = card.getByTestId("team-keys-lost");
  await expect(notice).toContainText(
    "The key store did not answer; try again. This device started setting up the team's root key without finishing",
  );
  await expect(notice).not.toContainText("This device is the root custodian");
  await expect(notice.getByRole("button")).toHaveCount(0);
});

test("an expired join code of a device with an unfinished root setup offers no Enroll again", async ({ page: a }) => {
  const server = fakeTeamServer();
  // The server lists A pending, where an ordinary device could enroll again.
  Object.assign(server.devices[0], { status: "pending" });
  const card = await teamDevicePage(a, "a", server);
  await a.evaluate(() => {
    const ipc = (window as unknown as { __TAURI_INTERNALS__: { invoke: (...args: unknown[]) => Promise<unknown> } }).__TAURI_INTERNALS__;
    const original = ipc.invoke.bind(ipc);
    ipc.invoke = async (...args) => {
      const result = await original(...args);
      if (args[0] === "team_custody_bootstrap_status") {
        return { ...(result as Record<string, unknown>), started: true, activated: false, anchor: "", root_key_id: "" };
      }
      return result;
    };
  });
  await a.getByRole("button", { name: "Settings", exact: true }).click();
  await a.getByRole("button", { name: "Team", exact: true }).click();
  const join = card.getByTestId("team-join");
  await expect(join).toBeVisible();
  await cardClick(a, "Show join code");
  await expect(join).toContainText("This join code has expired.");
  await expect(join).toContainText("it is the root custodian");
  await expect(card.getByRole("button", { name: "Enroll again" })).toHaveCount(0);
});

test("another device's finished root state selects no root actions for a readable member", async ({
  page: a, browser, baseURL, viewport,
}) => {
  test.slow();
  const server = fakeTeamServer();
  const b = await (await browser.newContext({ baseURL, viewport })).newPage();
  await teamDevicePage(a, "a", server);
  // A connection change after both old root keys were lost kept that root's journal; B enrolls on these roots.
  const card = await teamDevicePage(b, "b", server, false, "&teamRootJournal=foreign");
  // B shows and confirms its own join code and collects as any member.
  await admitB(a, b);
  await expect(card.getByText("Bootstrap anchor")).toHaveCount(0);
  await expect(card.getByTestId("team-devices")).toHaveCount(0);
  await expect(card.getByRole("button", { name: "Show devices" })).toHaveCount(0);
  await expect(card.getByTestId("team-export")).toHaveCount(0);
});

test("another device's unfinished root setup offers no Resume to a member", async ({ page }) => {
  const server = fakeTeamServer();
  const card = await teamDevicePage(page, "b", server, false, "&teamRootJournal=foreign-unfinished");
  await teamEnroll(page, "Machine B");
  await expect(card.getByTestId("custody-bootstrap")).toHaveCount(0);
  await expect(card.getByRole("button", { name: "Resume custody setup" })).toHaveCount(0);
  await cardClick(page, "Show join code");
  await expect(card.getByTestId("team-join-sas")).toBeVisible();
});

test("an expired join code of a revoked device offers Enroll again", async ({ page: b }) => {
  const server = fakeTeamServer();
  const card = await teamDevicePage(b, "b", server, true);
  await teamEnroll(b, "Machine B");
  await cardClick(b, "Show join code");
  await expect(b.getByTestId("team-join-sas")).toBeVisible();
  Object.assign(server.devices.find((d) => d.label === "Machine B")!, { status: "revoked" });
  await b.clock.fastForward("10:01");
  await cardClick(b, "Show join code");
  await expect(card.getByTestId("team-join")).toContainText("This join code has expired.");
  await cardClick(b, "Enroll again");
  await expect(card.getByRole("button", { name: "Enroll this device" })).toBeVisible();
});

test("an expired join code of a device the server no longer lists shows why and no Enroll again", async ({ page: b }) => {
  const server = fakeTeamServer();
  const card = await teamDevicePage(b, "b", server, true);
  await teamEnroll(b, "Machine B");
  await cardClick(b, "Show join code");
  await expect(b.getByTestId("team-join-sas")).toBeVisible();
  server.devices.splice(server.devices.findIndex((d) => d.label === "Machine B"), 1);
  await b.clock.fastForward("10:01");
  await cardClick(b, "Show join code");
  const join = card.getByTestId("team-join");
  await expect(join).toContainText("This join code has expired.");
  await expect(join).toContainText("the team server does not list it as waiting, approved or revoked");
  await expect(card.getByRole("button", { name: "Enroll again" })).toHaveCount(0);
});

test("connecting needs no token", async ({ page }) => {
  await gotoMocked(page);
  await page.getByRole("button", { name: "Team", exact: true }).click();
  const card = page.getByTestId("team-card");
  await expect(card.getByLabel("API token (optional, only for legacy passphrase sync)")).toHaveValue("");
  await card.getByLabel("Server URL").fill("https://team.example.com");
  await card.getByLabel("Tenant ID").fill("22222222222222222222222222222222");
  await card.getByRole("button", { name: "Save connection" }).click();
  await expect(page.getByText("Connection saved")).toBeVisible();
  await expect(card).not.toContainText("Save a server URL and tenant ID first.");

  await cardSignIn(page);
  await expect(card.getByRole("button", { name: "Enroll this device" })).toBeEnabled();
  await card.getByRole("button", { name: "Test connection" }).click();
  await expect(page.getByText(`Server identity: ${"5e".repeat(16)}`)).toBeVisible();
});

test("the first device sets up root custody once its passphrases agree", async ({ page }) => {
  await gotoMocked(page, "/?e2e=team-first-device");
  await page.getByRole("button", { name: "Team", exact: true }).click();

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

test("a fleet key Q-18 blocks is reported instead of the join steps", async ({ page }) => {
  await gotoMocked(page, "/?e2e=team-key-blocked");
  await page.getByRole("button", { name: "Team", exact: true }).click();
  await expect(page.getByTestId("team-key-blocked")).toContainText("pushing under it is blocked");
  await expect(page.getByTestId("team-join")).toHaveCount(0);
});

test("an interrupted custody setup resumes at its saved bundle without asking for a path", async ({ page }) => {
  await gotoMocked(page, "/?e2e=team-first-device-resume");
  await page.getByRole("button", { name: "Team", exact: true }).click();
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
  await page.getByRole("button", { name: "Team", exact: true }).click();

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
  await page.getByRole("button", { name: "Team", exact: true }).click();

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
