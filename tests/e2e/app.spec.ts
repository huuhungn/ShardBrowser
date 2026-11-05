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

type TeamHead = { version: number; label: string | null; holder: string | null; revoked: boolean };
type TeamDeviceRow = { device_id: string; label: string; status: "pending" | "active" | "revoked"; granted: boolean };

/**
 * The one team server both devices of the journey talk to, through the
 * `e2eTeamServer` binding the `team-device-*` mocks call. Each op answers with
 * the head a device would accept; a head signed by a key later proven revoked
 * quarantines whoever pulls it until a revert seals a valid one over it.
 *
 * It also lists the tenant's devices: A, the active root custodian, plus any
 * in `more`. Enrolling files a pending row; approving one grants it the fleet
 * key once A created it, and revoking one refuses its sessions from then on.
 */
function fakeTeamServer(more: TeamDeviceRow[] = []) {
  const heads = new Map<string, TeamHead>();
  const devices: TeamDeviceRow[] = [{ device_id: "aa".repeat(16), label: "Machine A", status: "active", granted: false }, ...more];
  let fleetKey = false;
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
      quarantine: h.revoked ? "SIGNER_REVOKED" : null, revert_available: h.revoked,
    };
  };
  type Args = {
    label?: string | null; remote_profile_id?: string; pin?: number | null; device_id?: string; target?: string;
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
      return devices.map(({ device_id: id, label, status }) => ({ device_id: id, label, status }));
    },
    fleetKey: (_device, { device_id }) => {
      live(device_id).granted = true;
      fleetKey = true;
      return null;
    },
    approve: (_device, { device_id, target }) => {
      live(device_id);
      const d = row(target);
      if (d?.status !== "pending") throw new Error("[[shardx:fleet.deviceNotPending]]");
      Object.assign(d, { status: "active", granted: fleetKey });
      return null;
    },
    revoke: (_device, { device_id, target }) => {
      live(device_id);
      Object.assign(row(target) ?? {}, { status: "revoked", granted: false });
      return null;
    },
    collect: (_device, { device_id }) => ({ granted: live(device_id).granted }),
    list: () => [...heads.keys()].map(reply),
    publish: (device, { label }) => {
      const id = `d${heads.size + 1}`.repeat(16);
      heads.set(id, { version: 0, label: label ?? null, holder: device, revoked: false });
      return reply(id);
    },
    pull: (_device, { remote_profile_id }) => reply(String(remote_profile_id)),
    // Check-in is the checkout inside push: it takes the lease when free and releases it.
    push: (device, { remote_profile_id, pin }) => {
      const h = head(String(remote_profile_id));
      if (h.holder && h.holder !== device) throw new Error(`lease held by device ${h.holder}`);
      if (h.revoked || pin !== h.version) throw new Error("[[shardx:sync.remoteAhead]]");
      Object.assign(h, { version: h.version + 1, holder: null });
      return reply(String(remote_profile_id));
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

/** Open team device `device`'s Team page against `server`, its clock faked when `clock` is set. */
async function teamDevicePage(page: Page, device: "a" | "b", server: ReturnType<typeof fakeTeamServer>, clock = false) {
  if (clock) await page.clock.install();
  await page.exposeFunction("e2eTeamServer", server.call);
  await gotoMocked(page, `/?e2e=team-device-${device}`);
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
    await expect(a.getByTestId("team-devices")).toContainText("The recovery bundle does not include the fleet key yet.");
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
    return rowB;
  });

  await test.step("Approve stays disabled until the codes are confirmed to match", async () => {
    const approve = row.getByRole("button", { name: "Approve" });
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
  await old.getByRole("button", { name: "Approve" }).click();
  await expect(old).toContainText("Active");

  await b.clock.fastForward("10:01");
  await expect(cardB.getByTestId("team-join")).toContainText("This join code has expired.");
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

test("a custodian with no usable key is not shown Fleet key ready", async ({ page: a }) => {
  const server = fakeTeamServer();
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
});

test("the custodian cannot approve a row it first saw more than ten minutes ago", async ({ page: a, browser, baseURL, viewport }) => {
  const server = fakeTeamServer();
  const b = await (await browser.newContext({ baseURL, viewport })).newPage();
  await teamDevicePage(a, "a", server, true);
  await teamDevicePage(b, "b", server);
  await cardClick(a, "Create fleet key");
  await teamEnroll(b, "Machine B");

  const row = await listDevices(a, "Machine B");
  const approve = row.getByRole("button", { name: "Approve" });
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

test("the reason list offers only Retired and Lost", async ({ page: a }) => {
  const server = fakeTeamServer([{ device_id: "c1".repeat(16), label: "Machine C", status: "active", granted: false }]);
  await teamDevicePage(a, "a", server);
  const row = await listDevices(a, "Machine C");
  await expect(a.getByTestId("team-device").filter({ hasText: "Machine A" }).getByRole("combobox")).toHaveCount(0);
  const reason = row.getByRole("combobox", { name: "Reason" });
  await expect(reason).toContainText("Retired");
  await reason.click();
  await expect(a.getByRole("option")).toHaveText(["Retired", "Lost"]);
  await a.getByRole("option", { name: "Lost" }).click();
  await expect(reason).toContainText("Lost");
});

test("approval stays disabled until the custodian creates its fleet key", async ({ page: a }) => {
  const server = fakeTeamServer([{ device_id: "c1".repeat(16), label: "Verifier Pending", status: "pending", granted: false }]);
  await teamDevicePage(a, "a", server);
  const row = await listDevices(a, "Verifier Pending");
  await row.getByLabel("The code on the other device matches").check();
  await cardSignIn(a);
  await expect(a.getByRole("button", { name: "Create fleet key", exact: true })).toBeVisible();
  await expect(row.getByRole("button", { name: "Approve", exact: true })).toBeDisabled();
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
