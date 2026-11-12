import { expect, test, type Page } from "@playwright/test";

// Bookmarks: row boxes and a header Select all pick what the page shows; the
// bar's Delete asks once, deletes them all, and Undo saves every one back.
async function openBookmarks(page: Page) {
  await page.goto("/?e2e=bookmarks", { waitUntil: "domcontentloaded" });
  await page.getByRole("button", { name: "Bookmarks" }).click();
  await expect(page.getByRole("heading", { name: "Bookmarks" })).toBeVisible();
}

const selectAll = (page: Page) => page.getByRole("checkbox", { name: "Select all bookmarks" });
const bar = (page: Page) => page.getByText(/^\d+ selected$/);
const stat = (page: Page, key: string) => page.locator("html").getAttribute(`data-e2e-${key}`);

test("Select all picks only the bookmarks the folder tab shows, and Delete takes only those", async ({ page }) => {
  await openBookmarks(page);
  await page.getByRole("button", { name: "QA", exact: true }).click();
  await selectAll(page).check();
  await expect(bar(page)).toHaveText("2 selected");

  // The bar sits above the list, so its Delete is the first one in the page.
  await page.getByRole("button", { name: "Delete", exact: true }).first().click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toContainText("Delete 2 selected bookmarks?");
  await dialog.getByRole("button", { name: "Delete", exact: true }).click();
  await expect(page.getByText("Nothing in this folder")).toBeVisible();
  expect(await stat(page, "bookmark-deletes")).toBe("2");

  // The two outside the tab are untouched.
  await page.getByRole("button", { name: "All", exact: true }).click();
  await expect(page.getByText("Ads Manager")).toBeVisible();
  await expect(page.getByText("Docs", { exact: true })).toBeVisible();
  await expect(page.getByText("Shop one")).toHaveCount(0);
});

test("Undo brings every deleted bookmark back", async ({ page }) => {
  await openBookmarks(page);
  await selectAll(page).check();
  await expect(bar(page)).toHaveText("4 selected");
  await page.getByRole("button", { name: "Delete", exact: true }).first().click();
  await page.getByRole("dialog").getByRole("button", { name: "Delete", exact: true }).click();
  await expect(page.getByRole("heading", { name: "No bookmarks yet" })).toBeVisible();
  await expect(page.getByText("Deleted 4 bookmarks")).toBeVisible();

  await page.getByRole("button", { name: "Undo" }).click();
  await expect(page.getByText("Shop two")).toBeVisible();
  await expect(page.getByText("Ads Manager")).toBeVisible();
  await expect(page.getByText("Docs", { exact: true })).toBeVisible();
  await expect(page.getByText("Shop one")).toBeVisible();
  expect(await stat(page, "bookmark-saves")).toBe("4");
  // The restored rows come back unselected, so a second Delete cannot take them again.
  await expect(bar(page)).toHaveCount(0);
});

test("a row box picks one bookmark and Clear drops the picks", async ({ page }) => {
  await openBookmarks(page);
  await page.getByRole("checkbox", { name: "Select Docs" }).check();
  await expect(bar(page)).toHaveText("1 selected");
  await expect(selectAll(page)).toBeVisible();
  await page.getByRole("button", { name: "Clear" }).click();
  await expect(bar(page)).toHaveCount(0);
});
