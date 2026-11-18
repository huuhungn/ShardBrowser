import { expect, test, type Page } from "@playwright/test";

// With the OS "reduce motion" setting, slides, fades and transitions finish at
// once; spinners keep turning so work in progress never looks frozen.
async function timings(page: Page, reducedMotion: "reduce" | "no-preference") {
  await page.emulateMedia({ reducedMotion });
  await page.goto("/", { waitUntil: "domcontentloaded" });
  return page.evaluate(() => {
    // Classes the app itself uses: the proxy popover, kit transitions, the kit spinner.
    const host = document.createElement("div");
    host.innerHTML =
      '<div class="animate-[fadeUp_0.12s_ease-out]"></div><div class="transition"></div><div class="animate-spin"></div>';
    document.body.append(host);
    const [fade, transition, spin] = [...host.children].map((el) => getComputedStyle(el));
    const seconds = (v: string) => parseFloat(v);
    return {
      fade: seconds(fade.animationDuration),
      transition: seconds(transition.transitionDuration),
      spin: seconds(spin.animationDuration),
      spinCount: spin.animationIterationCount,
    };
  });
}

test("reduced motion makes animations and transitions instant but keeps spinners turning", async ({ page }) => {
  const t = await timings(page, "reduce");
  expect(t.fade).toBeLessThan(0.001);
  expect(t.transition).toBeLessThan(0.001);
  expect(t.spin).toBeGreaterThan(0.5);
  expect(t.spinCount).toBe("infinite");
});

test("without the setting the animations keep their timing", async ({ page }) => {
  const t = await timings(page, "no-preference");
  expect(t.fade).toBeCloseTo(0.12);
  expect(t.transition).toBeGreaterThan(0.1);
  expect(t.spin).toBeCloseTo(1);
  expect(t.spinCount).toBe("infinite");
});
