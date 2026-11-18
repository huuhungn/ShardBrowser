// WCAG AA (4.5:1 for normal text) for the text tokens that used to fall short:
// the soft text token in both themes, and primary-coloured text in the dark
// theme, including the primary-tinted chips it sits on.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import test from "node:test";

const css = readFileSync(new URL("../ui-kit/src/styles/tokens.css", import.meta.url), "utf8");
const AA = 4.5;

// Custom properties declared in every top-level block with exactly this selector.
function block(selector) {
  const vars = {};
  const re = /(?:^|\n)([^\n{}]+?)\s*\{([^{}]*)\}/g;
  for (const [, sel, body] of css.matchAll(re)) {
    if (sel.trim() !== selector) continue;
    for (const [, name, value] of body.matchAll(/(--[\w-]+)\s*:\s*([^;]+);/g)) vars[name] = value.trim();
  }
  return vars;
}

const light = block(":root");
const dark = { ...light, ...block('[data-theme="dark"]') };
const theme = Object.fromEntries([...css.matchAll(/(--color-[\w-]+|--text-color-[\w-]+)\s*:\s*([^;]+);/g)].map((m) => [m[1], m[2].trim()]));

function rgba(hex) {
  const h = hex.replace("#", "");
  assert.match(h, /^[0-9a-f]{6}([0-9a-f]{2})?$/i, `not a hex colour: ${hex}`);
  const [r, g, b] = [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16));
  return { r, g, b, a: h.length === 8 ? parseInt(h.slice(6), 16) / 255 : 1 };
}

function over(top, bottom) {
  const t = rgba(top);
  const b = rgba(bottom);
  const mix = (x, y) => Math.round(t.a * x + (1 - t.a) * y).toString(16).padStart(2, "0");
  return `#${mix(t.r, b.r)}${mix(t.g, b.g)}${mix(t.b, b.b)}`;
}

function luminance(hex) {
  const { r, g, b } = rgba(hex);
  const lin = (c) => ((c /= 255) <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
}

function ratio(a, b) {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

function expectAA(fg, bg, label) {
  const r = ratio(fg, bg);
  assert.ok(r >= AA, `${label}: ${fg} on ${bg} is ${r.toFixed(2)}:1, below ${AA}:1`);
}

test("the WCAG ratio matches known reference pairs", () => {
  assert.equal(ratio("#000000", "#ffffff").toFixed(2), "21.00");
  assert.equal(ratio("#777777", "#ffffff").toFixed(2), "4.48");
  assert.equal(over("#535efd1a", "#171717"), "#1d1e2e");
});

for (const [name, vars] of [["light", light], ["dark", dark]]) {
  test(`${name}: soft text reaches AA on the page surfaces and stays softer than sub text`, () => {
    for (const bg of ["--bg-white-0", "--bg-weak-50"]) {
      expectAA(vars["--text-soft-400"], vars[bg], `${name} --text-soft-400 on ${bg}`);
      assert.ok(
        ratio(vars["--text-soft-400"], vars[bg]) < ratio(vars["--text-sub-600"], vars[bg]),
        `${name}: --text-soft-400 must stay softer than --text-sub-600 on ${bg}`,
      );
    }
  });
}

test("dark: primary-coloured text reaches AA on dark surfaces and primary-tinted chips", () => {
  const text = dark["--text-primary"];
  for (const bg of ["--bg-white-0", "--bg-weak-50", "--bg-soft-200"]) {
    expectAA(text, dark[bg], `dark --text-primary on ${bg}`);
    for (const tint of ["--color-primary-alpha-10", "--color-primary-alpha-16"]) {
      expectAA(text, over(theme[tint], dark[bg]), `dark --text-primary on ${tint} over ${bg}`);
    }
  }
});

test("text utilities read the theme-aware tokens; primary backgrounds keep the brand colour", () => {
  assert.equal(theme["--color-text-soft-400"], "var(--text-soft-400)");
  // `text-primary-base` resolves --text-color-* before --color-*, so only text changes.
  assert.equal(theme["--text-color-primary-base"], "var(--text-primary)");
  assert.equal(light["--text-primary"], theme["--color-primary-base"]);
  // White labels on primary buttons: unchanged brand colour, still AA.
  expectAA("#ffffff", theme["--color-primary-base"], "white on --color-primary-base");
});
