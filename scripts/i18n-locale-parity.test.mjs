// Every locale must answer for every key English has.
//
// The gap this catches is quiet: someone adds a key to en.json, ships it, and
// the Vietnamese UI keeps rendering English in that one spot. Nothing crashes
// and no test fails, so it survives until a user reports a half-translated
// screen. The same goes for a placeholder like {n} dropped in translation —
// the sentence then renders with a literal gap where the number belonged.

import { strict as assert } from "node:assert";
import { readdirSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const here = dirname(fileURLToPath(import.meta.url));
const dir = join(here, "..", "src", "shared", "i18n", "locales");

const read = (f) => JSON.parse(readFileSync(join(dir, f), "utf8"));
const placeholders = (s) => (s.match(/\{(\w+)\}/g) ?? []).sort();

const files = readdirSync(dir).filter((f) => f.endsWith(".json"));
const en = read("en.json");

// A product name is the same word in every language, so an identical value is
// the correct translation rather than a forgotten one. Listing the keys — as
// opposed to letting short strings through — keeps the check strict: adding a
// name here is a deliberate line in a diff, and a genuinely untranslated
// sentence can never slip past by being brief.
const SAME_IN_EVERY_LANGUAGE = new Set(["settings.helper.title"]);

test("english is the full key set", () => {
  assert.ok(Object.keys(en).length > 0, "en.json should not be empty");
});

for (const file of files.filter((f) => f !== "en.json")) {
  const lang = file.replace(/\.json$/, "");
  const dict = read(file);

  test(`${lang} covers every english key`, () => {
    const missing = Object.keys(en).filter((k) => !(k in dict));
    assert.deepEqual(
      missing,
      [],
      `${file} is missing keys that en.json has, so those spots render in ` +
        `English: ${missing.join(", ")}`,
    );
  });

  test(`${lang} has no key english dropped`, () => {
    const orphan = Object.keys(dict).filter((k) => !(k in en));
    assert.deepEqual(
      orphan,
      [],
      `${file} carries keys en.json does not, which are dead weight: ` +
        `${orphan.join(", ")}`,
    );
  });

  test(`${lang} keeps every placeholder`, () => {
    for (const key of Object.keys(en)) {
      if (!(key in dict)) continue;
      assert.deepEqual(
        placeholders(dict[key]),
        placeholders(en[key]),
        `${file} changed the placeholders in "${key}", so the value that ` +
          `belongs there will not appear`,
      );
    }
  });

  // Emphasis travels inside the string (*bold*, `code`, \n), so a translator
  // can move the bold word to where the sentence needs it. An unpaired marker
  // renders as a literal asterisk on screen instead of bolding anything.
  test(`${lang} keeps emphasis markers paired`, () => {
    for (const key of Object.keys(en)) {
      if (!(key in dict)) continue;
      for (const [mark, name] of [
        ["*", "bold"],
        ["`", "code"],
      ]) {
        const count = (s) => s.split(mark).length - 1;
        assert.equal(
          count(dict[key]) % 2,
          0,
          `${file} leaves an unpaired ${mark} in "${key}", which renders as a ` +
            `literal ${mark} rather than ${name}`,
        );
        assert.equal(
          count(dict[key]),
          count(en[key]),
          `${file} changed how many ${name} spans "${key}" has, so the ` +
            `emphasis no longer matches the English`,
        );
      }
    }
  });

  test(`${lang} left nothing in english`, () => {
    const untouched = Object.keys(en).filter(
      (k) =>
        !SAME_IN_EVERY_LANGUAGE.has(k) &&
        k in dict &&
        dict[k] === en[k] &&
        /[a-z]{4}/.test(en[k]),
    );
    assert.deepEqual(
      untouched,
      [],
      `${file} repeats the English text for these keys, which is a ` +
        `translation that was never written: ${untouched.join(", ")}`,
    );
  });
}

test("every locale in the folder is registered in the store", () => {
  const index = readFileSync(join(here, "..", "src", "shared", "i18n", "index.ts"), "utf8");
  for (const file of files) {
    const lang = file.replace(/\.json$/, "");
    assert.ok(
      new RegExp(`\\b${lang}:\\s`).test(index),
      `locales/${file} exists but ${lang} is not in DICTS, so the language ` +
        `cannot be chosen`,
    );
    assert.ok(
      index.includes(`value: "${lang}"`),
      `${lang} is in DICTS but not in LANG_OPTIONS, so it never appears in ` +
        `the settings picker`,
    );
  }
});
