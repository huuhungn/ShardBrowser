// Every locale must answer for every key English has.
//
// The gap this catches is quiet: someone adds a key to en.json, ships it, and
// the Vietnamese UI keeps rendering English in that one spot. Nothing crashes
// and no test fails, so it survives until a user reports a half-translated
// screen. The same goes for a placeholder like {n} dropped in translation —
// the sentence then renders with a literal gap where the number belonged.

import { strict as assert } from "node:assert";
import { readdirSync, readFileSync } from "node:fs";
import { join, dirname, relative } from "node:path";
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
const SAME_IN_EVERY_LANGUAGE = new Set([
  "settings.helper.title",
  "helper.email",
  "ps.relay",
  "team.linux",
  "team.windows",
  // Words Vietnamese borrowed outright: the proxy screens say "proxy" and
  // "residential", and a translated coinage would read as a different product.
  "profileTable.proxy",
  // Protocol and platform names, spelled the same on every screen in the world.
  "automation.get",
  "proxy.http",
  "proxy.https",
  "proxy.socks5",
  "ps.http",
  "ps.socks5",
  "ps.android",
  "ps.linux",
  "ps.windows",
  "ps.premium",
  "sidebar.proxyshard",
  // Web platform names a Vietnamese reader meets in English everywhere else —
  // in Chrome's own settings, in every tutorial. Translating "Canvas" or
  // "WebRTC" would make the row harder to recognise, not easier.
  "profile.canvas",
  "profile.clientRects",
  "profile.doNotTrack",
  "profile.userAgent",
  "profile.webcam",
  "profile.proxy",
  // A worked example of proxy syntax: it is input to copy, not prose to read.
  "profile.hostPortUserPassFacebook",
]);

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

// A screen that still holds its English inline is invisible to every check
// above: the locale files agree with each other perfectly while the page
// renders English to a Vietnamese reader. So read the sources themselves and
// fail on a sentence that never became a key.
//
// Pages are only half the interface. A profile row, a proxy editor, the update
// pill — most of what a person reads lives in widgets/ and features/, so those
// are walked too, and shared/ and entities/ with them.
//
// The rule is narrow on purpose — a JSX text node, or a label/title/placeholder
// attribute, that reads like a sentence rather than an identifier. A className
// or an icon name has no business here and would only teach people to add
// exceptions until the test means nothing.
const uiRoots = ["pages", "widgets", "features", "shared", "entities", "app"].map((d) =>
  join(here, "..", "src", d),
);

/** Every .tsx under a root, so a nested feature folder cannot hide from this. */
function tsxFilesUnder(dir) {
  const out = [];
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    const full = join(dir, e.name);
    if (e.isDirectory()) out.push(...tsxFilesUnder(full));
    else if (e.name.endsWith(".tsx")) out.push(full);
  }
  return out;
}

/**
 * Components are not the only place text lives: option lists, field catalogues
 * and confirm defaults sit in plain .ts data modules, and the Shard Helper's
 * whole field list ("First name", "Postcode", "Date of birth") stayed English
 * there long after every .tsx had been translated. Walk those too.
 *
 * One body of text is deliberately outside all of this: `pages/patchlog/
 * patchlog.json` is the release history, 44 entries of it, written once per
 * release the way release notes always are. It is a record of what shipped, not
 * interface text, so it stays in the language it was written in.
 */
function tsDataFilesUnder(dir) {
  const out = [];
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    const full = join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name === "locales") continue; // the translations themselves
      out.push(...tsDataFilesUnder(full));
    } else if (e.name.endsWith(".ts") && !e.name.endsWith(".d.ts")) {
      out.push(full);
    }
  }
  return out;
}

// The product's own name reads the same in every language; translating it would
// be a bug, not a feature. Nor do language endonyms belong in a translation
// file: a Vietnamese speaker picking German from a list looks for "Deutsch",
// not for the Vietnamese word for German. Operating-system names are likewise
// spelled one way everywhere.
const NOT_PROSE = new Set([
  "ShardX Launcher",
  "ShardX",
  "ProxyShard",
  "English",
  "English (US)",
  "English (UK)",
  "English (Canada)",
  "English (Australia)",
  "Deutsch (Deutschland)",
  "Italiano",
  "Nederlands",
  "Polski",
  "Svenska",
  "Suomi",
  "Norsk",
  "Dansk",
  "Magyar",
  "Bahasa Indonesia",
  "Windows",
  "Windows 10",
  "Windows 11",
  "Linux",
  "Android",
  "macOS",
]);

/** Comments explain the code to us; they are not text anyone reads on screen. */
function withoutComments(src) {
  return src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
}

/**
 * Every rule below was written against double quotes, because that is what this
 * codebase uses — and a reviewer showed that `toast.error('Could not save')`
 * therefore walks past all of them. Which quote character a string is written
 * with is a formatting choice; it must not decide whether the string is read.
 * Only quotes in a position where a string can start are rewritten, so the
 * apostrophe in a sentence like `don't` is never mistaken for an opening quote.
 */
function normalizeQuotes(src) {
  return src.replace(
    /(^|[=(,:[?{]\s*|\b(?:return|throw|case|typeof|await|yield)\s+|=>\s*)'((?:[^'\\\n]|\\.)*)'/gm,
    (_, lead, body) => `${lead}"${body.replace(/"/g, '\\"')}"`,
  );
}

/**
 * A className is machinery, but it sits on the same line as the prose it
 * styles. Skipping the whole line because it contains one — which is what the
 * machinery check used to do — hides every other string on that line, so
 * `<Field className="mt-2" helperText="Password must contain letters" />`
 * passed. Take the class lists out and judge what remains.
 */
function withoutClassNames(src) {
  return src
    .replace(/\bclassName=(?:"[^"]*"|\{`[^`]*`\}|\{[^{}]*\})/g, "")
    .replace(/\b(?:class|cn|clsx|cva|tw)\(/g, "(");
}

/**
 * Scanning the whole file at once — needed to see a template that wraps — means
 * a backtick inside a regex literal or a double-quoted string can pair with an
 * unrelated one far below and swallow the code between them. Blank the insides
 * of those two forms first; what is left is templates only.
 */
function withoutBacktickDecoys(src) {
  // Pad with a character no rule reads rather than with spaces: blanking a
  // string to whitespace lets the templates on either side of it run together
  // into one apparent match spanning the code between them.
  const blank = (m) => "\u0002".repeat(m.length);
  return src
    .replace(/"(?:[^"\\\n]|\\.)*"/g, blank)
    .replace(/\/(?![/*])(?:[^/\\\n[]|\\.|\[(?:[^\]\\]|\\.)*\])+\/[gimsuy]*/g, blank);
}

/** A literal's own characters, safe to drop into a RegExp. */
function escapeForRegExp(v) {
  return v.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** What a scanner should actually read: no comments, no styling, one quote style. */
function readable(src) {
  return normalizeQuotes(
    withoutShellCommands(withoutClassNames(withoutComments(withoutCodeSamples(src)))),
  );
}

/**
 * `<code>npm run build</code>` is an instruction to type, not a sentence to
 * translate. Blank the span but keep its length, so offsets and the `=>`
 * lookbehind further down still line up.
 */
function withoutShellCommands(src) {
  return src.replace(/<code>[\s\S]*?<\/code>/g, (m) => " ".repeat(m.length));
}

/**
 * A placeholder showing the shape of a JSON payload is an illustration of a
 * format, not a sentence — translating the keys inside it would make the
 * example wrong. Such a sample is written in single quotes precisely because
 * it contains double ones, so normalising quotes would otherwise drag it in.
 */
function withoutCodeSamples(src) {
  return src.replace(/'[^'\n]*[{}[\]][^'\n]*'/g, "''");
}

/**
 * An HTTP header name is not a sentence someone reads: "Accept-Language" is
 * wire protocol, spelled exactly this way in the RFC, and translating it
 * would break the request. Two capitalised words joined by a hyphen, no
 * spaces, is the shape.
 */
const PROTOCOL_TOKEN = /^(?:[A-Z][a-z0-9]*-)+[A-Z][a-z0-9]*$/;

/**
 * A product name is not translated: "Chrome" is Chrome in every locale, and
 * "ShardX Launcher v" is the name plus a version that follows it. Translating
 * these would misname the thing on screen, so they are carved out by name
 * rather than by shape — the list is short and deliberate.
 */
const PRODUCT_NAME = /^(?:Chrome|Chromium|ShardX|ProxyShard|ShardX Launcher v)$/;

/** JSX text nodes and human-facing attributes, with the obvious non-prose out. */
function englishInSource(src) {
  const found = [];
  for (const line of readable(src).split("\n")) {
    const s = line.trim();
    // A bare line of prose between tags: "Add block", "No projects yet".
    if (/^[A-Z][a-zA-Z][\w ,.'’·—–-]*[a-z.!?]$/.test(s) && !s.includes("=") && !s.includes("(")) {
      found.push(s);
    }
    // Short labels often share a line with their tag — `<div class=…>Notes</div>`
    // — so the bare-line rule above never sees them. A column heading that hid
    // behind its own className is still a word someone reads.
    // The run of text was required to reach `<` directly, so a label ending in
    // an ellipsis, or followed by an interpolation — `>Connected · {email}<` —
    // matched nothing and three sentences sat in the badge unread.
    // `=>` ends in `>`, so `() => Promise<void>` looked like a tag holding the
    // word "Promise". The lookbehind keeps a return type from reading as text.
    // A status word is often lowercase -- `starting...`, `testing...` -- and a
    // sentence can carry a symbol for a button it names, so the run may begin
    // lowercase and hold glyphs like the refresh arrow.
    // Arrow and guillemet glyphs decorate a button without being part of the
    // word: `‹ Prev`, `Parse →`. They sat outside the character class, so the
    // run never started or never finished and the label went unread.
    for (const m of s.matchAll(
      /(?<![=-])>\s*([‹›←→«»]?\s*[A-Za-z][a-zA-Z][\w ,.'’·—–↻✓✗-]*?[a-z.!?…·—]\s*[‹›←→«»]?)\s*(?:\{|<)/g,
    )) {
      const text = m[1].trim();
      if (!PRODUCT_NAME.test(text)) found.push(text);
    }
    // A paragraph long enough to wrap, with a <strong> inside it, matches none
    // of the rules above: the tag breaks the bare-line shape, and each
    // continuation line starts lowercase and ends mid-sentence. Strip the
    // inline tags and look at what is left — if the line is only words and
    // punctuation, with nothing a compiler would read, it is a sentence.
    const bare = s.replace(/<\/?(?:strong|em|b|i|code|span|br)\s*\/?>/g, "").trim();
    // A trailing comma means this is an import list or a destructured set of
    // props wrapped across lines, not a sentence. Sentences also start with a
    // capital and contain a space; identifier lists rarely do both.
    if (
      !/[=(){}"`$;:[\]<>]/.test(bare) &&
      !bare.endsWith(",") &&
      !/^[a-z]+[A-Z]/.test(bare) &&
      /^[A-Z]/.test(bare) &&
      bare.includes(" ") &&
      (bare.match(/[A-Za-z]{3,}/g) ?? []).length >= 3
    ) {
      found.push(bare);
    }
    // Prose that is returned or assigned rather than rendered: `return "Could
    // not save"`, `=> "Remove this proxy"`, `const msg = "Nothing to import"`.
    // The bare-line rule above cannot see these, because it rejects any line
    // holding `=`, `(` or a quote — which every one of these forms has.
    for (const m of s.matchAll(
      /(?:=>|\breturn\b|\bthrow new [A-Za-z]+\(|=)\s*"([A-Z][a-zA-Z][\w ,.'’—–-]*[a-z.!?])"/g,
    )) {
      const v = m[1];
      if (PROTOCOL_TOKEN.test(v)) continue;
      if ((v.match(/[A-Za-z]{2,}/g) ?? []).length >= 3) found.push(v);
    }
    for (const m of s.matchAll(
      /(?:label|title|placeholder|confirmLabel|cancelLabel|aria-label|helperText|hint|tooltip|description|caption|subtitle|alt|emptyText|errorText|summary)="([^"]{3,})"/g,
    )) {
      // A sample address or id is an illustration, not a sentence: it stays the
      // same in every language, and translating it would break the example.
      const v = m[1];
      if (/^https?:\/\//.test(v) || /^[\w-]+(\.[\w-]+)+(\/\S*)?$/.test(v)) continue;
      found.push(v);
    }
  }
  return found;
}

// The JSX scan above reads what sits between tags, which is why a sidebar
// built from `{ label: "Browsers" }` stayed English through a whole migration
// that claimed to be finished: the text never appears as a JSX child, only as
// a value in a table the component maps over. Menus, filter options, confirm
// dialogs and file pickers are all built this way, so they get their own check.
const PROSE_PROP =
  /\b(label|title|placeholder|heading|confirmLabel|cancelLabel|emptyText|message)\s*:\s*"([A-Z][A-Za-z0-9 ,.'()/-]{2,})"/g;

function englishInProps(src) {
  const out = [];
  for (const line of readable(src).split("\n")) {
    for (const m of line.matchAll(PROSE_PROP)) out.push(m[2]);
  }
  return out;
}

test("no data table still holds its English in a label", () => {
  const offenders = [];
  for (const root of uiRoots) {
    for (const file of [...tsxFilesUnder(root), ...tsDataFilesUnder(root)]) {
      const src = readFileSync(file, "utf8");
      const where = relative(join(here, "..", "src"), file).replace(/\\/g, "/");
      for (const text of englishInProps(src)) {
        if (NOT_PROSE.has(text)) continue;
        offenders.push(`${where}: ${text}`);
      }
    }
  }
  assert.deepEqual(
    offenders,
    [],
    `these labels read as English text rather than t("…") keys:\n  ${offenders.join("\n  ")}`,
  );
});

// The two checks above read JSX children and object labels. Text also reaches
// people through a third door: a bare literal in a ternary, a toast argument, a
// confirm message. `{running ? "Stop" : "Start"}` is neither a JSX child nor a
// property, and a whole table of row actions stayed English behind exactly that
// shape. So the last check is the general one — any English-looking literal in
// a .tsx file — with the genuinely non-prose spelled out rather than guessed.

// DOM and platform vocabulary: these strings are compared against, not read.
const NOT_TEXT = new Set([
  "Enter", "Escape", "Tab", "Backspace", "Delete", "Home", "End",
  "ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight", "PageUp", "PageDown",
  "Authorization", "Signature: ", "ShardX", "ProxyShard", "ShardX Launcher",
  "Windows", "Linux", "MacOS", "macOS", "IOS", "Android",
]);

const LITERAL = /"([A-Z][A-Za-z0-9 ,.'’:/()—–-]{2,60})"/g;
// A name with no spaces and a capital inside it — WebGL2RenderingContext,
// HTMLCanvasElement, AudioWorkletNode — is an API the fingerprint code checks
// for, not a label. Prose has spaces; these never do, so the absence of a
// space is what tells them apart rather than a list that needs adding to.
const CODE_IDENTIFIER = /^[A-Za-z][A-Za-z0-9_$]*$/;
function isCodeIdentifier(text) {
  return CODE_IDENTIFIER.test(text) && /[a-z]/.test(text) && /[A-Z0-9]/.test(text.slice(1));
}
// The updater pill wrote its whole status ladder in lower case — "ready to
// install", "up to date" — and a rule anchored on a capital never saw any of
// it. A lower-case string of three or more words is a sentence too.
const LOWER_SENTENCE = /"([a-z][a-z0-9]*(?: [A-Za-z0-9,'’.—–-]+){1,})[.…!?]?"/g;
// A single lower-case word stays out on purpose: "idle", "ready" and "error"
// are state values compared against, not labels, and there is no shape that
// tells those apart from a one-word button. Two words is where prose starts.
// Tailwind is written the same way a sentence is — words separated by spaces —
// so a class list has to be told apart by its vocabulary, not its shape.
const CSS_WORDS =
  /\b(flex|grid|items-|justify-|gap-|px-|py-|pt-|pb-|pl-|pr-|mx-|my-|mt-|mb-|ml-|mr-|rounded|border|bg-|text-|w-|h-|size-|min-|max-|absolute|relative|fixed|sticky|inset-|z-\d|overflow|transition|cursor-|place-|ring-|shadow|opacity-|truncate|whitespace|leading-|tracking-|hover:|focus:|disabled:)/;
// Lines where a string is machinery rather than prose: module paths, CSS class
// names, DOM ids, invoke() command names, HTTP headers.
const MACHINERY =
  /\b(import|from|className|invoke|querySelector|getElementById|setAttribute|localStorage|sessionStorage|fetch|headers|key=|data-|aria-label=\{t)\b|classList|\.(?:get|set|has)\(\s*["'`]?[\w.-]+["'`]?\s*\)/;

/**
 * The machinery check used to skip the whole line, which meant one invoke() or
 * one data- attribute hid every other string beside it:
 * `<button data-id="save" title="Delete this profile">` was never read. Blank
 * out the machinery arguments themselves and judge what is left, the same way
 * withoutClassNames already does for Tailwind.
 */
function withoutMachinery(line) {
  return line
    // import ... from "path" / export ... from "path"
    .replace(/\b(?:import|export)\b[^;]*?\bfrom\s*["'`][^"'`]*["'`]/g, "")
    .replace(/\bimport\s*\(\s*["'`][^"'`]*["'`]\s*\)/g, "")
    // A bare `from "path"` — in a re-export, or quoted inside a comment — is a
    // module path too, and letting the bare keyword stand hid the prose beside it.
    .replace(/\bfrom\s*["'`][^"'`]*["'`]/g, "")
    // invoke("cmd"), fetch("url"), getElementById("id"), localStorage.getItem("k")
    .replace(
      /\b(?:invoke|fetch|querySelector|querySelectorAll|getElementById|setAttribute|getAttribute|emit|listen)\s*\(\s*["'`][^"'`]*["'`]/g,
      "(",
    )
    .replace(
      /\b(?:localStorage|sessionStorage|headers|params|searchParams)\s*\.\s*(?:get|set|has|delete|getItem|setItem|removeItem|append)\s*\(\s*["'`][^"'`]*["'`]/g,
      "(",
    )
    // data-*, key=, id=, name=, type=, href=, src=: identifiers, not prose
    .replace(/\b(?:data-[\w-]+|key|id|name|type|href|src|htmlFor|role)=(?:["'`][^"'`]*["'`]|\{[^{}]*\})/g, "");
}

test("no ternary or toast still holds its English", () => {
  const offenders = [];
  for (const root of uiRoots) {
    // A string handed straight to a helper — notify("Could not save") — lives
    // just as often in a plain .ts store as in a component, and scanning only
    // .tsx left that whole half of the codebase unread.
    for (const file of [...tsxFilesUnder(root), ...tsDataFilesUnder(root)]) {
      const src = readable(readFileSync(file, "utf8"));
      const where = relative(join(here, "..", "src"), file).replace(/\\/g, "/");
      for (const rawLine of src.split("\n")) {
        const line = withoutMachinery(rawLine);
        if (MACHINERY.test(line)) continue;
        for (const re of [LITERAL, LOWER_SENTENCE]) {
          for (const m of line.matchAll(re)) {
            const text = m[1];
            if (NOT_TEXT.has(text) || NOT_PROSE.has(text) || isCodeIdentifier(text)) continue;
            if (!/[a-z]{2}/.test(text)) continue; // SCREAMING_CASE constants
            if (CSS_WORDS.test(text)) continue;
            // An IANA zone id — "Europe/Paris" — is the value the platform
            // expects, not a label; the UI shows the city from it separately.
            if (/^[A-Za-z]+\/[A-Za-z_]+(?:\/[A-Za-z_]+)?$/.test(text)) continue;
            // An HTTP header name is wire protocol spelled exactly as the RFC
            // has it — "Accept-Language" is sent, not shown.
            if (PROTOCOL_TOKEN.test(text)) continue;
            // A string being compared against, or used as a fallback key, is a
            // value the code branches on — `platform === "Other"`. Translating
            // it would break the comparison; the label is translated where it
            // is drawn instead.
            if (new RegExp(`[=!]==?\\s*["']${escapeForRegExp(text)}["']`).test(line)) continue;
            if (new RegExp(`\\|\\|\\s*["']${escapeForRegExp(text)}["']`).test(line)) continue;
            offenders.push(`${where}: ${text}`);
          }
        }
      }
    }
  }
  assert.deepEqual(
    offenders,
    [],
    `these literals reach the screen as English:\n  ${offenders.join("\n  ")}`,
  );
});

test("no screen still holds its English inline", () => {
  const offenders = [];
  for (const root of uiRoots) {
    // A sentence assigned in a plain .ts module reaches a screen exactly like
    // one written in JSX: `const msg = "Could not save"` is shown by whoever
    // imports it. Reading only .tsx here left that whole half of the code
    // unscanned.
    for (const file of [...tsxFilesUnder(root), ...tsDataFilesUnder(root)]) {
      const src = readFileSync(file, "utf8");
      const where = relative(join(here, "..", "src"), file).replace(/\\/g, "/");
      for (const text of englishInSource(src)) {
        if (NOT_PROSE.has(text)) continue;
        offenders.push(`${where}: ${text}`);
      }
    }
  }
  assert.deepEqual(
    offenders,
    [],
    `these read as English text rather than t("…") keys:\n  ${offenders.join("\n  ")}`,
  );
});

// Every check above reads double-quoted strings. A backtick is the fourth door,
// and the widest one: `Deleted folder "${f}"` is a whole sentence the quoted
// scans never see. It is also where the automated conversion left the worst of
// its damage, including a t("…") call stranded inside a template literal, which
// reaches the screen as those exact characters. So: read template literals too,
// and treat an interpolation as the word-boundary it is.
const TEMPLATE = /`([^`\\]*)`/g;
// The same shape, but allowed to span lines.
const TEMPLATE_MULTILINE = /`((?:[^`\\]|\\.)*)`/g;

function englishInTemplates(src) {
  const out = [];
  // A template that wraps across lines — a message long enough to need two
  // lines is exactly the kind that is prose — has no complete match on either
  // line, so scanning line by line could never see it. Scan the whole source
  // and locate each match afterwards to decide whether its line is machinery.
  const whole = withoutBacktickDecoys(readable(src));
  const lineStarts = [];
  { let n = 0; for (const l of whole.split("\n")) { lineStarts.push(n); n += l.length + 1; } }
  const lineAt = (idx) => {
    let lo = 0, hi = lineStarts.length - 1;
    while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (lineStarts[mid] <= idx) lo = mid; else hi = mid - 1; }
    return whole.split("\n")[lo] ?? "";
  };
  {
    for (const m of whole.matchAll(TEMPLATE_MULTILINE)) {
      const line = lineAt(m.index ?? 0);
      // Drop the ${…} holes; what is left is what a reader reads.
      const prose = maskInterpolations(m[1]).trim();
      if (!/[A-Za-z]{2}/.test(prose)) continue;
      // A path, a css value, a url fragment: machinery wearing backticks.
      if (/^[\w./\\:%-]+$/.test(prose.replace(/\u0001/g, ""))) continue;
      // A command someone pastes into a shell is copied verbatim, and a
      // translated flag would not run. Same for the `"` fragments the two
      // little markup parsers compare against: those are delimiters, not words.
      if (/\b(hermes|npm|npx|node|cargo|git)\s+\w/.test(prose)) continue;
      // A console transcript or a list of accepted input formats is shown so it
      // can be copied or matched character for character; translating an API
      // call or a proxy line would make the example wrong.
      if (/\w+\.\w+\(\)|^\w+:\/\/|^\s*->/m.test(prose)) continue;
      if (/^["'`)\s]*(&&|\|\|)/.test(prose) || /\b(startsWith|endsWith)\(/.test(line)) continue;
      // `${name} · ${host}:${port}` is punctuation holding values apart. There
      // is no English in it to translate, so leave those joins alone.
      if (!/[A-Za-z]{2}/.test(prose.replace(/\u0001/g, " "))) continue;
      // A sentence is not always whole between two holes. `Added ${n}
      // prox${n === 1 ? "y" : "ies"}` has no piece longer than one word, yet a
      // reader sees an English sentence. So read the pieces joined as well: a
      // hole stands for the value it will hold, which is one word.
      // An Accept-Language value is a protocol string: its "en" names a
      // language to a server, and translating it would change the request.
      if (/;q=0\.\d/.test(prose)) continue;
      const joined = prose.replace(/\u0001/g, " ").replace(/\s+/g, " ").trim();
      const words = joined.match(/[A-Za-z][a-z]+/g) ?? [];
      if (words.length >= 2 && !NOT_TEXT.has(joined) && !NOT_PROSE.has(joined)) {
        out.push(joined);
        continue;
      }
      for (const piece of prose.split("\u0001")) {
        const text = piece.trim();
        if (text.length < 4) continue;
        if (NOT_TEXT.has(text) || NOT_PROSE.has(text) || isCodeIdentifier(text)) continue;
        // Prose has at least two lowercase letters and a space, or ends a
        // sentence: "profile bound to this proxy", "Delete folder".
        if (!/[a-z]{2}/.test(text)) continue;
        if (!/\s/.test(text) && !/[.?!]$/.test(text)) continue;
        out.push(text);
      }
    }
  }
  return out;
}

/// Replace every ${...} with one marker, counting braces so a nested
/// template (`${a ? `${b}` : ""}`) is swallowed whole instead of ending at
/// the first inner brace and leaving its identifiers to look like prose.
function maskInterpolations(text) {
  let out = "";
  for (let i = 0; i < text.length; i++) {
    if (text[i] === "$" && text[i + 1] === "{") {
      let depth = 1;
      let j = i + 2;
      for (; j < text.length && depth > 0; j++) {
        if (text[j] === "{") depth++;
        else if (text[j] === "}") depth--;
      }
      out += "\u0001";
      i = j - 1;
    } else {
      out += text[i];
    }
  }
  return out;
}

test("no sentence hides inside a template literal", () => {
  const offenders = [];
  for (const root of uiRoots) {
    for (const file of [...tsxFilesUnder(root), ...tsDataFilesUnder(root)]) {
      const src = readFileSync(file, "utf8");
      const where = relative(join(here, "..", "src"), file).replace(/\\/g, "/");
      for (const text of englishInTemplates(src)) {
        offenders.push(`${where}: ${text}`);
      }
    }
  }
  assert.deepEqual(
    offenders,
    [],
    `these template literals reach the screen as English:\n  ${offenders.join("\n  ")}`,
  );
});

// A translator call that ended up inside a string instead of beside it renders
// as source code to whoever opens that dialog. One conversion left exactly this
// in a folder-deletion prompt; nothing else in the suite would have caught it.
test("no t() call is stranded inside a string", () => {
  const offenders = [];
  for (const root of uiRoots) {
    for (const file of [...tsxFilesUnder(root), ...tsDataFilesUnder(root)]) {
      const src = withoutComments(readFileSync(file, "utf8"));
      const where = relative(join(here, "..", "src"), file).replace(/\\/g, "/");
      // A `t("…")` written *as text* rather than called. Inside a template
      // literal the call only runs within `${…}`, so the damage is a t( that
      // is not preceded by an unclosed interpolation. Check line by line:
      // matching across lines finds pairs of unrelated strings instead.
      for (const line of src.split("\n")) {
        for (const m of line.matchAll(/`([^`]*)`/g)) {
          const inner = m[1];
          // Blank out every interpolation, where a call is legitimate.
          const outside = inner.replace(/\$\{[^}]*\}/g, "");
          const stranded = outside.match(/\bt\("[\w.]+"\)/);
          if (stranded) offenders.push(`${where}: ${stranded[0]} inside a template literal`);
        }
        // The same mistake in a double-quoted string shows up as an escaped
        // quote, since the call's own quotes have to be escaped to fit.
        for (const m of line.matchAll(/\bt\(\\"[\w.]+\\"\)/g)) {
          offenders.push(`${where}: ${m[0]}`);
        }
      }
    }
  }
  assert.deepEqual(
    offenders,
    [],
    `these render the translator call itself to the user:\n  ${offenders.join("\n  ")}`,
  );
});

// A translation read at module scope is read once, when the file is first
// imported, and keeps whichever language was loaded at that moment. Switching
// to Vietnamese then leaves those labels in English until the app restarts —
// a bug no screenshot catches, because the first run looks perfect. A
// function is fine: it runs when it is called, in the language of that moment.
test("no translation is frozen at import time", () => {
  const frozen = [];
  for (const root of uiRoots) {
  for (const file of [...tsxFilesUnder(root), ...tsDataFilesUnder(root)]) {
    const where = relative(join(here, "..", "src"), file).replace(/\\/g, "/");
    const src = readable(readFileSync(file, "utf8"));
    const lines = src.split("\n");
    let depth = 0;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (depth === 0 && /^\s*(?:export\s+)?(?:const|let|var)\s+\w+/.test(line)) {
        // Read the whole initializer: it may run to several lines.
        let d = 0, j = i, body = "";
        do {
          body += lines[j] + "\n";
          for (const ch of lines[j]) {
            if ("{([".includes(ch)) d++;
            else if ("})]".includes(ch)) d--;
          }
          j++;
        } while (d > 0 && j < lines.length);
        const beforeCall = body.split(/(?<![\w.])t\(/)[0];
        const callsT = /(?<![\w.])t\(\s*["'`]/.test(body);
        // An arrow before the call usually means the text is built later, when
        // the component draws. But an arrow that is *invoked at import time*
        // freezes just as hard as a plain call: `(() => t("k"))()` and
        // `list.map(() => t("k"))` both run now. Only a function that is
        // merely defined defers anything.
        // A zero-argument arrow that is immediately called, or a list built by
        // mapping one, runs at import. An arrow that TAKES arguments is a
        // callback someone else invokes later — a store's `(set, get) => ({…})`
        // holds its t() calls inside action functions, which run on click.
        // The closing `)()` sits AFTER the t( call, so beforeCall never holds
        // it — the whole declaration has to be read to see the arrow is run.
        const iife = /\(\s*\(\s*\)\s*=>[\s\S]*?\)\s*\(\s*\)/.test(body);
        const mappedNow =
          /\.\s*(?:map|flatMap|filter|forEach|reduce|from)\s*\(\s*\(\s*\)\s*=>/.test(beforeCall);
        const invokedNow = iife || mappedNow;
        const isFunction = /=>|\bfunction\b/.test(beforeCall) && !invokedNow;
        if (callsT && !isFunction) {
          frozen.push(`${where}:${i + 1}: ${lines[i].trim().slice(0, 70)}`);
        }
      }
      for (const ch of line) {
        if ("{([".includes(ch)) depth++;
        else if ("})]".includes(ch)) depth--;
      }
      if (depth < 0) depth = 0;
    }
  }
  }
  assert.deepEqual(
    frozen,
    [],
    `a module-scope t() keeps the language it was first imported with, so these stay in the old language after a switch:\n${frozen.join("\n")}`,
  );
});
