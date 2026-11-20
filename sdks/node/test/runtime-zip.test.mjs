// Zip extraction is the one place the SDK writes attacker-influenced paths to
// disk, so these tests cover the real archive shapes we ship (nested Windows
// runtime, Unicode fingerprint JSON) plus the traversal case that made us drop
// adm-zip (GHSA-vwc7-r8mq-g2x9).
//
// Archives are built by hand with `zlib` rather than a zip library so the test
// keeps working with no zip dependency in the tree at all.
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { crc32 } from "node:zlib";
import { createHash } from "node:crypto";

import { extractZipArchive, FINGERPRINTS_ARCHIVE, hostSpec, MANIFEST_URL, Runtime } from "../dist/runtime.js";

/** Minimal STORED-method zip writer: entries are `[name, contents]`. Names are
 *  written verbatim, which is what lets us emit a traversal path. */
function buildZip(entries) {
  const chunks = [];
  const central = [];
  let offset = 0;

  for (const [name, body] of entries) {
    const nameBuf = Buffer.from(name, "utf8");
    const data = Buffer.from(body, "utf8");
    const crc = crc32(data);

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // version needed
    local.writeUInt16LE(0x0800, 6); // UTF-8 names
    local.writeUInt16LE(0, 8); // stored
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    chunks.push(local, nameBuf, data);

    const header = Buffer.alloc(46);
    header.writeUInt32LE(0x02014b50, 0);
    header.writeUInt16LE(20, 4);
    header.writeUInt16LE(20, 6);
    header.writeUInt16LE(0x0800, 8);
    header.writeUInt16LE(0, 10);
    header.writeUInt32LE(crc, 16);
    header.writeUInt32LE(data.length, 20);
    header.writeUInt32LE(data.length, 24);
    header.writeUInt16LE(nameBuf.length, 28);
    header.writeUInt32LE(offset, 42);
    central.push(Buffer.concat([header, nameBuf]));

    offset += local.length + nameBuf.length + data.length;
  }

  const dir = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(dir.length, 12);
  end.writeUInt32LE(offset, 16);

  return Buffer.concat([...chunks, dir, end]);
}

function scratch() {
  return mkdtempSync(join(tmpdir(), "shardx-zip-"));
}

test("extracts and overwrites the nested Windows runtime layout", () => {
  const root = scratch();
  try {
    const archive = join(root, "runtime.zip");
    writeFileSync(archive, buildZip([
      ["ShardX-Windows/chrome.exe", "new-runtime"],
      ["ShardX-Windows/resources/app.asar", "resources"],
    ]));

    const destination = join(root, "out");
    mkdirSync(join(destination, "ShardX-Windows"), { recursive: true });
    writeFileSync(join(destination, "ShardX-Windows", "chrome.exe"), "stale-runtime");

    extractZipArchive(archive, destination);

    assert.equal(
      readFileSync(join(destination, "ShardX-Windows", "chrome.exe"), "utf8"),
      "new-runtime",
      "a stale runtime binary must be overwritten, not kept",
    );
    assert.equal(
      readFileSync(join(destination, "ShardX-Windows", "resources", "app.asar"), "utf8"),
      "resources",
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("preserves the fingerprint bundle directory and Unicode JSON", () => {
  const root = scratch();
  try {
    const archive = join(root, "fingerprints.zip");
    const payload = JSON.stringify({ name: "Hồ sơ Việt Nam" });
    writeFileSync(archive, buildZip([
      ["fingerprints/vi-VN.json", payload],
    ]));

    const destination = join(root, "out");
    extractZipArchive(archive, destination);

    assert.equal(
      readFileSync(join(destination, "fingerprints", "vi-VN.json"), "utf8"),
      payload,
      "Unicode JSON must survive extraction byte-for-byte",
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("refuses to write entries outside the destination directory", () => {
  const root = scratch();
  try {
    const archive = join(root, "evil.zip");
    writeFileSync(archive, buildZip([
      ["good.txt", "harmless"],
      ["../escaped.txt", "escaped"],
    ]));

    const destination = join(root, "out");
    // The two extractors disagree on how to reject traversal: bsdtar aborts,
    // while unzip strips the leading `..` and keeps the entry inside. Assert
    // the property that matters — nothing lands outside `destination` — rather
    // than either specific mechanism.
    try {
      extractZipArchive(archive, destination);
    } catch (err) {
      assert.match(String(err), /(tar|unzip) failed/);
    }

    assert.ok(
      !existsSync(join(root, "escaped.txt")),
      "no file may be written outside the destination directory",
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("reports a useful error when the archive is not a zip", () => {
  const root = scratch();
  try {
    const archive = join(root, "broken.zip");
    writeFileSync(archive, "this is not a zip file");

    assert.throws(
      () => extractZipArchive(archive, join(root, "out")),
      /(tar|unzip) failed/,
      "a corrupt download must fail loudly rather than yield an empty dir",
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("install extracts only archives whose SHA-256 the manifest names", async (t) => {
  const zip = buildZip([["marker.txt", "engine"]]);
  const good = createHash("sha256").update(zip).digest("hex");
  const spec = hostSpec();
  const keys = [spec.browser.key, spec.widevine?.key, FINGERPRINTS_ARCHIVE.key].filter(Boolean);
  const realFetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = realFetch; });

  // The manifest names `hash` (or nothing) for every archive; the bucket serves `zip`.
  const install = async (hash) => {
    const archives = Object.fromEntries(keys.map((key) => [key, "etag"]));
    const sha256 = hash ? Object.fromEntries(keys.map((key) => [key, hash])) : undefined;
    globalThis.fetch = async (url) => url === MANIFEST_URL
      ? new Response(JSON.stringify({ archives, sha256 }))
      : new Response(zip, { headers: { etag: '"etag"' } });
    const root = scratch();
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const result = await new Runtime({ cacheDir: root }).install().then(() => null, (e) => e);
    return { error: result, extracted: existsSync(join(root, "marker.txt")) };
  };

  const missing = await install(undefined);
  assert.match(String(missing.error), /no SHA-256/);
  assert.equal(missing.extracted, false, "an unverified archive must not be extracted");

  const wrong = await install("0".repeat(64));
  assert.match(String(wrong.error), /does not match the SHA-256/);
  assert.equal(wrong.extracted, false);

  const right = await install(good.toUpperCase());
  assert.equal(right.error, null);
  assert.equal(right.extracted, true);
});
