// `shardx install` argument handling and wiring, with the network cut off.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const CLI = fileURLToPath(new URL("../dist/cli.js", import.meta.url));
const OFFLINE = "data:text/javascript,globalThis.fetch=async()=>{throw new Error('offline')}";
const run = (...args) => spawnSync(process.execPath, ["--import", OFFLINE, CLI, ...args], { encoding: "utf8" });

test("no command, an unknown flag and a dangling --cache-dir print usage and exit 2", () => {
  for (const args of [[], ["bogus"], ["install", "--nope"], ["install", "--cache-dir"]]) {
    const r = run(...args);
    assert.equal(r.status, 2, args.join(" "));
    assert.match(r.stderr, /usage: shardx install \[--force\] \[--cache-dir DIR\]/);
  }
});

test("install --force --cache-dir uses that directory and fails cleanly offline", () => {
  const dir = join(mkdtempSync(join(tmpdir(), "shardx-cli-")), "engine");
  const r = run("install", "--force", "--cache-dir", dir);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /offline/);
  assert.ok(existsSync(dir));
});
