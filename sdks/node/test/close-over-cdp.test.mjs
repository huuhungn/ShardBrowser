// A CDP session is stopped with Browser.close, the way the launcher closes a profile.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:net";
import { spawn } from "node:child_process";
import { BrowserSession, closeOverCdp } from "../dist/browser.js";

test("Browser.close goes out as one masked frame after the upgrade", async () => {
  let got = null;
  const server = createServer((sock) => {
    sock.once("data", (hello) => {
      assert.match(hello.toString(), /^GET \/devtools\/browser\/x HTTP\/1\.1\r\n/);
      sock.write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n");
      sock.once("data", (f) => {
        const len = f[1] & 0x7f, mask = f.subarray(2, 6);
        got = Buffer.from(f.subarray(6, 6 + len).map((b, i) => b ^ mask[i % 4])).toString();
        sock.end();
      });
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const ok = await closeOverCdp(`ws://127.0.0.1:${server.address().port}/devtools/browser/x`);
  await new Promise((r) => setTimeout(r, 100));
  server.close();
  assert.equal(ok, true);
  assert.deepEqual(JSON.parse(got), { id: 1, method: "Browser.close" });
});

test("nothing listening is a no, not a hang", async () => {
  assert.equal(await closeOverCdp("ws://127.0.0.1:1/devtools/browser/x", 1000), false);
});

const sleeper = (code) => spawn(process.execPath, ["-e", code], { stdio: ["pipe", "ignore", "ignore"] });
const ready = (child) => new Promise((r) => setTimeout(r, 300, child));

test("stop() asks over CDP first: the browser exits on its own, no signal", async () => {
  const child = await ready(sleeper("process.stdin.on('data',()=>process.exit(0));setInterval(()=>{},1e3)"));
  const server = createServer((sock) => {
    sock.once("data", () => {
      sock.write("HTTP/1.1 101 Switching Protocols\r\n\r\n");
      sock.once("data", () => child.stdin.write("q"));
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const url = `ws://127.0.0.1:${server.address().port}/devtools/browser/x`;
  await new BrowserSession(child.pid, "udd", url, child).stop();
  server.close();
  assert.equal(child.exitCode, 0);
  assert.equal(child.signalCode, null);
});

test("stop() without CDP falls back to a signal", async () => {
  const child = await ready(sleeper("setInterval(()=>{},1e3)"));
  await new BrowserSession(child.pid, "udd", null, child).stop(2000);
  assert.ok(child.exitCode !== null || child.signalCode !== null);
});
