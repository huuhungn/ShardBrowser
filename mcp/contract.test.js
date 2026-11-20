import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const dir = path.dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(await readFile(path.join(dir, "package.json"), "utf8"));

test("stdio server exposes the versioned ShardX tool contract", async () => {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [path.join(dir, "index.js")],
    cwd: dir,
    stderr: "pipe",
  });
  const client = new Client({ name: "shardx-contract-test", version: "1.0.0" });

  try {
    await client.connect(transport);
    const { version } = client.getServerVersion() ?? {};
    const { tools } = await client.listTools();
    const names = new Set(tools.map((tool) => tool.name));

    // Read from package.json: pinning the literal here means every release
    // bump fails this test for no reason, which trains people to edit it
    // without reading what it guards.
    assert.equal(version, pkg.version);
    assert.equal(tools.length, 114);
    for (const name of [
      "health_check",
      "startup_status",
      "configure_startup",
      "find_profile_by_name",
      "ensure_profile_started",
      "safe_open_url",
      "devtools_context",
      "cleanup_stale_profile_processes",
      "challenge_status",
      "verification_checkpoint",
      "wait_for_human_verification",
      // Merged from upstream v2: human-timing input and the library/trash tools.
      "human_click",
      "human_type",
      "list_extensions",
      "list_bookmarks",
      "list_trash",
      "restore_profile",
      // Automation: the runner's only door for MCP clients.
      "list_automation_projects",
      "get_automation_project",
      "run_automation_project",
      "record_profile_traffic",
    ]) {
      assert(names.has(name), `missing MCP tool: ${name}`);
    }

    const safeOpen = tools.find((tool) => tool.name === "safe_open_url");
    assert(safeOpen.inputSchema.properties.keep_running, "safe_open_url.keep_running missing");

    // A run drives a logged-in browser, so it must offer the same lifecycle
    // control as safe_open_url rather than leaving profiles running.
    const run = tools.find((tool) => tool.name === "run_automation_project");
    assert(run.inputSchema.properties.keep_running, "run_automation_project.keep_running missing");

    // Recording drives a browser, so it must offer the same lifecycle control
    // as the other tools that open one: without it a caller cannot say
    // "leave the profile as you found it".
    const traffic = tools.find((tool) => tool.name === "record_profile_traffic");
    assert(traffic.inputSchema.properties.keep_running, "record_profile_traffic.keep_running missing");
    assert(traffic.inputSchema.properties.url, "record_profile_traffic.url missing");
  } finally {
    await client.close();
  }
});

// Clients written against v0.1.28 must keep working: no tool or argument they
// rely on may disappear, change type, or become required.
test("every v0.1.28 tool keeps its arguments and gains no required ones", async () => {
  const fixture = JSON.parse(await readFile(path.join(dir, "fixtures", "v0.1.28-tools.json"), "utf8"));
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [path.join(dir, "index.js")],
    cwd: dir,
    stderr: "pipe",
  });
  const client = new Client({ name: "shardx-contract-test", version: "1.0.0" });

  try {
    await client.connect(transport);
    const { tools } = await client.listTools();
    const current = new Map(tools.map((tool) => [tool.name, tool.inputSchema]));
    assert.equal(fixture.tools.length, fixture.toolCount);
    for (const { name, inputSchema: old } of fixture.tools) {
      const now = current.get(name);
      assert(now, `v0.1.28 tool removed: ${name}`);
      for (const [arg, schema] of Object.entries(old.properties ?? {})) {
        assert(now.properties?.[arg], `${name}.${arg} removed`);
        // An argument without a `type` (z.any) is only checked for presence.
        assert.equal(now.properties[arg].type, schema.type, `${name}.${arg} changed type`);
        assert.equal(now.properties[arg].items?.type, schema.items?.type, `${name}.${arg} changed item type`);
        for (const value of schema.enum ?? []) {
          assert(now.properties[arg].enum?.includes(value), `${name}.${arg} no longer accepts ${value}`);
        }
      }
      const wasRequired = new Set(old.required ?? []);
      for (const arg of now.required ?? []) {
        assert(wasRequired.has(arg), `${name}.${arg} became required`);
      }
    }
  } finally {
    await client.close();
  }
});

test("safe_open_url cleanup uses the launch-instance guard and never falls back to PID ownership", async () => {
  const source = await readFile(path.join(dir, "index.js"), "utf8");

  assert.match(source, /\/stop-if-launch-instance/);
  assert.match(source, /launch_instance_token:\s*launchInstanceToken/);
  assert.doesNotMatch(source, /\/stop-if-pid\//);
  assert.doesNotMatch(source, /globalThis\.process\.kill/);
  assert.match(source, /redactLaunchInstanceToken\(started\)/);
});

test("HTTP mode answers only a Bearer SHARDX_TOKEN on a loopback Host", async (t) => {
  const { spawn } = await import("node:child_process");
  const http = await import("node:http");
  const net = await import("node:net");
  const port = await new Promise((resolve) => {
    const probe = net.createServer().listen(0, "127.0.0.1", () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
  const token = "test-token-not-a-real-one";
  const child = spawn(process.execPath, [path.join(dir, "index.js")], {
    cwd: dir,
    env: { ...process.env, MCP_HTTP_PORT: String(port), SHARDX_TOKEN: token, SHARDX_API: "http://127.0.0.1:9" },
    stdio: ["ignore", "ignore", "pipe"],
  });
  t.after(() => child.kill());
  await new Promise((resolve, reject) => {
    child.stderr.on("data", (d) => String(d).includes("HTTP transport on") && resolve());
    child.once("exit", (code) => reject(new Error(`server exited ${code}`)));
  });

  const initialize = JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } },
  });
  const post = (headers) => new Promise((resolve, reject) => {
    const req = http.request({
      host: "127.0.0.1",
      port,
      path: "/mcp",
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        ...headers,
      },
    }, (res) => {
      res.resume();
      resolve(res.statusCode);
    });
    req.on("error", reject);
    req.end(initialize);
  });

  assert.equal(await post({}), 401, "no token");
  assert.equal(await post({ authorization: "Bearer wrong" }), 401, "wrong token");
  assert.equal(
    await post({ authorization: `Bearer ${token}`, host: `rebind.example:${port}` }),
    403,
    "a Host that is not the loopback port",
  );
  assert.equal(await post({ authorization: `Bearer ${token}` }), 200, "the token on 127.0.0.1");
});
