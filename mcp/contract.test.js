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
    assert.equal(tools.length, 113);
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
    ]) {
      assert(names.has(name), `missing MCP tool: ${name}`);
    }

    const safeOpen = tools.find((tool) => tool.name === "safe_open_url");
    assert(safeOpen.inputSchema.properties.keep_running, "safe_open_url.keep_running missing");

    // A run drives a logged-in browser, so it must offer the same lifecycle
    // control as safe_open_url rather than leaving profiles running.
    const run = tools.find((tool) => tool.name === "run_automation_project");
    assert(run.inputSchema.properties.keep_running, "run_automation_project.keep_running missing");
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
