# ShardX MCP server

An [MCP](https://modelcontextprotocol.io) server that lets an AI client
(Claude Desktop, Cursor, …) drive the **ShardX Launcher**:

- the local automation **HTTP API** — create/edit/launch/close profiles,
  manage proxies, fingerprints, folders and cookies;
- a launched profile's **browser over CDP**, driven with
  [`patchright`](https://github.com/Kaliiiiiiiiii-Vinyzu/patchright-nodejs)
  (a stealth-patched Playwright) so the automation stays undetected.

Requires **Node ≥ 18**. The app itself does **not** run this server — it
only downloads the source for you (**Settings → MCP server → Download MCP
server**, pick a folder). You then install deps and register it with your
MCP client.

### 1. Install deps

`connectOverCDP` only *connects* to the already-running ShardX browser, so
patchright's own Chromium is never needed — install with the browser
download skipped to keep `node_modules` small:

```powershell
Set-Location -LiteralPath 'C:\path\to\downloaded\mcp'
$env:PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD='1'
$env:PATCHRIGHT_SKIP_BROWSER_DOWNLOAD='1'
npm ci
```

```bash
cd /path/to/downloaded/mcp
PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 PATCHRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm ci
```

Release archives include `package-lock.json`, so `npm ci` recreates the tested
dependency graph. Use `npm install` only for a legacy or custom source folder
that does not contain a lockfile.

### 2. Register with your MCP client (stdio)

```json
{
  "mcpServers": {
    "shardx": {
      "command": "node",
      "args": ["/ABSOLUTE/PATH/mcp/index.js"],
      "env": {
        "SHARDX_API": "http://127.0.0.1:40325",
        "SHARDX_TOKEN": "<Bearer token from Settings → Automation API>"
      }
    }
  }
}
```

On Windows, if your MCP client strips custom environment variables, the server
also checks the current user's `HKCU\Environment` values for `SHARDX_API` and
`SHARDX_TOKEN`. This keeps Codex/Cursor-style stdio launches working without
copying the token into client config.

### Hermes Desktop (Windows)

First use the Settings button to store `SHARDX_TOKEN` in the Windows User
environment, then restart Hermes so it inherits the value. Register the
downloaded server without putting the token in Hermes config:

```powershell
hermes mcp add shardbrowser --env "SHARDX_API=http://127.0.0.1:40325" --command node --args "C:\absolute\path\to\mcp\index.js"
```

Inspect or repair the entry:

```powershell
hermes mcp list
hermes mcp test shardbrowser
hermes mcp remove shardbrowser
```

Note the flag shape: Hermes takes `--command` and `--args`, where the Codex CLI
below uses a bare `--` separator. After adding or repairing, restart Hermes so
it reloads the MCP tools, then call `health_check` first; it reports API
reachability and authentication without printing the token.

### Codex CLI (Windows)

Still supported; use this if Codex is your MCP host instead of Hermes.

First use the Settings button to store `SHARDX_TOKEN` in the Windows User
environment, then restart Codex so it inherits the value. Register the
downloaded server without putting the token in Codex config:

```powershell
codex mcp add shardbrowser --env "SHARDX_API=http://127.0.0.1:40325" -- node "C:\absolute\path\to\mcp\index.js"
```

If that name already exists, inspect or repair the entry:

```powershell
codex mcp get shardbrowser
codex mcp remove shardbrowser; codex mcp add shardbrowser --env "SHARDX_API=http://127.0.0.1:40325" -- node "C:\absolute\path\to\mcp\index.js"
```

ShardX Settings can also run a local **Check Codex registration** inspection,
under **Advanced actions** since Hermes is the primary host.
It compares Codex's `shardbrowser` entry with the selected `index.js` path and
`SHARDX_API`, and only reports whether `SHARDX_TOKEN` is present in config
without printing the token value. After adding or repairing, restart Codex so it
reloads the MCP tools. Call `health_check` first; it reports API reachability
and authentication without printing the token.

### HTTP mode (optional, self-hosted)

If you'd rather host it yourself and connect by URL, run it with
`MCP_HTTP_PORT` set — it then serves at `http://127.0.0.1:<port>/mcp`:

```bash
MCP_HTTP_PORT=40326 SHARDX_API=http://127.0.0.1:40325 SHARDX_TOKEN=… node index.js
```

## Environment

| Var             | Default                  | Notes                                               |
| --------------- | ------------------------ | --------------------------------------------------- |
| `SHARDX_API`    | `http://127.0.0.1:40325` | Launcher API base URL.                              |
| `SHARDX_TOKEN`  | —                        | Bearer token (Settings). Required.                  |
| `MCP_HTTP_PORT` | — (stdio)                | When set, serve HTTP at `127.0.0.1:<port>/mcp`.     |

## Tools

**API**

- `health_check` → confirms the launcher is reachable and auth works
- `startup_status` → reports launch-at-login registration plus embedded-API and client-spawned MCP modes
- `configure_startup(enabled, start_minimized?)` → updates the current user's Launcher startup entry; the API starts with the Launcher while the MCP process is still spawned on demand by its client
- `find_profile_by_name(query, exact?, limit?)` → safe profile summaries only
- `ensure_profile_started(profile_id? | profile_query?, exact?, headless?)`
  → idempotently starts one resolved profile and returns its CDP endpoint
- `safe_open_url(profile_id? | profile_query?, exact?, url, headless?, keep_running?, verification_timeout_ms?)`
  → opens an `http(s)` URL in the MCP-active tab and returns title/url plus
  Cloudflare challenge status. A profile started by this call is restored to
  stopped by default; set `keep_running: true` to retain that same tab for
  follow-up tab, screenshot, ARIA, or network tools, then call `stop_profile`.
  Automatic restoration is guarded by an opaque per-launch token, so a
  replacement process is never stopped solely because Windows reused its PID.
  A stopped profile is started only after Launcher advertises exact
  launch-instance ownership support; mixed old-Launcher/new-MCP installs fail
  before spawning a browser.
  Visible runs pause for manual verification for up to 120 seconds by default,
  then resume automatically when it clears; set `verification_timeout_ms: 0`
  to return immediately. Stale untracked processes are reported read-only;
  PID-only termination is intentionally disabled.
- `challenge_status(profile_id? | profile_query?, exact?)`
  → read-only inspection of the current page in an already-running profile;
  reports a Cloudflare interstitial or visible Turnstile widget to Launcher,
  persists a privacy-minimal checkpoint, and sends one Windows notification
  when a new verification handoff begins
- `verification_checkpoint(profile_id? | profile_query?, exact?)`
  → reads the pending verification checkpoint without starting, inspecting, or
  changing the profile; checkpoints contain no URL, token, cookie, profile
  name, fingerprint, or proxy data and expire after 24 hours
- `wait_for_human_verification(profile_id? | profile_query?, exact?, timeout_ms?)`
  → focuses an already-running profile and waits for a person to complete the
  verification; never clicks, solves, or bypasses challenge controls
- `devtools_context(profile_id? | profile_query?, exact?, headless?)`
  → starts/resolves one profile and returns its CDP endpoint, `/json/list`
  page targets, and the current title/url for DevTools handoff
- `cleanup_stale_profile_processes(profile_id? | profile_query?, exact?, dry_run?)`
  → reports untracked ShardX browser processes still holding that profile's
  user-data-dir; termination is disabled because a numeric PID cannot prove
  process ownership safely
- `list_profiles`, `get_profile`, `create_profile`, `create_temporary_profile`,
  `edit_profile`, `delete_profile`
  - `create_profile` / `create_temporary_profile` accept optional `launch`
    (`args`, `extension_dirs`); Launcher validates paths and safe switches at
    browser launch time.
- `new_fingerprint(platform?)`
- `start_profile(id, headless?)` → returns the CDP endpoint,
  `stop_profile(id)`, `list_running`
- `list_proxies`, `add_proxy`, `delete_proxy`
- `list_extensions`, `add_extension(url | path)`, `delete_extension` — a Web
  Store link or a bare extension id is enough; the launcher downloads the
  `.crx`. Pass the ids to `create_profile` / `edit_profile` as `extensions`.
- `list_bookmarks`, `save_bookmark(url, title?, folder?)`, `delete_bookmark` —
  bound to a folder they reach every profile in it on its next launch
- `list_trash`, `restore_profile(id)`, `purge_profile(id)` — `delete_profile`
  moves a profile here, restorable for 7 days
- `list_fingerprints`, `list_folders`, `rename_folder`, `delete_folder`
- `export_cookies`, `import_cookies(cookies | text)` — accepts Netscape
  `cookies.txt`, Cookie-Editor / EditThisCookie, Playwright / Puppeteer and
  ShardX cookies; entries that cannot be converted come back in `skipped`

**Browser (CDP via patchright)** — auto-starts the profile (CDP, optional
headless) if it isn't running; actions target the profile's *active* tab:

- Navigation: `browser_navigate(url, headless?)`, `browser_back`,
  `browser_forward`, `browser_reload`, `browser_current_url`
- Waiting: `browser_wait_for_selector(selector, state?, timeout_ms?)`,
  `browser_wait_for_load(state?)`, `browser_wait(ms)`,
  `browser_wait_for_url(url, timeout_ms?)`, `browser_wait_for_function(expression, timeout_ms?)`
- Read: `browser_content`, `browser_text`, `browser_get_html(selector?)`,
  `browser_get_text(selector)`, `browser_get_attribute(selector, name)`,
  `browser_exists(selector)`, `browser_count(selector)`,
  `browser_element_state(selector)`, `browser_bounding_box(selector)`,
  `browser_links`, `browser_evaluate(expression)`, `browser_get_cookies`
- Interact: `browser_click(selector)`, `browser_double_click(selector)`,
  `browser_right_click(selector)`, `browser_fill(selector, text)`,
  `browser_type(selector, text, delay_ms?)`, `browser_press(key)`,
  `browser_hover(selector)`, `browser_select_option(selector, value, by?)`,
  `browser_set_checkbox(selector, checked)`, `browser_focus(selector)`,
  `browser_drag(from, to)`, `browser_mouse_click(x, y)`,
  `browser_scroll(selector? | dx/dy)`, `browser_scroll_to_bottom`,
  `browser_set_files(selector, paths)`
- Human input (patched `Motion` domain — real pointer trajectories and
  key-by-key typing, produced inside the browser process):
  `human_click(selector | x,y)`, `human_move(selector | x,y)`,
  `human_fill(selector, text, clear?)`, `human_type(text)`,
  `human_release_pointer`
- Capture: `browser_screenshot(full_page?)`,
  `browser_element_screenshot(selector)`, `browser_pdf` (headless),
  `browser_set_viewport(width, height)`
- Storage / network: `browser_set_cookies(cookies)`, `browser_clear_cookies`,
  `browser_local_storage(action, key?, value?)`,
  `browser_set_extra_headers(headers)`, `browser_dialog(action, prompt_text?)`,
  `browser_block_resources(types)`
- Tabs: `browser_list_tabs`, `browser_open_tab(url?)`,
  `browser_switch_tab(index)`, `browser_close_tab(index?)`
- Frames: `browser_frames`, `browser_frame_evaluate(frame, expression)`
- Scrape / a11y: `browser_get_texts(selector)`, `browser_input_value(selector)`,
  `browser_insert_text(text)`, `browser_aria_snapshot(selector?)`
- Network: `browser_wait_for_response(url_pattern, timeout_ms?)`,
  `browser_capture_start` / `browser_capture_stop` (request log),
  `browser_mock(url_pattern, status?, body?, content_type?)` / `browser_unmock(url_pattern?)`,
  `browser_intercept(url_pattern, headers?, post_data?, abort?)` (modify in flight),
  `browser_set_network_conditions(offline?, latency_ms?, download_kbps?, upload_kbps?)`
- Keyboard: `browser_press_on(selector, key)`
- Downloads: `browser_wait_for_download(dir, timeout_ms?)`

(All take `profile_id` as the first argument.)

## Typical agent flow

1. `health_check` — fail fast when the launcher is closed or the token is stale.
2. `find_profile_by_name` or `create_profile` / `create_temporary_profile`.
3. `safe_open_url` for a one-shot smoke check (default restore),
   `safe_open_url(..., keep_running: true)` when follow-up tools must reuse its
   active tab, or
   `browser_navigate(profile_id, "https://…")` — starts the browser with
   CDP and opens the page.
3. `browser_evaluate` / `browser_screenshot` / `browser_click` / `browser_fill`.

### Human input

`browser_click` and `browser_fill` go through Playwright: instant, and
they look it. The `human_*` tools go through the patched core's `Motion`
domain instead — the pointer travels a real trajectory whose duration
obeys Fitts's law, and text is typed key by key with log-normal gaps,
digraph-dependent timing and key overlap. Nothing is injected into the
page to do it.

They take the same selectors as everything else; the wrapper resolves the
element, scrolls it into view, and hands the core the coordinates and the
element's real width (which is what makes a small target take longer to
reach than a large one). Give `x` and `y` instead of a selector when you
already know where to go.

```
human_fill(profile_id, "#email", "ada@example.com")
human_fill(profile_id, "#email", "new@example.com", clear: true)
human_click(profile_id, "button[type=submit]")
```

`clear: true` selects the current value with a triple click rather than a
keyboard shortcut, so the clearing is as human as the typing. `human_type`
types into whatever has focus, for the cases where the focus is already
where you want it.

These calls take **real time** — `human_fill` returns when the last key is
up, and reports how long the move and the typing took. Budget for it the
way you would for a person.
4. `stop_profile` when done (temporary profiles self-delete on close).
4. `devtools_context` when handing the live ShardX page to a DevTools client.
5. If navigation reports `challenge.detected`, ShardX records a checkpoint and
   sends one Windows notification. After an MCP/client restart, call
   `verification_checkpoint` to recover that handoff state. Complete
   verification manually in the visible browser, then use
   `wait_for_human_verification` before continuing automation.
6. `browser_evaluate` / `browser_screenshot` / `browser_click` / `browser_fill`.
7. `stop_profile` when done (temporary profiles self-delete on close).

For owner-side Cloudflare tuning and rollback guidance, see
[`docs/CLOUDFLARE_VERIFICATION.md`](../docs/CLOUDFLARE_VERIFICATION.md).
For an authorized, non-browser fallback for WordPress plugin administration,
see [`docs/WORDPRESS_WPCLI_FALLBACK.md`](../docs/WORDPRESS_WPCLI_FALLBACK.md).

## Troubleshooting Hermes registration

ShardX Settings can inspect the Hermes entry locally: **Check Hermes
registration** is the card primary action. It reads the resolved entry with
`hermes config get mcp_servers.shardbrowser` and compares it against the
selected `index.js` path and the running Automation API URL. As with the Codex
check, it only reports whether `SHARDX_TOKEN` is present in config and never
prints the value.

| Reported state | What it means | What to do |
| --- | --- | --- |
| `registered` | Entry matches the selected folder and API | Restart Hermes, then call `health_check` |
| `not_registered` | Hermes has no `shardbrowser` entry | Run the add command above |
| `disabled` | Entry exists but is switched off | Re-add it, or set `enabled: true` |
| `needs_repair` | Path, API, or token placement is wrong | Use **Copy Hermes add command**, then run it |
| `hermes_not_found` | `hermes` is not on `PATH` | Install or open Hermes, reopen the shell |
| `timeout` | Hermes did not answer within 4 seconds | Retry once Hermes has finished starting |

The specific mismatches it can report are: the entry is disabled, the `index.js`
path does not match the selected MCP folder, the path could not be verified,
`SHARDX_API` does not match the current Automation API URL, `SHARDX_API` is not
configured, and `SHARDX_TOKEN` is stored in Hermes config.

That last one is a configuration problem even though the server still runs: keep
the token in the Windows User environment so it does not sit in a config file
that gets copied or shared. Remove it from the entry and re-add the server
without `SHARDX_TOKEN`.

A repaired entry does not take effect until Hermes restarts, because MCP tools
are loaded once at startup. If `health_check` still fails afterwards, the
problem is the Automation API rather than registration: confirm the Launcher is
running and that the port in `SHARDX_API` matches its current one.

## Chrome DevTools MCP handoff

`devtools_context` exposes the browser's `cdp.http_url` and
`web_socket_debugger_url` without returning tokens, cookies, fingerprints, or
proxy credentials. Use that URL to configure a DevTools MCP server that supports
connecting to an existing browser, for example:

```powershell
codex mcp add shardbrowser-devtools -- cmd /c npx -y chrome-devtools-mcp@1.5.0 --browserUrl http://127.0.0.1:<cdp-port> --no-usage-statistics --no-performance-crux --redactNetworkHeaders
```

Codex's built-in `chrome_devtools` tools do not expose a runtime attach/connect
call; the DevTools MCP server chooses the browser at MCP startup. If the CDP
port changes, update the MCP client entry and restart the MCP client.

If a profile is already running without CDP, `devtools_context` cannot retrofit
the debugging port into that process. Stop and restart the profile through MCP
or the Automation API, then call `devtools_context` again.
