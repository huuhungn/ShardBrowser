# Remaining Rust strings: what to translate and what to leave

117 strings survive the guard after files.rs was coded. They are not
all worth a key, so each one was traced to the exit that shows it and
sorted by that, not by wording.

| verdict | count | meaning |
| --- | --- | --- |
| translate | 79 | an operator reads it in a toast and can act on it |
| script-only | 21 | api.rs answers HTTP JSON; a script gets English by contract |
| label | 13 | a .context() breadcrumb naming a step, printed behind the real error |
| internal | 4 | an invariant the operator cannot act on |

## Correction: the "label" and "internal" verdicts were wrong

The two verdicts below were built on the belief that a `.context()`
breadcrumb is printed *behind* the real error. It is not. `anyhow`'s
`Display` prints **only the outermost context**, and `{:#}` prints the
chain outermost-first. Every caller that reports with `e.to_string()`
— `automation_run`, the Tauri commands, the toast path — therefore
shows the breadcrumb *instead of* the cause, not after it.

Re-tracing each one to its exit:

| string | verdict | why |
| --- | --- | --- |
| cdp.rs, all 10 | translate | done; shipped in #64 |
| cookies.rs, 3 | translate | `read_key` → `os_crypt_key` → `export` → `cookies_export`, all bare `?`; the breadcrumb is what the operator reads |
| mcp_setup.rs, 2 | translate | `download_mcp` → `mcp_download` → `.map_err(|e| e.to_string())` |
| profile_icon.rs, 2 | translate | `ensure_icon` → `launch`, which is a toast path |
| gpu_caps.rs, 1 | translate | done below, with the other 7 |
| sync_bus.rs, 1 | leave | logged at startup, never shown; the only true label |
| fleet_client.rs, 2 | **bug, not a label** | see below |

`fleet_client.rs` was not a wording problem. `ok_or_err(res, key)` and
`decode_hex32(s, field)` both expect a **locale key**, and three call
sites passed an English phrase instead: `"open upload"`, `"commit
upload"`, `"challenge nonce"`. The first two became `[[shardx:open
upload|...]]`, a marker with no entry, so the operator read the raw
marker; the third was spliced into `{field}` of an already-translated
sentence, leaving English inside Vietnamese. Fixed with real keys, and
the nonce one nests a marker so the inner label is translated too.

So of the 11 remaining "labels", 9 needed translating, 1 is a genuine
label, and 2 were bugs. The verdict counts in the table above are kept
as first written, to show what the heuristic got wrong.

## Worth translating

### db.rs (10)
- a block runs one statement; remove the ';' and use a second block
- a parameter must be a string, number, boolean or null, not {other}
- a parameter number is out of range: {n}
- the database {} could not be opened
- the folder for {} could not be created
- the query could not be prepared: {sql}
- the query failed: {sql}
- the query returned more than {MAX_ROWS} rows; add a limit or a where clause
- the statement could not be prepared: {sql}
- the statement failed: {sql}

### runner.rs (10)
- every request matching {url_part:?} failed — {worst}
- expected {selector} to contain {expected:?}, saw {:?}
- no HTTP session is open for this profile; add an \"httpOpen\" block first
- no request matching {url_part:?} was made ({} recorded so far)
- the profile is not attached — start it before running a project
- the query returned {} rows, fewer than the {least} required
- this build cannot run the {kind:?} block ({id}); remove or disable it first
- this project loops forever: set a pass count or a time limit
- traffic is already being recorded; stop it before starting again
- {method} {url} answered HTTP {}, not a success

### gpu_caps.rs (7)
- connect to the core's debugging port
- core did not open a debugging port
- engine is not installed yet
- no config dir
- probe returned no value
- probe timed out
- the engine reported no WebGL at all

### http_session.rs (7)
- no HTTP session is open for this profile; add an httpOpen block first
- profile {profile_id} could not be read
- profile {profile_id} is bound to proxy {} which cannot be used for HTTP
- the HTTP client for this profile could not be built
- the request to {url} did not complete
- the response from {url} could not be read
- {method} is not an HTTP method

### migrate.rs (5)
- a migration is already running
- that is already where the data lives
- the new folder cannot be inside the current one
- {} did not copy cleanly — nothing was deleted
- {} is not writable

### runtime.rs (5)
- This engine build needs ShardX Launcher {} or newer — you are on {}. Update the launcher first.
- platform data dir not available
- system `unzip` not found ({e}); install with `apt install unzip` / `brew install unzip`
- unzip failed for {} (exit {}): {}
- widevine parent

### cdp.rs (4)
- no session id for the page
- the profile has no page to drive
- this profile is not attached
- this profile is not attached

### psapi.rs (4)
- ProxyShard API key not set
- Unauthorized — check your API key
- request to ProxyShard failed
- unsupported method {other}

### api.rs (3)
- API server stopped: {e}
- Could not bind {addr}: {e}
- Could not disable API listener inheritance: {e}

### automation.rs (3)
- no such project
- no such project
- this project was exported by a newer build (format {}, this build reads {})

### fleet_keys.rs (3)
- fleet key is not valid hex
- fleet key is not valid hex
- fleet key must be 32 bytes

### startup.rs (3)
- Windows application restart registration failed (HRESULT 0x{:08X})
- the operating system did not disable the startup entry
- the operating system did not enable the startup entry

### cookies.rs (2)
- DPAPI {} failed
- encrypted_key missing DPAPI tag

### fingerprints.rs (2)
- invalid fingerprint id
- not a valid JSON FingerprintConfig

### mcp_setup.rs (2)
- MCP archive contained no files (CDN delivered an empty bundle?)
- MCP archive request failed

### team_config.rs (2)
- device HPKE key is missing or corrupt; re-enroll this device
- device signing key is corrupt

### traffic.rs (2)
- the profile is not attached — start it before recording traffic
- the profile would not report its network activity

### trash.rs (2)
- archive has no profile.json
- invalid profile id

### codex_mcp.rs (1)
- Codex CLI returned a response that ShardX could not parse as JSON.

### fleet_client.rs (1)
- server returned no bytes at offset {} of {total}

### store.rs (1)
- OS config dir unavailable

## Leave English: script contract

### api.rs (21)
- `fingerprint` must be an object
- `port` required
- `proxy` string or host+port required
- `url` or `path` required
- `{key}` must be an object
- block {block_id} has unknown kind \"{kind}\"
- custom fonts are not available: browser-engine coherence has not been verified
- expected_pid must be positive
- fingerprint library is empty
- kind must be interstitial or turnstile when verification is required
- launch_instance_token must be a UUID
- launcher startup manager is not initialized
- legacy PID-only conditional stop is disabled; use stop-if-launch-instance
- no such extension: {}
- profile is not running
- profile {id} launch instance changed while pid {pid} was reused
- profile {id} process changed: expected pid {expected_pid}, running pid {actual_pid}
- unparseable proxy: {pstr}
- unparseable proxy: {pstr}
- unparseable proxy: {pstr}
- unparseable proxy: {s}

## Leave English: context breadcrumbs

### cookies.rs (3)
- base64 encrypted_key
- parse Local State
- read Local State

### cdp.rs (2)
- attach to page
- list targets

### fleet_client.rs (2)
- challenge nonce
- commit upload

### mcp_setup.rs (2)
- download MCP archive
- read MCP archive

### profile_icon.rs (2)
- allocate pixmap
- write icon png

### gpu_caps.rs (1)
- start the engine for a GPU probe

### sync_bus.rs (1)
- bind sync bus

## Leave English: internal invariants

### cdp.rs (4)
- cdp connection closed
- cdp connection closed
- cdp lock poisoned
- cdp lock poisoned

## Closing the sweep

Every string the guard tracked is now either coded or exempt, and the baseline
list is empty. What the last pass changed about the earlier verdicts:

- `sync_bus.rs` "bind sync bus" was filed under labels that only reach a log.
  It does not: `lib.rs` starts the bus with `.map_err(|e| e.to_string())`, so a
  loopback port that will not bind becomes a toast. Coded.
- `profile_icon.rs` was filed the other way round, as user-facing. Its one
  caller, `launch.rs`, prints the error with `eprintln!` and launches the
  profile anyway. The operator gets a profile with no icon and never reads the
  sentence. Left English, recorded under `deliberately_english`.
- `api.rs` keeps its 24 strings. Twenty-one answer a script in JSON. The other
  three land in `ApiRuntimeStatus.error`, and `McpCard.tsx` only tests that
  field for presence before rendering its own `mcp.bindFailed` — nothing prints
  the English.

Coding `automation.rs` also exposed a real defect rather than a wording
problem. `run_automation_project` chose its HTTP status by searching the error
text for `"no such project"`, so the moment that sentence became a code the
automation API answered 500 where it had answered 404. Status routing now
matches on the code through `errcode::has_code`, which compares at a marker
boundary so one key is never mistaken for a longer one.

The guard grew a `deliberately_english` map keyed by file. An entry states why
the file's English is correct, and a second test fails when an exempted file
stops producing English at all, so an exemption cannot quietly become a hiding
place for new strings.
