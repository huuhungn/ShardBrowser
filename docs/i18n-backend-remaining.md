# What is left of the backend's English

`fleet_client.rs` is done: every message it can put in front of an operator is
an error code. This is the survey of what remains, measured rather than
guessed, so the next slice can be picked by how often an operator actually
hits it.

## How these numbers were produced

The guard's baseline (`scripts/rust-user-strings.baseline.json`) counts English
sentences, but a count alone does not say whether anyone ever reads them. So
each string was located in its enclosing function, and the call graph was
walked backwards from every `#[tauri::command]`.

- 860 functions parsed, 122 of them Tauri commands
- 526 functions reachable from a command
- all 207 baseline strings located, none unaccounted for

Two facts worth keeping, because both reversed an assumption made while
looking into this:

**Every toast is already translated and redacted.** 113 call sites use
`toast.err(...)`, and only 10 pass `safeUiError` explicitly — which looks like
a 67-site hole until you read `src/shared/model/toast.ts:37`, where `err()`
applies `safeUiError` itself. Do not "fix" the call sites; there is nothing
wrong with them.

**`api.rs` is not a toast surface.** It is the local automation HTTP API
(axum, `127.0.0.1:<api_port>`), and its errors leave as
`Json({"error": ...})` to a script, not to a human. Its 7 strings should stay
English. They are the only baseline strings that are not toast-reachable.

So the real figure is **200 toast-reachable strings, not 207**.

## The remaining 200, by how routinely an operator meets them

| Count | Area | Files |
|------:|------|-------|
| 26 | automation: running projects | `runner.rs` |
| 19 | everyday: starting a profile | `launch.rs` |
| 18 | everyday: assorted commands | `lib.rs` |
| 15 | everyday: file/profile storage | `files.rs` |
| 14 | everyday: proxy setup | `proxy.rs` |
| 11 | everyday: profile CRUD | `profile.rs` |
| 10 | everyday: browser control | `cdp.rs` |
| 10 | everyday: extensions | `extensions.rs` |
| 9 | recovery: database | `db.rs` |
| 8 | diagnostic: GPU probe | `gpu_caps.rs` |
| 8 | fleet: sync commands | `sync_cmd.rs` |
| 6 | diagnostic: HTTP session | `http_session.rs` |
| 6 | recovery: backup/restore | `backup_cmd.rs` |
| 4 each | cookies, migrate, psapi, MCP wiring | `cookies.rs`, `migrate.rs`, `psapi.rs`, `mcp_setup.rs` |
| 3 each | fleet device keys, installer | `fleet_keys.rs`, `updater.rs` |
| 1-2 each | the remaining 10 files | |

## Suggested order

1. **`launch.rs` (19) and `profile.rs` (11).** Starting a profile is the first
   thing an operator does and the most common place to fail. Highest value per
   string.
2. **`proxy.rs` (14) and `extensions.rs` (10).** Setup paths, hit whenever the
   fleet changes.
3. **`runner.rs` (26).** The largest block, but it has two callers: the Tauri
   command `automation_run` (`lib.rs:938`, reaches a toast) and the HTTP API
   (`api.rs:914-939`, does not). Coding these means the API starts returning
   markers to scripts, so decide first whether `ApiError` should resolve a code
   back to English before serialising.
4. **`sync_cmd.rs` (8) and `fleet_keys.rs` (3).** Finishes the fleet surface
   that `fleet_client.rs` started.
5. Recovery and diagnostic paths last — rare, and their readers are usually
   already debugging.

## Pitfalls carried over from the fleet_client pass

- `anyhow` joins a context to its cause with `": "`. A locale string ending in
  a period renders as `".: connection refused"`. Context strings must not end
  in one; `npm run vi:toasts` fails on the seam.
- Do not pass a sentence fragment as a variable. An `ok_or_err("claim this
  profile")` shape forces the frontend to resolve one locale key inside
  another's argument. Give each call site its own code.
- Keep `{e:#}` in context chains. It is what preserves the inner cause
  (connection refused, parse error) behind the localised label.
- Lower the guard baseline with the guard's own scanner, never by hand-editing
  the JSON: it is the only way to prove the drop matches real removals.
