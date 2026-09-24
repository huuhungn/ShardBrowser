# What is left of the backend's English

`fleet_client.rs`, `launch.rs` and `profile.rs` are done: every message they
can put in front of an operator is an error code. This is the survey of what
remains, measured rather than guessed, so the next slice can be picked by how
often an operator actually hits it.

**Baseline: 177.** It was 238 before `fleet_client.rs`, 207 after it, and 177
after `launch.rs` + `profile.rs`. 7 of the 177 are `api.rs` and are meant to
stay English, so 170 are still worth translating.

## How these numbers were produced

The guard's baseline (`scripts/rust-user-strings.baseline.json`) counts English
sentences, but a count alone does not say whether anyone ever reads them. So
each string was located in its enclosing function, and the call graph was
walked backwards from every `#[tauri::command]`.

- 860 functions parsed, 122 of them Tauri commands
- 526 functions reachable from a command
- all baseline strings located, none unaccounted for

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

So the real figure at the time of the survey was **200 toast-reachable
strings, not 207**. After the `launch.rs` and `profile.rs` pass: **170**.

## The remaining 170, by how routinely an operator meets them

| Count | Area | Files |
|------:|------|-------|
| 26 | automation: running projects | `runner.rs` |
| 18 | everyday: assorted commands | `lib.rs` |
| 15 | everyday: file/profile storage | `files.rs` |
| 14 | everyday: proxy setup | `proxy.rs` |
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

1. ~~**`launch.rs` (19) and `profile.rs` (11).**~~ Done.
2. **`proxy.rs` (14) and `extensions.rs` (10).** Setup paths, hit whenever the
   fleet changes.
3. **`runner.rs` (26).** The largest block, and unblocked now: see
   "How the HTTP API handles a code" below.
4. **`sync_cmd.rs` (8) and `fleet_keys.rs` (3).** Finishes the fleet surface
   that `fleet_client.rs` started.
5. Recovery and diagnostic paths last — rare, and their readers are usually
   already debugging.

## How the HTTP API handles a code

An error code is written for the interface, which knows the operator's
language. The automation HTTP API has no such reader: a script author sees the
raw JSON, so `[[shardx:profile.parseRecord]]` there is strictly worse than the
sentence it replaced.

`ApiError::into_response` resolves the marker to English before serialising
(`src-tauri/src/api.rs`). That is the single choke point — all 69 error sites
in `api.rs` go through it — so nothing else has to know about codes.

The English comes from `src/shared/i18n/locales/en.json`, compiled in with
`include_str!`. Using the interface's own file rather than a second table in
Rust is what stops the two from drifting: a renamed key breaks the Rust test
that checks every emitted code exists in the dictionary.

This means the rest of the backend can move to error codes without changing
what a script sees. Behaviour by caller:

| Caller | Sees |
|--------|------|
| interface (toast) | Vietnamese, via `localiseBackendError` |
| HTTP API (script) | English, via `ApiError` |
| logs | the raw marker |

Two things to keep in mind when coding a new module:

- **Every code must exist in `en.json`.** `every_code_emitted_by_rust_exists_in_the_dictionary`
  scans the source for `code("…")` and fails on a key with no entry, so a typo
  cannot ship. It skips `errcode.rs`, whose doc comments carry deliberately
  fake keys.
- **A test asserting on the old English will fail.** That is the point — it is
  how you find the ones that were checking the message rather than the
  behaviour. Assert on the code instead, and keep any assertion about the
  runtime value (a path, an id) that the sentence carries.

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
