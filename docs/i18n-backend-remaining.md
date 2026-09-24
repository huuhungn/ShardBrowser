# What is left of the backend's English

`fleet_client.rs`, `launch.rs`, `profile.rs`, `proxy.rs`, `extensions.rs` and
`runner.rs` are done: every message they can put in front of an operator is an
error code. This is the survey of what remains, measured rather than guessed,
so the next slice can be picked by how often an operator actually hits it.

**Baseline: 127.** It was 238 before `fleet_client.rs`, 207 after it, 177 after
`launch.rs` + `profile.rs`, and 127 after `proxy.rs` + `extensions.rs` +
`runner.rs`. 7 of the 127 are `api.rs` and are meant to stay English, so 120
are still worth translating.

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

## The remaining 120, by who actually reads them

Ranking by count alone is misleading. `files.rs` has the most strings left, but
its errors are raised inside automation blocks (`readFile`, `writeFile`) and
propagate through `runner.rs` into the step table, where the reader is the
person who wrote the project — the same audience as `db.rs` and
`http_session.rs`. Those three are one slice, not three.

**Operator-facing (32).** Someone using the interface hits these.

| Count | Area | Files |
|------:|------|-------|
| 18 | everyday: assorted commands | `lib.rs` |
| 6 | recovery: backup/restore | `backup_cmd.rs` |
| 8 | fleet: sync and enrolment | `sync_cmd.rs` |
| 3 | installer | `updater.rs` |

`sync_cmd.rs` is the strongest candidate: `no team server configured — set one
in Settings` and `this device is not enrolled — enroll it in Settings` both
tell an operator where to go, which is exactly the kind of sentence that is
useless in a language they do not read.

**Automation-author-facing (30).** Read in the step table or an API response
by whoever wrote the project.

| Count | Area | Files |
|------:|------|-------|
| 15 | file blocks | `files.rs` |
| 9 | database blocks | `db.rs` |
| 6 | HTTP blocks | `http_session.rs` |

These carry instructions in the same voice as the `runner.rs` messages already
coded (`a block runs one statement; remove the ';' and use a second block`,
`no HTTP session is open for this profile; add an httpOpen block first`), so
they belong with that pass for consistency.

**Internal (51).** Technical breadcrumbs, mostly `.context()` on a lock or a
socket: `cdp lock poisoned`, `list targets`, `probe timed out`. Their reader is
whoever is reading a log, and a translated log entry is harder to search, not
easier. Leave them.

| Count | Files |
|------:|-------|
| 10 | `cdp.rs` |
| 8 | `gpu_caps.rs` |
| 7 | `api.rs` (deliberately English — see below) |
| 26 | the remaining 14 files, 1-4 each |

## Suggested order

1. ~~**`launch.rs` (19) and `profile.rs` (11).**~~ Done.
2. ~~**`proxy.rs` (14) and `extensions.rs` (10).**~~ Done.
3. ~~**`runner.rs` (26).**~~ Done.
4. **`sync_cmd.rs` (8), `backup_cmd.rs` (6), `updater.rs` (3).** Operator-facing
   and instructional — the highest value left.
5. **`lib.rs` (18).** Operator-facing but scattered across 110 commands, so it
   is the widest diff for the fewest related strings.
6. **`files.rs` (15), `db.rs` (9), `http_session.rs` (6).** Finishes the
   automation-author surface `runner.rs` started.
7. Internal breadcrumbs: leave them English.

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
  the JSON: it is the only way to prove the drop matches real removals. Filter
  by filename rather than by parsing the failure message — the message escapes
  its strings, and decoding those escapes corrupts any value containing a
  backslash or an em dash.

## Pitfalls found during the proxy/extensions/runner pass

- **Check whether anything switches on the English before coding a module.**
  `api.rs` picked its HTTP status by searching the message for `is not
  running`; coding that sentence silently turned a 409 into a 500. Classify
  refusals with a typed error and `downcast_ref` (`RunRefusal` in `runner.rs`,
  `ProfileErrorKind` in `profile.rs`), never by matching prose. Grep for
  `.contains("` over the module's own sentences first.
- **Argument values need escaping, not stripping.** `code_with` used to delete
  `|` and `]` from values so they could not break the marker. That silently
  corrupted the one thing the message existed to show — a CSS selector like
  `a[href='/x?a=1|2']` arrived as `a[href='/x?a=12'`. They are percent-escaped
  now and decoded on both sides; add a round-trip test when touching this.
- **Find the UI that renders the string, not just the one that toasts it.**
  Three places printed backend text straight into the DOM without
  `safeUiError`: the automation step table (`step.error`), the proxy tooltip
  (`udp_error`, read back out of `proxies-history.json`), and the bulk
  importer. A coded message in any of them renders as `[[shardx:...]]`.
- **`replaceAll` is not available.** The frontend's TS target predates it; use
  a global regex.
