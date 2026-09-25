# Changelog

## v2.2.9

### Fixed

- Four small labels that stayed English through a release that translated every
  screen around them: the sidebar's API pill, the patch log's version marker and
  its locked badge, and the tags on each patch log entry. They were written into
  the code rather than read from a translation file. An entry tag's colour still
  comes from the value stored with the entry, so translating the label changes
  what you read without changing what you see.
- The check for untranslated interface text no longer walks past short labels.
  One rule wanted a leading capital, so a lowercase badge was invisible to it;
  another wanted two letters before the text began, so a pill sitting between
  its tags on one line slipped through. The check now reads the line above to
  tell a label someone reads from a setting the code passes along.
- A slow asset upload no longer fails a release that already published. Version
  2.2.7 uploaded all twenty of its files and still reported failure: one file
  stalled for 148 seconds of a 197 second step, and the error arrived after the
  work was done. The upload is now retried once, and the action that performs it
  is pinned to an exact revision rather than a moving tag. A retry replaces what
  the first attempt sent, so nothing uploads twice, and a release that genuinely
  cannot publish still reports failure.

## v2.2.8

### Added

- The launcher speaks Vietnamese. Every screen, menu, button, toast and error
  message now comes from a translation file rather than being written into the
  code, and the language is chosen in Settings under Language. The choice
  survives a restart. Nothing about a profile changes with it — the interface
  language is not part of a browser's fingerprint.
- A profile can be driven through a scripted list of steps, and a probe reports
  whether a profile's GPU story is internally consistent.

### Fixed

- Errors raised by the engine reach the operator in their own language. A
  command that failed used to answer in English no matter the setting, because
  the message was built in Rust and handed straight to the toast. Roughly
  twenty groups of them were moved across: profiles that will not start,
  proxies, extensions, backups, cookies, the database, the automation runner,
  the graphics probe, engine download and migration.
- Toasts no longer show raw error markers. Twelve of them printed an internal
  code beside the message, which told the operator nothing and hid the part
  that mattered.
- Menu entries and dialog questions that were still English are translated.
  Three profile-menu items, two confirm questions and one Settings button had
  been missed because the guard that looks for untranslated text could not see
  a label ending in `…` or `?`, nor a button whose label is a single word.
- The patch log reads in Vietnamese, and the paths it tells you to click match
  the labels actually on screen. Four of them named Settings cards by a name
  the interface never used, so the instruction pointed at nothing.

### Internal

- The translation guard covers the shapes that hid real text: labels ending in
  punctuation, single-word buttons, prose in a plain `.ts` module, text frozen
  at import time, and instructions that quote an interface label. Each rule was
  checked by breaking it on purpose and confirming the suite fails.
- CI checks Rust formatting and runs Clippy.

## v2.2.7

### Fixed

- The profile and proxy tables no longer run past the right edge of a narrow
  window. On a portrait monitor the content column is about 780px wide, but
  the narrowest layout still asked for 904px, and the table clipped the
  overflow instead of scrolling it — the Start button and the row menu were
  simply unreachable. Narrow windows now drop the columns that repeat
  elsewhere, and anything still too wide scrolls rather than disappearing.
- Column headings line up with their rows again below 1280px. The Last run
  cell was hidden in the rows but not in the heading, so every heading after
  Notes sat above the wrong column.

## v2.2.6

### Added

- The patch log can be reopened from Settings, under What's new. The launcher
  shows it once after an update and records the version, so closing the page
  put the notes out of reach — awkward when the update lands mid-task, or when
  somebody else installs it on a shared machine. The sidebar's Patch log entry
  already led there; the button puts a door where people go looking.

## v2.2.5

### Added

- A profile's session restore can be turned on and off from the profile editor,
  under Privacy. Automation profiles accumulate tabs nobody closes, and
  reopening all of them on every launch costs time for no gain. Profiles
  without the setting keep restoring, exactly as before.

### Fixed

- The Shard Helper panel no longer deadlocks the launcher on Windows. Building
  the webview from a synchronous command occupied the message loop WebView2
  itself needs, so the panel came up blank and the whole window stopped
  responding.
- A browser that exits no longer leaves a phantom "Running" row behind. The
  bookkeeping that runs at exit could fail (a profile that is missing or has
  unreadable JSON) and abandon the tracker entry, stranding a Stop button that
  could never clear because the process it referred to was already gone.
- Pressing Stop on a row whose browser has already exited clears that row and
  says so, instead of doing nothing.
- Losing contact with the backend surfaces an error and empties the running
  list after three consecutive failures, rather than freezing the last known
  state on screen indefinitely.
- Starting or stopping several selected profiles at once reports what failed.
  Both paths discarded every error, so ten selected profiles yielding three
  browsers looked exactly like success.
- Closing every window in a sync group clears that group's state. Suspension,
  layout, and driving-member records were keyed by group name and outlived the
  group itself, so a new browser joining under a previously suspended group
  name arrived suspended with nothing on screen to explain why.
- `rustls` is updated to 0.23.45 in the launcher and server lockfiles, clearing
  RUSTSEC-2026-0285.

## v2.2.4

### Changed

- The Rust SDK is tested on Windows and macOS. Its host probes and runtime
  layout branch on the operating system, and those branches were compiled but
  never exercised anywhere: the crate reported `0 tests` while passing.
- The SDK's suite runs in the release build on all three platforms, so a
  platform-specific fault blocks publishing instead of reaching an installer.

### Fixed

- The SDK's display parsing rejects malformed geometry instead of accepting it.
  Twelve unit tests now cover screen and memory probing, the archive and
  executable layout for each platform, and the cache directory each one uses.
  Each assertion was verified against a deliberately broken build.

## v2.2.3

### Fixed

- Snapshot restore is verified correctly on Linux and macOS. Two round-trip
  tests asserted that a restored profile contains `Local State`, which
  snapshots deliberately exclude because the key it holds is bound to one
  machine. The file reappeared on Windows only because the key lives there and
  is minted on first read, so a Windows-specific side effect was being
  asserted as a cross-platform rule.

### Changed

- The Rust crates are tested on Windows in CI. Every runner was Linux, so the
  `cfg(windows)` half of the codebase — os_crypt key handling, cookie
  decryption, process control and autostart — was never compiled or tested
  there, on the launcher's primary platform.
- The shared core's tests and the interface toolkit's lint run in CI. The
  shared core is linked into the launcher, yet its tests had never run: a
  crate compiled as a dependency is not tested by its dependent.
- A release stops on a missing changelog section before any installer is
  built, rather than after all three platform builds finish.
- The interface toolkit is free of lint warnings. The theme and link contexts
  moved out of their provider modules so those files export components only,
  which restores state-preserving refreshes during development. The package's
  public API is unchanged.

## v2.2.2

### Security

- The release gate audits every lockfile that ships. It previously covered
  five of eight: `ui-kit` is compiled into each bundle by the prebuild step,
  `shared` links into the launcher as `shardx-core`, and `server` is
  published as a release asset, yet none of the three were scanned.
- `event-listener` and `spin` are updated in the team server, clearing an
  unsoundness advisory and a yanked release.
- RUSTSEC-2023-0071 (`rsa`) has no fixed release and is exempted with the
  reasoning recorded in the workflow: `rsa` enters the lockfile only through
  the `sqlx` MySQL feature, which the server does not enable, and a release
  build emits no `rsa` artifact. The exemption lapses if a MySQL backend is
  ever switched on.

## v2.2.1

### Security

- The Node SDK no longer bundles `adm-zip`, which followed archive entries
  that escape the extraction directory and let a crafted archive overwrite
  arbitrary files (GHSA-vwc7-r8mq-g2x9). No patched release exists: 0.6.0 is
  the newest version, and the automated fix downgrades to 0.5.8, which
  carries a high-severity 4GB-allocation advisory instead.
- Windows now extracts runtime archives with bsdtar (`tar.exe`, shipped
  since Windows 10 build 17063); macOS and Linux continue to use the system
  `unzip`. Neither writes outside the destination directory.
- `hono` is pinned past three advisories that reached the MCP package
  through the Model Context Protocol SDK.

### Release integrity

- The release workflow verifies every updater signature in the generated
  manifest before uploading it, so a manifest that would fail auto-update
  cannot be published.

### Continuous integration

- CI runs the Node SDK tests, which previously ran only during a release.

## v2.2.0

### MCP host

- Settings now leads with **Check Hermes registration**. Hermes is the
  primary MCP host for this fork, so its check is the primary action and
  the Codex check moves under Advanced actions.
- A new Hermes probe reads the resolved entry from
  `hermes config get mcp_servers.shardbrowser` and compares it against the
  selected `index.js` path and the running Automation API URL. It reports
  only whether `SHARDX_TOKEN` is present, never its value.
- The Codex repair copy is always available under Advanced actions. It was
  previously hidden whenever it duplicated the primary action, which would
  have left a broken Codex entry with no way to copy its repair command.

### Documentation

- `mcp/README.md` documents Hermes registration and maps each reported
  state to the action that resolves it.

## v2.1.2

### Patch log

- Ships the 2.1.0 and 2.1.1 patch log entries, which landed on main after the
  2.1.1 tag was cut. Without this release the installed app badges 2.0.1 as
  the latest entry and records nothing about the two releases since.

## v2.1.1

### Launcher

- An engine install now stops before deleting anything when a profile still
  has the browser open, and names the profiles it is waiting on. Replacing a
  held-open engine previously left it half written, which made the setup
  screen reappear on every launch.
- Settings offers **Use existing MCP folder** beside the download button, so
  the launcher can adopt an MCP server you already have instead of
  downloading a second copy.
- A running profile's window can be raised when a site is waiting on a human
  check.
- The Ctrl K search shortcut hint no longer wraps onto two lines.

## v2.1.0

### Team and profiles

- A device can be enrolled with a team server to sync encrypted profiles
  between machines.
- Profiles can be backed up and restored as ciphertext, keyed to your fleet.

### Engine

- The launcher checks the published engine hash before deciding an update is
  needed, so the pinned manifest decides rather than a version string.

## v0.2.4

### Root key custody

- Tenant root keys now have a recorded lifecycle. A generation is created in
  `PREPARING`, is activated only once its first grant exists, and grants are
  refused unless they name a generation that exists, is not retired, and
  wraps that generation's key.
- The first grant for a generation must be a `FirstRootSelfGrant`, and a
  second one is refused. Custodian-issued grants are only accepted afterwards,
  so a tenant cannot end up with two competing roots.
- Enrolled devices keep the HPKE private key generated during enrollment.
  Previously it was discarded, so a device could be sent a wrapped root key it
  could never open. Devices enrolled before this change are reported as unable
  to receive custody, and Settings says so rather than failing later.
- The Launcher can collect and open its own grants (`team_collect_custody`).

### Releases

- Releases now ship `shardx-team-server-<platform>` for all three platforms.
  The grant and generation endpoints are server-side, so earlier releases
  delivered them as source only. The release job fails if a server binary is
  missing rather than publishing an incomplete set.

### Note on scope

Profile sync still derives its file key from a passphrase. Moving sync onto
fleet keys needs the fleet key generation and grant tables that the plan
specifies, which are not built yet; the root key work here is the layer
underneath that. This release is not production-ready.

## v0.2.3

Tenant root key grants are stored and retrievable, and a class of silently
swallowed database errors is closed.

### Key custody

- `POST /v2/tenant-root-key-grants` now stores the grant it verifies. It
  previously checked the signature and discarded the payload, so
  `v2_tenant_root_key_grants` never held a row and a second device had no way
  to obtain the tenant root key.
- Add `GET /v2/tenants/:tenant/devices/:device/root-key-grants` to collect a
  device's sealed grants. Storing grants without a way to read them back would
  not have moved custody forward.
- Grant fields are read from the signed field map rather than the request body.
  A caller who could pair another issuer's signature with their own account and
  device ids would redirect the custody that signature authorises.
- The collection route derives tenant membership from the session, not the
  path, matching the fix in #21.
- `seal_trk` and `open_trk` now have a runtime caller and end-to-end coverage:
  a grant is sealed, filed, collected, and opened with the device's private key
  to recover the original root key.

### Replay ledger

- Fix a silent failure in `v2_replay_ledger`. Its `record_table` CHECK omitted
  the root key grant table, and because the claim uses `INSERT OR IGNORE`, the
  violation was indistinguishable from a duplicate key: zero rows affected,
  reported as "already used". Every grant was refused as a replay of a record
  that had never been stored, and grants had no replay protection at all,
  because no ledger row was ever written.
- Migration `0005` widens the constraint while preserving existing rows.
  Rebuilding the ledger empty would let every previously consumed record be
  presented again.
- The claim now confirms the row exists before reporting a replay, and the
  operation ledger reports the same class of fault instead of failing with an
  unexplained database error.

### Notes

Grants must still be filed by an external custodian. Nothing generates a tenant
root key, seals it to a newly enrolled device, or implements the root
generation lifecycle and recovery bundle, so profile sync continues to use a
passphrase-derived key. See `docs/key-custody.md`.

This release is not production-ready: the P-OP gate is unmet, and key custody
lifecycle and recovery are incomplete.

## v0.2.2

Enrollment and profile sync reach the shipped binary, plus the tenant-boundary
fix from #21.

### Device enrollment

- Add `POST /v2/devices/enrollment-challenges` and
  `/v2/devices/enrollment-proofs`. The server issues a nonce bound to a key
  commitment and verifies the device holds the key it claims; registering a
  public key without proof would let a caller enroll a key they cannot use.
- Store the challenge nonce hashed and consume it once, so a captured proof
  cannot be replayed.
- Add `shared::enrollment_proof`: one canonical encoding for both sides. The
  manifest format had already shown what happens when a wire format is defined
  in two places.
- Add Team settings for server URL and token, with device key material in its
  own `team.json` so an unrelated settings save cannot destroy device identity.
  The status command never returns the token or any key.

### Profile sync

- Wire the fleet client to the Launcher: `profile_sync_push`,
  `profile_sync_pull` and `profile_sync_status`, with push and pull in the
  profile menu on an enrolled device. The client shipped in v0.2.1 with no
  caller, so the linker dropped it — `/v2/fleet/uploads` was absent from the
  binary. It is present now.
- Sync uploads the same sealed container a local backup writes; the server
  stores ciphertext, a digest and a version, and holds no key.
- Enrollment now returns the account id the server assigned. Fleet routes are
  account-scoped and the client cannot infer that id, so a device enrolled
  before this change reports `can_sync: false` and must re-enroll.
- Both sync commands check running state before configuration, so a user with a
  running browser is told to close it rather than sent to fix server settings.

### Security fix: tenant boundary on every fleet route

Eight `/v2/` fleet handlers took `tenant_id` from the request and never checked
the caller belonged to it. Any authenticated user could lease, upload to or
download from any tenant. All eight now call `require_tenant_member`; the
regression test receives `201 Created` before the fix and is refused after it.

`AuthUser` carries no tenant, so at each individual call site an authentication
check looked sufficient. It was not.

### Documentation

- `docs/v1-authorization-audit.md` — every v1 route checked for the same flaw;
  none has it, and the one route that resembles it is explained rather than
  left for a future reader to re-derive.
- `docs/key-custody.md` — how profile keys are held, why sync currently needs a
  shared passphrase, and what is missing before per-device key wrapping works.
  The tenant root key machinery exists in `shared/src/grants.rs` but has no
  caller, and `POST /v2/tenant-root-key-grants` verifies a grant and then
  discards it.

### Still not production-ready

The `P-OP` gate remains blocked: no independent verifier, no full product-flow
or downgrade drill, and no two-device destructive verification.

## v0.2.1

First v0.2.x release with installable artifacts. v0.2.0 was tagged but its
release build failed before producing any, so it stays a prerelease with no
downloads; v0.1.29 remained the latest installable version. Nothing about the
v0.2.0 tag is changed or moved.

- Fix the release build: `npm audit --audit-level=moderate` failed the
  validation job on a high-severity `browserslist` advisory, so no build or
  publish step ever ran. Updated to 4.28.8; all three npm workspaces are clean.
- Read the MCP contract version from `package.json` rather than a literal, so
  a version bump no longer fails a test that exists to guard the tool contract.

### Fleet transfer client and a commit-path authorization fix

Adds the `/v2/` client from #17 and fixes a server flaw the work exposed.

- Add `shared::fleet_manifest`: one definition of the signed snapshot manifest,
  used by both the client that signs and the tests that verify, so the two
  cannot drift into a format only one side accepts.
- Add `fleet_client` in the Launcher: lease, chunked upload, signed commit and
  ranged download. The lease is released on every path, a failed upload aborts
  its staging session, and a download that stalls is an error rather than a
  silent truncation.
- Add `GET /v2/server-identity`. A client must bind its signed records to the
  live `server_instance_id` and `restore_epoch`; without this endpoint it could
  only guess them.
- **Security fix.** `/v2/fleet/uploads/commit` verified the manifest signature
  and then trusted the request body for `container_sha256`, `profile_id`,
  `snapshot_id`, `fleet_id`, `base_version` and `key_generation`. A caller with
  a valid token could present a genuine manifest signed for one snapshot and
  publish different bytes under it. The handler now rejects any body that
  contradicts the signed manifest, covered by a regression test that publishes
  version 1 when the check is removed.

`fleet_client` has no UI caller yet: that needs device enrollment, which the
server does not expose an endpoint for. #17 stays open.

### Encrypted profile backup, wired into the Launcher

Closes the gap recorded in #17: v0.2.0 shipped the sealing library and the
fleet server, but nothing in the app could reach them. `shared::backup` now has
a production caller.

- Add `shared::passphrase`: Argon2id (64 MiB, 3 passes) derivation of the
  backup FKEK from a user passphrase. Nothing is persisted but a random salt,
  so a backup opens on a machine that has never seen the source.
- Add `shared::backup_file`: `create`/`restore`/`inspect` over a self-contained
  `.shxbak` file (magic, salt, verifying key, sealed container). Written via a
  temp file and renamed, so an interrupted backup cannot replace a good file
  with a truncated one.
- Add Tauri commands `profile_backup_create`, `profile_backup_restore` and
  `profile_backup_inspect`. Both mutating commands take the same
  `begin_user_mutation` claim as delete/clone: a backup of a running profile is
  torn, and a restore under one corrupts it.
- Add "Back up (encrypted)" and "Restore from backup" to the profile menu, with
  a passphrase prompt that requires confirmation on backup and warns that a lost
  passphrase makes the backup unreadable.

Restore recovers and authenticates the whole container in memory before
`snapshot::unpack` touches the profile. `backup::open` streams authenticated
frames and only detects truncation at the signed head, so an in-place restore
could otherwise leave a profile that looks complete and was never verified.

## 0.2.0 - 2026-09-02

> Scope: this release adds a library and a server. It is not wired into the
> app — `shared::backup::{seal, open}` has no production caller, and the
> Launcher exposes no backup, restore, fleet or sync command. The entries
> below describe implemented and tested building blocks, not user-facing
> features.

### Team/fleet control plane (new)

- Add `shared/src/grants.rs`: RFC 9180 HPKE (DHKEM-X25519 / HKDF-SHA256 /
  ChaCha20Poly1305) tenant root key grants. The grant scope — tenant, fleet,
  profile, snapshot, key generation, recipient device — is bound as AEAD
  associated data, so a grant cannot be replayed under a different scope.
  Sealing uses the OS CSPRNG.
- Add the v2 control-plane schema (`0004_v2_team_fleet.sql`), additive over v1.
  Tenant-scoped rows join their parent by composite `(tenant_id, id)` foreign
  key, so cross-tenant references are rejected by the database rather than
  relying on every query remembering to filter. One-shot records are claimed
  through a UNIQUE index.
- Add signed authorization records: a request must carry a record binding the
  action to this domain, tenant, server instance and restore epoch, signed by
  an issuer the tenant trusts.
- Add replay rejection and idempotent retries: a record is consumable once, and
  a completed operation replays its exact original response bytes.
- Add `/v2/device-approvals`, `/v2/capability-grants`,
  `/v2/tenant-root-key-grants`, `/v2/operations/complete`. The server files
  root key grants without being able to read them — the payload stays sealed
  to the recipient device.

### Encrypted profile backup (new)

- Add a v2 encrypted backup container: streaming ChaCha20-Poly1305 frames over a
  wrapped per-snapshot DEK, with an Ed25519-signed head record.
- Add `shared/src/canonical.rs`: deterministic canonical CBOR encoding with
  strict rejection of non-canonical input, so signed bytes cannot be re-encoded
  into a different-but-accepted form.
- Add `shared/src/keys.rs`: key identities (`root_key_id`, `signing_key_id`) and
  DEK wrap/unwrap bound to a canonical slot context as AEAD associated data.
- Add `shared/src/signing.rs`: domain-separated signing over a length-prefixed
  transcript, with an acyclic commitment structure (the signature is not part of
  its own signed payload).
- Add `shared/src/envelope.rs`: DEK slots, pre-encryption intent records, STREAM
  frame nonces/AAD, and the restore-epoch Merkle tree with inclusion proofs.
- Add `shared/src/backup.rs`: the `seal`/`open` container API joining the above.

### Format guarantees

- Frames bind the exact envelope intent, frame counter, and final-frame flag, so
  truncation, reordering, and cross-envelope splicing all fail closed.
- The prologue is bound to the signed head, so slot/intent substitution before
  the signature check is rejected.
- Every single-byte mutation of a container is detected (exhaustive test).
- Merkle leaves enforce ordering, reject duplicates, and use domain-separated
  leaf/node hashing; unary promotion is only legal at an odd tail.

### Compatibility

- The v1 portable snapshot format is unchanged: `snapshot::pack`/`unpack` keep
  their existing behaviour and byte format.
- The v2 container wraps a v1 snapshot losslessly — sealing then opening returns
  the exact v1 bytes, which still restore through the v1 reader.
- The v1 reader rejects a v2 container rather than misparsing it.
- The MCP tool contract is unchanged at 96 tools.

### Notes

- `open` streams plaintext as it is decrypted, so its output must be treated as
  untrusted until the call returns `Ok`; this is a deliberate trade-off to keep
  memory bounded on large profiles. Callers restoring to disk should write to a
  staging path and promote only on success.
- Fleet sync transfer operations are not implemented in this release: the
  schema and authorization exist, the upload/download path does not.

## 0.1.29 - 2026-08-28

### Process ownership

- Assign an opaque in-memory UUID to every API-launched browser and require the exact profile, PID, and launch-instance token for conditional cleanup.
- Disable the legacy PID-only conditional stop endpoint with HTTP 410 so recycled numeric PIDs cannot stop replacement processes.
- Keep launch-instance tokens out of running-profile inventory, persistence, logs, API errors, and public MCP results.

### MCP lifecycle

- Preserve the page opened by `safe_open_url` as the active target for follow-up tab, screenshot, ARIA, and network tools.
- Preflight Launcher ownership capability before spawning a stopped profile and fail closed when CDP startup, restoration, or launch-instance ownership cannot be verified.
- Restore the profile state owned by `safe_open_url` without PID-only retries; stale-process cleanup is now inventory-only.

### Release integrity

- Enforce exact MCP archive-entry equality across staging, raw tar inspection, and extracted payload verification.
- Reject missing, extra, duplicate, nested-extra, symlink, non-regular, unsafe-root, and malformed release-staging inputs before publication.
- Preserve the 96-tool MCP contract, startup-in-tray behavior, signed updater flow, and existing headless automation compatibility.

## 0.1.28 - 2026-08-14

### Rust SDK

- Update the crate-level quickstart doctest to create a `Profile` before calling `ShardX::session`.
- Gate the CDP-control doctest and `quickstart` example behind the existing `control` feature so `--no-default-features` remains buildable.
- Upgrade `dirs` from 5 to 6 and `rand` from 0.8 to 0.9 after isolated default-feature, no-default-feature, and Rust 1.74.1 compatibility checks.
- Keep `chromiumoxide` 0.7, `reqwest` 0.12, and `zip` 2 because their current release lines are RustSec-clean while the next majors exceed the SDK's Rust 1.74 MSRV.
- Add stable, RustSec, and Rust 1.74.1 SDK gates to CI and release validation so vulnerable dependency graphs, doctest failures, feature-minimal regressions, and MSRV breaks cannot bypass packaging.

## 0.1.27 - 2026-08-13

### Security

- Resolved the current npm audit findings in the Launcher, MCP server, and Node SDK dependency graphs with compatible patch-level updates.
- Added a Node SDK archive extraction regression test for nested Windows paths and Unicode fingerprint bundles.

### Profile safety

- Reject profile mutations while the browser is running or while launch/exit cleanup owns the profile lifecycle.
- Serialize concurrent profile-name allocation and mutation while preserving unrelated profile launches.
- Validate profile names consistently across UI, API, create, edit, clone, and batch import paths.
- Reject unsafe Windows names, separators, control characters, overlong names, and case-insensitive collisions.
- Fail closed when profile inventory contains an unreadable or malformed record.
- Persist profile records with atomic replacement and report folder-operation write/delete failures instead of returning false success.

### Compatibility

- Preserve the 96-tool MCP contract, startup-in-tray behavior, signed updater flow, and existing headless automation compatibility.
- Defer SQLite/WAL dependency migration to the Team/Fleet Sync and encrypted-backup development line because the current server does not enable WAL.
