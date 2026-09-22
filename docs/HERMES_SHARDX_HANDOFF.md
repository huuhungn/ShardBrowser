# Hermes / ShardX local handoff

Last verified: 2026-09-19 (Hermes Desktop as the MCP host)

## Repository and runtime map

| Purpose | Path / branch |
| --- | --- |
| Development fork | `%USERPROFILE%\Documents\GitHub\ShardBrowser` |
| Fork remote | `origin = https://github.com/huuhungn/ShardBrowser.git` |
| Upstream remote | `upstream = https://github.com/ProxyShard/ShardBrowser.git` |
| Upstream push | Disabled intentionally |
| Custom integration branch | absorbed into `origin/main` (PR #37); do not recreate locally |
| Latest release source | tag `v2.2.7`, `origin/main`, commit `aaf4782` |
| Local MCP runtime clone | `%USERPROFILE%\Documents\MCP\ShardBrowser` |
| Hermes config | `%LOCALAPPDATA%\hermes\config.yaml` (`mcp_servers.shardbrowser`) |
| Active release source | fork `origin/main`, tag `v2.2.7`, commit `aaf4782` |
| Active MCP runtime branch | `codex-mcp-helpers-runtime`, merge commit `d73c1d9` |
| MCP runtime backup | `C:\Users\Administrator\AppData\Local\Temp\shardx-backups\mcp-runtime-pre-sync-2.2.5-20260919-102734.tar.gz` |

The development checkout and MCP runtime clone have different roles. Do not
move, delete, merge, or switch either clone casually. Development is backed up
to `origin`; upstream changes are proposed only through a scoped pull request.

## Current version state

- Launcher release `v2.2.7` is public at
  <https://github.com/huuhungn/ShardBrowser/releases/tag/v2.2.7>.
- The fork must stay at or above `2.0.1`, because the runtime manifest carries
  `min_launcher_version`.
- Release commit is `aaf4782`; the development fork's `origin/main` and tag
  `v2.2.7` point to that commit. The installed Launcher/API reports `2.2.7`
  on `http://127.0.0.1:40325`.
- The selected local MCP runtime is
  `%USERPROFILE%\Documents\MCP\ShardBrowser`, branch
  `codex-mcp-helpers-runtime`, merged through `d73c1d9`. Its root package,
  `mcp/package.json`, `mcp/package-lock.json`, and `src-tauri/tauri.conf.json`
  all report `2.2.7`.
- Hermes config launches `C:/Users/Administrator/Documents/MCP/ShardBrowser/mcp/index.js`
  with `SHARDX_API=http://127.0.0.1:40325`. Restart Hermes Desktop after a
  runtime replacement so it starts a fresh stdio process and reloads tools.
- MCP runtime sync backup:
  `C:\Users\Administrator\AppData\Local\Temp\shardx-backups\mcp-runtime-pre-sync-2.2.5-20260919-102734.tar.gz`.
- MCP tool count is 110 after the merge (96 from this fork, plus 14 upstream
  additions including `human_click` and `human_type`). `mcp/contract.test.js`
  asserts that count and fails on drift, which is how the change was noticed.
- Canonical profile: `VN Automation 001 - No Proxy`. Never use it for destructive
  tests; use disposable profiles and disposable servers only.

## Runtime-local backup and monitor inventory

These entries are intentionally outside Git's tracked source and were not
merged into the release runtime:

- `backup-hermes-safe-tools-20260828-133152/`: one 64 KB `index.js` snapshot;
  preserve as a rollback/reference copy, not as the active MCP source.
- `mcp-backup-20260716-211548/`: a 39 MB historical MCP tree including
  `node_modules`; preserve until the 2.2.7 runtime has completed its post-sync
  smoke check, then it is safe to archive or remove separately from source.
- `scripts/Run-ShardXStartMonitor-hidden.vbs`,
  `scripts/monitor-start-attribution.py`, and
  `scripts/test-monitor-start-attribution.py`: local Windows process-start
  attribution/monitor helpers. Preserve; they are not imported by `mcp/index.js`
  and are not part of the shipped MCP archive.
- `scripts/__pycache__/`: generated Python bytecode only. It is safe to remove
  after any monitor test is finished; never treat it as source.

The local `mcp/vet-*.mjs` scripts are tracked operator scripts restored after
sync; they are also not imported by `mcp/index.js` or included in the packaged
MCP archive. Do not delete them as part of routine runtime cleanup.

## Sync verification record (2026-09-19)

- Created branch `backup/pre-sync-2.2.7-20260919-102734` before merging.
- Archived `mcp/` before the merge and verified the archive contains the
  expected `index.js`, package manifests, lockfile, and README.
- Merged fork `origin/main` / `v2.2.7` into the runtime branch with no conflicts.
- Ran `PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 PATCHRIGHT_SKIP_BROWSER_DOWNLOAD=1
  npm ci --no-audit --no-fund` in `mcp/`, followed by `npm test`; all 29
  MCP tests passed (`29 passed, 0 failed`).
- The installed Launcher health endpoint reports `ok=true`, version `2.2.7`.
- The MCP process was not running during the source replacement. Restart Hermes
  Desktop before relying on the refreshed stdio tool schema.


`src-tauri/src/runtime.rs` fetches a runtime manifest at startup. It used to
point at `ProxyShard/ShardBrowser@main`, so upstream's v2 release retargeted
this fork's installed Launcher without any local change: it began fetching
Chromium 152 and recorded `applied_signature: 152.0.7977.65|Not?A_Brand|24`.

That is dangerous for an anti-detect tool. Upstream v2 pairs the engine bump
with a `tls` block that sets JA4 fingerprints, and the pre-merge fork had no
code reading it — the browser advertised a 152 user agent over an unchanged TLS
handshake, which is exactly the mismatch detection systems look for.

The manifest URL now points at this fork, so engine and TLS settings change
only when this repository changes. The merge also brought in upstream's TLS and
`min_launcher_version` handling, so the mismatch itself is fixed.

## Team, fleet and key custody

- Root key generations: `PREPARING -> ACTIVE -> RETIRED`, with the first grant
  of a generation required to be a unique `FirstRootSelfGrant`.
- Fleet key (FKEK) generations mirror that lifecycle and are anchored to the
  tenant's active root generation. Variants: `FirstFleetSelfGrant` and
  `DeviceHpkeGrant`, capability `fleet.key.receive`.
- The FKEK is not derived from the root key. The root key authorises custody;
  the FKEK wraps profile snapshots. They have separate lifecycles by design.
- Profile sync seals under the collected fleet key and asks for no passphrase.
  Pull tries every held generation, newest first. The passphrase path remains
  for devices that hold no grant yet.
- Collected keys live in `fleet-keys.json`, deliberately outside `team.json`,
  which the Settings page round-trips.
- The server stores ciphertext it cannot open, and holds no plaintext root key
  or fleet key at any point.

Not yet done, and not to be described as finished: recovery bundles, root and
fleet rotation, revocation, the custodian ceremony, and P-OP evidence with a
named operator and an independent verifier.

After a release is installed, keep Launcher, `mcp/package.json`, the selected
MCP folder, and `serverInfo.version` on the same version. Restart Hermes
Desktop after replacing MCP source so it starts a fresh stdio process and
reloads the tool schema.

## Secret and profile boundaries

- `SHARDX_TOKEN` is a Windows User environment variable. It is intentionally
  absent from `config.toml`; never print or copy its value into logs or docs.
- Never expose cookies, proxy credentials, profile storage, profile notes, or
  full fingerprint payloads.
- Reuse the canonical profile for smoke tests and restore its prior running or
  stopped state afterward.
- Prefer read-only checks: `health_check`, `list_profiles`,
  `find_profile_by_name`, and `list_running`.
- Use `safe_open_url` only with an explicit `http(s)` URL.

## MCP install and registration

Release `v0.1.21` and later archives include `package-lock.json`. Install the
matching MCP dependency graph without downloading a browser binary:

```powershell
Set-Location -LiteralPath 'C:\path\to\ShardX-MCP'
$env:PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD='1'
$env:PATCHRIGHT_SKIP_BROWSER_DOWNLOAD='1'
npm ci
```

`npm install` is only the fallback for a legacy or custom MCP folder that does
not contain a lockfile. Launcher Settings detects that distinction and copies
one appropriate command.

Hermes Desktop launches the selected `index.js` with Node. Settings can inspect the
`shardbrowser` registration, expected `index.js`, and `SHARDX_API`; it reports
only whether a token is configured, never the token itself.

## Helper contract

The local package includes these small agent-oriented helpers:

- `health_check`: authenticated Launcher/API reachability and version.
- `startup_status` and `configure_startup`: inspect or reconcile the current
  user's Launcher sign-in entry. The Automation API is embedded in the
  Launcher; MCP remains a client-spawned stdio process.
- `find_profile_by_name`: resolves a profile using a minimal summary.
- `ensure_profile_started`: idempotent start and CDP handoff.
- `safe_open_url`: validated `http(s)` navigation with state-preserving smoke
  behavior and one stale-process self-heal retry.
- `devtools_context`: CDP HTTP/WebSocket context and current page targets.
- `cleanup_stale_profile_processes`: narrowly targets untracked processes still
  holding one ShardX user-data-dir.
- `challenge_status`, `wait_for_human_verification`, and
  `verification_checkpoint`: read-only Cloudflare detection, human handoff,
  Windows notification, and privacy-minimal checkpoint recovery.

From `v0.1.21`, helper profile summaries contain only identity, folder, running
state, CDP context, and match metadata. Profile notes remain in storage and the
Launcher UI but are not returned by those helper summaries.

## Custom integration history

The custom branch includes the upstream contribution set plus local integration
work. Notable changes since `v0.1.16`:

- `v0.1.17`: Launcher startup/search/responsive/Settings/accessibility polish.
- Process-tree stop handling prevents hidden/tray smoke tests from leaving a
  child browser tree behind.
- `v0.1.18`: Cloudflare challenge status and manual verification handoff.
- `v0.1.19`: Windows notification and persisted verification checkpoint;
  MCP `serverInfo.version` is read from `mcp/package.json`.
- `v0.1.20`: the Windows Automation API listener handle is non-inheritable,
  preventing child processes from keeping port 40325 alive after Launcher exit.
- `v0.1.21`: reproducible MCP archive/install and CI tests, reduced MCP summary
  data, Vite 6.4.3, and inline proxy entry during profile creation.
- `v0.1.22`: Tauri updater signing and in-app update UX, Launcher UI/E2E
  regression coverage, a fail-closed custom-font capability gate, normalized
  release asset names, and a self-tested MCP release archive.
- `v0.1.23`: fail-closed NSIS in-place upgrades wait for the installed Launcher
  process to release the executable, replace the exact install target, and
  verify the installed product version. A real NSIS fixture now blocks release
  publishing on file-lock, stale-executable, or version-mismatch regressions.
- `v0.1.24`: optional current-user sign-in startup keeps the Launcher and its
  embedded Automation API ready in the system tray. Settings, authenticated
  `GET/PUT /startup`, and MCP startup helpers share the same verified state;
  MCP remains client-spawned instead of adding a redundant background daemon.
- `v0.1.25`: the release MCP archive now includes `contract.test.js`, so the
  downloaded package can run its own nine-test stdio/tool-contract suite.
- `v0.1.26`: Windows Application Restart registrations relaunch the primary
  process with `--shardx-autostart`, so Windows session restore cannot win the
  single-instance race and reveal the main window before the normal sign-in
  entry runs. A separate dependency-only patch also resolves all reported npm
  advisories in both the Launcher and MCP package graphs.
- `v0.1.27`: all npm advisory graphs used by the release are clean, profile
  names are validated through one shared boundary, and profile/folder mutation
  fails closed when lifecycle state is active, malformed, concurrent, or only
  partially persisted. API lifecycle conflicts map to HTTP 409. SQLite/WAL is
  intentionally deferred to the `v0.2.x` Team/Fleet Sync and encrypted-backup
  milestone instead of being mixed into this patch release.

The Release workflow builds Windows x64, Linux x64, and macOS arm64; packages
the matching `ShardX-MCP.tar.gz`; creates SHA-256 checksums and provenance; and
signs updater artifacts with the Tauri updater key. Windows installers and the
portable executable intentionally do not use Authenticode, so Windows can show
`Unknown publisher`; this is expected and is separate from the cryptographic
signature that the in-app updater verifies before installation.

Custom-font release gate: do not expose, advertise, or claim custom-font support
until the bundled engine explicitly supports
`--shardx-custom-fonts-manifest` and temporary-profile coherence tests pass for
`document.fonts`, CSS/glyph rendering, canvas, WebGL-adjacent observations,
enumeration/probes, and per-profile isolation. Tests must use temporary fixture
profiles/fonts only and must not mutate real profiles.

## Upstream pull requests

Verified 2026-09-19: upstream `ProxyShard/ShardBrowser` still has open PRs
[#19](https://github.com/ProxyShard/ShardBrowser/pull/19) (conflicting),
[#23](https://github.com/ProxyShard/ShardBrowser/pull/23) (mergeable),
[#24](https://github.com/ProxyShard/ShardBrowser/pull/24) (mergeable), and
[#33](https://github.com/ProxyShard/ShardBrowser/pull/33) (mergeable, authored by
another contributor). These are not part of the v2.2.7 runtime sync; review
individually before accepting any of them. The fork's v2.2.7 release work is
already on `origin/main`.

Historical release notes below are retained as an audit trail; they are not the
current version or test state.

The v0.1.23 tag and release passed frontend build/E2E, eight MCP tests, Rust
check/tests, updater-signing verification, and the real Windows NSIS regression
fixture. A silent in-place upgrade from the running v0.1.22 release stopped the
old process, installed the executable byte-for-byte from the v0.1.23 release
payload, preserved `settings.json` byte-for-byte, retained the selected MCP path
and agent registration file, and exposed Launcher/API version `0.1.23` on port
40325. The selected MCP folder matches all eight packaged release files, passed
`npm ci` plus all eight tests, and a fresh standalone stdio probe reported
`serverInfo.version` `0.1.23` with 94 tools. Fully restart the MCP host after the
active task is idle because its existing stdio processes predate the v0.1.23 MCP
source replacement.

The v0.1.25 release supersedes v0.1.24 because the earlier MCP archive omitted
`contract.test.js`. The Launcher/runtime binaries were unaffected. The v0.1.25
archive includes all nine source/test files, passes `npm ci` plus all nine
tests, and its stdio contract reports `serverInfo.version` `0.1.25` with 96
tools. The installed Launcher/API and Windows file/product version are also
`0.1.25`; startup registration is enabled and an actual `--shardx-autostart`
launch kept the main Launcher window hidden while the API became ready. Fully
restart Hermes Desktop to replace stdio MCP processes that predate the source update.

The v0.1.26 release passed frontend build and 20 Playwright tests, nine MCP
tests, Rust check and 27 passing Rust tests, both npm audits at zero findings,
the updater-signed multi-platform Release workflow, and the Windows NSIS
upgrade regression. Its downloaded MCP archive contains exactly nine source
and test files, installs reproducibly with `npm ci`, and a fresh stdio probe
reports `serverInfo.version` `0.1.26` with 96 tools. The local silent upgrade
preserved `settings.json` and the sign-in registration byte-for-byte, installed
Launcher/API `0.1.26`, and replaced the selected MCP source with the exact
nine-file release payload. `npm ci`, both MCP checks, and a fresh authenticated
stdio probe passed with 96 tools. An explicit `--shardx-autostart` smoke kept
the real Tauri window hidden, retained the tray icon, and registered Windows
Application Restart with the expected argument and flags. A real reboot remains
the final proof for the Windows session-restore path.

The v0.1.27 release supersedes v0.1.26 for security and profile-lifecycle
safety. Release workflow run
<https://github.com/huuhungn/ShardBrowser/actions/runs/31711893861>
passed validation plus Windows x64, Linux x64, macOS arm64, and public publish.
All 16 entries in `SHA256SUMS.txt` match the downloaded assets; public NSIS and
MSI updater signatures verify against the Launcher key. The public MCP archive
contains exactly nine source/test files under one root folder, installs with
`npm ci`, reports zero advisories, passes all nine tests, and a fresh
authenticated stdio probe reports `serverInfo.version` `0.1.27` with 96 tools.
The public NSIS upgrade preserved `settings.json` and the canonical profile
byte-for-byte. Launcher/API health is authenticated at `0.1.27`; startup is
configured, registered, matching, and minimized, and the actual `ShardX
Launcher` window is hidden. A CAffiliate `-Now` dry-run observed the account as
already checked in, did not dispatch a click, closed its temporary page,
restored the canonical profile to stopped, and left `/running` empty.

## Start-of-task verification

```powershell
git -C $env:USERPROFILE\Documents\GitHub\ShardBrowser status --short --branch
hermes mcp test shardbrowser
```

Then call `health_check`, confirm the version, and use `list_running`. For a
navigation smoke test, call `safe_open_url` on `https://example.com/` and verify
`Example Domain`; restore the profile's prior state. For DevTools QA, read
`docs/CODEX_DEVTOOLS_QA.md` (kept under its original filename; the procedure is
host-agnostic).

If helper tools or their schema are stale, fully quit and reopen Hermes Desktop. Do
not replace the runtime clone from upstream `main` without checking PR #19 and
custom helper compatibility.
