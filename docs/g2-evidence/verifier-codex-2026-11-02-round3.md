# Independent G2 verification — Codex

Commit: `aef00845cb83bfa2c223d72dc0515c8f4bfbd729`. Read-only repository review, 2026-11-02.

## Independent result and execution summary

**FAIL: one blocking finding, F1 (high).** A signature-valid approval from a non-custodian can change the scope used to validate a genuine compromised-device revocation. The revocation is then omitted from the local ledger and does not initiate Q-18's commit block. The primary defect is `shared/src/trust_chain.rs:526`, consumed at `src-tauri/src/team/ledger.rs:1063`. The full failure scenario, production-code probe and required closure appear under “Blocking finding F1” below. G2-61's DONE evidence is incomplete and G2-64 remains FAIL. The owner's G2-48 PENDING-MANUAL exception and deferred Team UI are respected.

The reported B1, B2, B3, B5, B6, B7, N1 and N2 scenarios are closed within the tested scope. B4's original case passes, but F1 prevents full closure of the underlying revocation-counting property. The SMB gap is closed locally. Two symlink branches require a privilege absent locally; exact-commit Windows CI supplies their evidence.

| Check | Outcome |
|---|---|
| Evidence checksum check, beginning and end | Exit 0 each time: `120 files checked, 0 problems` |
| Formatting: shared, server, launcher, Rust SDK | 4/4 commands pass |
| Clippy, all targets, warnings denied: shared, server, launcher | 3/3 commands pass |
| Shared full suite | 314 passed, 0 failed, 1 ignored |
| Server full suite, definitive serial rerun | 347 passed, 0 failed, 3 ignored |
| Launcher library suite, real credential-store test excluded | 502 passed, 0 failed, 11 ignored, 1 filtered out |
| Server build | Pass |
| Installed MSRV checks: shared 1.87.0, server 1.89.0, launcher 1.88.0 | 3/3 commands pass, locked dependencies, all targets |
| All packet row test commands, definitive serial runs | 96/96 commands exit 0; 325 passed executions, 0 failed, 0 ignored; one G2-48 real-store test intentionally excluded |
| npm i18n / Rust strings / backend locale / raw-error toast | 16 + 3 + 7 + 2 = 28 tests passed |
| Exact-commit CI run 41343000374 | All 5 jobs successful; includes advisory checks and other-platform/SDK checks |
| Independent F1 probe | Reproduced wrong decision; two repeat executions byte-identical |

Test totals count executions, including repeated tests across row commands. The 672-pass serial-run total later in this report includes the 347-pass full server rerun plus 325 row-test executions. The initially overlapping server/row runs failed from shared-fixture interference; those failures are retained below and superseded by clean serial reruns, not hidden. Passing cargo tests do not establish the missing F1 adversarial property.

Stable rustc/cargo is 1.99.1. Every compilation/test uses the requested private target and `-j 2`; every shared/server/launcher test invocation carries the requested loopback SMB directory. Exact commands and captured outcomes follow. No SMB branch reported SKIPPED. The exact two symlink skip messages, ignored-test assessment, credential-store exclusion and remaining evidence limits are recorded below.

This report applies the evidence-gate-verification skill. Its suggested source mutation was superseded by the user's read-only restriction; the independent adversarial probe used in-memory source and compiler artifacts under the permitted target directory. No repository source was modified.

## Execution evidence

`python scripts/g2-evidence.py --check`: exit 0; `120 files checked, 0 problems`. Stable rustc/cargo 1.99.1. Toolchains 1.87.0, 1.88.0, 1.89.0 installed. SMB path reachable.

All cargo builds use `CARGO_TARGET_DIR=C:/Users/User/AppData/Local/Temp/g264-target-codex`, `-j 2`, and `SHARDX_TEST_SMB_DIR=\\localhost\C$\Users\User\AppData\Local\Temp\g264-smb`. Credential Manager test excluded by explicit user restriction.

### `cargo +stable fmt --check --manifest-path shared/Cargo.toml`

Exit 0; 0.4 seconds.

```text

```

### `cargo +stable fmt --check --manifest-path server/Cargo.toml`

Exit 0; 0.6 seconds.

```text

```

### `cargo +stable fmt --check --manifest-path src-tauri/Cargo.toml`

Exit 0; 0.6 seconds.

```text

```

### `cargo +stable fmt --check --manifest-path sdks/rust/Cargo.toml`

Exit 0; 0.1 seconds.

```text

```

## Exact-commit CI

`gh run list --repo huuhungn/ShardBrowser --commit aef00845cb83bfa2c223d72dc0515c8f4bfbd729 --json databaseId,name,status,conclusion,headSha`; `gh run view 41343000374 --repo huuhungn/ShardBrowser --json jobs,conclusion,headSha`; `gh run view 41343000374 --repo huuhungn/ShardBrowser --log`.

success; frontend, Rust, and MCP checks: success, Launcher, server and shared MSRV: success, Rust tests on Windows: success, Rust SDK stable and MSRV: success, Rust compiles on macOS: success

```text
frontend, Rust, and MCP checks	Set up Rust stable	2026-11-01T19:41:38.5836548Z   stable-x86_64-unknown-linux-gnu unchanged - rustc 1.99.1 (58cf8f9c3 2026-10-13)
frontend, Rust, and MCP checks	Set up Rust stable	2026-11-01T19:41:38.6238291Z   stable-x86_64-unknown-linux-gnu unchanged - rustc 1.99.1 (58cf8f9c3 2026-10-13)
frontend, Rust, and MCP checks	Set up Rust stable	2026-11-01T19:41:38.8253040Z rustc 1.99.1 (58cf8f9c3 2026-10-13)
frontend, Rust, and MCP checks	Shared core tests	2026-11-01T19:50:17.1368704Z test result: ok. 307 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 97.58s
frontend, Rust, and MCP checks	Shared core tests	2026-11-01T19:50:37.4146245Z test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 20.27s
frontend, Rust, and MCP checks	Shared core tests	2026-11-01T19:50:37.4403480Z test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
frontend, Rust, and MCP checks	Shared core tests	2026-11-01T19:50:37.4427612Z test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
frontend, Rust, and MCP checks	Shared core tests	2026-11-01T19:50:37.4446198Z test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
frontend, Rust, and MCP checks	Shared core tests	2026-11-01T19:50:38.5554680Z test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
frontend, Rust, and MCP checks	Team server tests	2026-11-01T19:51:45.0721544Z test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
frontend, Rust, and MCP checks	Team server tests	2026-11-01T19:52:03.3371871Z test result: ok. 104 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 18.26s
frontend, Rust, and MCP checks	Team server tests	2026-11-01T19:52:15.7525165Z test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 12.41s
frontend, Rust, and MCP checks	Team server tests	2026-11-01T19:52:15.7559692Z test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
frontend, Rust, and MCP checks	Team server tests	2026-11-01T19:52:25.2573793Z test result: ok. 22 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 9.50s
frontend, Rust, and MCP checks	Team server tests	2026-11-01T19:52:26.5479879Z test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.29s
frontend, Rust, and MCP checks	Team server tests	2026-11-01T19:53:14.6365063Z test result: ok. 21 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 48.08s
frontend, Rust, and MCP checks	Team server tests	2026-11-01T19:55:13.5712525Z test result: ok. 75 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 118.92s
frontend, Rust, and MCP checks	Team server tests	2026-11-01T19:55:15.6249022Z test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.04s
frontend, Rust, and MCP checks	Team server tests	2026-11-01T19:55:28.6125343Z test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 12.98s
frontend, Rust, and MCP checks	Team server tests	2026-11-01T19:55:29.7149301Z test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.09s
frontend, Rust, and MCP checks	Team server tests	2026-11-01T19:55:30.6839514Z test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.97s
frontend, Rust, and MCP checks	Team server tests	2026-11-01T19:55:31.2699465Z test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.58s
frontend, Rust, and MCP checks	Team server tests	2026-11-01T19:55:52.4046443Z test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 21.13s
frontend, Rust, and MCP checks	Team server tests	2026-11-01T19:55:57.2486595Z test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 4.83s
frontend, Rust, and MCP checks	Team server tests	2026-11-01T19:55:58.7802791Z test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.53s
frontend, Rust, and MCP checks	Team server tests	2026-11-01T19:55:59.1792095Z test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.40s
frontend, Rust, and MCP checks	Team server tests	2026-11-01T19:55:59.4298026Z test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.25s
frontend, Rust, and MCP checks	Team server tests	2026-11-01T19:55:59.7569478Z test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.32s
frontend, Rust, and MCP checks	Team server tests	2026-11-01T19:56:00.6849940Z test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.93s
frontend, Rust, and MCP checks	Team server tests	2026-11-01T19:56:08.1470132Z test result: ok. 23 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 7.46s
frontend, Rust, and MCP checks	Team server tests	2026-11-01T19:56:08.2398214Z test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
frontend, Rust, and MCP checks	Rust tests	2026-11-01T20:03:29.3413800Z test result: ok. 489 passed; 0 failed; 10 ignored; 0 measured; 0 filtered out; finished in 252.47s
frontend, Rust, and MCP checks	Rust tests	2026-11-01T20:03:29.4203463Z test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
frontend, Rust, and MCP checks	Rust tests	2026-11-01T20:03:29.4541081Z test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s
frontend, Rust, and MCP checks	Rust tests	2026-11-01T20:03:55.2994761Z test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 25.84s
frontend, Rust, and MCP checks	Rust tests	2026-11-01T20:03:57.6336643Z test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.33s
frontend, Rust, and MCP checks	Rust tests	2026-11-01T20:03:57.6375283Z test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
frontend, Rust, and MCP checks	Rust tests	2026-11-01T20:03:57.6554355Z test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
frontend, Rust, and MCP checks	Rust tests	2026-11-01T20:03:57.6581709Z test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
frontend, Rust, and MCP checks	Rust tests	2026-11-01T20:03:57.6606471Z test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
frontend, Rust, and MCP checks	Rust tests	2026-11-01T20:03:57.6653442Z test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
frontend, Rust, and MCP checks	Rust tests	2026-11-01T20:03:58.7519609Z test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
Launcher, server and shared MSRV	Check each crate on its declared rust-version	2026-11-01T19:42:45.0259779Z   1.87-x86_64-unknown-linux-gnu installed - rustc 1.87.0 (17067e9ac 2025-05-09)
Launcher, server and shared MSRV	Check each crate on its declared rust-version	2026-11-01T19:43:07.7520647Z   1.89-x86_64-unknown-linux-gnu installed - rustc 1.89.0 (29483883e 2025-08-04)
Launcher, server and shared MSRV	Check each crate on its declared rust-version	2026-11-01T19:44:04.2160390Z   1.88-x86_64-unknown-linux-gnu installed - rustc 1.88.0 (6b00bc388 2025-06-23)
Rust tests on Windows	Set up Rust stable	2026-11-01T19:41:45.0476844Z   stable-x86_64-pc-windows-msvc unchanged - rustc 1.99.1 (58cf8f9c3 2026-10-13)
Rust tests on Windows	Set up Rust stable	2026-11-01T19:41:45.2027004Z   stable-x86_64-pc-windows-msvc unchanged - rustc 1.99.1 (58cf8f9c3 2026-10-13)
Rust tests on Windows	Set up Rust stable	2026-11-01T19:41:46.7862987Z rustc 1.99.1 (58cf8f9c3 2026-10-13)
Rust tests on Windows	Shared core tests	2026-11-01T19:43:25.6585042Z   SHARDX_TEST_SMB_DIR: \\localhost\shardx-g2-smb
Rust tests on Windows	Shared core tests	2026-11-01T19:45:54.5843276Z test result: ok. 300 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 101.95s
Rust tests on Windows	Shared core tests	2026-11-01T19:46:16.4293103Z test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 21.83s
Rust tests on Windows	Shared core tests	2026-11-01T19:46:16.8225240Z test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.38s
Rust tests on Windows	Shared core tests	2026-11-01T19:46:16.8376072Z test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
Rust tests on Windows	Shared core tests	2026-11-01T19:46:16.8532998Z test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
Rust tests on Windows	Shared core tests	2026-11-01T19:46:18.1840185Z test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
Rust tests on Windows	Team server tests	2026-11-01T19:46:18.3764465Z   SHARDX_TEST_SMB_DIR: \\localhost\shardx-g2-smb
Rust tests on Windows	Team server tests	2026-11-01T19:47:32.9626394Z test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
Rust tests on Windows	Team server tests	2026-11-01T19:48:59.9416117Z test result: ok. 106 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 86.96s
Rust tests on Windows	Team server tests	2026-11-01T19:49:38.2060108Z test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 38.25s
Rust tests on Windows	Team server tests	2026-11-01T19:49:38.2206778Z test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
Rust tests on Windows	Team server tests	2026-11-01T19:51:34.0553030Z test result: ok. 22 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 115.82s
Rust tests on Windows	Team server tests	2026-11-01T19:51:35.1194217Z test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.05s
Rust tests on Windows	Team server tests	2026-11-01T19:53:28.8510238Z test result: ok. 24 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 113.72s
Rust tests on Windows	Team server tests	2026-11-01T19:59:25.3089210Z test result: ok. 75 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 356.44s
Rust tests on Windows	Team server tests	2026-11-01T19:59:42.5051134Z test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 17.18s
Rust tests on Windows	Team server tests	2026-11-01T20:00:14.4717690Z test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 31.95s
Rust tests on Windows	Team server tests	2026-11-01T20:00:15.3149856Z test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.83s
Rust tests on Windows	Team server tests	2026-11-01T20:00:16.0180055Z test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.69s
Rust tests on Windows	Team server tests	2026-11-01T20:00:16.4628732Z test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.43s
Rust tests on Windows	Team server tests	2026-11-01T20:01:11.4993144Z test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 55.02s
Rust tests on Windows	Team server tests	2026-11-01T20:01:14.9970825Z test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.48s
Rust tests on Windows	Team server tests	2026-11-01T20:01:16.2040208Z test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.19s
Rust tests on Windows	Team server tests	2026-11-01T20:01:16.5779091Z test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.36s
Rust tests on Windows	Team server tests	2026-11-01T20:01:16.8693647Z test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.28s
Rust tests on Windows	Team server tests	2026-11-01T20:01:17.1978492Z test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.31s
Rust tests on Windows	Team server tests	2026-11-01T20:01:17.8607554Z test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.65s
Rust tests on Windows	Team server tests	2026-11-01T20:01:37.2419975Z test result: ok. 23 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 19.37s
Rust tests on Windows	Team server tests	2026-11-01T20:01:37.3971784Z test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
Rust tests on Windows	Launcher tests	2026-11-01T20:01:37.5686521Z   SHARDX_TEST_SMB_DIR: \\localhost\shardx-g2-smb
Rust tests on Windows	Launcher tests	2026-11-01T20:12:12.3630543Z test result: ok. 503 passed; 0 failed; 11 ignored; 0 measured; 0 filtered out; finished in 534.69s
Rust tests on Windows	Launcher tests	2026-11-01T20:12:12.3850859Z test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
Rust tests on Windows	Launcher tests	2026-11-01T20:12:12.8241405Z test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.42s
Rust tests on Windows	Launcher tests	2026-11-01T20:12:52.3098049Z test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 39.47s
Rust tests on Windows	Launcher tests	2026-11-01T20:13:01.8911436Z test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 9.56s
Rust tests on Windows	Launcher tests	2026-11-01T20:13:01.9184610Z test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
Rust tests on Windows	Launcher tests	2026-11-01T20:13:03.9850737Z test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.05s
Rust tests on Windows	Launcher tests	2026-11-01T20:13:04.0114973Z test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
Rust tests on Windows	Launcher tests	2026-11-01T20:13:04.0353284Z test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
Rust tests on Windows	Launcher tests	2026-11-01T20:13:04.0690306Z test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
Rust tests on Windows	Launcher tests	2026-11-01T20:13:06.0564400Z test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
Rust tests on Windows	Rust SDK tests	2026-11-01T20:13:06.4732425Z   SHARDX_TEST_SMB_DIR: \\localhost\shardx-g2-smb
Rust tests on Windows	Rust SDK tests	2026-11-01T20:13:22.0898479Z test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.57s
Rust tests on Windows	Rust SDK tests	2026-11-01T20:13:22.4753194Z test result: ok. 2 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.20s
Rust tests on Windows	Remove the temporary SMB share	2026-11-01T20:13:22.6339745Z   SHARDX_TEST_SMB_DIR: \\localhost\shardx-g2-smb
Rust SDK stable and MSRV	Set up Rust stable	2026-11-01T19:41:34.3188630Z   stable-x86_64-unknown-linux-gnu unchanged - rustc 1.99.1 (58cf8f9c3 2026-10-13)
Rust SDK stable and MSRV	Set up Rust stable	2026-11-01T19:41:34.3483970Z   stable-x86_64-unknown-linux-gnu unchanged - rustc 1.99.1 (58cf8f9c3 2026-10-13)
Rust SDK stable and MSRV	Set up Rust stable	2026-11-01T19:41:34.4856441Z rustc 1.99.1 (58cf8f9c3 2026-10-13)
Rust SDK stable and MSRV	Set up Rust SDK MSRV	2026-11-01T19:41:42.6444943Z   1.88.0-x86_64-unknown-linux-gnu installed - rustc 1.88.0 (6b00bc388 2025-06-23)
Rust SDK stable and MSRV	Set up Rust SDK MSRV	2026-11-01T19:41:42.6800831Z   1.88.0-x86_64-unknown-linux-gnu unchanged - rustc 1.88.0 (6b00bc388 2025-06-23)
Rust SDK stable and MSRV	Set up Rust SDK MSRV	2026-11-01T19:41:42.8279760Z rustc 1.88.0 (6b00bc388 2025-06-23)
Rust SDK stable and MSRV	Rust SDK stable checks	2026-11-01T19:42:48.0189191Z test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
Rust SDK stable and MSRV	Rust SDK stable checks	2026-11-01T19:42:48.2740769Z test result: ok. 2 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.05s
Rust SDK stable and MSRV	Rust SDK stable checks	2026-11-01T19:43:01.4414541Z test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
Rust SDK stable and MSRV	Rust SDK stable checks	2026-11-01T19:43:01.5173255Z test result: ok. 1 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.02s
Rust SDK stable and MSRV	Launcher, server and shared RustSec audit	2026-11-01T19:43:52.5112308Z ^[[0m^[[0m^[[1m^[[33mCrate:    ^[[0m proc-macro-error
Rust SDK stable and MSRV	Launcher, server and shared RustSec audit	2026-11-01T19:43:52.5115551Z ^[[0m^[[0m^[[1m^[[33mCrate:    ^[[0m ttf-parser
Rust SDK stable and MSRV	Launcher, server and shared RustSec audit	2026-11-01T19:43:52.5118384Z ^[[0m^[[0m^[[1m^[[33mCrate:    ^[[0m unic-char-property
Rust SDK stable and MSRV	Launcher, server and shared RustSec audit	2026-11-01T19:43:52.5121076Z ^[[0m^[[0m^[[1m^[[33mCrate:    ^[[0m unic-char-range
Rust SDK stable and MSRV	Launcher, server and shared RustSec audit	2026-11-01T19:43:52.5124075Z ^[[0m^[[0m^[[1m^[[33mCrate:    ^[[0m unic-common
Rust SDK stable and MSRV	Launcher, server and shared RustSec audit	2026-11-01T19:43:52.5126324Z ^[[0m^[[0m^[[1m^[[33mCrate:    ^[[0m unic-ucd-ident
Rust SDK stable and MSRV	Launcher, server and shared RustSec audit	2026-11-01T19:43:52.5128573Z ^[[0m^[[0m^[[1m^[[33mCrate:    ^[[0m unic-ucd-version
Rust SDK stable and MSRV	Launcher, server and shared RustSec audit	2026-11-01T19:43:52.5130890Z ^[[0m^[[0m^[[1m^[[33mCrate:    ^[[0m zbus_names
Rust SDK stable and MSRV	Launcher, server and shared RustSec audit	2026-11-01T19:43:52.5153663Z ^[[0m^[[0m^[[1m^[[33mCrate:    ^[[0m zvariant
Rust SDK stable and MSRV	Launcher, server and shared RustSec audit	2026-11-01T19:43:52.5155688Z ^[[0m^[[0m^[[1m^[[33mCrate:    ^[[0m zvariant_derive
Rust SDK stable and MSRV	Rust SDK MSRV checks	2026-11-01T19:44:58.9508119Z test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
Rust SDK stable and MSRV	Rust SDK MSRV checks	2026-11-01T19:44:59.0772221Z test result: ok. 2 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.06s
Rust SDK stable and MSRV	Rust SDK MSRV checks	2026-11-01T19:45:13.6958795Z test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
Rust SDK stable and MSRV	Rust SDK MSRV checks	2026-11-01T19:45:13.7807003Z test result: ok. 1 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.03s
Rust compiles on macOS	Set up Rust stable	2026-11-01T19:41:52.5211510Z   stable-x86_64-apple-darwin updated - rustc 1.99.1 (58cf8f9c3 2026-10-13) (from rustc 1.98.0 (88d9e12ae 2026-08-18))
Rust compiles on macOS	Set up Rust stable	2026-11-01T19:41:52.7737110Z   stable-x86_64-apple-darwin unchanged - rustc 1.99.1 (58cf8f9c3 2026-10-13)
Rust compiles on macOS	Set up Rust stable	2026-11-01T19:41:53.4756060Z rustc 1.99.1 (58cf8f9c3 2026-10-13)
```

### `cargo test --locked -j 2 --manifest-path shared/Cargo.toml -- --nocapture`

Exit 0; 59.3 seconds.

```text
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.77s
test result: ok. 300 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 49.90s
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 7.77s
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.04s
test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

### Row command G2-01

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- the_first_device_approves_itself_once_and_a_retry_gets_the_same_receipt every_approval_column_is_compared_with_its_container_on_each_request the_startup_pass_quarantines_approvals_that_left_their_containers --nocapture`

Exit 101; 8.6 s; 3 filters; unmatched filters: ['the_startup_pass_quarantines_approvals_that_left_their_containers'].

```text
test the_startup_pass_quarantines_approvals_that_left_their_containers ... FAILED
failures:
failures:
test result: FAILED. 2 passed; 1 failed; 0 ignored; 0 measured; 72 filtered out; finished in 8.23s
error: test failed, to rerun pass `--test v2_auth`
2026-11-02T01:24:53.016670Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
test the_first_device_approves_itself_once_and_a_retry_gets_the_same_receipt ... ok
2026-11-02T01:24:53.295982Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
2026-11-02T01:24:53.501868Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
2026-11-02T01:24:53.633222Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
2026-11-02T01:24:53.842676Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
2026-11-02T01:24:53.990434Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
2026-11-02T01:24:54.134483Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
2026-11-02T01:24:54.294813Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
2026-11-02T01:24:54.528914Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
2026-11-02T01:24:54.668155Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
2026-11-02T01:24:54.773160Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
2026-11-02T01:24:54.920347Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="device_approval"
test every_approval_column_is_compared_with_its_container_on_each_request ... ok

failures:

failures:
    the_startup_pass_quarantines_approvals_that_left_their_containers

test result: FAILED. 2 passed; 1 failed; 0 ignored; 0 measured; 72 filtered out; finished in 8.23s

    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.27s
     Running tests\v2_auth.rs (C:/Users/User/AppData/Local/Temp/g264-target-codex\debug\deps\v2_auth-adbaa5c4f4d9fcb5.exe)

thread 'the_startup_pass_quarantines_approvals_that_left_their_containers' (31536) panicked at tests\v2_auth.rs:260:9:
 Error: no tenant with slug acme

note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
error: test failed, to rerun pass `--test v2_auth`
```

### Row command G2-01

`cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- authz_record::tests::golden_vectors --nocapture`

Exit 0; 0.2 s; 1 filters; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 299 filtered out; finished in 0.01s
```

### Row command G2-02

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- every_capability_grant_column_is_compared_with_its_container_on_each_request_and_at_startup --nocapture`

Exit 101; 0.4 s; 1 filters; unmatched filters: ['every_capability_grant_column_is_compared_with_its_container_on_each_request_and_at_startup'].

```text
test every_capability_grant_column_is_compared_with_its_container_on_each_request_and_at_startup ... FAILED
failures:
failures:
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 74 filtered out; finished in 0.03s
error: test failed, to rerun pass `--test v2_auth`

running 1 test
test every_capability_grant_column_is_compared_with_its_container_on_each_request_and_at_startup ... FAILED

failures:

failures:
    every_capability_grant_column_is_compared_with_its_container_on_each_request_and_at_startup

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 74 filtered out; finished in 0.03s

    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.25s
     Running tests\v2_auth.rs (C:/Users/User/AppData/Local/Temp/g264-target-codex\debug\deps\v2_auth-adbaa5c4f4d9fcb5.exe)

thread 'every_capability_grant_column_is_compared_with_its_container_on_each_request_and_at_startup' (7324) panicked at tests\v2_auth.rs:144:10:
called `Result::unwrap()` on an `Err` value: Database(SqliteError { code: 1555, message: "UNIQUE constraint failed: v2_server_state.singleton" })
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
error: test failed, to rerun pass `--test v2_auth`
```

### Row command G2-02

`cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- authz_record::tests::golden_vectors --nocapture`

Exit 0; 0.2 s; 1 filters; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 299 filtered out; finished in 0.02s
```

### Row command G2-03

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- every_fleet_grant_column_is_compared_with_its_container_on_each_request the_startup_pass_quarantines_fleet_grants_that_left_their_containers --nocapture`

Exit 101; 0.4 s; 2 filters; unmatched filters: ['every_fleet_grant_column_is_compared_with_its_container_on_each_request', 'the_startup_pass_quarantines_fleet_grants_that_left_their_containers'].

```text
test every_fleet_grant_column_is_compared_with_its_container_on_each_request ... FAILED
test the_startup_pass_quarantines_fleet_grants_that_left_their_containers ... FAILED
failures:
failures:
test result: FAILED. 0 passed; 2 failed; 0 ignored; 0 measured; 73 filtered out; finished in 0.04s
error: test failed, to rerun pass `--test v2_auth`

running 2 tests
test every_fleet_grant_column_is_compared_with_its_container_on_each_request ... FAILED
test the_startup_pass_quarantines_fleet_grants_that_left_their_containers ... FAILED

failures:

failures:
    every_fleet_grant_column_is_compared_with_its_container_on_each_request
    the_startup_pass_quarantines_fleet_grants_that_left_their_containers

test result: FAILED. 0 passed; 2 failed; 0 ignored; 0 measured; 73 filtered out; finished in 0.04s

    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.27s
     Running tests\v2_auth.rs (C:/Users/User/AppData/Local/Temp/g264-target-codex\debug\deps\v2_auth-adbaa5c4f4d9fcb5.exe)

thread 'every_fleet_grant_column_is_compared_with_its_container_on_each_request' (28732) panicked at tests\v2_auth.rs:144:10:
called `Result::unwrap()` on an `Err` value: Database(SqliteError { code: 1555, message: "UNIQUE constraint failed: v2_server_state.singleton" })
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace

thread 'the_startup_pass_quarantines_fleet_grants_that_left_their_containers' (25004) panicked at tests\v2_auth.rs:144:10:
called `Result::unwrap()` on an `Err` value: Database(SqliteError { code: 1555, message: "UNIQUE constraint failed: v2_server_state.singleton" })
error: test failed, to rerun pass `--test v2_auth`
```

### Row command G2-03

`cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- authz_record::tests::golden_vectors --nocapture`

Exit 0; 0.2 s; 1 filters; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 299 filtered out; finished in 0.02s
```

### Row command G2-04

`cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- recovery_grant_binds_context_suite_and_lengths recovery_grant_opens_only_under_its_root_and_to_its_fkek authz_record::tests::golden_vectors --nocapture`

Exit 0; 0.2 s; 3 filters; unmatched filters: [].

```text
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 297 filtered out; finished in 0.03s
```

### Row command G2-04

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- every_fleet_grant_column_is_compared_with_its_container_on_each_request --nocapture`

Exit 101; 0.4 s; 1 filters; unmatched filters: ['every_fleet_grant_column_is_compared_with_its_container_on_each_request'].

```text
test every_fleet_grant_column_is_compared_with_its_container_on_each_request ... FAILED
failures:
failures:
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 74 filtered out; finished in 0.06s
error: test failed, to rerun pass `--test v2_auth`

running 1 test
test every_fleet_grant_column_is_compared_with_its_container_on_each_request ... FAILED

failures:

failures:
    every_fleet_grant_column_is_compared_with_its_container_on_each_request

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 74 filtered out; finished in 0.06s

    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.22s
     Running tests\v2_auth.rs (C:/Users/User/AppData/Local/Temp/g264-target-codex\debug\deps\v2_auth-adbaa5c4f4d9fcb5.exe)

thread 'every_fleet_grant_column_is_compared_with_its_container_on_each_request' (25292) panicked at tests\v2_auth.rs:144:10:
called `Result::unwrap()` on an `Err` value: Database(SqliteError { code: 1555, message: "UNIQUE constraint failed: v2_server_state.singleton" })
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
error: test failed, to rerun pass `--test v2_auth`
```

### Row command G2-05

`cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- rotation_grant_follows_its_generation_window_and_count_rules authz_record::tests::golden_vectors --nocapture`

Exit 0; 0.2 s; 2 filters; unmatched filters: [].

```text
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 298 filtered out; finished in 0.01s
```

### Row command G2-05

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- every_fleet_grant_column_is_compared_with_its_container_on_each_request --nocapture`

Exit 101; 0.3 s; 1 filters; unmatched filters: ['every_fleet_grant_column_is_compared_with_its_container_on_each_request'].

```text
test every_fleet_grant_column_is_compared_with_its_container_on_each_request ... FAILED
failures:
failures:
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 74 filtered out; finished in 0.03s
error: test failed, to rerun pass `--test v2_auth`

running 1 test
test every_fleet_grant_column_is_compared_with_its_container_on_each_request ... FAILED

failures:

failures:
    every_fleet_grant_column_is_compared_with_its_container_on_each_request

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 74 filtered out; finished in 0.03s

    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.22s
     Running tests\v2_auth.rs (C:/Users/User/AppData/Local/Temp/g264-target-codex\debug\deps\v2_auth-adbaa5c4f4d9fcb5.exe)

thread 'every_fleet_grant_column_is_compared_with_its_container_on_each_request' (17076) panicked at tests\v2_auth.rs:144:10:
called `Result::unwrap()` on an `Err` value: Database(SqliteError { code: 1555, message: "UNIQUE constraint failed: v2_server_state.singleton" })
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
error: test failed, to rerun pass `--test v2_auth`
```

### Row command G2-06

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- every_root_grant_column_is_compared_with_its_container_on_each_request_and_at_startup --nocapture`

Exit 101; 0.3 s; 1 filters; unmatched filters: ['every_root_grant_column_is_compared_with_its_container_on_each_request_and_at_startup'].

```text
test every_root_grant_column_is_compared_with_its_container_on_each_request_and_at_startup ... FAILED
failures:
failures:
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 74 filtered out; finished in 0.01s
error: test failed, to rerun pass `--test v2_auth`

running 1 test
test every_root_grant_column_is_compared_with_its_container_on_each_request_and_at_startup ... FAILED

failures:

failures:
    every_root_grant_column_is_compared_with_its_container_on_each_request_and_at_startup

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 74 filtered out; finished in 0.01s

    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.25s
     Running tests\v2_auth.rs (C:/Users/User/AppData/Local/Temp/g264-target-codex\debug\deps\v2_auth-adbaa5c4f4d9fcb5.exe)

thread 'every_root_grant_column_is_compared_with_its_container_on_each_request_and_at_startup' (21140) panicked at tests\v2_auth.rs:144:10:
called `Result::unwrap()` on an `Err` value: Database(SqliteError { code: 1555, message: "UNIQUE constraint failed: v2_server_state.singleton" })
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
error: test failed, to rerun pass `--test v2_auth`
```

### Row command G2-06

`cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- authz_record::tests::golden_vectors --nocapture`

Exit 0; 0.2 s; 1 filters; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 299 filtered out; finished in 0.02s
```

### Row command G2-07

`cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- snapshot_v2::tests::golden_vectors payload_rejects_every_field_level_defect container_rejects_every_field_level_defect signing_binds_the_signer_key manifest_binds_a_sealed_envelope_v2_object --nocapture`

Exit 0; 0.2 s; 5 filters; unmatched filters: [].

```text
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 294 filtered out; finished in 0.05s
```

### Row command G2-08

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_profiles -- every_upload_refusal_has_its_status_and_code --nocapture`

Exit 0; 11.9 s; 1 filters; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out; finished in 11.49s
```

### Row command G2-09

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_profiles -- an_upload_commits_once_and_the_next_checkout_starts_at_its_head --nocapture`

Exit 0; 4.6 s; 1 filters; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out; finished in 4.33s
```

### `cargo test --locked -j 2 --manifest-path server/Cargo.toml -- --nocapture`

Exit 101; 147.2 seconds.

```text
    Finished `test` profile [unoptimized + debuginfo] target(s) in 6.56s
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
warning: C:\Users\User\AppData\Local\Temp\shardx-audit-squat-29412\audit-ro-failures is not a regular file; remove it, the audit failure count needs that name
warning: C:\Users\User\AppData\Local\Temp\shardx-audit-squat-29412\audit-ro-failures is a link or reparse point; remove it, the audit failure count is never written through one
warning: the count file was not understood; set aside as C:\Users\User\AppData\Local\Temp\shardx-audit-switch-29412\audit-ro-failures.corrupt-1793582582405
warning: the count file was not understood; set aside as C:\Users\User\AppData\Local\Temp\shardx-audit-hostile-29412\audit-ro-failures.corrupt-1793582582450
warning: the count file was not understood; set aside as C:\Users\User\AppData\Local\Temp\shardx-audit-hostile-29412\audit-ro-failures.corrupt-1793582582452
test result: ok. 106 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 28.72s
test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 4.95s
test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 22 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 4.88s
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.96s
SKIPPED: cannot create a symlink here: A required privilege is not held by the client. (os error 1314)
test result: ok. 24 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 21.13s
failures:
failures:
test result: FAILED. 74 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 79.80s
error: test failed, to rerun pass `--test v2_auth`
2026-11-02T01:25:16.481198Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-02T01:25:17.068403Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-02T01:25:17.085650Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-02T01:25:17.087117Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-02T01:25:17.087185Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-02T01:25:17.090403Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-02T01:25:17.558802Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-02T01:25:17.577570Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-02T01:25:17.579328Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-02T01:25:17.579371Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-02T01:25:17.582316Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-02T01:25:18.066540Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-02T01:25:18.084769Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-02T01:25:18.085950Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-02T01:25:18.085989Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-02T01:25:18.088499Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-02T01:25:18.597586Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-02T01:25:18.616938Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-02T01:25:18.618332Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-02T01:25:18.618401Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-02T01:25:18.621003Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-02T01:25:19.121835Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-02T01:25:19.139125Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-02T01:25:19.140274Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-02T01:25:19.140312Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-02T01:25:19.142729Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-02T01:25:19.650526Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-02T01:25:19.667657Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-02T01:25:19.669158Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-02T01:25:19.669205Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-02T01:25:19.671681Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-02T01:25:20.179821Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-02T01:25:20.196987Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-02T01:25:20.198382Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-02T01:25:20.198422Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-02T01:25:20.200810Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-02T01:25:20.741842Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-02T01:25:20.759746Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-02T01:25:20.761077Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-02T01:25:20.761129Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-02T01:25:20.763867Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-02T01:25:21.259445Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-02T01:25:21.276449Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-02T01:25:21.277562Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-02T01:25:21.277597Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-02T01:25:21.280517Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-02T01:25:21.886879Z  WARN shardx_team_server::quarantine: quarantined a stored grant that does not match its signed container kind="root_grant"
2026-11-02T01:25:21.904153Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 1, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-02T01:25:21.905296Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-02T01:25:21.905334Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-02T01:25:21.907808Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
2026-11-02T01:25:22.393481Z  INFO shardx_team_server: v2 integrity pass report=Report { quarantined_devices: 0, guards_created: 0, guards_to_recovery: 0, quarantined_grants: 0, untrusted_revocations: [], revocations_served_again: 0, foreign_key_violations: 0 }
2026-11-02T01:25:22.396102Z  INFO shardx_team_server: v2 upload reconciliation report=Report { kept: 0, promoted: 0, committed: 0, quarantined: 0, retried: 0, staging_removed: 0, aborted: 0 }
2026-11-02T01:25:22.396224Z  INFO shardx_team_server: server identity verified: instance 07070707070707070707070707070707 epoch 0
2026-11-02T01:25:22.399831Z  INFO shardx_team_server: ShardX Team Server listening on http://127.0.0.1:28312
test every_root_grant_column_is_compared_with_its_container_on_each_request_and_at_startup ... ok

failures:

failures:
    the_first_device_approves_itself_once_and_a_retry_gets_the_same_receipt

test result: FAILED. 74 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 79.80s

error: test failed, to rerun pass `--test v2_auth`
```

### `cargo build --locked -j 2 --manifest-path server/Cargo.toml`

Exit 0; 6.3 seconds.

```text
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 6.21s
```

### `cargo test --locked -j 2 --manifest-path src-tauri/Cargo.toml --lib -- --nocapture --skip credential::tests::a_real_os_store_key_survives_into_a_fresh_process`

Exit 0; 211.7 seconds.

```text
    Finished `test` profile [unoptimized + debuginfo] target(s) in 1.07s
test result: ok. 502 passed; 0 failed; 11 ignored; 0 measured; 1 filtered out; finished in 210.50s
```

### `cargo +stable clippy --locked -j 2 --manifest-path shared/Cargo.toml --all-targets -- -D warnings`

Exit 0; 0.7 seconds.

```text
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.44s
```

### `cargo +stable clippy --locked -j 2 --manifest-path server/Cargo.toml --all-targets -- -D warnings`

Exit 0; 0.8 seconds.

```text
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.74s
```

### `cargo +stable clippy --locked -j 2 --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings`

Exit 0; 1.3 seconds.

```text
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1.14s
```

### `cargo +1.87.0 check --locked -j 2 --all-targets --manifest-path shared/Cargo.toml`

Exit 0; 0.7 seconds.

```text
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.61s
```

### `cargo +1.89.0 check --locked -j 2 --all-targets --manifest-path server/Cargo.toml`

Exit 0; 1.2 seconds.

```text
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1.16s
```

### `cargo +1.88.0 check --locked -j 2 --all-targets --manifest-path src-tauri/Cargo.toml`

Exit 0; 1.8 seconds.

```text
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1.69s
```

### Serial reproduction Server full serial rerun

`cargo test --locked -j 2 --manifest-path server/Cargo.toml -- --nocapture`

Exit 0; 214.8 s; unmatched filters: [].

```text
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.06s
test audit::tests::a_failed_read_only_audit_write_is_logged_and_counted ... ok
test result: ok. 106 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 35.35s
test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 8.74s
test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
skipping: cannot create a symlink here: A required privilege is not held by the client. (os error 1314)
Error: another instance holds the data directory lock C:\Users\User\AppData\Local\Temp\shardx-idauth-lock-1812\data\shardx.lock (the server is running?); stop it first
test result: ok. 22 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 5.81s
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.79s
SKIPPED: cannot create a symlink here: A required privilege is not held by the client. (os error 1314)
test g2_55_a_read_only_start_logs_the_failed_audit_writes_counted_so_far ... ok
test g2_55_a_failed_read_only_audit_write_is_counted_in_restore_status ... ok
test result: ok. 24 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 25.94s
2026-11-02T01:31:01.529248Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: the integrity pass failed: checking the device revocations failed: Internal("db: error occurred while decoding column 0: mismatched types; Rust type `alloc::vec::Vec<u8>` (as SQL type `BLOB`) is not compatible with SQL type `INTEGER`"); v1 is unaffected
2026-11-02T01:31:33.576529Z  WARN shardx_team_server::integrity: a device revocation mark could not be recorded: error returned from database: (code: 787) FOREIGN KEY constraint failed
test result: ok. 75 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 75.53s
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.73s
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 7.30s
test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.05s
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.66s
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.36s
2026-11-02T01:32:14.223424Z ERROR tower_http::trace::on_failure: response failed classification=Status code: 500 Internal Server Error latency=47 ms
2026-11-02T01:32:15.413548Z ERROR tower_http::trace::on_failure: response failed classification=Status code: 500 Internal Server Error latency=45 ms
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 11.75s
test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 7.75s
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.51s
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.39s
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.34s
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.36s
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.73s
test result: ok. 23 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 11.23s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

### Serial reproduction G2-01

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- the_first_device_approves_itself_once_and_a_retry_gets_the_same_receipt every_approval_column_is_compared_with_its_container_on_each_request the_startup_pass_quarantines_approvals_that_left_their_containers --nocapture`

Exit 0; 7.1 s; unmatched filters: [].

```text
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 72 filtered out; finished in 6.00s
```

### Serial reproduction G2-01

`cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- authz_record::tests::golden_vectors --nocapture`

Exit 0; 0.2 s; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 299 filtered out; finished in 0.04s
```

### Serial reproduction G2-02

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- every_capability_grant_column_is_compared_with_its_container_on_each_request_and_at_startup --nocapture`

Exit 0; 14.1 s; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 74 filtered out; finished in 13.75s
```

### Serial reproduction G2-02

`cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- authz_record::tests::golden_vectors --nocapture`

Exit 0; 0.1 s; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 299 filtered out; finished in 0.01s
```

### Serial reproduction G2-03

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- every_fleet_grant_column_is_compared_with_its_container_on_each_request the_startup_pass_quarantines_fleet_grants_that_left_their_containers --nocapture`

Exit 0; 9.0 s; unmatched filters: [].

```text
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 73 filtered out; finished in 8.72s
```

### Serial reproduction G2-03

`cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- authz_record::tests::golden_vectors --nocapture`

Exit 0; 0.1 s; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 299 filtered out; finished in 0.01s
```

### Serial reproduction G2-04

`cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- recovery_grant_binds_context_suite_and_lengths recovery_grant_opens_only_under_its_root_and_to_its_fkek authz_record::tests::golden_vectors --nocapture`

Exit 0; 0.1 s; unmatched filters: [].

```text
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 297 filtered out; finished in 0.01s
```

### Serial reproduction G2-04

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- every_fleet_grant_column_is_compared_with_its_container_on_each_request --nocapture`

Exit 0; 9.6 s; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 74 filtered out; finished in 9.36s
```

### Serial reproduction G2-05

`cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- rotation_grant_follows_its_generation_window_and_count_rules authz_record::tests::golden_vectors --nocapture`

Exit 0; 0.1 s; unmatched filters: [].

```text
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 298 filtered out; finished in 0.01s
```

### Serial reproduction G2-05

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- every_fleet_grant_column_is_compared_with_its_container_on_each_request --nocapture`

Exit 0; 8.2 s; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 74 filtered out; finished in 7.95s
```

### Serial reproduction G2-06

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- every_root_grant_column_is_compared_with_its_container_on_each_request_and_at_startup --nocapture`

Exit 0; 31.1 s; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 74 filtered out; finished in 30.80s
```

### Serial reproduction G2-06

`cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- authz_record::tests::golden_vectors --nocapture`

Exit 0; 0.1 s; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 299 filtered out; finished in 0.01s
```

### Serial reproduction G2-07

`cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- snapshot_v2::tests::golden_vectors payload_rejects_every_field_level_defect container_rejects_every_field_level_defect signing_binds_the_signer_key manifest_binds_a_sealed_envelope_v2_object --nocapture`

Exit 0; 0.1 s; unmatched filters: [].

```text
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 294 filtered out; finished in 0.01s
```

### Serial reproduction G2-08

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_profiles -- every_upload_refusal_has_its_status_and_code --nocapture`

Exit 0; 7.6 s; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out; finished in 7.34s
```

### Serial reproduction G2-09

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_profiles -- an_upload_commits_once_and_the_next_checkout_starts_at_its_head --nocapture`

Exit 0; 4.4 s; unmatched filters: [].

```text
2026-11-02T01:34:14.219312Z ERROR tower_http::trace::on_failure: response failed classification=Status code: 500 Internal Server Error latency=39 ms
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out; finished in 4.11s
```

### Serial reproduction G2-10

`cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- the_closed_maps_parse_what_the_builders_write every_dek_slot_context_rule_is_enforced every_dek_slot_rule_is_enforced a_slot_that_differs_from_the_intent_is_refused the_reader_refuses_an_open_map g2_golden_vector_dek_slot g2_golden_vector_dek_slot_context_hash --nocapture`

Exit 0; 0.1 s; unmatched filters: [].

```text
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 293 filtered out; finished in 0.01s
```

### Serial reproduction G2-11

`cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- the_intent_bounds_are_the_plans every_envelope_intent_rule_is_enforced the_intent_and_slot_must_be_the_ones_the_manifest_names manifest_binds_a_sealed_envelope_v2_object g2_golden_vector_intent g2_golden_vector_intent_genesis --nocapture`

Exit 0; 0.1 s; unmatched filters: [].

```text
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 294 filtered out; finished in 0.01s
```

### Serial reproduction G2-12

`cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- restore_epoch::tests::golden_vectors leaf_roundtrips_and_refuses_contract_violations leaf_sets_must_be_non_empty_sorted_and_unique every_leaf_proves_and_every_tampering_fails a_proof_binds_tenant_profile_instance_epochs_count_and_root proof_parser_refuses_every_contract_violation g2_golden_vectors_merkle_roots --nocapture`

Exit 0; 0.2 s; unmatched filters: [].

```text
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 293 filtered out; finished in 0.08s
```

### Serial reproduction G2-13

`cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- transition_roundtrips_and_verifies transition_payload_refuses_every_contract_violation signed_transition_refuses_every_container_defect transition_signature_binds_key_bytes_and_label --nocapture`

Exit 0; 0.1 s; unmatched filters: [].

```text
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 296 filtered out; finished in 0.02s
```

### Serial reproduction G2-14

`cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- mutation::tests::golden_vectors every_map_roundtrips_byte_for_byte every_map_refuses_another_domain_or_version every_kind_has_one_scope_and_the_scope_must_match hashes_and_closed_fields_are_checked device_revoke_maps_carry_one_container_and_roundtrip fleet_lifecycle::tests::golden_vectors --nocapture`

Exit 0; 3.2 s; unmatched filters: [].

```text
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 292 filtered out; finished in 3.11s
```

### Serial reproduction G2-14

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- a_revocation_commits_its_fleet_activation_or_nothing a_revocation_commits_its_root_activation --nocapture`

Exit 0; 3.9 s; unmatched filters: [].

```text
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 73 filtered out; finished in 3.58s
```

### Serial reproduction G2-15

`cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- mutation::tests::golden_vectors every_map_roundtrips_byte_for_byte every_map_refuses_another_domain_or_version --nocapture`

Exit 0; 0.1 s; unmatched filters: [].

```text
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 296 filtered out; finished in 0.00s
```

### Serial reproduction G2-16

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- the_first_device_bootstraps_the_root_once_and_a_retry_gets_the_same_response --nocapture`

Exit 0; 2.6 s; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 74 filtered out; finished in 2.32s
```

### Serial reproduction G2-17

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- every_root_grant_column_is_compared_with_its_container_on_each_request_and_at_startup --nocapture`

Exit 0; 32.2 s; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 74 filtered out; finished in 31.98s
```

### Serial reproduction G2-18

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- readback_ack_and_activate_refuse_anything_but_the_exact_stored_grant --nocapture`

Exit 0; 3.5 s; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 74 filtered out; finished in 3.21s
```

### Serial reproduction G2-19

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- readback_ack_and_activate_refuse_anything_but_the_exact_stored_grant --nocapture`

Exit 0; 3.6 s; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 74 filtered out; finished in 3.22s
```

### Serial reproduction G2-20

`cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- a_revocation_names_a_known_reason_and_its_outcome --nocapture`

Exit 0; 0.1 s; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 299 filtered out; finished in 0.00s
```

### Serial reproduction G2-20

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- a_custodian_revokes_a_root_grant_but_never_the_last_one --nocapture`

Exit 0; 4.9 s; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 74 filtered out; finished in 4.64s
```

### Serial reproduction G2-21

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_profiles -- one_lease_and_one_fence_per_grant_and_every_retry_gets_the_stored_bytes --nocapture`

Exit 0; 4.3 s; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out; finished in 3.99s
```

### Serial reproduction G2-21

`cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_profile_is_published_with_its_first_lease_and_then_pushed every_publish_crash_point_resumes_with_the_exact_stored_bytes --nocapture --skip credential::tests::a_real_os_store_key_survives_into_a_fresh_process`

Exit 0; 2.9 s; unmatched filters: [].

```text
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 512 filtered out; finished in 1.71s
```

### Serial reproduction G2-22

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_profiles -- one_lease_and_one_fence_per_grant_and_every_retry_gets_the_stored_bytes a_stored_response_naming_another_profile_or_lease_is_never_replayed --nocapture`

Exit 0; 4.6 s; unmatched filters: [].

```text
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out; finished in 4.30s
```

### Serial reproduction G2-22

`cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_checkout_reply_for_another_tenant_fleet_or_expiry_is_never_kept a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key --nocapture --skip credential::tests::a_real_os_store_key_survives_into_a_fresh_process`

Exit 0; 2.5 s; unmatched filters: [].

```text
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 512 filtered out; finished in 2.01s
```

### Serial reproduction G2-23

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_profiles -- an_upload_commits_once_and_the_next_checkout_starts_at_its_head every_upload_refusal_has_its_status_and_code --nocapture`

Exit 0; 10.0 s; unmatched filters: [].

```text
2026-11-02T01:35:28.118673Z ERROR tower_http::trace::on_failure: response failed classification=Status code: 500 Internal Server Error latency=42 ms
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out; finished in 9.68s
```

### Serial reproduction G2-23

`cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_create_upload_whose_reply_was_lost_is_replayed_byte_for_byte --nocapture --skip credential::tests::a_real_os_store_key_survives_into_a_fresh_process`

Exit 0; 2.9 s; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 513 filtered out; finished in 1.73s
```

### Serial reproduction G2-24

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_profiles -- an_upload_commits_once_and_the_next_checkout_starts_at_its_head a_restart_reconciles_uploads_and_an_abort_frees_the_lease_slot --nocapture`

Exit 0; 6.5 s; unmatched filters: [].

```text
2026-11-02T01:35:40.751160Z ERROR tower_http::trace::on_failure: response failed classification=Status code: 500 Internal Server Error latency=40 ms
2026-11-02T01:35:42.416309Z ERROR tower_http::trace::on_failure: response failed classification=Status code: 500 Internal Server Error latency=46 ms
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out; finished in 6.12s
```

### Serial reproduction G2-24

`cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- every_crash_point_resumes_with_the_exact_stored_bytes --nocapture --skip credential::tests::a_real_os_store_key_survives_into_a_fresh_process`

Exit 0; 3.0 s; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 513 filtered out; finished in 2.13s
```

### Serial reproduction G2-25

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_profiles -- one_lease_and_one_fence_per_grant_and_every_retry_gets_the_stored_bytes a_stored_response_naming_another_profile_or_lease_is_never_replayed --nocapture`

Exit 0; 4.8 s; unmatched filters: [].

```text
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out; finished in 4.36s
```

## Independent adversarial scope probe

Compile from stdin against unchanged `shardx_core`; `counted` extracted verbatim from launcher source in memory. Only compiler artifacts created in the designated build target. Initial link attempt lacked native library paths; this invocation includes Cargo build-script linked paths.

`rustc +stable --edition=2021 --crate-name g264_scope_probe - --extern shardx_core=C:\Users\User\AppData\Local\Temp\g264-target-codex\debug\libshardx_core.rlib -L dependency=C:\Users\User\AppData\Local\Temp\g264-target-codex\debug\deps -o C:\Users\User\AppData\Local\Temp\g264-target-codex\g264_scope_probe.exe -L native=C:\Users\User\.cargo\registry\src\index.crates.io-1949cf8c6b5b557f\windows_x86_64_msvc-0.52.6\lib -L native=C:\Users\User\AppData\Local\Temp\g264-target-codex\debug\build\libsqlite3-sys-e54f11981502ec6e\out`

Source SHA-256: 142717e3bfc1c8c933f5053ee742cdfa2511125a30854992126bd012cf335920

```text
compile exit 0
probe exit 0
injected=false; outsider_custodian=false; victim_has_valid_tenant_approval=false; scope_is_tenant=false; valid_compromised_revocation_counted=true
injected=true; outsider_custodian=false; victim_has_valid_tenant_approval=false; scope_is_tenant=true; valid_compromised_revocation_counted=false

```

```rust

use shardx_core::authz_record::*;
use shardx_core::keys::signing_key_id;
use shardx_core::signing::Ed25519SigningKey as SigningKey;
use shardx_core::trust_chain::{Binding, Evidence, TrustChain, Scope};
use shardx_core::trust_evidence::TenantTrustEvidencePageV2;
use std::collections::BTreeMap;
const T:u64=1_800_000_000_000;
const DAY:u64=86_400_000;
const TENANT:[u8;16]=[1;16];
const INSTANCE:[u8;16]=[2;16];
const FLEET:[u8;16]=[5;16];
fn common(n:u8)->CommonFields { CommonFields{replay_id:[n;16],tenant_id:TENANT,issued_at_ms:T,not_before_ms:T,not_after_ms:T+30*DAY,server_instance_id:INSTANCE,restore_epoch:0} }
fn pk(k:&SigningKey)->[u8;32]{*k.verifying_key().as_bytes()}
fn id(k:&SigningKey)->[u8;32]{signing_key_id(&pk(k))}
fn approval(issuer:&SigningKey,subject:&SigningKey,n:u8,scope:ApprovalScopeKind)->Vec<u8>{let a=DeviceApprovalV2{common:common(n),subject_account_id:[9;16],subject_device_id:[if n==10 {1}else{2};16],subject_signing_key_id:id(subject),subject_hpke_key_id:[8;32],approval_scope_kind:scope,approval_scope_id:if scope==ApprovalScopeKind::Tenant {TENANT}else{FLEET}};build_record(issuer,DOMAIN_DEVICE_APPROVAL,&a.encode())}
fn cap(k:&SigningKey,n:u8,c:Capability,scope:CapabilityScopeKind)->Vec<u8>{let g=TenantCapabilityGrantV2{common:common(n),subject:GrantSubject::Device{account_id:[9;16],device_id:[1;16],signing_key_id:id(k),hpke_key_id:[8;32]},scope_kind:scope,scope_id:if scope==CapabilityScopeKind::Tenant {TENANT}else{FLEET},capability:c};build_record(k,DOMAIN_TENANT_CAPABILITY_GRANT,&g.encode())}
fn main(){
 let a=SigningKey::from_bytes(&[1;32]);let victim=SigningKey::from_bytes(&[2;32]);let outsider=SigningKey::from_bytes(&[3;32]);let binding=Binding{tenant_id:TENANT,server_instance_id:INSTANCE};
 let root=TenantRootKeyGrantV2{common:common(11),variant:RootGrantVariant::FirstRootSelfGrant,root_key_id:[7;32],root_generation:0,subject_account_id:[9;16],subject_device_id:[1;16],subject_signing_key_id:id(&a),recipient_hpke_key_id:[8;32],subject_device_approval_replay_id:[10;16],hpke_encapped_key_bytes:[3;32],hpke_wrapped_trk_bytes:[4;48]};
 let mut page=TenantTrustEvidencePageV2{server_instance_id:INSTANCE,tenant_id:TENANT,server_now_ms:T+DAY,page_index:0,next_cursor:vec![],signing_public_keys:vec![pk(&a),pk(&victim),pk(&outsider)],containers:vec![approval(&a,&a,10,ApprovalScopeKind::Tenant),build_record(&a,DOMAIN_TENANT_ROOT_KEY_GRANT,&root.encode()),cap(&a,12,Capability::DeviceApprove,CapabilityScopeKind::Tenant),cap(&a,13,Capability::DeviceRevoke,CapabilityScopeKind::Fleet),approval(&a,&victim,20,ApprovalScopeKind::Fleet)],revocations:vec![],device_revocations:vec![]};
 let revoke=DeviceRevocationV2{common:common(30),subject_account_id:[9;16],subject_device_id:[2;16],subject_signing_key_id:id(&victim),subject_hpke_key_id:[8;32],reason_code:DeviceRevocationReason::Compromised};let bytes=build_record(&a,DOMAIN_DEVICE_REVOCATION,&revoke.encode());page.containers.push(bytes.clone());
 let keys=BTreeMap::from([(id(&a),pk(&a)),(id(&victim),pk(&victim)),(id(&outsider),pk(&outsider))]);
 for injected in [false,true]{
  if injected{page.containers.push(approval(&outsider,&victim,21,ApprovalScopeKind::Tenant));}
  let chain=TrustChain::evaluate(Evidence::collect(&binding,&[page.clone()]).unwrap(),Some(&id(&a))).unwrap();
  let outcome=counted(&chain,&binding,&keys,AuthorizationRecord::parse(&bytes).unwrap(),T+DAY).is_some();
  println!("injected={injected}; outsider_custodian={}; victim_has_valid_tenant_approval={}; scope_is_tenant={}; valid_compromised_revocation_counted={outcome}",chain.custodian_at(&id(&outsider),T),chain.approval_valid_at(&id(&victim),Scope::Tenant,T),chain.revocation_scope(&id(&victim))==Scope::Tenant);
  assert_eq!(outcome,!injected);assert!(!chain.custodian_at(&id(&outsider),T));assert!(!chain.approval_valid_at(&id(&victim),Scope::Tenant,T));
 }
}
fn counted(
    chain: &TrustChain,
    binding: &Binding,
    keys: &BTreeMap<[u8; 32], [u8; 32]>,
    record: AuthorizationRecord,
    first_seen_ms: u64,
) -> Option<DeviceRevocationV2> {
    let issuer = *record.issuer_signing_key_id();
    let verified = record.verify_signature(keys.get(&issuer)?).ok()?;
    let Payload::DeviceRevocation(d) = verified.payload() else {
        return None;
    };
    let t = d.common.issued_at_ms;
    (d.common.tenant_id == binding.tenant_id
        && d.common.server_instance_id == binding.server_instance_id
        && chain.custodian_at(&issuer, t)
        && chain.capability_at(
            &issuer,
            Capability::DeviceRevoke,
            chain.revocation_scope(&d.subject_signing_key_id),
            t,
        )
        && chain.custodian_now(&issuer, first_seen_ms))
    .then(|| d.clone())
}

```

### Serial reproduction G2-25

`cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_release_whose_reply_was_lost_is_replayed_byte_for_byte --nocapture --skip credential::tests::a_real_os_store_key_survives_into_a_fresh_process`

Exit 0; 0.8 s; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 513 filtered out; finished in 0.26s
```

### Serial reproduction G2-26

`cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- the_unbind_maps_round_trip_and_pin_the_tombstone the_unbind_maps_refuse_what_l953_does_not_allow --nocapture`

Exit 0; 0.2 s; unmatched filters: [].

```text
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 298 filtered out; finished in 0.03s
```

### Serial reproduction G2-26

`cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- an_unbind_tombstone_outlives_its_binding_and_replays_exactly an_unbind_at_version_zero_omits_the_head an_unbind_cut_off_at_any_write_leaves_the_binding_whole an_unbind_is_refused_while_a_lease_request_or_journal_is_open --nocapture --skip credential::tests::a_real_os_store_key_survives_into_a_fresh_process`

Exit 0; 2.6 s; unmatched filters: [].

```text
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 510 filtered out; finished in 2.09s
```

### Serial reproduction G2-27

`cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- xchacha20poly1305_matches_the_draft_vector golden_objects every_preamble_rule_is_enforced every_frame_rule_is_enforced the_stream_counter_stops_at_the_provider_maximum --nocapture`

Exit 0; 0.3 s; unmatched filters: [].

```text
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 295 filtered out; finished in 0.17s
```

### Serial reproduction G2-28

`cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- the_pinned_suite_matches_the_rfc_9180_vectors info_bytes_match_g2_vector only_the_granted_device_can_open grant_cannot_be_replayed_into_another_tenant_or_epoch the_fleet_grant_aad_is_the_label_the_length_and_the_info a_device_fleet_grant_opens_only_to_the_key_it_names a_sealed_fleet_key_opens_to_the_exact_same_bytes --nocapture`

Exit 0; 0.1 s; unmatched filters: [].

```text
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 293 filtered out; finished in 0.01s
```

### Serial reproduction G2-29

`cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- signature_binds_issuer_and_bytes small_order_issuer_key_never_verifies rfc8032_vectors_sign_and_verify_strictly speccheck_matrix_accepts_only_the_unambiguous_case g2_golden_vector_signed_container_hash --nocapture`

Exit 0; 0.1 s; unmatched filters: [].

```text
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 295 filtered out; finished in 0.03s
```

### Serial reproduction G2-30

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- every_device_revocation_column_is_compared_with_its_container_on_each_request the_startup_pass_quarantines_device_revocations_that_left_their_containers a_revocation_of_another_instance_turns_v2_off_until_it_is_put_back a_revocation_quarantined_at_runtime_refuses_the_trust_evidence a_quarantined_revocation_that_verifies_again_is_served_again_after_a_restart a_marked_row_swapped_for_another_genuine_revocation_is_not_served_again a_corrupt_container_is_marked_without_a_hash_and_served_again_once_restored the_trust_evidence_reports_a_revoked_device_from_its_record_not_its_column a_revocation_row_swapped_for_another_genuine_one_does_not_answer_a_retry a_revocation_row_the_startup_pass_cannot_read_turns_v2_off --nocapture`

Exit 0; 23.6 s; unmatched filters: [].

```text
2026-11-02T01:36:04.586480Z  WARN shardx_team_server: v2 writes disabled: CONTROL_PLANE_INTEGRITY_UNTRUSTED: the integrity pass failed: checking the device revocations failed: Internal("db: error occurred while decoding column 0: mismatched types; Rust type `alloc::vec::Vec<u8>` (as SQL type `BLOB`) is not compatible with SQL type `INTEGER`"); v1 is unaffected
2026-11-02T01:36:16.479324Z  WARN shardx_team_server::integrity: a device revocation mark could not be recorded: error returned from database: (code: 787) FOREIGN KEY constraint failed
test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 65 filtered out; finished in 23.25s
```

### Serial reproduction G2-30

`cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_kept_revocation_reloads_with_every_column_equal --nocapture --skip credential::tests::a_real_os_store_key_survives_into_a_fresh_process`

Exit 0; 1.8 s; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 513 filtered out; finished in 1.24s
```

### Serial reproduction G2-31

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- the_first_device_approves_itself_once_and_a_retry_gets_the_same_receipt the_first_device_bootstraps_the_root_once_and_a_retry_gets_the_same_response every_custody_operation_replays_its_lost_response_after_a_restart --nocapture`

Exit 0; 12.6 s; unmatched filters: [].

```text
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 72 filtered out; finished in 12.27s
```

### Serial reproduction G2-31

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_e2e -- v2_operations_replay_the_stored_response --nocapture`

Exit 0; 2.3 s; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out; finished in 2.02s
```

### Serial reproduction G2-31

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_profiles -- one_lease_and_one_fence_per_grant_and_every_retry_gets_the_stored_bytes a_stored_response_naming_another_profile_or_lease_is_never_replayed a_restart_reconciles_uploads_and_an_abort_frees_the_lease_slot every_profile_operation_replays_its_lost_response_after_a_restart --nocapture`

Exit 0; 8.4 s; unmatched filters: [].

```text
2026-11-02T01:36:38.981523Z ERROR tower_http::trace::on_failure: response failed classification=Status code: 500 Internal Server Error latency=43 ms
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out; finished in 8.13s
```

### Serial reproduction G2-31

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- d1_replays_of_rolled_back_results_answer_as_superseded_and_kept_ones_replay --nocapture`

Exit 0; 8.2 s; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 23 filtered out; finished in 7.84s
```

### Serial reproduction G2-31

`cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- every_publish_crash_point_resumes_with_the_exact_stored_bytes a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key a_create_upload_whose_reply_was_lost_is_replayed_byte_for_byte every_crash_point_resumes_with_the_exact_stored_bytes a_release_whose_reply_was_lost_is_replayed_byte_for_byte an_unbind_tombstone_outlives_its_binding_and_replays_exactly --nocapture --skip credential::tests::a_real_os_store_key_survives_into_a_fresh_process`

Exit 0; 6.2 s; unmatched filters: [].

```text
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 508 filtered out; finished in 5.69s
```

### Serial reproduction G2-32

`cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_new_database_reopens_with_its_schema_and_settings a_version_5_file_with_data_moves_to_version_6_keeping_every_row the_triggers_and_indexes_of_a_version_5_file_survive_version_6 --nocapture --skip credential::tests::a_real_os_store_key_survives_into_a_fresh_process`

Exit 0; 2.0 s; unmatched filters: [].

```text
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 511 filtered out; finished in 1.54s
```

### Serial reproduction G2-33

`cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- an_unbind_tombstone_outlives_its_binding_and_replays_exactly an_unbind_cut_off_at_any_write_leaves_the_binding_whole a_tombstone_that_no_longer_recomputes_is_never_returned an_unbind_after_an_accepted_transition_keeps_its_evidence a_version_4_file_keeps_its_proofs_and_lets_them_outlive_the_binding --nocapture --skip credential::tests::a_real_os_store_key_survives_into_a_fresh_process`

Exit 0; 6.0 s; unmatched filters: [].

```text
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 509 filtered out; finished in 5.50s
```

Scope probe repeated twice: both exit 0; stdout byte-identical.

### Serial reproduction G2-34

`cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_release_whose_reply_was_lost_is_replayed_byte_for_byte an_unsent_cancel_release_is_retried_and_then_given_up an_unreadable_release_reply_is_reported_and_replayed --nocapture --skip credential::tests::a_real_os_store_key_survives_into_a_fresh_process`

Exit 0; 3.5 s; unmatched filters: [].

```text
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 511 filtered out; finished in 2.87s
```

### Serial reproduction G2-35

`cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- six_records_reopen_exactly_and_refuse_every_changed_column a_second_self_grant_and_a_cross_instance_generation_are_refused only_a_self_grant_files_a_generation_and_a_duplicate_row_refuses a_filed_grant_files_the_key_state_it_names a_binding_and_its_rows_name_the_servers_account_and_key a_kept_revocation_reloads_with_every_column_equal --nocapture --skip credential::tests::a_real_os_store_key_survives_into_a_fresh_process`

Exit 0; 3.4 s; unmatched filters: [].

```text
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 508 filtered out; finished in 2.81s
```

### Serial reproduction G2-36

`cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- an_upload_session_refuses_a_second_identity_and_a_stranger_commit_or_key an_interrupted_upload_resumes_at_the_offset_head_reports --nocapture --skip credential::tests::a_real_os_store_key_survives_into_a_fresh_process`

Exit 0; 1.2 s; unmatched filters: [].

```text
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 512 filtered out; finished in 0.56s
```

### Serial reproduction G2-37

`cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- every_crash_point_resumes_with_the_exact_stored_bytes a_stored_column_that_drifts_from_its_bytes_is_never_sent a_stored_publish_that_drifts_from_its_bytes_is_never_sent --nocapture --skip credential::tests::a_real_os_store_key_survives_into_a_fresh_process`

Exit 0; 13.3 s; unmatched filters: [].

```text
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 511 filtered out; finished in 12.71s
```

### Serial reproduction G2-38

`cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_receipt_or_readback_that_does_not_match_is_never_kept a_published_profile_pushes_and_another_device_pulls_it an_upload_session_refuses_a_second_identity_and_a_stranger_commit_or_key --nocapture --skip credential::tests::a_real_os_store_key_survives_into_a_fresh_process`

Exit 0; 2.1 s; unmatched filters: [].

```text
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 511 filtered out; finished in 1.54s
```

## Test citation inventory (repository-derived)

323 row-to-test citations, 271 distinct (file, function) pairs; missing functions: []. References in prose and code paths are not misclassified as test names. G2-62 and G2-64 have no unit-test citation.

| Row | Cited test count | Source locations |
|---|---:|---|
| G2-01 | 4 | `server/tests/v2_auth.rs:1583` the_first_device_approves_itself_once_and_a_retry_gets_the_same_receipt; `server/tests/v2_auth.rs:8686` every_approval_column_is_compared_with_its_container_on_each_request; `server/tests/v2_auth.rs:8792` the_startup_pass_quarantines_approvals_that_left_their_containers; `shared/src/authz_record.rs:1940` golden_vectors |
| G2-02 | 2 | `server/tests/v2_auth.rs:9469` every_capability_grant_column_is_compared_with_its_container_on_each_request_and_at_startup; `shared/src/authz_record.rs:1940` golden_vectors |
| G2-03 | 3 | `server/tests/v2_auth.rs:8444` every_fleet_grant_column_is_compared_with_its_container_on_each_request; `server/tests/v2_auth.rs:8589` the_startup_pass_quarantines_fleet_grants_that_left_their_containers; `shared/src/authz_record.rs:1940` golden_vectors |
| G2-04 | 4 | `shared/src/authz_record.rs:2508` recovery_grant_binds_context_suite_and_lengths; `shared/src/authz_record.rs:2550` recovery_grant_opens_only_under_its_root_and_to_its_fkek; `shared/src/authz_record.rs:1940` golden_vectors; `server/tests/v2_auth.rs:8444` every_fleet_grant_column_is_compared_with_its_container_on_each_request |
| G2-05 | 3 | `shared/src/authz_record.rs:2600` rotation_grant_follows_its_generation_window_and_count_rules; `shared/src/authz_record.rs:1940` golden_vectors; `server/tests/v2_auth.rs:8444` every_fleet_grant_column_is_compared_with_its_container_on_each_request |
| G2-06 | 2 | `server/tests/v2_auth.rs:9166` every_root_grant_column_is_compared_with_its_container_on_each_request_and_at_startup; `shared/src/authz_record.rs:1940` golden_vectors |
| G2-07 | 5 | `shared/src/snapshot_v2.rs:1054` golden_vectors; `shared/src/snapshot_v2.rs:1167` payload_rejects_every_field_level_defect; `shared/src/snapshot_v2.rs:1268` container_rejects_every_field_level_defect; `shared/src/snapshot_v2.rs:1374` signing_binds_the_signer_key; `shared/src/snapshot_v2.rs:1666` manifest_binds_a_sealed_envelope_v2_object |
| G2-08 | 1 | `server/tests/v2_profiles.rs:2646` every_upload_refusal_has_its_status_and_code |
| G2-09 | 1 | `server/tests/v2_profiles.rs:2294` an_upload_commits_once_and_the_next_checkout_starts_at_its_head |
| G2-10 | 7 | `shared/src/envelope_v2.rs:1897` the_closed_maps_parse_what_the_builders_write; `shared/src/envelope_v2.rs:1970` every_dek_slot_context_rule_is_enforced; `shared/src/envelope_v2.rs:2037` every_dek_slot_rule_is_enforced; `shared/src/envelope_v2.rs:2330` a_slot_that_differs_from_the_intent_is_refused; `shared/src/envelope_v2.rs:2380` the_reader_refuses_an_open_map; `shared/src/envelope.rs:769` g2_golden_vector_dek_slot; `shared/src/canonical.rs:666` g2_golden_vector_dek_slot_context_hash |
| G2-11 | 6 | `shared/src/envelope_v2.rs:1688` the_intent_bounds_are_the_plans; `shared/src/envelope_v2.rs:2121` every_envelope_intent_rule_is_enforced; `shared/src/envelope_v2.rs:1665` the_intent_and_slot_must_be_the_ones_the_manifest_names; `shared/src/snapshot_v2.rs:1666` manifest_binds_a_sealed_envelope_v2_object; `shared/src/envelope.rs:780` g2_golden_vector_intent; `shared/src/envelope.rs:792` g2_golden_vector_intent_genesis |
| G2-12 | 7 | `shared/src/restore_epoch.rs:815` golden_vectors; `shared/src/restore_epoch.rs:1088` leaf_roundtrips_and_refuses_contract_violations; `shared/src/restore_epoch.rs:1136` leaf_sets_must_be_non_empty_sorted_and_unique; `shared/src/restore_epoch.rs:1194` every_leaf_proves_and_every_tampering_fails; `shared/src/restore_epoch.rs:1253` a_proof_binds_tenant_profile_instance_epochs_count_and_root; `shared/src/restore_epoch.rs:1291` proof_parser_refuses_every_contract_violation; `shared/src/envelope.rs:819` g2_golden_vectors_merkle_roots |
| G2-13 | 4 | `shared/src/restore_epoch.rs:873` transition_roundtrips_and_verifies; `shared/src/restore_epoch.rs:895` transition_payload_refuses_every_contract_violation; `shared/src/restore_epoch.rs:961` signed_transition_refuses_every_container_defect; `shared/src/restore_epoch.rs:1044` transition_signature_binds_key_bytes_and_label |
| G2-14 | 9 | `shared/src/mutation.rs:1855` golden_vectors; `shared/src/mutation.rs:1738` every_map_roundtrips_byte_for_byte; `shared/src/mutation.rs:1762` every_map_refuses_another_domain_or_version; `shared/src/mutation.rs:1924` every_kind_has_one_scope_and_the_scope_must_match; `shared/src/mutation.rs:1954` hashes_and_closed_fields_are_checked; `shared/src/mutation.rs:2358` device_revoke_maps_carry_one_container_and_roundtrip; `server/tests/v2_auth.rs:5949` a_revocation_commits_its_fleet_activation_or_nothing; `server/tests/v2_auth.rs:6141` a_revocation_commits_its_root_activation; `shared/src/fleet_lifecycle.rs:1142` golden_vectors |
| G2-15 | 3 | `shared/src/mutation.rs:1855` golden_vectors; `shared/src/mutation.rs:1738` every_map_roundtrips_byte_for_byte; `shared/src/mutation.rs:1762` every_map_refuses_another_domain_or_version |
| G2-16 | 1 | `server/tests/v2_auth.rs:2089` the_first_device_bootstraps_the_root_once_and_a_retry_gets_the_same_response |
| G2-17 | 1 | `server/tests/v2_auth.rs:9166` every_root_grant_column_is_compared_with_its_container_on_each_request_and_at_startup |
| G2-18 | 1 | `server/tests/v2_auth.rs:2939` readback_ack_and_activate_refuse_anything_but_the_exact_stored_grant |
| G2-19 | 1 | `server/tests/v2_auth.rs:2939` readback_ack_and_activate_refuse_anything_but_the_exact_stored_grant |
| G2-20 | 2 | `shared/src/mutation.rs:2653` a_revocation_names_a_known_reason_and_its_outcome; `server/tests/v2_auth.rs:5257` a_custodian_revokes_a_root_grant_but_never_the_last_one |
| G2-21 | 3 | `server/tests/v2_profiles.rs:798` one_lease_and_one_fence_per_grant_and_every_retry_gets_the_stored_bytes; `src-tauri/src/team/sync.rs:4506` a_profile_is_published_with_its_first_lease_and_then_pushed; `src-tauri/src/team/sync.rs:4603` every_publish_crash_point_resumes_with_the_exact_stored_bytes |
| G2-22 | 4 | `server/tests/v2_profiles.rs:798` one_lease_and_one_fence_per_grant_and_every_retry_gets_the_stored_bytes; `server/tests/v2_profiles.rs:1845` a_stored_response_naming_another_profile_or_lease_is_never_replayed; `src-tauri/src/team/sync.rs:5251` a_checkout_reply_for_another_tenant_fleet_or_expiry_is_never_kept; `src-tauri/src/team/sync.rs:7864` a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key |
| G2-23 | 3 | `server/tests/v2_profiles.rs:2294` an_upload_commits_once_and_the_next_checkout_starts_at_its_head; `server/tests/v2_profiles.rs:2646` every_upload_refusal_has_its_status_and_code; `src-tauri/src/team/sync.rs:5544` a_create_upload_whose_reply_was_lost_is_replayed_byte_for_byte |
| G2-24 | 3 | `server/tests/v2_profiles.rs:2294` an_upload_commits_once_and_the_next_checkout_starts_at_its_head; `server/tests/v2_profiles.rs:3258` a_restart_reconciles_uploads_and_an_abort_frees_the_lease_slot; `src-tauri/src/team/sync.rs:4358` every_crash_point_resumes_with_the_exact_stored_bytes |
| G2-25 | 3 | `server/tests/v2_profiles.rs:798` one_lease_and_one_fence_per_grant_and_every_retry_gets_the_stored_bytes; `server/tests/v2_profiles.rs:1845` a_stored_response_naming_another_profile_or_lease_is_never_replayed; `src-tauri/src/team/sync.rs:4466` a_release_whose_reply_was_lost_is_replayed_byte_for_byte |
| G2-26 | 6 | `shared/src/profile_lease.rs:1076` the_unbind_maps_round_trip_and_pin_the_tombstone; `shared/src/profile_lease.rs:1126` the_unbind_maps_refuse_what_l953_does_not_allow; `src-tauri/src/team/sync.rs:6873` an_unbind_tombstone_outlives_its_binding_and_replays_exactly; `src-tauri/src/team/sync.rs:6957` an_unbind_at_version_zero_omits_the_head; `src-tauri/src/team/sync.rs:6975` an_unbind_cut_off_at_any_write_leaves_the_binding_whole; `src-tauri/src/team/sync.rs:7011` an_unbind_is_refused_while_a_lease_request_or_journal_is_open |
| G2-27 | 5 | `shared/src/envelope_v2.rs:1111` xchacha20poly1305_matches_the_draft_vector; `shared/src/envelope_v2.rs:1273` golden_objects; `shared/src/envelope_v2.rs:1308` every_preamble_rule_is_enforced; `shared/src/envelope_v2.rs:1461` every_frame_rule_is_enforced; `shared/src/envelope_v2.rs:1223` the_stream_counter_stops_at_the_provider_maximum |
| G2-28 | 7 | `shared/src/grants.rs:503` the_pinned_suite_matches_the_rfc_9180_vectors; `shared/src/grants.rs:619` info_bytes_match_g2_vector; `shared/src/grants.rs:650` only_the_granted_device_can_open; `shared/src/grants.rs:689` grant_cannot_be_replayed_into_another_tenant_or_epoch; `shared/src/grants.rs:925` the_fleet_grant_aad_is_the_label_the_length_and_the_info; `shared/src/grants.rs:935` a_device_fleet_grant_opens_only_to_the_key_it_names; `shared/src/fleet_grants.rs:236` a_sealed_fleet_key_opens_to_the_exact_same_bytes |
| G2-29 | 5 | `shared/src/authz_record.rs:2099` signature_binds_issuer_and_bytes; `shared/src/authz_record.rs:2134` small_order_issuer_key_never_verifies; `shared/src/signing.rs:225` rfc8032_vectors_sign_and_verify_strictly; `shared/src/signing.rs:264` speccheck_matrix_accepts_only_the_unambiguous_case; `shared/src/signing.rs:436` g2_golden_vector_signed_container_hash |
| G2-30 | 11 | `server/tests/v2_auth.rs:9609` every_device_revocation_column_is_compared_with_its_container_on_each_request; `server/tests/v2_auth.rs:9832` the_startup_pass_quarantines_device_revocations_that_left_their_containers; `server/tests/v2_auth.rs:9940` a_revocation_of_another_instance_turns_v2_off_until_it_is_put_back; `server/tests/v2_auth.rs:10000` a_revocation_quarantined_at_runtime_refuses_the_trust_evidence; `server/tests/v2_auth.rs:10061` a_quarantined_revocation_that_verifies_again_is_served_again_after_a_restart; `server/tests/v2_auth.rs:10132` a_marked_row_swapped_for_another_genuine_revocation_is_not_served_again; `server/tests/v2_auth.rs:10280` a_corrupt_container_is_marked_without_a_hash_and_served_again_once_restored; `server/tests/v2_auth.rs:10393` the_trust_evidence_reports_a_revoked_device_from_its_record_not_its_column; `server/tests/v2_auth.rs:10447` a_revocation_row_swapped_for_another_genuine_one_does_not_answer_a_retry; `server/tests/v2_auth.rs:10503` a_revocation_row_the_startup_pass_cannot_read_turns_v2_off; `src-tauri/src/team/sync.rs:6369` a_kept_revocation_reloads_with_every_column_equal |
| G2-31 | 15 | `server/tests/v2_auth.rs:1583` the_first_device_approves_itself_once_and_a_retry_gets_the_same_receipt; `server/tests/v2_auth.rs:2089` the_first_device_bootstraps_the_root_once_and_a_retry_gets_the_same_response; `server/tests/v2_auth.rs:10642` every_custody_operation_replays_its_lost_response_after_a_restart; `server/tests/v2_e2e.rs:251` v2_operations_replay_the_stored_response; `server/tests/v2_profiles.rs:798` one_lease_and_one_fence_per_grant_and_every_retry_gets_the_stored_bytes; `server/tests/v2_profiles.rs:1845` a_stored_response_naming_another_profile_or_lease_is_never_replayed; `server/tests/v2_profiles.rs:3258` a_restart_reconciles_uploads_and_an_abort_frees_the_lease_slot; `server/tests/v2_profiles.rs:3971` every_profile_operation_replays_its_lost_response_after_a_restart; `server/tests/restore_epoch_harness.rs:2203` d1_replays_of_rolled_back_results_answer_as_superseded_and_kept_ones_replay; `src-tauri/src/team/sync.rs:4603` every_publish_crash_point_resumes_with_the_exact_stored_bytes; `src-tauri/src/team/sync.rs:7864` a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key; `src-tauri/src/team/sync.rs:5544` a_create_upload_whose_reply_was_lost_is_replayed_byte_for_byte; `src-tauri/src/team/sync.rs:4358` every_crash_point_resumes_with_the_exact_stored_bytes; `src-tauri/src/team/sync.rs:4466` a_release_whose_reply_was_lost_is_replayed_byte_for_byte; `src-tauri/src/team/sync.rs:6873` an_unbind_tombstone_outlives_its_binding_and_replays_exactly |
| G2-32 | 3 | `src-tauri/src/team/db.rs:1511` a_new_database_reopens_with_its_schema_and_settings; `src-tauri/src/team/db.rs:2213` a_version_5_file_with_data_moves_to_version_6_keeping_every_row; `src-tauri/src/team/db.rs:2168` the_triggers_and_indexes_of_a_version_5_file_survive_version_6 |
| G2-33 | 5 | `src-tauri/src/team/sync.rs:6873` an_unbind_tombstone_outlives_its_binding_and_replays_exactly; `src-tauri/src/team/sync.rs:6975` an_unbind_cut_off_at_any_write_leaves_the_binding_whole; `src-tauri/src/team/sync.rs:7081` a_tombstone_that_no_longer_recomputes_is_never_returned; `src-tauri/src/team/sync.rs:8098` an_unbind_after_an_accepted_transition_keeps_its_evidence; `src-tauri/src/team/db.rs:1866` a_version_4_file_keeps_its_proofs_and_lets_them_outlive_the_binding |
| G2-34 | 3 | `src-tauri/src/team/sync.rs:4466` a_release_whose_reply_was_lost_is_replayed_byte_for_byte; `src-tauri/src/team/sync.rs:5122` an_unsent_cancel_release_is_retried_and_then_given_up; `src-tauri/src/team/sync.rs:6802` an_unreadable_release_reply_is_reported_and_replayed |
| G2-35 | 6 | `src-tauri/src/team/records.rs:487` six_records_reopen_exactly_and_refuse_every_changed_column; `src-tauri/src/team/records.rs:559` a_second_self_grant_and_a_cross_instance_generation_are_refused; `src-tauri/src/team/records.rs:627` only_a_self_grant_files_a_generation_and_a_duplicate_row_refuses; `src-tauri/src/team/ledger.rs:1471` a_filed_grant_files_the_key_state_it_names; `src-tauri/src/team/sync.rs:4691` a_binding_and_its_rows_name_the_servers_account_and_key; `src-tauri/src/team/sync.rs:6369` a_kept_revocation_reloads_with_every_column_equal |
| G2-36 | 2 | `src-tauri/src/team/db.rs:2549` an_upload_session_refuses_a_second_identity_and_a_stranger_commit_or_key; `src-tauri/src/team/sync.rs:5618` an_interrupted_upload_resumes_at_the_offset_head_reports |
| G2-37 | 3 | `src-tauri/src/team/sync.rs:4358` every_crash_point_resumes_with_the_exact_stored_bytes; `src-tauri/src/team/sync.rs:4393` a_stored_column_that_drifts_from_its_bytes_is_never_sent; `src-tauri/src/team/sync.rs:5507` a_stored_publish_that_drifts_from_its_bytes_is_never_sent |
| G2-38 | 5 | `src-tauri/src/team/sync.rs:5642` a_receipt_or_readback_that_does_not_match_is_never_kept; `src-tauri/src/team/sync.rs:4274` a_published_profile_pushes_and_another_device_pulls_it; `src-tauri/src/team/db.rs:2549` an_upload_session_refuses_a_second_identity_and_a_stranger_commit_or_key; `server/tests/v2_profiles.rs:2294` an_upload_commits_once_and_the_next_checkout_starts_at_its_head; `server/tests/v2_profiles.rs:2646` every_upload_refusal_has_its_status_and_code |
| G2-39 | 12 | `src-tauri/src/team/sync.rs:7327` a_verified_transition_moves_only_the_bindings_it_covers; `src-tauri/src/team/sync.rs:7507` a_transition_that_does_not_verify_keeps_the_binding_quarantined; `src-tauri/src/team/sync.rs:7690` a_restore_epoch_that_goes_back_is_a_rollback; `src-tauri/src/team/sync.rs:7714` a_cut_off_acceptance_leaves_the_binding_quarantined_until_reopen; `src-tauri/src/team/sync.rs:7938` a_leaf_head_is_accepted_only_as_a_new_head_is; `src-tauri/src/team/sync.rs:8019` a_pinned_head_is_read_back_only_as_the_bindings_own; `src-tauri/src/team/sync.rs:8047` a_lapsed_or_former_custodian_signs_no_transition; `src-tauri/src/team/sync.rs:8098` an_unbind_after_an_accepted_transition_keeps_its_evidence; `src-tauri/src/team/sync.rs:8139` a_binding_changed_during_acceptance_is_not_moved; `src-tauri/src/team/sync.rs:8268` a_lease_from_before_the_restore_is_released_before_the_binding_moves; `src-tauri/src/team/sync.rs:8410` a_custodian_not_yet_appointed_signs_no_transition; `src-tauri/src/team/sync.rs:8526` a_failed_release_of_an_old_lease_is_retried_as_stored |
| G2-40 | 2 | `src-tauri/src/team/db.rs:1540` an_unknown_schema_fails_closed_and_is_left_as_it_was; `src-tauri/src/team/db.rs:1990` a_database_held_in_wal_mode_is_refused |
| G2-41 | 14 | `src-tauri/src/team/journal.rs:701` every_restore_phase_survives_close_and_reopen_in_order; `src-tauri/src/team/journal.rs:724` a_restore_phase_cannot_skip_repeat_or_leave_a_terminal_one; `src-tauri/src/team/journal.rs:745` a_restore_journal_retires_only_when_settled; `src-tauri/src/team/journal.rs:757` the_restore_resume_table_is_fixed_per_crash_point; `src-tauri/src/team/journal.rs:834` a_clone_journal_walks_its_chain_with_every_phase_surviving_reopen; `src-tauri/src/team/journal.rs:906` a_downgrade_phase_cannot_skip_and_a_rollback_is_always_open; `src-tauri/src/team/journal.rs:1157` the_resume_table_for_a_downgrade_journal_continues_every_open_phase; `src-tauri/src/team/journal.rs:1171` the_digests_survive_reopen_byte_for_byte; `src-tauri/src/team/downgrade.rs:1778` a_cut_off_at_every_step_resumes_to_the_same_finished_clone; `src-tauri/src/team/downgrade.rs:1828` a_process_killed_at_every_step_resumes_to_the_same_finished_clone; `src-tauri/src/team/downgrade.rs:1843` a_rollback_from_every_step_puts_the_original_back_and_frees_the_profile; `src-tauri/src/team/downgrade.rs:3029` a_readback_that_v0_1_28_would_not_agree_with_fails_the_flow; `src-tauri/src/team/downgrade.rs:1597` discovery_sees_every_place_v0_1_28_reads_and_nothing_in_the_archive; `src-tauri/src/team/sync.rs:7011` an_unbind_is_refused_while_a_lease_request_or_journal_is_open |
| G2-42 | 2 | `src-tauri/src/team/db.rs:2858` every_sync_integer_class_keeps_its_range_across_a_reopen; `src-tauri/src/team/records.rs:675` every_integer_class_keeps_its_range_across_a_reopen |
| G2-43 | 7 | `src-tauri/src/team/sync.rs:4603` every_publish_crash_point_resumes_with_the_exact_stored_bytes; `src-tauri/src/team/sync.rs:7864` a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key; `src-tauri/src/team/sync.rs:5544` a_create_upload_whose_reply_was_lost_is_replayed_byte_for_byte; `src-tauri/src/team/sync.rs:4358` every_crash_point_resumes_with_the_exact_stored_bytes; `src-tauri/src/team/sync.rs:6873` an_unbind_tombstone_outlives_its_binding_and_replays_exactly; `src-tauri/src/team/sync.rs:4466` a_release_whose_reply_was_lost_is_replayed_byte_for_byte; `src-tauri/src/team/sync.rs:7803` a_superseded_replay_ends_cleanly_and_the_next_push_starts_fresh |
| G2-44 | 7 | `server/tests/v2_upgrade_chain.rs:1307` the_plan_assertions_hold_on_a_reopened_fresh_file; `server/tests/v2_upgrade_chain.rs:1318` the_plan_assertions_hold_on_a_reopened_v0_1_28_file_and_its_backup_restores; `server/tests/v2_upgrade_chain.rs:1355` fixtures_1_to_4_hold_on_a_fresh_file; `server/tests/v2_upgrade_chain.rs:1364` fixtures_1_to_4_hold_on_a_v0_1_28_file_after_its_upgrade; `server/tests/v2_upgrade_chain.rs:1376` fixtures_1_to_4_hold_on_a_populated_0016_file_after_its_upgrade; `server/tests/v2_upgrade_chain.rs:366` m0017_root_generations_only_move_forward_on_upgraded_rows; `server/tests/v2_upgrade_chain.rs:1438` m0033_the_quarantine_gains_a_container_hash_and_stays_append_only |
| G2-45 | 6 | `server/tests/v2_upgrade_chain.rs:489` m0030_upgraded_integer_columns_refuse_values_that_are_no_integers; `server/tests/v2_integer_domain.rs:209` every_class_decodes_its_domain_ends_and_refuses_everything_else; `server/tests/v2_integer_domain.rs:370` every_class_column_stores_its_domain_ends_and_its_check_refuses_the_rest; `server/tests/v2_integer_domain.rs:492` every_integer_column_of_every_v2_table_has_an_upper_bound_check; `server/tests/v2_integer_domain.rs:526` every_integer_column_of_every_v2_table_refuses_a_value_that_is_no_integer; `server/tests/v2_integer_domain.rs:586` the_bound_scan_tells_bounded_from_unbounded_columns |
| G2-46 | 2 | `shared/src/recovery_bundle.rs:741` argon2id_matches_the_rfc_9106_vector; `shared/src/recovery_bundle.rs:767` the_kek_is_argon2id_over_the_labelled_salt |
| G2-47 | 17 | `src-tauri/src/team_config.rs:427` debug_never_prints_the_token_or_a_seed; `src-tauri/src/fleet_keys.rs:410` debug_never_prints_a_key; `src-tauri/src/fleet_client.rs:1503` a_session_debug_print_hides_its_tokens; `src-tauri/src/root_bootstrap.rs:1447` the_trk_is_stored_and_the_saved_state_holds_only_its_reference; `src-tauri/src/root_bootstrap.rs:1494` a_locked_or_unavailable_store_stops_every_trk_step_and_writes_nothing; `src-tauri/src/root_bootstrap.rs:1591` a_legacy_cleartext_trk_moves_into_the_store_and_the_file_is_rewritten_without_it; `src-tauri/src/root_bootstrap.rs:1326` the_legacy_trk_zeroizes_on_drop_and_is_read_but_never_written; `src-tauri/src/root_bootstrap.rs:1315` the_saved_state_never_prints_the_legacy_trk; `src-tauri/src/root_bootstrap.rs:1467` a_crash_between_storing_and_saving_the_key_resumes_with_the_same_key; `src-tauri/src/root_bootstrap.rs:1539` a_reference_to_another_credential_is_refused_and_that_credential_is_kept; `src-tauri/src/root_bootstrap.rs:1686` the_activation_is_saved_before_the_key_is_forgotten; `src-tauri/src/root_bootstrap.rs:1748` the_run_nonce_is_saved_before_the_key_is_stored; `src-tauri/src/root_bootstrap.rs:1723` a_new_run_never_reuses_a_key_an_abandoned_run_left; `src-tauri/src/root_bootstrap.rs:1620` a_store_that_refuses_the_legacy_trk_leaves_the_file_untouched_and_fails_closed; `src-tauri/src/root_bootstrap.rs:1858` a_legacy_trk_nobody_has_seen_is_dropped_and_a_fresh_one_is_made; `src-tauri/src/root_bootstrap.rs:1898` a_nonce_less_legacy_trk_stays_in_the_file_until_the_store_holds_it; `src-tauri/src/key_file.rs:319` a_forget_succeeds_only_once_the_key_is_confirmed_gone |
| G2-48 | 6 | `src-tauri/src/credential.rs:172` a_key_round_trips_and_is_forgotten; `src-tauri/src/credential.rs:185` references_are_separate_credentials; `src-tauri/src/credential.rs:193` a_failed_write_or_read_back_is_reported; `src-tauri/src/credential.rs:263` a_real_os_store_key_survives_into_a_fresh_process; `src-tauri/src/credential.rs:305` an_unavailable_store_fails_closed_in_a_fresh_process; `src-tauri/src/credential.rs:359` a_key_file_key_is_locked_then_served_in_a_fresh_process |
| G2-49 | 13 | `src-tauri/src/durable.rs:151` a_durable_write_replaces_the_file_and_leaves_no_temporary; `src-tauri/src/durable.rs:190` a_failed_replace_keeps_the_old_file_and_removes_the_temporary; `src-tauri/src/durable.rs:233` a_write_killed_at_any_step_leaves_the_old_or_the_new_file; `src-tauri/src/durable.rs:269` a_kill_during_back_to_back_writes_never_tears_or_loses_a_returned_write; `src-tauri/src/durable.rs:290` creating_a_file_that_exists_never_overwrites_it; `shared/src/volume.rs:126` only_a_local_ntfs_disk_is_accepted; `shared/src/volume.rs:160` a_local_ntfs_directory_is_accepted_and_a_missing_one_is_not; `shared/src/volume.rs:179` an_smb_share_is_refused; `server/src/db.rs:348` storage_that_cannot_be_resolved_is_refused; `server/src/db.rs:371` storage_on_an_smb_share_is_refused; `server/src/identity.rs:697` preflight_refuses_an_identity_directory_on_an_smb_share; `server/tests/restore_epoch_harness.rs:2519` an_identity_directory_the_preflight_refuses_never_falls_to_k1; `server/tests/restore_epoch_harness.rs:2833` an_empty_identity_directory_setting_refuses_to_start |
| G2-50 | 8 | `server/src/db.rs:293` the_database_runs_a_synced_rollback_journal_and_survives_an_unclosed_pool; `server/src/db.rs:526` a_killed_transaction_reopens_old_or_new_never_half; `server/src/db.rs:595` a_kill_between_commits_keeps_every_returned_commit; `server/src/db.rs:617` a_second_writer_waits_for_the_write_lock; `server/src/db.rs:371` storage_on_an_smb_share_is_refused; `src-tauri/src/crash_harness.rs:141` a_killed_transaction_reopens_old_or_new_never_half; `src-tauri/src/team/db.rs:1990` a_database_held_in_wal_mode_is_refused; `shared/src/volume.rs:179` an_smb_share_is_refused |
| G2-51 | 7 | `shared/src/snapshot.rs:1265` the_windows_path_corpus_is_refused_in_every_position; `shared/src/snapshot.rs:1287` every_name_windows_rewrites_is_refused; `shared/src/snapshot.rs:1308` ntfs_case_fold_collisions_are_refused_and_distinct_names_kept; `shared/src/snapshot.rs:1359` long_paths_unpack_and_an_overlong_one_is_refused; `shared/src/snapshot.rs:1394` a_junction_is_neither_packed_through_nor_followed_on_replace; `src-tauri/src/team/downgrade.rs:1597` discovery_sees_every_place_v0_1_28_reads_and_nothing_in_the_archive; `src-tauri/src/team/downgrade.rs:1979` a_trace_of_the_old_id_after_the_move_fails_the_discovery_scan |
| G2-52 | 1 | `server/tests/restore_epoch_harness.rs:1260` g2_52_every_crash_point_maps_to_one_row_and_resumes_to_the_restored_state |
| G2-53 | 3 | `server/tests/identity_authority.rs:194` a_symlinked_record_is_refused; `server/tests/identity_authority.rs:456` show_detects_a_tampered_record_and_a_record_the_mirror_does_not_attest; `server/tests/restore_epoch_harness.rs:2596` an_identity_directory_that_is_not_there_is_missing_and_stops_the_server |
| G2-54 | 1 | `server/tests/restore_epoch_harness.rs:1635` l2259_g2_54_a_record_equal_to_its_mirror_without_a_manifest_opens_normally |
| G2-55 | 16 | `server/tests/restore_epoch_harness.rs:1674` l2260_g2_55_a_durable_preparation_at_e_keeps_writes_off_until_commit_or_abort; `server/tests/restore_epoch_harness.rs:1471` g2_55_a_failed_read_only_audit_write_is_counted_in_restore_status; `server/tests/restore_epoch_harness.rs:1543` g2_55_the_k2_incident_output_prints_the_audit_failure_count; `server/tests/restore_epoch_harness.rs:1587` g2_55_a_directory_at_the_count_path_stops_a_read_only_start_by_name; `server/tests/restore_epoch_harness.rs:2636` g2_55_restore_commit_prints_the_final_audit_failure_count_and_clears_it; `server/tests/restore_epoch_harness.rs:2677` g2_55_a_read_only_start_logs_the_failed_audit_writes_counted_so_far; `server/tests/restore_epoch_harness.rs:2728` g2_55_a_read_only_start_on_a_network_data_directory_writes_no_count; `server/tests/restore_epoch_harness.rs:2758` g2_55_a_count_under_a_changed_episode_key_is_kept_and_cleared_by_name; `server/tests/restore_epoch_harness.rs:2913` g2_55_a_count_file_with_a_bad_line_is_set_aside_and_its_valid_lines_kept; `server/src/audit.rs:532` a_failed_read_only_audit_write_is_logged_and_counted; `server/src/audit.rs:573` the_count_continues_across_read_only_restarts_of_one_episode; `server/src/audit.rs:597` a_changed_episode_key_keeps_the_old_count_until_it_is_cleared_by_name; `server/src/audit.rs:641` one_bad_line_in_the_count_file_loses_only_itself; `server/src/audit.rs:709` a_crash_while_setting_a_file_aside_never_loses_the_valid_lines; `server/src/audit.rs:762` the_count_is_written_atomically_and_an_unreadable_one_is_reported; `server/src/audit.rs:792` a_directory_or_link_at_the_count_path_is_refused_by_name |
| G2-56 | 1 | `server/tests/restore_epoch_harness.rs:1756` l2261_g2_56_an_authority_ahead_of_the_live_mirror_resumes_only_the_install |
| G2-57 | 1 | `server/tests/restore_epoch_harness.rs:1823` l2262_g2_57_an_installed_db_behind_the_record_is_verified_then_rebuilt |
| G2-58 | 2 | `server/tests/restore_epoch_harness.rs:1918` l2263_g2_58_an_authority_ahead_without_exact_evidence_fails_closed; `server/tests/restore_epoch_harness.rs:1962` l2263_g2_58_only_a_live_custodian_transition_over_the_computed_leaves_prepares |
| G2-59 | 1 | `server/tests/restore_epoch_harness.rs:1543` g2_55_the_k2_incident_output_prints_the_audit_failure_count |
| G2-60 | 1 | `server/tests/restore_epoch_harness.rs:2031` l2265_g2_60_a_reconciled_epoch_retires_its_bundle_and_the_next_start_is_normal |
| G2-61 | 26 | `shared/src/backup_file.rs:448` a_snapshot_sealed_for_another_profile_is_refused; `shared/src/backup_file.rs:402` another_fleet_key_cannot_open_it; `shared/tests/backup_file_roundtrip.rs:133` the_ciphertext_does_not_contain_the_plaintext; `shared/tests/backup_file_roundtrip.rs:219` a_tampered_backup_body_is_refused; `shared/tests/backup_file_roundtrip.rs:185` a_truncated_backup_is_refused_and_leaves_the_destination_untouched; `shared/src/backup.rs:826` every_single_byte_mutation_is_detected; `shared/src/backup.rs:844` truncation_at_any_length_is_detected; `shared/src/backup.rs:869` cross_envelope_frame_splice_is_rejected; `src-tauri/src/sync_cmd.rs:662` pull_refuses_another_profiles_snapshot; `src-tauri/src/sync_cmd.rs:598` push_seals_under_the_passphrase_even_with_a_cached_fleet_key; `shared/src/grants.rs:689` grant_cannot_be_replayed_into_another_tenant_or_epoch; `shared/src/fleet_grants.rs:276` tampering_with_the_stored_info_fails_the_open; `server/tests/identity_authority.rs:406` an_interrupted_init_is_reported_and_never_repaired; `server/src/integrity.rs:559` wrong_domain_hpke_ids_are_quarantined_once; `src-tauri/src/lib.rs:2990` a_server_delivered_fleet_key_is_counted_but_never_cached; `src-tauri/src/lib.rs:3580` a_fleet_scoped_device_revoke_counts_for_a_member_of_that_fleet; `src-tauri/src/team/sync.rs:5779` a_compromised_revocation_blocks_commits_under_an_exposed_generation; `src-tauri/src/team/sync.rs:5993` a_compromised_custodian_blocks_every_fleet_through_the_root; `src-tauri/src/team/sync.rs:6303` an_exposure_survives_a_recollection_that_omits_its_grant; `src-tauri/src/team/sync.rs:6131` an_open_upload_is_aborted_once_a_compromise_is_counted; `src-tauri/src/team/sync.rs:6181` a_compromise_counted_mid_transfer_aborts_the_upload; `src-tauri/src/team/sync.rs:6053` a_known_custodian_with_no_root_holding_blocks; `src-tauri/src/team/sync.rs:6075` a_compromise_counted_after_a_lost_revocation_of_the_same_key_blocks; `src-tauri/src/team/sync.rs:6217` a_stored_finalize_is_not_sent_once_a_compromise_is_counted; `src-tauri/src/team/sync.rs:6255` a_blocked_push_leaves_the_profile_available_and_dirty_with_the_local_code; `src-tauri/src/team/ledger.rs:1343` a_version_6_file_with_unreadable_kept_pages_still_opens |
| G2-62 | 0 |  |
| G2-63 | 8 | `shared/tests/registry_pins.rs:144` every_signing_domain_is_distinct_and_versioned; `shared/tests/registry_pins.rs:161` every_hash_label_is_distinct_and_nul_terminated; `shared/tests/registry_pins.rs:201` the_numeric_registry_holds_the_reviewed_values; `shared/src/keys.rs:578` g2_golden_vector_profile_label; `shared/src/keys.rs:427` a_profile_label_opens_only_where_it_was_sealed; `shared/src/keys.rs:470` a_profile_label_has_a_length_bound_both_ways; `shared/src/keys.rs:495` a_profile_label_is_padded_to_a_bucket; `shared/src/keys.rs:524` a_profile_label_that_is_not_canonical_is_refused |
| G2-64 | 0 |  |

## Selected normalized SHA-256 values

CRLF normalized to LF, exactly as the packet checker. All 120 manifest artifacts passed; these values also freeze the README and manifest themselves.

| Artifact | SHA-256 |
|---|---|
| `.omx/plans/shardbrowser-v0.2.x-team-fleet-encrypted-backup.md` | `8b9ef41a21e93d19b4e4fe4641aff06d96a123256cb00c0e8580f0fa70a5523e` |
| `docs/adr/0002-g2-contract-decisions.md` | `11e7f0d2824c64e6589d9ec89db52372d208721e5a46858f18c5816d99939940` |
| `docs/g2-evidence/README.md` | `bdf712b53a3e8e61c876e712e211f18a953764da8257f4dcfcc4bef2d0ec85c6` |
| `docs/g2-evidence/SHA256SUMS` | `51ce75c6ba6ee3698fc4c36f2f96694f256e9a156081f05ad5c16dab5849e976` |
| `scripts/g2-evidence.py` | `f0583b8214b7dfd4e45f3f5c727b04b4ff9766c8bd889c56c7e2de0994fbed2e` |
| `src-tauri/src/team/ledger.rs` | `c29aa26014a73f4d74daac81017ed7c9cc07e5f85eac9c49b3a4ca64ed2cab32` |
| `src-tauri/src/team/sync.rs` | `2f22c922b298e3443928e54963e77b9883c60c30cfdd9c744b01497acaf88e1b` |
| `shared/src/trust_chain.rs` | `2070eca62a8d86471842f8ea75d95990102c1a8ffb7814ec4e284bf9ccd22b72` |
| `shared/tests/registry_pins.rs` | `8a1ba7f685328c58c3bca57f0cd5d03fa91313550ff05c2fbc335e39e2b1a326` |

### Serial reproduction G2-38

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_profiles -- an_upload_commits_once_and_the_next_checkout_starts_at_its_head every_upload_refusal_has_its_status_and_code --nocapture`

Exit 0; 10.4 s; unmatched filters: [].

```text
2026-11-02T01:37:34.585317Z ERROR tower_http::trace::on_failure: response failed classification=Status code: 500 Internal Server Error latency=43 ms
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out; finished in 9.97s
```

### Serial reproduction G2-39

`cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_verified_transition_moves_only_the_bindings_it_covers a_transition_that_does_not_verify_keeps_the_binding_quarantined a_restore_epoch_that_goes_back_is_a_rollback a_cut_off_acceptance_leaves_the_binding_quarantined_until_reopen a_leaf_head_is_accepted_only_as_a_new_head_is a_pinned_head_is_read_back_only_as_the_bindings_own a_lapsed_or_former_custodian_signs_no_transition an_unbind_after_an_accepted_transition_keeps_its_evidence a_binding_changed_during_acceptance_is_not_moved a_lease_from_before_the_restore_is_released_before_the_binding_moves a_custodian_not_yet_appointed_signs_no_transition a_failed_release_of_an_old_lease_is_retried_as_stored --nocapture --skip credential::tests::a_real_os_store_key_survives_into_a_fresh_process`

Exit 0; 40.8 s; unmatched filters: [].

```text
test team::sync::tests::a_failed_release_of_an_old_lease_is_retried_as_stored ... ok
test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 502 filtered out; finished in 40.22s
```

### Serial reproduction G2-40

`cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- an_unknown_schema_fails_closed_and_is_left_as_it_was a_database_held_in_wal_mode_is_refused --nocapture --skip credential::tests::a_real_os_store_key_survives_into_a_fresh_process`

Exit 0; 1.0 s; unmatched filters: [].

```text
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 512 filtered out; finished in 0.46s
```

### Serial reproduction G2-41

`cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- every_restore_phase_survives_close_and_reopen_in_order a_restore_phase_cannot_skip_repeat_or_leave_a_terminal_one a_restore_journal_retires_only_when_settled the_restore_resume_table_is_fixed_per_crash_point a_clone_journal_walks_its_chain_with_every_phase_surviving_reopen a_downgrade_phase_cannot_skip_and_a_rollback_is_always_open the_resume_table_for_a_downgrade_journal_continues_every_open_phase the_digests_survive_reopen_byte_for_byte a_cut_off_at_every_step_resumes_to_the_same_finished_clone a_process_killed_at_every_step_resumes_to_the_same_finished_clone a_rollback_from_every_step_puts_the_original_back_and_frees_the_profile a_readback_that_v0_1_28_would_not_agree_with_fails_the_flow discovery_sees_every_place_v0_1_28_reads_and_nothing_in_the_archive an_unbind_is_refused_while_a_lease_request_or_journal_is_open --nocapture --skip credential::tests::a_real_os_store_key_survives_into_a_fresh_process`

Exit 0; 8.9 s; unmatched filters: [].

```text
test team::journal::tests::a_restore_phase_cannot_skip_repeat_or_leave_a_terminal_one ... ok
test team::journal::tests::a_downgrade_phase_cannot_skip_and_a_rollback_is_always_open ... ok
test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 500 filtered out; finished in 8.42s
```

### Serial reproduction G2-42

`cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- every_sync_integer_class_keeps_its_range_across_a_reopen every_integer_class_keeps_its_range_across_a_reopen --nocapture --skip credential::tests::a_real_os_store_key_survives_into_a_fresh_process`

Exit 0; 0.8 s; unmatched filters: [].

```text
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 512 filtered out; finished in 0.34s
```

### Serial reproduction G2-43

`cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- every_publish_crash_point_resumes_with_the_exact_stored_bytes a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key a_create_upload_whose_reply_was_lost_is_replayed_byte_for_byte every_crash_point_resumes_with_the_exact_stored_bytes an_unbind_tombstone_outlives_its_binding_and_replays_exactly a_release_whose_reply_was_lost_is_replayed_byte_for_byte a_superseded_replay_ends_cleanly_and_the_next_push_starts_fresh --nocapture --skip credential::tests::a_real_os_store_key_survives_into_a_fresh_process`

Exit 0; 11.0 s; unmatched filters: [].

```text
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 507 filtered out; finished in 10.47s
```

### Serial reproduction G2-44

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_upgrade_chain -- the_plan_assertions_hold_on_a_reopened_fresh_file the_plan_assertions_hold_on_a_reopened_v0_1_28_file_and_its_backup_restores fixtures_1_to_4_hold_on_a_fresh_file fixtures_1_to_4_hold_on_a_v0_1_28_file_after_its_upgrade fixtures_1_to_4_hold_on_a_populated_0016_file_after_its_upgrade m0017_root_generations_only_move_forward_on_upgraded_rows m0033_the_quarantine_gains_a_container_hash_and_stays_append_only --nocapture`

Exit 0; 2.8 s; unmatched filters: [].

```text
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 16 filtered out; finished in 2.40s
```

### Serial reproduction G2-45

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_upgrade_chain -- m0030_upgraded_integer_columns_refuse_values_that_are_no_integers --nocapture`

Exit 0; 0.6 s; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 22 filtered out; finished in 0.24s
```

### Serial reproduction G2-45

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test v2_integer_domain -- every_class_decodes_its_domain_ends_and_refuses_everything_else every_class_column_stores_its_domain_ends_and_its_check_refuses_the_rest every_integer_column_of_every_v2_table_has_an_upper_bound_check every_integer_column_of_every_v2_table_refuses_a_value_that_is_no_integer the_bound_scan_tells_bounded_from_unbounded_columns --nocapture`

Exit 0; 1.0 s; unmatched filters: [].

```text
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.70s
```

### Serial reproduction G2-46

`cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- argon2id_matches_the_rfc_9106_vector the_kek_is_argon2id_over_the_labelled_salt --nocapture`

Exit 0; 4.7 s; unmatched filters: [].

```text
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 298 filtered out; finished in 4.51s
```

### Serial reproduction G2-47

`cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- debug_never_prints_the_token_or_a_seed debug_never_prints_a_key a_session_debug_print_hides_its_tokens the_trk_is_stored_and_the_saved_state_holds_only_its_reference a_locked_or_unavailable_store_stops_every_trk_step_and_writes_nothing a_legacy_cleartext_trk_moves_into_the_store_and_the_file_is_rewritten_without_it the_legacy_trk_zeroizes_on_drop_and_is_read_but_never_written the_saved_state_never_prints_the_legacy_trk a_crash_between_storing_and_saving_the_key_resumes_with_the_same_key a_reference_to_another_credential_is_refused_and_that_credential_is_kept the_activation_is_saved_before_the_key_is_forgotten the_run_nonce_is_saved_before_the_key_is_stored a_new_run_never_reuses_a_key_an_abandoned_run_left a_store_that_refuses_the_legacy_trk_leaves_the_file_untouched_and_fails_closed a_legacy_trk_nobody_has_seen_is_dropped_and_a_fresh_one_is_made a_nonce_less_legacy_trk_stays_in_the_file_until_the_store_holds_it a_forget_succeeds_only_once_the_key_is_confirmed_gone --nocapture --skip credential::tests::a_real_os_store_key_survives_into_a_fresh_process`

Exit 0; 39.0 s; unmatched filters: [].

```text
test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured; 497 filtered out; finished in 38.46s
```

### Serial reproduction G2-48

`cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_key_round_trips_and_is_forgotten references_are_separate_credentials a_failed_write_or_read_back_is_reported a_real_os_store_key_survives_into_a_fresh_process an_unavailable_store_fails_closed_in_a_fresh_process a_key_file_key_is_locked_then_served_in_a_fresh_process --nocapture --skip credential::tests::a_real_os_store_key_survives_into_a_fresh_process`

Exit 0; 12.2 s; unmatched filters: [].

```text
test credential::tests::a_failed_write_or_read_back_is_reported ... ok
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 509 filtered out; finished in 11.73s
```

### Serial reproduction G2-49

`cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_durable_write_replaces_the_file_and_leaves_no_temporary a_failed_replace_keeps_the_old_file_and_removes_the_temporary a_write_killed_at_any_step_leaves_the_old_or_the_new_file a_kill_during_back_to_back_writes_never_tears_or_loses_a_returned_write creating_a_file_that_exists_never_overwrites_it --nocapture --skip credential::tests::a_real_os_store_key_survives_into_a_fresh_process`

Exit 0; 0.6 s; unmatched filters: [].

```text
test durable::tests::a_failed_replace_keeps_the_old_file_and_removes_the_temporary ... ok
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 509 filtered out; finished in 0.12s
```

### Serial reproduction G2-49

`cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- only_a_local_ntfs_disk_is_accepted a_local_ntfs_directory_is_accepted_and_a_missing_one_is_not an_smb_share_is_refused --nocapture`

Exit 0; 0.1 s; unmatched filters: [].

```text
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 297 filtered out; finished in 0.01s
```

### Serial reproduction G2-49

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --bin shardx-team-server -- storage_that_cannot_be_resolved_is_refused storage_on_an_smb_share_is_refused preflight_refuses_an_identity_directory_on_an_smb_share --nocapture`

Exit 0; 0.3 s; unmatched filters: [].

```text
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 105 filtered out; finished in 0.01s
```

### Serial reproduction G2-49

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- an_identity_directory_the_preflight_refuses_never_falls_to_k1 an_empty_identity_directory_setting_refuses_to_start --nocapture`

Exit 0; 2.0 s; unmatched filters: [].

```text
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 22 filtered out; finished in 1.73s
```

### Serial reproduction G2-50

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --bin shardx-team-server -- the_database_runs_a_synced_rollback_journal_and_survives_an_unclosed_pool a_killed_transaction_reopens_old_or_new_never_half a_kill_between_commits_keeps_every_returned_commit a_second_writer_waits_for_the_write_lock storage_on_an_smb_share_is_refused --nocapture`

Exit 0; 0.8 s; unmatched filters: [].

```text
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 103 filtered out; finished in 0.50s
```

### Serial reproduction G2-50

`cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_killed_transaction_reopens_old_or_new_never_half a_database_held_in_wal_mode_is_refused --nocapture --skip credential::tests::a_real_os_store_key_survives_into_a_fresh_process`

Exit 0; 0.9 s; unmatched filters: [].

```text
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 512 filtered out; finished in 0.44s
```

### Serial reproduction G2-50

`cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- an_smb_share_is_refused --nocapture`

Exit 0; 0.1 s; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 299 filtered out; finished in 0.00s
```

### Serial reproduction G2-51

`cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- the_windows_path_corpus_is_refused_in_every_position every_name_windows_rewrites_is_refused ntfs_case_fold_collisions_are_refused_and_distinct_names_kept long_paths_unpack_and_an_overlong_one_is_refused a_junction_is_neither_packed_through_nor_followed_on_replace --nocapture`

Exit 0; 0.2 s; unmatched filters: [].

```text
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 295 filtered out; finished in 0.11s
```

### Serial reproduction G2-51

`cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- discovery_sees_every_place_v0_1_28_reads_and_nothing_in_the_archive a_trace_of_the_old_id_after_the_move_fails_the_discovery_scan --nocapture --skip credential::tests::a_real_os_store_key_survives_into_a_fresh_process`

Exit 0; 0.9 s; unmatched filters: [].

```text
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 512 filtered out; finished in 0.35s
```

### Serial reproduction G2-52

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- g2_52_every_crash_point_maps_to_one_row_and_resumes_to_the_restored_state --nocapture`

Exit 0; 19.9 s; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 23 filtered out; finished in 19.60s
```

### Serial reproduction G2-53

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test identity_authority -- a_symlinked_record_is_refused show_detects_a_tampered_record_and_a_record_the_mirror_does_not_attest --nocapture`

Exit 0; 1.0 s; unmatched filters: [].

```text
skipping: cannot create a symlink here: A required privilege is not held by the client. (os error 1314)
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 20 filtered out; finished in 0.74s
```

### Serial reproduction G2-53

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- an_identity_directory_that_is_not_there_is_missing_and_stops_the_server --nocapture`

Exit 0; 0.8 s; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 23 filtered out; finished in 0.54s
```

### Serial reproduction G2-54

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- l2259_g2_54_a_record_equal_to_its_mirror_without_a_manifest_opens_normally --nocapture`

Exit 0; 2.8 s; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 23 filtered out; finished in 2.49s
```

### Serial reproduction G2-55

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- l2260_g2_55_a_durable_preparation_at_e_keeps_writes_off_until_commit_or_abort g2_55_a_failed_read_only_audit_write_is_counted_in_restore_status g2_55_the_k2_incident_output_prints_the_audit_failure_count g2_55_a_directory_at_the_count_path_stops_a_read_only_start_by_name g2_55_restore_commit_prints_the_final_audit_failure_count_and_clears_it g2_55_a_read_only_start_logs_the_failed_audit_writes_counted_so_far g2_55_a_read_only_start_on_a_network_data_directory_writes_no_count g2_55_a_count_under_a_changed_episode_key_is_kept_and_cleared_by_name g2_55_a_count_file_with_a_bad_line_is_set_aside_and_its_valid_lines_kept --nocapture`

Exit 0; 7.3 s; unmatched filters: [].

```text
test g2_55_a_read_only_start_logs_the_failed_audit_writes_counted_so_far ... ok
test g2_55_a_failed_read_only_audit_write_is_counted_in_restore_status ... ok
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 15 filtered out; finished in 6.84s
```

### Serial reproduction G2-55

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --bin shardx-team-server -- a_failed_read_only_audit_write_is_logged_and_counted the_count_continues_across_read_only_restarts_of_one_episode a_changed_episode_key_keeps_the_old_count_until_it_is_cleared_by_name one_bad_line_in_the_count_file_loses_only_itself a_crash_while_setting_a_file_aside_never_loses_the_valid_lines the_count_is_written_atomically_and_an_unreadable_one_is_reported a_directory_or_link_at_the_count_path_is_refused_by_name --nocapture`

Exit 0; 0.4 s; unmatched filters: [].

```text
test audit::tests::a_failed_read_only_audit_write_is_logged_and_counted ... ok
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 101 filtered out; finished in 0.10s
```

### Serial reproduction G2-56

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- l2261_g2_56_an_authority_ahead_of_the_live_mirror_resumes_only_the_install --nocapture`

Exit 0; 4.3 s; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 23 filtered out; finished in 4.04s
```

### Serial reproduction G2-57

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- l2262_g2_57_an_installed_db_behind_the_record_is_verified_then_rebuilt --nocapture`

Exit 0; 8.7 s; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 23 filtered out; finished in 8.35s
```

### Serial reproduction G2-58

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- l2263_g2_58_an_authority_ahead_without_exact_evidence_fails_closed l2263_g2_58_only_a_live_custodian_transition_over_the_computed_leaves_prepares --nocapture`

Exit 0; 8.7 s; unmatched filters: [].

```text
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 22 filtered out; finished in 8.33s
```

### Serial reproduction G2-59

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- g2_55_the_k2_incident_output_prints_the_audit_failure_count --nocapture`

Exit 0; 3.5 s; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 23 filtered out; finished in 3.17s
```

## Blocking finding F1 — an untrusted approval suppresses a genuine fleet-scoped compromised revocation

**Severity: high; G2-61 does not hold, and B4 is only partially closed.** `shared/src/trust_chain.rs:520` derives `revocation_scope` from every signature-valid approval indexed for the subject. At line 526 it reads the scope without checking `approval_issuer_ok` (`:493`). In contrast, ordinary approval use calls that authority check through `approval_holds_at` and `approvals_of` (`:463`, `:480`). `Evidence::collect` establishes syntax, signature and binding, not the signer's authorization to approve the device (`:194` onwards).

The launcher consumes this scope in `src-tauri/src/team/ledger.rs:1063`. An approval signed by an unrelated, non-custodian key therefore changes the scope needed to count an otherwise valid revocation. `record_in` at `:803` skips the revocation when `counted` returns `None`. Q-18's block reads only counted revocations at `:672`; it has no independent repair for this case.

Failure scenario:

1. An anchored tenant has an honestly approved member of fleet F. An active custodian has `device.revoke` over F and signs a valid `compromised` revocation for that member. The server permits that scope (`server/src/routes/v2_device_revoke.rs:344`); all authentic approvals of the member name F.
2. A hostile evidence responder supplies the genuine revocation and adds a tenant-scoped approval for the member signed by a fresh outsider key. It includes that public key in the unsigned evidence page. The outsider is not a custodian and has no `device.approve` authority.
3. The ordinary approval check correctly rejects the outsider's tenant approval. Nevertheless, `revocation_scope` includes it and selects Tenant. The custodian's genuine fleet capability then fails the new tenant-scope check, so the genuine signed compromised revocation is not counted. With no earlier counted compromise, the Q-18 cause is never filed and does not initiate the block.

The independent executable probe above uses the unchanged production shared crate and the exact `counted` function extracted from the launcher. It reports `outsider_custodian=false` and `victim_has_valid_tenant_approval=false` in both cases. Adding only the outsider approval changes `valid_compromised_revocation_counted` from `true` to `false`. The probe was repeated twice with byte-identical output. It does not touch a launcher data directory or a credential store. This is a direct predicate reproduction; a complete launcher/network push was not added because repository edits are prohibited. The propagation into recording and the commit check was inspected in source.

This is separate from the ADR's accepted withheld-revocation limit: the authentic signed revocation and its legitimate authority are present here. A record that does not establish approval authority alters the security decision. The existing B4 regression (`src-tauri/src/lib.rs:3580`) checks a fleet-only member, the wrong fleet, a **legitimate** extra tenant approval, and tenant capability. It never inserts an approval signed by a non-custodian. The full suite and every cited positive B4 test can therefore pass while this scenario remains.

Required closure: derive historical revocation scope only from approvals whose issuing authority is established, retaining the server's historical-scope semantics. Add regressions for an outsider-signed tenant approval and another-fleet approval alongside the genuine revocation. Verify that the compromised revocation is still recorded and that a push under the exposed generation is blocked. No implementation changes were made in this verification.

## Prior findings independently reassessed

| Finding | Decision | Code, scenario and evidence |
|---|---|---|
| B1 | Original scenario closed | `team/ledger.rs:447` records issuer and recipient holdings for device/root grants, RecoveryGrant issuer root+fleet holdings, and RotationGrant issuer fleet holdings. `commit_blocked:634` checks every root generation at or above the bound root, including PREPARING, and conservatively handles missing activation evidence and known custodians without holdings. `team/sync.rs:5993` tries root-only exposure, fleet-before-root rotation, root-then-fleet release, later PREPARING exposure, and missing/mismatched activation evidence. All are exercised by the cited tests. |
| B2 | Closed | Append-only `trust_key_holdings` and non-increasing activation bounds in schema 7 (`team/db.rs:1227`), recording at `team/ledger.rs:566`, survive replacement of the fetched evidence pages. The recollection test removes the revoked member's grant, recollects the same generation and still sees a block. Version-6 backfill, including unreadable pages, is covered. |
| B3 | Closed for the reported paths | `team/sync.rs:1454` checks before a new checkout; `:1491` checks OPEN uploads independent of pending FINALIZE; `:2516` checks between chunks and before finishing transfer. `abort_compromised:2455` sends upload DELETE, records the local code and releases the lease. The OPEN-upload and mid-transfer tests assert no further PATCH/finalize/commit, local and fake-server ABORTED, failed COMMIT, released lease, and no next checkout. Lost abort responses are not an atomic distributed transaction; this review makes no stronger claim. |
| B4 | Original case fixed; closure incomplete | A fleet-scoped revocation now counts for a fleet-only member, and the regression executes. The new F1 scenario still suppresses this legitimate revocation by adding an invalid approval, so the broader client trust property remains open. |
| B5 | Closed | `server/src/routes/v2_device_revoke.rs:689` applies each root/fleet activation in the same transaction as revocation and response (`:771`). `v2_auth.rs:5949` first leaves recovery acknowledgement incomplete: `409 FLEET_GRANTS_INCOMPLETE`, no revocation, generation still PREPARING and session still live. After acknowledgement the same type of request activates and revokes atomically with byte-identical replay. Root activation and sorted/unique bounded activation parsing are independently tested. |
| B6 | Closed by sound, explicit contract amendment | ADR 0002 Q-43 (`:122`) accepts SQLite affinity conversion and documents decimal/exponent rounding above 2^53. Local callers bind checked i64 values (`team/records.rs:81`, `team/sync.rs` wire conversion); the wire codec rejects noninteger and over-i64 encodings. Server migration 0030 checks the post-affinity storage type, so it has the same semantics. No claim is made that direct hostile SQL decimal TEXT is lossless. The two reopen tests and server integer tests pass. A supplementary in-memory SQLite 3.49.1 probe independently confirmed integer TEXT, integer REAL, fraction/out-of-range refusal, and `'9007199254740993.0' -> 9007199254740992` for both STRICT and server-style INTEGER+trigger. The live-user-data rewrite rejected by Q-43 is unnecessary for typed wire writes. |
| B7 | Closed | `v2_auth.rs:10577` helper sends a real mutation, snapshots every table, restarts on the same database, compares exact status/body, checks altered-request mismatch and verifies every table remains identical. The custody matrix at `:10642` exhaustively matches OperationKind. `v2_profiles.rs:3971` covers the profile kinds; LocalUnbind is exercised by the launcher. This is durable response-loss evidence, not an in-memory replay assertion. |
| N1 | Closed | Schema 8 permits only the container column to change; application code at `team/ledger.rs:816` permits replacement only by a counted Compromised record when the retained one is not verifiably Compromised. `team/sync.rs:6076` demonstrates Lost -> Compromised -> Retired and preserves the earliest count. The source and repeated execution support this exact transition; see the SQL-trigger wording discrepancy below. |
| N2 | Closed | The OPEN branch at `team/sync.rs:1491` now checks compromise before it consults the pending FINALIZE. The test stores a finalize dropped before server processing, counts a compromise, then asserts only the original dropped finalize exists, no COMMIT, both uploads ABORTED, and lease gone. |
| SMB gap | Closed on this machine and exact-commit CI | The supplied UNC directory is reachable. Shared, server and launcher runs carry the requested SHARDX_TEST_SMB_DIR. Explicitly configured inaccessible shares panic. Local SMB refusal branches execute; no SMB skip is observed. G2-55 also uses its own fixture's loopback administrative path, so its actual branch was checked separately. CI 41343000374 provides a second Windows run with a temporary share. |

## In-depth row review

The following 21 samples include every mandatory sample. Plan references were read from the actual frozen plan, not inferred from old line numbers in test names. Tests were inspected for substantive assertions and their production code paths were read. Execution counts and exact commands are in the serial reproduction entries.

| Row | Contract readback and independently assessed evidence |
|---|---|
| G2-01 | Plan L443-L508; ADR D-2/Q-22. The server matrix mutates mapped approval columns, compares exact signed containers, and reruns startup quarantine. Signature verification and row reconstruction precede use. Golden hashes are fixed literals, not values generated by the code under test. |
| G2-07 | Plan L509-L589; Q-1/Q-36. `snapshot_v2.rs:1167` refuses unknown/missing fields, duplicate keys, trailing CBOR, wrong domain/version, over-i64 fences, invalid base/target progression and invalid previous-head presence. The real parser, signer and envelope binding paths are called. |
| G2-12 | Plan L590-L759; D-1/Q-36. `restore_epoch.rs:1194` verifies every leaf for n=1..7 and tampers sibling, direction, step count/order, leaf index, substituted leaf and head. Golden n=1/2/3 vectors plus explicit tenant/profile/instance/epoch/root/count bindings cover the plan's odd-node/unary rules. |
| G2-14 | Plan L910-L1054; Q-5/Q-13. Closed mutation kinds, request/response hashes and exact serialization are tested. DEVICE_REVOKE carries root/fleet activations rather than accepting only an empty list; B5's positive and rollback cases exercise the real route transaction. |
| G2-27 | Plan L1352-L1371; ADR 0003. `envelope_v2.rs:1308,1461` asserts precise failures for malformed preamble and framing. Read-head hashes the whole object before parsing/decrypting (`:701`); length bounds precede allocation, scope/intent/slot/hash equality is checked, and DATA/FINAL rules enforce nonempty final content. Provider maximum and official XChaCha vector are separate tests. |
| G2-28 | Plan L1358; D-8/D-5. RFC 9180 KATs, wrong recipient/context rejection and exact AAD are present. `grants.rs:619` now pins HPKE info SHA-256 `620962718813f10b5300922863f97c7b663acb2e559446fd53ab07f23deceb8a`; the earlier roundtrip-only weakness is gone. |
| G2-30 | Plan L2338/L2040/L2058; Q-13/Q-38. `v2_auth.rs:9609` enumerates the revocation columns, mutates them on read and at startup, and checks 422/423 behavior, quarantine hashes, wrong-instance rows and restored-container behavior. The other six record families are exercised by G2-01..06 and G2-35; the row is not a standalone seven-family command. `load_revocation` re-verifies signed bytes and mapped columns. |
| G2-31 | Plan L1424/L2048/L2338; Q-34/Q-42. Real restart matrices enumerate every operation kind; exact stored bytes and all rows remain unchanged. Separate approval, commit, restore-superseded and local-unbind cases fill the non-OperationKind paths. B7 is closed. |
| G2-35 | Plan L2034/L2040/L2058; Q-13/Q-26/Q-42. `team/records.rs:487` reopens six records and mutates each mapped column with CHECK/FK disabled, asserting the intended unreadable error and restoring the control. It asserts 326 refusals (5*57+41), not an empty loop. Separate UNIQUE/FK tests reject second self-grants and cross-instance generations. Revocation is kept separately and gets its own equality test. `load` derives comparisons from actual canonical payload/container bytes. |
| G2-41 | Plan L2046; Q-35/Q-40. Journal transitions persist through close/reopen, refuse skipping/terminal transitions and pin next/rollback classifications. Downgrade tests both inject errors and kill child processes at POINTS, then verify original/archive/clone state, metadata/data readback, repeated resume and rollback. Restore journal has no complete production restore writer; the packet states this limitation, and probe 9 asks for journal persistence/state behavior. |
| G2-42 | Plan L2047 narrowed by Q-43. Local tests accept both domain ends and reopen at max; reject fractions, invalid text/blob and out-of-range numbers before mutation. Wire conversions are checked. SQLite affinity semantics agree with the server; see B6 and supplementary probe. Text-max intermediate readback is weaker than the test comment claims (below), but actual semantics were independently reproduced. |
| G2-43 | Plan L2048; D-7/Q-42. Publish, checkout, upload, finalize, release and unbind loss cases reopen the local DB and compare exact stored bytes and resource counts. An expired checkout is replayed unchanged and a new lease uses a new key after reconciliation. These tests run the production local operations, with a deterministic fake HTTP peer; server replay has separate real-binary coverage in G2-31. |
| G2-44 | Plan L2080-L2222; Q-34/Q-38. Fresh, v0.1.28 and populated 0016 fixtures use real file databases and reopen. Shape/UNIQUE/FK helpers contain assertions. `m0017_root_generations_only_move_forward_on_upgraded_rows` delegates to a substantive transition helper; it is not an assertion-free pass. Backup hash and restore/re-upgrade are checked. Mutation scripts were read as evidence references but not executed because they edit the repository. |
| G2-45 | Plan L2338/L2343; D-6. Tests exercise class extrema and refusal, scan >150 INTEGER columns for upper bounds and assert exactly 181 columns have insert/update type guards. Migration 0030 matches the decoder's i64 domain. The trigger text scan is structural evidence, complemented by actual inserts/updates and the local SQLite probe. |
| G2-47 | Plan L2335; D-5. Secret-bearing types use Zeroizing/redacted Debug; bootstrap persists only a reference, saves its nonce before store, verifies reference ownership and saves activation before forgetting. Legacy cleartext migration tests exercise store failure, interruption and resume. This is type/lifecycle evidence, not proof of every physical freed-memory byte being wiped. All these test stores are mocks. |
| G2-49 | Plan L2337/L1175/L2250; Q-30/Q-39. Windows durable adapter syncs the temporary file and uses MoveFileExW with WRITE_THROUGH; crash parents require child checkpoints and verify old-or-new plus preservation of returned writes. Real local NTFS and UNC classification run. FAT/exFAT coverage is classification evidence, not a mounted-volume identity integration run. Q-30 accepts process-kill evidence without a physical power interruption. |
| G2-50 | Plan L2337/L2063; Q-16/Q-30/Q-31. Actual rollback-journal/FULL/busy policy, unclosed pool, killed transaction, acknowledged-commit preservation and second-writer waiting are tested; launcher refuses an externally held WAL DB. Network-share branches execute with the supplied UNC path. |
| G2-52 | Plan L2250-L2269/L2339; D-1/Q-30/Q-33/Q-35. A sweep injects process exits across prepare and commit, verifies exact crash class and external epoch monotonicity, and resumes to the restored state. It exercises a hot SQLite journal, sidecar moves, authority commit, DB install and bundle retirement. |
| G2-55 | Plan L2262; D-1/Q-38. Durable preparation holds both v1 writes and v2 operations off while allowing the intended read/login behavior. Audit failures persist per episode across restart, remain reportable after episode changes, survive corrupt-line salvage and clear only by the proper operation. UNC data-directory refusal writes no count. A related symlink sub-branch in the full restore harness (outside this row's nine cited restore-harness tests) skips locally; exact-commit Windows CI covers it with CI's no-skip assertion. |
| G2-61 | Plan L2340; Q-13/Q-14/Q-18. Tamper/confidentiality/context tests and original B1..B4/N1/N2 scenarios pass. The new F1 adversarial approval case contradicts the client revocation-counting property. DONE evidence is materially incomplete here even with a green full suite. |
| G2-63 | Plan L2341; D-8/Q-41. Registry contains 70 domain constants, 28 string labels and 7 byte labels, checks collision/shape and numeric IDs. Label code uses separate HKDF-SHA256 subkey and AAD over tenant/fleet/profile/generation, minimal 64/256/1024 padding buckets and strict padding checks. Golden subkey/ciphertext hashes and altered-context/tag/canonicality cases are exercised. Review document's old constant count/line references are stale, not a wire-format failure. |

## Discrepancies and evidence limits

- The packet still says it reviews `fe8c8e36`, lists historic runs as in progress, and says the packet commit has not been pushed. Actual HEAD is `aef00845...`, and exact-commit CI 41343000374 completed successfully. The hashes and commands were independently checked against actual HEAD; historical prose was not used as execution evidence.
- The initial server full-suite run overlapped an accidentally started row-command run. `v2_auth.rs:127` uses fixed temporary fixture names and fixed ports; overlapping invocations collided and reported `UNIQUE constraint failed: v2_server_state.singleton`/approval failures. I stopped the duplicate row runner, let the gate batch finish, and reran the full server suite and all row commands serially. Those initial failures are retained in the execution log and are attributed to verifier interference, not counted as product regressions. Future independent runs must serialize these test binaries.
- Local symlink creation lacks privilege (Windows error 1314). Exact messages: `skipping: cannot create a symlink here: A required privilege is not held by the client. (os error 1314)` in `server/tests/identity_authority.rs:220`; `SKIPPED: cannot create a symlink here: A required privilege is not held by the client. (os error 1314)` in `server/tests/restore_epoch_harness.rs:2876`. The directory/refusal control still runs. There were no SMB skips. CI 41343000374 passes on Windows; source makes these skips assertions when CI is set. No system privilege or Developer Mode setting was changed.
- `credential::tests::a_real_os_store_key_survives_into_a_fresh_process` was deliberately filtered from launcher invocations because it creates/deletes Windows Credential Manager entries (`credential.rs:263`). This follows the task's explicit restriction. The mock and key-file checks ran. G2-48 remains the owner's accepted PENDING-MANUAL exception. A byte-for-byte unfiltered launcher test command would violate the restriction; the exact adaptation is printed in each command.
- Ignored tests in full-suite totals are child-process entry points (parents explicitly launch them with `--ignored`) and live/manual integration examples; none of the packet's 323 cited test-function occurrences is itself marked ignored. A passing parent is required to reach the crash marker. The real-store child was not launched.
- `docs/security-review-g2.md:16` says 87 constants and names old line positions/exclusions. The current registry has 105 entries across its three lists; some former exclusions are now included. Inline literal domains remain outside a constants-only collision list, as the document acknowledges. Their codecs/golden vectors provide separate coverage.
- Section 8's N1 description overstates the SQL trigger: schema 8 (`team/db.rs:1273`) checks immutable identity/count columns and non-null container, not the cryptographic reason transition. The application performs the Compromised-only transition check (`team/ledger.rs:816`). The fix's behavior is correct on that write path; the SQL trigger alone does not enforce it against arbitrary direct SQL.
- G2-42 tests write lossless TEXT(max), then REAL(min), and only read back the latter before restoring max as an INTEGER. Thus they do not directly assert the intermediate TEXT(max) value despite the comment. The independent SQLite probe confirms it exactly, including the explicitly accepted decimal/exponent precision caveat; this is a test-strength note, not an additional blocking finding.
- Local runs did not perform physical power loss, mount exFAT/FAT32, inspect freed secret memory, reboot/lock the session, or exercise Windows Credential Manager. The ADR explicitly accepts the first three forms of evidence as stated; G2-48 is excepted by the owner. Team UI is deferred and was not treated as a blocker.
- RustSec audit, macOS compile, frontend/MCP/SDK checks are supported by the read-only exact-commit CI evidence. No package installation, dependency update, mutation script, real service, repository edit, commit, push, issue or PR action occurred. The only authored source was an in-memory adversarial probe recorded in this report; its executable is a compiler artifact under the requested private target.
- The frozen plan and ADR, evidence packet, cited source/tests/fixtures, manifests/lockfiles and workflow were used. No implementer review reports, prior verifier report contents, `.omc`, `.omx/reports`, or other authors' scratch directories were consulted. The required hash checker reads artifact bytes for comparison, including the prior-verifier artifacts, without exposing their contents.

## Security coverage conclusion

Beyond the packet's per-row names, I checked the Q-22 tenant-custodian restriction, Q-25 history-before-new-evidence lapse, Q-26 distrust withdrawing cached keys, Q-27 skipped generations, Q-28 restore epochs, Q-36 transition signer timing and Q-41 label separation against existing tests. The full suites exercise these additional tests. The specific uncovered security property is the integrity of the authority used to derive a revocation's scope (F1). No existing test supplies an outsider-signed extra approval to the revocation-counting path. The independent positive/negative probe demonstrates the resulting wrong decision. This is the material reason the rest of the gate does not hold; G2-48 and the deferred UI are not reasons for failure.

### Serial reproduction G2-60

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- l2265_g2_60_a_reconciled_epoch_retires_its_bundle_and_the_next_start_is_normal --nocapture`

Exit 0; 7.7 s; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 23 filtered out; finished in 7.33s
```

### Serial reproduction G2-61

`cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- a_snapshot_sealed_for_another_profile_is_refused every_single_byte_mutation_is_detected truncation_at_any_length_is_detected cross_envelope_frame_splice_is_rejected another_fleet_key_cannot_open_it grant_cannot_be_replayed_into_another_tenant_or_epoch tampering_with_the_stored_info_fails_the_open --nocapture`

Exit 0; 41.6 s; unmatched filters: [].

```text
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 293 filtered out; finished in 41.38s
```

### Serial reproduction G2-61

`cargo test -j 2 --locked --manifest-path shared/Cargo.toml --test backup_file_roundtrip -- the_ciphertext_does_not_contain_the_plaintext a_tampered_backup_body_is_refused a_truncated_backup_is_refused_and_leaves_the_destination_untouched --nocapture`

Exit 0; 5.4 s; unmatched filters: [].

```text
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out; finished in 4.91s
```

### Serial reproduction G2-61

`cargo test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- pull_refuses_another_profiles_snapshot push_seals_under_the_passphrase_even_with_a_cached_fleet_key a_server_delivered_fleet_key_is_counted_but_never_cached a_fleet_scoped_device_revoke_counts_for_a_member_of_that_fleet a_compromised_revocation_blocks_commits_under_an_exposed_generation a_compromised_custodian_blocks_every_fleet_through_the_root an_exposure_survives_a_recollection_that_omits_its_grant an_open_upload_is_aborted_once_a_compromise_is_counted a_compromise_counted_mid_transfer_aborts_the_upload a_known_custodian_with_no_root_holding_blocks a_compromise_counted_after_a_lost_revocation_of_the_same_key_blocks a_stored_finalize_is_not_sent_once_a_compromise_is_counted a_blocked_push_leaves_the_profile_available_and_dirty_with_the_local_code a_version_6_file_with_unreadable_kept_pages_still_opens --nocapture --skip credential::tests::a_real_os_store_key_survives_into_a_fresh_process`

Exit 0; 17.1 s; unmatched filters: [].

```text
test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 500 filtered out; finished in 14.82s
```

### Serial reproduction G2-61

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --test identity_authority -- an_interrupted_init_is_reported_and_never_repaired --nocapture`

Exit 0; 2.0 s; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 21 filtered out; finished in 1.55s
```

### Serial reproduction G2-61

`cargo test -j 2 --locked --manifest-path server/Cargo.toml --bin shardx-team-server -- wrong_domain_hpke_ids_are_quarantined_once --nocapture`

Exit 0; 0.6 s; unmatched filters: [].

```text
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 107 filtered out; finished in 0.28s
```

### Serial reproduction G2-63

`cargo test -j 2 --locked --manifest-path shared/Cargo.toml --test registry_pins -- every_signing_domain_is_distinct_and_versioned every_hash_label_is_distinct_and_nul_terminated the_numeric_registry_holds_the_reviewed_values --nocapture`

Exit 0; 0.1 s; unmatched filters: [].

```text
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

### Serial reproduction G2-63

`cargo test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- g2_golden_vector_profile_label a_profile_label_opens_only_where_it_was_sealed a_profile_label_has_a_length_bound_both_ways a_profile_label_is_padded_to_a_bucket a_profile_label_that_is_not_canonical_is_refused --nocapture`

Exit 0; 0.1 s; unmatched filters: [].

```text
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 295 filtered out; finished in 0.01s
```

Serial reproduction totals (repeated tests counted): [672, 0, 3]; failures/unmatched filters: []

```text
npm run test:i18n exit 0
ℹ tests 16
ℹ pass 16
ℹ fail 0
```

```text
npm run test:rust-strings exit 0
ℹ tests 3
ℹ pass 3
ℹ fail 0
```

```text
npm run test:backend-locale exit 0
ℹ tests 7
ℹ pass 7
ℹ fail 0
npm notice run node --test scripts/backend-error-locale.test.mjs
```

```text
npm run test:raw-error-toast exit 0
✔ a backend error is never toasted raw (10.7909ms)
✔ safeUiError resolves a marker and scrubs a token (0.3878ms)
ℹ tests 2
ℹ pass 2
ℹ fail 0
npm notice run shardx-launcher@2.5.0 test:raw-error-toast
npm notice run node --test scripts/raw-error-toast.test.mjs
```

## Per-row independent outcome index

The citation inventory above locates every cited test. All 96 packet test commands were run serially; the table below counts actual passing test executions for each row, including repeated golden-vector filters. The 21 in-depth samples above add production-code and contract readback. The remaining rows received citation/assertion review and command reproduction; “reproduced” is an evidence assessment within the stated scope, not a claim that passing tests prove every possible behavior. G2-62 is a CI gate and G2-64 is this independent review, so neither has a row unit-test command.

| Row | Commands | Passed test executions | Independent assessment |
|---|---:|---:|---|
| G2-01 | 2 | 4 | Reproduced; no additional blocking discrepancy found. |
| G2-02 | 2 | 2 | Reproduced; no additional blocking discrepancy found. |
| G2-03 | 2 | 3 | Reproduced; no additional blocking discrepancy found. |
| G2-04 | 2 | 4 | Reproduced; no additional blocking discrepancy found. |
| G2-05 | 2 | 3 | Reproduced; no additional blocking discrepancy found. |
| G2-06 | 2 | 2 | Reproduced; no additional blocking discrepancy found. |
| G2-07 | 1 | 6 | Reproduced; no additional blocking discrepancy found. |
| G2-08 | 1 | 1 | Reproduced; no additional blocking discrepancy found. |
| G2-09 | 1 | 1 | Reproduced; no additional blocking discrepancy found. |
| G2-10 | 1 | 7 | Reproduced; no additional blocking discrepancy found. |
| G2-11 | 1 | 6 | Reproduced; no additional blocking discrepancy found. |
| G2-12 | 1 | 7 | Reproduced; no additional blocking discrepancy found. |
| G2-13 | 1 | 4 | Reproduced; no additional blocking discrepancy found. |
| G2-14 | 2 | 10 | Reproduced; no additional blocking discrepancy found. |
| G2-15 | 1 | 4 | Reproduced; no additional blocking discrepancy found. |
| G2-16 | 1 | 1 | Reproduced; no additional blocking discrepancy found. |
| G2-17 | 1 | 1 | Reproduced; no additional blocking discrepancy found. |
| G2-18 | 1 | 1 | Reproduced; no additional blocking discrepancy found. |
| G2-19 | 1 | 1 | Reproduced; no additional blocking discrepancy found. |
| G2-20 | 2 | 2 | Reproduced; no additional blocking discrepancy found. |
| G2-21 | 2 | 3 | Reproduced; no additional blocking discrepancy found. |
| G2-22 | 2 | 4 | Reproduced; no additional blocking discrepancy found. |
| G2-23 | 2 | 3 | Reproduced; no additional blocking discrepancy found. |
| G2-24 | 2 | 3 | Reproduced; no additional blocking discrepancy found. |
| G2-25 | 2 | 3 | Reproduced; no additional blocking discrepancy found. |
| G2-26 | 2 | 6 | Reproduced; no additional blocking discrepancy found. |
| G2-27 | 1 | 5 | Reproduced; no additional blocking discrepancy found. |
| G2-28 | 1 | 7 | Reproduced; no additional blocking discrepancy found. |
| G2-29 | 1 | 5 | Reproduced; no additional blocking discrepancy found. |
| G2-30 | 2 | 11 | Reproduced; no additional blocking discrepancy found. |
| G2-31 | 5 | 15 | Reproduced; no additional blocking discrepancy found. |
| G2-32 | 1 | 3 | Reproduced; no additional blocking discrepancy found. |
| G2-33 | 1 | 5 | Reproduced; no additional blocking discrepancy found. |
| G2-34 | 1 | 3 | Reproduced; no additional blocking discrepancy found. |
| G2-35 | 1 | 6 | Reproduced; no additional blocking discrepancy found. |
| G2-36 | 1 | 2 | Reproduced; no additional blocking discrepancy found. |
| G2-37 | 1 | 3 | Reproduced; no additional blocking discrepancy found. |
| G2-38 | 2 | 5 | Reproduced; no additional blocking discrepancy found. |
| G2-39 | 1 | 12 | Reproduced; no additional blocking discrepancy found. |
| G2-40 | 1 | 2 | Reproduced; no additional blocking discrepancy found. |
| G2-41 | 1 | 14 | Reproduced for journal scope; complete restore writer is outside the evidence claimed. |
| G2-42 | 1 | 2 | Reproduced under Q-43; intermediate TEXT readback assertion is weaker than its comment. |
| G2-43 | 1 | 7 | Reproduced; no additional blocking discrepancy found. |
| G2-44 | 1 | 7 | Reproduced; no additional blocking discrepancy found. |
| G2-45 | 2 | 6 | Reproduced; no additional blocking discrepancy found. |
| G2-46 | 1 | 2 | Reproduced; no additional blocking discrepancy found. |
| G2-47 | 1 | 17 | Reproduced; no additional blocking discrepancy found. |
| G2-48 | 1 | 5 | PENDING-MANUAL owner exception; mock/key-file tests pass, real Credential Manager test excluded. |
| G2-49 | 4 | 13 | Reproduced; no additional blocking discrepancy found. |
| G2-50 | 3 | 8 | Reproduced; no additional blocking discrepancy found. |
| G2-51 | 2 | 7 | Reproduced; no additional blocking discrepancy found. |
| G2-52 | 1 | 1 | Reproduced; no additional blocking discrepancy found. |
| G2-53 | 2 | 3 | Other branches reproduced; local symlink creation skipped, covered by exact-commit Windows CI. |
| G2-54 | 1 | 1 | Reproduced; no additional blocking discrepancy found. |
| G2-55 | 2 | 16 | Reproduced, including UNC refusal; related full-harness symlink limitation recorded above. |
| G2-56 | 1 | 1 | Reproduced; no additional blocking discrepancy found. |
| G2-57 | 1 | 1 | Reproduced; no additional blocking discrepancy found. |
| G2-58 | 1 | 2 | Reproduced; no additional blocking discrepancy found. |
| G2-59 | 1 | 1 | Reproduced; no additional blocking discrepancy found. |
| G2-60 | 1 | 1 | Reproduced; no additional blocking discrepancy found. |
| G2-61 | 5 | 26 | FAIL F1 despite passing cited tests; outsider approval suppresses genuine revocation. |
| G2-62 | 0 | 0 | Exact-commit CI: all five jobs success; stale packet run prose noted. |
| G2-63 | 2 | 8 | Reproduced; security-review constant count and line references are stale. |
| G2-64 | 0 | 0 | FAIL: independent review found F1; G2-48 and deferred UI are not blockers. |

## Final disposition

The rest of the G2 gate does not hold: F1 is a reproduced security decision error in a DONE row, even though every permitted cited command and required local build gate passes on the definitive runs. The exact-commit CI is green. B4 needs the additional authority-validation regression and correction described above before independent PASS is justified. No other blocking defect was established in this review. The local symlink privilege limitation, manual credential-store exception, optional mutation-script exclusion and other unverified physical/environmental properties remain explicitly recorded above.

VERDICT: FAIL
