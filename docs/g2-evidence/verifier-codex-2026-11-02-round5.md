# Independent G2 verification — ShardBrowser

Date: 2026-11-02. Repository: https://github.com/huuhungn/ShardBrowser.
Commit reviewed: `6c5b6bdfd325f5c7bfc1aedc642eceb202f2c0fb`.
Worktree: `C:/Users/User/dev/wt/shardbrowser-g264b-codex`.

This report applies the G2 contract in the named plan, ADR 0002 and its referenced ADRs, with the owner's explicit G2-48 PENDING-MANUAL exception and Team UI deferral. It is an independent source/test verification, not adoption of the packet's verdict. No earlier verifier report, implementer review report, `.omc/`, `.omx/reports/` or scratch directory was read. The named plan was read directly. The security-review artifact was integrity-checked by the required hash checker, not read for its conclusions. Historical failure descriptions came from the user's request and evidence README section 8; closure judgments below came from implementation and executed regressions.

The evidence-gate-verification skill was applied. Its optional source mutation procedure was superseded by the user's read-only requirement. Negative cases already present in the repository were executed; no source mutation or new test file was authored. No repository, branch, worktree, GitHub or production-state changes were made. Tests used temporary fixture roots and the private build directory. The test that explicitly opens the real Windows credential store was filtered out, as detailed below.

## Environment, fixtures and integrity

All compiling local Cargo invocations used `-j 2` and `--locked`, with:

```powershell
$env:CARGO_TARGET_DIR='C:/Users/User/AppData/Local/Temp/g264-target-codex'
$env:SHARDX_TEST_SMB_DIR='\\localhost\C$\Users\User\AppData\Local\Temp\g264-smb'
```

The supplied UNC directory was reachable. The tests exercised their SMB refusal branches. G2-55 also independently obtains its own fixture through the loopback administrative share; its network case executed without the unreachable-share fallback. The local Windows host lacks symbolic-link creation privilege (1314); actual symlink branches are accounted for separately in the CI section.

| Component | Observed version |
| --- | --- |
| Windows Rust host | x86_64-pc-windows-msvc |
| stable rustc | 1.99.1 (58cf8f9c3 2026-10-13) |
| stable cargo | 1.99.1 (5f94df478 2026-08-27) |
| shared MSRV | rustc 1.87.0 (17067e9ac 2025-05-09) |
| launcher MSRV | rustc 1.88.0 (6b00bc388 2025-06-23) |
| server MSRV | rustc 1.89.0 (29483883e 2025-08-04) |
| Python | 3.12.10 |
| Node | v24.22.2 |
| cargo-audit | 0.22.2 |
| Independent in-memory SQLite probe | SQLite 3.49.1 |

The required command `python scripts/g2-evidence.py --check` exited 0 and printed exactly:

```text
120 files checked, 0 problems
```

The script normalizes CRLF to LF before SHA-256. The following independent hashes use that same normalization. The manifest identifies the remaining fixtures, vectors, migrations, manifests, lockfiles and directly cited test artifacts; the commit identifies the complete source tree.

| Artifact | SHA-256 (LF-normalized) |
| --- | --- |
| .omx/plans/shardbrowser-v0.2.x-team-fleet-encrypted-backup.md | 8b9ef41a21e93d19b4e4fe4641aff06d96a123256cb00c0e8580f0fa70a5523e |
| docs/adr/0002-g2-contract-decisions.md | 1c5c1e2cbabe2d3010a6e27c37f4a6e898e7a3508428de9fa59ffb243cad8ed8 |
| docs/g2-evidence/README.md | 60c15ded1cd03526e84b7b3d5d3588733520b0900195fadd237b45ce1cfd0d96 |
| docs/g2-evidence/SHA256SUMS | b24a9bd944229494bbae9ef67585ccd321e0172525f403ec6700a3152a1a3fe5 |
| shared/src/trust_chain.rs | ecc6f1b8a7ef83dabc507c0ec055bd8c1e724c1240a5db0896b007b5f44dca6a |
| src-tauri/src/team/ledger.rs | c29aa26014a73f4d74daac81017ed7c9cc07e5f85eac9c49b3a4ca64ed2cab32 |
| src-tauri/src/team/sync.rs | 6b2a5ec85df71d3679585251fd29ac44aeff9f444a46d74792272454127bc701 |
| server/tests/v2_auth.rs | 4c2cb8616f660f2c015dd28ded153390ad5ee1a5f0623cd8d4eaeb19ed3d1d3e |
| server/tests/v2_profiles.rs | 55d771dee17d1626b0132bfca7f1d09d5fa1758658f35bb3a3d1acda12b01ac8 |
| server/tests/restore_epoch_harness.rs | 6b66a5b81fa26fb21b75e551f6e16aa15625e945161d052f8cc2a154dbfdd3b2 |

## Commands and local outcomes

Each command's exit status was captured before filtering output. Counts below are test-harness counts, not claims that every branch ran locally. All section 6 filters matched executed tests. Repeated tests across rows are intentionally counted more than once in the row table.

| Gate | Command / expansion | Outcome |
| --- | --- | --- |
| Evidence | `python scripts/g2-evidence.py --check` | Exit 0; 120 files, 0 problems |
| Format | `cargo +stable fmt --check --manifest-path C/Cargo.toml`, C = shared, server, src-tauri, sdks/rust | 4 invocations; all exit 0 |
| Clippy | `cargo +stable clippy --locked -j 2 --manifest-path C/Cargo.toml --all-targets -- -D warnings`, C = shared, server, src-tauri | 3 invocations; all exit 0 |
| Shared full suite | `cargo +stable test --locked -j 2 --manifest-path shared/Cargo.toml -- --nocapture` | 315 passed, 0 failed, 1 ignored |
| Server full suite | `cargo +stable test --locked -j 2 --manifest-path server/Cargo.toml -- --nocapture` | 347 passed, 0 failed, 3 ignored |
| Launcher library | `cargo +stable test --locked -j 2 --manifest-path src-tauri/Cargo.toml --lib -- --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process` | 506 passed, 0 failed, 11 ignored, 1 filtered |
| Shared MSRV | `cargo +1.87.0 check --locked -j 2 --all-targets --manifest-path shared/Cargo.toml` | Exit 0 |
| Server MSRV | `cargo +1.89.0 check --locked -j 2 --all-targets --manifest-path server/Cargo.toml` | Exit 0 |
| Launcher MSRV | `cargo +1.88.0 check --locked -j 2 --all-targets --manifest-path src-tauri/Cargo.toml` | Exit 0 |
| Individual row reproduction | Appendix A, 96 invocations | 325 passing executions, 0 failed, 0 ignored, 0 unmatched filters; real-store test filtered |
| Additional PR #226 launcher regressions | Appendix B | 4 passed, 0 failed |
| Additional report-to-key trust regression | Appendix B | 1 passed, 0 failed |
| Interface language checks | `npm run test:i18n`, `test:rust-strings`, `test:backend-locale`, `test:raw-error-toast` | 16 + 3 + 7 + 2 = 28 passed; all exit 0 |

The full shared count is lib 301 + backup-file integration 8 + compatibility 3 + registry 3. The ignored shared test is the operator recovery drill. The server's three ignored entries are two crash-child entry points and a real-profile G6 memory drill; parent crash tests launch the child entries explicitly. The launcher's 11 ignored entries are crash-child helpers and the explicit-engine proxy/release-signing drills. None of the G2-cited tests has an `#[ignore]` attribute. The single filtered launcher test at `src-tauri/src/credential.rs:263` explicitly uses the real Windows Credential Manager, despite the mock store used elsewhere; filtering it obeys the user's machine-data restriction and falls entirely within G2-48.

The server count was read across all targets: lib 9, binary 106, e2e 10, identity 22, migration line endings 3, restore 24, v2_auth 75, durability 6, v2_e2e 9, instance 11, integer 5, nullable 3, profiles 9, schema 15, upgrades 0012/0013/0014/0015/0016 = 8/3/1/2/3, and upgrade-chain 23.

Local advisory commands used the existing advisory database with `--no-fetch`, avoiding an advisory-cache update:

```text
cargo +stable audit --no-fetch --deny unsound --deny yanked --file shared/Cargo.lock
cargo +stable audit --no-fetch --deny unsound --deny yanked --file server/Cargo.lock --ignore RUSTSEC-2023-0071
cargo +stable audit --no-fetch --deny unsound --deny yanked --file src-tauri/Cargo.lock --ignore RUSTSEC-2026-0194 --ignore RUSTSEC-2026-0195 --ignore RUSTSEC-2026-0367 --ignore RUSTSEC-2026-0368 --ignore RUSTSEC-2026-0369 --ignore RUSTSEC-2024-0429
```

All three exited 0, scanning 120 / 338 / 690 dependencies with 1395 cached advisories. Launcher output included 10 allowed unmaintained warnings. These are not a claim of zero advisories: the reviewed ignores and warnings remain. Exact-commit CI performs the packet's fetching audit commands.


## Exact-commit CI and the local symlink gap

Read-only run: [CI 41390571594](https://github.com/huuhungn/ShardBrowser/actions/runs/41390571594), exact `headSha = 6c5b6bdfd325f5c7bfc1aedc642eceb202f2c0fb`. The run completed successfully. All five required jobs are green:

| Job | Conclusion | Completed UTC |
| --- | --- | --- |
| Rust tests on Windows | success | 2026-11-02 05:20:44 |
| frontend, Rust, and MCP checks | success | 2026-11-02 05:13:34 |
| Rust compiles on macOS | success | 2026-11-02 04:50:49 |
| Launcher, server and shared MSRV | success | 2026-11-02 04:52:25 |
| Rust SDK stable and MSRV | success | 2026-11-02 04:52:15 |

`gh run view 41390571594 --repo huuhungn/ShardBrowser --log` exited 0. It returned 16,284 lines. SHA-256 of the UTF-8 stdout captured by Python in text mode (normalized line endings): `9ea425aa8ccc9b0f7e5e0db9ebdcb6d6669657f16436f070afab9dd9d78464ac`. The log was processed in memory, not saved to another file.

Windows log evidence includes:

```text
2026-11-02T04:53:27.1343818Z test volume::tests::an_smb_share_is_refused ... ok
2026-11-02T04:54:39.9865755Z test db::tests::storage_on_an_smb_share_is_refused ... ok
2026-11-02T04:55:49.5680303Z test identity::tests::preflight_refuses_an_identity_directory_on_an_smb_share ... ok
2026-11-02T04:57:29.9902299Z test a_symlinked_record_is_refused ... ok
2026-11-02T04:58:41.5589337Z test a_symlink_to_a_valid_manifest_is_not_the_manifest ... ok
2026-11-02T04:59:32.8522746Z test g2_55_a_read_only_start_on_a_network_data_directory_writes_no_count ... ok
2026-11-02T05:19:34.0889328Z test result: ok. 507 passed; 0 failed; 11 ignored; 0 measured; 0 filtered out
```

Windows shared totals are 315 passed/1 ignored; server totals 347 passed/3 ignored. Launcher library is 507 passed/11 ignored, including the real-store automated test on the CI runner; the additional launcher integration targets total 39 passes, so its full launcher command totals 546 passes. Windows Rust SDK adds 17 passes/1 ignored. No Windows `SKIPPED` or `skipping:` line was observed; no uppercase `SKIPPED` line was found elsewhere in the retrieved combined log.

The local full server run did print these two skip messages:

```text
skipping: cannot create a symlink here: A required privilege is not held by the client. (os error 1314)
SKIPPED: cannot create a symlink here: A required privilege is not held by the client. (os error 1314)
```

They correspond to `server/tests/identity_authority.rs:194` (return at 221) and `server/tests/restore_epoch_harness.rs:2886` (helper at 2864, return at 2899). The first test still executes its non-regular directory control locally. Neither actual symlink branch is claimed as locally executed.

The CI judgment is stronger than absence of printed skips: both helpers assert that `CI` is absent before taking the creation-failure return (`identity_authority.rs:216–219`, `restore_epoch_harness.rs:2872–2875`). GitHub Actions sets CI. Both named tests pass on the Windows job; therefore they created the links and executed the refusal assertions there. The valid manifest positive control transitions from K7 to K5a under a symlink and back to K7 after replacing the original. This closes the essential local symlink evidence gap without changing host privilege.

The Windows job's temporary-share creation and cleanup steps both succeeded. CI's fresh advisory step fetched RustSec, loaded 1395 advisories, scanned 120/338/690 dependencies, and completed successfully with the same 10 allowed warnings. The frontend job also passed the UI, MCP, Node SDK and Vietnamese backend-toast checks; macOS compilation was verified through its job rather than run on this Windows host. GitHub emitted an action-runtime deprecation annotation for `actions/cache@v4` (Node 20 action forced to Node 24); this was a warning, not a failed gate or skipped required test.


## All 64 rows: citation and execution readback

For every row, the cited test functions were located in the named source files, their assertions or called assertion helpers inspected, and the plan/ADR references read back. The cited line numbers reflect the current plan; older line numbers embedded in test names are two lines lower. The table lists section 6 passing executions (including shared filters selecting more than one test), not unique test counts. Detailed samples follow. No cited test was empty or ignored. The environment-dependent returns are the SMB/symlink cases described in this report. Rows 62 and 64 have no unit-test command by design.

| Row | Packet name | Plan citation | ADR 0002 citation | Local commands / passes | Finding |
| --- | --- | --- | --- | --- | --- |
| G2-01 | DeviceApprovalV2 + container | L443-L508 | D-2, Q-1, Q-13, Q-22 | 2 / 4 | Approval container/every-column request and startup checks; golden bytes. |
| G2-02 | TenantCapabilityGrantV2 | L443-L508 | Q-2, D-2, Q-13 | 2 / 2 | Capability-grant all-column equality at request and startup. |
| G2-03 | FleetKeyGrantV2::DeviceHpkeGrant | L443-L508, L1358 | D-8, D-9, Q-5, Q-13, Q-26 | 2 / 3 | Device HPKE grant equality and startup quarantine; context/key-use path inspected. |
| G2-04 | FleetKeyGrantV2::RecoveryGrant | L443-L508 | D-5, D-9 | 2 / 4 | Recovery grant context, suite, lengths and root/FKEK binding. |
| G2-05 | FleetKeyGrantV2::RotationGrant | L443-L508 | D-5, D-9, Q-5 | 2 / 3 | Rotation grant generation windows and count rules. |
| G2-06 | TenantRootKeyGrantV2 (3 variants, lifecycle) | L760-L909 | Q-1, D-4, Q-23, Q-24 | 2 / 2 | Root variants and lifecycle; launcher writes FirstRootSelfGrant, server covers rotation. |
| G2-07 | SnapshotManifestV2 / signed / head hash | L509-L589 | Q-1, Q-36 | 1 / 6 | Deep sample: closed manifest/container, hashes, signatures and envelope binding. |
| G2-08 | CommitRequestV2 | L509-L589 | Q-34 | 1 / 1 | Commit request refusals assert status/code, with successful upload control. |
| G2-09 | CommitReceiptBindingV2 | L509-L589 | none | 1 / 1 | Receipt tied to the committed head; checkout reads that head. |
| G2-10 | DekSlotContextV2 / DekSlotV2 | L590-L759 | D-3, ADR 0003, D-8 | 1 / 7 | Deep sample: exact slot/context maps, wrap lengths, hashes and open-map refusal. |
| G2-11 | EnvelopeIntentV2 | L590-L759 | D-3, ADR 0003 | 1 / 6 | Deep sample: exact intent, genesis omission and manifest consistency. |
| G2-12 | RestoreEpochLeafV2 / inclusion proof | L590-L759 | D-1, Q-1, Q-36 | 1 / 7 | Deep sample: leaf/proof context, deterministic roots, directions and tampering. |
| G2-13 | RestoreEpochTransitionV2 / signed | L590-L759 | D-1, Q-33, Q-36 | 1 / 4 | Transition payload/container/signature and context rejection. |
| G2-14 | IdempotentMutationRequestV2 | L910-L1054 | Q-5, Q-13 | 2 / 10 | Deep sample: real atomic revoke plus optional activation; B5 closed. |
| G2-15 | IdempotentStoredResponseV2 | L910-L1054 | D-6, Q-34 | 1 / 4 | Stored response exact roundtrip, domains and versions. |
| G2-16 | ROOT_GENERATION_CREATE | L915 | Q-5, D-4, D-9, Q-28 | 1 / 1 | Root bootstrap real mutation and identical retry response. |
| G2-17 | ROOT_GRANT_CREATE | L915 | Q-5, D-4, D-9 | 1 / 1 | Root-grant table/container equality. |
| G2-18 | ROOT_GRANT_ACK | L915 | Q-5, D-9 | 1 / 1 | Readback/ack names the exact stored grant. |
| G2-19 | ROOT_GENERATION_ACTIVATE | L915 | Q-5, D-9, Q-24, Q-28 | 1 / 1 | Activation checks acknowledged exact grant and current generation. |
| G2-20 | ROOT_GRANT_REVOKE | L915 | Q-5, Q-23 | 2 / 2 | Known revoke reason/outcome and last-custodian protection. |
| G2-21 | PROFILE_PUBLISH_CREATE | L915, L1139 | Q-41, Q-42 | 2 / 3 | Publish first lease and push; every publication crash checkpoint replays bytes. |
| G2-22 | PROFILE_CHECKOUT | L915, L1140 | Q-34, Q-42 | 2 / 4 | Lease/response scope and expiry, restore replay and fresh key. |
| G2-23 | CREATE_UPLOAD | L915, L1147-L1158 | Q-34 | 2 / 3 | Upload response loss replays exact request without a second resource. |
| G2-24 | FINALIZE_UPLOAD | L915, L1159-L1219 | Q-34 | 2 / 3 | Finalize, abort/restart reconciliation and commit crash checkpoints. |
| G2-25 | RELEASE_LEASE | L915, L1142 | Q-34, Q-42 | 2 / 3 | Release after lost reply remains byte-identical after lease removal. |
| G2-26 | LOCAL_UNBIND | L915, L2038, ADR D-7 | D-7, Q-37, Q-40 | 2 / 6 | Local tombstone survives binding, genesis omission and transaction interruption. |
| G2-27 | STREAM / preamble / final frame | L1352-L1371 | D-3, ADR 0003 | 1 / 5 | Deep sample: official cipher vector, golden object, final frame and LE31 boundary. |
| G2-28 | HPKE TRK/FKEK grants | L1358 | D-8, D-5 | 1 / 7 | Deep sample: RFC 9180 vectors, pinned info hash, labelled AAD and tenant binding. |
| G2-29 | Signing suite | L2335 | D-8 | 1 / 5 | Deep sample: RFC 8032, strict verification and small-order-key negatives. |
| G2-30 | Grant ALL-column + HPKE equality (seven under Q-13) | L2338, L2040, L2058 | Q-13, Q-38 | 2 / 11 | Deep sample: seventh record equality, runtime/startup quarantine and sticky integrity. |
| G2-31 | Durable response-loss replay, every operation | L2338, L1424, L2048 | Q-34, Q-42 | 5 / 15 | Deep sample: exhaustive operation replay after real server restart; B7 closed. |
| G2-32 | Local plan DDL + 11 probes | L1450-L2034, L2036 | Q-1, Q-37, Q-42 | 1 / 3 | File reopen, upgrade and retained triggers/indexes. |
| G2-33 | Probe 1 UNBIND tombstone | L2038 | D-7, Q-37 | 1 / 5 | Tombstone exact bytes/hash, transition evidence and durability. |
| G2-34 | Probe 2 RELEASE replay after lease gone | L2039 | Q-34 | 1 / 3 | Release retries after lease removal, cancel/error handling. |
| G2-35 | Probe 3 grant equality + second self-grant + cross-instance FK | L2040, L2034, L2058 | Q-13, Q-26, Q-42 | 1 / 6 | Deep sample: 326 changed-column cases, unreadable records, duplicate/cross-instance refusal. |
| G2-36 | Probe 4 upload resume + UNIQUE/FK | L2041 | none | 1 / 2 | Session uniqueness/foreign keys and offset-based upload resume. |
| G2-37 | Probe 5 manifest/request replay, 3 crash points | L2042 | none | 1 / 3 | Manifest/request drift rejected; exact bytes across crash points. |
| G2-38 | Probe 6 receipt equality/readback | L2043 | none | 2 / 5 | Receipt and readback equality plus upload/second-device pull. |
| G2-39 | Probe 7 local epoch transition/proof | L2044 | Q-1, Q-36, Q-37 | 1 / 12 | Deep sample: verified transition, proof, stale custodian/epoch and atomic binding move. |
| G2-40 | Probe 8 unknown/newer schema | L2045 | none | 1 / 2 | Unknown schema leaves file unchanged; existing WAL refused. |
| G2-41 | Probe 9 recovery/downgrade journals | L2046 | Q-35, Q-40 | 1 / 14 | Deep sample: journal reopen and actual child-process kills; production restore-writer limit disclosed. |
| G2-42 | Probe 10 local integer range | L2047 | D-6, Q-43 | 1 / 2 | Deep sample: Q-43 integer affinity clarification matches server; B6 closed. |
| G2-43 | Probe 11 local mutation replay | L2048 | D-7, Q-42 | 1 / 7 | Deep sample: durable local mutation replay and restore supersession. |
| G2-44 | Server migrations fresh + upgrade | L2080-L2222 | Q-34, Q-38 | 1 / 7 | Deep sample: substantive shared helpers, fresh/old-file upgrade, SQL assertions and restore. |
| G2-45 | Unsigned i64 domain (server) | L2343, L2338 | D-6 | 2 / 6 | Deep sample: numeric ends, invalid types, every v2 integer column bounded. |
| G2-46 | Argon2id | L1377 | D-5, Q-7, Q-21 | 1 / 2 | RFC 9106 and labelled Argon2id salt; local p=1 is the recorded Q-7 exception. |
| G2-47 | Secrecy/zeroization | L2335 | D-5 | 1 / 17 | Debug redaction, TRK store reference, migration/crash behavior; zeroization is type-level. |
| G2-48 | Windows credential store | L1374-L1376, L2335, ADR Q-29 | Q-29, D-5 | 1 / 5 | 5 automated tests pass; real-store test deliberately filtered; manual run remains excepted. |
| G2-49 | Windows file durability (local NTFS, Q-30) | L2337, L1175, L2250 | Q-30, Q-39 | 4 / 13 | Deep sample: actual write/kill durability and reachable SMB refusal; local NTFS scope. |
| G2-50 | SQLite WAL/busy/crash ordering | L2337, L2063 | Q-16, Q-30, Q-31 | 3 / 8 | Deep sample: DELETE/FULL, lock wait, killed transaction and WAL/SMB refusal. |
| G2-51 | Windows path corpus | L2338 | Q-30 | 2 / 7 | Deep sample: rewritten names, case folding, junctions, long paths and old-ID discovery. |
| G2-52 | Restore-epoch FS harness | L2339, L2250-L2269 | D-1, Q-30, Q-33, Q-35 | 1 / 1 | Filesystem restore crash table traversed by one substantive harness. |
| G2-53 | Missing/corrupt record | L2260 | D-1, Q-39 | 2 / 3 | Corrupt/missing record checks pass; local symlink subcase needs CI. |
| G2-54 | External = mirror, no preparation | L2261 | D-1 | 1 / 1 | Equal record/mirror with no preparation opens normally. |
| G2-55 | Preparation durable, authority E | L2262 | D-1, Q-38 | 2 / 16 | Deep sample: preparation read-only behavior and persistent audit-failure accounting. |
| G2-56 | External E+1, live mirror E | L2263 | D-1, Q-33 | 1 / 1 | Authority E+1 / live mirror E resumes install only. |
| G2-57 | E+1, restored mirror behind | L2264 | D-1, Q-33 | 1 / 1 | Installed DB behind external record requires verification and mirror rebuild. |
| G2-58 | Ahead without evidence | L2265 | D-1, Q-33, Q-36 | 1 / 2 | Ahead without exact evidence fails closed; live custodian and computed leaves required. |
| G2-59 | Behind/different instance | L2266 | D-1, Q-39 | 1 / 1 | Cited test covers different-instance K2; full restore suite also covers behind-mirror case. |
| G2-60 | Reconciled E+1, retire bundle | L2267 | D-1, Q-28 | 1 / 1 | Reconciliation retires bundle and next startup is normal. |
| G2-61 | Trust-boundary tests/docs | L2340 | Q-13, Q-14, Q-18 | 5 / 26 | Deep sample: tamper/confidentiality, trust ledger and all historical compromise regressions. |
| G2-62 | Dependencies (license, advisories, MSRV, feature graph) | L2336, L2343 | D-3, ADR 0003 | — | No unit command by design: manifests, dependency review, audits and three MSRVs checked. |
| G2-63 | Security review artifact | L2341 | D-8, Q-41 | 2 / 8 | Deep sample: registry completeness, numeric pins and exact profile-label construction. |
| G2-64 | Independent verifier PASS | L2343, L2512, L2565 | Q-15, Q-32 | — | This independent report supplies the new verdict; earlier reports were not opened. |

## In-depth samples and exercised paths

The following 24 samples include all nine rows specifically required by the owner. Each observation combines the cited test, its helper/production path and its plan/ADR decision; these are not judgments based only on test names.

1. **G2-07 — manifest/container (plan 509–539; Q-1/Q-36).** Read `shared/src/snapshot_v2.rs` and its payload/container defect matrices. The plan-side field inventory is: domain/version; snapshot, tenant, fleet, profile and lease IDs; target/base versions, fence and key generation; FKEK ID; preamble/intent/slot/ciphertext hashes; ciphertext size; optional previous head; signer ID; server instance; restore epoch; replay ID; informational creation time. The builder/parser contain that set with no extra open-map fields. Genesis omits previous head; other versions require it. The container has domain/version, payload domain/version/bytes/hash, signature suite/version/signer/signature, and core-container hash. The external head is SHA-256 of the NUL-terminated head label, big-endian u32 byte length, then exact container bytes; it is distinct from the core hash and plain exact-bytes hash. Negative fixtures mutate the fields and hashes, and the positive control binds a real sealed envelope. Six matching tests passed.

2. **G2-10 — DEK slot (plan 601–635; D-3/D-8/ADR 0003).** Read `shared/src/envelope_v2.rs`, wrapping code and canonical labels. Plan inventory: context domain/version; snapshot/tenant/fleet/profile IDs; FKEK ID; generation; wrap suite; slot index 0; context nonce. Slot inventory: domain/version/index, exact context bytes, labelled context hash, wrap nonce, wrapped DEK. Context AAD is the exact stored bytes. Neither slot nor context includes intent/ciphertext/manifest, so the dependency is acyclic. Parser closes both maps, pins registry/lengths, recomputes the hash and cross-checks the intent. Golden context and slot tests are independent fixed expectations. Seven selected tests passed.

3. **G2-11 — intent (plan 637–659; D-3).** The checked inventory extends identity/lease/replay/version/fence/generation with FKEK, preamble and numeric suites, archive/policy/compression IDs, bounded frame size, stream nonce prefix, true final-frame flag, plaintext/ciphertext limits, creation time, genesis-dependent previous head, intended signer, instance/epoch, context hash and slot hash. Read the parser, writer and manifest-binding comparison. Missing/extra/wrong fields, genesis and bounds have negative cases, not just a roundtrip. Six tests passed.

4. **G2-12 — Merkle/restore leaf (plan 590–759; D-1/Q-1/Q-36).** Read `shared/src/restore_epoch.rs` proof construction and validation. The tests include n=1/2/3 and larger small trees, odd-node behavior, direction/sibling mutation, sorted/unique leaf constraints, tenant/profile/instance/epoch/count/root binding and canonical proof parsing. Fixed roots plus mutation cases check more than agreement of two implementations sharing an error. Seven tests passed.

5. **G2-14 — atomic activations (plan 910–1054; Q-5/Q-13).** Read `shared/src/mutation.rs`, `server/src/routes/v2_device_revoke.rs` and `server/tests/v2_auth.rs:5949,6141`. Activations are a sorted unique list bounded at 65535; empty remains valid. An invalid/unacknowledged included activation leaves revocation, sessions and generation unchanged. Valid fleet/root activations commit with the revocation; replay returns stored output. This exercises the B5 failure scenario against a real transaction. Ten selected executions passed.

6. **G2-27 — STREAM (plan 1352–1371; ADR 0003).** Read framing/sealing/opening paths, the official XChaCha20Poly1305 vector, golden object hashes, and `shared/src/envelope_v2.rs:1223,1273,1308,1461`. The last-frame flag, authenticated preamble/frame context, missing/trailing/changed frames and plaintext/ciphertext bounds are asserted. The LE31 provider boundary accepts 0x7fffffff and rejects 0x80000000; the test actually invokes the provider boundary path. Five tests passed.

7. **G2-28 — HPKE (plan 1358; D-5/D-8).** Read `shared/src/grants.rs:503,619` and fleet-grant use. The RFC 9180 vector checks two ciphertexts and exported material, not only local seal/open agreement. The info vector now pins its hash. Tenant, generation and recipient binding and labelled length-prefixed AAD have negative controls; another device/key fails to open. Seven tests passed. The earlier roundtrip-only info-vector weakness is closed.

8. **G2-29 — Ed25519 (plan 2335; D-8).** Read `shared/src/signing.rs` and authz container verification. RFC 8032 expectations and the strict-verification matrix cover small-order/noncanonical ambiguity; issuer IDs and exact domain-separated, length-prefixed bytes are bound. Five tests passed.

9. **G2-30 — seventh record and quarantine (plan 2338/2040/2058; Q-13/Q-38).** Read device-revocation loading in `server/src/routes/v2_device_revoke.rs`, `server/src/integrity.rs`, request/startup matrices around `server/tests/v2_auth.rs:9609`, and kept-record reload. Every mapped column is compared against verified container data. Wrong instance, unreadable data, corrupt hashes and swapped genuine containers produce specific refusal/quarantine behavior. The startup scan and request-time checks are both exercised; restore of the exact original bytes is distinguished from substitution. Eleven executions passed. Q-38's separately accepted pre-quarantine two-step genuine-container swap remains a documented boundary.

10. **G2-31 — durable replay (plan 2338/1424/2048; Q-34/Q-42).** Read `server/tests/v2_auth.rs:10642`, `server/tests/v2_profiles.rs:3971`, production replay paths and launcher operation persistence. The matrices exhaustively match `OperationKind`, perform the real mutation, restart using the same DB and repeat the same request. They compare exact output and resource rows, and reject the same key with changed request bytes. They cover custody and profile operations; local unbind is intentionally local and has its own persistent tombstone replay. This is substantive lost-response evidence rather than a mocked receipt. Fifteen selected executions passed.

11. **G2-35 — local all-column comparison (plan 2040/2034/2058; Q-13/Q-26/Q-42).** Read `src-tauri/src/team/records.rs:487`, ledger filing/key-use paths and DB constraints. The fixture is reopened, then a savepoint-based matrix changes every mapped column across six stored authorization variants on that reopened connection: 326 nonlocal changes must produce the specific unreadable-record outcome. Three kinds of local metadata are deliberately exempt; after rollback, unchanged records retain exact bytes. A second self-grant, cross-instance generation and duplicate row are refused. The seventh revocation record is in its separate store and is covered by the additional sync test. Six tests passed.

12. **G2-39 — transition acceptance (plan 2044; Q-1/Q-36/Q-37).** Read transition verification and transactional binding moves in `src-tauri/src/team/sync.rs`. Tests cover invalid proof/signature, wrong epoch, stale/lapsed/not-yet-appointed custodian, a binding changed during acceptance, interrupted acceptance and old lease release failure/replay. Valid acceptance moves only covered bindings; failure preserves quarantine. Twelve tests passed. No additional issue was established by examining first-evaluation ordering against the ADR's stated no-history limit.

13. **G2-41 — journal/downgrade (plan 2046; Q-35/Q-40).** Read `src-tauri/src/team/journal.rs:701` and `downgrade.rs:1778,1828` plus production resume logic. Journal phases are persisted/reopened in order, illegal skips and terminal repeats fail, and digests remain exact. Downgrade tests inject every listed checkpoint and also kill real child processes at each checkpoint, then resume or roll back and inspect the clone/original/discovery state. Fourteen tests passed. The restore journal lacks a production writer; the packet explicitly scopes this row to the journal/probe and defers the full pre-v2 restore flow. It does not establish a shipped restore UI.

14. **G2-42 — integer domains (plan 2047; D-6/Q-43).** Read `src-tauri/src/team/db.rs:2858`, `records.rs:675`, numeric parsing/binding and server migration 0030. Both reopen probes retain ends exactly and reject out-of-domain/fractional/nonnumeric/BLOB writes without losing the old value. An independent in-memory SQLite 3.49.1 probe confirms integer TEXT max remains exact, REAL 1.0 stores INTEGER 1, and decimal TEXT '9007199254740993.0' rounds to 9007199254740992. Q-43 explicitly discloses that last case. SQLite affinity precedes CHECK/triggers; typed wire decoding and i64 binds prevent that text conversion on the product path. Two selected tests passed. The contract correction is internally sound and consistent with server post-affinity enforcement; it is not proof that arbitrary SQL TEXT preserves decimal precision.

15. **G2-43 — local replay (plan 2048; D-7/Q-42).** Read durable request/response storage and resume branches. Publish, checkout, create upload, commit/finalize, release and unbind cases replay exact bytes after response loss/crash. Expired or restored checkout gets a new key; superseded restore replay terminates old work and starts fresh. Seven tests passed.

16. **G2-44 — migrations (plan 2080–2222; Q-34/Q-38).** Read `server/tests/v2_upgrade_chain.rs`, its `upgrade`, `fixtures_on`, `run_fixtures`, `assert_plan_shapes` helpers, `fixtures/plan_assert.sql` and old-schema fixtures. Some top-level tests have no inline assert because the helpers reopen real files and assert schema shapes, FK/UNIQUE behavior, populated upgrade data and backup restoration. They are not vacuous wrappers. Seven selected tests passed; the complete upgrade-chain target has 23 passes. Optional source-mutating scripts were not run.

17. **G2-45 — server integers (plan 2338/2343; D-6).** Read `server/tests/v2_integer_domain.rs`, SQL scanning/negative control and migration 0030. The scan distinguishes bounded from deliberately unbounded columns and checks every v2 integer column, not a handpicked subset. Endpoints, overflow, bad types and upgraded rows are exercised. Six selected executions passed. Q-43's affinity semantics also apply here.

18. **G2-49 — durable file writes (plan 2337/1175/2250; Q-30/Q-39).** Read `src-tauri/src/durable.rs`, shared volume classification, server identity preflight and caller integration. Windows replacement uses flushed content and MoveFileExW WRITE_THROUGH; immutable create does not overwrite. Actual kill tests demand whole old/new values and preservation of acknowledged writes. Local NTFS is the supported classification; supplied SMB resolves and is refused in shared/server/identity paths. Thirteen executions passed. FAT/exFAT classification has unit evidence, not a physical removable-filesystem or power-loss run.

19. **G2-50 — SQLite ordering (plan 2337/2063; Q-16/Q-30/Q-31).** Read pool settings, crash harnesses, lock wait and WAL detection. Tests check synced rollback journal/DELETE mode and FULL synchronization, a second writer waits, killed transactions reopen atomically, and returned commits survive subsequent kills. A database held in WAL is refused. Eight executions passed, including actual SMB refusal.

20. **G2-51 — paths/discovery (plan 2338; Q-30).** Read archive pack/unpack replacement and downgrade discovery. The corpus covers device/reserved names, Windows rewrites, NTFS case collisions, long path bounds and junction traversal in pack and replace. A valid junction is created locally, so junction evidence does not rest on the skipped symlink capability. Seven executions passed.

21. **G2-55 — read-only/audit failure (plan 2262; D-1/Q-38).** Read `server/src/audit.rs`, `server/src/restore.rs` and real CLI/process tests in the restore harness. A durable preparation at E prevents writes until commit/abort; audit-write failure remains observable through persistent episode counters and incident/status output. Directory/link refusal, atomic count writes, interrupted set-aside, malformed line retention, changed episode IDs and explicit clearing are checked. Network data startup performs no counter write. Sixteen selected executions passed.

22. **G2-61 — independent trust-boundary review (plan 2340; Q-13/Q-14/Q-18).** Read shared tamper paths, trust fixpoint, launcher ledger and push/pull decisions; closure scenarios below extend the cited list with PR #226. Source and tests distinguish ciphertext/container tampering from hostile coordination/control-plane history. Proven compromise survives page omission and blocks current encryption until root/fleet rotation; unsigned reports quarantine reads but do not create a compromised-generation commit block. Twenty-six section 6 executions plus the explicit PR #226 regressions passed. No new blocking gap was established beyond the expressly deferred/limited cases listed below.

23. **G2-63 — suite/label/registry (plan 2341; D-8/Q-41).** Read `shared/tests/registry_pins.rs` and `shared/src/keys.rs:578`. An independent scan of exported domain/label constants found none missing from the registry. Numeric suite pins are asserted at registry line 201. The profile-label path derives a distinct HKDF subkey, uses labelled contextual AAD, validates canonical bounded plaintext and minimal bucket padding, and has a fixed golden ciphertext/hash expectation. Eight selected tests passed. The security-review artifact's hash exists and matches; this report supplies its own code assessment without consuming the authors' review conclusions.

24. **G2-52/53/54/56/57/58/59/60 — external authority crash table (plan 2250–2269; D-1/Q-33/Q-39).** Read identity/preflight and restore classification plus the crash mapping. Missing/corrupt/behind/different-instance/ahead-without-exact-proof cases close writes; authority committed before DB install resumes only the install; a restored mirror is rebuilt from verified evidence; a reconciled bundle is retired. Positive normal/prepare/restore controls prevent every error case from passing merely because the server never starts. G2-59's one cited command directly covers different-instance K2; the full restore suite adds behind-mirror coverage around `restore_epoch_harness.rs:1635–1650,2031–2057`.


## Earlier findings: independent closure decisions

The original reports were not opened. The scenarios below were taken from the task/packet, traced in current source, and tried through the repository's concrete regression fixtures. No regression fixture was weakened or edited for this run.

| Finding | Current source and failure scenario exercised | Decision |
| --- | --- | --- |
| B1: incomplete root-derived exposure | `src-tauri/src/team/ledger.rs:634` derives the compromised commit block from immutable key holdings/activation evidence. `sync.rs:6016` exercises a compromised custodian through root-to-fleet exposure, fleet-before-root rotation, root-then-fleet release, issuer exposure and higher/PREPARING roots. `sync.rs:6076` covers a known custodian with missing root holding. | Closed; tests passed. Missing evidence is conservative. |
| B2: recollection forgets exposure | Append-only `trust_key_holdings` and `trust_fleet_activations` retain earlier grant exposure. `sync.rs:6326` recollects a generation while omitting the earlier exposed grant and checks that the block remains. Version migration also preserves operation when kept pages are unreadable. | Closed; omission scenario passed. |
| B3: OPEN upload resumes after compromise; checkout too early | `sync.rs:1511` checks OPEN status and compromise before pending-finalize replay; abort path at `sync.rs:2472` sends DELETE for the remote upload and releases the lease. `sync.rs:6154,6204,6278` verify abort before the next chunk/finalize/commit, no early checkout when already blocked, and the local rotation-required error while profile content stays available/dirty. | Closed; real fixture request/state assertions passed. |
| B4: fleet-scoped revoke ignored | `shared/src/trust_chain.rs:522` computes scope from allowed approvals; server issuer rules at `server/src/routes/v2_device_revoke.rs:349` were compared. `src-tauri/src/lib.rs:3580` counts a fleet-scoped member revocation, rejects wrong fleet, and requires tenant authority for a real tenant approval. | Closed, including the later F1 correction. |
| B5: activation array forced empty | Sorted/unique bounded activations in `shared/src/mutation.rs`; the revoke route applies them in its transaction around line 689. `server/tests/v2_auth.rs:5949,6141` try invalid/unacknowledged activation with no side effects, then valid fleet/root activation and replay. | Closed; both atomicity regressions passed. |
| B6: local coercions disagree with probe 10 | ADR Q-43 at `docs/adr/0002-g2-contract-decisions.md:122`, the two local reopen tests, server migration 0030 and an independent SQLite affinity probe agree. Exact typed i64 wire values are the product boundary; decimal/exponent TEXT rounding above 2^53 is explicitly retained as a SQL-only limitation. | Closed by a sound, disclosed contract clarification. The old unconditional “reject all TEXT/REAL” reading is superseded. |
| B7: no all-operation durable response-loss matrix | `server/tests/v2_auth.rs:10642` and `v2_profiles.rs:3971` execute each operation, reopen the same database, compare exact retry bytes and absence of a second resource. Exhaustive `OperationKind` matches force coverage for future variants. LocalUnbind has its own persistent replay fixture. | Closed; 15 row executions and full suites passed. |
| N1: first lost revocation masks later compromised | `src-tauri/src/team/ledger.rs:809–846` upgrades kept non-compromised evidence to a verified compromised container, retaining earliest count; schema 8 limits allowed updates. `sync.rs:6098` first counts lost, later compromised, and demands the commit block. | Closed; upgrade scenario passed. |
| N2: saved FINALIZE bypasses OPEN check | The OPEN check at `sync.rs:1511` precedes pending FINALIZE. `sync.rs:6240` stores an unprocessed FINALIZE, counts compromise and resumes: no finalize/commit is sent; remote upload aborts. | Closed; stored-finalize scenario passed. |
| F1: outsider approval suppresses genuine fleet revoke | `shared/src/trust_chain.rs:529` filters with `approval_issuer_ok` (line 493) before deriving scope. `src-tauri/src/lib.rs:3580` injects outsider-signed tenant and other-fleet approvals; the genuine fleet-scoped compromised revocation still counts. Positive/negative allowed-issuer controls distinguish legitimate wider authority. | Closed; extended fleet-scope regression passed. |
| R1: revoked pinned signer remains readable | `sync.rs:291–303,3142` applies revoked/distrusted/reported checks even to an already pinned manifest. `sync.rs:6659` pins a real accepted head, then supplies either signed revocation or unsigned report and demands SIGNER_REVOKED quarantine with no output directory. `sync.rs:6681` confirms mere approval/grant expiry still permits pinned reads. | Closed; both strengths plus lapse control passed, including a separate 4-test run. |
| R2: ordinary pull does not file evaluated evidence | `sync.rs:3118–3122` records evaluation before head decisions; new heads check at line 3194. `sync.rs:6695` supplies signed revocation in this pull, with no report, and asserts withdrawal/quarantine/no output. `sync.rs:6720` later omits an unsigned report and checks it is retained. `shared/src/trust_chain.rs:1370` requires allowed approval mapping. | Closed; pull and shared regressions passed separately and in full suites. |
| SMB coverage gap | Set the requested reachable UNC path on shared/server/launcher runs; executed volume, server storage, identity preflight and network read-only/audit tests. No SMB skip/unreachable warning occurred. G2-55's own loopback fixture also executed. | Closed locally; Windows CI provides additional coverage. |

## Discrepancies and limits

No blocking implementation finding was established. The following discrepancies are preserved rather than hidden by a green test result:

1. **Packet metadata is stale.** README header and historical CI/status sections name fe8c8e36/5c1cd7b8 and still call G2-64 FAIL. This verification is for the full SHA above. Section 8 stops at N1/N2 and does not enumerate F1/R1/R2; the section 6 commands omit the new PR #226 names. Those fixes were independently read and tested here. The packet should eventually be refreshed, but changing it was forbidden in this task.
2. **Hash coverage is direct-citation coverage.** The 120-file checker does not promise to hash every transitively exercised implementation file. This report adds a direct normalized hash for the important trust-chain file and the current commit binds the rest of the tree. A matching hash proves identity, not correctness.
3. **Plan line drift is disclosed.** Some test names preserve older plan lines two lower than the current file. Current row citations were checked against the current plan. G2-45's earlier out-of-range line citation is replaced by existing test names in this packet.
4. **G2-59's section 6 selection is narrow.** It directly exercises different-instance K2 and audit count; the behind-mirror case rests on other tests in the full restore target, which also ran.
5. **“CI only” SMB notes are no longer true for this run.** The supplied local administrative share made the SMB branches executable. A passed harness containing a local symlink early return is not counted as symlink proof; that evidence comes from CI as described above.
6. **Dependency-review counts are stale.** `cargo +stable metadata --locked --offline --format-version 1 --manifest-path C/Cargo.toml` returned 120/338/690 resolved packages, 119/336/688 external packages. The document lists 118/335/687. All external packages declare licenses; only local ShardBrowser packages omit a Cargo license field. No GPL/LGPL-only dependency was found; the same five MPL-2.0 external crates remain. The broad “every crate declares a license” sentence needs that local-package qualification. This does not change the reviewed dependency disposition.
7. **Advisory status is qualified.** Local audits used the existing cache and the packet's ignores, with 10 allowed unmaintained warnings. Fresh exact-commit CI audit, not the local cached check alone, is the freshness evidence. Custody feature graph was independently reproduced; HPKE remains alloc/chacha/hkdfsha2/x25519 with default suites disabled. `rsa` and server `hkdf@0.12.4` have no selected all-target inverse tree; updater zip and build-time quick-xml paths match the document.
8. **Credential persistence remains excepted.** G2-48's real-store/fresh-process test and manual Store/reboot/Verify/Locked/Unavailable/Cleanup procedure were not executed on this machine. The five remaining credential tests passed. No real ShardX data or Credential Manager entries were touched.
9. **Deferred product paths are not claimed as tested product behavior.** Team screens/events are deferred. The restore journal has no production writer. ADR 0002 line 1552 explicitly defers reader-side revert acceptance (skip/audit) to the Team UI phase and excludes it from G2; quarantine remains. The ADR's aspirational revert vectors therefore are not implemented acceptance tests, and this verdict does not certify that future flow.
10. **Unsigned-report omission limit is explicit.** ADR 0002 line 1552 acknowledges that retained device reports map to a key through approvals in current evidence; withholding that approval too can leave an already pinned head readable. Proven revocation is retained by key. PR #226 closes the stated R1/R2 cases within this recorded boundary; it does not remove the documented withholding/no-history limits.
11. **Other accepted security limits remain.** Q-38 permits a two-step substitution using another genuine revocation before a quarantine marker; hostile-server/backdated first-evaluation and no-history risks remain under D-6/Q-19. Q-42 rejects a second origin sharing an already stored grant's key state and treats an expired lease on a fast clock as unavailable. Orphaned test/bootstrap keys and production key lifecycle need their separately documented handling. These were not silently converted into stronger guarantees.
12. **Nature of durability/zeroization evidence.** File/SQLite tests kill processes, not electrical power. NTFS/SMB were exercised; no physical FAT/exFAT device or hardware power-cut experiment ran. Zeroization is evidenced by Zeroizing/ZeroizeOnDrop types and redacted Debug output, not reading freed memory. Local SHXBAK01 p=1 remains Q-7's accepted exception while recovery-bundle Argon2 uses p=4.
13. **Read-only exclusions.** Optional source-mutating journal/migration scripts, `g2-evidence.py --write` and its mutating self-test were not run. No independent mutation of an old vulnerable tree was made; failure scenarios used the current repository's substantive regression fixtures. No authors' review conclusions were used.

Within the current G2 contract, the security-property coverage review found no additional mandatory untested property that blocks this gate. The untested credential persistence, deferred revert acceptance/UX, production restore-writer scope and physical zeroization/power-loss limits above are deliberately distinguished from executed evidence.


## Appendix A — exact per-row test invocations

The environment block above applies to every command. These 96 commands each exited 0. `--skip` only excludes the explicitly forbidden real-store credential test; on other rows it has no matching test. All filters were matched against executed test names, with no unmatched filters. Counts are in the all-row table. These are the packet's commands with the required toolchain/job limit and visible-output/credential exclusion arguments.

### G2-01

```text
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- the_first_device_approves_itself_once_and_a_retry_gets_the_same_receipt every_approval_column_is_compared_with_its_container_on_each_request the_startup_pass_quarantines_approvals_that_left_their_containers --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- authz_record::tests::golden_vectors --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-02

```text
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- every_capability_grant_column_is_compared_with_its_container_on_each_request_and_at_startup --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- authz_record::tests::golden_vectors --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-03

```text
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- every_fleet_grant_column_is_compared_with_its_container_on_each_request the_startup_pass_quarantines_fleet_grants_that_left_their_containers --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- authz_record::tests::golden_vectors --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-04

```text
cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- recovery_grant_binds_context_suite_and_lengths recovery_grant_opens_only_under_its_root_and_to_its_fkek authz_record::tests::golden_vectors --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- every_fleet_grant_column_is_compared_with_its_container_on_each_request --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-05

```text
cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- rotation_grant_follows_its_generation_window_and_count_rules authz_record::tests::golden_vectors --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- every_fleet_grant_column_is_compared_with_its_container_on_each_request --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-06

```text
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- every_root_grant_column_is_compared_with_its_container_on_each_request_and_at_startup --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- authz_record::tests::golden_vectors --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-07

```text
cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- snapshot_v2::tests::golden_vectors payload_rejects_every_field_level_defect container_rejects_every_field_level_defect signing_binds_the_signer_key manifest_binds_a_sealed_envelope_v2_object --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-08

```text
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_profiles -- every_upload_refusal_has_its_status_and_code --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-09

```text
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_profiles -- an_upload_commits_once_and_the_next_checkout_starts_at_its_head --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-10

```text
cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- the_closed_maps_parse_what_the_builders_write every_dek_slot_context_rule_is_enforced every_dek_slot_rule_is_enforced a_slot_that_differs_from_the_intent_is_refused the_reader_refuses_an_open_map g2_golden_vector_dek_slot g2_golden_vector_dek_slot_context_hash --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-11

```text
cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- the_intent_bounds_are_the_plans every_envelope_intent_rule_is_enforced the_intent_and_slot_must_be_the_ones_the_manifest_names manifest_binds_a_sealed_envelope_v2_object g2_golden_vector_intent g2_golden_vector_intent_genesis --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-12

```text
cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- restore_epoch::tests::golden_vectors leaf_roundtrips_and_refuses_contract_violations leaf_sets_must_be_non_empty_sorted_and_unique every_leaf_proves_and_every_tampering_fails a_proof_binds_tenant_profile_instance_epochs_count_and_root proof_parser_refuses_every_contract_violation g2_golden_vectors_merkle_roots --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-13

```text
cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- transition_roundtrips_and_verifies transition_payload_refuses_every_contract_violation signed_transition_refuses_every_container_defect transition_signature_binds_key_bytes_and_label --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-14

```text
cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- mutation::tests::golden_vectors every_map_roundtrips_byte_for_byte every_map_refuses_another_domain_or_version every_kind_has_one_scope_and_the_scope_must_match hashes_and_closed_fields_are_checked device_revoke_maps_carry_one_container_and_roundtrip fleet_lifecycle::tests::golden_vectors --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- a_revocation_commits_its_fleet_activation_or_nothing a_revocation_commits_its_root_activation --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-15

```text
cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- mutation::tests::golden_vectors every_map_roundtrips_byte_for_byte every_map_refuses_another_domain_or_version --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-16

```text
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- the_first_device_bootstraps_the_root_once_and_a_retry_gets_the_same_response --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-17

```text
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- every_root_grant_column_is_compared_with_its_container_on_each_request_and_at_startup --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-18

```text
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- readback_ack_and_activate_refuse_anything_but_the_exact_stored_grant --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-19

```text
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- readback_ack_and_activate_refuse_anything_but_the_exact_stored_grant --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-20

```text
cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- a_revocation_names_a_known_reason_and_its_outcome --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- a_custodian_revokes_a_root_grant_but_never_the_last_one --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-21

```text
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_profiles -- one_lease_and_one_fence_per_grant_and_every_retry_gets_the_stored_bytes --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_profile_is_published_with_its_first_lease_and_then_pushed every_publish_crash_point_resumes_with_the_exact_stored_bytes --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-22

```text
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_profiles -- one_lease_and_one_fence_per_grant_and_every_retry_gets_the_stored_bytes a_stored_response_naming_another_profile_or_lease_is_never_replayed --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_checkout_reply_for_another_tenant_fleet_or_expiry_is_never_kept a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-23

```text
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_profiles -- an_upload_commits_once_and_the_next_checkout_starts_at_its_head every_upload_refusal_has_its_status_and_code --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_create_upload_whose_reply_was_lost_is_replayed_byte_for_byte --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-24

```text
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_profiles -- an_upload_commits_once_and_the_next_checkout_starts_at_its_head a_restart_reconciles_uploads_and_an_abort_frees_the_lease_slot --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- every_crash_point_resumes_with_the_exact_stored_bytes --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-25

```text
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_profiles -- one_lease_and_one_fence_per_grant_and_every_retry_gets_the_stored_bytes a_stored_response_naming_another_profile_or_lease_is_never_replayed --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_release_whose_reply_was_lost_is_replayed_byte_for_byte --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-26

```text
cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- the_unbind_maps_round_trip_and_pin_the_tombstone the_unbind_maps_refuse_what_l953_does_not_allow --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- an_unbind_tombstone_outlives_its_binding_and_replays_exactly an_unbind_at_version_zero_omits_the_head an_unbind_cut_off_at_any_write_leaves_the_binding_whole an_unbind_is_refused_while_a_lease_request_or_journal_is_open --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-27

```text
cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- xchacha20poly1305_matches_the_draft_vector golden_objects every_preamble_rule_is_enforced every_frame_rule_is_enforced the_stream_counter_stops_at_the_provider_maximum --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-28

```text
cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- the_pinned_suite_matches_the_rfc_9180_vectors info_bytes_match_g2_vector only_the_granted_device_can_open grant_cannot_be_replayed_into_another_tenant_or_epoch the_fleet_grant_aad_is_the_label_the_length_and_the_info a_device_fleet_grant_opens_only_to_the_key_it_names a_sealed_fleet_key_opens_to_the_exact_same_bytes --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-29

```text
cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- signature_binds_issuer_and_bytes small_order_issuer_key_never_verifies rfc8032_vectors_sign_and_verify_strictly speccheck_matrix_accepts_only_the_unambiguous_case g2_golden_vector_signed_container_hash --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-30

```text
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- every_device_revocation_column_is_compared_with_its_container_on_each_request the_startup_pass_quarantines_device_revocations_that_left_their_containers a_revocation_of_another_instance_turns_v2_off_until_it_is_put_back a_revocation_quarantined_at_runtime_refuses_the_trust_evidence a_quarantined_revocation_that_verifies_again_is_served_again_after_a_restart a_marked_row_swapped_for_another_genuine_revocation_is_not_served_again a_corrupt_container_is_marked_without_a_hash_and_served_again_once_restored the_trust_evidence_reports_a_revoked_device_from_its_record_not_its_column a_revocation_row_swapped_for_another_genuine_one_does_not_answer_a_retry a_revocation_row_the_startup_pass_cannot_read_turns_v2_off --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_kept_revocation_reloads_with_every_column_equal --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-31

```text
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_auth -- the_first_device_approves_itself_once_and_a_retry_gets_the_same_receipt the_first_device_bootstraps_the_root_once_and_a_retry_gets_the_same_response every_custody_operation_replays_its_lost_response_after_a_restart --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_e2e -- v2_operations_replay_the_stored_response --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_profiles -- one_lease_and_one_fence_per_grant_and_every_retry_gets_the_stored_bytes a_stored_response_naming_another_profile_or_lease_is_never_replayed a_restart_reconciles_uploads_and_an_abort_frees_the_lease_slot every_profile_operation_replays_its_lost_response_after_a_restart --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- d1_replays_of_rolled_back_results_answer_as_superseded_and_kept_ones_replay --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- every_publish_crash_point_resumes_with_the_exact_stored_bytes a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key a_create_upload_whose_reply_was_lost_is_replayed_byte_for_byte every_crash_point_resumes_with_the_exact_stored_bytes a_release_whose_reply_was_lost_is_replayed_byte_for_byte an_unbind_tombstone_outlives_its_binding_and_replays_exactly --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-32

```text
cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_new_database_reopens_with_its_schema_and_settings a_version_5_file_with_data_moves_to_version_6_keeping_every_row the_triggers_and_indexes_of_a_version_5_file_survive_version_6 --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-33

```text
cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- an_unbind_tombstone_outlives_its_binding_and_replays_exactly an_unbind_cut_off_at_any_write_leaves_the_binding_whole a_tombstone_that_no_longer_recomputes_is_never_returned an_unbind_after_an_accepted_transition_keeps_its_evidence a_version_4_file_keeps_its_proofs_and_lets_them_outlive_the_binding --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-34

```text
cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_release_whose_reply_was_lost_is_replayed_byte_for_byte an_unsent_cancel_release_is_retried_and_then_given_up an_unreadable_release_reply_is_reported_and_replayed --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-35

```text
cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- six_records_reopen_exactly_and_refuse_every_changed_column a_second_self_grant_and_a_cross_instance_generation_are_refused only_a_self_grant_files_a_generation_and_a_duplicate_row_refuses a_filed_grant_files_the_key_state_it_names a_binding_and_its_rows_name_the_servers_account_and_key a_kept_revocation_reloads_with_every_column_equal --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-36

```text
cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- an_upload_session_refuses_a_second_identity_and_a_stranger_commit_or_key an_interrupted_upload_resumes_at_the_offset_head_reports --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-37

```text
cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- every_crash_point_resumes_with_the_exact_stored_bytes a_stored_column_that_drifts_from_its_bytes_is_never_sent a_stored_publish_that_drifts_from_its_bytes_is_never_sent --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-38

```text
cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_receipt_or_readback_that_does_not_match_is_never_kept a_published_profile_pushes_and_another_device_pulls_it an_upload_session_refuses_a_second_identity_and_a_stranger_commit_or_key --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_profiles -- an_upload_commits_once_and_the_next_checkout_starts_at_its_head every_upload_refusal_has_its_status_and_code --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-39

```text
cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_verified_transition_moves_only_the_bindings_it_covers a_transition_that_does_not_verify_keeps_the_binding_quarantined a_restore_epoch_that_goes_back_is_a_rollback a_cut_off_acceptance_leaves_the_binding_quarantined_until_reopen a_leaf_head_is_accepted_only_as_a_new_head_is a_pinned_head_is_read_back_only_as_the_bindings_own a_lapsed_or_former_custodian_signs_no_transition an_unbind_after_an_accepted_transition_keeps_its_evidence a_binding_changed_during_acceptance_is_not_moved a_lease_from_before_the_restore_is_released_before_the_binding_moves a_custodian_not_yet_appointed_signs_no_transition a_failed_release_of_an_old_lease_is_retried_as_stored --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-40

```text
cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- an_unknown_schema_fails_closed_and_is_left_as_it_was a_database_held_in_wal_mode_is_refused --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-41

```text
cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- every_restore_phase_survives_close_and_reopen_in_order a_restore_phase_cannot_skip_repeat_or_leave_a_terminal_one a_restore_journal_retires_only_when_settled the_restore_resume_table_is_fixed_per_crash_point a_clone_journal_walks_its_chain_with_every_phase_surviving_reopen a_downgrade_phase_cannot_skip_and_a_rollback_is_always_open the_resume_table_for_a_downgrade_journal_continues_every_open_phase the_digests_survive_reopen_byte_for_byte a_cut_off_at_every_step_resumes_to_the_same_finished_clone a_process_killed_at_every_step_resumes_to_the_same_finished_clone a_rollback_from_every_step_puts_the_original_back_and_frees_the_profile a_readback_that_v0_1_28_would_not_agree_with_fails_the_flow discovery_sees_every_place_v0_1_28_reads_and_nothing_in_the_archive an_unbind_is_refused_while_a_lease_request_or_journal_is_open --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-42

```text
cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- every_sync_integer_class_keeps_its_range_across_a_reopen every_integer_class_keeps_its_range_across_a_reopen --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-43

```text
cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- every_publish_crash_point_resumes_with_the_exact_stored_bytes a_checkout_replayed_after_its_expiry_or_a_restore_takes_a_new_key a_create_upload_whose_reply_was_lost_is_replayed_byte_for_byte every_crash_point_resumes_with_the_exact_stored_bytes an_unbind_tombstone_outlives_its_binding_and_replays_exactly a_release_whose_reply_was_lost_is_replayed_byte_for_byte a_superseded_replay_ends_cleanly_and_the_next_push_starts_fresh --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-44

```text
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_upgrade_chain -- the_plan_assertions_hold_on_a_reopened_fresh_file the_plan_assertions_hold_on_a_reopened_v0_1_28_file_and_its_backup_restores fixtures_1_to_4_hold_on_a_fresh_file fixtures_1_to_4_hold_on_a_v0_1_28_file_after_its_upgrade fixtures_1_to_4_hold_on_a_populated_0016_file_after_its_upgrade m0017_root_generations_only_move_forward_on_upgraded_rows m0033_the_quarantine_gains_a_container_hash_and_stays_append_only --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-45

```text
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_upgrade_chain -- m0030_upgraded_integer_columns_refuse_values_that_are_no_integers --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test v2_integer_domain -- every_class_decodes_its_domain_ends_and_refuses_everything_else every_class_column_stores_its_domain_ends_and_its_check_refuses_the_rest every_integer_column_of_every_v2_table_has_an_upper_bound_check every_integer_column_of_every_v2_table_refuses_a_value_that_is_no_integer the_bound_scan_tells_bounded_from_unbounded_columns --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-46

```text
cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- argon2id_matches_the_rfc_9106_vector the_kek_is_argon2id_over_the_labelled_salt --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-47

```text
cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- debug_never_prints_the_token_or_a_seed debug_never_prints_a_key a_session_debug_print_hides_its_tokens the_trk_is_stored_and_the_saved_state_holds_only_its_reference a_locked_or_unavailable_store_stops_every_trk_step_and_writes_nothing a_legacy_cleartext_trk_moves_into_the_store_and_the_file_is_rewritten_without_it the_legacy_trk_zeroizes_on_drop_and_is_read_but_never_written the_saved_state_never_prints_the_legacy_trk a_crash_between_storing_and_saving_the_key_resumes_with_the_same_key a_reference_to_another_credential_is_refused_and_that_credential_is_kept the_activation_is_saved_before_the_key_is_forgotten the_run_nonce_is_saved_before_the_key_is_stored a_new_run_never_reuses_a_key_an_abandoned_run_left a_store_that_refuses_the_legacy_trk_leaves_the_file_untouched_and_fails_closed a_legacy_trk_nobody_has_seen_is_dropped_and_a_fresh_one_is_made a_nonce_less_legacy_trk_stays_in_the_file_until_the_store_holds_it a_forget_succeeds_only_once_the_key_is_confirmed_gone --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-48

```text
cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_key_round_trips_and_is_forgotten references_are_separate_credentials a_failed_write_or_read_back_is_reported a_real_os_store_key_survives_into_a_fresh_process an_unavailable_store_fails_closed_in_a_fresh_process a_key_file_key_is_locked_then_served_in_a_fresh_process --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-49

```text
cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_durable_write_replaces_the_file_and_leaves_no_temporary a_failed_replace_keeps_the_old_file_and_removes_the_temporary a_write_killed_at_any_step_leaves_the_old_or_the_new_file a_kill_during_back_to_back_writes_never_tears_or_loses_a_returned_write creating_a_file_that_exists_never_overwrites_it --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- only_a_local_ntfs_disk_is_accepted a_local_ntfs_directory_is_accepted_and_a_missing_one_is_not an_smb_share_is_refused --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --bin shardx-team-server -- storage_that_cannot_be_resolved_is_refused storage_on_an_smb_share_is_refused preflight_refuses_an_identity_directory_on_an_smb_share --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- an_identity_directory_the_preflight_refuses_never_falls_to_k1 an_empty_identity_directory_setting_refuses_to_start --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-50

```text
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --bin shardx-team-server -- the_database_runs_a_synced_rollback_journal_and_survives_an_unclosed_pool a_killed_transaction_reopens_old_or_new_never_half a_kill_between_commits_keeps_every_returned_commit a_second_writer_waits_for_the_write_lock storage_on_an_smb_share_is_refused --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- a_killed_transaction_reopens_old_or_new_never_half a_database_held_in_wal_mode_is_refused --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- an_smb_share_is_refused --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-51

```text
cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- the_windows_path_corpus_is_refused_in_every_position every_name_windows_rewrites_is_refused ntfs_case_fold_collisions_are_refused_and_distinct_names_kept long_paths_unpack_and_an_overlong_one_is_refused a_junction_is_neither_packed_through_nor_followed_on_replace --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- discovery_sees_every_place_v0_1_28_reads_and_nothing_in_the_archive a_trace_of_the_old_id_after_the_move_fails_the_discovery_scan --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-52

```text
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- g2_52_every_crash_point_maps_to_one_row_and_resumes_to_the_restored_state --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-53

```text
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test identity_authority -- a_symlinked_record_is_refused show_detects_a_tampered_record_and_a_record_the_mirror_does_not_attest --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- an_identity_directory_that_is_not_there_is_missing_and_stops_the_server --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-54

```text
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- l2259_g2_54_a_record_equal_to_its_mirror_without_a_manifest_opens_normally --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-55

```text
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- l2260_g2_55_a_durable_preparation_at_e_keeps_writes_off_until_commit_or_abort g2_55_a_failed_read_only_audit_write_is_counted_in_restore_status g2_55_the_k2_incident_output_prints_the_audit_failure_count g2_55_a_directory_at_the_count_path_stops_a_read_only_start_by_name g2_55_restore_commit_prints_the_final_audit_failure_count_and_clears_it g2_55_a_read_only_start_logs_the_failed_audit_writes_counted_so_far g2_55_a_read_only_start_on_a_network_data_directory_writes_no_count g2_55_a_count_under_a_changed_episode_key_is_kept_and_cleared_by_name g2_55_a_count_file_with_a_bad_line_is_set_aside_and_its_valid_lines_kept --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --bin shardx-team-server -- a_failed_read_only_audit_write_is_logged_and_counted the_count_continues_across_read_only_restarts_of_one_episode a_changed_episode_key_keeps_the_old_count_until_it_is_cleared_by_name one_bad_line_in_the_count_file_loses_only_itself a_crash_while_setting_a_file_aside_never_loses_the_valid_lines the_count_is_written_atomically_and_an_unreadable_one_is_reported a_directory_or_link_at_the_count_path_is_refused_by_name --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-56

```text
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- l2261_g2_56_an_authority_ahead_of_the_live_mirror_resumes_only_the_install --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-57

```text
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- l2262_g2_57_an_installed_db_behind_the_record_is_verified_then_rebuilt --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-58

```text
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- l2263_g2_58_an_authority_ahead_without_exact_evidence_fails_closed l2263_g2_58_only_a_live_custodian_transition_over_the_computed_leaves_prepares --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-59

```text
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- g2_55_the_k2_incident_output_prints_the_audit_failure_count --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-60

```text
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test restore_epoch_harness -- l2265_g2_60_a_reconciled_epoch_retires_its_bundle_and_the_next_start_is_normal --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-61

```text
cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- a_snapshot_sealed_for_another_profile_is_refused every_single_byte_mutation_is_detected truncation_at_any_length_is_detected cross_envelope_frame_splice_is_rejected another_fleet_key_cannot_open_it grant_cannot_be_replayed_into_another_tenant_or_epoch tampering_with_the_stored_info_fails_the_open --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --test backup_file_roundtrip -- the_ciphertext_does_not_contain_the_plaintext a_tampered_backup_body_is_refused a_truncated_backup_is_refused_and_leaves_the_destination_untouched --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
cargo +stable test -j 2 --locked --manifest-path src-tauri/Cargo.toml --lib -- pull_refuses_another_profiles_snapshot push_seals_under_the_passphrase_even_with_a_cached_fleet_key a_server_delivered_fleet_key_is_counted_but_never_cached a_fleet_scoped_device_revoke_counts_for_a_member_of_that_fleet a_compromised_revocation_blocks_commits_under_an_exposed_generation a_compromised_custodian_blocks_every_fleet_through_the_root an_exposure_survives_a_recollection_that_omits_its_grant an_open_upload_is_aborted_once_a_compromise_is_counted a_compromise_counted_mid_transfer_aborts_the_upload a_known_custodian_with_no_root_holding_blocks a_compromise_counted_after_a_lost_revocation_of_the_same_key_blocks a_stored_finalize_is_not_sent_once_a_compromise_is_counted a_blocked_push_leaves_the_profile_available_and_dirty_with_the_local_code a_version_6_file_with_unreadable_kept_pages_still_opens --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --test identity_authority -- an_interrupted_init_is_reported_and_never_repaired --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
cargo +stable test -j 2 --locked --manifest-path server/Cargo.toml --bin shardx-team-server -- wrong_domain_hpke_ids_are_quarantined_once --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

### G2-63

```text
cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --test registry_pins -- every_signing_domain_is_distinct_and_versioned every_hash_label_is_distinct_and_nul_terminated the_numeric_registry_holds_the_reviewed_values --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
cargo +stable test -j 2 --locked --manifest-path shared/Cargo.toml --lib -- g2_golden_vector_profile_label a_profile_label_opens_only_where_it_was_sealed a_profile_label_has_a_length_bound_both_ways a_profile_label_is_padded_to_a_bucket a_profile_label_that_is_not_canonical_is_refused --nocapture --skip a_real_os_store_key_survives_into_a_fresh_process
```

## Appendix B — supplementary commands

```text
cargo +stable test --locked -j 2 --manifest-path src-tauri/Cargo.toml --lib -- a_pinned_head_of_a_since_revoked_signer_is_not_restored a_pinned_head_stays_readable_after_its_signers_grants_expire a_new_head_of_a_signer_revoked_in_this_pulls_evidence_is_refused a_report_of_a_revoked_signer_a_pull_saw_is_kept --nocapture
cargo +stable test --locked -j 2 --manifest-path shared/Cargo.toml --lib -- a_key_is_reported_revoked_only_through_an_allowed_approval --nocapture
```

Those produced 4/0/0 and 1/0/0 passed/failed/ignored, respectively.

Additional read-only dependency commands:

```text
cargo +stable metadata --locked --offline --format-version 1 --manifest-path shared/Cargo.toml
cargo +stable metadata --locked --offline --format-version 1 --manifest-path server/Cargo.toml
cargo +stable metadata --locked --offline --format-version 1 --manifest-path src-tauri/Cargo.toml
cargo +stable tree --locked --offline --manifest-path shared/Cargo.toml -e normal -f "{p} [{f}]" --depth 1
cargo +stable tree --locked --offline --manifest-path server/Cargo.toml --target all -i rsa
cargo +stable tree --locked --offline --manifest-path server/Cargo.toml --target all -i hkdf@0.12.4
cargo +stable tree --locked --offline --manifest-path src-tauri/Cargo.toml --target all -i zip@4.6.1
cargo +stable tree --locked --offline --manifest-path src-tauri/Cargo.toml --target all -i quick-xml@0.39.4
```

All eight dependency commands exited 0; the two empty inverse trees print Cargo's “nothing to print” warning. Python captured metadata in memory and reported only license/count/feature information.

Read-only GitHub commands used `gh run view 41390571594 --repo huuhungn/ShardBrowser --json ...` for exact SHA, status and step outcomes, and `gh run view 41390571594 --repo huuhungn/ShardBrowser --log` for execution evidence. Attempts to obtain logs before completion returned exit 1 with “logs will be available when it is complete”; that transient limitation is distinguished from a failed gate. Repository inspection used `git rev-parse HEAD`, `git status --short`, read-only diff/show queries, `rg`, PowerShell/Python source reads and in-memory SHA-256 calculation.


### Independent Q-43 probe

The following script ran through `@' ... '@ | python -` in PowerShell, using only an in-memory database (exit 0):

```python
import sqlite3
c = sqlite3.connect(':memory:')
c.execute("CREATE TABLE probe(v INTEGER NOT NULL CHECK(typeof(v)='integer' AND v BETWEEN 0 AND 9223372036854775807))")
c.execute('INSERT INTO probe VALUES (7)')
print('SQLite', sqlite3.sqlite_version)
for literal in ["'9223372036854775807'", '1.0', "'9007199254740993.0'", '-1', '0.5', "'9223372036854775808'", "'zero'", "x'00'"]:
    c.execute('UPDATE probe SET v=7')
    try:
        c.execute('UPDATE probe SET v=' + literal)
        print(literal, 'accepted', c.execute('SELECT v,typeof(v) FROM probe').fetchone())
    except sqlite3.IntegrityError:
        print(literal, 'rejected', c.execute('SELECT v,typeof(v) FROM probe').fetchone())
```

This independently tests SQLite affinity, while the repository tests exercise actual local/server schemas. Output:

```text
SQLite 3.49.1
'9223372036854775807' accepted (9223372036854775807, 'integer')
1.0 accepted (1, 'integer')
'9007199254740993.0' accepted (9007199254740992, 'integer')
-1 rejected (7, 'integer')
0.5 rejected (7, 'integer')
'9223372036854775808' rejected (7, 'integer')
'zero' rejected (7, 'integer')
x'00' rejected (7, 'integer')
```

## Final assessment

All required local gates passed, the 96 cited row commands matched and passed, and the exact-commit five-job CI run succeeded. B1–B7, N1, N2, F1, R1 and R2 are closed within the current ADR; the SMB and symlink evidence gaps are closed by actual local SMB execution and exact-commit Windows CI execution. There are no blocking findings from this verification. The packet has the nonblocking documentation discrepancies listed above.

The final integrity recheck again printed `120 files checked, 0 problems`; HEAD remained `6c5b6bdfd325f5c7bfc1aedc642eceb202f2c0fb`, all separately computed normalized hashes were unchanged, and `git status --short` remained empty. This report is the only authored file, at the requested output path. G2-48 remains PENDING-MANUAL under the owner's exception; this report makes no claim that reboot/locked-session credential persistence was reproduced.

VERDICT: PASS (excluding G2-48 PENDING-MANUAL)

